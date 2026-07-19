use clap::Parser;
use km003c_lib::{
    DeviceConfig, GraphSampleRate, KM003C,
    packet::{Attribute, AttributeSet},
};
use std::error::Error;
use std::time::Duration;

/// AdcQueue streaming example for POWER-Z KM003C
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Sample rate: 2, 10, 50, or 1000 SPS
    #[arg(short, long, default_value = "50", value_parser = ["2", "10", "50", "1000"])]
    rate: String,

    /// Duration in seconds
    #[arg(short, long, default_value = "10")]
    duration: u64,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Skip USB reset (defaults to true on macOS for compatibility)
    #[arg(long, default_value_t = cfg!(target_os = "macos"))]
    no_reset: bool,

    /// Force USB reset even on macOS (overrides --no-reset)
    #[arg(long)]
    reset: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(log_level).init();

    // Parse rate
    let rate = match args.rate.as_str() {
        "2" => GraphSampleRate::Sps2,
        "10" => GraphSampleRate::Sps10,
        "50" => GraphSampleRate::Sps50,
        "1000" => GraphSampleRate::Sps1000,
        _ => unreachable!(),
    };

    // AdcQueue requires vendor interface (Full mode)
    let mut config = DeviceConfig::vendor();
    if args.no_reset && !args.reset {
        config = config.skip_reset();
    }

    println!("Connecting to POWER-Z KM003C...\n");
    let mut device = KM003C::new(config).await?;

    // Check authentication
    if !device.adcqueue_enabled() {
        return Err("Authentication failed - AdcQueue not enabled".into());
    }

    let state = device.state().expect("device initialized");
    println!("{}\n", state);

    // Drain any remaining responses
    while let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(100), device.receive_raw()).await {}

    println!("Init complete!\n");

    // Start graph mode using library API
    println!(
        "Starting AdcQueue streaming at {} SPS (rate_index={})...",
        args.rate,
        rate as u16
    );
    device.start_graph_mode(rate).await?;
    println!("Streaming started\n");

    // Brief warmup - start polling quickly to avoid large initial batch
    let warmup_ms: u64 = 200;
    println!("Brief warmup {}ms...\n", warmup_ms);
    tokio::time::sleep(Duration::from_millis(warmup_ms)).await;

    println!("{}", "=".repeat(90));
    println!(
        "{:>6} {:>10} {:>10} {:>10} {:>8} {:>8} {:>8} {:>8}",
        "Seq", "VBUS", "IBUS", "Power", "CC1", "CC2", "D+", "D-"
    );
    println!(
        "{:>6} {:>10} {:>10} {:>10} {:>8} {:>8} {:>8} {:>8}",
        "", "(V)", "(A)", "(W)", "(V)", "(V)", "(V)", "(V)"
    );
    println!("{}", "=".repeat(90));

    let start_time = std::time::Instant::now();
    let mut total_samples = 0;
    let mut packet_count = 0;
    let mut last_seq: Option<u16> = None;
    let mut seq_stride: Option<u16> = None;

    while start_time.elapsed() < Duration::from_secs(args.duration) {
        // Request AdcQueue data using library API
        let mask = AttributeSet::single(Attribute::AdcQueue);
        let packet = match device.request_data(mask).await {
            Ok(p) => p,
            Err(e) => {
                if args.verbose {
                    println!("DEBUG: Request error: {:?}", e);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        // Extract AdcQueue data from the parsed packet
        let queue_data = match packet.get_adc_queue() {
            Some(data) => data,
            None => {
                if args.verbose {
                    println!("DEBUG: No AdcQueue data in response");
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
        };

        if queue_data.samples.is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        }

        packet_count += 1;

        if args.verbose {
            if let Some((first, last)) = queue_data.sequence_range() {
                println!(
                    "DEBUG: Packet {} - {} samples, seq {}..{}",
                    packet_count,
                    queue_data.samples.len(),
                    first,
                    last
                );
            }
        }

        // Print interval based on rate
        let print_interval = match rate {
            GraphSampleRate::Sps2 | GraphSampleRate::Sps10 => 1,
            GraphSampleRate::Sps50 => 5,
            GraphSampleRate::Sps1000 => 50,
        };

        for (i, sample) in queue_data.samples.iter().enumerate() {
            // Detect stride from consecutive samples in same packet
            if let Some(last) = last_seq {
                if i > 0 && seq_stride.is_none() {
                    let detected = sample.sequence.wrapping_sub(last);
                    seq_stride = Some(detected);
                    if args.verbose {
                        println!("DEBUG: Detected seq stride = {}", detected);
                    }
                }

                // Check for dropped samples using detected stride
                if i == 0 {
                    let stride = seq_stride.unwrap_or(20);
                    let expected = last.wrapping_add(stride);
                    if sample.sequence != expected {
                        let gap = sample.sequence.wrapping_sub(last);
                        let dropped = gap.saturating_sub(stride) / stride;
                        if dropped > 0 {
                            println!("Warning: {} samples dropped (gap={})", dropped, gap);
                        }
                    }
                }
            }
            last_seq = Some(sample.sequence);

            total_samples += 1;

            if total_samples % print_interval == 1 {
                println!(
                    "{:>6} {:>10.3} {:>10.3} {:>10.3} {:>8.3} {:>8.3} {:>8.3} {:>8.3}",
                    sample.sequence, sample.vbus_v, sample.ibus_a, sample.power_w, sample.cc1_v, sample.cc2_v,
                    sample.vdp_v, sample.vdm_v
                );
            }
        }

        // Drain any queued unsolicited responses (PD events etc.) before sleeping
        while let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(5), device.receive_raw()).await {
            if args.verbose {
                println!("DEBUG: Drained unsolicited response");
            }
        }

        // Minimal delay - device needs time to buffer samples
        tokio::time::sleep(Duration::from_millis(40)).await;
    }

    println!("{}", "=".repeat(90));
    println!("\nStopping streaming...");

    // Stop graph mode using library API
    device.stop_graph_mode().await?;
    println!("Stopped\n");

    // Statistics
    let elapsed = start_time.elapsed().as_secs_f64();
    let effective_rate = total_samples as f64 / elapsed;

    println!("Statistics:");
    println!("  Duration: {:.1}s", elapsed);
    println!("  Packets received: {}", packet_count);
    println!("  Total samples: {}", total_samples);
    if packet_count > 0 {
        println!(
            "  Average samples/packet: {:.1}",
            total_samples as f64 / packet_count as f64
        );
    }
    println!("  Effective sample rate: {:.1} SPS", effective_rate);
    println!("  Expected rate: {} SPS", args.rate);

    Ok(())
}
