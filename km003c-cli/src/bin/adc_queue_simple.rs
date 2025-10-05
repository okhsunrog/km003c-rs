use clap::Parser;
use km003c_lib::{Attribute, AttributeSet, DeviceConfig, GraphSampleRate, KM003C, Packet};
use std::error::Error;
use std::time::Duration;

/// AdcQueue streaming example for POWER-Z KM003C
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Sample rate: 1, 10, 50, or 1000 SPS
    #[arg(short, long, default_value = "50", value_parser = ["1", "10", "50", "1000"])]
    rate: String,

    /// Duration in seconds
    #[arg(short, long, default_value = "10")]
    duration: u64,

    /// USB interface: "vendor" or "hid"
    #[arg(short, long, default_value = "hid")]
    interface: String,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Skip USB reset (for MacOS compatibility)
    #[arg(long)]
    no_reset: bool,
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
        "1" => GraphSampleRate::Sps1,
        "10" => GraphSampleRate::Sps10,
        "50" => GraphSampleRate::Sps50,
        "1000" => GraphSampleRate::Sps1000,
        _ => unreachable!(),
    };

    // Select interface
    let mut config = match args.interface.as_str() {
        "vendor" => DeviceConfig::vendor_interface(),
        "hid" => DeviceConfig::hid_interface(),
        _ => unreachable!(),
    };

    if args.no_reset {
        config = config.with_skip_reset();
    }

    println!("🔍 Connecting to POWER-Z KM003C...");
    let mut device = KM003C::with_config(config).await?;
    println!("✅ Connected\n");

    // Device needs warmup with normal ADC requests before StartGraph works
    println!("⏳ Warming up device...");
    for _ in 0..3 {
        let _ = device.request_adc_data().await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    println!("✅ Device ready\n");

    println!("📊 Starting AdcQueue streaming at {} SPS", args.rate);
    device.start_graph_mode(rate).await?;
    println!("✅ Streaming started");
    
    // Wait for device to accumulate first samples in buffer
    let warmup_ms = match rate {
        GraphSampleRate::Sps1 => 2000,    // 2 seconds for 1-2 samples
        GraphSampleRate::Sps10 => 500,    // 0.5s for 5 samples
        GraphSampleRate::Sps50 => 200,    // 0.2s for 10 samples
        GraphSampleRate::Sps1000 => 100,  // 0.1s for 100 samples
    };
    println!("⏳ Waiting {}ms for buffer to fill...\n", warmup_ms);
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

    while start_time.elapsed() < Duration::from_secs(args.duration) {
        // Request AdcQueue data
        let packet = device.request_data(AttributeSet::single(Attribute::AdcQueue)).await?;

        // Extract and display samples
        if let Packet::DataResponse { payloads } = packet {
            if payloads.is_empty() {
                // Empty response - buffer not ready yet, skip
                continue;
            }
            
            for payload in payloads {
                if let km003c_lib::PayloadData::AdcQueue(queue) = payload {
                    packet_count += 1;

                    for sample in &queue.samples {
                        total_samples += 1;

                        // Print every Nth sample to avoid flooding terminal
                        let print_interval = match rate {
                            GraphSampleRate::Sps1 | GraphSampleRate::Sps10 => 1, // Print all
                            GraphSampleRate::Sps50 => 5,                         // Every 5th
                            GraphSampleRate::Sps1000 => 50,                      // Every 50th
                        };

                        if total_samples % print_interval == 1 {
                            println!(
                                "{:>6} {:>10.3} {:>10.3} {:>10.3} {:>8.3} {:>8.3} {:>8.3} {:>8.3}",
                                sample.sequence,
                                sample.vbus_v,
                                sample.ibus_a,
                                sample.power_w,
                                sample.cc1_v,
                                sample.cc2_v,
                                sample.vdp_v,
                                sample.vdm_v
                            );
                        }
                    }

                    // Check for dropped samples
                    if queue.has_dropped_samples() {
                        println!("⚠️  Dropped samples detected in packet!");
                    }
                }
            }
        }

        // Small delay between requests
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    println!("{}", "=".repeat(90));
    println!("\n📊 Stopping streaming...");
    device.stop_graph_mode().await?;
    println!("✅ Stopped\n");

    // Statistics
    let elapsed = start_time.elapsed().as_secs_f64();
    let effective_rate = total_samples as f64 / elapsed;

    println!("Statistics:");
    println!("  Duration: {:.1}s", elapsed);
    println!("  Packets received: {}", packet_count);
    println!("  Total samples: {}", total_samples);
    println!(
        "  Average samples/packet: {:.1}",
        total_samples as f64 / packet_count as f64
    );
    println!("  Effective sample rate: {:.1} SPS", effective_rate);
    println!("  Expected rate: {} SPS", args.rate);

    Ok(())
}
