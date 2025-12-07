use clap::Parser;
use km003c_lib::{Attribute, AttributeSet, DeviceConfig, GraphSampleRate, KM003C, Packet, PayloadData};
use std::error::Error;
use std::time::Duration;

/// Minimal AdcQueue test without Unknown68 commands
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Sample rate: 1, 10, 50, or 1000 SPS
    #[arg(short, long, default_value = "50", value_parser = ["1", "10", "50", "1000"])]
    rate: String,

    /// Duration in seconds
    #[arg(short, long, default_value = "5")]
    duration: u64,

    /// USB interface: "vendor" or "hid"
    #[arg(short, long, default_value = "hid")]
    interface: String,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
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
    let config = match args.interface.as_str() {
        "vendor" => DeviceConfig::vendor_interface(),
        "hid" => DeviceConfig::hid_interface(),
        _ => unreachable!(),
    };

    println!("🔍 Connecting to POWER-Z KM003C...");
    let mut device = KM003C::with_config(config).await?;
    println!("✅ Connected\n");

    // Minimal initialization - just start graph mode
    println!("📊 Starting AdcQueue at {} SPS (no Unknown68 commands)", args.rate);
    device.start_graph_mode(rate).await?;
    println!("✅ Graph mode started");

    // Wait for buffer to fill
    println!("⏳ Waiting 500ms for buffer...\n");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let start_time = std::time::Instant::now();
    let mut total_samples = 0;
    let mut packet_count = 0;

    println!("{:>6} {:>10} {:>10} {:>10}", "Seq", "VBUS (V)", "IBUS (A)", "Power (W)");
    println!("{}", "-".repeat(50));

    while start_time.elapsed() < Duration::from_secs(args.duration) {
        // Request AdcQueue using high-level API
        let result = device.request_data(AttributeSet::single(Attribute::AdcQueue)).await;

        match result {
            Ok(Packet::DataResponse { payloads }) => {
                for payload in &payloads {
                    if let PayloadData::AdcQueue(adc_queue) = payload {
                        if !adc_queue.samples.is_empty() {
                            packet_count += 1;
                        }

                        for sample in &adc_queue.samples {
                            total_samples += 1;

                            // Print every Nth sample based on rate
                            let print_interval = match rate {
                                GraphSampleRate::Sps1 | GraphSampleRate::Sps10 => 1,
                                GraphSampleRate::Sps50 => 5,
                                GraphSampleRate::Sps1000 => 50,
                            };

                            if total_samples % print_interval == 1 {
                                let power = sample.vbus_v * sample.ibus_a;
                                println!(
                                    "{:>6} {:>10.3} {:>10.3} {:>10.3}",
                                    sample.sequence, sample.vbus_v, sample.ibus_a, power
                                );
                            }
                        }
                    }
                }
            }
            Ok(Packet::Generic(_)) => {
                // Empty response or unknown packet, wait a bit
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok(other) => {
                if args.verbose {
                    println!("DEBUG: Unexpected packet: {:?}", other);
                }
            }
            Err(e) => {
                if args.verbose {
                    println!("DEBUG: Error: {:?}", e);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        // Small delay between requests
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    println!("{}", "-".repeat(50));
    println!("\n📊 Stopping graph mode...");
    match device.stop_graph_mode().await {
        Ok(_) => println!("✅ Stopped"),
        Err(e) => println!("⚠️  Stop error (may be OK): {:?}", e),
    }

    // Statistics
    let elapsed = start_time.elapsed().as_secs_f64();
    let effective_rate = total_samples as f64 / elapsed;

    println!("\nStatistics:");
    println!("  Duration: {:.1}s", elapsed);
    println!("  Packets: {}", packet_count);
    println!("  Total samples: {}", total_samples);
    println!("  Effective rate: {:.1} SPS", effective_rate);
    println!("  Expected rate: {} SPS", args.rate);

    Ok(())
}
