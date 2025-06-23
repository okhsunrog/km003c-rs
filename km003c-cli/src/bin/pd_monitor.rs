use clap::Parser;
use km003c_lib::KM003C;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{Duration, SystemTime};
use tokio::time::interval;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(author, version, about = "Monitor PD (Power Delivery) packets from POWER-Z KM003C", long_about = None)]
struct Args {
    /// Polling frequency in Hz (default: 1.0)
    #[arg(short, long, default_value = "1.0")]
    frequency: f64,

    /// Number of packets to capture (default: unlimited)
    #[arg(short, long)]
    count: Option<u64>,

    /// Optional file to save hex data
    #[arg(short, long)]
    output: Option<String>,

    /// Just print hex without extra formatting
    #[arg(long)]
    hex_only: bool,

    /// Include timestamps in output
    #[arg(short, long)]
    timestamp: bool,

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

    // Validate frequency
    if args.frequency <= 0.0 {
        error!("Frequency must be positive");
        std::process::exit(1);
    }

    // Connect to the device
    let mut device = KM003C::new().await?;
    info!("Connected to POWER-Z KM003C");

    // Calculate interval from frequency
    let interval_ms = (1000.0 / args.frequency) as u64;
    let mut timer = interval(Duration::from_millis(interval_ms));

    // Open output file if specified
    let mut output_file = if let Some(ref path) = args.output {
        Some(OpenOptions::new().create(true).append(true).open(path)?)
    } else {
        None
    };

    info!("Starting PD monitoring at {:.1} Hz", args.frequency);
    if let Some(count) = args.count {
        info!("Will capture {} packets", count);
    } else {
        info!("Capturing packets until interrupted (Ctrl+C)");
    }

    let mut packet_count = 0u64;
    let start_time = SystemTime::now();

    loop {
        // Check if we've reached the packet limit
        if let Some(max_count) = args.count {
            if packet_count >= max_count {
                break;
            }
        }

        // Wait for the next interval
        timer.tick().await;

        // Request PD data
        match device.request_pd_data().await {
            Ok(pd_data) => {
                packet_count += 1;

                // Calculate timestamp
                let elapsed = start_time.elapsed().unwrap_or(Duration::ZERO);
                let timestamp_secs = elapsed.as_secs_f64();

                // Format the output
                let output = if args.hex_only {
                    hex::encode(&pd_data)
                } else {
                    let timestamp_str = if args.timestamp {
                        format!(" @ {:.6}s", timestamp_secs)
                    } else {
                        String::new()
                    };

                    format!(
                        "PD Packet #{}{}\n  Raw hex: {}\n  Length: {} bytes",
                        packet_count,
                        timestamp_str,
                        hex::encode(&pd_data),
                        pd_data.len()
                    )
                };

                // Print to console
                println!("{}", output);

                // Write to file if specified
                if let Some(ref mut file) = output_file {
                    writeln!(file, "{}", output)?;
                    file.flush()?;
                }
            }
            Err(e) => {
                error!("Failed to request PD data: {}", e);
                // Continue trying instead of exiting
            }
        }
    }

    info!("Captured {} PD packets", packet_count);
    Ok(())
}
