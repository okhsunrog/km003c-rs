use clap::Parser;
use km003c_lib::KM003C;
use km003c_lib::pd::{EventPacket, parse_event_stream};
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write as IoWrite; // Renamed to avoid conflict with fmt::Write
use std::time::{Duration, SystemTime};
use tokio::time::interval;
use tracing::{error, info};

// --- Add this entire block for PD parsing ---
// ------------------------------------------

#[derive(Parser, Debug)]
#[command(author, version, about = "Monitor PD (Power Delivery) packets from POWER-Z KM003C")]
struct Args {
    /// Polling frequency in Hz (default: 1.0)
    #[arg(short, long, default_value = "1.0")]
    frequency: f64,

    /// Number of PD messages to capture (default: unlimited)
    #[arg(short, long)]
    count: Option<u64>,

    /// Optional file to save output
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
    let log_level = if args.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(log_level).init();

    if args.frequency <= 0.0 {
        error!("Frequency must be positive");
        std::process::exit(1);
    }

    let mut device = KM003C::new().await?;
    info!("Connected to POWER-Z KM003C");

    let interval_ms = (1000.0 / args.frequency) as u64;
    let mut timer = interval(Duration::from_millis(interval_ms));

    let mut output_file = if let Some(ref path) = args.output {
        Some(OpenOptions::new().create(true).append(true).open(path)?)
    } else {
        None
    };

    info!("Starting PD monitoring at {:.1} Hz", args.frequency);
    if let Some(count) = args.count {
        info!("Will capture {} PD messages", count);
    } else {
        info!("Capturing PD messages until interrupted (Ctrl+C)");
    }

    let mut pd_message_count = 0u64;
    let start_time = SystemTime::now();

    loop {
        if let Some(max_count) = args.count {
            if pd_message_count >= max_count {
                break;
            }
        }

        timer.tick().await;

        match device.request_pd_data().await {
            Ok(pd_data) => {
                if pd_data.is_empty() {
                    continue;
                }

                if args.hex_only {
                    let output = hex::encode(&pd_data);
                    println!("{}", output);
                    if let Some(ref mut file) = output_file {
                        writeln!(file, "{}", output)?;
                        file.flush()?;
                    }
                    continue;
                }

                match parse_event_stream(&pd_data) {
                    Ok(events) => {
                        for event in events {
                            let elapsed = start_time.elapsed().unwrap_or(Duration::ZERO);
                            let timestamp_str = if args.timestamp {
                                format!(" @ {:.6}s", elapsed.as_secs_f64())
                            } else {
                                String::new()
                            };

                            match &event {
                                EventPacket::PdMessage(_) => {
                                    pd_message_count += 1;
                                    let header = format!("\n=== PD Message #{}{} ===", pd_message_count, timestamp_str);
                                    print_section(&header, &event, &mut output_file)?;
                                }
                                EventPacket::Connection(_) => {
                                    let header = format!("\n--- Connection Event{} ---", timestamp_str);
                                    print_section(&header, &event, &mut output_file)?;
                                }
                                EventPacket::Status(_) => {
                                    let header = format!("\n--- Status Packet{} ---", timestamp_str);
                                    print_section(&header, &event, &mut output_file)?;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse PD event stream: {:?}", e);
                    }
                }
            }
            Err(e) => {
                error!("Failed to request PD data: {}", e);
            }
        }
    }

    info!("Captured {} PD messages", pd_message_count);
    Ok(())
}

fn print_section(header: &str, event: &EventPacket, output_file: &mut Option<std::fs::File>) -> std::io::Result<()> {
    println!("{}\n{}", header, event);
    if let Some(file) = output_file {
        writeln!(file, "{}\n{}", header, event)?;
        file.flush()?;
    }
    Ok(())
}
