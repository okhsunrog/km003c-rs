//! Example: Collect PD data from KM003C device and save to Parquet files
//!
//! This example demonstrates how to use the ProtocolAnalyzer to collect
//! real-time PD data and save it for later analysis.

use clap::Parser;
use km003c_lib::{analysis::ProtocolAnalyzer, KM003C};
use std::error::Error;
use std::time::{Duration, SystemTime};
use tokio::time::interval;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(author, version, about = "Collect PD data from KM003C and save to Parquet")]
struct Args {
    /// Polling frequency in Hz (default: 1.0)
    #[arg(short, long, default_value = "1.0")]
    frequency: f64,

    /// Duration to collect data in seconds (default: 60)
    #[arg(short, long, default_value = "60")]
    duration: u64,

    /// Output file path (default: pd_capture_<timestamp>.parquet)
    #[arg(short, long)]
    output: Option<String>,

    /// Session ID for the capture
    #[arg(short, long)]
    session_id: Option<String>,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    
    // Setup logging
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

    // Connect to device
    let mut device = KM003C::new().await?;
    info!("Connected to POWER-Z KM003C");

    // Create analyzer
    let mut analyzer = ProtocolAnalyzer::new(args.session_id);
    info!("Created protocol analyzer with session ID: {}", analyzer.session_id());

    // Setup timing
    let interval_ms = (1000.0 / args.frequency) as u64;
    let mut timer = interval(Duration::from_millis(interval_ms));
    let start_time = SystemTime::now();
    let duration = Duration::from_secs(args.duration);

    // Determine output filename
    let output_path = args.output.unwrap_or_else(|| {
        let timestamp = start_time.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        format!("pd_capture_{}.parquet", timestamp)
    });

    info!("Starting data collection for {} seconds at {:.1} Hz", args.duration, args.frequency);
    info!("Output will be saved to: {}", output_path);

    let mut packet_count = 0u64;

    loop {
        // Check if we've exceeded the duration
        if start_time.elapsed().unwrap_or(Duration::ZERO) >= duration {
            break;
        }

        timer.tick().await;

        match device.request_pd_data().await {
            Ok(pd_data) => {
                if pd_data.is_empty() {
                    continue;
                }

                packet_count += 1;
                let timestamp = start_time.elapsed().unwrap_or(Duration::ZERO).as_secs_f64();
                
                if let Err(e) = analyzer.add_events(&pd_data, timestamp) {
                    error!("Failed to add events: {}", e);
                }

                if packet_count % 10 == 0 {
                    info!("Collected {} packets, {} events total", packet_count, analyzer.events.len());
                }
            }
            Err(e) => {
                error!("Failed to request PD data: {}", e);
            }
        }
    }

    // Save the collected data
    info!("Collection complete. Saving {} events to {}", analyzer.events.len(), output_path);
    analyzer.save_to_parquet(&output_path)?;

    // Print statistics
    let stats = analyzer.get_statistics();
    info!("Collection Statistics:");
    for (key, value) in stats {
        info!("  {}: {}", key, value);
    }

    // Show some basic analysis
    if let Ok(patterns) = analyzer.analyze_packet_patterns() {
        info!("Packet Patterns:");
        println!("{}", patterns);
    }

    Ok(())
} 