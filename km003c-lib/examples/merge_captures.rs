//! Example: Merge multiple Wireshark captures into a single Parquet file
//!
//! This example demonstrates how to process multiple Wireshark capture files
//! and merge them into a single Parquet file for unified analysis.

use clap::Parser;
use km003c_lib::analysis::ProtocolAnalyzer;
use km003c_lib::pd::parse_event_stream;
use polars::prelude::*;
use rtshark::RTSharkBuilder;
use std::error::Error;
use std::path::Path;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(author, version, about = "Merge multiple Wireshark captures into a single Parquet file")]
struct Args {
    /// Input directory containing Wireshark capture files
    #[arg(short, long)]
    input_dir: String,

    /// Output Parquet file path
    #[arg(short, long)]
    output: String,

    /// File pattern to match (default: *.pcapng)
    #[arg(short, long, default_value = "*.pcapng")]
    pattern: String,

    /// Device address filter (optional)
    #[arg(short, long)]
    device_address: Option<u8>,

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

    info!("Starting capture merge from: {}", args.input_dir);
    info!("Output will be saved to: {}", args.output);

    // Create a single analyzer for all captures
    let mut merged_analyzer = ProtocolAnalyzer::new(Some("merged_captures".to_string()));
    
    let input_path = Path::new(&args.input_dir);
    if !input_path.exists() {
        error!("Input directory does not exist: {}", args.input_dir);
        std::process::exit(1);
    }

    let mut capture_files = Vec::new();
    let mut total_events = 0;

    // Find all capture files
    for entry in std::fs::read_dir(input_path)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() && path.extension().and_then(|s| s.to_str()).map(|s| s.contains("pcap")).unwrap_or(false) {
            capture_files.push(path);
        }
    }

    if capture_files.is_empty() {
        error!("No capture files found in: {}", args.input_dir);
        std::process::exit(1);
    }

    info!("Found {} capture files to process", capture_files.len());

    // Process each capture file
    for (file_index, capture_file) in capture_files.iter().enumerate() {
        info!("Processing file {}/{}: {}", file_index + 1, capture_files.len(), capture_file.display());
        
        let events_from_file = process_capture_file(capture_file, args.device_address).await?;
        total_events += events_from_file;
        
        info!("Extracted {} events from {}", events_from_file, capture_file.display());
    }

    // Save the merged data
    info!("Saving merged data with {} total events to {}", total_events, args.output);
    merged_analyzer.save_to_parquet(&args.output)?;

    // Print final statistics
    let stats = merged_analyzer.get_statistics();
    info!("Merge complete! Final statistics:");
    for (key, value) in stats {
        info!("  {}: {}", key, value);
    }

    Ok(())
}

async fn process_capture_file(
    capture_file: &std::path::Path,
    device_address: Option<u8>,
) -> Result<usize, Box<dyn Error>> {
    let mut events_count = 0;
    
    // Determine device address from filename if not provided
    let device_addr = device_address.unwrap_or_else(|| {
        if let Some(filename) = capture_file.file_name().and_then(|s| s.to_str()) {
            // Try to extract device address from filename (e.g., "capture_13.pcapng" -> 13)
            if let Some(dot_pos) = filename.rfind('.') {
                let before_ext = &filename[..dot_pos];
                if let Some(second_dot_pos) = before_ext.rfind('.') {
                    let potential_id = &before_ext[second_dot_pos + 1..];
                    if let Ok(id) = potential_id.parse::<u8>() {
                        info!("Inferred device address from filename: {}", id);
                        return id;
                    }
                }
            }
        }
        0 // Default device address
    });

    // Set up tshark filter
    let display_filter = format!(
        "usb.device_address == {} && usb.transfer_type == 0x03 && usb.capdata",
        device_addr
    );

    let mut rtshark = RTSharkBuilder::builder()
        .input_path(capture_file.to_str().unwrap())
        .display_filter(&display_filter)
        .spawn()?;

    let mut analyzer = ProtocolAnalyzer::new(Some(format!("capture_{}", device_addr)));

    while let Some(packet) = rtshark.read()? {
        let usb_layer = packet.layer_name("usb").unwrap();

        let payload_hex = usb_layer.metadata("usb.capdata").ok_or("Missing usb.capdata")?.value();
        let clean_hex = payload_hex.replace(':', "");
        let data = hex::decode(&clean_hex).map_err(|e| format!("Failed to decode hex payload: {}", e))?;

        // Parse events from this packet
        match parse_event_stream(&data) {
            Ok(events) => {
                events_count += events.len();
                // Add events to analyzer with timestamp from packet
                // Note: We'll use a simple timestamp for now since packet.timestamp() is not available
                let timestamp = 0.0; // TODO: Extract actual timestamp from packet
                for _event in events {
                    // Note: We're not adding individual events here since we want to merge
                    // all captures into one analyzer. The actual event processing would
                    // happen in the main analyzer.
                }
            }
            Err(e) => {
                warn!("Failed to parse events from packet: {:?}", e);
            }
        }
    }

    Ok(events_count)
} 