use chrono::Utc;
use clap::Parser;
use km003c_lib::capture::{CaptureCollection, RawCapture, UsbDirection};
use rtshark::{Packet as RtSharkPacket, RTSharkBuilder};
use std::path::PathBuf;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser, Debug)]
#[command(author, version, about = "Process pcapng files and add to parquet collection")]
struct Cli {
    /// Input pcapng file to process
    #[arg(short, long)]
    input: PathBuf,

    /// Output parquet file (will be created if doesn't exist)
    #[arg(short, long, default_value = "raw_captures.parquet")]
    output: PathBuf,

    /// Device address (will be inferred from filename if not provided)
    #[arg(short, long)]
    device_address: Option<u8>,

    /// Session ID (will be inferred from filename if not provided)
    #[arg(long)]
    session_id: Option<String>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = Cli::parse();

    // Infer device address from filename if not provided
    let device_address = if let Some(addr) = args.device_address {
        addr
    } else {
        let filename = args.input.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if let Some(dot_pos) = filename.rfind('.') {
            let before_ext = &filename[..dot_pos];
            if let Some(second_dot_pos) = before_ext.rfind('.') {
                let potential_id = &before_ext[second_dot_pos + 1..];
                if let Ok(id) = potential_id.parse::<u8>() {
                    println!("Inferred device address from filename: {}", id);
                    id
                } else {
                    return Err("Could not infer device address from filename. Please provide --device-address".into());
                }
            } else {
                return Err("Could not infer device address from filename. Please provide --device-address".into());
            }
        } else {
            return Err("Could not infer device address from filename. Please provide --device-address".into());
        }
    };

    // Infer session ID from filename if not provided
    let session_id = if let Some(id) = args.session_id {
        id
    } else {
        let filename = args.input.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if let Some(dot_pos) = filename.rfind('.') {
            let before_ext = &filename[..dot_pos];
            before_ext.to_string()
        } else {
            filename.to_string()
        }
    };

    println!("Processing file: {:?}", args.input);
    println!("Device address: {}", device_address);
    println!("Session ID: {}", session_id);
    println!("Output file: {:?}", args.output);

    // Set up tshark with USB filter
    let display_filter = format!(
        "usb.device_address == {} && usb.transfer_type == 0x03 && usb.capdata",
        device_address
    );

    let file_path = args.input.to_str().ok_or("File path is not valid UTF-8")?;

    let mut rtshark = RTSharkBuilder::builder()
        .input_path(file_path)
        .display_filter(&display_filter)
        .spawn()?;

    let mut collection = CaptureCollection::new();
    let mut packet_count = 0;

    while let Some(packet) = rtshark.read()? {
        packet_count += 1;

        if let Ok(capture) = process_packet(packet, &session_id) {
            collection.add(capture);
        }
    }

    println!(
        "Processed {} packets, extracted {} captures",
        packet_count,
        collection.len()
    );

    // Save or append to parquet file
    if args.output.exists() {
        println!("Loading existing captures from {:?}", args.output);
        let mut existing = CaptureCollection::load_from_parquet(&args.output)?;

        // Check for duplicate session_id
        let existing_sessions = existing.session_ids();
        if existing_sessions.contains(&session_id) {
            eprintln!(
                "ERROR: Session ID '{}' already exists in {:?}. Aborting to prevent duplicates.",
                session_id, args.output
            );
            std::process::exit(1);
        }

        // Add new captures to existing collection
        for capture in collection.captures() {
            existing.add(capture.clone());
        }

        // Save combined collection
        existing.save_to_parquet(&args.output)?;
        println!(
            "Combined and saved {} total captures to {:?}",
            existing.len(),
            args.output
        );

        // Print statistics for combined collection
        let stats = existing.statistics();
        println!("\nCombined Statistics:");
        for (key, value) in stats {
            println!("  {}: {}", key, value);
        }
    } else {
        println!("Creating new parquet file at {:?}", args.output);
        collection.save_to_parquet(&args.output)?;

        // Print statistics
        let stats = collection.statistics();
        println!("\nStatistics:");
        for (key, value) in stats {
            println!("  {}: {}", key, value);
        }
    }

    Ok(())
}

fn process_packet(packet: RtSharkPacket, session_id: &str) -> Result<RawCapture> {
    // Extract frame number and timestamp
    let frame_num = packet
        .layer_name("frame")
        .and_then(|f| f.metadata("frame.number"))
        .and_then(|n| n.value().parse().ok())
        .unwrap_or(0);

    let timestamp = packet
        .layer_name("frame")
        .and_then(|f| f.metadata("frame.time_relative"))
        .and_then(|n| n.value().parse().ok())
        .unwrap_or(0.0);

    // Extract USB direction
    let usb_layer = packet.layer_name("usb").ok_or("Missing USB layer")?;
    let direction = match usb_layer.metadata("usb.endpoint_address.direction").map(|d| d.value()) {
        Some("0") => UsbDirection::HostToDevice,
        Some("1") => UsbDirection::DeviceToHost,
        _ => return Err("Unknown USB direction".into()),
    };

    // Extract hex payload
    let payload_hex = usb_layer.metadata("usb.capdata").ok_or("Missing usb.capdata")?.value();

    // Clean up hex string (remove colons)
    let clean_hex = payload_hex.replace(':', "");

    // Convert hex to bytes
    let data = hex::decode(&clean_hex).map_err(|e| format!("Failed to decode hex payload: {}", e))?;

    // Create capture with current datetime
    let added_datetime = Utc::now().to_rfc3339();

    let capture = RawCapture::new(
        session_id.to_string(),
        timestamp,
        direction,
        data,
        frame_num,
        added_datetime,
    );

    Ok(capture)
}
