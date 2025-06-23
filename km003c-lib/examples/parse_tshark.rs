use bytes::Bytes;
use clap::Parser;
use rtshark::{Packet as RtSharkPacket, RTSharkBuilder};
use std::path::PathBuf;

use km003c_lib::packet::RawPacket;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    device_address: Option<u8>,
    #[arg(short, long, help = "Read from a .pcapng file")]
    file: PathBuf,
}

fn main() -> Result<()> {
    let mut cli = Cli::parse();

    // Try to infer device address from filename if not provided
    if cli.device_address.is_none() {
        let filename = cli.file.file_name().and_then(|s| s.to_str()).unwrap_or("");
        // Look for pattern like "filename.16.pcapng" where 16 is the device address
        // Simple parsing without regex
        if let Some(dot_pos) = filename.rfind('.') {
            let before_ext = &filename[..dot_pos];
            if let Some(second_dot_pos) = before_ext.rfind('.') {
                let potential_id = &before_ext[second_dot_pos + 1..];
                if let Ok(id) = potential_id.parse::<u8>() {
                    println!("Inferred device address from filename: {}", id);
                    cli.device_address = Some(id);
                }
            }
        }
    }

    let device_address = cli.device_address.ok_or("Device address is required. Provide it with -d/--device-address or name the input file like 'capture.<id>.pcapng'")?;

    // Set up tshark with USB filter
    let display_filter = format!(
        "usb.device_address == {} && usb.transfer_type == 0x03 && usb.capdata",
        device_address
    );

    let file_path = cli.file.to_str().ok_or("File path is not valid UTF-8")?;

    let mut rtshark = RTSharkBuilder::builder()
        .input_path(file_path)
        .display_filter(&display_filter)
        .spawn()?;

    println!("Reading packets from file: {:?}", cli.file);
    println!("Device address: {}", device_address);
    println!("----------------------------------------");

    let mut packet_count = 0;
    while let Some(packet) = rtshark.read()? {
        packet_count += 1;
        process_packet(packet, packet_count)?;
    }

    println!("----------------------------------------");
    println!("Total packets processed: {}", packet_count);
    Ok(())
}

fn process_packet(packet: RtSharkPacket, packet_num: usize) -> Result<()> {
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
        Some("0") => "H->D",
        Some("1") => "D->H",
        _ => "???",
    };

    // Extract hex payload
    let payload_hex = usb_layer.metadata("usb.capdata").ok_or("Missing usb.capdata")?.value();

    // Clean up hex string (remove colons)
    let clean_hex = payload_hex.replace(':', "");

    // Convert hex to bytes
    let data = hex::decode(&clean_hex).map_err(|e| format!("Failed to decode hex payload: {}", e))?;
    let bytes = Bytes::from(data);

    // Print packet info
    println!(
        "Packet #{} (Frame {}) @ {:.6}s [{}]",
        packet_num, frame_num, timestamp, direction
    );
    println!("  Raw hex: {}", clean_hex);

    // Try to parse with km003c packet parser
    match RawPacket::try_from(bytes) {
        Ok(parsed_packet) => {
            println!("  Parsed:  {:?}", parsed_packet);

            // Print additional packet details
            println!("  Type:    {:?}", parsed_packet.packet_type());
            println!("  ID:      {}", parsed_packet.id());
            if parsed_packet.is_extended() {
                println!("  Extended: true");
                if let Some(ext_header) = parsed_packet.get_extended_header() {
                    println!("  Ext Header: {:?}", ext_header);
                }
            }
            if let Some(attr) = parsed_packet.get_attribute() {
                println!("  Attribute: {:?}", attr);
            }
            let payload_data = parsed_packet.get_payload_data();
            if !payload_data.is_empty() {
                println!("  Payload: {} bytes", payload_data.len());
            }
        }
        Err(e) => {
            println!("  Parse Error: {}", e);
        }
    }
    println!();

    Ok(())
}
