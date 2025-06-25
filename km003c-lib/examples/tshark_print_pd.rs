use bytes::Bytes;
use rtshark::{Packet as RtSharkPacket, RTSharkBuilder};

use km003c_lib::{message::Packet, packet::RawPacket};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    let mut device_address: Option<u8> = None;
    let filename = "wireshark/orig_with_pd.13.pcapng";
    if let Some(dot_pos) = filename.rfind('.') {
        let before_ext = &filename[..dot_pos];
        if let Some(second_dot_pos) = before_ext.rfind('.') {
            let potential_id = &before_ext[second_dot_pos + 1..];
            if let Ok(id) = potential_id.parse::<u8>() {
                println!("Inferred device address from filename: {}", id);
                device_address = Some(id);
            }
        }
    }

    let device_address = device_address.unwrap();

    // Set up tshark with USB filter
    let display_filter = format!(
        "usb.device_address == {} && usb.transfer_type == 0x03 && usb.capdata",
        device_address
    );

    let mut rtshark = RTSharkBuilder::builder()
        .input_path(filename)
        .display_filter(&display_filter)
        .spawn()?;

    println!("Reading packets from file: {:?}", filename);
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
    // println!(
    //     "Packet #{} (Frame {}) @ {:.6}s [{}]",
    //     packet_num, frame_num, timestamp, direction
    // );
    // println!("  Raw hex: {}", clean_hex);

    // Try to parse with km003c packet parser
    if let Ok(raw_packet) = RawPacket::try_from(bytes) {
        if let Ok(packet) = Packet::try_from(raw_packet) {
            match packet {
                Packet::PdRawData(data) => println!("PD raw data: {}", hex::encode(data)),
                _ => {}
            }
        }
    }

    Ok(())
}
