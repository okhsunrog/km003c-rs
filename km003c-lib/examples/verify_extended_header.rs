use bytes::Bytes;
use km003c_lib::packet::{ExtendedHeader, RawPacket};
use rtshark::RTSharkBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filenames = vec![
        "wireshark/rust_simple_logger.16.pcapng",
        "wireshark/orig_with_pd.13.pcapng",
        "wireshark/orig_open_close.16.pcapng",
        "wireshark/orig_adc_record.6.pcapng",
        "wireshark/orig_adc_50hz.6.pcapng",
        "wireshark/orig_adc_1000hz.6.pcapng",
    ];

    println!("Starting ExtendedHeader verification across all captures...");
    println!("The theory is that only PutData (0x41) packets should have a valid header.");
    println!("---------------------------------------------------------------------------");

    for filename in filenames {
        println!("\n--- Processing file: {} ---", filename);
        process_file(filename)?;
    }

    Ok(())
}

fn process_file(filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut device_address: Option<u8> = None;
    if let Some(dot_pos) = filename.rfind('.') {
        let before_ext = &filename[..dot_pos];
        if let Some(second_dot_pos) = before_ext.rfind('.') {
            let potential_id = &before_ext[second_dot_pos + 1..];
            if let Ok(id) = potential_id.parse::<u8>() {
                device_address = Some(id);
            }
        }
    }

    let device_address = device_address.ok_or("Could not infer device address")?;

    let display_filter = format!(
        "usb.device_address == {} && usb.transfer_type == 0x03 && usb.capdata",
        device_address
    );

    let mut rtshark = RTSharkBuilder::builder()
        .input_path(filename)
        .display_filter(&display_filter)
        .spawn()?;

    while let Some(packet) = rtshark.read()? {
        let usb_layer = packet.layer_name("usb").unwrap();
        let payload_hex = usb_layer.metadata("usb.capdata").ok_or("Missing usb.capdata")?.value();
        let clean_hex = payload_hex.replace(':', "");
        let data = hex::decode(&clean_hex)?;
        let bytes = Bytes::from(data);

        if let Ok(raw_packet) = RawPacket::try_from(bytes) {
            let payload = raw_packet.payload();
            if payload.len() >= 4 {
                if let Ok(header_bytes) = payload[..4].try_into() {
                    let potential_header = ExtendedHeader::from_bytes(header_bytes);
                    let expected_size = payload.len() - 4;

                    if potential_header.size() as usize == expected_size {
                        let ptype: u8 = raw_packet.packet_type().into();
                        println!(
                            "[MATCH FOUND] Packet Type: 0x{:02x}, Attribute: {:?}, Header: {:?}",
                            ptype,
                            potential_header.attribute(),
                            potential_header
                        );
                    }
                }
            }
        }
    }
    Ok(())
}
