#[test]
fn verify_extended_header_in_captures() {
    let filenames = vec![
        "../wireshark/rust_simple_logger.16.pcapng",
        "../wireshark/orig_with_pd.13.pcapng",
        "../wireshark/orig_open_close.16.pcapng",
        "../wireshark/orig_adc_record.6.pcapng",
        "../wireshark/orig_adc_50hz.6.pcapng",
        "../wireshark/orig_adc_1000hz.6.pcapng",
    ];

    for filename in filenames {
        process_file(filename).unwrap();
    }
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

    let mut rtshark = rtshark::RTSharkBuilder::builder()
        .input_path(filename)
        .display_filter(&display_filter)
        .spawn()?;

    while let Some(packet) = rtshark.read()? {
        let usb_layer = packet.layer_name("usb").unwrap();
        let payload_hex = usb_layer.metadata("usb.capdata").ok_or("Missing usb.capdata")?.value();
        let clean_hex = payload_hex.replace(':', "");
        let data = hex::decode(&clean_hex)?;
        let bytes = bytes::Bytes::from(data);

        if let Ok(raw_packet) = km003c_lib::packet::RawPacket::try_from(bytes) {
            if let Some(ext) = raw_packet.get_extended_header() {
                let ptype: u8 = raw_packet.packet_type().into();
                assert!(
                    ptype == 0x41 || ptype == 0x44,
                    "Found a valid extended header in a packet that is not PutData or 0x44",
                );
                assert_eq!(ext.size() as usize, raw_packet.payload().len());
            }
        }
    }
    Ok(())
}
