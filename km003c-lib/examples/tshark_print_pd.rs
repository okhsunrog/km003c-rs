use bytes::Bytes;
use rtshark::RTSharkBuilder;
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

    while let Some(packet) = rtshark.read()? {
            let usb_layer = packet.layer_name("usb").unwrap();

    let payload_hex = usb_layer.metadata("usb.capdata").ok_or("Missing usb.capdata")?.value();
    let clean_hex = payload_hex.replace(':', "");
    let data = hex::decode(&clean_hex).map_err(|e| format!("Failed to decode hex payload: {}", e))?;
    let bytes = Bytes::from(data);

    if let Ok(raw_packet) = RawPacket::try_from(bytes) {
        if let Ok(packet) = Packet::try_from(raw_packet) {
            match packet {
                Packet::PdRawData(data) => println!("PD raw data: {}", hex::encode(data)),
                _ => {}
            }
        }
    }

    }
    Ok(())
}

