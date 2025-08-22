use bytes::Bytes;
use clap::Parser;
use km003c_lib::{message::Packet, packet::RawPacket, pd::{parse_event_stream, EventPacket}};
use rtshark::RTSharkBuilder;
use std::path::PathBuf;
use usbpd::protocol_layer::message::{Message, header::{MessageType}};

#[derive(Parser, Debug)]
#[command(author, version, about = "Print PD message sequence from pcap captures" )]
struct Cli {
    /// Input pcapng file
    #[arg(short, long, default_value = "matching_record/wireshark_0.7.pcapng")]
    file: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let filename = cli.file;

    // Infer device address from filename as "*.ID.pcapng"
    let mut device_address: Option<u8> = None;
    if let Some(stem) = filename.file_stem().and_then(|s| s.to_str()) {
        if let Some(dot_pos) = stem.rfind('.') {
            let potential_id = &stem[dot_pos + 1..];
            if let Ok(id) = potential_id.parse::<u8>() {
                device_address = Some(id);
            }
        }
    }
    let device_address = device_address.ok_or("Could not infer device address from filename")?;

    let display_filter = format!(
        "usb.device_address == {} && usb.transfer_type == 0x03 && usb.capdata",
        device_address
    );
    let mut rtshark = RTSharkBuilder::builder()
        .input_path(filename.to_str().unwrap())
        .display_filter(&display_filter)
        .spawn()?;

    let mut index = 0u32;
    while let Some(packet) = rtshark.read()? {
        let usb_layer = match packet.layer_name("usb") {
            Some(l) => l,
            None => continue,
        };
        let payload_hex = match usb_layer.metadata("usb.capdata") {
            Some(m) => m.value(),
            None => continue,
        };
        let clean_hex = payload_hex.replace(':', "");
        let data = match hex::decode(&clean_hex) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let bytes = Bytes::from(data);
        if let Ok(raw_packet) = RawPacket::try_from(bytes) {
            if let Ok(pkt) = Packet::try_from(raw_packet) {
                if let Packet::PdRawData(data) = pkt {
                    if let Ok(events) = parse_event_stream(&data) {
                        for ev in events {
                            match ev {
                                EventPacket::Connection(ev) => {
                                    let action = match ev.action() {
                                        1 => "Attach",
                                        2 => "Detach",
                                        _ => "Other",
                                    };
                                    println!("{index:03}: Connection CC{} {action}", ev.cc_pin());
                                    index += 1;
                                }
                                EventPacket::PdMessage(msg) => {
                                    if let Ok(pd) = Message::from_bytes(&msg.pd_bytes) {
                                        let name = match pd.header.message_type() {
                                            MessageType::Control(c) => format!("{:?}", c),
                                            MessageType::Data(d) => format!("{:?}", d),
                                        };
                                        let dir = if msg.is_src_to_snk { "SRC->SNK" } else { "SNK->SRC" };
                                        println!("{index:03}: {dir} {name}");
                                        index += 1;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
