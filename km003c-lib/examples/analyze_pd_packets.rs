use bytes::Bytes;
use clap::Parser;
use km003c_lib::{message::Packet, packet::RawPacket, pd::{parse_event_stream, EventPacket}};
use rtshark::{RTSharkBuilder};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(
        short,
        long,
        help = "Read from a .pcapng file",
        default_value = "wireshark"
    )]
    files: Vec<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut files_to_process = Vec::new();

    for path in cli.files {
        if path.is_dir() {
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("pcapng") {
                    files_to_process.push(path);
                }
            }
        } else if path.is_file() {
            files_to_process.push(path);
        }
    }

    for filename in files_to_process {
        println!("
--- Processing file: {} ---", filename.display());
        process_file(&filename)?;
    }

    Ok(())
}

fn process_file(filename: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut device_address: Option<u8> = None;
    if let Some(stem) = filename.file_stem().and_then(|s| s.to_str()) {
        if let Some(dot_pos) = stem.rfind('.') {
            let potential_id = &stem[dot_pos + 1..];
            if let Ok(id) = potential_id.parse::<u8>() {
                println!("Inferred device address from filename: {}", id);
                device_address = Some(id);
            }
        }
    }

    let device_address = match device_address {
        Some(addr) => addr,
        None => {
            eprintln!(
                "Could not infer device address for {}. Skipping.",
                filename.display()
            );
            return Ok(());
        }
    };

    let display_filter = format!(
        "usb.device_address == {} && usb.transfer_type == 0x03 && usb.capdata",
        device_address
    );

    let mut rtshark = RTSharkBuilder::builder()
        .input_path(filename.to_str().unwrap())
        .display_filter(&display_filter)
        .spawn()?;

    while let Some(packet) = rtshark.read()? {
        let usb_layer = packet.layer_name("usb").unwrap();

        let payload_hex = usb_layer
            .metadata("usb.capdata")
            .ok_or("Missing usb.capdata")?
            .value();
        let clean_hex = payload_hex.replace(':', "");
        let data =
            hex::decode(&clean_hex).map_err(|e| format!("Failed to decode hex payload: {}", e))?;
        let bytes = Bytes::from(data);

        match RawPacket::try_from(bytes) {
            Ok(raw_packet) => match Packet::try_from(raw_packet) {
                Ok(Packet::PdRawData(data)) => {
                    println!("{}", hex::encode(&data));
                }
                _ => {}
                _ => {}
            },
            Err(e) => {
                println!("[ERROR] Failed to parse raw packet: {}", e);
            }
        }
    }
    Ok(())
}
