use bytes::Bytes;
use clap::Parser;
use km003c_lib::{message::Packet, packet::RawPacket, pd::{parse_event_stream, EventPacket}};
use rtshark::RTSharkBuilder;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "Summarize PD event sequences in PutData packets" )]
struct Cli {
    /// Input pcapng files or directories
    #[arg(short, long, default_value = "matching_record/wireshark_0.7.pcapng")]
    files: Vec<PathBuf>,

    /// Print verbose output for each packet
    #[arg(short, long)]
    verbose: bool,
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
        println!("\n--- Processing file: {} ---", filename.display());
        process_file(&filename, cli.verbose)?;
    }
    Ok(())
}

fn process_file(filename: &PathBuf, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
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

    let mut pd_raw_sequences: HashMap<String, usize> = HashMap::new();
    let mut pd_status_sequences: HashMap<String, usize> = HashMap::new();

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
                match pkt {
                    Packet::PdRawData(data) => {
                        if let Ok(events) = parse_event_stream(&data) {
                            let seq = sequence_string(&events);
                            *pd_raw_sequences.entry(seq.clone()).or_default() += 1;
                            if verbose {
                                println!("PdRawData: {}", seq);
                            }
                        }
                    }
                    Packet::PdStatusData(data) => {
                        if let Ok(events) = parse_event_stream(&data) {
                            let seq = sequence_string(&events);
                            *pd_status_sequences.entry(seq.clone()).or_default() += 1;
                            if verbose {
                                println!("PdStatusData: {}", seq);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    println!("PdRawData combinations:");
    for (seq, count) in pd_raw_sequences.iter() {
        println!("  {:<10} {}", seq, count);
    }
    println!("PdStatusData combinations:");
    for (seq, count) in pd_status_sequences.iter() {
        println!("  {:<10} {}", seq, count);
    }
    Ok(())
}

fn sequence_string(events: &[EventPacket]) -> String {
    let mut parts = Vec::new();
    for ev in events {
        let ch = match ev {
            EventPacket::Connection(_) => 'C',
            EventPacket::Status(_) => 'S',
            EventPacket::PdMessage(_) => 'P',
        };
        parts.push(ch);
    }
    parts.iter().collect::<String>()
}
