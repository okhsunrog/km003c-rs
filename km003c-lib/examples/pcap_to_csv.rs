use bytes::Bytes;
use clap::Parser;
use km003c_lib::{message::Packet, packet::RawPacket};
use std::{fs::File, io::Write, path::PathBuf, process::Command};

use csv::Writer;
use serde_json::Value;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser, Debug)]
#[command(author, version, about = "Log pcapng packets to CSV and Markdown")]
struct Cli {
    /// Optional USB device address filter; inferred from filename if not supplied
    #[arg(short, long)]
    device_address: Option<u8>,
    /// Optional USB transfer type filter
    #[arg(short = 't', long)]
    transfer_type: Option<u8>,
    /// Only include packets that contain usb.capdata
    #[arg(long)]
    capdata_only: bool,
    /// Input pcapng file
    #[arg(short, long)]
    file: PathBuf,
    /// Output CSV file
    #[arg(long, default_value = "packet_log.csv")]
    csv: PathBuf,
    /// Output Markdown file
    #[arg(long, default_value = "protocol_flow.md")]
    md: PathBuf,
}

fn main() -> Result<()> {
    let mut cli = Cli::parse();

    // Infer device address from filename if not provided
    if cli.device_address.is_none() {
        if let Some(filename) = cli.file.file_name().and_then(|s| s.to_str()) {
            if let Some(dot_pos) = filename.rfind('.') {
                let before_ext = &filename[..dot_pos];
                if let Some(second_dot_pos) = before_ext.rfind('.') {
                    if let Ok(id) = before_ext[second_dot_pos + 1..].parse::<u8>() {
                        cli.device_address = Some(id);
                    }
                }
            }
        }
    }

    let mut filter_parts = Vec::new();
    if let Some(addr) = cli.device_address {
        filter_parts.push(format!("usb.device_address == {}", addr));
    }
    if let Some(tt) = cli.transfer_type {
        filter_parts.push(format!("usb.transfer_type == 0x{:02x}", tt));
    }
    if cli.capdata_only {
        filter_parts.push("usb.capdata".to_string());
    }
    let display_filter = filter_parts.join(" && ");

    let file_path = cli.file.to_str().ok_or("File path is not valid UTF-8")?;

    let mut cmd = Command::new("tshark");
    cmd.env("TSHARK_RUN_AS_ROOT", "1")
        .arg("-r")
        .arg(file_path)
        .arg("-T")
        .arg("json");
    if !display_filter.is_empty() {
        cmd.arg("-Y").arg(&display_filter);
    }
    let output = cmd.output()?;

    let packets: Value = serde_json::from_slice(&output.stdout)?;
    let array = packets.as_array().ok_or("Unexpected JSON output from tshark")?;

    let mut wtr = Writer::from_path(&cli.csv)?;
    wtr.write_record(["frame", "time", "direction", "hex", "raw_packet", "packet"])?;

    let mut md = File::create(&cli.md)?;
    writeln!(
        md,
        "# Protocol Flow\n\nSource: `{}`\n\n| Frame | Time (s) | Dir | Hex | RawPacket | Packet |\n|---|---|---|---|---|---|",
        cli.file.display()
    )?;

    let mut count = 0;
    for (idx, packet) in array.iter().enumerate() {
        count += 1;
        let info = process_packet(packet, idx + 1)?;
        wtr.write_record([
            info.frame_num.to_string(),
            format!("{:.6}", info.timestamp),
            info.direction.to_string(),
            info.hex.clone(),
            info.raw_packet.clone(),
            info.packet.clone(),
        ])?;
        writeln!(
            md,
            "| {} | {:.6} | {} | `{}` | `{}` | `{}` |",
            info.frame_num, info.timestamp, info.direction, info.hex, info.raw_packet, info.packet
        )?;
    }

    wtr.flush()?;
    println!(
        "Processed {} packets. CSV written to {:?}, Markdown to {:?}",
        count, cli.csv, cli.md
    );
    Ok(())
}

struct PacketInfo {
    frame_num: usize,
    timestamp: f64,
    direction: String,
    hex: String,
    raw_packet: String,
    packet: String,
}

fn process_packet(packet: &Value, packet_num: usize) -> Result<PacketInfo> {
    let layers = &packet["_source"]["layers"];
    let frame = &layers["frame"];
    let frame_num = frame["frame.number"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or(packet_num);
    let timestamp = frame["frame.time_relative"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);

    let usb = &layers["usb"];
    let direction = match usb["usb.endpoint_address_tree"]["usb.endpoint_address.direction"].as_str() {
        Some("0") => "H->D",
        Some("1") => "D->H",
        _ => "?",
    }
    .to_string();

    let mut hex = String::new();
    let mut raw_packet_str = String::from("-");
    let mut packet_str = String::from("-");

    if let Some(payload_hex) = layers["usb.capdata"].as_str() {
        hex = payload_hex.replace(':', "");
        if let Ok(data) = hex::decode(&hex) {
            let bytes = Bytes::from(data.clone());
            match RawPacket::try_from(bytes.clone()) {
                Ok(rp) => {
                    raw_packet_str = format!("{:?}", rp);
                    match Packet::try_from(rp.clone()) {
                        Ok(p) => packet_str = format!("{:?}", p),
                        Err(e) => packet_str = format!("Err({})", e),
                    }
                }
                Err(e) => {
                    raw_packet_str = format!("Err({})", e);
                }
            }
        }
    }

    Ok(PacketInfo {
        frame_num,
        timestamp,
        direction,
        hex,
        raw_packet: raw_packet_str,
        packet: packet_str,
    })
}
