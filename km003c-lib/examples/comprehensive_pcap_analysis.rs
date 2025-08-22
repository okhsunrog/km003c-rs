use bytes::Bytes;
use clap::Parser;
use km003c_lib::{message::Packet, packet::RawPacket};
use std::{fs::File, io::Write, path::PathBuf, process::Command};

use csv::Writer;
use serde_json::Value;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser, Debug)]
#[command(author, version, about = "Comprehensive KM003C Protocol Analysis - Captures ALL USB traffic with detailed analysis")]
struct Cli {
    /// Input pcapng file
    #[arg(short, long)]
    file: PathBuf,
    /// Output CSV file
    #[arg(long, default_value = "comprehensive_analysis.csv")]
    csv: PathBuf,
    /// Output Markdown file
    #[arg(long, default_value = "comprehensive_analysis.md")]
    md: PathBuf,
    /// Output detailed analysis file
    #[arg(long, default_value = "detailed_analysis.txt")]
    analysis: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let file_path = cli.file.to_str().ok_or("File path is not valid UTF-8")?;

    // Capture ALL USB traffic - no filters!
    let mut cmd = Command::new("tshark");
    cmd.env("TSHARK_RUN_AS_ROOT", "1")
        .arg("-r")
        .arg(file_path)
        .arg("-T")
        .arg("json")
        .arg("-Y")  // Only filter for USB traffic, but capture everything
        .arg("usb"); // This captures ALL USB packets (control, data, interrupt, etc.)

    let output = cmd.output()?;

    let packets: Value = serde_json::from_slice(&output.stdout)?;
    let array = packets.as_array().ok_or("Unexpected JSON output from tshark")?;

    // Enhanced CSV with comprehensive fields
    let mut wtr = Writer::from_path(&cli.csv)?;
    wtr.write_record([
        "frame", "time", "usb_transfer_type", "usb_endpoint", "direction", 
        "usb_setup_data", "usb_capdata", "hex_data", "raw_packet", "packet", 
        "event_detail", "analysis_notes", "data_source", "protocol_layer"
    ])?;

    // Enhanced Markdown
    let mut md = File::create(&cli.md)?;
    writeln!(
        md,
        "# Comprehensive KM003C Protocol Analysis\n\nSource: `{}`\n\n| Frame | Time | USB Type | Endpoint | Dir | Setup | Data | Hex | RawPacket | Packet | EventDetail | Analysis | Source | Layer |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
        cli.file.display()
    )?;

    // Detailed analysis file
    let mut analysis_file = File::create(&cli.analysis)?;
    writeln!(analysis_file, "# Detailed KM003C Protocol Analysis\n")?;
    writeln!(analysis_file, "Source: {}\n", cli.file.display())?;
    writeln!(analysis_file, "Total packets captured: {}\n", array.len())?;

    let mut count = 0;
    let mut control_transfers = 0;
    let mut data_transfers = 0;
    let mut interrupt_transfers = 0;
    let mut bulk_transfers = 0;

    for (idx, packet) in array.iter().enumerate() {
        count += 1;
        let info = process_packet_comprehensive(packet, idx + 1)?;
        
        // Count transfer types
        match info.usb_transfer_type.as_str() {
            "0x02" => control_transfers += 1,
            "0x03" => interrupt_transfers += 1,
            "0x01" => data_transfers += 1,
            "0x00" => control_transfers += 1,
            _ => {}
        }

        // Enhanced event analysis
        let (event_detail, analysis_notes, data_source, protocol_layer) = analyze_packet_comprehensive(&info)?;

        let hex_print = info.hex_data.to_lowercase();
        wtr.write_record([
            info.frame_num.to_string(),
            format!("{:.6}", info.timestamp),
            info.usb_transfer_type.clone(),
            info.usb_endpoint.clone(),
            info.direction.clone(),
            info.usb_setup_data.clone(),
            info.usb_capdata.clone(),
            hex_print.clone(),
            info.raw_packet.clone(),
            info.packet.clone(),
            event_detail.clone(),
            analysis_notes.clone(),
            data_source.clone(),
            protocol_layer.clone(),
        ])?;

        writeln!(
            md,
            "| {} | {:.6} | {} | {} | {} | {} | {} | `{}` | `{}` | `{}` | `{}` | `{}` | {} | {} |",
            info.frame_num, info.timestamp, info.usb_transfer_type, info.usb_endpoint, 
            info.direction, info.usb_setup_data, info.usb_capdata, hex_print, 
            info.raw_packet, info.packet, event_detail.replace('|', "\\|").replace('`', "'"),
            analysis_notes.replace('|', "\\|").replace('`', "'"), data_source, protocol_layer
        )?;

        // Write detailed analysis
        writeln!(analysis_file, "## Frame {} - {:.6}s\n", info.frame_num, info.timestamp)?;
        writeln!(analysis_file, "**USB Transfer Type:** {} ({})", info.usb_transfer_type, get_transfer_type_description(&info.usb_transfer_type))?;
        writeln!(analysis_file, "**Endpoint:** {} ({})", info.usb_endpoint, get_endpoint_description(&info.usb_endpoint))?;
        writeln!(analysis_file, "**Direction:** {} ({})", info.direction, get_direction_description(&info.direction))?;
        writeln!(analysis_file, "**Setup Data:** {}", info.usb_setup_data)?;
        writeln!(analysis_file, "**Data:** {}", info.usb_capdata)?;
        writeln!(analysis_file, "**Analysis:** {}", analysis_notes)?;
        writeln!(analysis_file, "**Data Source:** {}", data_source)?;
        writeln!(analysis_file, "**Protocol Layer:** {}\n", protocol_layer)?;
    }

    // Write summary statistics
    writeln!(analysis_file, "## Summary Statistics\n")?;
    writeln!(analysis_file, "- **Total Packets:** {}", count)?;
    writeln!(analysis_file, "- **Control Transfers:** {}", control_transfers)?;
    writeln!(analysis_file, "- **Data Transfers:** {}", data_transfers)?;
    writeln!(analysis_file, "- **Interrupt Transfers:** {}", interrupt_transfers)?;
    writeln!(analysis_file, "- **Bulk Transfers:** {}", bulk_transfers)?;

    wtr.flush()?;
    println!(
        "Processed {} packets. CSV written to {:?}, Markdown to {:?}, Analysis to {:?}",
        count, cli.csv, cli.md, cli.analysis
    );
    println!("Transfer types: Control={}, Data={}, Interrupt={}, Bulk={}", 
             control_transfers, data_transfers, interrupt_transfers, bulk_transfers);
    Ok(())
}

#[derive(Debug)]
struct ComprehensivePacketInfo {
    frame_num: usize,
    timestamp: f64,
    usb_transfer_type: String,
    usb_endpoint: String,
    direction: String,
    usb_setup_data: String,
    usb_capdata: String,
    hex_data: String,
    raw_packet: String,
    packet: String,
}

fn process_packet_comprehensive(packet: &Value, packet_num: usize) -> Result<ComprehensivePacketInfo> {
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
    
    // Enhanced USB information extraction
    let usb_transfer_type = usb["usb.transfer_type"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    
    let usb_endpoint = if let Some(endpoint) = usb.get("usb.endpoint_address") {
        endpoint.as_str().unwrap_or("unknown").to_string()
    } else {
        "N/A".to_string()
    };

    let direction = match usb["usb.endpoint_address_tree"]["usb.endpoint_address.direction"].as_str() {
        Some("0") => "H->D",
        Some("1") => "D->H",
        _ => "?",
    }.to_string();

    let usb_setup_data = if let Some(setup_data) = layers.get("Setup Data") {
        // Extract setup data from the separate "Setup Data" section
        if let Some(bm_request_type) = setup_data.get("usb.bmRequestType") {
            let bm_request_type = bm_request_type.as_str().unwrap_or("0x00");
            let b_request = setup_data.get("usb.setup.bRequest").and_then(|v| v.as_str()).unwrap_or("0");
            let w_value = setup_data.get("usb.setup.wValue").and_then(|v| v.as_str()).unwrap_or("0x0000");
            let w_index = setup_data.get("usb.setup.wIndex").and_then(|v| v.as_str()).unwrap_or("0x0000");
            let w_length = setup_data.get("usb.setup.wLength").and_then(|v| v.as_str()).unwrap_or("0");
            format!("{}:{}:{}:{}:{}", bm_request_type, b_request, w_value, w_index, w_length)
        } else {
            "Setup data present but unparseable".to_string()
        }
    } else {
        "N/A".to_string()
    };

    let usb_capdata = if let Some(capdata) = usb.get("usb.capdata") {
        capdata.as_str().unwrap_or("").to_string()
    } else {
        "N/A".to_string()
    };

    let mut hex_data = String::new();
    let mut raw_packet_str = String::from("-");
    let mut packet_str = String::from("-");

    // Try to parse as KM003C packet if we have data
    if !usb_capdata.is_empty() && usb_capdata != "N/A" {
        hex_data = usb_capdata.replace(':', "");
        if let Ok(data) = hex::decode(&hex_data) {
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

    Ok(ComprehensivePacketInfo {
        frame_num,
        timestamp,
        usb_transfer_type,
        usb_endpoint,
        direction,
        usb_setup_data,
        usb_capdata,
        hex_data,
        raw_packet: raw_packet_str,
        packet: packet_str,
    })
}

fn analyze_packet_comprehensive(info: &ComprehensivePacketInfo) -> Result<(String, String, String, String)> {
    let mut event_detail = String::new();
    let mut analysis_notes = String::new();
    let mut data_source = String::new();
    let mut protocol_layer = String::new();

    // Analyze based on USB transfer type
    match info.usb_transfer_type.as_str() {
        "0x02" | "0x00" => {
            protocol_layer = "USB Control Transfer".to_string();
            if !info.usb_setup_data.is_empty() && info.usb_setup_data != "N/A" && !info.usb_setup_data.contains("Setup data present but unparseable") {
                data_source = "USB Setup Stage".to_string();
                analysis_notes = analyze_setup_data(&info.usb_setup_data);
            } else {
                data_source = "USB Data Stage".to_string();
                analysis_notes = "Control transfer data stage".to_string();
            }
        }
        "0x03" => {
            protocol_layer = "USB Interrupt Transfer".to_string();
            data_source = "Device Interrupt Endpoint".to_string();
            analysis_notes = "High-priority data transfer (ADC, PD, status)".to_string();
        }
        "0x01" => {
            protocol_layer = "USB Isochronous Transfer".to_string();
            data_source = "Real-time Data Stream".to_string();
            analysis_notes = "Time-critical data transfer".to_string();
        }
        _ => {
            protocol_layer = "Unknown USB Transfer".to_string();
            data_source = "Unknown".to_string();
            analysis_notes = "Unrecognized transfer type".to_string();
        }
    }

    // Try to parse KM003C protocol data
    if !info.hex_data.is_empty() {
        match hex::decode(&info.hex_data) {
            Ok(bytes) => {
                match RawPacket::try_from(Bytes::from(bytes)) {
                    Ok(raw_pkt) => {
                        // Analyze the raw packet
                        let (packet_analysis, packet_source) = analyze_raw_packet(&raw_pkt);
                        analysis_notes = format!("{} | {}", analysis_notes, packet_analysis);
                        data_source = format!("{} | {}", data_source, packet_source);
                        
                        // Try to parse as high-level packet
                        match Packet::try_from(raw_pkt) {
                            Ok(pkt) => {
                                event_detail = format!("{:?}", pkt);
                                protocol_layer = format!("{} | KM003C Protocol", protocol_layer);
                            }
                            Err(e) => {
                                event_detail = format!("Parse error: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        event_detail = format!("Raw packet error: {:?}", e);
                    }
                }
            }
            Err(_) => {
                event_detail = "Invalid hex data".to_string();
            }
        }
    } else {
        event_detail = "No data payload".to_string();
    }

    Ok((event_detail, analysis_notes, data_source, protocol_layer))
}

fn analyze_raw_packet(raw_pkt: &RawPacket) -> (String, String) {
    let mut analysis = String::new();
    let mut source = String::new();

    match raw_pkt {
        RawPacket::Ctrl { header, payload } => {
            source = "KM003C Control Packet".to_string();
            analysis = format!("Ctrl: Type={}, Flag={}, ID={}, Attr={}", 
                             header.packet_type(), header.flag(), header.id(), header.attribute());
        }
        RawPacket::Data { header, extended, payload } => {
            source = "KM003C Data Packet".to_string();
            analysis = format!("Data: Type={}, Flag={}, ID={}, Attr={}, Size={}", 
                             header.packet_type(), header.flag(), header.id(), 
                             extended.attribute(), extended.size());
        }
    }

    (analysis, source)
}

fn analyze_setup_data(setup_data: &str) -> String {
    if setup_data.contains(':') {
        // Parse the new format: "0x80:6:0x0001:0x0000:18"
        let parts: Vec<&str> = setup_data.split(':').collect();
        if parts.len() >= 5 {
            let bm_request_type = parts[0];
            let b_request = parts[1];
            let w_value = parts[2];
            let w_index = parts[3];
            let w_length = parts[4];
            
            // Decode the request type
            let direction = if bm_request_type.contains("0x80") { "Device->Host" } else { "Host->Device" };
            let request_type = if bm_request_type.contains("0x00") { "Standard" } else if bm_request_type.contains("0x20") { "Class" } else { "Vendor" };
            
            // Decode common requests
            let request_name = match b_request {
                "6" => "Get Descriptor",
                "5" => "Set Address", 
                "9" => "Set Configuration",
                "0" => "Get Status",
                "1" => "Clear Feature",
                "3" => "Set Feature",
                _ => "Unknown"
            };
            
            return format!("{} {} Request: {} (Val={}, Idx={}, Len={})", 
                          direction, request_type, request_name, w_value, w_index, w_length);
        }
    }
    "Setup data analysis failed".to_string()
}

fn get_transfer_type_description(transfer_type: &str) -> &'static str {
    match transfer_type {
        "0x00" => "Control",
        "0x01" => "Isochronous", 
        "0x02" => "Control",
        "0x03" => "Interrupt",
        "0x04" => "Bulk",
        _ => "Unknown"
    }
}

fn get_endpoint_description(endpoint: &str) -> String {
    if endpoint == "N/A" { return "N/A".to_string(); }
    
    if let Ok(addr) = u8::from_str_radix(endpoint, 16) {
        let number = addr & 0x0F;
        let direction = if (addr & 0x80) != 0 { "IN" } else { "OUT" };
        return format!("EP{}{}", number, direction);
    }
    "Invalid".to_string()
}

fn get_direction_description(direction: &str) -> &'static str {
    match direction {
        "H->D" => "Host to Device",
        "D->H" => "Device to Host", 
        _ => "Unknown"
    }
}
