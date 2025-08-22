use bytes::Bytes;
use clap::Parser;
use km003c_lib::{message::Packet, packet::RawPacket, pd::parse_event_stream};
use rtshark::RTSharkBuilder;
use std::fmt::Write;
use std::path::PathBuf;
use usbpd::protocol_layer::message::pdo::{Augmented, PowerDataObject, SourceCapabilities};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, help = "Read from a .pcapng file", default_value = "wireshark")]
    files: Vec<PathBuf>,

    #[arg(short, long, help = "Print verbose output")]
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
            eprintln!("Could not infer device address for {}. Skipping.", filename.display());
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

        let payload_hex = usb_layer.metadata("usb.capdata").ok_or("Missing usb.capdata")?.value();
        let clean_hex = payload_hex.replace(':', "");
        let data = hex::decode(&clean_hex).map_err(|e| format!("Failed to decode hex payload: {}", e))?;
        let bytes = Bytes::from(data);

        match RawPacket::try_from(bytes) {
            Ok(raw_packet) => match Packet::try_from(raw_packet) {
                                Ok(packet) => {
                    let pd_data = match packet {
                        Packet::PdRawData(data) => Some(data),
                        Packet::CombinedAdcPdData { pd_data, .. } => Some(pd_data),
                        _ => None,
                    };

                    if let Some(data) = pd_data {
                        if verbose {
                            match parse_event_stream(&data) {
                                Ok(events) => {
                                    for event in events {
                                        println!("[PD EVENT] {}", event);
                                    }
                                }
                                Err(e) => {
                                    println!("[PD EVENT] Error parsing events: {:?}", e);
                                }
                            }
                        } else {
                            println!("{}", hex::encode(&data));
                        }
                    }
                }
            },
            Err(e) => {
                println!("[ERROR] Failed to parse raw packet: {}", e);
            }
        }
    }
    Ok(())
}

pub fn format_source_capabilities(caps: &SourceCapabilities) -> String {
    let mut output = String::new();

    writeln!(&mut output, "Source Power Capabilities:").unwrap();

    writeln!(
        &mut output,
        "  Flags: DRP: {}, Unconstrained: {}, USB Comm: {}, USB Suspend: {}, EPR Capable: {}",
        caps.dual_role_power(),
        caps.unconstrained_power(),
        caps.vsafe_5v().map_or(false, |p| p.usb_communications_capable()),
        caps.usb_suspend_supported(),
        caps.epr_mode_capable()
    )
    .unwrap();

    for (i, pdo) in caps.pdos().iter().enumerate() {
        let pdo_index = i + 1;

        // Use raw value methods and apply scaling factors manually.
        let line = match pdo {
            PowerDataObject::FixedSupply(p) => {
                let voltage = p.raw_voltage() as f32 * 50.0 / 1000.0;
                let current = p.raw_max_current() as f32 * 10.0 / 1000.0;
                format!("Fixed:       {:.2} V @ {:.2} A", voltage, current)
            }
            PowerDataObject::VariableSupply(p) => {
                let min_v = p.raw_min_voltage() as f32 * 50.0 / 1000.0;
                let max_v = p.raw_max_voltage() as f32 * 100.0 / 1000.0;
                let current = p.raw_max_current() as f32 * 10.0 / 1000.0;
                format!("Variable:    {:.2} - {:.2} V @ {:.2} A", min_v, max_v, current)
            }
            PowerDataObject::Battery(p) => {
                let min_v = p.raw_min_voltage() as f32 * 50.0 / 1000.0;
                let max_v = p.raw_max_voltage() as f32 * 50.0 / 1000.0;
                let power = p.raw_max_power() as f32 * 250.0 / 1000.0;
                format!("Battery:     {:.2} - {:.2} V @ {:.2} W", min_v, max_v, power)
            }
            PowerDataObject::Augmented(augmented) => match augmented {
                Augmented::Spr(p) => {
                    let min_v = p.raw_min_voltage() as f32 * 100.0 / 1000.0;
                    let max_v = p.raw_max_voltage() as f32 * 100.0 / 1000.0;
                    let current = p.raw_max_current() as f32 * 50.0 / 1000.0;
                    let mut pps_str = format!("PPS:         {:.2} - {:.2} V @ {:.2} A", min_v, max_v, current);
                    if p.pps_power_limited() {
                        pps_str.push_str(" (Power Limited)");
                    }
                    pps_str
                }
                Augmented::Epr(p) => {
                    let min_v = p.raw_min_voltage() as f32 * 100.0 / 1000.0;
                    let max_v = p.raw_max_voltage() as f32 * 100.0 / 1000.0;
                    let power = p.raw_pd_power() as f32; // This is already in full Watts
                    format!("AVS (EPR):   {:.2} - {:.2} V up to {:.2} W", min_v, max_v, power)
                }
                Augmented::Unknown(raw) => format!("Unknown Augmented PDO (raw: 0x{:08x})", raw),
            },
            PowerDataObject::Unknown(raw) => format!("Unknown PDO (raw: 0x{:08x})", raw.0),
        };

        writeln!(&mut output, "  [{}] {}", pdo_index, line).unwrap();
    }

    output
}
