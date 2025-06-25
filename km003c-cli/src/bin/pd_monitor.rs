use clap::Parser;
use km003c_lib::KM003C;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write as IoWrite; // Renamed to avoid conflict with fmt::Write
use std::time::{Duration, SystemTime};
use tokio::time::interval;
use tracing::{error, info};

// --- Add this entire block for PD parsing ---
use std::convert::TryInto;
use std::fmt::Write as FmtWrite;
use usbpd::protocol_layer::message::{
    Message,
    pdo::{Augmented, PowerDataObject, SourceCapabilities},
};
// ------------------------------------------

#[derive(Parser, Debug)]
#[command(author, version, about = "Monitor PD (Power Delivery) packets from POWER-Z KM003C", long_about = None)]
struct Args {
    // ... (Your Args struct is unchanged) ...
    /// Polling frequency in Hz (default: 1.0)
    #[arg(short, long, default_value = "1.0")]
    frequency: f64,

    /// Number of packets to capture (default: unlimited)
    #[arg(short, long)]
    count: Option<u64>,

    /// Optional file to save hex data
    #[arg(short, long)]
    output: Option<String>,

    /// Just print hex without extra formatting
    #[arg(long)]
    hex_only: bool,

    /// Include timestamps in output
    #[arg(short, long)]
    timestamp: bool,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let log_level = if args.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(log_level).init();

    if args.frequency <= 0.0 {
        error!("Frequency must be positive");
        std::process::exit(1);
    }

    let mut device = KM003C::new().await?;
    info!("Connected to POWER-Z KM003C");

    let interval_ms = (1000.0 / args.frequency) as u64;
    let mut timer = interval(Duration::from_millis(interval_ms));

    let mut output_file = if let Some(ref path) = args.output {
        Some(OpenOptions::new().create(true).append(true).open(path)?)
    } else {
        None
    };

    info!("Starting PD monitoring at {:.1} Hz", args.frequency);
    if let Some(count) = args.count {
        info!("Will capture {} packets", count);
    } else {
        info!("Capturing packets until interrupted (Ctrl+C)");
    }

    let mut packet_count = 0u64;
    let start_time = SystemTime::now();

    loop {
        if let Some(max_count) = args.count {
            if packet_count >= max_count {
                break;
            }
        }

        timer.tick().await;

        match device.request_pd_data().await {
            Ok(pd_data) => {
                // If there's no data, it's just a poll response, so we skip.
                if pd_data.is_empty() {
                    continue;
                }

                if args.hex_only {
                    // --- HEX ONLY LOGIC (Unchanged) ---
                    let output = hex::encode(&pd_data);
                    println!("{}", output);
                    if let Some(ref mut file) = output_file {
                        writeln!(file, "{}", output)?;
                        file.flush()?;
                    }
                } else {
                    // --- NEW PD PARSING LOGIC ---
                    let formatted_packets = parse_and_format_pd_stream(&pd_data);

                    // Only process if the stream contained actual PD messages
                    if !formatted_packets.is_empty() {
                        for packet_str in formatted_packets {
                            packet_count += 1;
                            let elapsed = start_time.elapsed().unwrap_or(Duration::ZERO);
                            let timestamp_secs = elapsed.as_secs_f64();
                            let timestamp_str = if args.timestamp {
                                format!(" @ {:.6}s", timestamp_secs)
                            } else {
                                String::new()
                            };

                            // Print each parsed packet with a header
                            let final_output = format!("PD Packet #{}{}\n{}", packet_count, timestamp_str, packet_str);
                            println!("{}", final_output);

                            if let Some(ref mut file) = output_file {
                                writeln!(file, "{}", final_output)?;
                                file.flush()?;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to request PD data: {}", e);
            }
        }
    }

    info!("Captured {} PD packets", packet_count);
    Ok(())
}

// --- HELPER FUNCTION 1: Stream Parser ---
// This function now returns a Vec of formatted strings.
fn parse_and_format_pd_stream(mut stream: &[u8]) -> Vec<String> {
    const KM003C_HEADER_LEN: usize = 6;
    const POLLING_PACKET_LEN: usize = 12;

    let mut formatted_messages = Vec::new();

    while !stream.is_empty() {
        if stream.len() < KM003C_HEADER_LEN {
            break;
        }

        let wrapper_header = &stream[..KM003C_HEADER_LEN];
        let potential_payload = &stream[KM003C_HEADER_LEN..];

        let is_sop_packet = (wrapper_header[0] & 0x80) != 0;

        if is_sop_packet && potential_payload.len() >= 2 {
            let pd_header_bytes: [u8; 2] = potential_payload[0..2].try_into().unwrap();
            let pd_header_val = u16::from_le_bytes(pd_header_bytes);
            let message_type = pd_header_val & 0x1F;

            if message_type > 0 && message_type <= 0x16 {
                let num_objects = ((pd_header_val >> 12) & 0x07) as usize;
                let pd_message_len = 2 + num_objects * 4;
                let total_chunk_len = KM003C_HEADER_LEN + pd_message_len;

                if stream.len() >= total_chunk_len {
                    let pd_message_bytes = &stream[KM003C_HEADER_LEN..total_chunk_len];
                    let message = Message::from_bytes(pd_message_bytes);

                    let formatted_str =
                        if let Some(usbpd::protocol_layer::message::Data::SourceCapabilities(caps)) = &message.data {
                            format_source_capabilities(caps)
                        } else {
                            format!("  -> Parsed: {:?}", message)
                        };
                    formatted_messages.push(formatted_str);

                    stream = &stream[total_chunk_len..];
                    continue;
                }
            }
        }

        if stream.len() >= POLLING_PACKET_LEN {
            stream = &stream[POLLING_PACKET_LEN..];
        } else {
            break;
        }
    }
    formatted_messages
}

// --- HELPER FUNCTION 2: Pretty Printer for Source Capabilities ---
pub fn format_source_capabilities(caps: &SourceCapabilities) -> String {
    let mut output = String::new();
    write!(&mut output, "  -> Parsed:\n").unwrap(); // Indent to match debug output
    write!(&mut output, "    Source Power Capabilities:\n").unwrap();
    write!(
        &mut output,
        "      Flags: DRP: {}, Unconstrained: {}, USB Comm: {}, USB Suspend: {}, EPR Capable: {}\n",
        caps.dual_role_power(),
        caps.unconstrained_power(),
        caps.vsafe_5v().map_or(false, |p| p.usb_communications_capable()),
        caps.usb_suspend_supported(),
        caps.epr_mode_capable()
    )
    .unwrap();

    for (i, pdo) in caps.pdos().iter().enumerate() {
        let pdo_index = i + 1;
        let line = match pdo {
            PowerDataObject::FixedSupply(p) => {
                let voltage = p.raw_voltage() as f32 * 50.0 / 1000.0;
                let current = p.raw_max_current() as f32 * 10.0 / 1000.0;
                format!("Fixed:       {:.2} V @ {:.2} A", voltage, current)
            }
            PowerDataObject::VariableSupply(p) => {
                let min_v = p.raw_min_voltage() as f32 * 50.0 / 1000.0;
                let max_v = p.raw_max_voltage() as f32 * 50.0 / 1000.0;
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
                    let power = p.raw_pd_power() as f32;
                    format!("AVS (EPR):   {:.2} - {:.2} V up to {:.2} W", min_v, max_v, power)
                }
                Augmented::Unknown(raw) => format!("Unknown Augmented PDO (raw: 0x{:08x})", raw),
            },
            PowerDataObject::Unknown(raw) => format!("Unknown PDO (raw: 0x{:08x})", raw.0),
        };
        write!(&mut output, "      [{}] {}", pdo_index, line).unwrap();
        // Add newline if not the last element
        if i < caps.pdos().len() - 1 {
            write!(&mut output, "\n").unwrap();
        }
    }
    output
}
