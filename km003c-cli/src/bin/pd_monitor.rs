use clap::Parser;
use km003c_lib::KM003C;
use km003c_lib::pd::{EventPacket, parse_event_stream};
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
#[command(author, version, about = "Monitor PD (Power Delivery) packets from POWER-Z KM003C")]
struct Args {
    /// Polling frequency in Hz (default: 1.0)
    #[arg(short, long, default_value = "1.0")]
    frequency: f64,

    /// Number of PD messages to capture (default: unlimited)
    #[arg(short, long)]
    count: Option<u64>,

    /// Optional file to save output
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
        info!("Will capture {} PD messages", count);
    } else {
        info!("Capturing PD messages until interrupted (Ctrl+C)");
    }

    let mut pd_message_count = 0u64;
    let start_time = SystemTime::now();

    loop {
        if let Some(max_count) = args.count {
            if pd_message_count >= max_count {
                break;
            }
        }

        timer.tick().await;

        match device.request_pd_data().await {
            Ok(pd_data) => {
                if pd_data.is_empty() {
                    continue;
                }

                if args.hex_only {
                    let output = hex::encode(&pd_data);
                    println!("{}", output);
                    if let Some(ref mut file) = output_file {
                        writeln!(file, "{}", output)?;
                        file.flush()?;
                    }
                    continue;
                }

                let events = parse_event_stream(&pd_data);
                for event in events {
                    let elapsed = start_time.elapsed().unwrap_or(Duration::ZERO);
                    let timestamp_str = if args.timestamp {
                        format!(" @ {:.6}s", elapsed.as_secs_f64())
                    } else {
                        String::new()
                    };

                    match &event {
                        EventPacket::PdMessage(_) => {
                            pd_message_count += 1;
                            let header = format!("\n=== PD Message #{}{} ===", pd_message_count, timestamp_str);
                            print_section(&header, &event, &mut output_file)?;
                        }
                        EventPacket::Connection(_) => {
                            let header = format!("\n--- Connection Event{} ---", timestamp_str);
                            print_section(&header, &event, &mut output_file)?;
                        }
                        EventPacket::Status(_) => {
                            let header = format!("\n--- Status Packet{} ---", timestamp_str);
                            print_section(&header, &event, &mut output_file)?;
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to request PD data: {}", e);
            }
        }
    }

    info!("Captured {} PD messages", pd_message_count);
    Ok(())
}

fn print_section(header: &str, event: &EventPacket, output_file: &mut Option<std::fs::File>) -> std::io::Result<()> {
    println!("{}\n{}", header, event);
    if let Some(file) = output_file {
        writeln!(file, "{}\n{}", header, event)?;
        file.flush()?;
    }
    Ok(())
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
