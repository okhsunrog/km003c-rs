use std::time::{Duration, Instant};

use clap::Parser;
use km003c_lib::pd::PdEventData;
use km003c_lib::uom::si::electric_current::ampere;
use km003c_lib::uom::si::electric_potential::volt;
use km003c_lib::uom::si::power::watt;
use km003c_lib::uom::si::time::millisecond;
use km003c_lib::usbpd::protocol_layer::message::Payload;
use km003c_lib::usbpd::protocol_layer::message::data::source_capabilities::{
    Augmented, PowerDataObject, SourceCapabilities,
};
use km003c_lib::usbpd::protocol_layer::message::data::{self, Data};
use km003c_lib::usbpd::protocol_layer::message::extended::Extended;
use km003c_lib::{
    DecodedPdEvent, DecodedPdMessage, DeviceConfig, KM003C, Packet, PdChunkState, PdChunkStatus, PdDecodeFailure,
    PdSessionDecoder,
};

/// USB PD negotiation capture for POWER-Z KM003C.
///
/// PD capture only works reliably with the vendor interface. The HID interface
/// can crash the device when attempting PD operations.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Skip USB reset (defaults to true on macOS for compatibility).
    #[arg(long, default_value_t = cfg!(target_os = "macos"))]
    no_reset: bool,

    /// Force USB reset even on macOS (overrides --no-reset).
    #[arg(long)]
    reset: bool,

    /// Capture duration in seconds.
    #[arg(short, long, default_value = "20")]
    duration: u64,

    /// Show raw bytes for each message.
    #[arg(long)]
    raw: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    tracing_subscriber::fmt::init();

    let config = if args.no_reset && !args.reset {
        DeviceConfig::vendor().skip_reset()
    } else {
        DeviceConfig::vendor()
    };

    let mut device = KM003C::new(config).await?;
    let state = device.state().expect("vendor interface provides state");
    println!("{state}\n");

    println!("USB PD Negotiation Capture");
    println!("NOW: Disconnect and reconnect your USB-C load!");
    println!(
        "Capturing for {} seconds... (Press Ctrl+C to stop early)\n",
        args.duration
    );

    let start_time = Instant::now();
    let duration = Duration::from_secs(args.duration);
    let mut decoder = PdSessionDecoder::new();

    loop {
        if start_time.elapsed() >= duration {
            break;
        }

        if let Ok(packet) = device.request_pd_data().await
            && let Some(stream) = KM003C::extract_pd_events(&packet)
        {
            for event in &stream.events {
                if args.raw
                    && let PdEventData::PdMessage { wire_data, .. } = &event.data
                {
                    print_raw(event.timestamp.get::<millisecond>(), wire_data);
                }

                let decoded = decoder.decode_event(event);
                print_decoded(&decoded, decoder.source_capabilities());
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(30)) => {},
            _ = tokio::signal::ctrl_c() => {
                println!("\nInterrupted by user");
                break;
            }
        }
    }

    device.send(Packet::Disconnect).await?;
    println!("\nCapture complete.");
    Ok(())
}

fn print_raw(timestamp_ms: f64, wire_data: &[u8]) {
    print!("[{:>8.3}s] RAW[{}]: ", timestamp_ms / 1000.0, wire_data.len());
    for (index, byte) in wire_data.iter().enumerate() {
        if index > 0 && index % 16 == 0 {
            print!("\n                     ");
        }
        print!("{byte:02X} ");
    }
    println!();
}

fn print_decoded(decoded: &DecodedPdEvent, source_caps: Option<&SourceCapabilities>) {
    match decoded {
        DecodedPdEvent::Connect { timestamp } => {
            println!("[{:>8.3}s] ** CONNECT **", timestamp.get::<millisecond>() / 1000.0);
        }
        DecodedPdEvent::Disconnect { timestamp } => {
            println!("[{:>8.3}s] ** DISCONNECT **", timestamp.get::<millisecond>() / 1000.0);
        }
        DecodedPdEvent::Message(message) => print_message(message, source_caps),
        DecodedPdEvent::Chunk(status) => print_chunk_status(*status),
        DecodedPdEvent::Error(failure) => print_failure(failure),
    }
}

fn print_message(decoded: &DecodedPdMessage, source_caps: Option<&SourceCapabilities>) {
    let message = &decoded.message;
    println!(
        "[{:>8.3}s] SOP{}: {:<20} (ID={}, ROLE={:?}/{:?})",
        decoded.timestamp.get::<millisecond>() / 1000.0,
        decoded.sop,
        format!("{:?}", message.header.message_type()),
        message.header.message_id(),
        message.header.port_power_role(),
        message.header.port_data_role(),
    );

    match &message.payload {
        Some(Payload::Data(Data::SourceCapabilities(capabilities))) => {
            print_capabilities(capabilities.pdos(), "SPR Source Capabilities");
        }
        Some(Payload::Data(Data::Request(request))) => print_request(request, source_caps),
        Some(Payload::Data(Data::EprMode(mode))) => println!("             EPR Mode: {mode:?}"),
        Some(Payload::Data(Data::Unknown)) => println!("             Unknown Data Message"),
        Some(Payload::Data(data)) => println!("             Data: {data:?}"),
        Some(Payload::Extended(Extended::EprSourceCapabilities(pdos))) => {
            print_capabilities(pdos.as_slice(), "EPR Source Capabilities");
        }
        Some(Payload::Extended(Extended::ExtendedControl(control))) => println!(
            "             Extended Control: {:?} (data=0x{:02X})",
            control.message_type(),
            control.data()
        ),
        Some(Payload::Extended(extended)) => println!("             Extended: {extended:?}"),
        None => {}
    }
}

fn print_chunk_status(status: PdChunkStatus) {
    let timestamp = status.timestamp.get::<millisecond>() / 1000.0;
    match status.state {
        PdChunkState::Request { chunk_number } => println!(
            "[{timestamp:>8.3}s] SOP{}: Chunk Request (chunk={chunk_number}, type={:?})",
            status.sop, status.message_type
        ),
        PdChunkState::Pending {
            received_chunk,
            next_chunk,
        } => println!(
            "[{timestamp:>8.3}s] SOP{}: {:?} chunk {received_chunk} received, waiting for chunk {next_chunk}",
            status.sop, status.message_type
        ),
        PdChunkState::Requested { chunk_number } => println!(
            "[{timestamp:>8.3}s] SOP{}: {:?} chunk {chunk_number} requested",
            status.sop, status.message_type
        ),
        PdChunkState::Unsupported {
            chunk_number,
            data_size,
        } => println!(
            "[{timestamp:>8.3}s] SOP{}: Chunked {:?} (chunk {chunk_number}, {data_size} bytes) - not assembled",
            status.sop, status.message_type
        ),
    }
}

fn print_failure(failure: &PdDecodeFailure) {
    println!(
        "[{:>8.3}s] SOP{}: Failed to parse: {} (Hex: {:02X?})",
        failure.timestamp.get::<millisecond>() / 1000.0,
        failure.sop,
        failure.error,
        failure.wire_data
    );
}

fn print_request(request: &data::request::PowerSource, source_caps: Option<&SourceCapabilities>) {
    use data::request::PowerSource;

    match request {
        PowerSource::FixedVariableSupply(request) => {
            let current = request.operating_current().get::<ampere>();
            let max_current = request.max_operating_current().get::<ampere>();
            let position = request.object_position();
            if let Some(pdo) = source_caps.and_then(|caps| caps.pdos().get(position as usize - 1)) {
                println!("             RDO: PDO#{position} ({}) @ {current:.1}A", format_pdo(pdo));
            } else {
                println!("             RDO: PDO#{position} @ {current:.1}A (Max {max_current:.1}A)");
            }
        }
        PowerSource::Battery(request) => println!(
            "             RDO: Requesting Battery PDO#{} @ {:.2}W",
            request.object_position(),
            request.operating_power().get::<watt>()
        ),
        PowerSource::Pps(request) => println!(
            "             RDO: Requesting PPS PDO#{} @ {:.2}V / {:.2}A",
            request.object_position(),
            request.output_voltage().get::<volt>(),
            request.operating_current().get::<ampere>()
        ),
        PowerSource::Avs(request) => println!(
            "             RDO: Requesting AVS PDO#{} @ {:.2}V / {:.2}A",
            request.object_position(),
            request.output_voltage().get::<volt>(),
            request.operating_current().get::<ampere>()
        ),
        PowerSource::EprRequest { rdo, pdo } => print_epr_request(*rdo, pdo),
        PowerSource::Unknown(raw) => {
            let position = raw.object_position();
            if let Some(pdo) = source_caps.and_then(|caps| caps.pdos().get(position as usize - 1)) {
                let request = data::request::FixedVariableSupply(raw.0);
                println!(
                    "             RDO: Requesting PDO#{position} ({}) @ {:.1}A",
                    format_pdo(pdo),
                    request.operating_current().get::<ampere>()
                );
            } else {
                println!("             RDO: Requesting PDO#{position} (Raw=0x{:08X})", raw.0);
            }
        }
    }
}

fn print_epr_request(rdo: u32, pdo: &PowerDataObject) {
    use data::request::{Avs as RdoAvs, FixedVariableSupply as RdoFixed, RawDataObject};

    let position = RawDataObject(rdo).object_position();
    match pdo {
        PowerDataObject::FixedSupply(fixed) => {
            let request = RdoFixed(rdo);
            println!(
                "             RDO: EPR Fixed PDO#{position} ({:.1}V) @ {:.2}A (Max {:.2}A)",
                fixed.voltage().get::<volt>(),
                request.operating_current().get::<ampere>(),
                request.max_operating_current().get::<ampere>()
            );
        }
        PowerDataObject::Augmented(Augmented::Spr(pps)) => {
            let request = RdoAvs(rdo);
            println!(
                "             RDO: EPR PPS PDO#{position} ({:.1}-{:.1}V) @ {:.2}V / {:.2}A",
                pps.min_voltage().get::<volt>(),
                pps.max_voltage().get::<volt>(),
                request.output_voltage().get::<volt>(),
                request.operating_current().get::<ampere>()
            );
        }
        PowerDataObject::Augmented(Augmented::Epr(avs)) => {
            let request = RdoAvs(rdo);
            println!(
                "             RDO: EPR AVS PDO#{position} ({:.1}-{:.1}V @ {:.0}W) @ {:.2}V / {:.2}A",
                avs.min_voltage().get::<volt>(),
                avs.max_voltage().get::<volt>(),
                avs.pd_power().get::<watt>(),
                request.output_voltage().get::<volt>(),
                request.operating_current().get::<ampere>()
            );
        }
        PowerDataObject::Augmented(_) => {
            println!("             RDO: EPR Augmented PDO#{position} (Raw=0x{rdo:08X})");
        }
        _ => println!("             RDO: EPR PDO#{position} (Raw=0x{rdo:08X}, PDO={pdo:?})"),
    }
}

fn format_pdo(pdo: &PowerDataObject) -> String {
    match pdo {
        PowerDataObject::FixedSupply(fixed) => {
            let voltage = fixed.voltage().get::<volt>();
            let current = fixed.max_current().get::<ampere>();
            let mut flags = Vec::new();
            if fixed.dual_role_power() {
                flags.push("DRP");
            }
            if fixed.usb_communications_capable() {
                flags.push("USB");
            }
            if fixed.dual_role_data() {
                flags.push("DRD");
            }
            if fixed.unconstrained_power() {
                flags.push("UP");
            }
            if fixed.epr_mode_capable() {
                flags.push("EPR");
            }
            let flags = if flags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", flags.join(","))
            };
            format!("Fixed {voltage:.0}V @ {current:.1}A ({:.0}W){flags}", voltage * current)
        }
        PowerDataObject::Battery(battery) => format!(
            "Battery {:.0}-{:.0}V @ {:.0}W",
            battery.min_voltage().get::<volt>(),
            battery.max_voltage().get::<volt>(),
            battery.max_power().get::<watt>()
        ),
        PowerDataObject::VariableSupply(variable) => format!(
            "Variable {:.0}-{:.0}V @ {:.1}A",
            variable.min_voltage().get::<volt>(),
            variable.max_voltage().get::<volt>(),
            variable.max_current().get::<ampere>()
        ),
        PowerDataObject::Augmented(Augmented::Spr(pps)) => {
            let min_voltage = pps.min_voltage().get::<volt>();
            let max_voltage = pps.max_voltage().get::<volt>();
            let current = pps.max_current().get::<ampere>();
            let limited = if pps.pps_power_limited() { " (limited)" } else { "" };
            format!(
                "PPS {min_voltage:.1}-{max_voltage:.1}V @ {current:.1}A ({:.0}W){limited}",
                max_voltage * current
            )
        }
        PowerDataObject::Augmented(Augmented::Epr(avs)) => format!(
            "EPR AVS {:.0}-{:.0}V @ {:.0}W",
            avs.min_voltage().get::<volt>(),
            avs.max_voltage().get::<volt>(),
            avs.pd_power().get::<watt>()
        ),
        PowerDataObject::Augmented(Augmented::Unknown(raw)) => format!("Augmented(0x{raw:08X})"),
        PowerDataObject::Unknown(raw) => format!("Unknown(0x{:08X})", raw.0),
    }
}

fn print_capabilities(capabilities: &[PowerDataObject], title: &str) {
    println!("             [{title}]");
    for (index, pdo) in capabilities.iter().enumerate() {
        if matches!(pdo, PowerDataObject::FixedSupply(fixed) if fixed.0 == 0) {
            println!("             PDO[{}]: --- (separator) ---", index + 1);
        } else {
            println!("             PDO[{}]: {}", index + 1, format_pdo(pdo));
        }
    }
}
