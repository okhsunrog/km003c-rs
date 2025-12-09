use km003c_lib::{KM003C, device::DeviceConfig, pd::PdEventData};
use std::time::{Duration, Instant};
use usbpd::protocol_layer::message::data::source_capabilities::{Augmented, PowerDataObject, SourceCapabilities};
use usbpd::protocol_layer::message::data::{self, Data};
use usbpd::protocol_layer::message::extended::Extended;
use usbpd::protocol_layer::message::extended::chunked::{ChunkResult, ChunkedMessageAssembler};
use usbpd::protocol_layer::message::header::ExtendedMessageType;
use usbpd::protocol_layer::message::{Message, ParseError, Payload};

// Use uom for nice formatting
use uom::si::electric_current::ampere;
use uom::si::electric_potential::volt;
use uom::si::power::watt;

/// Format a single PDO for display
fn format_pdo(pdo: &PowerDataObject) -> String {
    match pdo {
        PowerDataObject::FixedSupply(f) => {
            let v = f.voltage().get::<volt>();
            let i = f.max_current().get::<ampere>();
            let p = v * i;
            let mut flags = Vec::new();
            if f.dual_role_power() {
                flags.push("DRP");
            }
            if f.usb_communications_capable() {
                flags.push("USB");
            }
            if f.dual_role_data() {
                flags.push("DRD");
            }
            if f.unconstrained_power() {
                flags.push("UP");
            }
            if f.epr_mode_capable() {
                flags.push("EPR");
            }
            let flags_str = if flags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", flags.join(","))
            };
            format!("Fixed {:.0}V @ {:.1}A ({:.0}W){}", v, i, p, flags_str)
        }
        PowerDataObject::Battery(b) => {
            let min_v = b.min_voltage().get::<volt>();
            let max_v = b.max_voltage().get::<volt>();
            let p = b.max_power().get::<watt>();
            format!("Battery {:.0}-{:.0}V @ {:.0}W", min_v, max_v, p)
        }
        PowerDataObject::VariableSupply(v) => {
            let min_v = v.min_voltage().get::<volt>();
            let max_v = v.max_voltage().get::<volt>();
            let i = v.max_current().get::<ampere>();
            format!("Variable {:.0}-{:.0}V @ {:.1}A", min_v, max_v, i)
        }
        PowerDataObject::Augmented(aug) => match aug {
            Augmented::Spr(pps) => {
                let min_v = pps.min_voltage().get::<volt>();
                let max_v = pps.max_voltage().get::<volt>();
                let i = pps.max_current().get::<ampere>();
                let p = max_v * i;
                let limited = if pps.pps_power_limited() { " (limited)" } else { "" };
                format!("PPS {:.1}-{:.1}V @ {:.1}A ({:.0}W){}", min_v, max_v, i, p, limited)
            }
            Augmented::Epr(avs) => {
                let min_v = avs.min_voltage().get::<volt>();
                let max_v = avs.max_voltage().get::<volt>();
                let p = avs.pd_power().get::<watt>();
                format!("EPR AVS {:.0}-{:.0}V @ {:.0}W", min_v, max_v, p)
            }
            Augmented::Unknown(raw) => {
                format!("Augmented(0x{:08X})", raw)
            }
        },
        PowerDataObject::Unknown(u) => {
            format!("Unknown(0x{:08X})", u.0)
        }
    }
}

/// Print source capabilities in a nice format
fn print_capabilities(caps: &[PowerDataObject], title: &str) {
    println!("             [{}]", title);
    for (i, pdo) in caps.iter().enumerate() {
        // Skip null PDOs (separator between SPR and EPR)
        if matches!(pdo, PowerDataObject::FixedSupply(f) if f.0 == 0) {
            println!("             PDO[{}]: --- (separator) ---", i + 1);
        } else {
            println!("             PDO[{}]: {}", i + 1, format_pdo(pdo));
        }
    }
}

struct PdDecoder {
    source_caps: Option<SourceCapabilities>,
    /// Assembler for chunked EPR Source Capabilities
    epr_assembler: ChunkedMessageAssembler,
}

impl PdDecoder {
    fn new() -> Self {
        Self {
            source_caps: None,
            epr_assembler: ChunkedMessageAssembler::new(),
        }
    }

    fn handle_connect(&mut self) {
        self.source_caps = None;
        self.epr_assembler.reset();
    }

    fn decode(&mut self, sop: u8, wire_data: &[u8]) {
        if wire_data.is_empty() {
            return;
        }

        // Print raw bytes first
        print!("       RAW[{}]: ", wire_data.len());
        for (i, byte) in wire_data.iter().enumerate() {
            if i > 0 && i % 16 == 0 {
                print!("\n                ");
            }
            print!("{:02X} ", byte);
        }
        println!();

        match Message::from_bytes(wire_data) {
            Ok(msg) => {
                let msg_type = msg.header.message_type();
                let msg_id = msg.header.message_id();
                let role = format!("{:?}/{:?}", msg.header.port_power_role(), msg.header.port_data_role());

                let type_str = format!("{:?}", msg_type);
                println!("SOP{}: {:<20} (ID={}, ROLE={})", sop, type_str, msg_id, role);

                match &msg.payload {
                    Some(Payload::Data(data)) => match data {
                        Data::SourceCapabilities(caps) => {
                            self.source_caps = Some(caps.clone());
                            print_capabilities(caps.pdos(), "SPR Source Capabilities");
                        }
                        Data::Request(req) => {
                            self.print_request(req);
                        }
                        Data::EprMode(mode) => {
                            println!("             EPR Mode: {:?}", mode);
                        }
                        Data::Unknown => {
                            println!("             Unknown Data Message");
                        }
                        _ => {
                            println!("             Data: {:?}", data);
                        }
                    },
                    Some(Payload::Extended(ext)) => match ext {
                        Extended::EprSourceCapabilities(pdos) => {
                            print_capabilities(pdos.as_slice(), "EPR Source Capabilities");
                        }
                        Extended::ExtendedControl(ctrl) => {
                            println!(
                                "             Extended Control: {:?} (data=0x{:02X})",
                                ctrl.message_type(),
                                ctrl.data()
                            );
                        }
                        _ => {
                            println!("             Extended: {:?}", ext);
                        }
                    },
                    None => {
                        // Control message (GoodCRC, Accept, etc.) - already summarized by type_str
                    }
                }
            }
            Err(ParseError::ChunkedExtendedMessage {
                chunk_number,
                data_size,
                request_chunk,
                message_type,
            }) => {
                // Handle chunked extended messages
                if request_chunk {
                    // This is a chunk request - just log it
                    println!(
                        "SOP{}: Chunk Request (chunk={}, type={:?})",
                        sop, chunk_number, message_type
                    );
                    return;
                }

                // Only handle EPR Source Capabilities for now
                if message_type != ExtendedMessageType::EprSourceCapabilities {
                    println!(
                        "SOP{}: Chunked {:?} (chunk {}/{} bytes) - not assembled",
                        sop, message_type, chunk_number, data_size
                    );
                    return;
                }

                // Parse chunk and feed to assembler
                match Message::parse_extended_chunk(wire_data) {
                    Ok((header, ext_header, chunk_data)) => {
                        match self.epr_assembler.process_chunk(header, ext_header, chunk_data) {
                            Ok(ChunkResult::Complete(assembled_data)) => {
                                // Parse the assembled EPR Source Capabilities
                                let ext = Message::parse_extended_payload(
                                    ExtendedMessageType::EprSourceCapabilities,
                                    &assembled_data,
                                );

                                if let Extended::EprSourceCapabilities(pdos) = ext {
                                    let msg_id = header.message_id();
                                    let role = format!("{:?}/{:?}", header.port_power_role(), header.port_data_role());
                                    println!(
                                        "SOP{}: Extended(EprSourceCapabilities) (ID={}, ROLE={})",
                                        sop, msg_id, role
                                    );
                                    let title =
                                        format!("EPR Source Capabilities - {} chunks assembled", chunk_number + 1);
                                    print_capabilities(pdos.as_slice(), &title);
                                }
                            }
                            Ok(ChunkResult::NeedMoreChunks(next)) => {
                                println!(
                                    "SOP{}: EPR Source Caps chunk {} received, waiting for chunk {}...",
                                    sop, chunk_number, next
                                );
                            }
                            Ok(ChunkResult::ChunkRequested(num)) => {
                                println!("SOP{}: Chunk {} requested", sop, num);
                            }
                            Err(e) => {
                                println!("SOP{}: Chunk assembly error: {:?}", sop, e);
                                self.epr_assembler.reset();
                            }
                        }
                    }
                    Err(e) => {
                        println!("SOP{}: Failed to parse chunk: {:?}", sop, e);
                    }
                }
            }
            Err(e) => {
                println!("SOP{}: Failed to parse: {:?} (Hex: {:02X?})", sop, e, wire_data);
            }
        }
    }

    fn print_request(&self, req: &data::request::PowerSource) {
        use data::request::PowerSource;

        match req {
            PowerSource::FixedVariableSupply(p) => {
                let curr = p.operating_current().get::<ampere>();
                let max_curr = p.max_operating_current().get::<ampere>();
                let pos = p.object_position();

                // Look up Voltage from PDO if available
                let pdo_info = self
                    .source_caps
                    .as_ref()
                    .and_then(|caps| caps.pdos().get(pos as usize - 1))
                    .map(format_pdo);

                if let Some(info) = pdo_info {
                    println!("             RDO: PDO#{} ({}) @ {:.1}A", pos, info, curr);
                } else {
                    println!("             RDO: PDO#{} @ {:.1}A (Max {:.1}A)", pos, curr, max_curr);
                }
            }
            PowerSource::Battery(p) => {
                let power = p.operating_power().get::<watt>();
                println!(
                    "             RDO: Requesting Battery PDO#{} @ {:.2}W",
                    p.object_position(),
                    power
                );
            }
            PowerSource::Pps(p) => {
                let v = p.output_voltage().get::<volt>();
                let c = p.operating_current().get::<ampere>();
                println!(
                    "             RDO: Requesting PPS PDO#{} @ {:.2}V / {:.2}A",
                    p.object_position(),
                    v,
                    c
                );
            }
            PowerSource::Avs(p) => {
                let v = p.output_voltage().get::<volt>();
                let c = p.operating_current().get::<ampere>();
                println!(
                    "             RDO: Requesting AVS PDO#{} @ {:.2}V / {:.2}A",
                    p.object_position(),
                    v,
                    c
                );
            }
            PowerSource::EprRequest { rdo, pdo } => {
                use usbpd::protocol_layer::message::data::request::{
                    Avs as RdoAvs, FixedVariableSupply as RdoFixed, RawDataObject,
                };
                use usbpd::protocol_layer::message::data::source_capabilities::PowerDataObject;

                let pos = RawDataObject(*rdo).object_position();

                // Parse the RDO based on the PDO type
                match pdo {
                    PowerDataObject::FixedSupply(f) => {
                        let rdo_parsed = RdoFixed(*rdo);
                        let curr = rdo_parsed.operating_current().get::<ampere>();
                        let max_curr = rdo_parsed.max_operating_current().get::<ampere>();
                        let voltage = f.voltage().get::<volt>();
                        println!(
                            "             RDO: EPR Fixed PDO#{} ({:.1}V) @ {:.2}A (Max {:.2}A)",
                            pos, voltage, curr, max_curr
                        );
                    }
                    PowerDataObject::Augmented(a) => {
                        use usbpd::protocol_layer::message::data::source_capabilities::Augmented;
                        match a {
                            Augmented::Spr(pps) => {
                                let rdo_parsed = RdoAvs(*rdo);
                                let v = rdo_parsed.output_voltage().get::<volt>();
                                let c = rdo_parsed.operating_current().get::<ampere>();
                                println!(
                                    "             RDO: EPR PPS PDO#{} ({:.1}-{:.1}V) @ {:.2}V / {:.2}A",
                                    pos,
                                    pps.min_voltage().get::<volt>(),
                                    pps.max_voltage().get::<volt>(),
                                    v,
                                    c
                                );
                            }
                            Augmented::Epr(avs) => {
                                let rdo_parsed = RdoAvs(*rdo);
                                let v = rdo_parsed.output_voltage().get::<volt>();
                                let c = rdo_parsed.operating_current().get::<ampere>();
                                println!(
                                    "             RDO: EPR AVS PDO#{} ({:.1}-{:.1}V @ {:.0}W) @ {:.2}V / {:.2}A",
                                    pos,
                                    avs.min_voltage().get::<volt>(),
                                    avs.max_voltage().get::<volt>(),
                                    avs.pd_power().get::<watt>(),
                                    v,
                                    c
                                );
                            }
                            _ => {
                                println!("             RDO: EPR Augmented PDO#{} (Raw=0x{:08X})", pos, rdo);
                            }
                        }
                    }
                    _ => {
                        println!("             RDO: EPR PDO#{} (Raw=0x{:08X}, PDO={:?})", pos, rdo, pdo);
                    }
                }
            }
            PowerSource::Unknown(raw) => {
                let pos = raw.object_position();
                print!("             RDO: Requesting PDO#{} (Raw=0x{:08X})", pos, raw.0);

                if let Some(caps) = &self.source_caps
                    && let Some(pdo) = caps.pdos().get(pos as usize - 1)
                {
                    print!(" [Matches PDO: {:?}]", pdo);
                }
                println!();
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    // We use Vendor interface for speed
    let config = DeviceConfig::vendor_interface();
    let mut device = KM003C::with_config(config).await?;

    println!("============================================================");
    println!("USB PD Negotiation Capture (Rust + usbpd crate)");
    println!("============================================================");
    println!("Connected to KM003C");
    println!("NOW: Disconnect and reconnect your USB-C load!");
    println!("Capturing for 20 seconds... (Press Ctrl+C to stop early)");
    println!("============================================================");

    // Initial drain
    let _ = device.receive_raw().await;

    // Send Connect to ensure we are receiving events
    use km003c_lib::message::Packet;
    device.send(Packet::Connect).await?;

    let start_time = Instant::now();
    let duration = Duration::from_secs(20);
    let mut decoder = PdDecoder::new();

    loop {
        if start_time.elapsed() >= duration {
            break;
        }

        match device.request_pd_data().await {
            Ok(packet) => {
                if let Some(stream) = KM003C::extract_pd_events(&packet) {
                    for event in &stream.events {
                        match &event.data {
                            PdEventData::Connect(_) => {
                                println!("[{}ms] ** CONNECT **", event.timestamp);
                                decoder.handle_connect();
                            }
                            PdEventData::Disconnect(_) => {
                                println!("[{}ms] ** DISCONNECT **", event.timestamp);
                            }
                            PdEventData::PdMessage { sop, wire_data } => {
                                decoder.decode(*sop, wire_data);
                            }
                        }
                    }
                }
            }
            Err(_e) => {}
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
