use km003c_lib::pd::{PdEvent, PdEventData};
use usbpd::protocol_layer::message::data::source_capabilities::{Augmented, PowerDataObject, SourceCapabilities};
use usbpd::protocol_layer::message::data::{self, Data};
use usbpd::protocol_layer::message::extended::Extended;
use usbpd::protocol_layer::message::extended::chunked::{ChunkResult, ChunkedMessageAssembler};
use usbpd::protocol_layer::message::header::ExtendedMessageType;
use usbpd::protocol_layer::message::{Message, ParseError, Payload};

use uom::si::electric_current::ampere;
use uom::si::electric_potential::volt;
use uom::si::power::watt;
use uom::si::time::millisecond;

/// Category of a decoded PD entry, used for color-coding in the UI
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdCategory {
    Connect,
    Disconnect,
    SourceCaps,
    Request,
    Control,  // Accept, Reject, GoodCRC, PS_RDY, etc.
    Extended, // EPR caps, extended control
    Error,    // Parse failures
}

/// A single decoded PD log entry for display
#[derive(Debug, Clone)]
pub struct DecodedPdEntry {
    pub category: PdCategory,
    pub summary: String,
    pub details: Vec<String>,
}

/// PD protocol decoder that maintains state across events
pub struct PdDecoder {
    source_caps: Option<SourceCapabilities>,
    epr_assembler: ChunkedMessageAssembler,
}

impl PdDecoder {
    pub fn new() -> Self {
        Self {
            source_caps: None,
            epr_assembler: ChunkedMessageAssembler::new(),
        }
    }

    /// Reset state on new connection
    pub fn handle_connect(&mut self) {
        self.source_caps = None;
        self.epr_assembler.reset();
    }

    /// Decode a PdEvent into one or more DecodedPdEntry structs
    pub fn decode_event(&mut self, event: &PdEvent) -> Vec<DecodedPdEntry> {
        match &event.data {
            PdEventData::Connect(()) => {
                self.handle_connect();
                vec![DecodedPdEntry {
                    category: PdCategory::Connect,
                    summary: format!("[{:.3}s] ** CONNECT **", event.timestamp.get::<millisecond>() / 1000.0),
                    details: vec![],
                }]
            }
            PdEventData::Disconnect(()) => {
                vec![DecodedPdEntry {
                    category: PdCategory::Disconnect,
                    summary: format!(
                        "[{:.3}s] ** DISCONNECT **",
                        event.timestamp.get::<millisecond>() / 1000.0
                    ),
                    details: vec![],
                }]
            }
            PdEventData::PdMessage { sop, wire_data } => {
                self.decode_message(event.timestamp.get::<millisecond>() as u32, *sop, wire_data)
            }
        }
    }

    fn decode_message(&mut self, timestamp_ms: u32, sop: u8, wire_data: &[u8]) -> Vec<DecodedPdEntry> {
        if wire_data.is_empty() {
            return vec![];
        }

        let ts = timestamp_ms as f64 / 1000.0;

        match Message::from_bytes(wire_data) {
            Ok(msg) => {
                let msg_type = msg.header.message_type();
                let msg_id = msg.header.message_id();
                let role = format!("{:?}/{:?}", msg.header.port_power_role(), msg.header.port_data_role());

                let type_str = format!("{:?}", msg_type);
                let summary = format!("[{:.3}s] SOP{}: {} (ID={}, ROLE={})", ts, sop, type_str, msg_id, role);

                match &msg.payload {
                    Some(Payload::Data(data)) => match data {
                        Data::SourceCapabilities(caps) => {
                            self.source_caps = Some(caps.clone());
                            let details = format_capabilities(caps.pdos(), "SPR Source Capabilities");
                            vec![DecodedPdEntry {
                                category: PdCategory::SourceCaps,
                                summary,
                                details,
                            }]
                        }
                        Data::Request(req) => {
                            let details = self.format_request(req);
                            vec![DecodedPdEntry {
                                category: PdCategory::Request,
                                summary,
                                details,
                            }]
                        }
                        Data::EprMode(mode) => {
                            vec![DecodedPdEntry {
                                category: PdCategory::Extended,
                                summary,
                                details: vec![format!("EPR Mode: {:?}", mode)],
                            }]
                        }
                        Data::Unknown => {
                            vec![DecodedPdEntry {
                                category: PdCategory::Control,
                                summary,
                                details: vec!["Unknown Data Message".to_string()],
                            }]
                        }
                        _ => {
                            vec![DecodedPdEntry {
                                category: PdCategory::Control,
                                summary,
                                details: vec![format!("Data: {:?}", data)],
                            }]
                        }
                    },
                    Some(Payload::Extended(ext)) => match ext {
                        Extended::EprSourceCapabilities(pdos) => {
                            let details = format_capabilities(pdos.as_slice(), "EPR Source Capabilities");
                            vec![DecodedPdEntry {
                                category: PdCategory::Extended,
                                summary,
                                details,
                            }]
                        }
                        Extended::ExtendedControl(ctrl) => {
                            vec![DecodedPdEntry {
                                category: PdCategory::Extended,
                                summary,
                                details: vec![format!(
                                    "Extended Control: {:?} (data=0x{:02X})",
                                    ctrl.message_type(),
                                    ctrl.data()
                                )],
                            }]
                        }
                        _ => {
                            vec![DecodedPdEntry {
                                category: PdCategory::Extended,
                                summary,
                                details: vec![format!("Extended: {:?}", ext)],
                            }]
                        }
                    },
                    None => {
                        // Control message (GoodCRC, Accept, etc.)
                        vec![DecodedPdEntry {
                            category: PdCategory::Control,
                            summary,
                            details: vec![],
                        }]
                    }
                }
            }
            Err(ParseError::ChunkedExtendedMessage {
                chunk_number,
                data_size: _,
                request_chunk,
                message_type,
            }) => self.handle_chunked(ts, sop, chunk_number, request_chunk, message_type, wire_data),
            Err(e) => {
                vec![DecodedPdEntry {
                    category: PdCategory::Error,
                    summary: format!("[{:.3}s] SOP{}: Parse error: {:?}", ts, sop, e),
                    details: vec![format!("Hex: {:02X?}", wire_data)],
                }]
            }
        }
    }

    fn handle_chunked(
        &mut self,
        ts: f64,
        sop: u8,
        chunk_number: u8,
        request_chunk: bool,
        message_type: ExtendedMessageType,
        wire_data: &[u8],
    ) -> Vec<DecodedPdEntry> {
        if request_chunk {
            return vec![DecodedPdEntry {
                category: PdCategory::Extended,
                summary: format!(
                    "[{:.3}s] SOP{}: Chunk Request (chunk={}, type={:?})",
                    ts, sop, chunk_number, message_type
                ),
                details: vec![],
            }];
        }

        if message_type != ExtendedMessageType::EprSourceCapabilities {
            return vec![DecodedPdEntry {
                category: PdCategory::Extended,
                summary: format!(
                    "[{:.3}s] SOP{}: Chunked {:?} (chunk {}) - not assembled",
                    ts, sop, message_type, chunk_number
                ),
                details: vec![],
            }];
        }

        match Message::parse_extended_chunk(wire_data) {
            Ok((header, ext_header, chunk_data)) => {
                match self.epr_assembler.process_chunk(header, ext_header, chunk_data) {
                    Ok(ChunkResult::Complete(assembled_data)) => {
                        let ext = Message::parse_extended_payload(
                            ExtendedMessageType::EprSourceCapabilities,
                            &assembled_data,
                        );

                        if let Extended::EprSourceCapabilities(pdos) = ext {
                            let msg_id = header.message_id();
                            let role = format!("{:?}/{:?}", header.port_power_role(), header.port_data_role());
                            let title = format!("EPR Source Capabilities - {} chunks assembled", chunk_number + 1);
                            let details = format_capabilities(pdos.as_slice(), &title);
                            vec![DecodedPdEntry {
                                category: PdCategory::SourceCaps,
                                summary: format!(
                                    "[{:.3}s] SOP{}: Extended(EprSourceCapabilities) (ID={}, ROLE={})",
                                    ts, sop, msg_id, role
                                ),
                                details,
                            }]
                        } else {
                            vec![]
                        }
                    }
                    Ok(ChunkResult::NeedMoreChunks(next)) => {
                        vec![DecodedPdEntry {
                            category: PdCategory::Extended,
                            summary: format!(
                                "[{:.3}s] SOP{}: EPR Source Caps chunk {} received, waiting for chunk {}...",
                                ts, sop, chunk_number, next
                            ),
                            details: vec![],
                        }]
                    }
                    Ok(ChunkResult::ChunkRequested(num)) => {
                        vec![DecodedPdEntry {
                            category: PdCategory::Extended,
                            summary: format!("[{:.3}s] SOP{}: Chunk {} requested", ts, sop, num),
                            details: vec![],
                        }]
                    }
                    Err(e) => {
                        self.epr_assembler.reset();
                        vec![DecodedPdEntry {
                            category: PdCategory::Error,
                            summary: format!("[{:.3}s] SOP{}: Chunk assembly error: {:?}", ts, sop, e),
                            details: vec![],
                        }]
                    }
                }
            }
            Err(e) => {
                vec![DecodedPdEntry {
                    category: PdCategory::Error,
                    summary: format!("[{:.3}s] SOP{}: Failed to parse chunk: {:?}", ts, sop, e),
                    details: vec![],
                }]
            }
        }
    }

    fn format_request(&self, req: &data::request::PowerSource) -> Vec<String> {
        use data::request::PowerSource;

        match req {
            PowerSource::FixedVariableSupply(p) => {
                let curr = p.operating_current().get::<ampere>();
                let max_curr = p.max_operating_current().get::<ampere>();
                let pos = p.object_position();

                let pdo_info = self
                    .source_caps
                    .as_ref()
                    .and_then(|caps| caps.pdos().get(pos as usize - 1))
                    .map(format_pdo);

                if let Some(info) = pdo_info {
                    vec![format!("RDO: PDO#{} ({}) @ {:.1}A", pos, info, curr)]
                } else {
                    vec![format!("RDO: PDO#{} @ {:.1}A (Max {:.1}A)", pos, curr, max_curr)]
                }
            }
            PowerSource::Battery(p) => {
                let power = p.operating_power().get::<watt>();
                vec![format!(
                    "RDO: Requesting Battery PDO#{} @ {:.2}W",
                    p.object_position(),
                    power
                )]
            }
            PowerSource::Pps(p) => {
                let v = p.output_voltage().get::<volt>();
                let c = p.operating_current().get::<ampere>();
                vec![format!(
                    "RDO: Requesting PPS PDO#{} @ {:.2}V / {:.2}A",
                    p.object_position(),
                    v,
                    c
                )]
            }
            PowerSource::Avs(p) => {
                let v = p.output_voltage().get::<volt>();
                let c = p.operating_current().get::<ampere>();
                vec![format!(
                    "RDO: Requesting AVS PDO#{} @ {:.2}V / {:.2}A",
                    p.object_position(),
                    v,
                    c
                )]
            }
            PowerSource::EprRequest { rdo, pdo } => {
                use usbpd::protocol_layer::message::data::request::{
                    Avs as RdoAvs, FixedVariableSupply as RdoFixed, RawDataObject,
                };
                use usbpd::protocol_layer::message::data::source_capabilities::PowerDataObject;

                let pos = RawDataObject(*rdo).object_position();

                match pdo {
                    PowerDataObject::FixedSupply(f) => {
                        let rdo_parsed = RdoFixed(*rdo);
                        let curr = rdo_parsed.operating_current().get::<ampere>();
                        let max_curr = rdo_parsed.max_operating_current().get::<ampere>();
                        let voltage = f.voltage().get::<volt>();
                        vec![format!(
                            "RDO: EPR Fixed PDO#{} ({:.1}V) @ {:.2}A (Max {:.2}A)",
                            pos, voltage, curr, max_curr
                        )]
                    }
                    PowerDataObject::Augmented(a) => {
                        use usbpd::protocol_layer::message::data::source_capabilities::Augmented;
                        match a {
                            Augmented::Spr(pps) => {
                                let rdo_parsed = RdoAvs(*rdo);
                                let v = rdo_parsed.output_voltage().get::<volt>();
                                let c = rdo_parsed.operating_current().get::<ampere>();
                                vec![format!(
                                    "RDO: EPR PPS PDO#{} ({:.1}-{:.1}V) @ {:.2}V / {:.2}A",
                                    pos,
                                    pps.min_voltage().get::<volt>(),
                                    pps.max_voltage().get::<volt>(),
                                    v,
                                    c
                                )]
                            }
                            Augmented::Epr(avs) => {
                                let rdo_parsed = RdoAvs(*rdo);
                                let v = rdo_parsed.output_voltage().get::<volt>();
                                let c = rdo_parsed.operating_current().get::<ampere>();
                                vec![format!(
                                    "RDO: EPR AVS PDO#{} ({:.1}-{:.1}V @ {:.0}W) @ {:.2}V / {:.2}A",
                                    pos,
                                    avs.min_voltage().get::<volt>(),
                                    avs.max_voltage().get::<volt>(),
                                    avs.pd_power().get::<watt>(),
                                    v,
                                    c
                                )]
                            }
                            _ => {
                                vec![format!("RDO: EPR Augmented PDO#{} (Raw=0x{:08X})", pos, rdo)]
                            }
                        }
                    }
                    _ => {
                        vec![format!("RDO: EPR PDO#{} (Raw=0x{:08X}, PDO={:?})", pos, rdo, pdo)]
                    }
                }
            }
            PowerSource::Unknown(raw) => {
                let pos = raw.object_position();

                if let Some(caps) = &self.source_caps
                    && let Some(pdo) = caps.pdos().get(pos as usize - 1)
                {
                    let rdo_parsed = data::request::FixedVariableSupply(raw.0);
                    let curr = rdo_parsed.operating_current().get::<ampere>();
                    vec![format!(
                        "RDO: Requesting PDO#{} ({}) @ {:.1}A",
                        pos,
                        format_pdo(pdo),
                        curr
                    )]
                } else {
                    vec![format!("RDO: Requesting PDO#{} (Raw=0x{:08X})", pos, raw.0)]
                }
            }
        }
    }
}

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

/// Format source capabilities as a list of detail strings
fn format_capabilities(caps: &[PowerDataObject], title: &str) -> Vec<String> {
    let mut lines = vec![format!("[{}]", title)];
    for (i, pdo) in caps.iter().enumerate() {
        if matches!(pdo, PowerDataObject::FixedSupply(f) if f.0 == 0) {
            lines.push(format!("PDO[{}]: --- (separator) ---", i + 1));
        } else {
            lines.push(format!("PDO[{}]: {}", i + 1, format_pdo(pdo)));
        }
    }
    lines
}
