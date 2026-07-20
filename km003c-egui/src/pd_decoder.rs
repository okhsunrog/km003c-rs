use km003c_lib::pd::PdEvent;
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
use km003c_lib::{DecodedPdEvent, DecodedPdMessage, PdChunkState, PdChunkStatus, PdDecodeFailure, PdSessionDecoder};

/// Category of a decoded PD entry, used for color-coding in the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdCategory {
    Connect,
    Disconnect,
    SourceCaps,
    Request,
    Control,
    Extended,
    Error,
}

/// A single decoded PD log entry for display.
#[derive(Debug, Clone)]
pub struct DecodedPdEntry {
    pub timestamp_seconds: f64,
    pub category: PdCategory,
    pub summary: String,
    pub details: Vec<String>,
}

/// UI formatter backed by the shared stateful decoder in `km003c-lib`.
pub struct PdDecoder {
    session: PdSessionDecoder,
}

impl PdDecoder {
    pub fn new() -> Self {
        Self {
            session: PdSessionDecoder::new(),
        }
    }

    pub fn decode_event(&mut self, event: &PdEvent) -> Vec<DecodedPdEntry> {
        let decoded = self.session.decode_event(event);
        vec![match decoded {
            DecodedPdEvent::Connect { timestamp } => DecodedPdEntry {
                timestamp_seconds: timestamp.get::<millisecond>() / 1000.0,
                category: PdCategory::Connect,
                summary: format!("[{:.3}s] ** CONNECT **", timestamp.get::<millisecond>() / 1000.0),
                details: vec![],
            },
            DecodedPdEvent::Disconnect { timestamp } => DecodedPdEntry {
                timestamp_seconds: timestamp.get::<millisecond>() / 1000.0,
                category: PdCategory::Disconnect,
                summary: format!("[{:.3}s] ** DISCONNECT **", timestamp.get::<millisecond>() / 1000.0),
                details: vec![],
            },
            DecodedPdEvent::Message(message) => self.format_message(&message),
            DecodedPdEvent::Chunk(status) => format_chunk_status(status),
            DecodedPdEvent::Error(failure) => format_failure(failure),
        }]
    }

    fn format_message(&self, decoded: &DecodedPdMessage) -> DecodedPdEntry {
        let message = &decoded.message;
        let message_type = message.header.message_type();
        let timestamp_seconds = decoded.timestamp.get::<millisecond>() / 1000.0;
        let summary = format!(
            "[{:.3}s] SOP{}: {:?} (ID={}, ROLE={:?}/{:?})",
            decoded.timestamp.get::<millisecond>() / 1000.0,
            decoded.sop,
            message_type,
            message.header.message_id(),
            message.header.port_power_role(),
            message.header.port_data_role(),
        );

        match &message.payload {
            Some(Payload::Data(Data::SourceCapabilities(capabilities))) => DecodedPdEntry {
                timestamp_seconds,
                category: PdCategory::SourceCaps,
                summary,
                details: format_capabilities(capabilities.pdos(), "SPR Source Capabilities"),
            },
            Some(Payload::Data(Data::Request(request))) => DecodedPdEntry {
                timestamp_seconds,
                category: PdCategory::Request,
                summary,
                details: format_request(request, self.session.source_capabilities()),
            },
            Some(Payload::Data(Data::EprMode(mode))) => DecodedPdEntry {
                timestamp_seconds,
                category: PdCategory::Extended,
                summary,
                details: vec![format!("EPR Mode: {mode:?}")],
            },
            Some(Payload::Data(Data::Unknown)) => DecodedPdEntry {
                timestamp_seconds,
                category: PdCategory::Control,
                summary,
                details: vec!["Unknown Data Message".to_string()],
            },
            Some(Payload::Data(data)) => DecodedPdEntry {
                timestamp_seconds,
                category: PdCategory::Control,
                summary,
                details: vec![format!("Data: {data:?}")],
            },
            Some(Payload::Extended(Extended::EprSourceCapabilities(pdos))) => DecodedPdEntry {
                timestamp_seconds,
                category: PdCategory::Extended,
                summary,
                details: format_capabilities(pdos.as_slice(), "EPR Source Capabilities"),
            },
            Some(Payload::Extended(Extended::ExtendedControl(control))) => DecodedPdEntry {
                timestamp_seconds,
                category: PdCategory::Extended,
                summary,
                details: vec![format!(
                    "Extended Control: {:?} (data=0x{:02X})",
                    control.message_type(),
                    control.data()
                )],
            },
            Some(Payload::Extended(extended)) => DecodedPdEntry {
                timestamp_seconds,
                category: PdCategory::Extended,
                summary,
                details: vec![format!("Extended: {extended:?}")],
            },
            None => DecodedPdEntry {
                timestamp_seconds,
                category: PdCategory::Control,
                summary,
                details: vec![],
            },
        }
    }
}

fn format_chunk_status(status: PdChunkStatus) -> DecodedPdEntry {
    let timestamp = status.timestamp.get::<millisecond>() / 1000.0;
    let summary = match status.state {
        PdChunkState::Request { chunk_number } => format!(
            "[{timestamp:.3}s] SOP{}: Chunk Request (chunk={chunk_number}, type={:?})",
            status.sop, status.message_type
        ),
        PdChunkState::Pending {
            received_chunk,
            next_chunk,
        } => format!(
            "[{timestamp:.3}s] SOP{}: {:?} chunk {received_chunk} received, waiting for chunk {next_chunk}",
            status.sop, status.message_type
        ),
        PdChunkState::Requested { chunk_number } => format!(
            "[{timestamp:.3}s] SOP{}: {:?} chunk {chunk_number} requested",
            status.sop, status.message_type
        ),
        PdChunkState::Unsupported {
            chunk_number,
            data_size,
        } => format!(
            "[{timestamp:.3}s] SOP{}: Chunked {:?} (chunk {chunk_number}, {data_size} bytes) - not assembled",
            status.sop, status.message_type
        ),
    };

    DecodedPdEntry {
        timestamp_seconds: timestamp,
        category: PdCategory::Extended,
        summary,
        details: vec![],
    }
}

fn format_failure(failure: PdDecodeFailure) -> DecodedPdEntry {
    let timestamp_seconds = failure.timestamp.get::<millisecond>() / 1000.0;
    DecodedPdEntry {
        timestamp_seconds,
        category: PdCategory::Error,
        summary: format!(
            "[{:.3}s] SOP{}: Parse error: {}",
            failure.timestamp.get::<millisecond>() / 1000.0,
            failure.sop,
            failure.error
        ),
        details: vec![format!("Hex: {:02X?}", failure.wire_data)],
    }
}

fn format_request(request: &data::request::PowerSource, source_caps: Option<&SourceCapabilities>) -> Vec<String> {
    use data::request::PowerSource;

    match request {
        PowerSource::FixedVariableSupply(request) => {
            let current = request.operating_current().get::<ampere>();
            let max_current = request.max_operating_current().get::<ampere>();
            let position = request.object_position();
            let pdo = source_caps
                .and_then(|capabilities| capabilities.pdos().get(position as usize - 1))
                .map(format_pdo);

            if let Some(pdo) = pdo {
                vec![format!("RDO: PDO#{position} ({pdo}) @ {current:.1}A")]
            } else {
                vec![format!("RDO: PDO#{position} @ {current:.1}A (Max {max_current:.1}A)")]
            }
        }
        PowerSource::Battery(request) => vec![format!(
            "RDO: Requesting Battery PDO#{} @ {:.2}W",
            request.object_position(),
            request.operating_power().get::<watt>()
        )],
        PowerSource::Pps(request) => vec![format!(
            "RDO: Requesting PPS PDO#{} @ {:.2}V / {:.2}A",
            request.object_position(),
            request.output_voltage().get::<volt>(),
            request.operating_current().get::<ampere>()
        )],
        PowerSource::Avs(request) => vec![format!(
            "RDO: Requesting AVS PDO#{} @ {:.2}V / {:.2}A",
            request.object_position(),
            request.output_voltage().get::<volt>(),
            request.operating_current().get::<ampere>()
        )],
        PowerSource::EprRequest { rdo, pdo } => {
            use data::request::{Avs as RdoAvs, FixedVariableSupply as RdoFixed, RawDataObject};

            let position = RawDataObject(*rdo).object_position();
            match pdo {
                PowerDataObject::FixedSupply(fixed) => {
                    let request = RdoFixed(*rdo);
                    vec![format!(
                        "RDO: EPR Fixed PDO#{position} ({:.1}V) @ {:.2}A (Max {:.2}A)",
                        fixed.voltage().get::<volt>(),
                        request.operating_current().get::<ampere>(),
                        request.max_operating_current().get::<ampere>()
                    )]
                }
                PowerDataObject::Augmented(Augmented::Spr(pps)) => {
                    let request = RdoAvs(*rdo);
                    vec![format!(
                        "RDO: EPR PPS PDO#{position} ({:.1}-{:.1}V) @ {:.2}V / {:.2}A",
                        pps.min_voltage().get::<volt>(),
                        pps.max_voltage().get::<volt>(),
                        request.output_voltage().get::<volt>(),
                        request.operating_current().get::<ampere>()
                    )]
                }
                PowerDataObject::Augmented(Augmented::Epr(avs)) => {
                    let request = RdoAvs(*rdo);
                    vec![format!(
                        "RDO: EPR AVS PDO#{position} ({:.1}-{:.1}V @ {:.0}W) @ {:.2}V / {:.2}A",
                        avs.min_voltage().get::<volt>(),
                        avs.max_voltage().get::<volt>(),
                        avs.pd_power().get::<watt>(),
                        request.output_voltage().get::<volt>(),
                        request.operating_current().get::<ampere>()
                    )]
                }
                PowerDataObject::Augmented(_) => {
                    vec![format!("RDO: EPR Augmented PDO#{position} (Raw=0x{rdo:08X})")]
                }
                _ => vec![format!("RDO: EPR PDO#{position} (Raw=0x{rdo:08X}, PDO={pdo:?})")],
            }
        }
        PowerSource::Unknown(raw) => {
            let position = raw.object_position();
            if let Some(pdo) = source_caps.and_then(|capabilities| capabilities.pdos().get(position as usize - 1)) {
                let request = data::request::FixedVariableSupply(raw.0);
                vec![format!(
                    "RDO: Requesting PDO#{position} ({}) @ {:.1}A",
                    format_pdo(pdo),
                    request.operating_current().get::<ampere>()
                )]
            } else {
                vec![format!("RDO: Requesting PDO#{position} (Raw=0x{:08X})", raw.0)]
            }
        }
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

fn format_capabilities(capabilities: &[PowerDataObject], title: &str) -> Vec<String> {
    let mut lines = vec![format!("[{title}]")];
    for (index, pdo) in capabilities.iter().enumerate() {
        if matches!(pdo, PowerDataObject::FixedSupply(fixed) if fixed.0 == 0) {
            lines.push(format!("PDO[{}]: --- (separator) ---", index + 1));
        } else {
            lines.push(format!("PDO[{}]: {}", index + 1, format_pdo(pdo)));
        }
    }
    lines
}
