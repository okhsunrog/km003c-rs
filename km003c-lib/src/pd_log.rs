//! Human-readable log entries for a stream of KM003C USB PD events.
//!
//! [`PdLogger`] runs events through the stateful [`PdSessionDecoder`] and
//! describes each result for display: a category for colour coding, the
//! message name as the USB PD specification spells it, the header fields, and
//! detail lines for capabilities and requests. Front ends lay the fields out
//! as they see fit; [`PdLogEntry::summary`] joins them into one line.

use uom::si::electric_current::milliampere;
use uom::si::electric_potential::millivolt;
use uom::si::power::microwatt;
use uom::si::time::second;
use usbpd::protocol_layer::message::Payload;
use usbpd::protocol_layer::message::data::source_capabilities::{Augmented, PowerDataObject, SourceCapabilities};
use usbpd::protocol_layer::message::data::{self, Data};
use usbpd::protocol_layer::message::extended::Extended;
use usbpd::protocol_layer::message::header::{
    ControlMessageType, DataMessageType, ExtendedMessageType, Header, MessageType,
};
use usbpd::units::{ElectricCurrent, ElectricPotential, Power};

use crate::pd::PdEvent;
use crate::pd_decode::{
    DecodedPdEvent, DecodedPdMessage, PdChunkState, PdChunkStatus, PdDecodeFailure, PdSessionDecoder,
};

// usbpd stores quantities as `u32` in milliamperes, millivolts and
// microwatts. Reading them in amperes or volts drops the fraction (2.2 A reads
// as 2 A), so these convert from the exact base units instead.
trait Amps {
    fn amps(self) -> f64;
}
trait Volts {
    fn volts(self) -> f64;
}
trait Watts {
    fn watts(self) -> f64;
}

impl Amps for ElectricCurrent {
    fn amps(self) -> f64 {
        f64::from(self.get::<milliampere>()) / 1e3
    }
}

impl Volts for ElectricPotential {
    fn volts(self) -> f64 {
        f64::from(self.get::<millivolt>()) / 1e3
    }
}

impl Watts for Power {
    fn watts(self) -> f64 {
        f64::from(self.get::<microwatt>()) / 1e6
    }
}

/// Kind of a log entry, for colour coding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdLogCategory {
    Connect,
    Disconnect,
    SourceCaps,
    Request,
    Control,
    Extended,
    Error,
}

/// One PD event described for display.
#[derive(Debug, Clone, PartialEq)]
pub struct PdLogEntry {
    /// Device time of the event.
    pub timestamp_seconds: f64,
    pub category: PdLogCategory,
    /// SOP type of a wire message; `None` for connection events.
    pub sop: Option<u8>,
    /// What happened, such as `Source_Capabilities` or `Connect`.
    pub title: String,
    /// Header fields of a decoded message: ID and power/data roles.
    pub header: Option<String>,
    /// Detail lines, such as one per PDO or the decoded RDO.
    pub details: Vec<String>,
}

impl PdLogEntry {
    /// The entry as a single line: `[12.345s] SOP0: Accept (ID=3, Source/Dfp)`.
    pub fn summary(&self) -> String {
        let time = format!("[{:.3}s]", self.timestamp_seconds);
        match (self.sop, &self.header) {
            (None, _) => format!("{time} ** {} **", self.title.to_uppercase()),
            (Some(sop), None) => format!("{time} SOP{sop}: {}", self.title),
            (Some(sop), Some(header)) => format!("{time} SOP{sop}: {} ({header})", self.title),
        }
    }

    /// Whether this is a GoodCRC acknowledgement, which follows nearly every
    /// message and is usually hidden.
    pub fn is_good_crc(&self) -> bool {
        self.title == "GoodCRC"
    }
}

/// Describes KM003C PD events, keeping the decoding state across them.
#[derive(Debug, Clone, Default)]
pub struct PdLogger {
    session: PdSessionDecoder,
}

impl PdLogger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget the connection state, as a new connection does.
    pub fn reset(&mut self) {
        self.session.reset();
    }

    /// Most recently observed SPR source capabilities.
    pub fn source_capabilities(&self) -> Option<&SourceCapabilities> {
        self.session.source_capabilities()
    }

    pub fn log_event(&mut self, event: &PdEvent) -> PdLogEntry {
        match self.session.decode_event(event) {
            DecodedPdEvent::Connect { timestamp } => connection_entry(timestamp.get::<second>(), true),
            DecodedPdEvent::Disconnect { timestamp } => connection_entry(timestamp.get::<second>(), false),
            DecodedPdEvent::Message(message) => self.message_entry(&message),
            DecodedPdEvent::Chunk(status) => chunk_entry(status),
            DecodedPdEvent::Error(failure) => failure_entry(failure),
        }
    }

    fn message_entry(&self, decoded: &DecodedPdMessage) -> PdLogEntry {
        let message = &decoded.message;
        let (category, details) = match &message.payload {
            Some(Payload::Data(Data::SourceCapabilities(capabilities))) => (
                PdLogCategory::SourceCaps,
                format_capabilities(capabilities.pdos(), "SPR Source Capabilities"),
            ),
            Some(Payload::Data(Data::Request(request))) => (
                PdLogCategory::Request,
                format_request(request, self.session.source_capabilities()),
            ),
            Some(Payload::Data(Data::EprMode(mode))) => (PdLogCategory::Extended, vec![format!("EPR Mode: {mode:?}")]),
            Some(Payload::Data(Data::Unknown)) => (PdLogCategory::Control, vec!["Unknown Data Message".to_string()]),
            Some(Payload::Data(data)) => (PdLogCategory::Control, vec![format!("Data: {data:?}")]),
            Some(Payload::Extended(Extended::EprSourceCapabilities(pdos))) => (
                PdLogCategory::Extended,
                format_capabilities(pdos.as_slice(), "EPR Source Capabilities"),
            ),
            Some(Payload::Extended(Extended::ExtendedControl(control))) => (
                PdLogCategory::Extended,
                vec![format!(
                    "Extended Control: {:?} (data=0x{:02X})",
                    control.message_type(),
                    control.data()
                )],
            ),
            Some(Payload::Extended(extended)) => (PdLogCategory::Extended, vec![format!("Extended: {extended:?}")]),
            None => (PdLogCategory::Control, Vec::new()),
        };

        PdLogEntry {
            timestamp_seconds: decoded.timestamp.get::<second>(),
            category,
            sop: Some(decoded.sop),
            title: message_type_name(message.header.message_type()).to_string(),
            header: Some(format_header(&message.header)),
            details,
        }
    }
}

fn connection_entry(timestamp_seconds: f64, connected: bool) -> PdLogEntry {
    PdLogEntry {
        timestamp_seconds,
        category: if connected {
            PdLogCategory::Connect
        } else {
            PdLogCategory::Disconnect
        },
        sop: None,
        title: if connected { "Connect" } else { "Disconnect" }.to_string(),
        header: None,
        details: Vec::new(),
    }
}

fn format_header(header: &Header) -> String {
    format!(
        "ID={}, {:?}/{:?}",
        header.message_id(),
        header.port_power_role(),
        header.port_data_role()
    )
}

fn chunk_entry(status: PdChunkStatus) -> PdLogEntry {
    let message_type = message_type_name(MessageType::Extended(status.message_type));
    let title = match status.state {
        PdChunkState::Request { chunk_number } => format!("Chunk Request (chunk={chunk_number}, type={message_type})"),
        PdChunkState::Pending {
            received_chunk,
            next_chunk,
        } => format!("{message_type} chunk {received_chunk} received, waiting for chunk {next_chunk}"),
        PdChunkState::Requested { chunk_number } => format!("{message_type} chunk {chunk_number} requested"),
        PdChunkState::Unsupported {
            chunk_number,
            data_size,
        } => format!("Chunked {message_type} (chunk {chunk_number}, {data_size} bytes) - not assembled"),
    };

    PdLogEntry {
        timestamp_seconds: status.timestamp.get::<second>(),
        category: PdLogCategory::Extended,
        sop: Some(status.sop),
        title,
        header: None,
        details: Vec::new(),
    }
}

fn failure_entry(failure: PdDecodeFailure) -> PdLogEntry {
    PdLogEntry {
        timestamp_seconds: failure.timestamp.get::<second>(),
        category: PdLogCategory::Error,
        sop: Some(failure.sop),
        title: format!("Parse error: {}", failure.error),
        header: None,
        details: vec![format!("Hex: {:02X?}", failure.wire_data)],
    }
}

/// The message name as the USB PD specification spells it.
pub fn message_type_name(message_type: MessageType) -> &'static str {
    match message_type {
        MessageType::Control(control) => match control {
            ControlMessageType::GoodCRC => "GoodCRC",
            ControlMessageType::GotoMin => "GotoMin",
            ControlMessageType::Accept => "Accept",
            ControlMessageType::Reject => "Reject",
            ControlMessageType::Ping => "Ping",
            ControlMessageType::PsRdy => "PS_RDY",
            ControlMessageType::GetSourceCap => "Get_Source_Cap",
            ControlMessageType::GetSinkCap => "Get_Sink_Cap",
            ControlMessageType::DrSwap => "DR_Swap",
            ControlMessageType::PrSwap => "PR_Swap",
            ControlMessageType::VconnSwap => "VCONN_Swap",
            ControlMessageType::Wait => "Wait",
            ControlMessageType::SoftReset => "Soft_Reset",
            ControlMessageType::DataReset => "Data_Reset",
            ControlMessageType::DataResetComplete => "Data_Reset_Complete",
            ControlMessageType::NotSupported => "Not_Supported",
            ControlMessageType::GetSourceCapExtended => "Get_Source_Cap_Extended",
            ControlMessageType::GetStatus => "Get_Status",
            ControlMessageType::FrSwap => "FR_Swap",
            ControlMessageType::GetPpsStatus => "Get_PPS_Status",
            ControlMessageType::GetCountryCodes => "Get_Country_Codes",
            ControlMessageType::GetSinkCapExtended => "Get_Sink_Cap_Extended",
            ControlMessageType::GetSourceInfo => "Get_Source_Info",
            ControlMessageType::GetRevision => "Get_Revision",
            ControlMessageType::Reserved => "Reserved",
        },
        MessageType::Data(data) => match data {
            DataMessageType::SourceCapabilities => "Source_Capabilities",
            DataMessageType::Request => "Request",
            DataMessageType::Bist => "BIST",
            DataMessageType::SinkCapabilities => "Sink_Capabilities",
            DataMessageType::BatteryStatus => "Battery_Status",
            DataMessageType::Alert => "Alert",
            DataMessageType::GetCountryInfo => "Get_Country_Info",
            DataMessageType::EnterUsb => "Enter_USB",
            DataMessageType::EprRequest => "EPR_Request",
            DataMessageType::EprMode => "EPR_Mode",
            DataMessageType::SourceInfo => "Source_Info",
            DataMessageType::Revision => "Revision",
            DataMessageType::VendorDefined => "Vendor_Defined",
            DataMessageType::Reserved => "Reserved",
        },
        MessageType::Extended(extended) => match extended {
            ExtendedMessageType::SourceCapabilitiesExtended => "Source_Capabilities_Extended",
            ExtendedMessageType::Status => "Status",
            ExtendedMessageType::GetBatteryCap => "Get_Battery_Cap",
            ExtendedMessageType::GetBatteryStatus => "Get_Battery_Status",
            ExtendedMessageType::BatteryCapabilities => "Battery_Capabilities",
            ExtendedMessageType::GetManufacturerInfo => "Get_Manufacturer_Info",
            ExtendedMessageType::ManufacturerInfo => "Manufacturer_Info",
            ExtendedMessageType::SecurityRequest => "Security_Request",
            ExtendedMessageType::SecurityResponse => "Security_Response",
            ExtendedMessageType::FirmwareUpdateRequest => "Firmware_Update_Request",
            ExtendedMessageType::FirmwareUpdateResponse => "Firmware_Update_Response",
            ExtendedMessageType::PpsStatus => "PPS_Status",
            ExtendedMessageType::CountryInfo => "Country_Info",
            ExtendedMessageType::CountryCodes => "Country_Codes",
            ExtendedMessageType::SinkCapabilitiesExtended => "Sink_Capabilities_Extended",
            ExtendedMessageType::ExtendedControl => "Extended_Control",
            ExtendedMessageType::EprSourceCapabilities => "EPR_Source_Capabilities",
            ExtendedMessageType::EprSinkCapabilities => "EPR_Sink_Capabilities",
            ExtendedMessageType::VendorDefinedExtended => "Vendor_Defined_Extended",
            ExtendedMessageType::Reserved => "Reserved",
        },
    }
}

fn format_request(request: &data::request::PowerSource, source_caps: Option<&SourceCapabilities>) -> Vec<String> {
    use data::request::PowerSource;

    match request {
        PowerSource::FixedVariableSupply(request) => {
            let current = request.operating_current().amps();
            let max_current = request.max_operating_current().amps();
            let position = request.object_position();
            let pdo = source_caps
                .and_then(|capabilities| capabilities.pdos().get(usize::from(position).checked_sub(1)?))
                .map(format_pdo);

            if let Some(pdo) = pdo {
                vec![format!("RDO: PDO#{position} ({pdo}) @ {current:.1}A")]
            } else {
                vec![format!("RDO: PDO#{position} @ {current:.1}A (Max {max_current:.1}A)")]
            }
        }
        // usbpd returns this one in whole-watt u32 storage, so it is already
        // rounded down to the watt.
        PowerSource::Battery(request) => vec![format!(
            "RDO: Requesting Battery PDO#{} @ {}W",
            request.object_position(),
            request.operating_power().get::<uom::si::power::watt>()
        )],
        PowerSource::Pps(request) => vec![format!(
            "RDO: Requesting PPS PDO#{} @ {:.2}V / {:.2}A",
            request.object_position(),
            request.output_voltage().volts(),
            request.operating_current().amps()
        )],
        PowerSource::Avs(request) => vec![format!(
            "RDO: Requesting AVS PDO#{} @ {:.2}V / {:.2}A",
            request.object_position(),
            request.output_voltage().volts(),
            request.operating_current().amps()
        )],
        PowerSource::EprRequest(request) => {
            use data::request::{Avs as RdoAvs, FixedVariableSupply as RdoFixed, RawDataObject};

            let (rdo, pdo) = (&request.rdo, &request.pdo);
            let position = RawDataObject(*rdo).object_position();
            match pdo {
                PowerDataObject::FixedSupply(fixed) => {
                    let request = RdoFixed(*rdo);
                    vec![format!(
                        "RDO: EPR Fixed PDO#{position} ({:.1}V) @ {:.2}A (Max {:.2}A)",
                        fixed.voltage().volts(),
                        request.operating_current().amps(),
                        request.max_operating_current().amps()
                    )]
                }
                PowerDataObject::Augmented(Augmented::Spr(pps)) => {
                    let request = RdoAvs(*rdo);
                    vec![format!(
                        "RDO: EPR PPS PDO#{position} ({:.1}-{:.1}V) @ {:.2}V / {:.2}A",
                        pps.min_voltage().volts(),
                        pps.max_voltage().volts(),
                        request.output_voltage().volts(),
                        request.operating_current().amps()
                    )]
                }
                PowerDataObject::Augmented(Augmented::Epr(avs)) => {
                    let request = RdoAvs(*rdo);
                    vec![format!(
                        "RDO: EPR AVS PDO#{position} ({:.1}-{:.1}V @ {:.0}W) @ {:.2}V / {:.2}A",
                        avs.min_voltage().volts(),
                        avs.max_voltage().volts(),
                        avs.pd_power().watts(),
                        request.output_voltage().volts(),
                        request.operating_current().amps()
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
            if let Some(pdo) =
                source_caps.and_then(|capabilities| capabilities.pdos().get(usize::from(position).checked_sub(1)?))
            {
                let request = data::request::FixedVariableSupply(raw.0);
                vec![format!(
                    "RDO: Requesting PDO#{position} ({}) @ {:.1}A",
                    format_pdo(pdo),
                    request.operating_current().amps()
                )]
            } else {
                vec![format!("RDO: Requesting PDO#{position} (Raw=0x{:08X})", raw.0)]
            }
        }
    }
}

/// One PDO as a short line, such as `Fixed 9V @ 3.0A (27W) [USB]`.
pub fn format_pdo(pdo: &PowerDataObject) -> String {
    match pdo {
        PowerDataObject::FixedSupply(fixed) => {
            let voltage = fixed.voltage().volts();
            let current = fixed.max_current().amps();
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
            battery.min_voltage().volts(),
            battery.max_voltage().volts(),
            battery.max_power().watts()
        ),
        PowerDataObject::VariableSupply(variable) => format!(
            "Variable {:.0}-{:.0}V @ {:.1}A",
            variable.min_voltage().volts(),
            variable.max_voltage().volts(),
            variable.max_current().amps()
        ),
        PowerDataObject::Augmented(Augmented::Spr(pps)) => {
            let min_voltage = pps.min_voltage().volts();
            let max_voltage = pps.max_voltage().volts();
            let current = pps.max_current().amps();
            let limited = if pps.pps_power_limited() { " (limited)" } else { "" };
            format!(
                "PPS {min_voltage:.1}-{max_voltage:.1}V @ {current:.1}A ({:.0}W){limited}",
                max_voltage * current
            )
        }
        PowerDataObject::Augmented(Augmented::Epr(avs)) => format!(
            "EPR AVS {:.0}-{:.0}V @ {:.0}W",
            avs.min_voltage().volts(),
            avs.max_voltage().volts(),
            avs.pd_power().watts()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pd::PdEventData;
    use uom::si::f64::Time;
    use uom::si::time::millisecond;

    fn message(timestamp_ms: f64, wire_hex: &str) -> PdEvent {
        PdEvent {
            timestamp: Time::new::<millisecond>(timestamp_ms),
            data: PdEventData::PdMessage {
                sop: 0,
                wire_data: hex::decode(wire_hex).unwrap(),
            },
        }
    }

    // Captured Source_Capabilities with six PDOs and the Request that follows.
    const SOURCE_CAPS: &str = "a1612c9101082cd102002cc103002cb10400454106003c21dcc0";
    const REQUEST: &str = "8210dc700323";

    #[test]
    fn source_capabilities_list_their_pdos() {
        let entry = PdLogger::new().log_event(&message(1_500.0, SOURCE_CAPS));

        assert_eq!(entry.category, PdLogCategory::SourceCaps);
        assert_eq!(entry.title, "Source_Capabilities");
        assert_eq!(entry.sop, Some(0));
        assert_eq!(entry.details[0], "[SPR Source Capabilities]");
        assert_eq!(entry.details.len(), 7);
        assert!(entry.details[1].starts_with("PDO[1]: Fixed 5V @ 3.0A (15W)"));
        // Fractional volts survive: usbpd's u32 storage used to cut 3.3 V to 3.
        assert!(entry.details[6].starts_with("PDO[6]: PPS 3.3-"), "{}", entry.details[6]);
        assert!(entry.summary().starts_with("[1.500s] SOP0: Source_Capabilities (ID="));
    }

    #[test]
    fn a_request_names_the_pdo_it_selects() {
        let mut logger = PdLogger::new();
        logger.log_event(&message(0.0, SOURCE_CAPS));
        let entry = logger.log_event(&message(10.0, REQUEST));

        assert_eq!(entry.category, PdLogCategory::Request);
        assert_eq!(entry.title, "Request");
        assert_eq!(
            entry.details,
            vec!["RDO: PDO#2 (Fixed 9V @ 3.0A (27W)) @ 2.2A".to_string()]
        );
    }

    #[test]
    fn connection_events_have_no_sop() {
        let entry = PdLogger::new().log_event(&PdEvent {
            timestamp: Time::new::<millisecond>(2_000.0),
            data: PdEventData::Connect,
        });

        assert_eq!(entry.category, PdLogCategory::Connect);
        assert_eq!(entry.sop, None);
        assert_eq!(entry.summary(), "[2.000s] ** CONNECT **");
    }

    #[test]
    fn good_crc_is_recognised() {
        let entry = PdLogger::new().log_event(&message(0.0, "4102"));
        assert!(entry.is_good_crc());
    }
}
