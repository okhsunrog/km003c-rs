//! KM003C PD Event Packet parsing and representation

use bytes::Bytes;
use std::fmt;
use usbpd::protocol_layer::message::{
    Data, Message,
    pdo::{Augmented, PowerDataObject, SourceCapabilities},
};

/// Enum for the three event types in the KM003C PD event stream.
#[derive(Debug, Clone, PartialEq)]
pub enum EventPacket {
    Connection(ConnectionEvent),
    Status(StatusPacket),
    PdMessage(WrappedPdMessage),
}

/// Connection event (Attach/Detach)
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionEvent {
    pub timestamp: u32, // 24 bits
    pub cc_pin: u8,     // 1 = CC1, 2 = CC2
    pub action: u8,     // 1 = Attach, 2 = Detach
}

/// Periodic status packet (VBUS/IBUS/CC voltages)
#[derive(Debug, Clone, PartialEq)]
pub struct StatusPacket {
    pub timestamp: u32, // 24 bits
    pub vbus_raw: u16,
    pub ibus_raw: u16,
    pub cc1_raw: u16,
    pub cc2_raw: u16,
    pub type_id: u8, // First byte
}

/// Wrapped PD message (with direction, timestamp, and raw PD bytes)
#[derive(Debug, Clone, PartialEq)]
pub struct WrappedPdMessage {
    pub direction: PdDirection,
    pub timestamp: u32,    // 24 bits
    pub pd_bytes: Bytes,   // The full PD message (header + data objects)
    pub wrapper_flags: u8, // The first byte (for debugging)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdDirection {
    SrcToSnk,
    SnkToSrc,
    Unknown,
}

/// Parse a single EventPacket from the start of the given byte slice.
/// Returns (packet, bytes_consumed) on success, or None if not enough data.
pub fn parse_event_packet(input: &[u8]) -> Option<(EventPacket, usize)> {
    if input.is_empty() {
        return None;
    }
    let first = input[0];
    if first == 0x45 {
        // Connection event: 6 bytes
        if input.len() < 6 {
            return None;
        }
        let timestamp = u32::from_le_bytes([input[1], input[2], input[3], 0]);
        let event_data = input[5];
        let cc_pin = (event_data & 0xF0) >> 4;
        let action = event_data & 0x0F;
        let event = ConnectionEvent {
            timestamp,
            cc_pin,
            action,
        };
        Some((EventPacket::Connection(event), 6))
    } else if (0x80..=0x9F).contains(&first) {
        // Wrapped PD message
        if input.len() < 8 {
            return None;
        }
        let timestamp = u32::from_le_bytes([input[1], input[2], input[3], 0]);
        let wrapper_flags = input[0];
        let direction = if (wrapper_flags & 0x04) != 0 {
            PdDirection::SrcToSnk
        } else {
            PdDirection::SnkToSrc
        };
        // PD header is at input[6..8]
        let pd_header = u16::from_le_bytes([input[6], input[7]]);
        let num_objects = ((pd_header >> 12) & 0x07) as usize;
        let pd_len = 2 + num_objects * 4;
        let total_len = 6 + pd_len;
        if input.len() < total_len {
            return None;
        }
        let pd_bytes = Bytes::copy_from_slice(&input[6..6 + pd_len]);
        let msg = WrappedPdMessage {
            direction,
            timestamp,
            pd_bytes,
            wrapper_flags,
        };
        Some((EventPacket::PdMessage(msg), total_len))
    } else {
        // Status packet: 12 bytes
        if input.len() < 12 {
            return None;
        }
        let type_id = input[0];
        let timestamp = u32::from_le_bytes([input[1], input[2], input[3], 0]);
        let vbus_raw = u16::from_le_bytes([input[4], input[5]]);
        let ibus_raw = u16::from_le_bytes([input[6], input[7]]);
        let cc1_raw = u16::from_le_bytes([input[8], input[9]]);
        let cc2_raw = u16::from_le_bytes([input[10], input[11]]);
        let pkt = StatusPacket {
            timestamp,
            vbus_raw,
            ibus_raw,
            cc1_raw,
            cc2_raw,
            type_id,
        };
        Some((EventPacket::Status(pkt), 12))
    }
}

/// Parse a stream of event packets from a byte slice.
pub fn parse_event_stream(mut input: &[u8]) -> Vec<EventPacket> {
    let mut packets = Vec::new();
    while !input.is_empty() {
        if let Some((pkt, consumed)) = parse_event_packet(input) {
            packets.push(pkt);
            input = &input[consumed..];
        } else {
            break;
        }
    }
    packets
}

// --- Pretty-printing stubs ---

impl fmt::Display for EventPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventPacket::Connection(ev) => write!(f, "{:?}", ev),
            EventPacket::Status(ev) => write!(f, "{:?}", ev),
            EventPacket::PdMessage(ev) => write!(f, "{}", ev),
        }
    }
}

impl fmt::Display for WrappedPdMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = Message::from_bytes(&self.pd_bytes);
        if let Some(Data::SourceCapabilities(ref caps)) = msg.data {
            writeln!(f, "Source Capabilities:")?;
            write!(f, "{}", format_source_capabilities(caps))
        } else {
            write!(f, "{:?}", msg)
        }
    }
}

fn format_source_capabilities(caps: &SourceCapabilities) -> String {
    let mut output = String::new();
    use std::fmt::Write;
    writeln!(
        output,
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
        writeln!(output, "  [{}] {}", pdo_index, line).unwrap();
    }
    output
}
