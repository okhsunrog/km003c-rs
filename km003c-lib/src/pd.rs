//! KM003C PD Event Packet parsing and representation.
//!
//! This module handles the parsing of the "inner event stream" found within
//! the payload of `PutData` packets from the KM003C device. This stream is a
//! concatenation of three different event packet types.

use bytes::Bytes;
use std::fmt;
use usbpd::protocol_layer::message::{
    Data, Message,
    pdo::{Augmented, PowerDataObject, SourceCapabilities},
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, byteorder::little_endian::U16};

// --- Data Structures ---

/// A single, self-contained event from the KM003C's inner data stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventPacket {
    /// A physical connection event (Attach/Detach). Carries record timestamp.
    Connection(ConnectionEvent, u32),
    /// A periodic status update containing live voltage/current readings. Carries record timestamp.
    Status(StatusPacket, u32),
    /// An encapsulated USB Power Delivery message. Carries record timestamp.
    PdMessage(WrappedPdMessage, u32),
}

/// Connection event (Attach/Detach) body.
/// Identified by the first body byte `0x45`.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionEvent {
    pub _reserved: u8,
    pub event_data: u8,
}

/// Periodic status packet containing live ADC readings (per-event update).
/// Body size is 8 bytes (four u16 values).
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusPacket {
    pub vbus_raw: U16,
    pub ibus_raw: U16,
    pub cc1_raw: U16,
    pub cc2_raw: U16,
}

/// A wrapper for a standard USB Power Delivery message.
/// The length is variable (from 8 to 32 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedPdMessage {
    /// True if the message direction is from Source to Sink.
    pub is_src_to_snk: bool,
    /// The raw bytes of the standard PD message (header + data objects).
    /// This can be parsed by `usbpd::protocol_layer::message::Message::from_bytes`.
    pub pd_bytes: Bytes,
}

// --- Parsing Logic ---

impl EventPacket {
    /// Parse one inner record. `input` must point at the start of a record header (8 bytes).
    pub fn from_slice(input: &[u8]) -> Result<(Self, usize), ParseError> {
        if input.len() < 8 {
            return Err(ParseError::UnexpectedEof);
        }

        // 8-byte meta header
        let header = &input[0..8];
        let len = header[6] as usize; // payload length stored at header[6]
        let total_len = 8 + len;
        if input.len() < total_len {
            return Err(ParseError::UnexpectedEof);
        }

        let ts = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let body = &input[8..total_len];

        // Detect PD prelude wrapper: AA .. CRC .. AA with SOP check
        if is_pd_prelude(body) {
            // body layout: [0]=0xAA, [1..=3]=hdr3, [4]=crc, [5]=0xAA, [6..=12]=aux, [13..]=PD bytes
            let pd_bytes = &body[13..];
            // Calculate PD length from PD header to slice correctly
            let pd_len = compute_pd_length(pd_bytes).ok_or(ParseError::UnexpectedEof)?;
            // Direction bit is carried in prelude header[1]
            let is_src_to_snk = (body[1] & 0x04) != 0;
            let packet = WrappedPdMessage {
                is_src_to_snk,
                pd_bytes: Bytes::copy_from_slice(&pd_bytes[..pd_len]),
            };
            return Ok((EventPacket::PdMessage(packet, ts), total_len));
        }

        // Connection event: body starts with 0x45 and has at least 2 bytes
        if !body.is_empty() && body[0] == 0x45 {
            if body.len() < 2 {
                return Err(ParseError::UnexpectedEof);
            }
            let event = ConnectionEvent::ref_from_bytes(&body[0..2]).map_err(|_| ParseError::UnexpectedEof)?;
            return Ok((EventPacket::Connection(*event, ts), total_len));
        }

        // Status event: expect 8-byte body containing 4 u16 values
        if body.len() >= 8 {
            if let Ok(status) = StatusPacket::ref_from_bytes(&body[0..8]) {
                return Ok((EventPacket::Status(*status, ts), total_len));
            }
        }

        // Fallback: treat as unrecognized status-like record if shorter
        Err(ParseError::UnexpectedEof)
    }
}

/// Custom error type for parsing events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// The input slice was too short to contain a full packet.
    UnexpectedEof,
}

/// Parses a full stream of concatenated event packets.
/// It will stop if it encounters a parsing error (e.g., a truncated final packet).
pub fn parse_event_stream(mut input: &[u8]) -> Result<Vec<EventPacket>, ParseError> {
    let mut packets = Vec::new();
    while !input.is_empty() {
        match EventPacket::from_slice(input) {
            Ok((packet, consumed)) => {
                packets.push(packet);
                input = &input[consumed..];
            }
            Err(e) => {
                // For a stream, hitting an EOF on the last, partial packet is normal.
                // We just return what we have so far.
                if e == ParseError::UnexpectedEof {
                    break;
                }
                return Err(e);
            }
        }
    }
    Ok(packets)
}

impl ConnectionEvent {
    /// Decodes the CC pin from the event data.
    pub fn cc_pin(&self) -> u8 {
        (self.event_data & 0xF0) >> 4
    }
    /// Decodes the connection action from the event data.
    pub fn action(&self) -> u8 {
        self.event_data & 0x0F
    }
}

impl StatusPacket {
}

impl WrappedPdMessage {
    /// Performs a simple, stateless parse of the contained PD message bytes.
    ///
    /// Note: For a fully detailed parse of `Request` messages, the library user
    /// should maintain the `SourceCapabilities` state and use the stateful
    /// `Message::from_bytes_with_state` function on the `pd_bytes` field.
    pub fn parse_message_stateless(&self) -> Result<Message, usbpd::protocol_layer::message::ParseError> {
        Message::from_bytes(&self.pd_bytes)
    }
}

// --- Pretty-printing implementations ---

impl fmt::Display for EventPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventPacket::Connection(ev, ts) => {
                let action = match ev.action() {
                    1 => "Attach",
                    2 => "Detach",
                    _ => "Unknown",
                };
                let cc = match ev.cc_pin() {
                    1 => "CC1",
                    2 => "CC2",
                    _ => "Unknown",
                };
                write!(f, "[{}] [Conn] {}: {}", ts, action, cc)
            }
            EventPacket::Status(ev, ts) => {
                write!(
                    f,
                    "[{}] [Status] Vbus:{} Ibus:{} CC1:{} CC2:{}",
                    ts,
                    ev.vbus_raw.get(),
                    ev.ibus_raw.get(),
                    ev.cc1_raw.get(),
                    ev.cc2_raw.get()
                )
            }
            EventPacket::PdMessage(ev, ts) => {
                let direction = if ev.is_src_to_snk { "->" } else { "<-" };
                // Safe to unwrap here because we know it's valid from the parsing step.
                let msg = ev.parse_message_stateless().unwrap();
                write!(f, "[{}] [PD {}] {}", ts, direction, format_pd_message(&msg))
            }
        }
    }
}

/// Helper function to format PD messages without violating orphan rules
fn format_pd_message(msg: &Message) -> String {
    if let Some(Data::SourceCapabilities(ref caps)) = msg.data {
        // Special, pretty-printing for SourceCapabilities
        let mut output = String::from("SourceCapabilities:");
        output.push('\n');
        output.push_str(&format_source_capabilities(caps));
        output
    } else {
        // For all other message types, use the default debug format.
        format!("{:?}", msg)
    }
}

/// Helper to pretty-print SourceCapabilities PDOs.
fn format_source_capabilities(caps: &SourceCapabilities) -> String {
    let mut output = String::new();
    // Use `std::fmt::Write` trait to write into the string.
    use std::fmt::Write;
    for (i, pdo) in caps.pdos().iter().enumerate() {
        let pdo_index = i + 1;
        let line = match pdo {
            PowerDataObject::FixedSupply(p) => {
                let voltage = p.raw_voltage() as f32 * 50.0 / 1000.0;
                let current = p.raw_max_current() as f32 * 10.0 / 1000.0;
                format!("  [{}] Fixed:       {:.2} V @ {:.2} A", pdo_index, voltage, current)
            }
            PowerDataObject::VariableSupply(p) => {
                let min_v = p.raw_min_voltage() as f32 * 50.0 / 1000.0;
                let max_v = p.raw_max_voltage() as f32 * 50.0 / 1000.0;
                let current = p.raw_max_current() as f32 * 10.0 / 1000.0;
                format!(
                    "  [{}] Variable:    {:.2} - {:.2} V @ {:.2} A",
                    pdo_index, min_v, max_v, current
                )
            }
            PowerDataObject::Battery(p) => {
                let min_v = p.raw_min_voltage() as f32 * 50.0 / 1000.0;
                let max_v = p.raw_max_voltage() as f32 * 50.0 / 1000.0;
                let power = p.raw_max_power() as f32 * 250.0 / 1000.0;
                format!(
                    "  [{}] Battery:     {:.2} - {:.2} V @ {:.2} W",
                    pdo_index, min_v, max_v, power
                )
            }
            PowerDataObject::Augmented(augmented) => match augmented {
                Augmented::Spr(p) => {
                    let min_v = p.raw_min_voltage() as f32 * 100.0 / 1000.0;
                    let max_v = p.raw_max_voltage() as f32 * 100.0 / 1000.0;
                    let current = p.raw_max_current() as f32 * 50.0 / 1000.0;
                    let pps_str = format!("PPS:         {:.2} - {:.2} V @ {:.2} A", min_v, max_v, current);
                    format!("  [{}] {}", pdo_index, pps_str)
                }
                _ => format!("  [{}] Unknown Augmented PDO", pdo_index),
            },
            _ => format!("  [{}] Unknown PDO", pdo_index),
        };
        writeln!(output, "{}", line).unwrap();
    }
    output
}

// --- Helpers ---

fn is_pd_prelude(body: &[u8]) -> bool {
    if body.len() < 14 {
        return false;
    }
    if body[0] != 0xAA || body[5] != 0xAA {
        return false;
    }
    // SOP check: lower 3 bits of body[2] == 0 (SOP)
    if (body[2] & 0x07) != 0 {
        return false;
    }
    // CRC over body[1..=3] must equal body[4]
    let mut crc: u8 = 0;
    for &b in &body[1..=3] {
        crc ^= b;
        for _ in 0..8 {
            let msb = (crc & 0x80) != 0;
            crc = crc.wrapping_shl(1);
            if msb {
                crc ^= 0x29; // matches observed polynomial in binary loop
            }
        }
    }
    crc == body[4]
}

fn compute_pd_length(pd: &[u8]) -> Option<usize> {
    if pd.len() < 2 { return None; }
    let hdr = u16::from_le_bytes([pd[0], pd[1]]);
    let extended = (hdr & 0x8000) != 0;
    if extended {
        if pd.len() < 4 { return None; }
        let ext = u16::from_le_bytes([pd[2], pd[3]]);
        let size = (ext & 0x01ff) as usize; // 9-bit data size
        let total = 4 + size;
        if total <= pd.len() { Some(total) } else { None }
    } else {
        let ndo = ((hdr >> 12) & 0x07) as usize; // number of 32-bit data objects
        let total = 2 + 4 * ndo;
        if total <= pd.len() { Some(total) } else { None }
    }
}

// Optional metadata exposure for callers that need header flags without breaking existing API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventMetaHeader {
    pub timestamp: u32,
    pub flags4: u8,
    pub flags5: u8,
    pub len: u8,
    pub flags7: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DLine {
    DP,
    DM,
}

impl EventMetaHeader {
    /// Heuristic from Windows app: header[7] bit0 selects D+/D- label (0=DP, 1=DM)
    pub fn d_line(self) -> DLine {
        if (self.flags7 & 0x01) == 0 { DLine::DP } else { DLine::DM }
    }
}

/// Parse inner stream and return packets alongside their meta headers.
pub fn parse_event_stream_with_meta(mut input: &[u8]) -> Result<Vec<(EventPacket, EventMetaHeader)>, ParseError> {
    let mut out = Vec::new();
    while !input.is_empty() {
        if input.len() < 8 { return Err(ParseError::UnexpectedEof); }
        let hdr = &input[..8];
        let meta = EventMetaHeader {
            timestamp: u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]),
            flags4: hdr[4], flags5: hdr[5], len: hdr[6], flags7: hdr[7],
        };
        match EventPacket::from_slice(input) {
            Ok((pkt, consumed)) => { out.push((pkt, meta)); input = &input[consumed..]; }
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use crate::packet::{RawPacket, Attribute};

    #[test]
    fn crc_and_prelude_detection_synthetic() {
        // Construct a synthetic PD prelude body with valid CRC and minimal PD header
        let mut body = Vec::new();
        body.push(0xAA);
        let b1 = 0x04; // direction bit set (SRC->SNK)
        let b2 = 0x00; // SOP
        let b3 = 0x12; // arbitrary
        body.push(b1);
        body.push(b2);
        body.push(b3);
        // Compute CRC-8 poly 0x29 over [b1,b2,b3]
        let mut crc: u8 = 0;
        for &bb in [b1,b2,b3].iter() {
            crc ^= bb;
            for _ in 0..8 { let msb = (crc & 0x80) != 0; crc = crc.wrapping_shl(1); if msb { crc ^= 0x29; } }
        }
        body.push(crc);
        body.push(0xAA);
        body.extend_from_slice(&[0u8;7]); // aux
        // Append minimal PD header (no data objects)
        body.extend_from_slice(&[0x00, 0x00]);

        assert!(is_pd_prelude(&body));
        let pd = &body[13..];
        let len = compute_pd_length(pd).expect("pd length");
        assert_eq!(len, 2);
        // Tamper with CRC input and ensure detection fails
        let mut tampered = body.clone();
        tampered[1] ^= 0x01;
        assert!(!is_pd_prelude(&tampered));
    }
}
