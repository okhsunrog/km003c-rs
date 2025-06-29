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
    /// A physical connection event (Attach/Detach).
    Connection(ConnectionEvent),
    /// A periodic status update containing live voltage/current readings.
    Status(StatusPacket),
    /// An encapsulated USB Power Delivery message.
    PdMessage(WrappedPdMessage),
}

/// A 6-byte connection event packet (Attach/Detach).
/// Identified by a first byte of `0x45`.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionEvent {
    pub type_id: u8,              // Always 0x45
    pub timestamp_bytes: [u8; 3], // 24-bit little-endian timestamp
    _reserved: u8,
    pub event_data: u8,
}

/// A 12-byte periodic status packet containing live ADC readings.
/// This is the default packet type for any identifier that isn't a known
/// Connection or Wrapped PD Message.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusPacket {
    pub type_id: u8,
    pub timestamp_bytes: [u8; 3], // 24-bit little-endian timestamp
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
    /// The 24-bit timestamp from the wrapper.
    pub timestamp: u32,
    /// The raw bytes of the standard PD message (header + data objects).
    /// This can be parsed by `usbpd::protocol_layer::message::Message::from_bytes`.
    pub pd_bytes: Bytes,
}

// --- Parsing Logic ---

impl EventPacket {
    /// Parses a single `EventPacket` from the start of the given byte slice.
    ///
    /// This is the core parsing logic. It correctly identifies the three known
    /// packet types and handles the ambiguity between `StatusPacket` and
    /// `WrappedPdMessage` packets that start with a byte in the 0x80-0x9F range.
    ///
    /// Returns a `Result` containing the parsed packet and the number of
    /// bytes consumed, or a `ParseError` if the data is malformed or truncated.
    pub fn from_slice(input: &[u8]) -> Result<(Self, usize), ParseError> {
        if input.is_empty() {
            return Err(ParseError::UnexpectedEof);
        }

        match input[0] {
            // Case 1: Connection Event (unambiguous, 6 bytes).
            0x45 => {
                let event = ConnectionEvent::ref_from_bytes(input).map_err(|_| ParseError::UnexpectedEof)?;
                Ok((EventPacket::Connection(*event), std::mem::size_of::<ConnectionEvent>()))
            }

            // Case 2: Potential Wrapped PD Message (ambiguous).
            0x80..=0x9F => {
                const WRAPPER_LEN: usize = 6;
                const MIN_PD_LEN: usize = 2;

                // Check if we have enough data for a wrapper and the smallest possible PD message.
                if input.len() < WRAPPER_LEN + MIN_PD_LEN {
                    // Not enough data for a valid PD message, so it cannot be Type C.
                    // Fall back to treating it as a potentially truncated Type B.
                    let status = StatusPacket::ref_from_bytes(input).map_err(|_| ParseError::UnexpectedEof)?;
                    return Ok((EventPacket::Status(*status), std::mem::size_of::<StatusPacket>()));
                }

                // Attempt to parse the inner bytes as a PD message to validate it.
                // We use the fallible `usbpd::protocol_layer::message::Message::from_bytes` for this check.
                if let Ok(msg) = Message::from_bytes(&input[WRAPPER_LEN..]) {
                    // Success! It's a real PD message. Calculate its full length.
                    let pd_len = 2 + (msg.header.num_objects() * 4);
                    let total_len = WRAPPER_LEN + pd_len;

                    if input.len() < total_len {
                        return Err(ParseError::UnexpectedEof);
                    }

                    let ts_bytes = &input[1..4];
                    let packet = WrappedPdMessage {
                        is_src_to_snk: (input[0] & 0x04) != 0,
                        timestamp: u32::from_le_bytes([ts_bytes[0], ts_bytes[1], ts_bytes[2], 0]),
                        pd_bytes: Bytes::copy_from_slice(&input[WRAPPER_LEN..total_len]),
                    };
                    Ok((EventPacket::PdMessage(packet), total_len))
                } else {
                    // False positive. The `usbpd` parser rejected it. This means it's a
                    // 12-byte status packet that happened to start with a "magic" byte.
                    let status = StatusPacket::ref_from_bytes(input).map_err(|_| ParseError::UnexpectedEof)?;
                    Ok((EventPacket::Status(*status), std::mem::size_of::<StatusPacket>()))
                }
            }

            // Case 3: Default to Periodic Status Packet (unambiguous, 12 bytes).
            _ => {
                let status = StatusPacket::ref_from_bytes(input).map_err(|_| ParseError::UnexpectedEof)?;
                Ok((EventPacket::Status(*status), std::mem::size_of::<StatusPacket>()))
            }
        }
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
    /// Gets the 24-bit timestamp as a u32
    pub fn timestamp(&self) -> u32 {
        u32::from_le_bytes([
            self.timestamp_bytes[0],
            self.timestamp_bytes[1],
            self.timestamp_bytes[2],
            0,
        ])
    }

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
    /// Gets the 24-bit timestamp as a u32
    pub fn timestamp(&self) -> u32 {
        u32::from_le_bytes([
            self.timestamp_bytes[0],
            self.timestamp_bytes[1],
            self.timestamp_bytes[2],
            0,
        ])
    }
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
            EventPacket::Connection(ev) => {
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
                write!(f, "[Conn] {}: {}", action, cc)
            }
            EventPacket::Status(ev) => {
                write!(
                    f,
                    "[Status] Type:0x{:02X} Vbus:{} Ibus:{} CC1:{} CC2:{}",
                    ev.type_id,
                    ev.vbus_raw.get(),
                    ev.ibus_raw.get(),
                    ev.cc1_raw.get(),
                    ev.cc2_raw.get()
                )
            }
            EventPacket::PdMessage(ev) => {
                let direction = if ev.is_src_to_snk { "->" } else { "<-" };
                // Safe to unwrap here because we know it's valid from the parsing step.
                let msg = ev.parse_message_stateless().unwrap();
                write!(f, "[PD {}] {}", direction, format_pd_message(&msg))
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
