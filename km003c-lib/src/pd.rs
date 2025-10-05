use bytes::Bytes;
use zerocopy::byteorder::little_endian::{I16, U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::constants::*;
use crate::error::KMError;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// PD Status block (12 bytes) - appears in ADC+PD packets
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct PdStatusRaw {
    pub type_id: u8,
    pub timestamp24: [u8; 3], // 24-bit little-endian
    pub vbus_mv: U16,
    pub ibus_ma: U16,
    pub cc1_mv: U16,
    pub cc2_mv: U16,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "python", pyo3::pyclass(get_all))]
pub struct PdStatus {
    pub type_id: u8,
    pub timestamp: u32, // Converted from 24-bit, ~40ms per tick
    pub vbus_v: f64,
    pub ibus_a: f64,
    pub cc1_v: f64,
    pub cc2_v: f64,
}

impl From<PdStatusRaw> for PdStatus {
    fn from(raw: PdStatusRaw) -> Self {
        // Convert 24-bit timestamp to 32-bit
        let timestamp = u32::from_le_bytes([raw.timestamp24[0], raw.timestamp24[1], raw.timestamp24[2], 0]);

        Self {
            type_id: raw.type_id,
            timestamp,
            vbus_v: raw.vbus_mv.get() as f64 / 1000.0,
            ibus_a: raw.ibus_ma.get() as f64 / 1000.0,
            cc1_v: raw.cc1_mv.get() as f64 / 1000.0,
            cc2_v: raw.cc2_mv.get() as f64 / 1000.0,
        }
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl PdStatus {
    fn __repr__(&self) -> String {
        format!(
            "PdStatus(type_id={}, timestamp={}, vbus={:.3}V, ibus={:.3}A)",
            self.type_id, self.timestamp, self.vbus_v, self.ibus_a
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}

/// PD Preamble (12 bytes) - appears before event stream in PD-only responses
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct PdPreambleRaw {
    pub timestamp32: U32,
    pub vbus_mv: U16,
    pub ibus_ma: I16, // Signed!
    pub cc1_mv: U16,
    pub cc2_mv: U16,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "python", pyo3::pyclass(get_all))]
pub struct PdPreamble {
    pub timestamp: u32, // Milliseconds, frames following events
    pub vbus_v: f64,
    pub ibus_a: f64,
    pub cc1_v: f64,
    pub cc2_v: f64,
}

impl From<PdPreambleRaw> for PdPreamble {
    fn from(raw: PdPreambleRaw) -> Self {
        Self {
            timestamp: raw.timestamp32.get(),
            vbus_v: raw.vbus_mv.get() as f64 / 1000.0,
            ibus_a: raw.ibus_ma.get() as f64 / 1000.0,
            cc1_v: raw.cc1_mv.get() as f64 / 1000.0,
            cc2_v: raw.cc2_mv.get() as f64 / 1000.0,
        }
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl PdPreamble {
    fn __repr__(&self) -> String {
        format!(
            "PdPreamble(timestamp={}ms, vbus={:.3}V, ibus={:.3}A)",
            self.timestamp, self.vbus_v, self.ibus_a
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}

/// Event data types that can appear in PD stream
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "python", derive(pyo3::IntoPyObject))]
pub enum PdEventData {
    #[cfg_attr(feature = "python", pyo3(transparent))]
    Connect(()),
    #[cfg_attr(feature = "python", pyo3(transparent))]
    Disconnect(()),
    PdMessage {
        sop: u8,
        wire_data: Vec<u8>,
    },
}

/// Timestamped PD event
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "python", pyo3::pyclass(get_all, name = "PdEvent"))]
pub struct PdEvent {
    pub timestamp: u32,
    pub data: PdEventData,
}

/// Complete PD event stream with preamble and events
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "python", pyo3::pyclass(name = "PdEventStream"))]
pub struct PdEventStream {
    pub preamble: PdPreamble,
    pub events: Vec<PdEvent>,
}

impl PdEventStream {
    /// Parse PD event stream from bytes
    /// Expected format: 12-byte preamble + repeated (6-byte header + wire data) events
    pub fn from_bytes(bytes: Bytes) -> Result<Self, KMError> {
        if bytes.len() < PD_PREAMBLE_SIZE {
            return Err(KMError::InvalidPacket(format!(
                "PD event stream too short for preamble: need {}, got {}",
                PD_PREAMBLE_SIZE,
                bytes.len()
            )));
        }

        // Parse preamble
        let preamble_raw = PdPreambleRaw::ref_from_bytes(&bytes[..PD_PREAMBLE_SIZE])
            .map_err(|_| KMError::InvalidPacket("Failed to parse PD preamble".to_string()))?;
        let preamble = PdPreamble::from(*preamble_raw);

        let mut events = Vec::new();
        let mut offset = PD_PREAMBLE_SIZE;

        // Parse events
        while offset < bytes.len() {
            if bytes.len() - offset < PD_EVENT_HEADER_SIZE {
                // Not enough bytes for event header
                break;
            }

            let size_flag = bytes[offset];
            let timestamp = u32::from_le_bytes([
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
            ]);
            let sop = bytes[offset + 5];

            // Calculate wire data length: wire_len = (size_flag & mask) - offset
            let wire_len = (size_flag & PD_EVENT_SIZE_MASK).saturating_sub(PD_EVENT_SIZE_OFFSET) as usize;

            offset += PD_EVENT_HEADER_SIZE;

            if bytes.len() - offset < wire_len {
                return Err(KMError::InvalidPacket(format!(
                    "Insufficient bytes for wire data: expected {}, got {}",
                    wire_len,
                    bytes.len() - offset
                )));
            }

            let wire_data = if wire_len > 0 {
                bytes.slice(offset..offset + wire_len).to_vec()
            } else {
                Vec::new()
            };
            offset += wire_len;

            // Parse event type
            let data = if size_flag == PD_EVENT_TYPE_CONNECTION {
                // Connection event
                if let Some(&event_code) = wire_data.first() {
                    match event_code {
                        PD_CONNECTION_CONNECT => PdEventData::Connect(()),
                        PD_CONNECTION_DISCONNECT => PdEventData::Disconnect(()),
                        _ => PdEventData::PdMessage { sop, wire_data },
                    }
                } else {
                    PdEventData::PdMessage { sop, wire_data }
                }
            } else {
                PdEventData::PdMessage { sop, wire_data }
            };

            events.push(PdEvent { timestamp, data });
        }

        Ok(Self { preamble, events })
    }

    /// Helper: get all PD messages, ignoring connection events
    pub fn pd_messages(&self) -> impl Iterator<Item = (&u32, u8, &Vec<u8>)> {
        self.events.iter().filter_map(|e| match &e.data {
            PdEventData::PdMessage { sop, wire_data } => Some((&e.timestamp, *sop, wire_data)),
            _ => None,
        })
    }

    /// Helper: get connection state changes
    pub fn connection_events(&self) -> impl Iterator<Item = (&u32, bool)> {
        self.events.iter().filter_map(|e| match &e.data {
            PdEventData::Connect(()) => Some((&e.timestamp, true)),
            PdEventData::Disconnect(()) => Some((&e.timestamp, false)),
            _ => None,
        })
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl PdEvent {
    fn __repr__(&self) -> String {
        match &self.data {
            PdEventData::Connect(()) => format!("PdEvent(timestamp={}, type=connect)", self.timestamp),
            PdEventData::Disconnect(()) => format!("PdEvent(timestamp={}, type=disconnect)", self.timestamp),
            PdEventData::PdMessage { sop, wire_data } => format!(
                "PdEvent(timestamp={}, type=pd_message, sop={}, {} bytes)",
                self.timestamp,
                sop,
                wire_data.len()
            ),
        }
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl PdEventStream {
    #[getter]
    fn preamble(&self) -> PdPreamble {
        self.preamble
    }

    #[getter]
    fn events(&self) -> Vec<PdEvent> {
        self.events.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "PdEventStream(preamble={}, {} events)",
            self.preamble.__repr__(),
            self.events.len()
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}
