use bytes::Bytes;
use uom::si::electric_current::milliampere;
use uom::si::electric_potential::millivolt;
use uom::si::f64::{ElectricCurrent, ElectricPotential, Time};
use uom::si::time::millisecond;
use zerocopy::byteorder::little_endian::{I16, U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::constants::*;
use crate::error::KMError;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "python")]
use uom::si::{electric_current::ampere, electric_potential::volt};

/// PD measurement block (12 bytes).
///
/// The device uses this exact layout both as a standalone/chained PD status
/// payload and as the preamble of a PD event stream.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct PdStatusRaw {
    pub timestamp_ms: U32,
    pub vbus_mv: U16,
    pub ibus_ma: I16, // Signed! Negative = power flowing from male to female port
    pub cc1_mv: U16,
    pub cc2_mv: U16,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "python", pyo3::pyclass(skip_from_py_object))]
pub struct PdStatus {
    pub timestamp: Time,
    pub vbus: ElectricPotential,
    pub ibus: ElectricCurrent,
    pub cc1: ElectricPotential,
    pub cc2: ElectricPotential,
}

impl From<PdStatusRaw> for PdStatus {
    fn from(raw: PdStatusRaw) -> Self {
        Self {
            timestamp: Time::new::<millisecond>(f64::from(raw.timestamp_ms.get())),
            vbus: ElectricPotential::new::<millivolt>(f64::from(raw.vbus_mv.get())),
            ibus: ElectricCurrent::new::<milliampere>(f64::from(raw.ibus_ma.get())),
            cc1: ElectricPotential::new::<millivolt>(f64::from(raw.cc1_mv.get())),
            cc2: ElectricPotential::new::<millivolt>(f64::from(raw.cc2_mv.get())),
        }
    }
}

impl From<PdStatus> for PdStatusRaw {
    fn from(status: PdStatus) -> Self {
        Self {
            timestamp_ms: U32::new(status.timestamp.get::<millisecond>() as u32),
            vbus_mv: U16::new(status.vbus.get::<millivolt>() as u16),
            ibus_ma: I16::new(status.ibus.get::<milliampere>() as i16),
            cc1_mv: U16::new(status.cc1.get::<millivolt>() as u16),
            cc2_mv: U16::new(status.cc2.get::<millivolt>() as u16),
        }
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl PdStatus {
    #[getter]
    fn timestamp(&self) -> f64 {
        self.timestamp.get::<millisecond>()
    }
    #[getter]
    fn vbus_v(&self) -> f64 {
        self.vbus.get::<volt>()
    }
    #[getter]
    fn ibus_a(&self) -> f64 {
        self.ibus.get::<ampere>()
    }
    #[getter]
    fn cc1_v(&self) -> f64 {
        self.cc1.get::<volt>()
    }
    #[getter]
    fn cc2_v(&self) -> f64 {
        self.cc2.get::<volt>()
    }

    fn __repr__(&self) -> String {
        format!(
            "PdStatus(timestamp={}ms, vbus={:.3}V, ibus={:.3}A)",
            self.timestamp.get::<millisecond>(),
            self.vbus.get::<volt>(),
            self.ibus.get::<ampere>()
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
#[cfg_attr(feature = "python", pyo3::pyclass(skip_from_py_object, name = "PdEvent"))]
pub struct PdEvent {
    pub timestamp: Time,
    pub data: PdEventData,
}

/// Complete PD event stream with preamble and events
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "python", pyo3::pyclass(skip_from_py_object, name = "PdEventStream"))]
pub struct PdEventStream {
    /// Measurements captured immediately before the event records.
    pub preamble: PdStatus,
    pub events: Vec<PdEvent>,
}

impl PdEventStream {
    /// Parse PD event stream from bytes
    /// Expected format: 12-byte preamble + repeated (6-byte header + wire data) events
    pub fn from_bytes(bytes: Bytes) -> Result<Self, KMError> {
        if bytes.len() < PD_STATUS_SIZE {
            return Err(KMError::InvalidPacket(format!(
                "PD event stream too short for preamble: need {}, got {}",
                PD_STATUS_SIZE,
                bytes.len()
            )));
        }

        // Parse preamble
        let preamble_raw = PdStatusRaw::ref_from_bytes(&bytes[..PD_STATUS_SIZE])
            .map_err(|_| KMError::InvalidPacket("Failed to parse PD preamble".to_string()))?;
        let preamble = PdStatus::from(*preamble_raw);

        let mut events = Vec::new();
        let mut offset = PD_STATUS_SIZE;

        // Parse events
        while offset < bytes.len() {
            if bytes.len() - offset < PD_EVENT_HEADER_SIZE {
                return Err(KMError::InvalidPacket(format!(
                    "Incomplete PD event header at offset {}: need {}, got {}",
                    offset,
                    PD_EVENT_HEADER_SIZE,
                    bytes.len() - offset
                )));
            }

            let size_flag = bytes[offset];

            // Connection/status event (0x45): 6-byte header with ts24 + code
            if size_flag == PD_EVENT_TYPE_CONNECTION {
                let ts24 = u32::from_le_bytes([bytes[offset + 1], bytes[offset + 2], bytes[offset + 3], 0]);
                let event_code = bytes[offset + 5];
                let data = match event_code {
                    PD_CONNECTION_CONNECT | PD_CONNECTION_CONNECT_LEGACY => PdEventData::Connect(()),
                    PD_CONNECTION_DISCONNECT | PD_CONNECTION_DISCONNECT_LEGACY => PdEventData::Disconnect(()),
                    _ => PdEventData::PdMessage {
                        sop: event_code,
                        wire_data: Vec::new(),
                    },
                };
                events.push(PdEvent {
                    timestamp: Time::new::<millisecond>(f64::from(ts24)),
                    data,
                });
                offset += PD_EVENT_HEADER_SIZE;
                continue;
            }

            let timestamp = u32::from_le_bytes([
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
            ]);
            let sop = bytes[offset + 5];

            // Calculate wire data length: wire_len = (size_flag & mask) - offset
            let encoded_size = size_flag & PD_EVENT_SIZE_MASK;
            let wire_len = encoded_size.checked_sub(PD_EVENT_SIZE_OFFSET).ok_or_else(|| {
                KMError::InvalidPacket(format!(
                    "Invalid PD event size at offset {}: encoded size {} is below {}",
                    offset, encoded_size, PD_EVENT_SIZE_OFFSET
                ))
            })? as usize;

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

            let data = PdEventData::PdMessage { sop, wire_data };

            events.push(PdEvent {
                timestamp: Time::new::<millisecond>(f64::from(timestamp)),
                data,
            });
        }

        Ok(Self { preamble, events })
    }

    /// Helper: get all PD messages, ignoring connection events
    pub fn pd_messages(&self) -> impl Iterator<Item = (&Time, u8, &Vec<u8>)> {
        self.events.iter().filter_map(|e| match &e.data {
            PdEventData::PdMessage { sop, wire_data } => Some((&e.timestamp, *sop, wire_data)),
            _ => None,
        })
    }

    /// Helper: get connection state changes
    pub fn connection_events(&self) -> impl Iterator<Item = (&Time, bool)> {
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
    #[getter]
    fn timestamp(&self) -> f64 {
        self.timestamp.get::<millisecond>()
    }

    #[getter]
    fn data(&self) -> PdEventData {
        self.data.clone()
    }

    fn __repr__(&self) -> String {
        match &self.data {
            PdEventData::Connect(()) => format!(
                "PdEvent(timestamp={}ms, type=connect)",
                self.timestamp.get::<millisecond>()
            ),
            PdEventData::Disconnect(()) => format!(
                "PdEvent(timestamp={}ms, type=disconnect)",
                self.timestamp.get::<millisecond>()
            ),
            PdEventData::PdMessage { sop, wire_data } => format!(
                "PdEvent(timestamp={}, type=pd_message, sop={}, {} bytes)",
                self.timestamp.get::<millisecond>(),
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
    fn preamble(&self) -> PdStatus {
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
