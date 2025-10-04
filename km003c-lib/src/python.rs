//! Python bindings for the KM003C protocol library.
//!
//! This module exposes the KM003C USB-C analyzer protocol parsing capabilities
//! to Python through PyO3 bindings. It provides both low-level packet parsing
//! and high-level semantic interpretation of KM003C protocol data.
//!
//! # Main Functions
//!
//! - `parse_packet()`: Parse bytes into high-level semantic packets (Packet)
//! - `parse_raw_packet()`: Parse bytes into low-level protocol structure (RawPacket)  
//! - `parse_raw_adc_data()`: Parse raw ADC bytes directly into measurements (AdcData)
//! - `get_sample_rates()`: Get available device sample rates
//!
//! # Key Classes
//!
//! - `Packet`: High-level semantic packets (SimpleAdcData, PdRawData, etc.)
//! - `RawPacket`: Low-level protocol structure with headers and bitfields
//! - `AdcData`: Processed ADC measurements (voltage, current, power, temperature)
//! - `SampleRate`: Device sampling rate information
//!
//! # Protocol Overview
//!
//! The KM003C uses a custom USB protocol with these packet structures:
//! - Control packets: 4-byte CtrlHeader + payload
//! - Simple data packets: 4-byte DataHeader + payload
//! - Extended data packets: 4-byte DataHeader + 4-byte ExtendedHeader + payload
//!
//! Extended headers are only used for PutData (0x41) packets and contain
//! attribute information, chunk management, and size fields.
//!
//! # Unknown Packet Handling
//!
//! The library gracefully handles unknown packet types and attributes using
//! enum variants like `Unknown(123)`, allowing protocol research and analysis
//! of undocumented packet types while preserving the raw numeric values.

use crate::adc::{AdcDataRaw, AdcDataSimple, SampleRate};
use crate::message::Packet;
use crate::packet::RawPacket;
use crate::pd::{PdEventData, PdEventStream, PdPreamble, PdStatus};
use bytes::Bytes;
use pyo3::prelude::*;

/// Python wrapper for ADC measurement data from the KM003C device.
///
/// Contains electrical measurements, USB data line voltages, and USB-C CC line voltages.
/// All voltage/current values are converted to standard units (V/A/W/°C) from the raw ADC data.
///
/// Power flow direction:
/// - Positive current/power: USB female (input) → USB male (output)
/// - Negative current/power: USB male (input) → USB female (output)
#[pyclass(name = "AdcData")]
#[derive(Clone)]
pub struct PyAdcData {
    /// VBUS voltage in volts (instantaneous reading)
    #[pyo3(get)]
    pub vbus_v: f64,
    /// IBUS current in amperes (instantaneous reading)
    /// Positive: female→male, Negative: male→female
    #[pyo3(get)]
    pub ibus_a: f64,
    /// Calculated power in watts (vbus_v × ibus_a)
    /// Sign indicates power flow direction
    #[pyo3(get)]
    pub power_w: f64,
    /// VBUS voltage averaged over recent samples
    #[pyo3(get)]
    pub vbus_avg_v: f64,
    /// IBUS current averaged over recent samples
    #[pyo3(get)]
    pub ibus_avg_a: f64,
    /// Device internal temperature in Celsius
    #[pyo3(get)]
    pub temp_c: f64,
    /// USB D+ line voltage in volts (instantaneous)
    #[pyo3(get)]
    pub vdp_v: f64,
    /// USB D- line voltage in volts (instantaneous)
    #[pyo3(get)]
    pub vdm_v: f64,
    /// USB D+ line voltage averaged over recent samples
    #[pyo3(get)]
    pub vdp_avg_v: f64,
    /// USB D- line voltage averaged over recent samples
    #[pyo3(get)]
    pub vdm_avg_v: f64,
    /// USB-C CC1 line voltage in volts
    #[pyo3(get)]
    pub cc1_v: f64,
    /// USB-C CC2 line voltage in volts
    #[pyo3(get)]
    pub cc2_v: f64,
}

impl From<AdcDataSimple> for PyAdcData {
    fn from(data: AdcDataSimple) -> Self {
        PyAdcData {
            vbus_v: data.vbus_v,
            ibus_a: data.ibus_a,
            power_w: data.power_w,
            vbus_avg_v: data.vbus_avg_v,
            ibus_avg_a: data.ibus_avg_a,
            temp_c: data.temp_c,
            vdp_v: data.vdp_v,
            vdm_v: data.vdm_v,
            vdp_avg_v: data.vdp_avg_v,
            vdm_avg_v: data.vdm_avg_v,
            cc1_v: data.cc1_v,
            cc2_v: data.cc2_v,
        }
    }
}

#[pymethods]
impl PyAdcData {
    /// String representation showing key electrical measurements.
    fn __repr__(&self) -> String {
        format!(
            "AdcData(vbus={:.3}V, ibus={:.3}A, power={:.3}W, temp={:.1}°C)",
            self.vbus_v, self.ibus_a, self.power_w, self.temp_c
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}

/// Python wrapper for PD Status data from the KM003C device.
///
/// Contains USB-C voltage/current measurements at a specific timestamp.
/// Appears in combined ADC+PD packets as a 12-byte block.
#[pyclass(name = "PdStatus")]
#[derive(Clone)]
pub struct PyPdStatus {
    /// Type identifier for the PD status
    #[pyo3(get)]
    pub type_id: u8,
    /// Timestamp (24-bit value converted to u32, ~40ms per tick)
    #[pyo3(get)]
    pub timestamp: u32,
    /// VBUS voltage in volts
    #[pyo3(get)]
    pub vbus_v: f64,
    /// IBUS current in amperes
    #[pyo3(get)]
    pub ibus_a: f64,
    /// USB-C CC1 line voltage in volts
    #[pyo3(get)]
    pub cc1_v: f64,
    /// USB-C CC2 line voltage in volts
    #[pyo3(get)]
    pub cc2_v: f64,
}

impl From<PdStatus> for PyPdStatus {
    fn from(pd: PdStatus) -> Self {
        PyPdStatus {
            type_id: pd.type_id,
            timestamp: pd.timestamp,
            vbus_v: pd.vbus_v,
            ibus_a: pd.ibus_a,
            cc1_v: pd.cc1_v,
            cc2_v: pd.cc2_v,
        }
    }
}

#[pymethods]
impl PyPdStatus {
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

/// Python wrapper for PD event preamble.
///
/// Contains electrical state when PD events occurred.
/// Appears at the start of PD-only event streams (12-byte header).
#[pyclass(name = "PdPreamble")]
#[derive(Clone)]
pub struct PyPdPreamble {
    /// Timestamp in milliseconds
    #[pyo3(get)]
    pub timestamp: u32,
    /// VBUS voltage in volts
    #[pyo3(get)]
    pub vbus_v: f64,
    /// IBUS current in amperes (signed)
    #[pyo3(get)]
    pub ibus_a: f64,
    /// USB-C CC1 line voltage in volts
    #[pyo3(get)]
    pub cc1_v: f64,
    /// USB-C CC2 line voltage in volts
    #[pyo3(get)]
    pub cc2_v: f64,
}

impl From<PdPreamble> for PyPdPreamble {
    fn from(preamble: PdPreamble) -> Self {
        PyPdPreamble {
            timestamp: preamble.timestamp,
            vbus_v: preamble.vbus_v,
            ibus_a: preamble.ibus_a,
            cc1_v: preamble.cc1_v,
            cc2_v: preamble.cc2_v,
        }
    }
}

#[pymethods]
impl PyPdPreamble {
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

/// Python wrapper for a single PD event.
///
/// Represents a timestamped USB Power Delivery event (connect, disconnect, or PD message).
#[pyclass(name = "PdEvent")]
#[derive(Clone)]
pub struct PyPdEvent {
    /// Timestamp of the event
    #[pyo3(get)]
    pub timestamp: u32,
    /// Event type: "connect", "disconnect", or "pd_message"
    #[pyo3(get)]
    pub event_type: String,
    /// For PD messages: SOP (Start of Packet) type
    #[pyo3(get)]
    pub sop: Option<u8>,
    /// For PD messages: raw wire data bytes
    #[pyo3(get)]
    pub wire_data: Option<Vec<u8>>,
}

impl From<crate::pd::PdEvent> for PyPdEvent {
    fn from(event: crate::pd::PdEvent) -> Self {
        match event.data {
            PdEventData::Connect => PyPdEvent {
                timestamp: event.timestamp,
                event_type: "connect".to_string(),
                sop: None,
                wire_data: None,
            },
            PdEventData::Disconnect => PyPdEvent {
                timestamp: event.timestamp,
                event_type: "disconnect".to_string(),
                sop: None,
                wire_data: None,
            },
            PdEventData::PdMessage { sop, wire_data } => PyPdEvent {
                timestamp: event.timestamp,
                event_type: "pd_message".to_string(),
                sop: Some(sop),
                wire_data: Some(wire_data.to_vec()),
            },
        }
    }
}

#[pymethods]
impl PyPdEvent {
    fn __repr__(&self) -> String {
        match self.event_type.as_str() {
            "pd_message" => format!(
                "PdEvent(timestamp={}, type=pd_message, sop={}, {} bytes)",
                self.timestamp,
                self.sop.unwrap_or(0),
                self.wire_data.as_ref().map(|d| d.len()).unwrap_or(0)
            ),
            event_type => format!(
                "PdEvent(timestamp={}, type={})",
                self.timestamp, event_type
            ),
        }
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}

/// Python wrapper for a complete PD event stream.
///
/// Contains a preamble with electrical state and a list of timestamped events.
#[pyclass(name = "PdEventStream")]
#[derive(Clone)]
pub struct PyPdEventStream {
    /// Preamble containing electrical state
    #[pyo3(get)]
    pub preamble: PyPdPreamble,
    /// List of PD events
    #[pyo3(get)]
    pub events: Vec<PyPdEvent>,
}

impl From<PdEventStream> for PyPdEventStream {
    fn from(stream: PdEventStream) -> Self {
        PyPdEventStream {
            preamble: PyPdPreamble::from(stream.preamble),
            events: stream.events.into_iter().map(PyPdEvent::from).collect(),
        }
    }
}

#[pymethods]
impl PyPdEventStream {
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

/// Represents an ADC sampling rate supported by the KM003C device.
///
/// Available rates: 1, 10, 50, 1000, 10000 samples per second
#[pyclass(name = "SampleRate")]
#[derive(Clone)]
pub struct PySampleRate {
    /// Sample rate in samples per second (Hz)
    #[pyo3(get)]
    pub hz: u32,
    /// Human-readable name (e.g., "1 SPS", "10 SPS")
    #[pyo3(get)]
    pub name: String,
}

/// High-level semantic packet representation after protocol interpretation.
///
/// This represents packets that have been parsed and given semantic meaning,
/// as opposed to RawPacket which shows the low-level protocol structure.
///
/// Packet types:
/// - "DataResponse": Device response with parsed payload data (ADC, PD, etc.)
/// - "GetData": Request data with attribute set
/// - "Accept": Acknowledgment response
/// - "Connect": Connection command
/// - "Disconnect": Disconnection command
/// - "Generic": Unrecognized packet types (falls back to raw packet)
#[pyclass(name = "Packet")]
#[derive(Clone)]
pub struct PyPacket {
    /// String name of the packet type (see above for possible values)
    #[pyo3(get)]
    pub packet_type: String,
    /// ADC measurement data (present in DataResponse with ADC payload)
    #[pyo3(get)]
    pub adc_data: Option<PyAdcData>,
    /// PD status data (present in DataResponse with PdStatus payload)
    #[pyo3(get)]
    pub pd_status: Option<PyPdStatus>,
    /// PD event stream (present in DataResponse with PdEvents payload)
    #[pyo3(get)]
    pub pd_events: Option<PyPdEventStream>,
    /// Raw payload for "Unknown" payloads or "Generic" packets
    #[pyo3(get)]
    pub raw_payload: Option<Vec<u8>>,
}

impl From<Packet> for PyPacket {
    fn from(packet: Packet) -> Self {
        match packet {
            Packet::DataResponse(payloads) => {
                // Extract different payload types
                let adc_data = payloads.iter().find_map(|p| match p {
                    crate::message::PayloadData::Adc(adc) => Some(PyAdcData::from(*adc)),
                    _ => None,
                });

                let pd_status = payloads.iter().find_map(|p| match p {
                    crate::message::PayloadData::PdStatus(pd) => Some(PyPdStatus::from(*pd)),
                    _ => None,
                });

                let pd_events = payloads.iter().find_map(|p| match p {
                    crate::message::PayloadData::PdEvents(events) => Some(PyPdEventStream::from(events.clone())),
                    _ => None,
                });

                // For unknown payloads, put in raw_payload
                let raw_payload = payloads.iter().find_map(|p| match p {
                    crate::message::PayloadData::Unknown { data, .. } => Some(data.to_vec()),
                    _ => None,
                });

                PyPacket {
                    packet_type: "DataResponse".to_string(),
                    adc_data,
                    pd_status,
                    pd_events,
                    raw_payload,
                }
            },
            Packet::GetData(attr_set) => PyPacket {
                packet_type: "GetData".to_string(),
                adc_data: None,
                pd_status: None,
                pd_events: None,
                raw_payload: Some(attr_set.raw().to_le_bytes().to_vec()),
            },
            Packet::Accept { id } => PyPacket {
                packet_type: "Accept".to_string(),
                adc_data: None,
                pd_status: None,
                pd_events: None,
                raw_payload: Some(vec![id]),
            },
            Packet::Connect => PyPacket {
                packet_type: "Connect".to_string(),
                adc_data: None,
                pd_status: None,
                pd_events: None,
                raw_payload: None,
            },
            Packet::Disconnect => PyPacket {
                packet_type: "Disconnect".to_string(),
                adc_data: None,
                pd_status: None,
                pd_events: None,
                raw_payload: None,
            },
            Packet::Generic(raw_packet) => {
                // For generic packets, extract the raw payload from RawPacket
                let raw_payload = match &raw_packet {
                    RawPacket::Ctrl { payload, .. } => Some(payload.to_vec()),
                    RawPacket::SimpleData { payload, .. } => Some(payload.to_vec()),
                    RawPacket::Data { logical_packets, .. } => {
                        Some(logical_packets.iter().flat_map(|lp| lp.payload.iter()).copied().collect())
                    }
                };

                PyPacket {
                    packet_type: "Generic".to_string(),
                    adc_data: None,
                    pd_status: None,
                    pd_events: None,
                    raw_payload,
                }
            },
        }
    }
}

impl From<SampleRate> for PySampleRate {
    fn from(rate: SampleRate) -> Self {
        PySampleRate {
            hz: rate.as_hz(),
            name: rate.to_string(),
        }
    }
}

#[pymethods]
impl PyPacket {
    /// Detailed string representation showing packet type and key data.
    ///
    /// Examples:
    ///   - "Packet::DataResponse(adc=AdcData(...), pd_status=PdStatus(...))"
    ///   - "Packet::GetData"
    ///   - "Packet::Connect"
    fn __repr__(&self) -> String {
        match self.packet_type.as_str() {
            "DataResponse" => {
                let mut parts = vec![];
                if let Some(ref adc) = self.adc_data {
                    parts.push(format!("adc={}", adc.__repr__()));
                }
                if let Some(ref pd_status) = self.pd_status {
                    parts.push(format!("pd_status={}", pd_status.__repr__()));
                }
                if let Some(ref pd_events) = self.pd_events {
                    parts.push(format!("pd_events={}", pd_events.__repr__()));
                }
                if let Some(ref raw) = self.raw_payload {
                    parts.push(format!("unknown_payload={} bytes", raw.len()));
                }
                if parts.is_empty() {
                    "Packet::DataResponse(empty)".to_string()
                } else {
                    format!("Packet::DataResponse({})", parts.join(", "))
                }
            }
            "Generic" => {
                if let Some(ref payload) = self.raw_payload {
                    format!("Packet::Generic({} bytes payload)", payload.len())
                } else {
                    "Packet::Generic(no payload)".to_string()
                }
            }
            _ => format!("Packet::{}", self.packet_type),
        }
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}

#[pymethods]
impl PySampleRate {
    /// String representation showing the sample rate name.
    fn __repr__(&self) -> String {
        format!("SampleRate({})", self.name)
    }

    /// Human-readable sample rate name (e.g., "1 SPS", "10000 SPS").
    fn __str__(&self) -> String {
        self.name.clone()
    }
}

/// Low-level packet structure showing raw protocol details.
///
/// This exposes the actual packet structure with headers, bitfields, and protocol metadata.
/// Use this for protocol analysis, debugging, and understanding packet structure.
///
/// Packet structure varies by type:
/// - Control packets: CtrlHeader (4 bytes) + payload
/// - Simple data packets: DataHeader (4 bytes) + payload  
/// - Extended data packets: DataHeader (4 bytes) + ExtendedHeader (4 bytes) + payload
///
/// Note: Only PutData (0x41) packets have extended headers in the current protocol.
#[pyclass(name = "RawPacket")]
#[derive(Clone)]
pub struct PyRawPacket {
    /// Packet type name (e.g., "Sync", "GetData", "PutData", "Unknown(123)")
    #[pyo3(get)]
    pub packet_type: String,
    /// Raw packet type ID as u8 (0x01=Sync, 0x0C=GetData, 0x41=PutData, etc.)
    #[pyo3(get)]
    pub packet_type_id: u8,
    /// Transaction ID (0-255, wraps around) for matching request/response pairs
    #[pyo3(get)]
    pub id: u8,
    /// True if this packet has an extended header (4 additional bytes)
    /// Currently only true for PutData packets
    #[pyo3(get)]
    pub has_extended_header: bool,
    /// Reserved flag bit from the first header byte (vendor-specific meaning)
    /// NOTE: This does NOT indicate extended header presence
    #[pyo3(get)]
    pub reserved_flag: bool,

    // Extended header fields (only present when has_extended_header=True)
    /// Attribute ID from extended header (15-bit field)
    /// Values: 1=Adc, 2=AdcQueue, 4=AdcQueue10k, 8=Settings, 16=PdPacket, etc.
    #[pyo3(get)]
    pub ext_attribute_id: Option<u16>,
    /// Extended header 'next' flag - indicates if more chunks follow
    #[pyo3(get)]
    pub ext_next: Option<bool>,
    /// Extended header chunk number (6-bit field, 0-63)
    #[pyo3(get)]
    pub ext_chunk: Option<u8>,
    /// Extended header size field (10-bit field, typically payload size)
    #[pyo3(get)]
    pub ext_size: Option<u16>,

    // Attribute information (from control headers or extended headers)
    /// Human-readable attribute name (e.g., "Adc", "Settings", "Unknown(123)")
    /// Available for control packets and extended data packets
    #[pyo3(get)]
    pub attribute: Option<String>,
    /// Raw attribute ID as u16 - same as ext_attribute_id but works for all packet types
    /// For control packets: from 15-bit CtrlHeader.attribute field
    /// For extended packets: from 15-bit ExtendedHeader.attribute field
    #[pyo3(get)]
    pub attribute_id: Option<u16>,

    /// Packet payload bytes (excludes all headers)
    /// For extended packets: this excludes the 4-byte extended header
    #[pyo3(get)]
    pub payload: Vec<u8>,
    /// Complete raw packet bytes including all headers
    #[pyo3(get)]
    pub raw_bytes: Vec<u8>,
}

impl From<RawPacket> for PyRawPacket {
    fn from(raw_packet: RawPacket) -> Self {
        let raw_bytes: Vec<u8> = Bytes::from(raw_packet.clone()).to_vec();
        let payload = match &raw_packet {
            RawPacket::Ctrl { payload, .. } => payload.to_vec(),
            RawPacket::SimpleData { payload, .. } => payload.to_vec(),
            RawPacket::Data { logical_packets, .. } => {
                // Concatenate all logical packet payloads
                logical_packets.iter().flat_map(|lp| lp.payload.iter()).copied().collect()
            }
        };

        // Extract header info and extended header metadata based on packet type
        // Extended headers are represented via logical packets in Data variant
        let (has_extended_header, reserved_flag, ext_meta) = match &raw_packet {
            RawPacket::Ctrl { header, .. } => {
                // Control packets: 4-byte CtrlHeader only
                (false, header.reserved_flag(), None)
            }
            RawPacket::SimpleData { header, .. } => {
                // Simple data packets: 4-byte DataHeader only
                (false, header.reserved_flag(), None)
            }
            RawPacket::Data { header, logical_packets } => {
                // Data packets with logical packets
                // For the first logical packet, extract extended header info
                let ext_meta = logical_packets.first().map(|lp| {
                    (u16::from(lp.attribute), lp.next, lp.chunk, lp.size)
                });
                (true, header.reserved_flag(), ext_meta)
            }
        };

        PyRawPacket {
            packet_type: format!("{:?}", raw_packet.packet_type()),
            packet_type_id: raw_packet.packet_type().into(),
            id: raw_packet.id(),
            has_extended_header,
            reserved_flag,
            // Extended header fields: only populated for ExtendedData packets
            ext_attribute_id: ext_meta.map(|m| m.0), // 15-bit attribute field
            ext_next: ext_meta.map(|m| m.1),         // 1-bit next flag
            ext_chunk: ext_meta.map(|m| m.2),        // 6-bit chunk number
            ext_size: ext_meta.map(|m| m.3),         // 10-bit size field
            // General attribute info: works for both control and extended packets
            attribute: raw_packet.get_attribute().map(|attr| format!("{:?}", attr)),
            attribute_id: raw_packet.get_attribute().map(|attr| attr.into()),
            payload,
            raw_bytes,
        }
    }
}

#[pymethods]
impl PyRawPacket {
    /// Comprehensive string representation showing all protocol details.
    ///
    /// For extended packets (PutData), shows extended header fields.
    /// For simple packets, shows basic header information.
    ///
    /// Examples:
    ///   - "RawPacket(type=GetData, id=5, has_ext_hdr=false, reserved_flag=false, 4 bytes)"
    ///   - "RawPacket(type=PutData, id=10, has_ext_hdr=true, reserved_flag=true, ext_attr=1, ext_next=false, ext_chunk=0, ext_size=64, 72 bytes)"
    fn __repr__(&self) -> String {
        if self.has_extended_header {
            format!(
                "RawPacket(type={}, id={}, has_ext_hdr=true, reserved_flag={}, ext_attr={}, ext_next={}, ext_chunk={}, ext_size={}, {} bytes)",
                self.packet_type,
                self.id,
                self.reserved_flag,
                self.ext_attribute_id.unwrap_or_default(),
                self.ext_next.unwrap_or(false),
                self.ext_chunk.unwrap_or_default(),
                self.ext_size.unwrap_or_default(),
                self.raw_bytes.len()
            )
        } else {
            format!(
                "RawPacket(type={}, id={}, has_ext_hdr=false, reserved_flag={}, {} bytes)",
                self.packet_type,
                self.id,
                self.reserved_flag,
                self.raw_bytes.len()
            )
        }
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}

/// Parse raw ADC data bytes directly into processed measurements.
///
/// Args:
///     data: Raw ADC data bytes (must be exactly 64 bytes for AdcDataRaw)
///
/// Returns:
///     AdcData: Processed ADC measurements with voltage/current/power values
///
/// Raises:
///     ValueError: If data is not the correct size for AdcDataRaw structure
///
/// Example:
///     ```python
///     # Parse 64-byte ADC payload from a packet
///     adc_data = parse_raw_adc_data(packet_payload)
///     print(f"VBUS: {adc_data.vbus_v}V, IBUS: {adc_data.ibus_a}A")
///     ```
#[pyfunction]
pub fn parse_raw_adc_data(data: &[u8]) -> PyResult<PyAdcData> {
    use zerocopy::FromBytes;

    let adc_raw = AdcDataRaw::ref_from_bytes(data).map_err(|_| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Invalid ADC data size: expected {}, got {}",
            std::mem::size_of::<AdcDataRaw>(),
            data.len()
        ))
    })?;

    let adc_simple = AdcDataSimple::from(*adc_raw);
    Ok(PyAdcData::from(adc_simple))
}

/// Parse packet bytes into a high-level semantic packet representation.
///
/// This function performs two-stage parsing:
/// 1. Parse raw bytes into RawPacket (protocol structure)
/// 2. Interpret RawPacket semantically into Packet (meaning)
///
/// Args:
///     data: Complete packet bytes including headers
///
/// Returns:
///     Packet: High-level packet with semantic meaning
///             - SimpleAdcData: Contains parsed ADC measurements
///             - CmdGetSimpleAdcData: ADC data request command
///             - PdRawData: USB Power Delivery packet bytes
///             - CmdGetPdData: PD data request command  
///             - Generic: Unrecognized packets (contains RawPacket)
///
/// Raises:
///     ValueError: If packet bytes are malformed or too short
///
/// Example:
///     ```python
///     packet = parse_packet(usb_packet_bytes)
///     if packet.packet_type == "SimpleAdcData":
///         print(f"Power: {packet.adc_data.power_w}W")
///     ```
#[pyfunction]
pub fn parse_packet(data: &[u8]) -> PyResult<PyPacket> {
    let bytes = Bytes::from(data.to_vec());
    let raw_packet =
        RawPacket::try_from(bytes).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{}", e)))?;

    let packet =
        Packet::try_from(raw_packet).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{}", e)))?;

    Ok(PyPacket::from(packet))
}

/// Parse packet bytes into low-level protocol structure.
///
/// This exposes the raw packet structure including headers, bitfields,
/// and protocol details without semantic interpretation.
///
/// Args:
///     data: Complete packet bytes including headers
///
/// Returns:
///     RawPacket: Low-level packet structure with protocol details
///                - packet_type/packet_type_id: Packet type information
///                - id: Transaction ID for request/response matching
///                - has_extended_header: True for PutData packets
///                - attribute/attribute_id: Command attributes (if present)
///                - ext_*: Extended header fields (if has_extended_header)
///                - payload/raw_bytes: Payload and complete packet data
///
/// Raises:
///     ValueError: If packet bytes are malformed or too short (< 4 bytes)
///
/// Example:
///     ```python
///     raw = parse_raw_packet(usb_packet_bytes)
///     print(f"Type: {raw.packet_type}, ID: {raw.id}")
///     if raw.has_extended_header:
///         print(f"Attribute: {raw.attribute}, Size: {raw.ext_size}")
///     ```
#[pyfunction]
pub fn parse_raw_packet(data: &[u8]) -> PyResult<PyRawPacket> {
    let bytes = Bytes::from(data.to_vec());
    let raw_packet =
        RawPacket::try_from(bytes).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{}", e)))?;

    Ok(PyRawPacket::from(raw_packet))
}

/// Get all supported ADC sample rates for the KM003C device.
///
/// Returns:
///     List[SampleRate]: Available sample rates from 1 to 10000 samples per second
///                       Each has .hz (int) and .name (str) properties
///
/// Example:
///     ```python
///     rates = get_sample_rates()
///     for rate in rates:
///         print(f"{rate.name}: {rate.hz} Hz")
///     # Output:
///     # 1 SPS: 1 Hz
///     # 10 SPS: 10 Hz
///     # 50 SPS: 50 Hz
///     # 1000 SPS: 1000 Hz
///     # 10000 SPS: 10000 Hz
///     ```
#[pyfunction]
pub fn get_sample_rates() -> Vec<PySampleRate> {
    vec![
        PySampleRate::from(SampleRate::Sps1),
        PySampleRate::from(SampleRate::Sps10),
        PySampleRate::from(SampleRate::Sps50),
        PySampleRate::from(SampleRate::Sps1000),
        PySampleRate::from(SampleRate::Sps10000),
    ]
}

/// Python module for KM003C USB-C power analyzer protocol parsing.
///
/// This module provides comprehensive support for parsing and analyzing
/// KM003C protocol data captured from USB traffic.
///
/// Constants:
///   VID: USB Vendor ID for ChargerLAB (0x5FC9)
///   PID: USB Product ID for KM003C (0x0063)
#[pymodule]
fn km003c_lib(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Core data classes
    m.add_class::<PyAdcData>()?;
    m.add_class::<PyPdStatus>()?;
    m.add_class::<PyPdPreamble>()?;
    m.add_class::<PyPdEvent>()?;
    m.add_class::<PyPdEventStream>()?;
    m.add_class::<PySampleRate>()?;
    m.add_class::<PyPacket>()?;
    m.add_class::<PyRawPacket>()?;

    // Parsing functions
    m.add_function(wrap_pyfunction!(parse_raw_adc_data, m)?)?;
    m.add_function(wrap_pyfunction!(parse_packet, m)?)?;
    m.add_function(wrap_pyfunction!(parse_raw_packet, m)?)?;
    m.add_function(wrap_pyfunction!(get_sample_rates, m)?)?;

    // USB device identification constants
    m.add("VID", crate::device::VID)?;
    m.add("PID", crate::device::PID)?;

    Ok(())
}
