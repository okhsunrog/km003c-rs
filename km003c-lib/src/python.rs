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
//! - `parse_raw_adc_data()`: Parse raw ADC bytes directly into measurements (AdcDataSimple)
//! - `get_sample_rates()`: Get available device sample rates
//!
//! # Protocol Overview
//!
//! The KM003C uses a custom USB protocol with packet structures, ADC measurements,
//! and Power Delivery event tracking. All core types use PyO3's derive macros for
//! zero-overhead Python bindings.

use crate::adc::{AdcDataRaw, AdcDataSimple, SampleRate};
use crate::adcqueue::{AdcQueueData, AdcQueueSample};
use crate::message::Packet;
use crate::packet::{CtrlHeader, LogicalPacket, PacketType, RawPacket};
use crate::pd::{PdEvent, PdEventStream, PdPreamble, PdStatus};
use bytes::Bytes;
use num_enum::FromPrimitive;
use pyo3::prelude::*;

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
pub fn parse_raw_adc_data(data: &[u8]) -> PyResult<AdcDataSimple> {
    use zerocopy::FromBytes;

    let adc_raw = AdcDataRaw::ref_from_bytes(data).map_err(|_| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Invalid ADC data size: expected {}, got {}",
            std::mem::size_of::<AdcDataRaw>(),
            data.len()
        ))
    })?;

    let adc_simple = AdcDataSimple::from(*adc_raw);
    Ok(adc_simple)
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
///     Packet: High-level packet with semantic meaning (dict-like enum)
///             - DataResponse: Contains parsed payloads (ADC, PD, etc.)
///             - GetData: Data request command
///             - StartGraph/StopGraph: AdcQueue streaming control
///             - Accept/Connect/Disconnect: Device control commands
///             - Generic: Unrecognized packets (contains RawPacket)
///
/// Raises:
///     ValueError: If packet bytes are malformed or too short
///
/// Example:
///     ```python
///     packet = parse_packet(usb_packet_bytes)
///     if "DataResponse" in packet:
///         for payload in packet["DataResponse"]["payloads"]:
///             if "Adc" in payload:
///                 adc = payload["Adc"]
///                 print(f"Power: {adc.power_w}W")
///     ```
#[pyfunction]
pub fn parse_packet(data: &[u8]) -> PyResult<Packet> {
    let bytes = Bytes::from(data.to_vec());
    let raw_packet =
        RawPacket::try_from(bytes).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{}", e)))?;

    let packet =
        Packet::try_from(raw_packet).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{}", e)))?;

    Ok(packet)
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
///     RawPacket: Low-level packet structure (dict-like enum)
///                - Ctrl: Control packet with header and payload
///                - SimpleData: Simple data packet with header and payload
///                - Data: Data packet with header and logical_packets
///
/// Raises:
///     ValueError: If packet bytes are malformed or too short (< 4 bytes)
///
/// Example:
///     ```python
///     raw = parse_raw_packet(usb_packet_bytes)
///     if "Ctrl" in raw:
///         print(f"Control packet, ID: {raw['Ctrl']['header']['id']}")
///     elif "Data" in raw:
///         print(f"Data packet with {len(raw['Data']['logical_packets'])} logical packets")
///     ```
#[pyfunction]
pub fn parse_raw_packet(data: &[u8]) -> PyResult<RawPacket> {
    let bytes = Bytes::from(data.to_vec());
    let raw_packet =
        RawPacket::try_from(bytes).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{}", e)))?;

    Ok(raw_packet)
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
///     # 1 kSPS: 1000 Hz
///     # 10 kSPS: 10000 Hz
///     ```
#[pyfunction]
pub fn get_sample_rates() -> Vec<SampleRate> {
    vec![
        SampleRate::Sps1,
        SampleRate::Sps10,
        SampleRate::Sps50,
        SampleRate::Sps1000,
        SampleRate::Sps10000,
    ]
}

/// Create a protocol packet as bytes ready to send over USB.
///
/// This is a universal packet creation function that handles all packet types.
///
/// Args:
///     packet_type: Command type (use CMD_* constants)
///     transaction_id: Transaction ID (0-255)
///     data: Optional data word for commands that need it (attribute mask, rate index, etc.)
///
/// Returns:
///     4-byte packet ready to send over USB
///
/// Examples:
///     ```python
///     # Connect command
///     packet = create_packet(CMD_CONNECT, tid, 0)
///
///     # GetData for ADC
///     packet = create_packet(CMD_GET_DATA, tid, ATT_ADC)
///
///     # Start Graph at 50 SPS
///     packet = create_packet(CMD_START_GRAPH, tid, RATE_50_SPS)
///     ```
#[pyfunction]
pub fn create_packet(packet_type: u8, transaction_id: u8, data: u16) -> Vec<u8> {
    let _ptype = PacketType::from_primitive(packet_type);

    let header = CtrlHeader::new()
        .with_packet_type(packet_type)
        .with_reserved_flag(false)
        .with_id(transaction_id)
        .with_attribute(data);

    header.into_bytes().to_vec()
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
    // Core data classes (using native types with Python bindings)
    m.add_class::<AdcDataSimple>()?;
    m.add_class::<SampleRate>()?;
    m.add_class::<AdcQueueSample>()?;
    m.add_class::<AdcQueueData>()?;
    m.add_class::<PdStatus>()?;
    m.add_class::<PdPreamble>()?;
    m.add_class::<PdEvent>()?;
    m.add_class::<PdEventStream>()?;
    m.add_class::<LogicalPacket>()?;

    // Parsing functions
    m.add_function(wrap_pyfunction!(parse_raw_adc_data, m)?)?;
    m.add_function(wrap_pyfunction!(parse_packet, m)?)?;
    m.add_function(wrap_pyfunction!(parse_raw_packet, m)?)?;
    m.add_function(wrap_pyfunction!(get_sample_rates, m)?)?;

    // Packet creation function
    m.add_function(wrap_pyfunction!(create_packet, m)?)?;

    // USB device identification constants
    m.add("VID", crate::device::VID)?;
    m.add("PID", crate::device::PID)?;

    // PacketType constants (use Into trait for enums with catch_all)
    m.add("CMD_SYNC", u8::from(crate::packet::PacketType::Sync))?;
    m.add("CMD_CONNECT", u8::from(crate::packet::PacketType::Connect))?;
    m.add("CMD_DISCONNECT", u8::from(crate::packet::PacketType::Disconnect))?;
    m.add("CMD_ACCEPT", u8::from(crate::packet::PacketType::Accept))?;
    m.add("CMD_REJECT", u8::from(crate::packet::PacketType::Rejected))?;
    m.add("CMD_GET_DATA", u8::from(crate::packet::PacketType::GetData))?;
    m.add("CMD_START_GRAPH", u8::from(crate::packet::PacketType::StartGraph))?;
    m.add("CMD_STOP_GRAPH", u8::from(crate::packet::PacketType::StopGraph))?;

    // Attribute constants (use Into trait)
    m.add("ATT_ADC", u16::from(crate::packet::Attribute::Adc))?;
    m.add("ATT_ADC_QUEUE", u16::from(crate::packet::Attribute::AdcQueue))?;
    m.add("ATT_ADC_QUEUE_10K", u16::from(crate::packet::Attribute::AdcQueue10k))?;
    m.add("ATT_SETTINGS", u16::from(crate::packet::Attribute::Settings))?;
    m.add("ATT_PD_PACKET", u16::from(crate::packet::Attribute::PdPacket))?;

    // GraphSampleRate constants
    m.add("RATE_2_SPS", crate::adcqueue::GraphSampleRate::Sps2 as u16)?;
    m.add("RATE_10_SPS", crate::adcqueue::GraphSampleRate::Sps10 as u16)?;
    m.add("RATE_50_SPS", crate::adcqueue::GraphSampleRate::Sps50 as u16)?;
    m.add("RATE_1000_SPS", crate::adcqueue::GraphSampleRate::Sps1000 as u16)?;

    Ok(())
}
