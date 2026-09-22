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
use crate::adcqueue::{AdcQueueData, AdcQueueRawData, AdcQueueSample, AdcQueueSampleRaw, GraphSampleRate};
use crate::auth;
use crate::message::Packet;
use crate::offline::LogMetadata;
use crate::packet::{CtrlHeader, LogicalPacket, RawPacket};
use crate::pd::{PdEvent, PdEventStream, PdStatus};
use crate::pd_trace::{PdTrace, PdTraceProtocolEvent, PdTraceStateEvent};
use bytes::Bytes;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Parse raw ADC data bytes directly into processed measurements.
///
/// Args:
///     data: Raw ADC data bytes (must be exactly 44 bytes for AdcDataRaw)
///
/// Returns:
///     AdcData: Processed ADC measurements with voltage/current/power values
///
/// Raises:
///     ValueError: If data is not the correct size for AdcDataRaw structure
///
/// Example:
///     ```text
///     # Parse 44-byte ADC payload from a packet
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
///     ```text
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

/// Parse packet bytes using the graph rate selected by `StartGraph`.
///
/// This is the typed counterpart to [`parse_packet`] for callers processing
/// captured or live AdcQueue responses with known stream configuration.
#[pyfunction]
pub fn parse_packet_with_graph_rate(data: &[u8], rate_index: u16) -> PyResult<Packet> {
    let rate = GraphSampleRate::try_from(rate_index).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err(format!("Invalid graph sample rate index: {rate_index}"))
    })?;
    let raw_packet = RawPacket::try_from(Bytes::from(data.to_vec()))
        .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;

    Packet::from_raw_with_graph_rate(raw_packet, rate)
        .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))
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
///     ```text
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
///     List[SampleRate]: Available sample rates from 2 to 10000 samples per second
///                       Each has .hz (int) and .name (str) properties
///
/// Example:
///     ```text
///     rates = get_sample_rates()
///     for rate in rates:
///         print(f"{rate.name}: {rate.hz} Hz")
///     # Output:
///     # 2 SPS: 2 Hz
///     # 10 SPS: 10 Hz
///     # 50 SPS: 50 Hz
///     # 1 kSPS: 1000 Hz
///     # 10 kSPS: 10000 Hz
///     ```
#[pyfunction]
pub fn get_sample_rates() -> Vec<SampleRate> {
    vec![
        SampleRate::Sps2,
        SampleRate::Sps10,
        SampleRate::Sps50,
        SampleRate::Sps1000,
        SampleRate::Sps10000,
    ]
}

/// Build a complete MemoryRead (0x44) request packet.
///
/// Returns the 36 bytes to write to the OUT endpoint: a 4-byte header followed
/// by the AES-128-ECB encrypted request body. Use this instead of
/// re-implementing the AES key, CRC and padding layout in Python.
///
/// Args:
///     address: Memory address to read from
///     size: Number of bytes to read
///     transaction_id: Transaction ID for correlating the response
///
/// Returns:
///     bytes: 36-byte packet ready to send
#[pyfunction]
pub fn build_memory_read_packet(py: Python<'_>, address: u32, size: u32, transaction_id: u8) -> Bound<'_, PyBytes> {
    PyBytes::new(py, &auth::build_memory_read_packet(address, size, transaction_id))
}

/// Decrypt a MemoryRead confirmation or data payload.
///
/// The device answers a MemoryRead with an unframed AES-128-ECB ciphertext
/// whose length is a multiple of 16.
///
/// Args:
///     ciphertext: Encrypted bytes, length must be a non-zero multiple of 16
///
/// Returns:
///     bytes: Decrypted plaintext of the same length
///
/// Raises:
///     ValueError: If the ciphertext length is not AES-aligned
#[pyfunction]
pub fn decrypt_memory_payload<'py>(py: Python<'py>, ciphertext: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let plaintext = auth::decrypt_memory_read_response(ciphertext).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "Ciphertext length must be a non-zero multiple of 16, got {}",
            ciphertext.len()
        ))
    })?;
    Ok(PyBytes::new(py, &plaintext))
}

/// Decode a MemoryRead confirmation packet.
///
/// Validates the echoed address/size, the magic word and the CRC-32, exactly
/// as the Rust device layer does.
///
/// Args:
///     packet: Full confirmation packet (4-byte header + 16-byte body)
///
/// Returns:
///     tuple[int, int] | None: (address, size) when the confirmation is valid
#[pyfunction]
pub fn parse_memory_read_confirmation(packet: &[u8]) -> Option<(u32, u32)> {
    let body = packet.get(crate::constants::MAIN_HEADER_SIZE..)?;
    auth::parse_memory_read_confirmation(body)
}

/// Build a complete StreamingAuth (0x4C) request packet.
///
/// Args:
///     credential: 12-byte HardwareID (level 1) or calibration record (level 2)
///     transaction_id: Transaction ID
///
/// Returns:
///     bytes: 36-byte packet ready to send
///
/// Raises:
///     ValueError: If the credential is not exactly 12 bytes
#[pyfunction]
pub fn build_streaming_auth_packet<'py>(
    py: Python<'py>,
    credential: &[u8],
    transaction_id: u8,
) -> PyResult<Bound<'py, PyBytes>> {
    let credential: [u8; auth::STREAMING_AUTH_CREDENTIAL_SIZE] = credential.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "Credential must be exactly {} bytes, got {}",
            auth::STREAMING_AUTH_CREDENTIAL_SIZE,
            credential.len()
        ))
    })?;
    let packet = auth::build_streaming_auth_packet(&auth::AuthCredential::from_bytes(credential), transaction_id);
    Ok(PyBytes::new(py, &packet))
}

/// Parse a StreamingAuth (0x4C) response packet.
///
/// Args:
///     response: Full response packet (4-byte header + 32-byte body)
///
/// Returns:
///     dict | None: `success`, `auth_level`, `attribute` and `decrypted_payload`
#[pyfunction]
pub fn parse_streaming_auth_response<'py>(py: Python<'py>, response: &[u8]) -> Option<Bound<'py, PyAny>> {
    use pyo3::types::{PyDict, PyDictMethods};

    let result = auth::parse_streaming_auth_response(response)?;
    let dict = PyDict::new(py);
    dict.set_item("success", result.success).ok()?;
    dict.set_item("auth_level", result.auth_level).ok()?;
    dict.set_item("attribute", result.attribute).ok()?;
    dict.set_item("decrypted_payload", PyBytes::new(py, &result.decrypted_payload))
        .ok()?;
    Some(dict.into_any())
}

/// Parse one 48-byte offline recording catalog entry.
///
/// Args:
///     data: Exactly 48 bytes of `LogMetadata` payload
///
/// Returns:
///     LogMetadata: Typed catalog entry
///
/// Raises:
///     ValueError: If the payload is not exactly 48 bytes
#[pyfunction]
pub fn parse_log_metadata(data: &[u8]) -> PyResult<LogMetadata> {
    LogMetadata::from_bytes(data).map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))
}

/// Parse a downloaded offline recording into its samples.
///
/// Args:
///     data: Raw sample bytes, a multiple of 16
///
/// Returns:
///     `list[dict]`: One dict per sample with `voltage_uv`, `current_ua`,
///     `charge_uah` and `energy_uwh`
///
/// Raises:
///     ValueError: If the length is not a multiple of 16
#[pyfunction]
pub fn parse_offline_log_samples(py: Python<'_>, data: &[u8]) -> PyResult<Vec<Py<PyAny>>> {
    use crate::offline::OFFLINE_LOG_SAMPLE_SIZE;
    use pyo3::types::{PyDict, PyDictMethods};

    if !data.len().is_multiple_of(OFFLINE_LOG_SAMPLE_SIZE) {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Offline log length must be a multiple of {OFFLINE_LOG_SAMPLE_SIZE}, got {}",
            data.len()
        )));
    }

    data.as_chunks::<OFFLINE_LOG_SAMPLE_SIZE>()
        .0
        .iter()
        .map(|chunk| {
            let raw = crate::offline::OfflineLogSampleRaw::from_wire_bytes(chunk)
                .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
            let dict = PyDict::new(py);
            dict.set_item("voltage_uv", raw.voltage_uv)?;
            dict.set_item("current_ua", raw.current_ua)?;
            dict.set_item("charge_uah", raw.charge_uah)?;
            dict.set_item("energy_uwh", raw.energy_uwh)?;
            Ok(dict.into_any().unbind())
        })
        .collect()
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
#[pyfunction]
pub fn create_packet<'py>(py: Python<'py>, packet_type: u8, transaction_id: u8, data: u16) -> Bound<'py, PyBytes> {
    let header = CtrlHeader::new()
        .with_packet_type(packet_type)
        .with_reserved_flag(false)
        .with_id(transaction_id)
        .with_attribute(data);

    PyBytes::new(py, &header.into_bytes())
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
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    // Core data classes (using native types with Python bindings)
    m.add_class::<AdcDataSimple>()?;
    m.add_class::<SampleRate>()?;
    m.add_class::<AdcQueueSample>()?;
    m.add_class::<AdcQueueData>()?;
    m.add_class::<AdcQueueSampleRaw>()?;
    m.add_class::<AdcQueueRawData>()?;
    m.add_class::<PdStatus>()?;
    m.add_class::<PdEvent>()?;
    m.add_class::<PdEventStream>()?;
    m.add_class::<LogicalPacket>()?;
    m.add_class::<PdTrace>()?;
    m.add_class::<PdTraceStateEvent>()?;
    m.add_class::<PdTraceProtocolEvent>()?;
    m.add_class::<LogMetadata>()?;

    // Parsing functions
    m.add_function(wrap_pyfunction!(parse_raw_adc_data, m)?)?;
    m.add_function(wrap_pyfunction!(parse_packet, m)?)?;
    m.add_function(wrap_pyfunction!(parse_packet_with_graph_rate, m)?)?;
    m.add_function(wrap_pyfunction!(parse_raw_packet, m)?)?;
    m.add_function(wrap_pyfunction!(get_sample_rates, m)?)?;

    // Packet creation function
    m.add_function(wrap_pyfunction!(create_packet, m)?)?;

    // Authenticated command helpers. These exist so host tooling never has to
    // re-implement the AES keys, CRC layout or header framing in Python.
    m.add_function(wrap_pyfunction!(build_memory_read_packet, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_memory_payload, m)?)?;
    m.add_function(wrap_pyfunction!(parse_memory_read_confirmation, m)?)?;
    m.add_function(wrap_pyfunction!(build_streaming_auth_packet, m)?)?;
    m.add_function(wrap_pyfunction!(parse_streaming_auth_response, m)?)?;
    m.add_function(wrap_pyfunction!(parse_log_metadata, m)?)?;
    m.add_function(wrap_pyfunction!(parse_offline_log_samples, m)?)?;

    // USB device identification constants
    m.add("VID", crate::device::VID)?;
    m.add("PID", crate::device::PID)?;

    // USB endpoints, so host scripts do not hardcode them
    m.add("INTERFACE_VENDOR", crate::device::INTERFACE_VENDOR)?;
    m.add("ENDPOINT_OUT_VENDOR", crate::device::ENDPOINT_OUT_VENDOR)?;
    m.add("ENDPOINT_IN_VENDOR", crate::device::ENDPOINT_IN_VENDOR)?;
    m.add("INTERFACE_HID", crate::device::INTERFACE_HID)?;
    m.add("ENDPOINT_OUT_HID", crate::device::ENDPOINT_OUT_HID)?;
    m.add("ENDPOINT_IN_HID", crate::device::ENDPOINT_IN_HID)?;

    // Documented device memory map
    m.add("ADDR_DEVICE_INFO", auth::DEVICE_INFO_ADDRESS)?;
    m.add("ADDR_FIRMWARE_INFO", auth::FIRMWARE_INFO_ADDRESS)?;
    m.add("ADDR_CALIBRATION", auth::CALIBRATION_ADDRESS)?;
    m.add("ADDR_PREFERRED_CALIBRATION", auth::PREFERRED_CALIBRATION_ADDRESS)?;
    m.add("ADDR_HARDWARE_ID", auth::HARDWARE_ID_ADDRESS)?;
    m.add("ADDR_OFFLINE_LOG", crate::offline::OFFLINE_LOG_ADDRESS)?;
    m.add("INFO_BLOCK_SIZE", auth::INFO_BLOCK_SIZE)?;
    m.add("HARDWARE_ID_SIZE", auth::HARDWARE_ID_SIZE)?;
    m.add("LOG_METADATA_SIZE", crate::offline::LOG_METADATA_SIZE)?;
    m.add("OFFLINE_LOG_SAMPLE_SIZE", crate::offline::OFFLINE_LOG_SAMPLE_SIZE)?;

    // PacketType constants (use Into trait for enums with catch_all)
    m.add("CMD_SYNC", u8::from(crate::packet::PacketType::Sync))?;
    m.add("CMD_CONNECT", u8::from(crate::packet::PacketType::Connect))?;
    m.add("CMD_DISCONNECT", u8::from(crate::packet::PacketType::Disconnect))?;
    m.add("CMD_ACCEPT", u8::from(crate::packet::PacketType::Accept))?;
    m.add("CMD_REJECT", u8::from(crate::packet::PacketType::Rejected))?;
    m.add("CMD_GET_DATA", u8::from(crate::packet::PacketType::GetData))?;
    m.add("CMD_START_GRAPH", u8::from(crate::packet::PacketType::StartGraph))?;
    m.add("CMD_STOP_GRAPH", u8::from(crate::packet::PacketType::StopGraph))?;
    m.add(
        "CMD_ENABLE_PD_MONITOR",
        u8::from(crate::packet::PacketType::EnablePdMonitor),
    )?;
    m.add(
        "CMD_DISABLE_PD_MONITOR",
        u8::from(crate::packet::PacketType::DisablePdMonitor),
    )?;
    m.add("CMD_MEMORY_READ", u8::from(crate::packet::PacketType::MemoryRead))?;
    m.add("CMD_STREAMING_AUTH", u8::from(crate::packet::PacketType::StreamingAuth))?;

    // Attribute constants (use Into trait)
    m.add("ATT_ADC", u16::from(crate::packet::Attribute::Adc))?;
    m.add("ATT_ADC_QUEUE", u16::from(crate::packet::Attribute::AdcQueue))?;
    m.add("ATT_ADC_QUEUE_10K", u16::from(crate::packet::Attribute::AdcQueue10k))?;
    m.add("ATT_SETTINGS", u16::from(crate::packet::Attribute::Settings))?;
    m.add("ATT_PD_PACKET", u16::from(crate::packet::Attribute::PdPacket))?;
    m.add("ATT_PD_TRACE", u16::from(crate::packet::Attribute::PdTrace))?;
    m.add("ATT_LOG_METADATA", u16::from(crate::packet::Attribute::LogMetadata))?;

    // GraphSampleRate constants
    m.add("RATE_2_SPS", crate::adcqueue::GraphSampleRate::Sps2 as u16)?;
    m.add("RATE_10_SPS", crate::adcqueue::GraphSampleRate::Sps10 as u16)?;
    m.add("RATE_50_SPS", crate::adcqueue::GraphSampleRate::Sps50 as u16)?;
    m.add("RATE_1000_SPS", crate::adcqueue::GraphSampleRate::Sps1000 as u16)?;

    Ok(())
}
