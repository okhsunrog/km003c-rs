//! KM003C USB device communication
//!
//! # KM003C USB Interfaces
//!
//! The KM003C provides multiple USB interfaces for communication.
//! All interfaces support the same protocol commands (4-byte packets).
//!
//! ## Interface 0: Vendor Specific (Primary Protocol)
//! - **Transfer Type**: Bulk
//! - **Endpoints**: 0x01 OUT, 0x81 IN
//! - **Max Packet Size**: 64 bytes
//! - **Throughput**: ~200 KB/s (official spec)
//! - **Latency**: ~0.6 ms (measured)
//! - **Linux Driver**: `powerz` (hwmon)
//! - **Use Case**: Best performance, same as kernel driver
//! - **Note**: Requires detaching kernel driver on Linux
//!
//! ## Interface 1+2: CDC (Virtual Serial Port)
//! - **Transfer Type**: Bulk (Interface 2) + Interrupt (Interface 1)
//! - **Endpoints**: 0x02 OUT, 0x82 IN (data), 0x83 IN (control)
//! - **Throughput**: ~200 KB/s (official spec)
//! - **Linux Driver**: `cdc_acm`
//! - **Use Case**: Serial port compatibility
//! - **Note**: Not currently implemented in this library
//!
//! ## Interface 3: HID (Human Interface Device)
//! - **Transfer Type**: Interrupt
//! - **Endpoints**: 0x05 OUT, 0x85 IN
//! - **Max Packet Size**: 64 bytes
//! - **Throughput**: ~60 KB/s (official spec)
//! - **Latency**: ~3.8 ms (measured)
//! - **Linux Driver**: `usbhid`
//! - **Use Case**: Most compatible, no driver installation needed
//! - **Note**: Works on all platforms without custom drivers
//!
//! ## Performance Comparison
//! Based on real device measurements:
//! - **Interface 0 (Bulk)**: 0.6 ms latency - **6x faster** ⚡
//! - **Interface 3 (Interrupt)**: 3.8 ms latency - most compatible
//!
//! ## Recommendation
//! - Use **Interface 0** for performance-critical applications (same as kernel driver)
//! - Use **Interface 3** for maximum compatibility across platforms

use crate::adc::AdcDataSimple;
use crate::adcqueue::GraphSampleRate;
use crate::auth::{DeviceInfo, HardwareId};
use crate::error::KMError;
use crate::message::Packet;
use crate::offline::{LogMetadata, LogMetadataResponse, OFFLINE_LOG_ADDRESS, OfflineLog};
use crate::packet::{Attribute, AttributeSet, PacketType, RawPacket};
use crate::pd::{PdEventStream, PdStatus};
use bytes::Bytes;
use nusb::Interface;
use nusb::io::{EndpointRead, EndpointWrite};
use nusb::transfer::{Bulk, Interrupt};
use std::collections::VecDeque;
use std::fmt;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::{debug, info, trace, warn};

/// Device state populated by initialization
///
/// Contains all information gathered during device init:
/// - Device info (model, versions, serials)
/// - Hardware ID (used for authentication)
/// - Authentication state
#[derive(Debug, Clone)]
pub struct DeviceState {
    /// Device information (model, firmware, serials, etc.)
    pub info: DeviceInfo,
    /// Hardware ID used for authentication
    pub hardware_id: HardwareId,
    /// Authentication level (0 = not authenticated, 1+ = authenticated)
    pub auth_level: u8,
    /// Whether AdcQueue streaming is enabled
    pub adcqueue_enabled: bool,
}

impl DeviceState {
    /// Check if device is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.auth_level > 0
    }

    /// Get device model name
    pub fn model(&self) -> &str {
        &self.info.model
    }

    /// Get firmware version
    pub fn firmware_version(&self) -> &str {
        &self.info.fw_version
    }
}

impl fmt::Display for DeviceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const W: usize = 58; // inner width between │ and │

        // Helper to create a content line with label and value
        fn line(label: &str, value: &str) -> String {
            let content = format!(" {}: {}", label, value);
            format!("│{:<W$}│", content, W = W)
        }

        let sep = format!("├{:─<W$}┤", "", W = W);

        writeln!(f, "┌{:─<W$}┐", "", W = W)?;
        writeln!(f, "│{:^W$}│", "POWER-Z KM003C Device Information", W = W)?;
        writeln!(f, "{}", sep)?;
        writeln!(f, "{}", line("Model", &self.info.model))?;
        writeln!(f, "{}", line("Hardware Version", &self.info.hw_version))?;
        writeln!(f, "{}", line("Mfg Date", &self.info.mfg_date))?;
        writeln!(f, "{}", sep)?;
        writeln!(f, "{}", line("Firmware Version", &self.info.fw_version))?;
        writeln!(f, "{}", line("Firmware Date", &self.info.fw_date))?;
        writeln!(f, "{}", sep)?;
        writeln!(f, "{}", line("Serial ID", &self.info.serial_id))?;
        writeln!(f, "{}", line("UUID", &self.info.uuid))?;
        writeln!(f, "{}", line("Hardware ID", &format!("{}", self.hardware_id)))?;
        writeln!(f, "{}", sep)?;
        writeln!(f, "{}", line("Auth Level", &format!("{}", self.auth_level)))?;
        writeln!(f, "{}", line("AdcQueue Enabled", &format!("{}", self.adcqueue_enabled)))?;
        write!(f, "└{:─<W$}┘", "", W = W)
    }
}

/// USB device identification constants
pub const VID: u16 = 0x5FC9; // ChargerLAB vendor ID
pub const PID: u16 = 0x0063; // KM003C product ID

/// Interface 0 (Vendor Specific): Bulk transfers, fastest (~0.6ms)
pub const INTERFACE_VENDOR: u8 = 0;
pub const ENDPOINT_OUT_VENDOR: u8 = 0x01;
pub const ENDPOINT_IN_VENDOR: u8 = 0x81;

/// Interface 3 (HID): Interrupt transfers, most compatible (~3.8ms)
pub const INTERFACE_HID: u8 = 3;
pub const ENDPOINT_OUT_HID: u8 = 0x05;
pub const ENDPOINT_IN_HID: u8 = 0x85;

// Default timeout for USB operations
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
const BULK_TRANSFER_SIZE: usize = 2048;
const INTERRUPT_TRANSFER_SIZE: usize = 64;
const MAX_PENDING_RESPONSES: usize = 256;
const AES_BLOCK_SIZE: usize = 16;

fn parse_framed_response(bytes: &[u8]) -> Option<RawPacket> {
    RawPacket::try_from(Bytes::copy_from_slice(bytes)).ok()
}

fn response_matches(bytes: &[u8], id: u8, packet_type: PacketType) -> bool {
    parse_framed_response(bytes).is_some_and(|packet| packet.id() == id && packet.packet_type() == packet_type)
}

fn response_type_matches(bytes: &[u8], packet_type: PacketType) -> bool {
    parse_framed_response(bytes).is_some_and(|packet| packet.packet_type() == packet_type)
}

fn control_response_matches(bytes: &[u8], id: u8) -> bool {
    matches!(
        parse_framed_response(bytes),
        Some(RawPacket::Ctrl { header, .. }) if header.id() == id
    )
}

fn memory_confirmation_matches(bytes: &[u8], id: u8) -> bool {
    parse_framed_response(bytes).is_some_and(|packet| {
        packet.id() == id
            && matches!(
                packet.packet_type(),
                PacketType::MemoryRead | PacketType::Rejected | PacketType::NotReadable
            )
    })
}

fn memory_response_size(requested_size: u32) -> usize {
    (requested_size as usize).div_ceil(AES_BLOCK_SIZE) * AES_BLOCK_SIZE
}

fn append_memory_chunk(buffer: &mut Vec<u8>, chunk: &[u8], expected_size: usize) -> Result<bool, KMError> {
    if chunk.is_empty() {
        return Err(KMError::Protocol(
            "Received an empty encrypted memory chunk".to_string(),
        ));
    }

    let remaining = expected_size.saturating_sub(buffer.len());
    if chunk.len() > remaining {
        return Err(KMError::Protocol(format!(
            "Encrypted memory response exceeded expected size: expected {expected_size} bytes, got at least {}",
            buffer.len() + chunk.len()
        )));
    }

    buffer.extend_from_slice(chunk);
    Ok(buffer.len() == expected_size)
}

fn decrypt_memory_response(encrypted: &[u8], requested_size: u32) -> Result<Vec<u8>, KMError> {
    let expected_size = memory_response_size(requested_size);
    if encrypted.len() != expected_size {
        return Err(KMError::Protocol(format!(
            "Encrypted memory response has the wrong size: expected {expected_size} bytes, got {}",
            encrypted.len()
        )));
    }

    let mut decrypted = crate::auth::aes_ecb_decrypt_blocks(encrypted, crate::auth::MEMORY_READ_KEY)?;
    decrypted.truncate(requested_size as usize);
    Ok(decrypted)
}

fn validate_memory_read_confirmation(
    packet: &RawPacket,
    expected_id: u8,
    expected_address: u32,
    expected_size: u32,
) -> Result<(), KMError> {
    let RawPacket::SimpleData { header, payload } = packet else {
        return Err(KMError::Protocol(
            "MemoryRead confirmation has an unexpected packet layout".to_string(),
        ));
    };

    if header.id() != expected_id || PacketType::from(header.packet_type()) != PacketType::MemoryRead {
        return Err(KMError::Protocol(
            "MemoryRead confirmation does not match the request".to_string(),
        ));
    }
    if payload.len() != 16 {
        return Err(KMError::Protocol(format!(
            "MemoryRead confirmation must contain 16 bytes, got {}",
            payload.len()
        )));
    }

    let address = u32::from_le_bytes(payload[0..4].try_into()?);
    let size = u32::from_le_bytes(payload[4..8].try_into()?);
    let magic = u32::from_le_bytes(payload[8..12].try_into()?);
    let crc = u32::from_le_bytes(payload[12..16].try_into()?);
    let expected_crc = crc32fast::hash(&payload[..12]);

    if address != expected_address || size != expected_size {
        return Err(KMError::Protocol(format!(
            "MemoryRead confirmation echoed address 0x{address:08X} and size {size}, expected 0x{expected_address:08X} and {expected_size}"
        )));
    }
    if magic != u32::MAX {
        return Err(KMError::Protocol(format!(
            "MemoryRead confirmation has invalid magic 0x{magic:08X}"
        )));
    }
    if crc != expected_crc {
        return Err(KMError::Protocol(format!(
            "MemoryRead confirmation CRC mismatch: expected 0x{expected_crc:08X}, got 0x{crc:08X}"
        )));
    }

    Ok(())
}

/// Transfer type for USB communication
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferType {
    Bulk,
    Interrupt,
}

/// Connection mode determined by interface type
///
/// - **Basic**: HID interface - ADC/PD polling only, no initialization needed
/// - **Full**: Vendor interface - all features including AdcQueue streaming
#[derive(Debug, Clone)]
pub enum ConnectionMode {
    /// Basic mode (HID interface) - ADC/PD polling only
    Basic,
    /// Full mode (Vendor interface) - all features, includes device state
    Full(DeviceState),
}

fn ensure_adcqueue_available(mode: &ConnectionMode) -> Result<(), KMError> {
    match mode {
        ConnectionMode::Basic => Err(KMError::Protocol(
            "AdcQueue streaming requires Full mode (vendor interface)".to_string(),
        )),
        ConnectionMode::Full(state) if !state.adcqueue_enabled => Err(KMError::Protocol(
            "StreamingAuth did not enable AdcQueue streaming".to_string(),
        )),
        ConnectionMode::Full(_) => Ok(()),
    }
}

/// Configuration for KM003C device communication
///
/// Specifies which USB interface to use. The interface determines the connection mode:
/// - **Vendor** (Interface 0): Full mode - all features including AdcQueue
/// - **HID** (Interface 3): Basic mode - ADC/PD polling only
///
/// # Examples
///
/// ```no_run
/// use km003c_lib::{KM003C, DeviceConfig};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Full mode with vendor interface (fastest, all features)
/// let device = KM003C::new(DeviceConfig::vendor()).await?;
///
/// // Basic mode with HID interface (most compatible, ADC/PD only)
/// let device = KM003C::new(DeviceConfig::hid()).await?;
///
/// // With options
/// let device = KM003C::new(DeviceConfig::vendor().skip_reset()).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct DeviceConfig {
    /// USB interface number (0 or 3)
    interface: u8,
    /// OUT endpoint address
    endpoint_out: u8,
    /// IN endpoint address
    endpoint_in: u8,
    /// Transfer type (Bulk or Interrupt)
    transfer_type: TransferType,
    /// Skip initial USB reset
    skip_reset: bool,
}

impl DeviceConfig {
    /// Vendor interface (Interface 0) - Full mode with all features
    ///
    /// This is the **fastest option** with ~0.6ms latency (6x faster than HID).
    /// Enables all features including AdcQueue streaming.
    ///
    /// **Performance**:
    /// - Latency: ~600 µs per request
    /// - Throughput: ~200 KB/s
    ///
    /// **Features**: Full mode - ADC, PD, AdcQueue, device info, authentication
    ///
    /// **Note**: On Linux, requires detaching the `powerz` kernel driver,
    /// which this library handles automatically.
    pub fn vendor() -> Self {
        Self {
            interface: INTERFACE_VENDOR,
            endpoint_out: ENDPOINT_OUT_VENDOR,
            endpoint_in: ENDPOINT_IN_VENDOR,
            transfer_type: TransferType::Bulk,
            skip_reset: false,
        }
    }

    /// HID interface (Interface 3) - Basic mode for ADC/PD polling
    ///
    /// This is the **most compatible option** that works on all platforms
    /// without custom drivers. Only supports basic ADC and PD polling.
    ///
    /// **Performance**:
    /// - Latency: ~3.8 ms per request
    /// - Throughput: ~60 KB/s
    ///
    /// **Features**: Basic mode - ADC and PD polling only (no AdcQueue, no device info)
    ///
    /// **Advantages**:
    /// - Works without driver installation on Windows/Mac/Linux
    /// - Uses standard HID protocol
    /// - No permission issues
    pub fn hid() -> Self {
        Self {
            interface: INTERFACE_HID,
            endpoint_out: ENDPOINT_OUT_HID,
            endpoint_in: ENDPOINT_IN_HID,
            transfer_type: TransferType::Interrupt,
            skip_reset: false,
        }
    }

    /// Skip USB reset during connection
    ///
    /// Some systems (particularly MacOS) may have issues with USB reset.
    /// Use this if device connection fails with reset errors.
    pub fn skip_reset(mut self) -> Self {
        self.skip_reset = true;
        self
    }

    /// Check if this config uses vendor interface (full mode)
    pub fn is_vendor(&self) -> bool {
        self.interface == INTERFACE_VENDOR
    }

    /// Check if this config uses HID interface (basic mode)
    pub fn is_hid(&self) -> bool {
        self.interface == INTERFACE_HID
    }
}

/// Endpoint reader wrapper to handle both Bulk and Interrupt types
enum EndpointReaderType {
    Bulk(EndpointRead<Bulk>),
    Interrupt(EndpointRead<Interrupt>),
}

/// Endpoint writer wrapper to handle both Bulk and Interrupt types
enum EndpointWriterType {
    Bulk(EndpointWrite<Bulk>),
    Interrupt(EndpointWrite<Interrupt>),
}

pub struct KM003C {
    /// Kept alive for RAII - dropping this releases the USB interface claim
    #[allow(dead_code)]
    interface: Interface,
    transaction_id: u8,
    reader: EndpointReaderType,
    writer: EndpointWriterType,
    pending_responses: VecDeque<Vec<u8>>,
    /// Rate currently selected with StartGraph, used to decode rate-dependent fields.
    graph_sample_rate: Option<GraphSampleRate>,
    /// Connection mode: Basic (HID) or Full (Vendor with device state)
    mode: ConnectionMode,
}

impl KM003C {
    /// Connect to device with the given configuration
    ///
    /// The config determines the connection mode:
    /// - **`DeviceConfig::vendor()`**: Full mode - runs init sequence, all features enabled
    /// - **`DeviceConfig::hid()`**: Basic mode - no init, ADC/PD polling only
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use km003c_lib::{KM003C, DeviceConfig};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Full mode (vendor interface) - all features
    /// let device = KM003C::new(DeviceConfig::vendor()).await?;
    /// println!("Model: {}", device.state().unwrap().model());
    /// println!("AdcQueue enabled: {}", device.adcqueue_enabled());
    ///
    /// // Basic mode (HID interface) - ADC/PD polling only
    /// let mut device = KM003C::new(DeviceConfig::hid()).await?;
    /// let adc = device.request_adc_data().await?;
    ///
    /// // With options
    /// let device = KM003C::new(DeviceConfig::vendor().skip_reset()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(config: DeviceConfig) -> Result<Self, KMError> {
        let mut device = Self::connect(config).await?;

        if config.is_vendor() {
            // Full mode: run init sequence
            device.run_init().await?;
        }
        // HID mode: stays in Basic mode, no init needed

        Ok(device)
    }

    /// Internal: Connect to USB device without initialization
    async fn connect(config: DeviceConfig) -> Result<Self, KMError> {
        info!("Searching for POWER-Z KM003C...");
        let device_info = nusb::list_devices()
            .await?
            .find(|d| d.vendor_id() == VID && d.product_id() == PID)
            .ok_or(KMError::DeviceNotFound)?;

        info!(
            "Found device on bus {} addr {}",
            device_info.bus_id(),
            device_info.device_address()
        );

        let mut device = device_info.open().await?;

        // Optionally reset device (skip on MacOS if having issues)
        if !config.skip_reset {
            info!("Resetting device...");
            device.reset().await?;
            // CRITICAL: Device needs 1.5 seconds to fully initialize after reset
            // (validated through protocol research - 100ms is insufficient for AdcQueue)
            tokio::time::sleep(Duration::from_millis(1500)).await;
            // Re-enumerate and reopen after reset (old handle may be invalid).
            let device_info = nusb::list_devices()
                .await?
                .find(|d| d.vendor_id() == VID && d.product_id() == PID)
                .ok_or(KMError::DeviceNotFound)?;
            device = device_info.open().await?;
        } else {
            debug!("Skipping USB reset (skip_reset=true)");
        }

        // Detach kernel drivers from ALL interfaces
        // All 4 interfaces have kernel drivers on Linux:
        //   Interface 0: powerz (hwmon)
        //   Interface 1+2: cdc_acm (serial)
        //   Interface 3: usbhid (HID generic)
        // Detaching all prevents re-binding and ensures clean access
        for interface_num in 0..4 {
            if let Err(e) = device.detach_kernel_driver(interface_num) {
                // Ignore errors - driver may already be detached
                trace!("Could not detach interface {}: {}", interface_num, e);
            } else {
                debug!("Detached kernel driver from interface {}", interface_num);
            }
        }

        // Claim the configured interface
        let interface = device.claim_interface(config.interface).await?;
        info!("Interface {} claimed successfully", config.interface);

        // Create persistent endpoints based on transfer type
        // Using 4 concurrent transfers for better throughput
        // A bulk response can span multiple 2048-byte transfers. receive_raw()
        // joins transfers until the device terminates the response with a short packet.
        let (reader, writer) = match config.transfer_type {
            TransferType::Bulk => {
                let ep_in = interface.endpoint::<Bulk, _>(config.endpoint_in)?;
                let ep_out = interface.endpoint::<Bulk, _>(config.endpoint_out)?;
                (
                    EndpointReaderType::Bulk(ep_in.reader(BULK_TRANSFER_SIZE).with_num_transfers(4)),
                    EndpointWriterType::Bulk(ep_out.writer(INTERRUPT_TRANSFER_SIZE).with_num_transfers(4)),
                )
            }
            TransferType::Interrupt => {
                let ep_in = interface.endpoint::<Interrupt, _>(config.endpoint_in)?;
                let ep_out = interface.endpoint::<Interrupt, _>(config.endpoint_out)?;
                (
                    EndpointReaderType::Interrupt(ep_in.reader(INTERRUPT_TRANSFER_SIZE).with_num_transfers(4)),
                    EndpointWriterType::Interrupt(ep_out.writer(INTERRUPT_TRANSFER_SIZE).with_num_transfers(4)),
                )
            }
        };

        let km003c = Self {
            interface,
            transaction_id: 0,
            reader,
            writer,
            pending_responses: VecDeque::new(),
            graph_sample_rate: None,
            mode: ConnectionMode::Basic,
        };

        info!("USB connection established");
        Ok(km003c)
    }

    /// Get the next transaction ID (internal use)
    fn next_transaction_id(&mut self) -> u8 {
        let id = self.transaction_id;
        self.transaction_id = self.transaction_id.wrapping_add(1);
        id
    }

    /// Get the next transaction ID (for auth module and external use)
    pub fn next_tid(&mut self) -> u8 {
        self.next_transaction_id()
    }

    /// Set the transaction ID counter (for protocol research/sync purposes)
    pub fn set_transaction_id(&mut self, id: u8) {
        self.transaction_id = id;
    }

    /// Send a high-level packet without waiting for or correlating its response.
    ///
    /// This is a low-level protocol-research API. Prefer command-specific methods
    /// such as [`Self::request_data`] and [`Self::read_memory_block`] for normal use.
    pub async fn send(&mut self, packet: Packet) -> Result<(), KMError> {
        self.send_tracked(packet).await.map(|_| ())
    }

    /// Send a high-level packet and return the transaction ID placed on the wire.
    async fn send_tracked(&mut self, packet: Packet) -> Result<u8, KMError> {
        use crate::auth;

        let id = self.next_transaction_id();

        // Special handling for auth packets that need custom wire format
        // (MemoryRead and StreamingAuth use a different header layout than standard packets)
        match &packet {
            Packet::MemoryRead { address, size } => {
                let raw = auth::build_memory_read_packet(*address, *size, id);
                self.send_raw(&raw).await?;
                return Ok(id);
            }
            Packet::StreamingAuth { hardware_id } => {
                let raw = auth::build_streaming_auth_packet(hardware_id, id);
                self.send_raw(&raw).await?;
                return Ok(id);
            }
            _ => {}
        }

        let raw_packet = packet.to_raw_packet(id)?;
        self.send_raw_packet(raw_packet).await?;
        Ok(id)
    }

    /// Send a raw packet to the device
    async fn send_raw_packet(&mut self, packet: RawPacket) -> Result<(), KMError> {
        let (reserved_flag, has_logical_packets) = match &packet {
            RawPacket::Ctrl { header, .. } => (header.reserved_flag(), false),
            RawPacket::SimpleData { header, .. } => (header.reserved_flag(), false),
            RawPacket::Data {
                header,
                logical_packets,
            } => (header.reserved_flag(), !logical_packets.is_empty()),
        };

        debug!(
            "Sending packet: type={:?}, reserved_flag={}, has_logical_packets={}, id={}",
            packet.packet_type(),
            reserved_flag,
            has_logical_packets,
            packet.id(),
        );

        let message_bytes = Bytes::from(packet);
        let message = message_bytes.to_vec();
        trace!("TX [{} bytes]: {:02x?}", message.len(), message);

        // Use the persistent writer
        match &mut self.writer {
            EndpointWriterType::Bulk(writer) => {
                timeout(DEFAULT_TIMEOUT, writer.write_all(&message)).await??;
                timeout(DEFAULT_TIMEOUT, writer.flush_end_async()).await??;
            }
            EndpointWriterType::Interrupt(writer) => {
                timeout(DEFAULT_TIMEOUT, writer.write_all(&message)).await??;
                timeout(DEFAULT_TIMEOUT, writer.flush_end_async()).await??;
            }
        }

        debug!("Sent successfully");
        Ok(())
    }

    /// Send raw bytes to the device (for protocol research/testing)
    pub async fn send_raw(&mut self, data: &[u8]) -> Result<(), KMError> {
        trace!("TX [{} bytes]: {:02x?}", data.len(), data);
        match &mut self.writer {
            EndpointWriterType::Bulk(writer) => {
                timeout(DEFAULT_TIMEOUT, writer.write_all(data)).await??;
                timeout(DEFAULT_TIMEOUT, writer.flush_end_async()).await??;
            }
            EndpointWriterType::Interrupt(writer) => {
                timeout(DEFAULT_TIMEOUT, writer.write_all(data)).await??;
                timeout(DEFAULT_TIMEOUT, writer.flush_end_async()).await??;
            }
        }
        Ok(())
    }

    /// Read one complete response directly from the USB endpoint.
    async fn read_raw_from_usb(&mut self) -> Result<Vec<u8>, KMError> {
        let mut buffer = Vec::new();
        let bytes_read = match &mut self.reader {
            EndpointReaderType::Bulk(reader) => {
                // Bulk messages are delimited by a short USB packet. Reading through
                // this adapter preserves one complete protocol response even when it
                // is larger than either the caller's buffer or one 2048-byte transfer.
                let mut message = reader.until_short_packet();
                let bytes_read = timeout(DEFAULT_TIMEOUT, message.read_to_end(&mut buffer)).await??;
                message
                    .consume_end()
                    .map_err(|_| KMError::Protocol("Bulk response ended without a short packet".to_string()))?;
                bytes_read
            }
            EndpointReaderType::Interrupt(reader) => {
                buffer.resize(INTERRUPT_TRANSFER_SIZE, 0);
                let bytes_read = timeout(DEFAULT_TIMEOUT, reader.read(&mut buffer)).await??;
                buffer.truncate(bytes_read);
                bytes_read
            }
        };
        trace!("RX [{} bytes]: {:02x?}", bytes_read, buffer);
        Ok(buffer)
    }

    fn queue_pending_response(&mut self, response: Vec<u8>) {
        if self.pending_responses.len() == MAX_PENDING_RESPONSES {
            warn!("Dropping oldest unmatched response because the pending queue is full");
            self.pending_responses.pop_front();
        }
        self.pending_responses.push_back(response);
    }

    async fn receive_matching_raw<F>(&mut self, mut predicate: F) -> Result<Vec<u8>, KMError>
    where
        F: FnMut(&[u8]) -> bool,
    {
        if let Some(index) = self.pending_responses.iter().position(|response| predicate(response)) {
            return Ok(self
                .pending_responses
                .remove(index)
                .expect("pending response index is valid"));
        }

        let deadline = tokio::time::Instant::now() + DEFAULT_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(KMError::Protocol(
                    "Timed out waiting for a correlated response".to_string(),
                ));
            }

            let response = timeout(remaining, self.read_raw_from_usb()).await??;
            if predicate(&response) {
                return Ok(response);
            }

            if let Some(packet) = parse_framed_response(&response) {
                debug!(
                    "Queueing unmatched response: type={:?}, id={}, len={}",
                    packet.packet_type(),
                    packet.id(),
                    response.len()
                );
            } else {
                debug!("Queueing unframed response: len={}", response.len());
            }
            self.queue_pending_response(response);
        }
    }

    /// Receive raw bytes without transaction correlation.
    ///
    /// This is a low-level protocol-research API. Previously received
    /// out-of-order responses are returned first.
    pub async fn receive_raw(&mut self) -> Result<Vec<u8>, KMError> {
        if let Some(response) = self.pending_responses.pop_front() {
            return Ok(response);
        }
        self.read_raw_from_usb().await
    }

    fn parse_response(raw_bytes: Vec<u8>, graph_rate: Option<GraphSampleRate>) -> Result<Packet, KMError> {
        if raw_bytes.is_empty() {
            return Err(KMError::Protocol("Received 0 bytes".to_string()));
        }

        let raw_packet = RawPacket::try_from(Bytes::from(raw_bytes))?;
        if let Some(rate) = graph_rate {
            Packet::from_raw_with_graph_rate(raw_packet, rate)
        } else {
            Packet::try_from(raw_packet)
        }
    }

    /// Receive the next framed high-level packet without transaction correlation.
    ///
    /// Unframed transfers such as encrypted MemoryRead data cannot be parsed by
    /// this method. Use [`Self::read_memory_block`] for device memory reads.
    pub async fn receive(&mut self) -> Result<Packet, KMError> {
        let raw_bytes = self.receive_raw().await?;
        Self::parse_response(raw_bytes, self.graph_sample_rate)
    }

    async fn receive_control_response(&mut self, id: u8) -> Result<Packet, KMError> {
        let raw_bytes = self
            .receive_matching_raw(|bytes| control_response_matches(bytes, id))
            .await?;
        Self::parse_response(raw_bytes, self.graph_sample_rate)
    }

    async fn expect_accept(&mut self, id: u8, command: &str) -> Result<(), KMError> {
        match self.receive_control_response(id).await? {
            Packet::Accept { .. } => Ok(()),
            Packet::Reject { .. } => Err(KMError::Protocol(format!("{command} was rejected by the device"))),
            Packet::NotReadable { .. } => Err(KMError::Protocol(format!("{command} is not readable"))),
            other => Err(KMError::Protocol(format!(
                "Expected Accept for {command}, got {other:?}"
            ))),
        }
    }

    async fn receive_memory_read_data_exact(&mut self, requested_size: u32) -> Result<Vec<u8>, KMError> {
        let expected_size = memory_response_size(requested_size);
        if expected_size == 0 {
            return Ok(Vec::new());
        }

        let mut encrypted = Vec::with_capacity(expected_size);
        while encrypted.len() < expected_size {
            let chunk = self.read_raw_from_usb().await?;
            if append_memory_chunk(&mut encrypted, &chunk, expected_size)? {
                break;
            }
        }

        decrypt_memory_response(&encrypted, requested_size)
    }

    /// Request data with a specific attribute set
    pub async fn request_data(&mut self, mask: AttributeSet) -> Result<Packet, KMError> {
        let id = self
            .send_tracked(Packet::GetData {
                attribute_mask: mask.raw(),
            })
            .await?;
        let raw_bytes = self
            .receive_matching_raw(|bytes| response_matches(bytes, id, PacketType::PutData))
            .await?;
        let raw_packet = RawPacket::try_from(Bytes::from(raw_bytes))?;
        raw_packet.validate_correlation(mask.raw())?;
        if let Some(rate) = self.graph_sample_rate {
            Packet::from_raw_with_graph_rate(raw_packet, rate)
        } else {
            Packet::try_from(raw_packet)
        }
    }

    /// Request ADC data only
    pub async fn request_adc_data(&mut self) -> Result<AdcDataSimple, KMError> {
        let packet = self.request_data(AttributeSet::single(Attribute::Adc)).await?;
        packet
            .get_adc()
            .cloned()
            .ok_or_else(|| KMError::Protocol("No ADC data in response".to_string()))
    }

    /// Request metadata for the offline log currently selected on the device.
    ///
    /// Returns `None` when the device reports that no offline log is available.
    pub async fn request_log_metadata(&mut self) -> Result<Option<LogMetadata>, KMError> {
        let packet = self.request_data(AttributeSet::single(Attribute::LogMetadata)).await?;
        match packet.get_log_metadata() {
            Some(LogMetadataResponse::Empty) => Ok(None),
            Some(LogMetadataResponse::Available(metadata)) => Ok(Some(metadata.clone())),
            None => Err(KMError::Protocol("No LogMetadata data in response".to_string())),
        }
    }

    /// Download the offline samples described by previously requested metadata.
    pub async fn download_offline_log(&mut self, metadata: LogMetadata) -> Result<OfflineLog, KMError> {
        let data = self
            .read_memory_block(OFFLINE_LOG_ADDRESS, metadata.data_size())
            .await?;
        OfflineLog::from_bytes(metadata, &data)
    }

    /// Request metadata and download the selected offline log.
    ///
    /// Returns `None` when no offline log is available.
    pub async fn read_offline_log(&mut self) -> Result<Option<OfflineLog>, KMError> {
        let Some(metadata) = self.request_log_metadata().await? else {
            return Ok(None);
        };
        self.download_offline_log(metadata).await.map(Some)
    }

    /// Request PD data (returns full packet as it can contain PdStatus OR PdEventStream)
    ///
    /// The response depends on the device state:
    /// - If payload is 12 bytes: returns PdStatus (use packet.get_pd_status())
    /// - If payload > 12 bytes: returns PdEventStream (use packet.get_pd_events())
    ///
    /// Use `request_adc_with_pd()` to get ADC + PdStatus together (68 bytes).
    pub async fn request_pd_data(&mut self) -> Result<Packet, KMError> {
        self.request_data(AttributeSet::single(Attribute::PdPacket)).await
    }

    /// Request both ADC and PD data in a single request
    ///
    /// This typically returns ADC + PdStatus (68 bytes total).
    /// Use packet.get_adc() and packet.get_pd_status() to extract data.
    pub async fn request_adc_with_pd(&mut self) -> Result<Packet, KMError> {
        let mask = AttributeSet::single(Attribute::Adc).with(Attribute::PdPacket);
        self.request_data(mask).await
    }

    /// Helper: Try to get PD status from a packet
    ///
    /// Returns Some if the packet contains PdStatus (12-byte payload),
    /// None otherwise. Useful after request_pd_data() or request_adc_with_pd().
    pub fn extract_pd_status(packet: &Packet) -> Option<&PdStatus> {
        packet.get_pd_status()
    }

    /// Helper: Try to get PD event stream from a packet
    ///
    /// Returns Some if the packet contains PdEventStream (>12 bytes),
    /// None otherwise. Useful after request_pd_data().
    pub fn extract_pd_events(packet: &Packet) -> Option<&PdEventStream> {
        packet.get_pd_events()
    }

    /// Enable PD monitor/sniffer
    ///
    /// Sends the EnablePdMonitor command (0x10) to start capturing PD events.
    /// This may be required before `request_pd_data()` returns PD events,
    /// especially in Basic mode (HID interface).
    ///
    /// Returns Ok(()) on Accept, error otherwise.
    pub async fn enable_pd_monitor(&mut self) -> Result<(), KMError> {
        let id = self.send_tracked(Packet::EnablePdMonitor).await?;
        self.expect_accept(id, "EnablePdMonitor").await
    }

    /// Disable PD monitor/sniffer
    ///
    /// Sends the DisablePdMonitor command (0x11) to stop capturing PD events.
    ///
    /// Returns Ok(()) on Accept, error otherwise.
    pub async fn disable_pd_monitor(&mut self) -> Result<(), KMError> {
        let id = self.send_tracked(Packet::DisablePdMonitor).await?;
        self.expect_accept(id, "DisablePdMonitor").await
    }

    /// Internal: Run initialization sequence for vendor interface (Full mode)
    ///
    /// Performs the full initialization sequence:
    /// 1. Connect to device
    /// 2. Read DeviceInfo (0x420)
    /// 3. Read FirmwareInfo (0x4420)
    /// 4. Read Calibration (0x3000C00)
    /// 5. Read HardwareID (0x40010450)
    /// 6. StreamingAuth (authenticate for AdcQueue)
    ///
    /// After successful init, mode is set to Full(DeviceState).
    async fn run_init(&mut self) -> Result<(), KMError> {
        use crate::auth::{HARDWARE_ID_ADDRESS, HARDWARE_ID_SIZE};

        // 1. Connect (with retries - sometimes device responds with Disconnect on first try)
        const MAX_CONNECT_RETRIES: u8 = 3;
        let mut last_error = None;
        for attempt in 1..=MAX_CONNECT_RETRIES {
            match self.send_tracked(Packet::Connect).await {
                Err(err) => last_error = Some(format!("Connect send failed: {err:?}")),
                Ok(id) => match self.expect_accept(id, "Connect").await {
                    Ok(()) => {
                        last_error = None;
                        break;
                    }
                    Err(err) => last_error = Some(format!("Connect receive failed: {err:?}")),
                },
            }
            if attempt < MAX_CONNECT_RETRIES {
                debug!("Connect attempt {} failed, retrying...", attempt);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        if let Some(err) = last_error {
            return Err(KMError::Protocol(err));
        }

        let info = self.read_device_info_blocks().await;
        let mut hardware_id_bytes = [0u8; HARDWARE_ID_SIZE];

        // 5. Read HardwareID
        let hardware_id = if let Ok(data) = self
            .read_memory_block(HARDWARE_ID_ADDRESS, HARDWARE_ID_SIZE as u32)
            .await
        {
            if data.len() >= HARDWARE_ID_SIZE {
                hardware_id_bytes.copy_from_slice(&data[..HARDWARE_ID_SIZE]);
            }
            HardwareId::from_bytes(hardware_id_bytes)
        } else {
            return Err(KMError::Protocol(
                "Failed to read HardwareID - required for authentication".to_string(),
            ));
        };

        // 6. StreamingAuth
        self.send_tracked(Packet::StreamingAuth {
            hardware_id: hardware_id.clone(),
        })
        .await?;
        let auth_response = self
            // StreamingAuth is the documented exception to normal transaction
            // correlation: captured device responses always carry ID 0.
            .receive_matching_raw(|bytes| response_type_matches(bytes, PacketType::StreamingAuth))
            .await?;

        let auth = match Self::parse_response(auth_response, self.graph_sample_rate)? {
            Packet::StreamingAuthResponse(result) => result,
            other => {
                return Err(KMError::Protocol(format!(
                    "Expected StreamingAuthResponse, got {:?}",
                    other
                )));
            }
        };

        // Store device state in Full mode
        let state = DeviceState {
            info,
            hardware_id,
            auth_level: auth.auth_level,
            adcqueue_enabled: auth.adcqueue_enabled(),
        };

        info!("Device initialized: {} (auth_level={})", state.model(), auth.auth_level);

        self.mode = ConnectionMode::Full(state);

        Ok(())
    }

    /// Get the current connection mode
    ///
    /// - `ConnectionMode::Basic` - HID interface, ADC/PD polling only
    /// - `ConnectionMode::Full(state)` - Vendor interface, all features
    pub fn mode(&self) -> &ConnectionMode {
        &self.mode
    }

    /// Check if device is in full mode (vendor interface)
    pub fn is_full_mode(&self) -> bool {
        matches!(self.mode, ConnectionMode::Full(_))
    }

    /// Check if device is in basic mode (HID interface)
    pub fn is_basic_mode(&self) -> bool {
        matches!(self.mode, ConnectionMode::Basic)
    }

    /// Get device state (only available in Full mode)
    ///
    /// Returns `Some` when connected via vendor interface (Full mode).
    /// Returns `None` when connected via HID interface (Basic mode).
    pub fn state(&self) -> Option<&DeviceState> {
        match &self.mode {
            ConnectionMode::Full(state) => Some(state),
            ConnectionMode::Basic => None,
        }
    }

    /// Check if device is authenticated (Full mode only)
    ///
    /// Returns `false` in Basic mode or if authentication failed.
    pub fn is_authenticated(&self) -> bool {
        self.state().map(|s| s.is_authenticated()).unwrap_or(false)
    }

    /// Check if AdcQueue streaming is enabled (Full mode only)
    ///
    /// Returns `false` in Basic mode or if not authenticated for streaming.
    pub fn adcqueue_enabled(&self) -> bool {
        self.state().map(|s| s.adcqueue_enabled).unwrap_or(false)
    }

    /// Read an encrypted memory block from the device
    ///
    /// Sends a MemoryRead request, receives the confirmation, then receives
    /// and decrypts the actual data. Returns exactly `size` decrypted bytes;
    /// AES block padding received from the device is removed.
    pub async fn read_memory_block(&mut self, address: u32, size: u32) -> Result<Vec<u8>, KMError> {
        let id = self.send_tracked(Packet::MemoryRead { address, size }).await?;
        let confirmation = self
            .receive_matching_raw(|bytes| memory_confirmation_matches(bytes, id))
            .await?;

        let confirmation = RawPacket::try_from(Bytes::from(confirmation))?;
        match confirmation.packet_type() {
            PacketType::MemoryRead => {
                validate_memory_read_confirmation(&confirmation, id, address, size)?;
                self.receive_memory_read_data_exact(size).await
            }
            PacketType::Rejected => Err(KMError::Protocol(format!("MemoryRead at 0x{address:08X} was rejected"))),
            PacketType::NotReadable => Err(KMError::Protocol(format!(
                "Memory address 0x{address:08X} is not readable"
            ))),
            other => Err(KMError::Protocol(format!(
                "Expected MemoryRead confirmation, got {other:?}"
            ))),
        }
    }

    /// Read device information from memory
    ///
    /// Reads and parses:
    /// - DeviceInfo1 (0x420): model, hw_version, mfg_date
    /// - FirmwareInfo (0x4420): fw_version, fw_date
    /// - CalibrationData (0x3000C00): serial_id, uuid
    ///
    /// **Note:** Requires Connect to be sent first. Only works in Full mode.
    /// When using `DeviceConfig::vendor()`, this info is already available via `state()`.
    ///
    /// # Example
    /// ```no_run
    /// # use km003c_lib::{KM003C, DeviceConfig};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // In Full mode, device info is already available
    /// let device = KM003C::new(DeviceConfig::vendor()).await?;
    /// println!("Model: {}", device.state().unwrap().model());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_device_info(&mut self) -> Result<crate::auth::DeviceInfo, KMError> {
        Ok(self.read_device_info_blocks().await)
    }

    /// Internal: Read DeviceInfo, FirmwareInfo, and CalibrationData blocks
    ///
    /// Used by both `run_init()` and `get_device_info()`. Non-critical reads
    /// are logged as warnings on failure but don't prevent initialization.
    async fn read_device_info_blocks(&mut self) -> crate::auth::DeviceInfo {
        use crate::auth::{
            CALIBRATION_ADDRESS, DEVICE_INFO_ADDRESS, DeviceInfo, FIRMWARE_INFO_ADDRESS, INFO_BLOCK_SIZE,
        };
        use tracing::warn;

        let mut info = DeviceInfo::default();

        match self
            .read_memory_block(DEVICE_INFO_ADDRESS, INFO_BLOCK_SIZE as u32)
            .await
        {
            Ok(data) => info.parse_device_info(&data),
            Err(e) => warn!("Failed to read DeviceInfo at 0x{:08X}: {}", DEVICE_INFO_ADDRESS, e),
        }

        match self
            .read_memory_block(FIRMWARE_INFO_ADDRESS, INFO_BLOCK_SIZE as u32)
            .await
        {
            Ok(data) => info.parse_firmware_info(&data),
            Err(e) => warn!("Failed to read FirmwareInfo at 0x{:08X}: {}", FIRMWARE_INFO_ADDRESS, e),
        }

        match self
            .read_memory_block(CALIBRATION_ADDRESS, INFO_BLOCK_SIZE as u32)
            .await
        {
            Ok(data) => info.parse_calibration(&data),
            Err(e) => warn!("Failed to read CalibrationData at 0x{:08X}: {}", CALIBRATION_ADDRESS, e),
        }

        info
    }

    /// Start AdcQueue graph/streaming mode with specified sample rate
    ///
    /// # Arguments
    /// * `rate` - Sample rate (use GraphSampleRate enum)
    ///
    /// **Requires Full mode** (vendor interface) and successful StreamingAuth.
    ///
    /// Rate values:
    /// - `GraphSampleRate::Sps2` = 2 samples per second
    /// - `GraphSampleRate::Sps10` = 10 SPS
    /// - `GraphSampleRate::Sps50` = 50 SPS
    /// - `GraphSampleRate::Sps1000` = 1000 SPS
    ///
    /// After calling this, poll with `request_data(AttributeSet::single(Attribute::AdcQueue))`
    /// to receive buffered samples.
    ///
    /// # Example
    /// ```no_run
    /// # use km003c_lib::{KM003C, DeviceConfig, GraphSampleRate};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut device = KM003C::new(DeviceConfig::vendor()).await?;
    ///
    /// // Start 1000 SPS streaming
    /// device.start_graph_mode(GraphSampleRate::Sps1000).await?;
    ///
    /// // Poll for data...
    ///
    /// // Stop when done
    /// device.stop_graph_mode().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn start_graph_mode(&mut self, rate: GraphSampleRate) -> Result<(), KMError> {
        ensure_adcqueue_available(&self.mode)?;

        // Device expects rate index directly: 0=2SPS, 1=10SPS, 2=50SPS, 3=1000SPS
        let id = self
            .send_tracked(Packet::StartGraph {
                rate_index: rate as u16,
            })
            .await?;
        self.expect_accept(id, "StartGraph").await?;
        self.graph_sample_rate = Some(rate);
        Ok(())
    }

    /// Stop AdcQueue graph/streaming mode
    ///
    /// **Requires Full mode** (vendor interface). Will return error in Basic mode.
    ///
    /// Returns device to normal ADC polling mode.
    pub async fn stop_graph_mode(&mut self) -> Result<(), KMError> {
        if self.is_basic_mode() {
            return Err(KMError::Protocol(
                "AdcQueue streaming requires Full mode (vendor interface)".to_string(),
            ));
        }

        let id = self.send_tracked(Packet::StopGraph).await?;
        self.expect_accept(id, "StopGraph").await?;
        self.graph_sample_rate = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_matching_uses_the_typed_header_parser() {
        assert!(response_matches(&[0xc1, 7, 0, 0], 7, PacketType::PutData));
    }

    #[test]
    fn graph_mode_requires_streaming_auth_permission() {
        assert!(ensure_adcqueue_available(&ConnectionMode::Basic).is_err());

        let state = DeviceState {
            info: DeviceInfo::default(),
            hardware_id: HardwareId::from_bytes([0; 12]),
            auth_level: 0,
            adcqueue_enabled: false,
        };
        assert!(ensure_adcqueue_available(&ConnectionMode::Full(state.clone())).is_err());

        let enabled = DeviceState {
            auth_level: 1,
            adcqueue_enabled: true,
            ..state
        };
        assert!(ensure_adcqueue_available(&ConnectionMode::Full(enabled)).is_ok());
    }

    #[test]
    fn response_matching_requires_type_and_transaction_id() {
        assert!(!response_matches(&[0xc1, 8, 0, 0], 7, PacketType::PutData));
        assert!(!response_matches(&[0xc0, 7, 0, 0], 7, PacketType::PutData));
        assert!(!response_matches(&[0xc1], 7, PacketType::PutData));
    }

    #[test]
    fn response_type_matching_supports_fixed_id_protocol_exceptions() {
        assert!(response_type_matches(&[0x4c, 0, 3, 2], PacketType::StreamingAuth));
    }

    #[test]
    fn memory_response_size_rounds_to_complete_aes_blocks() {
        assert_eq!(memory_response_size(1), 16);
        assert_eq!(memory_response_size(12), 16);
        assert_eq!(memory_response_size(16), 16);
        assert_eq!(memory_response_size(17), 32);
        assert_eq!(memory_response_size(64), 64);
    }

    #[test]
    fn decrypted_memory_response_is_trimmed_to_the_requested_size() {
        let ciphertext = crate::auth::build_memory_read_payload(0x4001_0450, 12);
        let decrypted = decrypt_memory_response(&ciphertext[..16], 12).unwrap();

        assert_eq!(decrypted.len(), 12);
        assert_eq!(&decrypted[..4], &0x4001_0450_u32.to_le_bytes());
        assert_eq!(&decrypted[4..8], &12_u32.to_le_bytes());
        assert_eq!(&decrypted[8..12], &u32::MAX.to_le_bytes());
    }

    #[test]
    fn decrypted_memory_response_rejects_an_incorrect_ciphertext_size() {
        assert!(decrypt_memory_response(&[0; 32], 12).is_err());
    }

    #[test]
    fn memory_chunks_accumulate_across_usb_transfers() {
        // Source: reading_logs0.11; a requested 8336-byte log arrived as
        // three 2544-byte USB transfers followed by one 704-byte transfer.
        let mut response = Vec::new();
        assert!(!append_memory_chunk(&mut response, &vec![0x11; 2544], 8336).unwrap());
        assert!(!append_memory_chunk(&mut response, &vec![0x22; 2544], 8336).unwrap());
        assert!(!append_memory_chunk(&mut response, &vec![0x33; 2544], 8336).unwrap());
        assert!(append_memory_chunk(&mut response, &vec![0x44; 704], 8336).unwrap());
        assert_eq!(response.len(), 8336);
    }

    #[test]
    fn memory_chunks_reject_empty_and_oversized_transfers() {
        let mut response = vec![0; 15];
        assert!(append_memory_chunk(&mut response, &[], 16).is_err());
        assert!(append_memory_chunk(&mut response, &[1, 2], 16).is_err());
    }

    #[test]
    fn validates_recorded_memory_read_confirmation() {
        // Source: usb_master_dataset.parquet, orig_adc_1000hz.6, frame 264.
        let bytes = hex::decode("c40201012004000040000000ffffffff1b8c1b24").unwrap();
        let packet = RawPacket::try_from(Bytes::from(bytes)).unwrap();

        validate_memory_read_confirmation(&packet, 2, 0x420, 64).unwrap();
    }

    #[test]
    fn rejects_corrupted_memory_read_confirmation() {
        let mut bytes = hex::decode("c40201012004000040000000ffffffff1b8c1b24").unwrap();
        bytes[8] ^= 1;
        let packet = RawPacket::try_from(Bytes::from(bytes)).unwrap();

        assert!(validate_memory_read_confirmation(&packet, 2, 0x420, 64).is_err());
    }
}
