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
use crate::packet::{Attribute, AttributeSet, RawPacket};
use crate::pd::{PdEventStream, PdStatus};
use bytes::Bytes;
use nusb::Interface;
use nusb::io::{EndpointRead, EndpointWrite};
use nusb::transfer::{Bulk, Interrupt};
use std::fmt;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::{debug, info, trace};

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
    #[allow(dead_code)]
    interface: Interface,
    transaction_id: u8,
    #[allow(dead_code)]
    config: DeviceConfig,
    reader: EndpointReaderType,
    writer: EndpointWriterType,
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
    /// let device = KM003C::new(DeviceConfig::hid()).await?;
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

        let device = device_info.open().await?;

        // Optionally reset device (skip on MacOS if having issues)
        if !config.skip_reset {
            info!("Resetting device...");
            device.reset().await?;
            // CRITICAL: Device needs 1.5 seconds to fully initialize after reset
            // (validated through protocol research - 100ms is insufficient for AdcQueue)
            tokio::time::sleep(Duration::from_millis(1500)).await;
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
        // Buffer size of 2048 bytes to handle large AdcQueue responses (up to ~1300 bytes)
        let (reader, writer) = match config.transfer_type {
            TransferType::Bulk => {
                let ep_in = interface.endpoint::<Bulk, _>(config.endpoint_in)?;
                let ep_out = interface.endpoint::<Bulk, _>(config.endpoint_out)?;
                (
                    EndpointReaderType::Bulk(ep_in.reader(2048).with_num_transfers(4)),
                    EndpointWriterType::Bulk(ep_out.writer(64).with_num_transfers(4)),
                )
            }
            TransferType::Interrupt => {
                let ep_in = interface.endpoint::<Interrupt, _>(config.endpoint_in)?;
                let ep_out = interface.endpoint::<Interrupt, _>(config.endpoint_out)?;
                (
                    EndpointReaderType::Interrupt(ep_in.reader(64).with_num_transfers(4)),
                    EndpointWriterType::Interrupt(ep_out.writer(64).with_num_transfers(4)),
                )
            }
        };

        let km003c = Self {
            interface,
            transaction_id: 0,
            config,
            reader,
            writer,
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

    /// Send a high-level packet to the device
    pub async fn send(&mut self, packet: Packet) -> Result<(), KMError> {
        use crate::auth;

        let id = self.next_transaction_id();

        // Special handling for auth packets that need custom wire format
        // (MemoryRead and StreamingAuth use a different header layout than standard packets)
        match &packet {
            Packet::MemoryRead { address, size } => {
                let raw = auth::build_memory_read_packet(*address, *size, id);
                return self.send_raw(&raw).await;
            }
            Packet::StreamingAuth { hardware_id } => {
                let raw = auth::build_streaming_auth_packet(hardware_id, id);
                return self.send_raw(&raw).await;
            }
            _ => {}
        }

        let raw_packet = packet.to_raw_packet(id);
        self.send_raw_packet(raw_packet).await
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

    /// Receive raw bytes from the device (for protocol research/testing)
    pub async fn receive_raw(&mut self) -> Result<Vec<u8>, KMError> {
        let mut buffer = vec![0u8; 1024];
        let bytes_read = match &mut self.reader {
            EndpointReaderType::Bulk(reader) => timeout(DEFAULT_TIMEOUT, reader.read(&mut buffer)).await??,
            EndpointReaderType::Interrupt(reader) => timeout(DEFAULT_TIMEOUT, reader.read(&mut buffer)).await??,
        };
        buffer.truncate(bytes_read);
        trace!("RX [{} bytes]: {:02x?}", bytes_read, buffer);
        Ok(buffer)
    }

    /// Receive a high-level packet from the device
    pub async fn receive(&mut self) -> Result<Packet, KMError> {
        // First get raw bytes to check for special packet formats
        let raw_bytes = self.receive_raw().await?;

        if raw_bytes.is_empty() {
            return Err(KMError::Protocol("Received 0 bytes".to_string()));
        }

        let packet_type = raw_bytes[0] & 0x7F;

        // Special handling for StreamingAuth response (0x4C with high bit = 0xCC)
        // Format: [type:1][id:1][attr:2][encrypted_payload:32]
        if packet_type == 0x4C
            && raw_bytes.len() >= 36
            && let Some(result) = crate::auth::parse_streaming_auth_response(&raw_bytes)
        {
            return Ok(Packet::StreamingAuthResponse(result));
        }

        // Standard packet parsing
        let bytes = Bytes::copy_from_slice(&raw_bytes);
        let raw_packet = RawPacket::try_from(bytes)?;
        Packet::try_from(raw_packet)
    }

    /// Receive encrypted MemoryRead response data
    ///
    /// After sending a MemoryRead request and receiving the confirmation (0xC4),
    /// the actual data comes as raw encrypted AES blocks. This method
    /// receives and decrypts that data.
    ///
    /// Response size is rounded up to 16-byte boundary (AES block size):
    /// - 12-byte request → 16-byte response
    /// - 64-byte request → 64-byte response (4 blocks)
    pub async fn receive_memory_read_data(&mut self) -> Result<Packet, KMError> {
        let raw_bytes = self.receive_raw().await?;

        // Response must be multiple of 16 bytes (AES block size)
        if raw_bytes.is_empty() || raw_bytes.len() % 16 != 0 {
            return Err(KMError::Protocol(format!(
                "Expected encrypted data (multiple of 16 bytes), got {} bytes",
                raw_bytes.len()
            )));
        }

        // Decrypt all blocks with MEMORY_READ_KEY
        let decrypted = crate::auth::aes_ecb_decrypt_blocks(&raw_bytes, crate::auth::MEMORY_READ_KEY);

        Ok(Packet::MemoryReadResponse { data: decrypted })
    }

    /// Receive a raw packet from the device
    #[allow(dead_code)]
    async fn receive_raw_packet(&mut self) -> Result<RawPacket, KMError> {
        let mut buffer = vec![0u8; 1024];

        // Use the persistent reader
        let bytes_read = match &mut self.reader {
            EndpointReaderType::Bulk(reader) => timeout(DEFAULT_TIMEOUT, reader.read(&mut buffer)).await??,
            EndpointReaderType::Interrupt(reader) => timeout(DEFAULT_TIMEOUT, reader.read(&mut buffer)).await??,
        };

        if bytes_read == 0 {
            return Err(KMError::Protocol("Received 0 bytes".to_string()));
        }

        let raw_bytes = &buffer[..bytes_read];
        trace!("Received {} bytes: {:02x?}", bytes_read, raw_bytes);

        let bytes = Bytes::copy_from_slice(raw_bytes);
        let raw_packet = RawPacket::try_from(bytes)?;

        let (reserved_flag, has_logical_packets) = match &raw_packet {
            RawPacket::Ctrl { header, .. } => (header.reserved_flag(), false),
            RawPacket::SimpleData { header, .. } => (header.reserved_flag(), false),
            RawPacket::Data {
                header,
                logical_packets,
            } => (header.reserved_flag(), !logical_packets.is_empty()),
        };

        debug!(
            "Parsed packet: type={:?}, reserved_flag={}, has_logical_packets={}, id={}, is_empty={}",
            raw_packet.packet_type(),
            reserved_flag,
            has_logical_packets,
            raw_packet.id(),
            raw_packet.is_empty_response(),
        );

        // Log if we received an empty response (device has no data)
        if raw_packet.is_empty_response() {
            debug!("Received empty PutData response (obj_count_words=0) - device has no data");
        }

        Ok(raw_packet)
    }

    /// Request data with a specific attribute set
    pub async fn request_data(&mut self, mask: AttributeSet) -> Result<Packet, KMError> {
        self.send(Packet::GetData {
            attribute_mask: mask.raw(),
        })
        .await?;
        let packet = self.receive().await?;

        // TODO: Could validate correlation here if we stored the request mask
        // packet.validate_correlation(mask)?;

        Ok(packet)
    }

    /// Request ADC data only
    pub async fn request_adc_data(&mut self) -> Result<AdcDataSimple, KMError> {
        let packet = self.request_data(AttributeSet::single(Attribute::Adc)).await?;
        packet
            .get_adc()
            .cloned()
            .ok_or_else(|| KMError::Protocol("No ADC data in response".to_string()))
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
        self.send(Packet::EnablePdMonitor).await?;
        match self.receive().await? {
            Packet::Accept { .. } => Ok(()),
            other => Err(KMError::Protocol(format!(
                "Expected Accept for EnablePdMonitor, got {:?}",
                other
            ))),
        }
    }

    /// Disable PD monitor/sniffer
    ///
    /// Sends the DisablePdMonitor command (0x11) to stop capturing PD events.
    ///
    /// Returns Ok(()) on Accept, error otherwise.
    pub async fn disable_pd_monitor(&mut self) -> Result<(), KMError> {
        self.send(Packet::DisablePdMonitor).await?;
        match self.receive().await? {
            Packet::Accept { .. } => Ok(()),
            other => Err(KMError::Protocol(format!(
                "Expected Accept for DisablePdMonitor, got {:?}",
                other
            ))),
        }
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
        use crate::auth::{
            CALIBRATION_ADDRESS, DEVICE_INFO_ADDRESS, FIRMWARE_INFO_ADDRESS, HARDWARE_ID_ADDRESS, HARDWARE_ID_SIZE,
            INFO_BLOCK_SIZE,
        };

        // 1. Connect (with retries - sometimes device responds with Disconnect on first try)
        const MAX_CONNECT_RETRIES: u8 = 3;
        let mut last_error = None;
        for attempt in 1..=MAX_CONNECT_RETRIES {
            self.send(Packet::Connect).await?;
            match self.receive().await? {
                Packet::Accept { .. } => {
                    last_error = None;
                    break;
                }
                other => {
                    last_error = Some(format!("Expected Accept for Connect, got {:?}", other));
                    if attempt < MAX_CONNECT_RETRIES {
                        debug!("Connect attempt {} failed, retrying...", attempt);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
        if let Some(err) = last_error {
            return Err(KMError::Protocol(err));
        }

        let mut info = DeviceInfo::default();
        let mut hardware_id_bytes = [0u8; HARDWARE_ID_SIZE];

        // Helper to read memory block
        async fn read_block(device: &mut KM003C, address: u32, size: u32) -> Result<Vec<u8>, KMError> {
            device.send(Packet::MemoryRead { address, size }).await?;
            device.receive().await?; // confirmation
            match device.receive_memory_read_data().await? {
                Packet::MemoryReadResponse { data } => Ok(data),
                other => Err(KMError::Protocol(format!(
                    "Expected MemoryReadResponse, got {:?}",
                    other
                ))),
            }
        }

        // 2. Read DeviceInfo
        if let Ok(data) = read_block(self, DEVICE_INFO_ADDRESS, INFO_BLOCK_SIZE as u32).await {
            info.parse_device_info(&data);
        }

        // 3. Read FirmwareInfo
        if let Ok(data) = read_block(self, FIRMWARE_INFO_ADDRESS, INFO_BLOCK_SIZE as u32).await {
            info.parse_firmware_info(&data);
        }

        // 4. Read Calibration
        if let Ok(data) = read_block(self, CALIBRATION_ADDRESS, INFO_BLOCK_SIZE as u32).await {
            info.parse_calibration(&data);
        }

        // 5. Read HardwareID
        let hardware_id = if let Ok(data) = read_block(self, HARDWARE_ID_ADDRESS, HARDWARE_ID_SIZE as u32).await {
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
        self.send(Packet::StreamingAuth {
            hardware_id: hardware_id.clone(),
        })
        .await?;

        let auth = match self.receive().await? {
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
        use crate::auth::{
            CALIBRATION_ADDRESS, DEVICE_INFO_ADDRESS, DeviceInfo, FIRMWARE_INFO_ADDRESS, INFO_BLOCK_SIZE,
        };

        let mut info = DeviceInfo::default();

        // Helper to read memory block
        async fn read_block(device: &mut KM003C, address: u32, size: u32) -> Result<Vec<u8>, KMError> {
            device.send(Packet::MemoryRead { address, size }).await?;
            device.receive().await?; // confirmation
            match device.receive_memory_read_data().await? {
                Packet::MemoryReadResponse { data } => Ok(data),
                other => Err(KMError::Protocol(format!(
                    "Expected MemoryReadResponse, got {:?}",
                    other
                ))),
            }
        }

        // Read DeviceInfo1
        if let Ok(data) = read_block(self, DEVICE_INFO_ADDRESS, INFO_BLOCK_SIZE as u32).await {
            info.parse_device_info(&data);
        }

        // Read FirmwareInfo
        if let Ok(data) = read_block(self, FIRMWARE_INFO_ADDRESS, INFO_BLOCK_SIZE as u32).await {
            info.parse_firmware_info(&data);
        }

        // Read CalibrationData
        if let Ok(data) = read_block(self, CALIBRATION_ADDRESS, INFO_BLOCK_SIZE as u32).await {
            info.parse_calibration(&data);
        }

        Ok(info)
    }

    /// Start AdcQueue graph/streaming mode with specified sample rate
    ///
    /// # Arguments
    /// * `rate` - Sample rate (use GraphSampleRate enum)
    ///
    /// **Requires Full mode** (vendor interface). Will return error in Basic mode.
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
        if self.is_basic_mode() {
            return Err(KMError::Protocol(
                "AdcQueue streaming requires Full mode (vendor interface)".to_string(),
            ));
        }

        // Device expects rate index directly: 0=2SPS, 1=10SPS, 2=50SPS, 3=1000SPS
        self.send(Packet::StartGraph {
            rate_index: rate as u16,
        })
        .await?;

        // Wait for Accept
        match self.receive().await? {
            Packet::Accept { .. } => Ok(()),
            other => Err(KMError::Protocol(format!("Expected Accept response, got {:?}", other))),
        }
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

        self.send(Packet::StopGraph).await?;

        // Wait for Accept
        match self.receive().await? {
            Packet::Accept { .. } => Ok(()),
            other => Err(KMError::Protocol(format!("Expected Accept response, got {:?}", other))),
        }
    }
}
