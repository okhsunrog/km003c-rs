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
use crate::error::KMError;
use crate::message::Packet;
use crate::packet::{Attribute, AttributeSet, RawPacket};
use crate::pd::{PdEventStream, PdStatus};
use bytes::Bytes;
use nusb::Interface;
use nusb::io::{EndpointRead, EndpointWrite};
use nusb::transfer::{Bulk, Interrupt};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::{debug, info, trace};

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

/// Configuration for KM003C device communication
///
/// Specifies which USB interface and endpoints to use for communication.
/// The KM003C has multiple interfaces with different performance characteristics.
///
/// # Examples
///
/// ```no_run
/// use km003c_lib::{KM003C, DeviceConfig};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Use HID interface (most compatible, ~3.8ms latency)
/// let device = KM003C::new().await?;
///
/// // Use Vendor interface (fastest, ~0.6ms latency, 6x faster)
/// let device = KM003C::with_config(DeviceConfig::vendor_interface()).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct DeviceConfig {
    /// USB interface number (0-3)
    pub interface: u8,
    /// OUT endpoint address
    pub endpoint_out: u8,
    /// IN endpoint address
    pub endpoint_in: u8,
    /// Transfer type (Bulk or Interrupt)
    pub transfer_type: TransferType,
    /// Skip initial USB reset (for compatibility with some systems/OSes)
    pub skip_reset: bool,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        // Use HID interface by default (more compatible, ~3.8ms latency)
        Self {
            interface: INTERFACE_HID,
            endpoint_out: ENDPOINT_OUT_HID,
            endpoint_in: ENDPOINT_IN_HID,
            transfer_type: TransferType::Interrupt,
            skip_reset: false,
        }
    }
}

impl DeviceConfig {
    /// Use vendor-specific interface (Interface 0) with Bulk transfers
    ///
    /// This is the **fastest option** with ~0.6ms latency (6x faster than HID).
    /// Uses the same interface as the Linux kernel `powerz` driver.
    ///
    /// **Specifications** (official):
    /// - Throughput: ~200 KB/s
    /// - Endpoints: 0x01 OUT, 0x81 IN (Bulk)
    ///
    /// **Measured performance**:
    /// - Latency: ~600 µs per request
    /// - Best for high-frequency polling and performance-critical applications
    ///
    /// **Note**: On Linux, requires detaching the `powerz` kernel driver,
    /// which this library handles automatically.
    pub fn vendor_interface() -> Self {
        Self {
            interface: INTERFACE_VENDOR,
            endpoint_out: ENDPOINT_OUT_VENDOR,
            endpoint_in: ENDPOINT_IN_VENDOR,
            transfer_type: TransferType::Bulk,
            skip_reset: false,
        }
    }

    /// Use HID interface (Interface 3) with Interrupt transfers
    ///
    /// This is the **most compatible option** that works on all platforms
    /// without installing custom drivers. Slightly slower than Interface 0.
    ///
    /// **Specifications** (official):
    /// - Throughput: ~60 KB/s
    /// - Endpoints: 0x05 OUT, 0x85 IN (Interrupt)
    ///
    /// **Measured performance**:
    /// - Latency: ~3.8 ms per request
    /// - Good for standard monitoring applications
    ///
    /// **Advantages**:
    /// - Works without driver installation on Windows/Mac/Linux
    /// - Uses standard HID protocol
    /// - No permission issues
    pub fn hid_interface() -> Self {
        Self::default()
    }

    /// Skip USB reset during initialization (for MacOS compatibility)
    ///
    /// Some systems (particularly MacOS) may have issues with USB reset.
    /// Use this option if device initialization fails with reset errors.
    pub fn with_skip_reset(mut self) -> Self {
        self.skip_reset = true;
        self
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
}

impl KM003C {
    /// Create a new KM003C instance using HID interface (Interface 3, no kernel driver detach)
    pub async fn new() -> Result<Self, KMError> {
        Self::with_config(DeviceConfig::default()).await
    }

    /// Create a new KM003C instance with custom configuration
    pub async fn with_config(config: DeviceConfig) -> Result<Self, KMError> {
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
        };

        // Device is ready - no Connect command needed
        // (kernel driver and other implementations start directly with GetData)
        info!("Device ready");

        Ok(km003c)
    }

    /// Get the next transaction ID
    fn next_transaction_id(&mut self) -> u8 {
        let id = self.transaction_id;
        self.transaction_id = self.transaction_id.wrapping_add(1);
        id
    }

    /// Set the transaction ID counter (for protocol research/sync purposes)
    pub fn set_transaction_id(&mut self, id: u8) {
        self.transaction_id = id;
    }

    /// Send a high-level packet to the device
    pub async fn send(&mut self, packet: Packet) -> Result<(), KMError> {
        let id = self.next_transaction_id();
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
        trace!("Sending {} bytes: {:02x?}", message.len(), message);

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
        Ok(buffer)
    }

    /// Receive a high-level packet from the device
    pub async fn receive(&mut self) -> Result<Packet, KMError> {
        let raw_packet = self.receive_raw_packet().await?;
        Packet::try_from(raw_packet)
    }

    /// Receive a raw packet from the device
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

    /// Start AdcQueue graph/streaming mode with specified sample rate
    ///
    /// # Arguments
    /// * `rate` - Sample rate (use GraphSampleRate enum)
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
    /// # use km003c_lib::{KM003C, GraphSampleRate};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut device = KM003C::new().await?;
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
        // Device uses bits 1-2 of the rate byte as selector, so multiply by 2
        self.send(Packet::StartGraph {
            rate_index: (rate as u16) * 2,
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
    /// Returns device to normal ADC polling mode.
    pub async fn stop_graph_mode(&mut self) -> Result<(), KMError> {
        self.send(Packet::StopGraph).await?;

        // Wait for Accept
        match self.receive().await? {
            Packet::Accept { .. } => Ok(()),
            other => Err(KMError::Protocol(format!("Expected Accept response, got {:?}", other))),
        }
    }
}
