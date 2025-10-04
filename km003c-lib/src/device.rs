use crate::adc::AdcDataSimple;
use crate::error::KMError;
use crate::message::Packet;
use crate::packet::{Attribute, AttributeSet, RawPacket};
use crate::pd::{PdEventStream, PdStatus};
use bytes::Bytes;
use nusb::Interface;
use nusb::transfer::{Bulk, Interrupt};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::{debug, info, trace};

// Constants for USB device identification
pub const VID: u16 = 0x5FC9;
pub const PID: u16 = 0x0063;

// Interface 0 (Vendor Specific - primary protocol, requires detach)
pub const INTERFACE_VENDOR: u8 = 0;
pub const ENDPOINT_OUT_VENDOR: u8 = 0x01;
pub const ENDPOINT_IN_VENDOR: u8 = 0x81;

// Interface 3 (HID - alternative, no detach needed)  
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
#[derive(Debug, Clone, Copy)]
pub struct DeviceConfig {
    pub interface: u8,
    pub endpoint_out: u8,
    pub endpoint_in: u8,
    pub transfer_type: TransferType,
    pub auto_detach: bool,
    pub reset_before_claim: bool,  // For compatibility with some systems
}

impl Default for DeviceConfig {
    fn default() -> Self {
        // Use HID interface by default (Interrupt transfers)
        Self {
            interface: INTERFACE_HID,
            endpoint_out: ENDPOINT_OUT_HID,
            endpoint_in: ENDPOINT_IN_HID,
            transfer_type: TransferType::Interrupt,
            auto_detach: false,
            reset_before_claim: false,
        }
    }
}

impl DeviceConfig {
    /// Use vendor-specific interface (Interface 0) with Bulk transfers
    /// Requires detaching kernel driver (powerz)
    /// This matches the kernel driver and old nusb 0.1.x implementation
    pub fn vendor_interface() -> Self {
        Self {
            interface: INTERFACE_VENDOR,
            endpoint_out: ENDPOINT_OUT_VENDOR,
            endpoint_in: ENDPOINT_IN_VENDOR,
            transfer_type: TransferType::Bulk,
            auto_detach: true,
            reset_before_claim: true,  // Old implementation did this
        }
    }
    
    /// Use HID interface (Interface 3) with Interrupt transfers
    /// More compatible, no kernel driver detach needed
    pub fn hid_interface() -> Self {
        Self::default()
    }
}

pub struct KM003C {
    interface: Interface,
    transaction_id: u8,
    config: DeviceConfig,
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
        
        // Reset before claiming if requested (matches old nusb 0.1.x behavior)
        if config.reset_before_claim {
            info!("Performing USB device reset...");
            device.reset().await?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        // Detach kernel drivers from ALL interfaces (prevents re-binding after operations)
        // This matches the behavior of Python examples and ensures device is accessible
        for interface_num in 0..4 {
            if let Err(e) = device.detach_kernel_driver(interface_num) {
                // Ignore errors - interface may not have a driver or may not exist
                trace!("Could not detach interface {}: {}", interface_num, e);
            } else {
                debug!("Detached kernel driver from interface {}", interface_num);
            }
        }

        // Try to claim the configured interface
        let interface = match device.claim_interface(config.interface).await {
            Ok(iface) => {
                info!("Interface {} claimed directly (no kernel driver attached)", config.interface);
                iface
            }
            Err(e) if e.kind() == nusb::ErrorKind::Busy => {
                // Still busy after detach_all - should not happen
                return Err(KMError::Protocol(
                    format!("Interface {} still busy after detach attempt", config.interface)
                ));
            }
            Err(e) => {
                return Err(e.into());
            }
        };

        let km003c = Self {
            interface,
            transaction_id: 0,
            config,
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

        // Use writer with proper configuration
        match self.config.transfer_type {
            TransferType::Bulk => {
                let endpoint = self.interface.endpoint::<Bulk, _>(self.config.endpoint_out)?;
                let mut writer = endpoint.writer(64).with_num_transfers(1);
                timeout(DEFAULT_TIMEOUT, writer.write_all(&message)).await??;
                timeout(DEFAULT_TIMEOUT, writer.flush_end_async()).await??;
            }
            TransferType::Interrupt => {
                let endpoint = self.interface.endpoint::<Interrupt, _>(self.config.endpoint_out)?;
                let mut writer = endpoint.writer(64).with_num_transfers(1);
                timeout(DEFAULT_TIMEOUT, writer.write_all(&message)).await??;
                timeout(DEFAULT_TIMEOUT, writer.flush_end_async()).await??;
            }
        }

        debug!("Sent successfully");
        Ok(())
    }

    /// Receive a high-level packet from the device
    pub async fn receive(&mut self) -> Result<Packet, KMError> {
        let raw_packet = self.receive_raw_packet().await?;
        Packet::try_from(raw_packet)
    }

    /// Receive a raw packet from the device
    async fn receive_raw_packet(&mut self) -> Result<RawPacket, KMError> {
        let mut buffer = vec![0u8; 1024];

        // Use reader with proper configuration
        let bytes_read = match self.config.transfer_type {
            TransferType::Bulk => {
                let endpoint = self.interface.endpoint::<Bulk, _>(self.config.endpoint_in)?;
                let mut reader = endpoint
                    .reader(64)
                    .with_num_transfers(4)
                    .with_read_timeout(Duration::from_millis(2000));
                timeout(DEFAULT_TIMEOUT, reader.read(&mut buffer)).await??
            }
            TransferType::Interrupt => {
                let endpoint = self.interface.endpoint::<Interrupt, _>(self.config.endpoint_in)?;
                let mut reader = endpoint
                    .reader(64)
                    .with_num_transfers(4)
                    .with_read_timeout(Duration::from_millis(2000));
                timeout(DEFAULT_TIMEOUT, reader.read(&mut buffer)).await??
            }
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
        self.send(Packet::GetData(mask)).await?;
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
}
