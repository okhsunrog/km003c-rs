use crate::adc::AdcDataSimple;
use crate::error::KMError;
use crate::message::Packet;
use crate::packet::{Attribute, AttributeSet, RawPacket};
use crate::pd::PdEventStream;
use bytes::Bytes;
use nusb::Interface;
use nusb::transfer::Bulk;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::{debug, info, trace};

// Constants for USB device identification
pub const VID: u16 = 0x5FC9;
pub const PID: u16 = 0x0063;
pub const ENDPOINT_OUT: u8 = 0x01;
pub const ENDPOINT_IN: u8 = 0x81;

// Default timeout for USB operations
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

pub struct KM003C {
    interface: Interface,
    transaction_id: u8,
}

impl KM003C {
    /// Create a new KM003C instance by finding and connecting to the device
    pub async fn new() -> Result<Self, KMError> {
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

        // Try to claim interface 0 directly first. On some Linux systems, a kernel
        // driver (e.g., HID/CDC-ACM on other interfaces) may temporarily keep the
        // device busy right after enumeration or reset. Avoid resetting first and
        // only reset if the initial claim fails, then retry with a longer delay.
        let interface = match device.claim_interface(0).await {
            Ok(iface) => iface,
            Err(e) => {
                info!(
                    "Initial interface claim failed: {}. Resetting device and retrying...",
                    e
                );
                device.reset().await?;
                // Allow more time for the kernel to rebind other interfaces
                tokio::time::sleep(Duration::from_millis(500)).await;
                device.claim_interface(0).await?
            }
        };
        info!("Interface claimed successfully.");

        let km003c = Self {
            interface,
            transaction_id: 0,
        };

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

        let endpoint = self.interface.endpoint::<Bulk, _>(ENDPOINT_OUT)?;
        let mut writer = endpoint.writer(1024);

        timeout(DEFAULT_TIMEOUT, writer.write_all(&message)).await??;

        debug!("Sent {} bytes", message.len());
        Ok(())
    }

    /// Receive a high-level packet from the device
    pub async fn receive(&mut self) -> Result<Packet, KMError> {
        let raw_packet = self.receive_raw_packet().await?;
        Packet::try_from(raw_packet)
    }

    /// Receive a raw packet from the device
    async fn receive_raw_packet(&mut self) -> Result<RawPacket, KMError> {
        let endpoint = self.interface.endpoint::<Bulk, _>(ENDPOINT_IN)?;
        let mut reader = endpoint.reader(1024);
        let mut buffer = vec![0u8; 1024];

        let bytes_read = timeout(DEFAULT_TIMEOUT, reader.read(&mut buffer)).await??;

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
            "Parsed packet: type={:?}, reserved_flag={}, has_logical_packets={}, id={}",
            raw_packet.packet_type(),
            reserved_flag,
            has_logical_packets,
            raw_packet.id(),
        );

        Ok(raw_packet)
    }

    /// Request data with a specific attribute set
    pub async fn request_data(&mut self, mask: AttributeSet) -> Result<Packet, KMError> {
        self.send(Packet::GetData(mask)).await?;
        self.receive().await
    }

    /// Request ADC data only
    pub async fn request_adc_data(&mut self) -> Result<AdcDataSimple, KMError> {
        let packet = self.request_data(AttributeSet::single(Attribute::Adc)).await?;
        packet
            .get_adc()
            .cloned()
            .ok_or_else(|| KMError::Protocol("No ADC data in response".to_string()))
    }

    /// Request PD data
    pub async fn request_pd_data(&mut self) -> Result<PdEventStream, KMError> {
        let packet = self.request_data(AttributeSet::single(Attribute::PdPacket)).await?;
        packet
            .get_pd_events()
            .cloned()
            .ok_or_else(|| KMError::Protocol("No PD event data in response".to_string()))
    }

    /// Request both ADC and PD data in a single request
    pub async fn request_adc_with_pd(&mut self) -> Result<Packet, KMError> {
        let mask = AttributeSet::single(Attribute::Adc).with(Attribute::PdPacket);
        self.request_data(mask).await
    }
}
