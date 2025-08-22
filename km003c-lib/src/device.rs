use crate::adc::AdcDataSimple;
use crate::error::KMError;
use crate::message::Packet;
use crate::packet::RawPacket;
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
        info!("Performing USB device reset...");
        device.reset().await?;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let interface = device.detach_and_claim_interface(0).await?;
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
        debug!(
            "Sending packet: type={:?}, flag={}, id={}, payload_len={}",
            packet.packet_type(),
            packet.flag(),
            packet.id(),
            packet.payload().len()
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

        debug!(
            "Parsed packet: type={:?}, flag={}, id={}, payload_len={}",
            raw_packet.packet_type(),
            raw_packet.flag(),
            raw_packet.id(),
            raw_packet.payload().len()
        );

        Ok(raw_packet)
    }

    /// Request ADC data
    pub async fn request_adc_data(&mut self) -> Result<AdcDataSimple, KMError> {
        self.send(Packet::CmdGetSimpleAdcData).await?;
        let response = self.receive().await?;
        match response {
            Packet::SimpleAdcData(adc_data) => Ok(adc_data),
            _ => Err(KMError::Protocol("Unexpected response type for ADC data".to_string())),
        }
    }

    /// Request PD data
    pub async fn request_pd_data(&mut self) -> Result<Bytes, KMError> {
        self.send(Packet::CmdGetPdData).await?;
        let response = self.receive().await?;
        match response {
            Packet::PdRawData(pd_data) => Ok(pd_data),
            _ => Err(KMError::Protocol("Unexpected response type for PD data".to_string())),
        }
    }
}
