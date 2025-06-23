use crate::adc::AdcDataSimple;
use crate::error::KMError;
use crate::message::Packet;
use crate::packet::RawPacket;
use bytes::Bytes;
use nusb::{Interface, transfer::RequestBuffer};
use std::time::Duration;
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
        let device_info = nusb::list_devices()?
            .find(|d| d.vendor_id() == VID && d.product_id() == PID)
            .ok_or(KMError::DeviceNotFound)?;

        info!(
            "Found device on bus {} addr {}",
            device_info.bus_number(),
            device_info.device_address()
        );

        let device = device_info.open()?;
        info!("Performing USB device reset...");
        device.reset()?;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let interface = device.detach_and_claim_interface(0)?;
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
        // Log packet details
        debug!(
            "Sending packet: type={:?}, extend={}, id={}, payload_len={}",
            packet.packet_type(),
            packet.is_extended(),
            packet.id(),
            packet.payload().len()
        );

        // Convert the packet to bytes
        let message_bytes = Bytes::from(packet);
        let message = message_bytes.to_vec();

        // Log the full message being sent at trace level
        trace!("Sending {} bytes: {:02x?}", message.len(), message);

        // Send the message
        let timeout_duration = DEFAULT_TIMEOUT;

        // Use bulk_out with the Vec<u8> directly
        let transfer_future = self.interface.bulk_out(ENDPOINT_OUT, message);

        // Apply timeout to the future
        let result = timeout(timeout_duration, transfer_future).await?;

        // Wait for the transfer to complete and get the result
        let bytes_sent = result.into_result()?;

        debug!("Sent {} bytes", bytes_sent.actual_length());
        Ok(())
    }

    /// Receive a high-level packet from the device
    pub async fn receive(&mut self) -> Result<Packet, KMError> {
        let raw_packet = self.receive_raw_packet().await?;
        Packet::try_from(raw_packet)
    }

    /// Receive a raw packet from the device
    async fn receive_raw_packet(&mut self) -> Result<RawPacket, KMError> {
        // Allocate a buffer for the response - RequestBuffer::new takes a size
        let buffer = RequestBuffer::new(1024);
        let timeout_duration = DEFAULT_TIMEOUT;

        // Use bulk_in with the RequestBuffer directly
        let transfer_future = self.interface.bulk_in(ENDPOINT_IN, buffer);

        // Apply timeout to the future
        let result = timeout(timeout_duration, transfer_future).await?;

        // Wait for the transfer to complete and get the result
        let response_buffer = result.into_result()?;

        let bytes_received = response_buffer.len();
        let raw_bytes = &response_buffer.as_slice()[..bytes_received];
        trace!("Received {} bytes: {:02x?}", bytes_received, raw_bytes);

        // Convert the response to a packet
        let bytes = Bytes::copy_from_slice(raw_bytes);
        let raw_packet = RawPacket::try_from(bytes)?;

        // Log packet parsing details at debug level
        debug!(
            "Parsed packet: type={:?}, extend={}, id={}, payload_len={}",
            raw_packet.packet_type(),
            raw_packet.is_extended(),
            raw_packet.id(),
            raw_packet.payload().len()
        );

        Ok(raw_packet)
    }

    /// Request ADC data
    pub async fn request_adc_data(&mut self) -> Result<AdcDataSimple, KMError> {
        // Send the request
        self.send(Packet::CmdGetSimpleAdcData).await?;

        // Receive the response
        let response = self.receive().await?;

        // Extract the ADC data
        match response {
            Packet::SimpleAdcData(adc_data) => Ok(adc_data),
            _ => Err(KMError::Protocol("Unexpected response type".to_string())),
        }
    }

    /// Request PD data
    pub async fn request_pd_data(&mut self) -> Result<Bytes, KMError> {
        // Send the request
        self.send(Packet::CmdGetPdData).await?;

        // Receive the response
        let response = self.receive().await?;

        // Extract the PD data
        match response {
            Packet::PdRawData(pd_data) => Ok(pd_data),
            _ => Err(KMError::Protocol("Unexpected response type".to_string())),
        }
    }
}
