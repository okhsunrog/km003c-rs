use crate::adc::AdcDataSimple;
use crate::error::KMError;
use crate::message::Packet;
use crate::packet::RawPacket;
use bytes::Bytes;
use nusb::{Interface, transfer::RequestBuffer};
use std::time::Duration;
use tokio::time::timeout;
use tracing::info;

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
        // Convert the packet to bytes
        let mut header_bytes = [0u8; 4];
        match &packet {
            RawPacket::Ctrl { header, .. } => {
                header_bytes.copy_from_slice(&header.into_bytes());
                info!(
                    "Sending Ctrl packet: packet_type={}, extend={}, id={}, attribute=0x{:04x}",
                    header.packet_type(),
                    header.extend(),
                    header.id(),
                    header.attribute()
                );
            }
            RawPacket::Data { header, .. } => {
                header_bytes.copy_from_slice(&header.into_bytes());
                info!(
                    "Sending Data packet: packet_type={}, extend={}, id={}, obj_count_words={}",
                    header.packet_type(),
                    header.extend(),
                    header.id(),
                    header.obj_count_words()
                );
            }
        }

        // Create the full message
        let mut message = Vec::with_capacity(4 + packet.payload().len());
        message.extend_from_slice(&header_bytes);
        message.extend_from_slice(packet.payload().as_ref());

        // Log the full message being sent
        info!("Sending {} bytes: {:02x?}", message.len(), message);

        // Send the message
        let timeout_duration = DEFAULT_TIMEOUT;

        // Use bulk_out with the Vec<u8> directly
        let transfer_future = self.interface.bulk_out(ENDPOINT_OUT, message);

        // Apply timeout to the future
        let result = timeout(timeout_duration, transfer_future).await?;

        // Wait for the transfer to complete and get the result
        let bytes_sent = result.into_result()?;

        info!("Sent {} bytes", bytes_sent.actual_length());
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
        info!("Received {} bytes: {:02x?}", bytes_received, raw_bytes);

        // Convert the response to a packet
        let bytes = Bytes::copy_from_slice(raw_bytes);
        let raw_packet = RawPacket::try_from(bytes)?;

        // Log packet parsing details
        match &raw_packet {
            RawPacket::Ctrl { header, payload } => {
                info!(
                    "Parsed as Ctrl packet: packet_type={}, extend={}, id={}, attribute=0x{:04x}, payload_len={}",
                    header.packet_type(),
                    header.extend(),
                    header.id(),
                    header.attribute(),
                    payload.len()
                );
            }
            RawPacket::Data { header, payload } => {
                info!(
                    "Parsed as Data packet: packet_type={}, extend={}, id={}, obj_count_words={}, payload_len={}",
                    header.packet_type(),
                    header.extend(),
                    header.id(),
                    header.obj_count_words(),
                    payload.len()
                );
            }
        }

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
}
