// src/device.rs

use crate::error::Error;
use crate::protocol::{Attribute, CommandType, Direction, ENDPOINT_IN, ENDPOINT_OUT, PID, Packet, VID};
use bytes::{Bytes, BytesMut};
use nusb::{Interface, transfer::RequestBuffer};
use std::time::Duration;
use tracing::{debug, info, warn};

const AUTH_PAYLOAD_1: &[u8] = &[
    0x33, 0xf8, 0x86, 0x0c, 0x00, 0x54, 0x28, 0x8c, 0xdc, 0x7e, 0x52, 0x72, 0x98, 0x26, 0x87, 0x2d, 0xd1, 0x8b, 0x53,
    0x9a, 0x39, 0xc4, 0x07, 0xd5, 0xc0, 0x63, 0xd9, 0x11, 0x02, 0xe3, 0x6a, 0x9e,
];
const AUTH_PAYLOAD_2: &[u8] = &[
    0x63, 0x6b, 0xea, 0xf3, 0xf0, 0x85, 0x65, 0x06, 0xee, 0xe9, 0xa2, 0x7e, 0x89, 0x72, 0x2d, 0xcf, 0xd1, 0x8b, 0x53,
    0x9a, 0x39, 0xc4, 0x07, 0xd5, 0xc0, 0x63, 0xd9, 0x11, 0x02, 0xe3, 0x6a, 0x9e,
];
const AUTH_PAYLOAD_3: &[u8] = &[
    0xc5, 0x11, 0x67, 0xae, 0x61, 0x3a, 0x6d, 0x46, 0xec, 0x84, 0xa6, 0xbd, 0xe8, 0xbd, 0x46, 0x2a, 0xd1, 0x8b, 0x53,
    0x9a, 0x39, 0xc4, 0x07, 0xd5, 0xc0, 0x63, 0xd9, 0x11, 0x02, 0xe3, 0x6a, 0x9e,
];
const AUTH_PAYLOAD_4: &[u8] = &[
    0x9c, 0x40, 0x9d, 0xeb, 0xc8, 0xdf, 0x53, 0xb8, 0x3b, 0x06, 0x6c, 0x31, 0x52, 0x50, 0xd0, 0x5c, 0xd1, 0x8b, 0x53,
    0x9a, 0x39, 0xc4, 0x07, 0xd5, 0xc0, 0x63, 0xd9, 0x11, 0x02, 0xe3, 0x6a, 0x9e,
];

#[rustfmt::skip]
const SET_RECORDER_MODE_PAYLOAD: &[u8] = &[
    0x2c, 0xc0, 0xc2, 0x8b, 0x15, 0xe4, 0x78, 0x34, 0x65, 0xf1, 0xec, 0xcc, 0x36, 0xdb, 0xc8, 0xe3,
    0xd1, 0xba, 0x34, 0x17, 0xec, 0x04, 0x63, 0x40, 0xd3, 0xdf, 0x92, 0xb6, 0xce, 0x2a, 0x51, 0xb4,
];

/// Represents a connection to a POWER-Z KM003C device.
pub struct KM003C {
    interface: Interface,
    transaction_id: u8,
}

impl KM003C {
    pub async fn new(with_auth: bool) -> Result<Self, Error> {
        info!("Searching for POWER-Z KM003C...");
        let device_info = nusb::list_devices()?
            .find(|d| d.vendor_id() == VID && d.product_id() == PID)
            .ok_or(Error::DeviceNotFound)?;

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

        let mut km003c = Self {
            interface,
            transaction_id: 0,
        };

        info!("--- Starting Connection Handshake ---");
        km003c
            .transact_and_discard(CommandType::Connect, Attribute::None, None)
            .await?;

        if with_auth {
            km003c.authenticate().await?;
        }

        info!("--- Setting Recorder Mode ---");
        km003c
            .transact_and_discard(
                CommandType::CommandWithPayload,
                Attribute::SetDataRecorderMode,
                Some(SET_RECORDER_MODE_PAYLOAD),
            )
            .await?;

        info!("--- Initial Info Dump ---");
        km003c
            .transact_and_discard(CommandType::GetData, Attribute::GetDeviceInfo, None)
            .await?;
        km003c
            .transact_and_discard(CommandType::GetData, Attribute::GetStartupInfo, None)
            .await?;

        info!("--- Stopping Stream for Clean State ---");
        km003c
            .transact_and_discard(CommandType::StopStream, Attribute::None, None)
            .await?;

        info!("Device initialized and ready for polling.");
        Ok(km003c)
    }

    async fn authenticate(&mut self) -> Result<(), Error> {
        info!("--- Starting Authentication Replay ---");
        self.transact_and_discard(CommandType::Authenticate, Attribute::AuthStep, Some(AUTH_PAYLOAD_1))
            .await?;
        self.transact_and_discard(CommandType::Authenticate, Attribute::AuthStep, Some(AUTH_PAYLOAD_2))
            .await?;
        self.transact_and_discard(CommandType::Authenticate, Attribute::AuthStep, Some(AUTH_PAYLOAD_3))
            .await?;
        self.transact_and_discard(CommandType::Authenticate, Attribute::AuthStep, Some(AUTH_PAYLOAD_4))
            .await?;
        info!("--- Authentication Replay Complete ---");
        Ok(())
    }

    pub async fn poll_sensor_data(&mut self) -> Result<crate::protocol::SensorDataPacket, Error> {
        let response_packets = self.transact(CommandType::GetData, Attribute::AdcQueue, None).await?;
        for packet in response_packets {
            if let Packet::SensorData(sensor_packet) = packet {
                return Ok(sensor_packet);
            }
        }
        Err(Error::Protocol(
            "Did not receive a valid SensorDataPacket in response to poll.".to_string(),
        ))
    }

    fn next_id(&mut self) -> u8 {
        self.transaction_id = self.transaction_id.wrapping_add(1);
        self.transaction_id
    }

    fn build_command_bytes(id: u8, cmd: CommandType, attr: Attribute, payload: Option<&[u8]>) -> Vec<u8> {
        let mut command = BytesMut::with_capacity(64);
        command.extend_from_slice(&[cmd as u8, id]);
        command.extend_from_slice(&u16::from(attr).to_le_bytes());
        if let Some(p) = payload {
            command.extend_from_slice(p);
        }
        command.to_vec()
    }

    async fn send_bytes(&self, data: Vec<u8>) -> Result<(), Error> {
        debug!(bytes = hex::encode(&data), "USB Write");
        let write_transfer = self.interface.bulk_out(ENDPOINT_OUT, data);
        let completion = tokio::time::timeout(Duration::from_secs(1), write_transfer).await?;
        completion.into_result()?;
        Ok(())
    }

    async fn read_packet_with_timeout(&self, timeout: Duration) -> Result<Packet, Error> {
        let read_transfer = self.interface.bulk_in(ENDPOINT_IN, RequestBuffer::new(512));
        let completion = tokio::time::timeout(timeout, read_transfer).await?;
        let data = completion.into_result()?;
        debug!(bytes = hex::encode(&data), "USB Read");
        Ok(Packet::from_bytes(Bytes::from(data), Direction::DeviceToHost))
    }

    async fn transact(
        &mut self,
        cmd: CommandType,
        attr: Attribute,
        payload: Option<&[u8]>,
    ) -> Result<Vec<Packet>, Error> {
        let id = self.next_id();
        self.transact_with_ids(cmd, attr, payload, id, id).await
    }

    async fn transact_and_discard(
        &mut self,
        cmd: CommandType,
        attr: Attribute,
        payload: Option<&[u8]>,
    ) -> Result<(), Error> {
        let send_id = self.next_id();
        let expected_id = if cmd == CommandType::CommandWithPayload && attr == Attribute::SetDataRecorderMode {
            0
        } else {
            send_id
        };
        self.transact_with_ids(cmd, attr, payload, send_id, expected_id).await?;
        Ok(())
    }

    async fn transact_with_ids(
        &mut self,
        cmd: CommandType,
        attr: Attribute,
        payload: Option<&[u8]>,
        send_id: u8,
        expected_id: u8,
    ) -> Result<Vec<Packet>, Error> {
        let command_bytes = Self::build_command_bytes(send_id, cmd, attr, payload);
        self.send_bytes(command_bytes).await?;

        let mut responses = Vec::new();
        loop {
            let timeout = if responses.is_empty() {
                Duration::from_millis(250)
            } else {
                Duration::from_millis(50)
            };
            match self.read_packet_with_timeout(timeout).await {
                Ok(packet) => responses.push(packet),
                Err(_) => break,
            }
        }

        let relevant_responses = responses
            .into_iter()
            .filter(|p| {
                let is_id_match = match p {
                    Packet::Acknowledge { header, .. } => header.transaction_id == expected_id,
                    Packet::GenericResponse { header, .. } => header.transaction_id == expected_id,
                    // Use the new, structured header for a clean and direct comparison
                    Packet::SensorData(sd) => sd.header.transaction_id == expected_id,
                    _ => false,
                };
                // Keep this logic, as it's correct for collecting multi-part responses
                matches!(p, Packet::DataChunk(_)) || is_id_match
            })
            .collect::<Vec<_>>();

        if relevant_responses.is_empty() {
            warn!(
                "Transaction for {:?} (sent ID {}, expected ID {}) completed but no relevant response packets were found.",
                cmd, send_id, expected_id
            );
        } else {
            info!(
                "Transaction for {:?} (sent ID {}, expected ID {}) complete, received {} relevant response packet(s)",
                cmd,
                send_id,
                expected_id,
                relevant_responses.len()
            );
        }
        Ok(relevant_responses)
    }
}
