// src/protocol.rs

//! # ChargerLAB POWER-Z KM003C USB Protocol (Ghidra/Wireshark Verified)
//!
//! This module provides a comprehensive set of constants, structs, and enums for
//! interacting with the ChargerLAB POWER-Z KM003C device. The definitions are
//! based on extensive reverse engineering of the official Windows application using
//! Ghidra and USB traffic analysis with Wireshark.
//!
//! ## Protocol Overview
//!
//! Communication occurs over a USB Bulk interface (`0xFF` Vendor-Specific) or
//! a fallback HID interface (`0x03`). The protocol is stateful and uses a
//! consistent 4-byte header for most commands, sometimes followed by a payload.
//!
//! ### Core Types
//!
//! - **`Packet`**: The central enum of this module. It represents any fully-parsed
//!   message that can be observed on the USB bus, whether it's a command from
//!   the host, a data response from the device, or an unsolicited stream packet.
//!   It is created using `Packet::from_bytes(bytes, direction)`.
//!
//! - **`CommandHeader`**: A struct representing the 4-byte header that precedes
//!   most messages. It contains the command type, a transaction ID, and an attribute.
//!
//! - **`SensorDataPacket` / `DeviceInfoBlock`**: Structs representing large,
//!   structured data payloads from the device.

use bytes::{Buf, Bytes};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use speedy::{Readable, Writable};
use std::convert::TryFrom;
use std::fmt;
use tracing::debug;

use crate::error::Error;

// --- Constants ---

pub const VID: u16 = 0x5FC9;
pub const PID: u16 = 0x0063;
pub const ENDPOINT_OUT: u8 = 0x01;
pub const ENDPOINT_IN: u8 = 0x81;

// --- Core Enums and Structs ---

/// Represents the direction of a USB transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    HostToDevice,
    DeviceToHost,
}

/// The primary enum representing any parsed packet on the bus.
#[derive(Debug, Clone)]
pub enum Packet {
    /// A command sent from the Host to the Device.
    Command(CommandHeader, Option<Bytes>),
    /// A simple acknowledgment response (Accept/Rejected) from the Device.
    Acknowledge { header: CommandHeader, kind: AckType },
    /// A structured 52-byte sensor data packet. Can be from a direct poll
    /// or part of an unsolicited high-speed data stream.
    SensorData(SensorDataPacket),
    /// A large, structured block of device information and capabilities.
    DeviceInfo(DeviceInfoBlock),
    /// A generic response from the device, typically of a known command type,
    /// but with a payload that is not yet fully structured.
    GenericResponse { header: CommandHeader, payload: Bytes },
    /// A raw data chunk from the device that does not have a valid command header.
    /// Often a continuation of a multi-part response.
    DataChunk(Bytes),
    /// A packet that could not be parsed into any known format and doesn't fit other categories.
    Unknown { bytes: Bytes, direction: Direction },
}

impl Packet {
    pub fn from_bytes(bytes: Bytes, direction: Direction) -> Self {
        // Host-to-Device is always a simple Command
        if direction == Direction::HostToDevice {
            if let Ok(header) = CommandHeader::try_from(bytes.slice(0..4)) {
                let payload = if bytes.len() > 4 { Some(bytes.slice(4..)) } else { None };
                return Packet::Command(header, payload);
            } else {
                return Packet::Unknown { bytes, direction };
            }
        }

        // --- Device-To-Host Parsing Logic ---

        // Heuristic 1: Is it a 52-byte packet? It's almost certainly SensorData.
        if bytes.len() == 52 {
            if let Ok(sensor_data) = SensorDataPacket::read_from_buffer(&bytes) {
                if sensor_data.header.response_type == CommandType::DataResponse.into() {
                    return Packet::SensorData(sensor_data);
                }
            }
        }

        // Heuristic 2: Does it have a valid 4-byte command header?
        if bytes.len() >= 4 {
            if let Ok(header) = CommandHeader::try_from(bytes.slice(0..4)) {
                let payload = if bytes.len() > 4 {
                    bytes.slice(4..)
                } else {
                    Bytes::new()
                };

                return match header.command_type {
                    CommandType::Accept => Packet::Acknowledge {
                        header,
                        kind: AckType::Accept,
                    },
                    CommandType::Rejected => Packet::Acknowledge {
                        header,
                        kind: AckType::Rejected,
                    },

                    CommandType::DataResponse => {
                        // Check if the payload matches the signature of a DeviceInfoBlock.
                        if payload.len() >= 200 {
                            if let Ok(info) = DeviceInfoBlock::try_from(payload.clone()) {
                                return Packet::DeviceInfo(info);
                            }
                        }

                        // Fallback to a generic response.
                        Packet::GenericResponse { header, payload }
                    }

                    _ => Packet::GenericResponse { header, payload },
                };
            }
        }

        // Heuristic 3: No valid header? It must be a raw data continuation chunk.
        if !bytes.is_empty() {
            return Packet::DataChunk(bytes);
        }

        // Fallback for empty or completely unidentifiable packets.
        Packet::Unknown { bytes, direction }
    }
}

/// Represents the 4-byte header of a command or response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandHeader {
    pub command_type: CommandType,
    pub transaction_id: u8,
    pub attribute: Attribute,
}

impl TryFrom<Bytes> for CommandHeader {
    type Error = Error;

    fn try_from(mut bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.remaining() < 4 {
            return Err(Error::Protocol("Header must be 4 bytes".to_string()));
        }

        let command_val = bytes.get_u8();
        let command_type = CommandType::try_from(command_val).map_err(|e| {
            debug!("Invalid CommandType value: {}", e);
            Error::Protocol(format!("Invalid CommandType value: {}", command_val))
        })?;

        let transaction_id = bytes.get_u8();

        let attribute_val = bytes.get_u16_le();
        let attribute = Attribute::try_from(attribute_val).map_err(|_| {
            debug!("Invalid Attribute value: {}", attribute_val);
            Error::Protocol(format!("Invalid Attribute value: {}", attribute_val))
        })?;

        Ok(Self {
            command_type,
            transaction_id,
            attribute,
        })
    }
}

/// Represents a simple Acknowledgment type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckType {
    Accept,
    Rejected,
}

/// Represents the packed 4-byte header of a SensorDataPacket.
#[derive(Debug, Clone, Copy, Default, Readable)]
pub struct SensorDataHeader {
    pub response_type: u8,
    pub transaction_id: u8,
    pub flags: u8,
    pub attribute_echo: u8,
}

#[derive(Debug, Clone, Copy, Default, Readable)]
pub struct SensorDataPacket {
    // These fields are based on the protocol spec table.
    pub header: SensorDataHeader,
    pub extended_header: u32,
    pub vbus_uv: i32,
    pub ibus_ua: i32,
    pub vbus_avg_uv: i32,
    pub ibus_avg_ua: i32,
    pub vbus_ori_avg_uv: i32,
    pub ibus_ori_avg_ua: i32,
    pub temp_raw: i16,
    pub vcc1_tenth_mv: u16,
    pub vcc2_raw: u16,
    pub vdp_mv: u16,
    pub vdm_mv: u16,
    pub vdd_raw: u16,
    pub rate: SampleRate,
    pub unknown1: u8,
    pub vcc2_avg_raw: u16,
    pub vdp_avg_mv: u16,
    pub vdm_avg_mv: u16,
}

impl fmt::Display for SensorDataPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // All units confirmed via testing.
        let vbus_v = self.vbus_uv as f64 / 1_000_000.0;
        let ibus_a = self.ibus_ua as f64 / 1_000_000.0;
        let power_w = vbus_v * ibus_a;

        let vbus_avg_v = self.vbus_avg_uv as f64 / 1_000_000.0;
        let ibus_avg_a = self.ibus_avg_ua as f64 / 1_000_000.0;

        let temp_c = self.temp_raw as f64 / 100.0;

        // The unit is 0.1mV, so divide by 10,000 to get Volts.
        let vdp_v = self.vdp_mv as f64 / 10_000.0;
        let vdm_v = self.vdm_mv as f64 / 10_000.0;
        let vdp_avg_v = self.vdp_avg_mv as f64 / 10_000.0;
        let vdm_avg_v = self.vdm_avg_mv as f64 / 10_000.0;

        // CC lines also use the 0.1mV unit.
        let cc1_v = self.vcc1_tenth_mv as f64 / 10_000.0;
        let cc2_v = self.vcc2_raw as f64 / 10_000.0;

        writeln!(f, "┌─ Live Measurements ─────────────────────────────────┐")?;
        writeln!(
            f,
            "│ VBUS:  {:>8.4} V  |  IBUS:   {:>8.4} A        │",
            vbus_v,
            ibus_a.abs()
        )?;
        writeln!(
            f,
            "│ Power: {:>8.4} W  |  Temp:    {:>8.2} °C        │",
            power_w.abs(),
            temp_c
        )?;
        writeln!(f, "├─ Average Measurements ──────────────────────────────┤")?;
        writeln!(
            f,
            "│ VBUS:  {:>8.4} V  |  IBUS:   {:>8.4} A        │",
            vbus_avg_v,
            ibus_avg_a.abs()
        )?;
        writeln!(f, "├─ Data & CC Lines ───────────────────────────────────┤")?;
        writeln!(
            f,
            "│ D+ (live/avg): {:>6.4} V / {:>6.4} V             │",
            vdp_v, vdp_avg_v
        )?;
        writeln!(
            f,
            "│ D- (live/avg): {:>6.4} V / {:>6.4} V             │",
            vdm_v, vdm_avg_v
        )?;
        writeln!(f, "│ CC1: {:>12.4} V  |  CC2:     {:>8.4} V        │", cc1_v, cc2_v)?;
        writeln!(f, "├─ Device Info ───────────────────────────────────────┤")?;
        writeln!(f, "│ Rate: {:<42} │", self.rate)?;
        writeln!(f, "└─────────────────────────────────────────────────────┘")
    }
}

/// Represents the 200-byte device information block.
#[derive(Debug, Clone)]
pub struct DeviceInfoBlock {
    pub firmware_version: u32,
    pub capabilities: u32,
    pub device_name: String,
    pub checksum: u32,
    pub raw_bytes: Bytes,
}

impl TryFrom<Bytes> for DeviceInfoBlock {
    type Error = Error;

    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        debug!(
            "Attempting to parse DeviceInfoBlock from payload of length {}",
            bytes.len()
        );

        // The core data block is 200 bytes long.
        if bytes.len() < 200 {
            debug!("DeviceInfoBlock::try_from failed: payload len {} is < 200", bytes.len());
            return Err(Error::Protocol("Device info block payload too short".to_string()));
        }

        // All slices are now guaranteed to be within bounds.
        let firmware_version = bytes.slice(8..12).get_u32_le();
        let capabilities = bytes.slice(16..20).get_u32_le();

        // Device name is from offset 136 to 200.
        let name_slice = bytes.slice(136..200);
        let name_end = name_slice.iter().position(|&b| b == 0).unwrap_or(64);
        let device_name = String::from_utf8_lossy(&name_slice[..name_end]).to_string();

        // Checksum is at a fixed offset from 196 to 200.
        let checksum = bytes.slice(196..200).get_u32_le();

        debug!("Successfully parsed DeviceInfoBlock with name '{}'", device_name);
        Ok(Self {
            firmware_version,
            capabilities,
            device_name,
            checksum,
            raw_bytes: bytes,
        })
    }
}

/// Command types used in the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum CommandType {
    Connect = 0x02,
    Disconnect = 0x03,
    Accept = 0x05,
    Rejected = 0x06,
    JumpAprom = 0x08,
    JumpDfu = 0x09,
    GetData = 0x0C,
    GetFile = 0x0E,
    StopStream = 0x0F,
    SetConfig = 0x10,
    ResetConfig = 0x11,
    GetDeviceInfo = 0x40,
    DataResponse = 0x41,
    Serial = 0x43,
    Authenticate = 0x44,
    CommandWithPayload = 0x4C,

    // Known handshake/response types
    ResponseC4 = 0xC4,
    Response75 = 0x75,
}

/// Attribute values used in command headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub enum Attribute {
    None = 0x0000,
    Adc = 0x0001,
    AdcQueue = 0x0002,
    AdcQueue10k = 0x0004,
    Settings = 0x0008,
    GetDeviceInfo = 0x0010,
    PdStatus = 0x0020,
    QcPacket = 0x0040,
    Timestamp = 0x0080,
    Serial = 0x0180,
    PollPdEvents = 0x2000,
    /// Used in the multi-step authentication handshake (0x0101).
    AuthStep = 0x0101,
    /// Used with CommandWithPayload to enter the default data recorder mode (0x0200).
    SetDataRecorderMode = 0x0200,
    /// Used to get a secondary block of info during startup (0x0400).
    GetStartupInfo = 0x0400,
    /// An attribute not yet identified.
    #[num_enum(catch_all)]
    Unknown(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Writable, Readable, strum_macros::Display, Default)]
#[speedy(tag_type = u8)]
pub enum SampleRate {
    #[default]
    #[strum(to_string = "1 SPS")]
    Sps1 = 0,
    #[strum(to_string = "10 SPS")]
    Sps10 = 1,
    #[strum(to_string = "50 SPS")]
    Sps50 = 2,
    #[strum(to_string = "1 kSPS")]
    Sps1000 = 3,
    #[strum(to_string = "10 kSPS")]
    Sps10000 = 4,
}

// NOTE: PdPacket is not yet used but is kept for future protocol additions.
#[derive(Debug, Clone)]
pub struct PdPacket {
    pub raw_data: Bytes,
}

impl TryFrom<Bytes> for PdPacket {
    type Error = Error;

    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.is_empty() {
            return Err(Error::Protocol("PD packet cannot be empty".to_string()));
        }
        Ok(Self { raw_data: bytes })
    }
}
