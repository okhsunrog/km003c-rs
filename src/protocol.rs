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
use std::convert::TryFrom;
use std::fmt;

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
        // Host-to-Device is always a command.
        if direction == Direction::HostToDevice {
            if let Ok(header) = CommandHeader::try_from(bytes.slice(0..4)) {
                let payload = if bytes.len() > 4 { Some(bytes.slice(4..)) } else { None };
                return Packet::Command(header, payload);
            } else {
                return Packet::Unknown { bytes, direction };
            }
        }

        // --- NEW, MORE ROBUST PARSING LOGIC FOR DEVICE-TO-HOST ---

        // Heuristic 1: Is it a 52-byte packet? It's almost certainly SensorData.
        // Let's check this first because it's a very strong indicator.
        if bytes.len() == 52 {
            if let Ok(sensor_data) = SensorDataPacket::try_from(bytes.clone()) {
                // We can still double-check the command type if we want
                if sensor_data.header.response_type == CommandType::DataResponse as u8 {
                    return Packet::SensorData(sensor_data);
                }
            }
        }

        // Heuristic 2: Does it have a valid command header?
        if let Ok(header) = CommandHeader::try_from(bytes.slice(0..4)) {
            let payload_bytes = if bytes.len() > 4 {
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
                    // Check for large structured payloads based on length, NOT attribute.
                    // The payload for DeviceInfo is > 188 bytes long.
                    if payload_bytes.len() >= 188 {
                        if let Ok(info) = DeviceInfoBlock::try_from(payload_bytes.clone()) {
                            return Packet::DeviceInfo(info);
                        }
                    }
                    // If it's not a DeviceInfo block, it's a generic response.
                    Packet::GenericResponse {
                        header,
                        payload: payload_bytes,
                    }
                }

                // Any other known command type is a generic response for now.
                _ => Packet::GenericResponse {
                    header,
                    payload: payload_bytes,
                },
            };
        }

        // Heuristic 3: No valid header? It's a DataChunk (like the auth responses).
        if !bytes.is_empty() {
            return Packet::DataChunk(bytes);
        }

        // Fallback for zero-length or otherwise unclassifiable packets.
        Packet::Unknown { bytes, direction }
    }
}

/// Represents the 4-byte header of a command or response.
// ... (CommandHeader struct and its impls remain the same) ...
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandHeader {
    pub command_type: CommandType,
    pub transaction_id: u8,
    pub attribute: Attribute,
}

impl TryFrom<Bytes> for CommandHeader {
    type Error = &'static str;

    fn try_from(mut bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.remaining() < 4 {
            return Err("Header must be 4 bytes");
        }
        let command_val = bytes.get_u8();
        let command_type = CommandType::try_from(command_val).map_err(|_| "Invalid CommandType value")?;

        Ok(Self {
            command_type,
            transaction_id: bytes.get_u8(),
            attribute: Attribute::from(bytes.get_u16_le()),
        })
    }
}

/// Represents a simple Acknowledgment type.
// ... (AckType enum remains the same) ...
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckType {
    Accept,
    Rejected,
}

/// Represents the packed 4-byte header of a SensorDataPacket.
#[derive(Debug, Clone, Copy, Default)]
pub struct SensorDataHeader {
    pub response_type: u8,
    pub transaction_id: u8,
    pub flags: u8,
    pub attribute_echo: u8,
}

impl From<u32> for SensorDataHeader {
    fn from(val: u32) -> Self {
        let bytes = val.to_le_bytes();
        Self {
            response_type: bytes[0],
            transaction_id: bytes[1],
            flags: bytes[2],
            attribute_echo: bytes[3],
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
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

// In km003c-rs/src/protocol.rs

impl fmt::Display for SensorDataPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // --- Calculations with CORRECTED divisors ---
        let vbus_v = self.vbus_uv as f64 / 1_000_000.0;
        let ibus_a = self.ibus_ua as f64 / 1_000_000.0;
        let power_w = vbus_v * ibus_a;

        let vbus_avg_v = self.vbus_avg_uv as f64 / 1_000_000.0;
        let ibus_avg_a = self.ibus_avg_ua as f64 / 1_000_000.0;

        let temp_c = self.temp_raw as f64 / 100.0;

        // FIX: The unit is 0.1mV, so divide by 10,000 to get Volts.
        let vdp_v = self.vdp_mv as f64 / 10_000.0;
        let vdm_v = self.vdm_mv as f64 / 10_000.0;
        let vdp_avg_v = self.vdp_avg_mv as f64 / 10_000.0;
        let vdm_avg_v = self.vdm_avg_mv as f64 / 10_000.0;

        // FIX: CC lines also use the 0.1mV unit.
        let cc1_v = self.vcc1_tenth_mv as f64 / 10_000.0;
        let cc2_v = self.vcc2_raw as f64 / 10_000.0;

        // --- Formatting ---
        writeln!(f, "┌─ Live Measurements ─────────────────────────────────┐")?;
        // FIX: Use .abs() for current and power
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

impl TryFrom<Bytes> for SensorDataPacket {
    type Error = std::io::Error;

    fn try_from(mut bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.remaining() < 52 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Sensor data packet must be 52 bytes",
            ));
        }
        Ok(Self {
            header: SensorDataHeader::from(bytes.get_u32_le()),
            extended_header: bytes.get_u32_le(),
            vbus_uv: bytes.get_i32_le(),
            ibus_ua: bytes.get_i32_le(),
            vbus_avg_uv: bytes.get_i32_le(),
            ibus_avg_ua: bytes.get_i32_le(),
            vbus_ori_avg_uv: bytes.get_i32_le(),
            ibus_ori_avg_ua: bytes.get_i32_le(),
            temp_raw: bytes.get_i16_le(),
            vcc1_tenth_mv: bytes.get_u16_le(),
            vcc2_raw: bytes.get_u16_le(),
            vdp_mv: bytes.get_u16_le(),
            vdm_mv: bytes.get_u16_le(),
            vdd_raw: bytes.get_u16_le(),
            rate: SampleRate::from_index(bytes.get_u8()),
            unknown1: bytes.get_u8(),
            vcc2_avg_raw: bytes.get_u16_le(),
            vdp_avg_mv: bytes.get_u16_le(),
            vdm_avg_mv: bytes.get_u16_le(),
        })
    }
}

/// Represents the 200+ byte device information block.
// ... (DeviceInfoBlock struct and its impls remain the same) ...
#[derive(Debug, Clone)]
pub struct DeviceInfoBlock {
    pub firmware_version: u32,
    pub capabilities: u32,
    pub device_name: String,
    pub checksum: u32,
    pub raw_bytes: Bytes,
}

impl TryFrom<Bytes> for DeviceInfoBlock {
    type Error = std::io::Error;

    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.len() < 188 {
            // Use 188 to match the check in Packet::from_bytes
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Device info block too short",
            ));
        }

        let firmware_version = bytes.slice(8..12).get_u32_le();
        let capabilities = bytes.slice(16..20).get_u32_le();

        let name_bytes = &bytes.slice(136..200);
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(64);
        let device_name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

        let checksum = bytes.slice(bytes.len() - 4..).get_u32_le();

        Ok(Self {
            firmware_version,
            capabilities,
            device_name,
            checksum,
            raw_bytes: bytes,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl TryFrom<u8> for CommandType {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x02 => Ok(Self::Connect),
            0x03 => Ok(Self::Disconnect),
            0x05 => Ok(Self::Accept),
            0x06 => Ok(Self::Rejected),
            0x08 => Ok(Self::JumpAprom),
            0x09 => Ok(Self::JumpDfu),
            0x0C => Ok(Self::GetData),
            0x0E => Ok(Self::GetFile),
            0x0F => Ok(Self::StopStream),
            0x10 => Ok(Self::SetConfig),
            0x11 => Ok(Self::ResetConfig),
            0x40 => Ok(Self::GetDeviceInfo),
            0x41 => Ok(Self::DataResponse), // RENAMED
            0x43 => Ok(Self::Serial),
            0x44 => Ok(Self::Authenticate),
            0x4C => Ok(Self::CommandWithPayload),
            0xC4 => Ok(Self::ResponseC4),
            0x75 => Ok(Self::Response75),
            _ => Err(()),
        }
    }
}

// --- CHANGE: Attribute enum updated ---
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attribute {
    None,
    Adc,
    AdcQueue,
    AdcQueue10k,
    Settings,
    GetDeviceInfo,
    PdStatus,
    QcPacket,
    Timestamp,
    Serial,
    Auth,
    PollPdEvents,
    // --- NEW VARIANTS ---
    /// Used in the multi-step authentication handshake (0x0101).
    AuthStep,
    /// Used with CommandWithPayload to enter the default data recorder mode (0x0200).
    SetDataRecorderMode,
    /// Used to get a secondary block of info during startup (0x0400).
    GetStartupInfo,
    /// An attribute not yet identified.
    Unknown(u16),
}

// --- CHANGE: from<u16> for Attribute updated ---
impl From<u16> for Attribute {
    fn from(val: u16) -> Self {
        match val {
            0x0000 => Self::None,
            0x0001 => Self::Adc,
            0x0002 => Self::AdcQueue,
            0x0004 => Self::AdcQueue10k,
            0x0008 => Self::Settings,
            0x0010 => Self::GetDeviceInfo,
            0x0020 => Self::PdStatus,
            0x0040 => Self::QcPacket,
            0x0080 => Self::Timestamp,
            0x0101 => Self::AuthStep, // NEW
            0x0180 => Self::Serial,
            0x0200 => Self::SetDataRecorderMode, // NEW
            0x0400 => Self::GetStartupInfo,      // NEW
            0x2000 => Self::PollPdEvents,
            other => Self::Unknown(other),
        }
    }
}

// --- CHANGE: u16::from for Attribute updated ---
impl From<Attribute> for u16 {
    fn from(attr: Attribute) -> Self {
        match attr {
            Attribute::None => 0x0000,
            Attribute::Adc => 0x0001,
            Attribute::AdcQueue => 0x0002,
            Attribute::AdcQueue10k => 0x0004,
            Attribute::Settings => 0x0008,
            Attribute::GetDeviceInfo => 0x0010,
            Attribute::PdStatus => 0x0020,
            Attribute::QcPacket => 0x0040,
            Attribute::Timestamp => 0x0080,
            Attribute::AuthStep => 0x0101,
            Attribute::Serial => 0x0180,
            Attribute::SetDataRecorderMode => 0x0200,
            Attribute::Auth => 0x0200,
            Attribute::GetStartupInfo => 0x0400,
            Attribute::PollPdEvents => 0x2000,
            Attribute::Unknown(val) => val,
        }
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleRate {
    #[default]
    Sps1,
    Sps10,
    Sps50,
    Sps1000,
    Sps10000,
    Unknown(u8),
}

impl SampleRate {
    pub fn from_index(index: u8) -> Self {
        match index {
            0 => Self::Sps1,
            1 => Self::Sps10,
            2 => Self::Sps50,
            3 => Self::Sps1000,
            4 => Self::Sps10000,
            _ => Self::Unknown(index),
        }
    }
}

impl fmt::Display for SampleRate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SampleRate::Sps1 => write!(f, "1 SPS"),
            SampleRate::Sps10 => write!(f, "10 SPS"),
            SampleRate::Sps50 => write!(f, "50 SPS"),
            SampleRate::Sps1000 => write!(f, "1 kSPS"),
            SampleRate::Sps10000 => write!(f, "10 kSPS"),
            SampleRate::Unknown(v) => write!(f, "Unknown ({})", v),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PdPacket {
    // For now, we just wrap the raw data. Later, we can parse fields from this.
    pub raw_data: Bytes,
}

impl TryFrom<Bytes> for PdPacket {
    type Error = std::io::Error;

    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        // A simple length check. We can make this more robust later.
        if bytes.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "PD packet cannot be empty",
            ));
        }
        Ok(Self { raw_data: bytes })
    }
}
