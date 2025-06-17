//! # ChargerLAB POWER-Z KM003C USB Protocol
//!
//! This module provides constants, structs, and enums for interacting with the
//! ChargerLAB POWER-Z KM003C device over its Vendor-Specific (WinUSB/libusb) interface.
//!
//! The protocol was reverse-engineered from a combination of official documentation,
//! a Pascal header file, and extensive USB traffic analysis.
//!
//! ## Protocol Overview
//!
//! The device communication is based on a 4-byte command/response header,
//! sometimes followed by a data payload. The protocol is stateful, requiring a
//! specific sequence of commands to perform actions like changing sample rates
//! or switching operational modes.
//!
//! ### Key Concepts
//!
//! - **Endpoints:** All commands are sent via Bulk Transfer to Endpoint `0x01` (OUT).
//!   All responses and data are received on Endpoint `0x81` (IN).
//! - **Header:** A 4-byte little-endian header precedes all messages.
//! - **State Machine:** The device operates in different modes (e.g., Data Recorder,
//!   PD Analyzer). Switching between them requires specific commands.
//! - **Configuration vs. Data Flow:** Setting parameters like sample rate is a separate
//!   "configuration" step. Starting and stopping the data stream is a "data flow" step.
//!
//! ### Basic Command Sequence (Data Recorder)
//!
//! 1.  `CMD_CONNECT`: Initial handshake.
//! 2.  `CMD_SET_RECORDER_MODE`: Puts the device in the default VBUS/IBUS logging mode.
//! 3.  `CMD_SET_CONFIG`: Sends the desired sample rate to the device.
//! 4.  `CMD_GET_DATA` with `ATT_ADC_QUEUE`: Starts and polls the high-frequency data stream.
//! 5.  `CMD_STOP_STREAM`: Halts the data stream.
//! 6.  `CMD_GET_DATA` with `ATT_ADC`: Can be used when no stream is active to get low-rate updates.

use bytes::{Buf, Bytes};
use std::convert::TryFrom;
use std::fmt;

// --- Constants ---

/// The USB Vendor ID for ChargerLAB devices.
pub const VID: u16 = 0x5FC9;
/// The USB Product ID for the KM003C model.
pub const PID: u16 = 0x0063;

/// The endpoint for sending commands from the Host to the Device.
pub const ENDPOINT_OUT: u8 = 0x01;
/// The endpoint for receiving data from the Device to the Host.
pub const ENDPOINT_IN: u8 = 0x81;

// --- Data Structures ---

/// Events that the controller sends back to the client application.
#[derive(Clone, Debug)]
pub enum DeviceEvent {
    Connected,
    SensorData(SensorDataPacket),
    PdPacket(Bytes), // Raw PD packet stream data
    SerialResponse(String),
    Disconnected,
}

/// Represents the full 52-byte sensor data packet received from the device.
#[derive(Debug, Clone, Copy, Default)]
pub struct SensorDataPacket {
    pub header: u32,
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

impl TryFrom<Bytes> for SensorDataPacket {
    type Error = std::io::Error;

    fn try_from(mut bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.remaining() < 52 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Sensor data packet must be at least 52 bytes, got {}",
                    bytes.len()
                ),
            ));
        }
        Ok(Self {
            header: bytes.get_u32_le(),
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

/// Provides convenient, human-readable methods for the sensor data.
impl SensorDataPacket {
    pub fn vbus_v(&self) -> f64 {
        self.vbus_uv as f64 / 1_000_000.0
    }
    pub fn ibus_a(&self) -> f64 {
        self.ibus_ua as f64 / 1_000_000.0
    }
    pub fn power_w(&self) -> f64 {
        self.vbus_v() * self.ibus_a()
    }
    pub fn vdp_v(&self) -> f64 {
        self.vdp_mv as f64 / 1_000.0
    }
    pub fn vdm_v(&self) -> f64 {
        self.vdm_mv as f64 / 1_000.0
    }
    pub fn vcc1_v(&self) -> f64 {
        self.vcc1_tenth_mv as f64 * 0.1 / 1_000.0
    }

    /// Returns the temperature in degrees Celsius.
    pub fn temperature_celsius(&self) -> f64 {
        let bytes = self.temp_raw.to_le_bytes();
        let low_byte = bytes[0] as f64;
        let high_byte = bytes[1] as f64;
        ((high_byte * 2000.0) + (low_byte * 7.8125)) / 1000.0
    }
}

impl fmt::Display for SensorDataPacket {
    // A nice, formatted display for logging
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "┌──────────────────────────────────────────┐")?;
        writeln!(
            f,
            "│ VBUS: {:>8.4} V │ IBus: {:>8.4} A │",
            self.vbus_v(),
            self.ibus_a()
        )?;
        writeln!(
            f,
            "│ Power: {:>6.3} W │ Temp: {:>7.2} °C      │",
            self.power_w(),
            self.temperature_celsius()
        )?;
        writeln!(f, "├──────────────────────────────────────────┤")?;
        writeln!(
            f,
            "│ Vdp: {:>8.4} V │ Vdm: {:>8.4} V │",
            self.vdp_v(),
            self.vdm_v()
        )?;
        writeln!(f, "│ Rate: {:<31} │", self.rate)?;
        writeln!(f, "└──────────────────────────────────────────┘")
    }
}

// --- Command and API Definitions ---

/// Represents the `type` field of the command header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandType {
    Connect = 0x02,
    Accept = 0x05,
    Rejected = 0x06,
    GetData = 0x0C,
    GetFile = 0x0E,
    StopStream = 0x0F,
    SetConfig = 0x10,
    StatusA = 0x41,
    SetRecorderMode = 0x4C,
    Authenticate = 0x44, // Likely has a complex payload
}

/// Represents the supported sample rates for the Data Recorder mode.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SampleRate {
    #[default]
    Sps1 = 1,
    Sps10 = 10,
    Sps50 = 50,
    Sps1000 = 1000,
    Unknown(u8),
}

impl SampleRate {
    pub fn from_index(index: u8) -> Self {
        match index {
            0 => Self::Sps1,
            1 => Self::Sps10,
            2 => Self::Sps50,
            3 => Self::Sps1000,
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
            SampleRate::Unknown(v) => write!(f, "Unknown ({})", v),
        }
    }
}

/// Commands that a client application can send to the controller.
#[derive(Debug, Clone)]
pub enum ControllerCommand {
    /// Send a text-based command over the serial interface.
    SendSerial(SerialCommand),
    /// Set the device's internal hardware sampling rate.
    SetHardwareSampleRate(SampleRate),
    /// Set the data polling mode for the raw USB interface.
    SetPollingMode(DataPollingMode),
}

/// Type-safe representation of all known text-based serial commands.
#[derive(Debug, Clone, PartialEq)]
pub enum SerialCommand {
    PdmOpen,
    PdmClose,
    Entry(ChargingProtocol),
    PdGetPdo,
    PdRequest {
        req: u8, // Object Position
        volt_mv: Option<u16>,
        cur_ma: Option<u16>,
    },
    // Add other serial commands from the PDF here...
}

// ... other helper enums like ChargingProtocol ...
// (These are omitted for brevity but should be included from the previous answer)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ChargingProtocol {
    Pd,
    Ufcs,
    Qc,
    Fcp,
    Scp,
    Afc,
    Vfcp,
    Sfcp,
}
impl fmt::Display for ChargingProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", format!("{:?}", self).to_lowercase())
    }
}
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum PdmPdType {
    Automatic = 0,
    Pd3_0 = 1,
    Pd3_1 = 2,
    ProprietaryPps = 3,
}
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum PdmEmarker {
    Off = 0,
    V20A5 = 1,
    V50A5Epr = 2,
    La135A6_75 = 3,
}

impl From<SerialCommand> for String {
    fn from(cmd: SerialCommand) -> Self {
        match cmd {
            SerialCommand::PdmOpen => "pdm open".to_string(),
            SerialCommand::PdmClose => "pdm close".to_string(),
            SerialCommand::Entry(protocol) => format!("entry {}", protocol),
            SerialCommand::PdGetPdo => "pd pdo".to_string(),
            SerialCommand::PdRequest {
                req,
                volt_mv,
                cur_ma,
            } => {
                let mut command = format!("pd req={}", req);
                if let Some(mv) = volt_mv {
                    command.push_str(&format!(",volt={}", mv));
                }
                if let Some(ma) = cur_ma {
                    command.push_str(&format!(",cur={}", ma));
                }
                command
            }
        }
    }
}

/// The different polling modes for the binary interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataPollingMode {
    /// Poll for standard sensor data.
    Adc,
    /// Poll for high-speed 1kSPS sensor data.
    Adc10k,
    /// Poll for PD packets (and piggy-backed sensor data).
    PdSniffer,
}

impl TryFrom<u8> for CommandType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == CommandType::Connect as u8 => Ok(CommandType::Connect),
            x if x == CommandType::Accept as u8 => Ok(CommandType::Accept),
            x if x == CommandType::Rejected as u8 => Ok(CommandType::Rejected),
            x if x == CommandType::GetData as u8 => Ok(CommandType::GetData),
            x if x == CommandType::GetFile as u8 => Ok(CommandType::GetFile),
            x if x == CommandType::StopStream as u8 => Ok(CommandType::StopStream),
            x if x == CommandType::SetConfig as u8 => Ok(CommandType::SetConfig),
            x if x == CommandType::StatusA as u8 => Ok(CommandType::StatusA),
            x if x == CommandType::SetRecorderMode as u8 => Ok(CommandType::SetRecorderMode),
            x if x == CommandType::Authenticate as u8 => Ok(CommandType::Authenticate),
            _ => Err(()),
        }
    }
}

// src/protocol.rs

// ... (all the code before the Attribute enum) ...

/// Represents the `att` (Attribute) field of the command header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Attribute {
    None = 0x0000,
    Adc = 0x0001,
    AdcQueue = 0x0002,
    AdcQueue10k = 0x0004,
    Settings = 0x0008,
    PdPacket = 0x0010,
    PdStatus = 0x0020,
    SwitchToPdAnalyzer = 0x0200, // Note: This is a guess, 512 in decimal
    // Add an Unknown variant to handle the unlisted attributes like 0x0101, 0x0400 etc.
    Unknown(u16),
}

// And the new impl block
impl Attribute {
    pub fn from_u16(val: u16) -> Self {
        match val {
            0x0000 => Self::None,
            0x0001 => Self::Adc,
            0x0002 => Self::AdcQueue,
            0x0004 => Self::AdcQueue10k,
            0x0008 => Self::Settings,
            0x0010 => Self::PdPacket,
            0x0020 => Self::PdStatus,
            0x0200 => Self::SwitchToPdAnalyzer,
            // For any other value, store it in the Unknown variant.
            other => Self::Unknown(other),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            // For each field-less variant, return its explicit integer value.
            Self::None => 0x0000,
            Self::Adc => 0x0001,
            Self::AdcQueue => 0x0002,
            Self::AdcQueue10k => 0x0004,
            Self::Settings => 0x0008,
            Self::PdPacket => 0x0010,
            Self::PdStatus => 0x0020,
            Self::SwitchToPdAnalyzer => 0x0200,
            // For the variant with data, return the contained value.
            Self::Unknown(val) => *val,
        }
    }
}
