use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::fmt;
use strum_macros::Display;
use zerocopy::byteorder::little_endian::{I16, I32, U16};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, Default, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "python", pyo3::pyclass(eq, name = "SampleRate"))]
#[repr(u8)]
pub enum SampleRate {
    #[default]
    #[strum(to_string = "2 SPS")]
    Sps2 = 0,
    #[strum(to_string = "10 SPS")]
    Sps10 = 1,
    #[strum(to_string = "50 SPS")]
    Sps50 = 2,
    #[strum(to_string = "1 kSPS")]
    Sps1000 = 3,
    #[strum(to_string = "10 kSPS")]
    Sps10000 = 4,
}

impl SampleRate {
    /// Get the sample rate in samples per second
    pub fn as_hz(&self) -> u32 {
        match self {
            SampleRate::Sps2 => 2,
            SampleRate::Sps10 => 10,
            SampleRate::Sps50 => 50,
            SampleRate::Sps1000 => 1000,
            SampleRate::Sps10000 => 10000,
        }
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl SampleRate {
    #[getter]
    fn hz(&self) -> u32 {
        self.as_hz()
    }

    #[getter]
    fn name(&self) -> String {
        self.to_string()
    }

    fn __repr__(&self) -> String {
        format!("SampleRate({})", self)
    }

    fn __str__(&self) -> String {
        self.to_string()
    }
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct AdcDataRaw {
    pub vbus_uv: I32,          // Microvolts (µV)
    pub ibus_ua: I32,          // Microamps (µA)
    pub vbus_avg_uv: I32,      // Microvolts (µV)
    pub ibus_avg_ua: I32,      // Microamps (µA)
    pub vbus_ori_avg_raw: I32, // Uncalibrated
    pub ibus_ori_avg_raw: I32, // Uncalibrated
    // Temperature register, LSB = 1/128 °C (7.8125 m°C)
    pub temp_raw: I16,
    pub vcc1_tenth_mv: U16,    // 0.1 millivolts
    pub vcc2_raw: U16,         // 0.1 millivolts (instantaneous)
    pub vdp_mv: U16,           // 0.1 millivolts (instantaneous)
    pub vdm_mv: U16,           // 0.1 millivolts (instantaneous)
    pub internal_vdd_raw: U16, // Internal VDD (0.1 millivolts)
    pub rate_raw: u8,          // Sample rate index
    pub reserved: u8,          // Vendor flags (observed 128)
    pub vcc2_avg_raw: U16,     // 1 millivolt (averaged)
    pub vdp_avg_mv: U16,       // 1 millivolt (averaged)
    pub vdm_avg_mv: U16,       // 1 millivolt (averaged)
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "python", pyo3::pyclass(get_all, name = "AdcData"))]
pub struct AdcDataSimple {
    // Main measurements
    pub vbus_v: f64, // Voltage in Volts
    /// Current in amperes. Sign indicates power flow direction through the tester:
    /// - Positive: Power flows from USB female (input) to USB male (output)
    /// - Negative: Power flows from USB male (input) to USB female (output)
    pub ibus_a: f64, // Current in Amperes
    /// Power in watts. Sign indicates power flow direction through the tester:
    /// - Positive: Power flows from USB female (input) to USB male (output)
    /// - Negative: Power flows from USB male (input) to USB female (output)
    pub power_w: f64, // Power in Watts

    // Averaged measurements
    pub vbus_avg_v: f64, // Average voltage in Volts
    pub ibus_avg_a: f64, // Average current in Amperes

    // Temperature
    pub temp_c: f64, // Temperature in Celsius

    // USB data lines
    pub vdp_v: f64,     // D+ voltage in Volts
    pub vdm_v: f64,     // D- voltage in Volts
    pub vdp_avg_v: f64, // Average D+ voltage in Volts
    pub vdm_avg_v: f64, // Average D- voltage in Volts

    // USB CC lines
    pub cc1_v: f64,     // CC1 voltage in Volts
    pub cc2_v: f64,     // CC2 voltage in Volts
    pub cc2_avg_v: f64, // Average CC2 voltage in Volts

    // Internal voltage
    pub internal_vdd_v: f64, // Internal VDD in Volts

    // Sample rate
    pub sample_rate: SampleRate, // Sample rate as enum
}

impl From<AdcDataRaw> for AdcDataSimple {
    fn from(raw: AdcDataRaw) -> Self {
        // Convert voltage from µV to V
        let vbus_v = raw.vbus_uv.get() as f64 / 1_000_000.0;
        let ibus_a = raw.ibus_ua.get() as f64 / 1_000_000.0;
        let power_w = vbus_v * ibus_a;

        let vbus_avg_v = raw.vbus_avg_uv.get() as f64 / 1_000_000.0;
        let ibus_avg_a = raw.ibus_avg_ua.get() as f64 / 1_000_000.0;

        // Convert temperature using INA228/9 formula
        // LSB = 1/128 °C → temperature in °C = raw / 128.0
        let temp_c = raw.temp_raw.get() as f64 / 128.0;

        // Convert from 0.1mV to V (divide by 10,000)
        let vdp_v = raw.vdp_mv.get() as f64 / 10_000.0;
        let vdm_v = raw.vdm_mv.get() as f64 / 10_000.0;
        // Averaged D+/D- are in 1 mV units
        let vdp_avg_v = raw.vdp_avg_mv.get() as f64 / 1_000.0;
        let vdm_avg_v = raw.vdm_avg_mv.get() as f64 / 1_000.0;

        // CC lines also use the 0.1mV unit
        let cc1_v = raw.vcc1_tenth_mv.get() as f64 / 10_000.0;
        let cc2_v = raw.vcc2_raw.get() as f64 / 10_000.0;
        // Averaged CC2 is in 1 mV units
        let cc2_avg_v = raw.vcc2_avg_raw.get() as f64 / 1_000.0;

        // Internal VDD also uses 0.1mV
        let internal_vdd_v = raw.internal_vdd_raw.get() as f64 / 10_000.0;

        // Convert raw sample rate to enum (safely, fallback to 2 SPS if invalid)
        let sample_rate = SampleRate::try_from(raw.rate_raw).unwrap_or(SampleRate::Sps2);

        AdcDataSimple {
            vbus_v,
            ibus_a,
            power_w,
            vbus_avg_v,
            ibus_avg_a,
            temp_c,
            vdp_v,
            vdm_v,
            vdp_avg_v,
            vdm_avg_v,
            cc1_v,
            cc2_v,
            cc2_avg_v,
            internal_vdd_v,
            sample_rate,
        }
    }
}

impl From<AdcDataSimple> for AdcDataRaw {
    fn from(data: AdcDataSimple) -> Self {
        AdcDataRaw {
            vbus_uv: I32::new((data.vbus_v * 1_000_000.0) as i32),
            ibus_ua: I32::new((data.ibus_a * 1_000_000.0) as i32),
            vbus_avg_uv: I32::new((data.vbus_avg_v * 1_000_000.0) as i32),
            ibus_avg_ua: I32::new((data.ibus_avg_a * 1_000_000.0) as i32),
            vbus_ori_avg_raw: I32::new(0), // We don't have this information
            ibus_ori_avg_raw: I32::new(0), // We don't have this information
            // Encode temperature back to raw register: °C * 128
            temp_raw: I16::new((data.temp_c * 128.0) as i16),
            vcc1_tenth_mv: U16::new((data.cc1_v * 10_000.0) as u16),
            vcc2_raw: U16::new((data.cc2_v * 10_000.0) as u16),
            vdp_mv: U16::new((data.vdp_v * 10_000.0) as u16),
            vdm_mv: U16::new((data.vdm_v * 10_000.0) as u16),
            internal_vdd_raw: U16::new((data.internal_vdd_v * 10_000.0) as u16),
            rate_raw: data.sample_rate as u8,
            reserved: 0,
            // Store averaged fields in 1 mV units
            vcc2_avg_raw: U16::new((data.cc2_avg_v * 1_000.0) as u16),
            vdp_avg_mv: U16::new((data.vdp_avg_v * 1_000.0) as u16),
            vdm_avg_mv: U16::new((data.vdm_avg_v * 1_000.0) as u16),
        }
    }
}

impl AdcDataSimple {
    /// Get the absolute current in amperes (magnitude regardless of direction)
    pub fn current_abs_a(&self) -> f64 {
        self.ibus_a.abs()
    }

    /// Get the absolute power in watts (magnitude regardless of direction)
    pub fn power_abs_w(&self) -> f64 {
        self.power_w.abs()
    }
}

impl fmt::Display for AdcDataSimple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VBUS: {:.3} V, IBUS: {:.3} A, Power: {:.3} W, Temp: {:.1} °C, Rate: {}",
            self.vbus_v, self.ibus_a, self.power_w, self.temp_c, self.sample_rate
        )
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl AdcDataSimple {
    fn __repr__(&self) -> String {
        format!(
            "AdcData(vbus={:.3}V, ibus={:.3}A, power={:.3}W, temp={:.1}°C)",
            self.vbus_v, self.ibus_a, self.power_w, self.temp_c
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}
