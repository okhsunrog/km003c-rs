use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::fmt;
use strum_macros::Display;
use uom::si::electric_current::{ampere, microampere};
use uom::si::electric_potential::{microvolt, millivolt, volt};
use uom::si::f64::{ElectricCurrent, ElectricPotential, Frequency, Power, ThermodynamicTemperature};
use uom::si::frequency::hertz;
use uom::si::power::watt;
use uom::si::thermodynamic_temperature::degree_celsius;
use zerocopy::byteorder::little_endian::{I16, I32, U16};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, Default, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "python", pyo3::pyclass(eq, skip_from_py_object, name = "SampleRate"))]
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
    pub fn frequency(self) -> Frequency {
        Frequency::new::<hertz>(match self {
            Self::Sps2 => 2.0,
            Self::Sps10 => 10.0,
            Self::Sps50 => 50.0,
            Self::Sps1000 => 1_000.0,
            Self::Sps10000 => 10_000.0,
        })
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl SampleRate {
    #[getter]
    fn hz(&self) -> f64 {
        self.frequency().get::<hertz>()
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
#[cfg_attr(feature = "python", pyo3::pyclass(skip_from_py_object, name = "AdcData"))]
pub struct AdcDataSimple {
    // Main measurements
    pub vbus: ElectricPotential,
    /// Current in amperes. Sign indicates power flow direction through the tester:
    /// - Positive: Power flows from USB female (input) to USB male (output)
    /// - Negative: Power flows from USB male (input) to USB female (output)
    pub ibus: ElectricCurrent,
    /// Power in watts. Sign indicates power flow direction through the tester:
    /// - Positive: Power flows from USB female (input) to USB male (output)
    /// - Negative: Power flows from USB male (input) to USB female (output)
    pub power: Power,

    // Averaged measurements
    pub vbus_average: ElectricPotential,
    pub ibus_average: ElectricCurrent,
    /// Uncalibrated VBUS average preserved verbatim from the device.
    pub vbus_uncalibrated_average_raw: i32,
    /// Uncalibrated IBUS average preserved verbatim from the device.
    pub ibus_uncalibrated_average_raw: i32,

    // Temperature
    pub temperature: ThermodynamicTemperature,

    // USB data lines
    pub vdp: ElectricPotential,
    pub vdm: ElectricPotential,
    pub vdp_average: ElectricPotential,
    pub vdm_average: ElectricPotential,

    // USB CC lines
    pub cc1: ElectricPotential,
    pub cc2: ElectricPotential,
    pub cc2_average: ElectricPotential,

    // Internal voltage
    pub internal_vdd: ElectricPotential,

    /// Known sample rate, or `None` when the device reports an unknown index.
    pub sample_rate: Option<SampleRate>,
    /// Original sample-rate index, retained for lossless parsing and serialization.
    pub sample_rate_raw: u8,
    /// Opaque vendor flags preserved from the ADC payload.
    pub vendor_flags: u8,
}

impl From<AdcDataRaw> for AdcDataSimple {
    fn from(raw: AdcDataRaw) -> Self {
        let vbus = ElectricPotential::new::<microvolt>(f64::from(raw.vbus_uv.get()));
        let ibus = ElectricCurrent::new::<microampere>(f64::from(raw.ibus_ua.get()));

        let sample_rate = SampleRate::try_from(raw.rate_raw).ok();

        AdcDataSimple {
            vbus,
            ibus,
            power: vbus * ibus,
            vbus_average: ElectricPotential::new::<microvolt>(f64::from(raw.vbus_avg_uv.get())),
            ibus_average: ElectricCurrent::new::<microampere>(f64::from(raw.ibus_avg_ua.get())),
            vbus_uncalibrated_average_raw: raw.vbus_ori_avg_raw.get(),
            ibus_uncalibrated_average_raw: raw.ibus_ori_avg_raw.get(),
            temperature: ThermodynamicTemperature::new::<degree_celsius>(f64::from(raw.temp_raw.get()) / 128.0),
            vdp: ElectricPotential::new::<millivolt>(f64::from(raw.vdp_mv.get()) / 10.0),
            vdm: ElectricPotential::new::<millivolt>(f64::from(raw.vdm_mv.get()) / 10.0),
            vdp_average: ElectricPotential::new::<millivolt>(f64::from(raw.vdp_avg_mv.get())),
            vdm_average: ElectricPotential::new::<millivolt>(f64::from(raw.vdm_avg_mv.get())),
            cc1: ElectricPotential::new::<millivolt>(f64::from(raw.vcc1_tenth_mv.get()) / 10.0),
            cc2: ElectricPotential::new::<millivolt>(f64::from(raw.vcc2_raw.get()) / 10.0),
            cc2_average: ElectricPotential::new::<millivolt>(f64::from(raw.vcc2_avg_raw.get())),
            internal_vdd: ElectricPotential::new::<millivolt>(f64::from(raw.internal_vdd_raw.get()) / 10.0),
            sample_rate,
            sample_rate_raw: raw.rate_raw,
            vendor_flags: raw.reserved,
        }
    }
}

impl From<AdcDataSimple> for AdcDataRaw {
    fn from(data: AdcDataSimple) -> Self {
        AdcDataRaw {
            vbus_uv: I32::new(data.vbus.get::<microvolt>().round() as i32),
            ibus_ua: I32::new(data.ibus.get::<microampere>().round() as i32),
            vbus_avg_uv: I32::new(data.vbus_average.get::<microvolt>().round() as i32),
            ibus_avg_ua: I32::new(data.ibus_average.get::<microampere>().round() as i32),
            vbus_ori_avg_raw: I32::new(data.vbus_uncalibrated_average_raw),
            ibus_ori_avg_raw: I32::new(data.ibus_uncalibrated_average_raw),
            // Encode temperature back to raw register: °C * 128
            temp_raw: I16::new((data.temperature.get::<degree_celsius>() * 128.0).round() as i16),
            vcc1_tenth_mv: U16::new((data.cc1.get::<millivolt>() * 10.0).round() as u16),
            vcc2_raw: U16::new((data.cc2.get::<millivolt>() * 10.0).round() as u16),
            vdp_mv: U16::new((data.vdp.get::<millivolt>() * 10.0).round() as u16),
            vdm_mv: U16::new((data.vdm.get::<millivolt>() * 10.0).round() as u16),
            internal_vdd_raw: U16::new((data.internal_vdd.get::<millivolt>() * 10.0).round() as u16),
            rate_raw: data.sample_rate.map_or(data.sample_rate_raw, u8::from),
            reserved: data.vendor_flags,
            // Store averaged fields in 1 mV units
            vcc2_avg_raw: U16::new(data.cc2_average.get::<millivolt>().round() as u16),
            vdp_avg_mv: U16::new(data.vdp_average.get::<millivolt>().round() as u16),
            vdm_avg_mv: U16::new(data.vdm_average.get::<millivolt>().round() as u16),
        }
    }
}

impl AdcDataSimple {
    /// Get the absolute current in amperes (magnitude regardless of direction)
    pub fn current_abs(&self) -> ElectricCurrent {
        self.ibus.abs()
    }

    /// Get the absolute power in watts (magnitude regardless of direction)
    pub fn power_abs(&self) -> Power {
        self.power.abs()
    }
}

impl fmt::Display for AdcDataSimple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VBUS: {:.3} V, IBUS: {:.3} A, Power: {:.3} W, Temp: {:.1} °C, Rate: {}",
            self.vbus.get::<volt>(),
            self.ibus.get::<ampere>(),
            self.power.get::<watt>(),
            self.temperature.get::<degree_celsius>(),
            self.sample_rate.map_or_else(
                || format!("Unknown ({})", self.sample_rate_raw),
                |rate| rate.to_string()
            )
        )
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl AdcDataSimple {
    #[getter]
    fn vbus_v(&self) -> f64 {
        self.vbus.get::<volt>()
    }
    #[getter]
    fn ibus_a(&self) -> f64 {
        self.ibus.get::<ampere>()
    }
    #[getter]
    fn power_w(&self) -> f64 {
        self.power.get::<watt>()
    }
    #[getter]
    fn vbus_avg_v(&self) -> f64 {
        self.vbus_average.get::<volt>()
    }
    #[getter]
    fn ibus_avg_a(&self) -> f64 {
        self.ibus_average.get::<ampere>()
    }
    #[getter]
    fn temp_c(&self) -> f64 {
        self.temperature.get::<degree_celsius>()
    }
    #[getter]
    fn vdp_v(&self) -> f64 {
        self.vdp.get::<volt>()
    }
    #[getter]
    fn vdm_v(&self) -> f64 {
        self.vdm.get::<volt>()
    }
    #[getter]
    fn vdp_avg_v(&self) -> f64 {
        self.vdp_average.get::<volt>()
    }
    #[getter]
    fn vdm_avg_v(&self) -> f64 {
        self.vdm_average.get::<volt>()
    }
    #[getter]
    fn cc1_v(&self) -> f64 {
        self.cc1.get::<volt>()
    }
    #[getter]
    fn cc2_v(&self) -> f64 {
        self.cc2.get::<volt>()
    }
    #[getter]
    fn cc2_avg_v(&self) -> f64 {
        self.cc2_average.get::<volt>()
    }
    #[getter]
    fn internal_vdd_v(&self) -> f64 {
        self.internal_vdd.get::<volt>()
    }
    #[getter]
    fn sample_rate(&self) -> Option<SampleRate> {
        self.sample_rate
    }
    #[getter]
    fn sample_rate_raw(&self) -> u8 {
        self.sample_rate_raw
    }
    #[getter]
    fn vendor_flags(&self) -> u8 {
        self.vendor_flags
    }
    #[getter]
    fn vbus_uncalibrated_average_raw(&self) -> i32 {
        self.vbus_uncalibrated_average_raw
    }
    #[getter]
    fn ibus_uncalibrated_average_raw(&self) -> i32 {
        self.ibus_uncalibrated_average_raw
    }

    fn __repr__(&self) -> String {
        format!(
            "AdcData(vbus={:.3}V, ibus={:.3}A, power={:.3}W, temp={:.1}°C)",
            self.vbus.get::<volt>(),
            self.ibus.get::<ampere>(),
            self.power.get::<watt>(),
            self.temperature.get::<degree_celsius>()
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}
