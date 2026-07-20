use num_enum::TryFromPrimitive;
use std::fmt;
use uom::si::electric_current::microampere;
use uom::si::electric_potential::{microvolt, millivolt};
use uom::si::f64::{ElectricCurrent, ElectricPotential, Frequency, Power, Time};
use uom::si::frequency::hertz;
use uom::si::time::millisecond;
use zerocopy::byteorder::little_endian::{I32, U16};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "python")]
use uom::si::{electric_current::ampere, electric_potential::volt, power::watt};

/// Sample rate for AdcQueue streaming mode
///
/// Used with StartGraph (0x0E) command to configure device sampling rate.
/// The device expects the rate index directly (0-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u16)]
pub enum GraphSampleRate {
    /// 2 samples per second
    Sps2 = 0,
    /// 10 samples per second
    Sps10 = 1,
    /// 50 samples per second
    Sps50 = 2,
    /// 1000 samples per second
    Sps1000 = 3,
}

impl GraphSampleRate {
    const SEQUENCE_TICKS_PER_SECOND: u16 = 1000;

    const fn sample_count_per_second(self) -> u16 {
        match self {
            Self::Sps2 => 2,
            Self::Sps10 => 10,
            Self::Sps50 => 50,
            Self::Sps1000 => 1000,
        }
    }

    /// Expected increment of the device's 1000 Hz sequence counter.
    pub const fn sequence_step(self) -> u16 {
        Self::SEQUENCE_TICKS_PER_SECOND / self.sample_count_per_second()
    }

    /// Sampling frequency represented as a typed physical quantity.
    pub fn frequency(self) -> Frequency {
        Frequency::new::<hertz>(f64::from(self.sample_count_per_second()))
    }

    /// Frequency of the wrapping sequence counter used by graph samples.
    pub fn sequence_counter_frequency() -> Frequency {
        Frequency::new::<hertz>(f64::from(Self::SEQUENCE_TICKS_PER_SECOND))
    }

    /// Voltage represented by one auxiliary-line raw count.
    ///
    /// Recorded traffic and measurements against firmware 1.9.9 show that
    /// 2 SPS uses 0.1 mV units, while faster graph modes use 1 mV units.
    pub fn auxiliary_voltage_lsb(self) -> ElectricPotential {
        match self {
            Self::Sps2 => ElectricPotential::new::<millivolt>(0.1),
            Self::Sps10 | Self::Sps50 | Self::Sps1000 => ElectricPotential::new::<millivolt>(1.0),
        }
    }

    /// Infer the configured rate from a contiguous sequence-counter step.
    pub const fn from_sequence_step(step: u16) -> Option<Self> {
        match step {
            500 => Some(Self::Sps2),
            100 => Some(Self::Sps10),
            20 => Some(Self::Sps50),
            1 => Some(Self::Sps1000),
            _ => None,
        }
    }

    /// Number of samples missing between two sequence counter values.
    pub fn missing_samples(self, previous: u16, current: u16) -> u16 {
        let elapsed_ticks = current.wrapping_sub(previous);
        elapsed_ticks.saturating_sub(self.sequence_step()) / self.sequence_step()
    }
}

/// Elapsed device time between two values of the wrapping AdcQueue sequence counter.
pub fn sequence_elapsed(previous: u16, current: u16) -> Time {
    let elapsed_ticks = current.wrapping_sub(previous);
    Time::new::<millisecond>(f64::from(elapsed_ticks))
}

impl fmt::Display for GraphSampleRate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sps2 => write!(f, "2 SPS"),
            Self::Sps10 => write!(f, "10 SPS"),
            Self::Sps50 => write!(f, "50 SPS"),
            Self::Sps1000 => write!(f, "1000 SPS"),
        }
    }
}

/// AdcQueue sample structure (20 bytes)
///
/// AdcQueue provides high-rate streaming of power measurements.
/// Each sample contains voltage/current measurements for all major lines
/// (VBUS, IBUS, CC1, CC2, D+, D-) but without statistics or temperature.
///
/// Typical usage: Device buffers 5-48 samples and sends them in a single
/// USB transfer for efficient high-rate logging (up to 1000 SPS).
///
/// Fields NOT included (unlike ADC):
/// - Temperature (always request ADC separately for temp)
/// - Statistics (min/max/avg)
/// - VDD (internal voltage)
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct AdcQueueSampleWire {
    /// Incrementing sequence number for detecting dropped samples
    pub sequence: U16,
    /// Marker/flags field (varies by firmware version and mode, not temperature)
    pub marker: U16,
    /// VBUS voltage in microvolts (µV)
    pub vbus_uv: I32,
    /// IBUS current in microamperes (µA), signed
    pub ibus_ua: I32,
    /// CC1 line voltage; units depend on the configured graph sample rate
    pub cc1_raw: U16,
    /// CC2 line voltage; units depend on the configured graph sample rate
    pub cc2_raw: U16,
    /// D+ line voltage; units depend on the configured graph sample rate
    pub vdp_raw: U16,
    /// D- line voltage; units depend on the configured graph sample rate
    pub vdm_raw: U16,
}

/// Lossless raw AdcQueue sample.
///
/// The four auxiliary-line fields are device counts rather than voltages.
/// Converting them requires the sample rate selected by `StartGraph`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "python", pyo3::pyclass(get_all, skip_from_py_object))]
pub struct AdcQueueSampleRaw {
    pub sequence: u16,
    pub marker: u16,
    pub vbus_uv: i32,
    pub ibus_ua: i32,
    pub cc1_raw: u16,
    pub cc2_raw: u16,
    pub vdp_raw: u16,
    pub vdm_raw: u16,
}

impl From<AdcQueueSampleWire> for AdcQueueSampleRaw {
    fn from(raw: AdcQueueSampleWire) -> Self {
        Self {
            sequence: raw.sequence.get(),
            marker: raw.marker.get(),
            vbus_uv: raw.vbus_uv.get(),
            ibus_ua: raw.ibus_ua.get(),
            cc1_raw: raw.cc1_raw.get(),
            cc2_raw: raw.cc2_raw.get(),
            vdp_raw: raw.vdp_raw.get(),
            vdm_raw: raw.vdm_raw.get(),
        }
    }
}

impl From<AdcQueueSampleRaw> for AdcQueueSampleWire {
    fn from(raw: AdcQueueSampleRaw) -> Self {
        Self {
            sequence: U16::new(raw.sequence),
            marker: U16::new(raw.marker),
            vbus_uv: I32::new(raw.vbus_uv),
            ibus_ua: I32::new(raw.ibus_ua),
            cc1_raw: U16::new(raw.cc1_raw),
            cc2_raw: U16::new(raw.cc2_raw),
            vdp_raw: U16::new(raw.vdp_raw),
            vdm_raw: U16::new(raw.vdm_raw),
        }
    }
}

/// AdcQueue payload parsed without guessing the graph sample rate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "python", pyo3::pyclass(skip_from_py_object))]
pub struct AdcQueueRawData {
    pub samples: Vec<AdcQueueSampleRaw>,
}

impl AdcQueueRawData {
    const SAMPLE_SIZE: usize = 20;

    /// Parse a payload losslessly without assigning units to auxiliary counts.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::KMError> {
        if !bytes.len().is_multiple_of(Self::SAMPLE_SIZE) {
            return Err(crate::error::KMError::InvalidPacket(format!(
                "AdcQueue payload length must be a multiple of {}, got {}",
                Self::SAMPLE_SIZE,
                bytes.len()
            )));
        }

        let samples = bytes
            .chunks_exact(Self::SAMPLE_SIZE)
            .map(|sample| {
                AdcQueueSampleWire::ref_from_bytes(sample)
                    .map(|wire| AdcQueueSampleRaw::from(*wire))
                    .map_err(|_| crate::error::KMError::InvalidPacket("Failed to parse AdcQueue sample".to_string()))
            })
            .collect::<Result<_, _>>()?;

        Ok(Self { samples })
    }

    /// Convert raw auxiliary counts using an explicitly known graph rate.
    pub fn decode(&self, rate: GraphSampleRate) -> AdcQueueData {
        AdcQueueData {
            rate,
            samples: self
                .samples
                .iter()
                .copied()
                .map(|sample| AdcQueueSample::from_raw(sample, rate))
                .collect(),
        }
    }

    pub fn sequence_range(&self) -> Option<(u16, u16)> {
        self.samples
            .first()
            .zip(self.samples.last())
            .map(|(first, last)| (first.sequence, last.sequence))
    }

    pub fn has_dropped_samples(&self, rate: GraphSampleRate) -> bool {
        self.samples
            .windows(2)
            .any(|window| rate.missing_samples(window[0].sequence, window[1].sequence) > 0)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.samples
            .iter()
            .copied()
            .flat_map(|sample| AdcQueueSampleWire::from(sample).as_bytes().to_vec())
            .collect()
    }
}

/// Parsed AdcQueue sample with converted units
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "python", pyo3::pyclass(skip_from_py_object, name = "AdcQueueSample"))]
pub struct AdcQueueSample {
    pub sequence: u16,
    /// Opaque device marker/flags preserved from the wire sample.
    pub marker: u16,
    pub vbus: ElectricPotential,
    pub ibus: ElectricCurrent,
    pub power: Power,
    pub cc1: ElectricPotential,
    pub cc2: ElectricPotential,
    pub vdp: ElectricPotential,
    pub vdm: ElectricPotential,
}

impl AdcQueueSample {
    /// Convert a raw sample using the units for the configured graph rate.
    pub fn from_raw(raw: AdcQueueSampleRaw, rate: GraphSampleRate) -> Self {
        let vbus = ElectricPotential::new::<microvolt>(f64::from(raw.vbus_uv));
        let ibus = ElectricCurrent::new::<microampere>(f64::from(raw.ibus_ua));
        let auxiliary_voltage_lsb = rate.auxiliary_voltage_lsb();

        Self {
            sequence: raw.sequence,
            marker: raw.marker,
            vbus,
            ibus,
            power: vbus * ibus,
            cc1: auxiliary_voltage_lsb * f64::from(raw.cc1_raw),
            cc2: auxiliary_voltage_lsb * f64::from(raw.cc2_raw),
            vdp: auxiliary_voltage_lsb * f64::from(raw.vdp_raw),
            vdm: auxiliary_voltage_lsb * f64::from(raw.vdm_raw),
        }
    }
}

/// Complete AdcQueue response containing multiple buffered samples
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "python", pyo3::pyclass(skip_from_py_object, name = "AdcQueueData"))]
pub struct AdcQueueData {
    pub rate: GraphSampleRate,
    pub samples: Vec<AdcQueueSample>,
}

impl AdcQueueData {
    /// Parse AdcQueue payload using the explicitly configured graph rate.
    pub fn from_bytes_with_rate(bytes: &[u8], rate: GraphSampleRate) -> Result<Self, crate::error::KMError> {
        Ok(AdcQueueRawData::from_bytes(bytes)?.decode(rate))
    }

    /// Get the sequence number range of samples in this queue
    pub fn sequence_range(&self) -> Option<(u16, u16)> {
        self.samples
            .first()
            .zip(self.samples.last())
            .map(|(first, last)| (first.sequence, last.sequence))
    }

    /// Check for dropped samples using the configured graph rate.
    pub fn has_dropped_samples(&self) -> bool {
        self.samples
            .windows(2)
            .any(|window| self.rate.missing_samples(window[0].sequence, window[1].sequence) > 0)
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl AdcQueueRawData {
    #[getter]
    fn samples(&self) -> Vec<AdcQueueSampleRaw> {
        self.samples.clone()
    }

    #[pyo3(name = "sequence_range")]
    fn py_sequence_range(&self) -> Option<(u16, u16)> {
        self.sequence_range()
    }

    #[pyo3(name = "has_dropped_samples")]
    fn py_has_dropped_samples(&self, rate_index: u16) -> pyo3::PyResult<bool> {
        let rate = GraphSampleRate::try_from(rate_index).map_err(|_| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid graph sample rate index: {rate_index}"))
        })?;
        Ok(self.has_dropped_samples(rate))
    }

    /// Decode auxiliary-line counts using an explicitly known graph rate.
    #[pyo3(name = "decode")]
    fn py_decode(&self, rate_index: u16) -> pyo3::PyResult<AdcQueueData> {
        let rate = GraphSampleRate::try_from(rate_index).map_err(|_| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid graph sample rate index: {rate_index}"))
        })?;
        Ok(self.decode(rate))
    }

    fn __repr__(&self) -> String {
        format!("AdcQueueRawData({} samples)", self.samples.len())
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl AdcQueueData {
    #[getter]
    fn rate_index(&self) -> u16 {
        self.rate as u16
    }

    #[getter]
    fn samples(&self) -> Vec<AdcQueueSample> {
        self.samples.clone()
    }

    #[pyo3(name = "sequence_range")]
    fn py_sequence_range(&self) -> Option<(u16, u16)> {
        self.sequence_range()
    }

    #[pyo3(name = "has_dropped_samples")]
    fn py_has_dropped_samples(&self) -> bool {
        self.has_dropped_samples()
    }

    fn __repr__(&self) -> String {
        format!("AdcQueueData({} samples)", self.samples.len())
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl AdcQueueSample {
    #[getter]
    fn sequence(&self) -> u16 {
        self.sequence
    }
    #[getter]
    fn marker(&self) -> u16 {
        self.marker
    }
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
    fn cc1_v(&self) -> f64 {
        self.cc1.get::<volt>()
    }
    #[getter]
    fn cc2_v(&self) -> f64 {
        self.cc2.get::<volt>()
    }
    #[getter]
    fn vdp_v(&self) -> f64 {
        self.vdp.get::<volt>()
    }
    #[getter]
    fn vdm_v(&self) -> f64 {
        self.vdm.get::<volt>()
    }

    fn __repr__(&self) -> String {
        format!(
            "AdcQueueSample(seq={}, vbus={:.3}V, ibus={:.3}A, power={:.3}W)",
            self.sequence,
            self.vbus.get::<volt>(),
            self.ibus.get::<ampere>(),
            self.power.get::<watt>()
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}
