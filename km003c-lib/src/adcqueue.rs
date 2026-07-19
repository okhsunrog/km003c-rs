use num_enum::TryFromPrimitive;
use std::fmt;
use std::time::Duration;
use zerocopy::byteorder::little_endian::{I32, U16};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Sample rate for AdcQueue streaming mode
///
/// Used with StartGraph (0x0E) command to configure device sampling rate.
/// The device expects the rate index directly (0-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
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
    pub const SEQUENCE_TICKS_PER_SECOND: u16 = 1000;

    /// Number of samples produced by the device each second.
    pub const fn samples_per_second(self) -> u16 {
        match self {
            Self::Sps2 => 2,
            Self::Sps10 => 10,
            Self::Sps50 => 50,
            Self::Sps1000 => 1000,
        }
    }

    /// Expected increment of the device's 1000 Hz sequence counter.
    pub const fn sequence_step(self) -> u16 {
        Self::SEQUENCE_TICKS_PER_SECOND / self.samples_per_second()
    }

    /// Number of samples missing between two sequence counter values.
    pub fn missing_samples(self, previous: u16, current: u16) -> u16 {
        let elapsed_ticks = current.wrapping_sub(previous);
        elapsed_ticks.saturating_sub(self.sequence_step()) / self.sequence_step()
    }
}

/// Elapsed device time between two values of the wrapping AdcQueue sequence counter.
pub fn sequence_elapsed(previous: u16, current: u16) -> Duration {
    let elapsed_ticks = current.wrapping_sub(previous);
    Duration::from_secs_f64(f64::from(elapsed_ticks) / f64::from(GraphSampleRate::SEQUENCE_TICKS_PER_SECOND))
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
pub struct AdcQueueSampleRaw {
    /// Incrementing sequence number for detecting dropped samples
    pub sequence: U16,
    /// Marker/flags field (varies by firmware version and mode, not temperature)
    pub marker: U16,
    /// VBUS voltage in microvolts (µV)
    pub vbus_uv: I32,
    /// IBUS current in microamperes (µA), signed
    pub ibus_ua: I32,
    /// CC1 line voltage in 0.1 millivolt units (divide by 10000 for volts)
    pub cc1_tenth_mv: U16,
    /// CC2 line voltage in 0.1 millivolt units (divide by 10000 for volts)
    pub cc2_tenth_mv: U16,
    /// D+ line voltage in 0.1 millivolt units (divide by 10000 for volts)
    pub vdp_tenth_mv: U16,
    /// D- line voltage in 0.1 millivolt units (divide by 10000 for volts)
    pub vdm_tenth_mv: U16,
}

/// Parsed AdcQueue sample with converted units
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "python", pyo3::pyclass(get_all, name = "AdcQueueSample"))]
pub struct AdcQueueSample {
    pub sequence: u16,
    pub vbus_v: f64,  // Volts
    pub ibus_a: f64,  // Amperes (signed)
    pub power_w: f64, // Watts (calculated)
    pub cc1_v: f64,   // Volts (CC1 line)
    pub cc2_v: f64,   // Volts (CC2 line)
    pub vdp_v: f64,   // Volts (USB D+ line)
    pub vdm_v: f64,   // Volts (USB D- line)
}

impl From<AdcQueueSampleRaw> for AdcQueueSample {
    fn from(raw: AdcQueueSampleRaw) -> Self {
        let vbus_v = raw.vbus_uv.get() as f64 / 1_000_000.0;
        let ibus_a = raw.ibus_ua.get() as f64 / 1_000_000.0;
        let power_w = vbus_v * ibus_a;

        Self {
            sequence: raw.sequence.get(),
            vbus_v,
            ibus_a,
            power_w,
            // All voltage fields use 0.1mV units (same as ADC structure)
            cc1_v: raw.cc1_tenth_mv.get() as f64 / 10_000.0,
            cc2_v: raw.cc2_tenth_mv.get() as f64 / 10_000.0,
            vdp_v: raw.vdp_tenth_mv.get() as f64 / 10_000.0,
            vdm_v: raw.vdm_tenth_mv.get() as f64 / 10_000.0,
        }
    }
}

/// Complete AdcQueue response containing multiple buffered samples
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "python", pyo3::pyclass(get_all, name = "AdcQueueData"))]
pub struct AdcQueueData {
    pub samples: Vec<AdcQueueSample>,
}

impl AdcQueueData {
    /// Parse AdcQueue payload containing multiple 20-byte samples
    ///
    /// Note: Some firmware versions may return payloads not divisible by 20.
    /// In this case, we parse as many complete samples as possible.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::KMError> {
        const SAMPLE_SIZE: usize = 20;

        // Take as many complete samples as we can
        let num_samples = bytes.len() / SAMPLE_SIZE;
        let mut samples = Vec::with_capacity(num_samples);

        for i in 0..num_samples {
            let offset = i * SAMPLE_SIZE;
            let sample_raw = AdcQueueSampleRaw::ref_from_bytes(&bytes[offset..offset + SAMPLE_SIZE])
                .map_err(|_| crate::error::KMError::InvalidPacket("Failed to parse AdcQueue sample".to_string()))?;

            samples.push(AdcQueueSample::from(*sample_raw));
        }

        Ok(Self { samples })
    }

    /// Get the sequence number range of samples in this queue
    pub fn sequence_range(&self) -> Option<(u16, u16)> {
        if self.samples.is_empty() {
            None
        } else {
            Some((
                self.samples.first().unwrap().sequence,
                self.samples.last().unwrap().sequence,
            ))
        }
    }

    /// Check for dropped samples using the sequence step for `rate`.
    pub fn has_dropped_samples(&self, rate: GraphSampleRate) -> bool {
        self.samples
            .windows(2)
            .any(|window| rate.missing_samples(window[0].sequence, window[1].sequence) > 0)
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl AdcQueueData {
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
    fn __repr__(&self) -> String {
        format!(
            "AdcQueueSample(seq={}, vbus={:.3}V, ibus={:.3}A, power={:.3}W)",
            self.sequence, self.vbus_v, self.ibus_a, self.power_w
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}
