use zerocopy::byteorder::little_endian::{I32, U16};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Sample rate for AdcQueue streaming mode
///
/// Used with StartGraph (0x0E) command to configure device sampling rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum GraphSampleRate {
    /// 1 sample per second
    Sps1 = 0,
    /// 10 samples per second
    Sps10 = 1,
    /// 50 samples per second
    Sps50 = 2,
    /// 1000 samples per second
    Sps1000 = 3,
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

    /// Check for dropped samples by detecting gaps in sequence numbers
    pub fn has_dropped_samples(&self) -> bool {
        if self.samples.len() < 2 {
            return false;
        }

        for window in self.samples.windows(2) {
            let expected_next = window[0].sequence.wrapping_add(1);
            if window[1].sequence != expected_next {
                return true;
            }
        }
        false
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl AdcQueueData {
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
