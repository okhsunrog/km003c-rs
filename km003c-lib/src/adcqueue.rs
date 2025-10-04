use zerocopy::byteorder::little_endian::{I32, U16};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// AdcQueue sample structure (20 bytes)
///
/// AdcQueue provides high-rate streaming of power measurements.
/// Each sample contains basic voltage/current measurements without
/// the detailed statistics (avg, min, max) that ADC packets provide.
///
/// Typical usage: Device buffers 38-40 samples (768-808 bytes total)
/// and sends them in a single USB transfer for efficient high-rate logging.
///
/// Fields NOT included (unlike ADC):
/// - Temperature (always request ADC separately for temp)
/// - D+ voltage (USB data lines)
/// - D- voltage (USB data lines)
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct AdcQueueSampleRaw {
    /// Incrementing sequence number for detecting dropped samples
    pub sequence: U16,
    /// Marker/constant value (typically 0x3C = 60)
    pub marker: U16,
    /// VBUS voltage in microvolts (µV)
    pub vbus_uv: I32,
    /// IBUS current in microamperes (µA), signed
    pub ibus_ua: I32,
    /// CC1 line voltage in millivolts (mV)
    pub cc1_mv: U16,
    /// CC2 line voltage in millivolts (mV)  
    pub cc2_mv: U16,
    /// Reserved bytes (always 0 in observed traffic)
    pub reserved: [u8; 4],
}

/// Parsed AdcQueue sample with converted units
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AdcQueueSample {
    pub sequence: u16,
    pub vbus_v: f64,  // Volts
    pub ibus_a: f64,  // Amperes (signed)
    pub power_w: f64, // Watts (calculated)
    pub cc1_v: f64,   // Volts
    pub cc2_v: f64,   // Volts
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
            cc1_v: raw.cc1_mv.get() as f64 / 1_000.0,
            cc2_v: raw.cc2_mv.get() as f64 / 1_000.0,
        }
    }
}

/// Complete AdcQueue response containing multiple buffered samples
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AdcQueueData {
    pub samples: Vec<AdcQueueSample>,
}

impl AdcQueueData {
    /// Parse AdcQueue payload containing multiple 20-byte samples
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::KMError> {
        const SAMPLE_SIZE: usize = 20;

        if bytes.len() % SAMPLE_SIZE != 0 {
            return Err(crate::error::KMError::InvalidPacket(format!(
                "AdcQueue payload size {} is not multiple of {}",
                bytes.len(),
                SAMPLE_SIZE
            )));
        }

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
