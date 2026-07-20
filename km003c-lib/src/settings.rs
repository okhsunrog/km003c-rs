//! Read-only parsing for the two persisted KM003C settings blocks.

use uom::si::f64::{Ratio, Time};
use uom::si::ratio::percent;
use uom::si::time::microsecond;

use crate::error::KMError;

/// Size of the first independently checksummed settings block.
pub const SETTINGS_A_SIZE: usize = 96;
/// Size of the second independently checksummed settings block.
pub const SETTINGS_B_SIZE: usize = 84;
/// Combined payload size returned by GetData(Settings).
pub const SETTINGS_SIZE: usize = SETTINGS_A_SIZE + SETTINGS_B_SIZE;

const SETTINGS_A_CHECKSUM_OFFSET: usize = 0x5c;
const SETTINGS_B_OFFSET: usize = SETTINGS_A_SIZE;
const SETTINGS_B_CHECKSUM_OFFSET: usize = SETTINGS_B_OFFSET + 0x50;
const SAMPLE_INTERVAL_OFFSET: usize = 0x08;
const DEVICE_NAME_OFFSET: usize = 0x70;
const DEVICE_NAME_END: usize = 0xb0;

const LANGUAGE_SELECTION_MASK: u32 = 1;
const UNCALIBRATED_MASK: u32 = 1 << 2;
const BRIGHTNESS_SHIFT: u32 = 3;
const BRIGHTNESS_MASK: u32 = 0x7f << BRIGHTNESS_SHIFT;
const ORIENTATION_MASK: u32 = 0b11;
const MTOOLS_DEVICE_MODE_SHIFT: u32 = 2;
const MTOOLS_DEVICE_MODE_MASK: u32 = 0b11 << MTOOLS_DEVICE_MODE_SHIFT;
const SELECTED_MAIN_PAGE_SHIFT: u32 = 6;
const SELECTED_MAIN_PAGE_MASK: u32 = 0x0f << SELECTED_MAIN_PAGE_SHIFT;

/// Lossless, read-only representation of a GetData(Settings) payload.
///
/// Unknown fields remain available through [`Self::settings_a_raw`] and
/// [`Self::settings_b_raw`]. Only fields whose meanings are corroborated by
/// KM003C V1.9.9 firmware consumers have semantic accessors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    bytes: [u8; SETTINGS_SIZE],
}

impl Settings {
    /// Parse both settings blocks and validate their independent CRC-32 values.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KMError> {
        let bytes: [u8; SETTINGS_SIZE] = bytes.try_into().map_err(|_| {
            KMError::InvalidPacket(format!(
                "Settings payload must be exactly {SETTINGS_SIZE} bytes, got {}",
                bytes.len()
            ))
        })?;

        validate_checksum("Settings-A", &bytes[..SETTINGS_A_SIZE], SETTINGS_A_CHECKSUM_OFFSET)?;
        validate_checksum(
            "Settings-B",
            &bytes[SETTINGS_B_OFFSET..],
            SETTINGS_B_CHECKSUM_OFFSET - SETTINGS_B_OFFSET,
        )?;

        Ok(Self { bytes })
    }

    /// Serialize the exact captured settings payload, including unknown fields.
    pub fn to_bytes(&self) -> [u8; SETTINGS_SIZE] {
        self.bytes
    }

    /// Return the complete first persisted settings block.
    pub fn settings_a_raw(&self) -> &[u8] {
        &self.bytes[..SETTINGS_A_SIZE]
    }

    /// Return the complete second persisted settings block.
    pub fn settings_b_raw(&self) -> &[u8] {
        &self.bytes[SETTINGS_B_OFFSET..]
    }

    /// Raw settings-A flags, including fields whose meanings remain unknown.
    pub fn settings_a_flags(&self) -> u32 {
        read_u32(&self.bytes, 0)
    }

    /// Raw settings-B flags, including fields whose meanings remain unknown.
    pub fn settings_b_flags(&self) -> u32 {
        read_u32(&self.bytes, SETTINGS_B_OFFSET)
    }

    /// Firmware language-table selection, encoded as 0 or 1.
    ///
    /// The mapping from these indices to a particular language is not yet
    /// independently confirmed, so this accessor deliberately returns the
    /// stored index rather than guessing an enum variant.
    pub fn language_selection(&self) -> u8 {
        (self.settings_a_flags() & LANGUAGE_SELECTION_MASK) as u8
    }

    /// Whether firmware marks the device as requiring calibration.
    pub fn is_uncalibrated(&self) -> bool {
        self.settings_a_flags() & UNCALIBRATED_MASK != 0
    }

    /// Display brightness as applied by firmware, in percent.
    ///
    /// The stored field is seven bits wide; firmware clamps values above 100.
    pub fn brightness(&self) -> Ratio {
        let percent_value = (((self.settings_a_flags() & BRIGHTNESS_MASK) >> BRIGHTNESS_SHIFT) as u8).min(100);
        Ratio::new::<percent>(f64::from(percent_value))
    }

    /// ADC sample interval stored in the settings block.
    pub fn sample_interval(&self) -> Time {
        Time::new::<microsecond>(f64::from(read_u16(&self.bytes, SAMPLE_INTERVAL_OFFSET)))
    }

    /// Display orientation index stored by firmware, in the range 0..=3.
    pub fn screen_orientation(&self) -> u8 {
        (self.settings_b_flags() & ORIENTATION_MASK) as u8
    }

    /// Mtools device-mode index stored by firmware, in the range 0..=3.
    pub fn mtools_device_mode(&self) -> u8 {
        ((self.settings_b_flags() & MTOOLS_DEVICE_MODE_MASK) >> MTOOLS_DEVICE_MODE_SHIFT) as u8
    }

    /// Persisted main-page index, in the range 0..=15.
    pub fn selected_main_page(&self) -> u8 {
        ((self.settings_b_flags() & SELECTED_MAIN_PAGE_MASK) >> SELECTED_MAIN_PAGE_SHIFT) as u8
    }

    /// Raw 64-byte device-name field, including trailing zero padding.
    pub fn device_name_raw(&self) -> &[u8] {
        &self.bytes[DEVICE_NAME_OFFSET..DEVICE_NAME_END]
    }

    /// UTF-8 device name when the stored bytes are valid UTF-8.
    pub fn device_name(&self) -> Option<&str> {
        let raw = self.device_name_raw();
        let length = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
        std::str::from_utf8(&raw[..length]).ok()
    }

    /// Stored CRC-32 for the first settings block.
    pub fn settings_a_checksum(&self) -> u32 {
        read_u32(&self.bytes, SETTINGS_A_CHECKSUM_OFFSET)
    }

    /// Stored CRC-32 for the second settings block.
    pub fn settings_b_checksum(&self) -> u32 {
        read_u32(&self.bytes, SETTINGS_B_CHECKSUM_OFFSET)
    }
}

fn validate_checksum(name: &str, block: &[u8], checksum_offset: usize) -> Result<(), KMError> {
    let stored = read_u32(block, checksum_offset);
    let calculated = crc32fast::hash(&block[..checksum_offset]);
    if stored != calculated {
        return Err(KMError::InvalidPacket(format!(
            "{name} checksum mismatch: stored 0x{stored:08x}, calculated 0x{calculated:08x}"
        )));
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("validated settings offset"))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("validated settings offset"))
}

#[cfg(feature = "python")]
impl<'py> pyo3::IntoPyObject<'py> for Settings {
    type Target = pyo3::types::PyDict;
    type Output = pyo3::Bound<'py, Self::Target>;
    type Error = pyo3::PyErr;

    fn into_pyobject(self, py: pyo3::Python<'py>) -> Result<Self::Output, Self::Error> {
        use pyo3::types::PyDictMethods;
        use uom::si::ratio::percent;
        use uom::si::time::microsecond;

        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("settings_a_flags", self.settings_a_flags())?;
        dict.set_item("settings_b_flags", self.settings_b_flags())?;
        dict.set_item("language_selection", self.language_selection())?;
        dict.set_item("uncalibrated", self.is_uncalibrated())?;
        dict.set_item("brightness_percent", self.brightness().get::<percent>())?;
        dict.set_item("sample_interval_us", self.sample_interval().get::<microsecond>())?;
        dict.set_item("screen_orientation", self.screen_orientation())?;
        dict.set_item("mtools_device_mode", self.mtools_device_mode())?;
        dict.set_item("selected_main_page", self.selected_main_page())?;
        dict.set_item("device_name", self.device_name())?;
        dict.set_item("settings_a_checksum", self.settings_a_checksum())?;
        dict.set_item("settings_b_checksum", self.settings_b_checksum())?;
        dict.set_item("raw", hex::encode(self.to_bytes()))?;
        Ok(dict)
    }
}
