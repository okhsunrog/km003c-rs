//! Reading and validating ChargerLAB `.mencrypt` firmware packages.

use crate::auth::{MEMORY_READ_KEY, aes_ecb_decrypt_blocks};
use crate::device::{DeviceSelector, KM003C, PID, VID};
use crate::error::KMError;
use std::num::NonZeroU8;
use std::time::Duration;

const FIELD_COUNT: usize = 10;
const MAX_FIELD_BYTES: usize = 64 * 1024;
const MAX_IMAGE_BYTES: usize = 32 * 1024 * 1024;
const WRITE_CHUNK_SIZE: usize = 0xFF0;
const APPLICATION_BASE: u32 = 0x4000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirmwareUsbMode {
    Application,
    Dfu,
    Other(String),
}

#[derive(Debug, Clone)]
pub struct FirmwareUsbDevice {
    pub serial_number: Option<String>,
    pub product_string: Option<String>,
    /// USB string descriptor 2, used by the Windows updater to report APP/DFU.
    pub mode_string: String,
    pub mode: FirmwareUsbMode,
    /// Physical-port identity when available. Stable across USB re-enumeration.
    pub port_selector: Option<DeviceSelector>,
}

/// Locate a KM003C in application or DFU mode. Multiple matching devices
/// require an explicit selector so an update cannot silently target the wrong unit.
pub async fn find_firmware_device(selector: &DeviceSelector) -> Result<FirmwareUsbDevice, KMError> {
    let matches: Vec<_> = nusb::list_devices()
        .await?
        .filter(|device| device.vendor_id() == VID && device.product_id() == PID && selector.matches(device))
        .collect();
    if matches.is_empty() {
        return Err(KMError::DeviceNotFound);
    }
    if matches.len() != 1 {
        return Err(KMError::Protocol(format!(
            "{} KM003C devices match; select one by USB serial number",
            matches.len()
        )));
    }
    let device = &matches[0];
    #[cfg(not(any(target_os = "android", target_arch = "wasm32")))]
    let port_selector = (!device.port_chain().is_empty()).then(|| DeviceSelector::PortPath {
        bus_id: device.bus_id().to_owned(),
        port_chain: device.port_chain().to_vec(),
    });
    #[cfg(any(target_os = "android", target_arch = "wasm32"))]
    let port_selector = None;
    let product_string = device.product_string().map(str::to_owned);
    let opened = device.open().await?;
    let languages = opened
        .get_string_descriptor_supported_languages(Duration::from_secs(2))
        .await
        .map_err(|error| KMError::Protocol(format!("cannot read USB descriptor languages: {error}")))?;
    let language = languages.into_iter().next().unwrap_or(0x0409);
    let raw_mode_string = opened
        .get_string_descriptor(
            NonZeroU8::new(2).expect("nonzero descriptor index"),
            language,
            Duration::from_secs(2),
        )
        .await
        .map_err(|error| KMError::Protocol(format!("cannot read USB mode descriptor: {error}")))?;
    let (mode_string, mode) = parse_mode_string(&raw_mode_string);
    Ok(FirmwareUsbDevice {
        serial_number: device.serial_number().map(str::to_owned),
        product_string,
        mode_string,
        mode,
        port_selector,
    })
}

fn parse_mode_string(raw: &str) -> (String, FirmwareUsbMode) {
    // KM003C's descriptor can contain a NUL and erased UTF-16 padding.
    // The Windows program uses libusb_get_string_descriptor_ascii, which
    // treats the NUL as the end of this mode label.
    let mode_string = raw
        .split('\0')
        .next()
        .unwrap_or_default()
        .trim_end_matches('\u{ffff}')
        .to_owned();
    let mode = match mode_string.as_str() {
        "APP" => FirmwareUsbMode::Application,
        "DFU" | "BOOT" => FirmwareUsbMode::Dfu,
        other => FirmwareUsbMode::Other(other.to_owned()),
    };
    (mode_string, mode)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareUpdateStage {
    Connecting,
    CheckingStatus,
    Erasing,
    Writing,
    Verifying,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareUpdateProgress {
    pub stage: FirmwareUpdateStage,
    pub bytes_written: usize,
    pub total_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareMetadata {
    pub model: String,
    pub version: String,
    pub date: String,
    pub crc32: u32,
    pub size: usize,
    pub notes_zh: String,
    pub notes_en: String,
}

#[derive(Debug, Clone)]
pub struct FirmwareImage {
    pub metadata: FirmwareMetadata,
    /// Decrypted firmware bytes. The package's extra AES block is excluded.
    pub data: Vec<u8>,
    /// Original encrypted payload sent to the device during an update.
    pub encrypted_data: Vec<u8>,
}

impl FirmwareImage {
    /// Parse a `.mencrypt` file and check its model, length and CRC-32.
    ///
    /// The package uses Qt's big-endian QString and QByteArray encoding.
    /// Its firmware payload is AES-128-ECB encrypted with the same key used
    /// by Mtools for device memory reads.
    pub fn parse(bytes: &[u8]) -> Result<Self, KMError> {
        let mut input = Input { bytes, offset: 0 };
        let count = input.u32()? as usize;
        if count != FIELD_COUNT {
            return Err(invalid(format!(
                "expected {FIELD_COUNT} firmware metadata fields, got {count}"
            )));
        }

        let mut fields = Vec::with_capacity(FIELD_COUNT);
        for _ in 0..FIELD_COUNT {
            let length = input.u32()? as usize;
            if length > MAX_FIELD_BYTES || !length.is_multiple_of(2) {
                return Err(invalid("invalid firmware metadata string length"));
            }
            let encoded = input.take(length)?;
            let units = encoded
                .as_chunks::<2>()
                .0
                .iter()
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]));
            let value = String::from_utf16(&units.collect::<Vec<_>>())
                .map_err(|_| invalid("firmware metadata contains invalid UTF-16"))?;
            fields.push(value);
        }

        if fields[0] != "Firmware file" || fields[1] != "ChargerLab" || fields[2] != "V1.0" {
            return Err(invalid("unsupported firmware package format"));
        }
        let crc32 = u32::from_str_radix(&fields[6], 16).map_err(|_| invalid("invalid firmware CRC-32"))?;
        let size = fields[7]
            .parse::<usize>()
            .map_err(|_| invalid("invalid firmware size"))?;
        if size == 0 || size > MAX_IMAGE_BYTES {
            return Err(invalid("firmware size is outside supported limits"));
        }
        let encrypted_len = input.u32()? as usize;
        if encrypted_len != input.bytes.len() - input.offset
            || !encrypted_len.is_multiple_of(16)
            || encrypted_len < size
            || encrypted_len > size.saturating_add(31)
        {
            return Err(invalid("firmware ciphertext length does not match metadata"));
        }
        let encrypted = input.take(encrypted_len)?;
        let mut data = aes_ecb_decrypt_blocks(encrypted, MEMORY_READ_KEY)?;
        data.truncate(size);
        let actual_crc = crc32fast::hash(&data);
        if actual_crc != crc32 {
            return Err(invalid(format!(
                "firmware CRC-32 mismatch: expected {crc32:08X}, got {actual_crc:08X}"
            )));
        }

        Ok(Self {
            metadata: FirmwareMetadata {
                model: fields[3].clone(),
                version: fields[4].clone(),
                date: fields[5].clone(),
                crc32,
                size,
                notes_zh: fields[8].clone(),
                notes_en: fields[9].clone(),
            },
            data,
            encrypted_data: encrypted.to_vec(),
        })
    }

    fn validate_for_update(&self) -> Result<(), KMError> {
        if self.metadata.model != "KM003C" {
            return Err(invalid(format!("firmware model {} is not KM003C", self.metadata.model)));
        }
        if self.metadata.size == 0 || self.metadata.size > MAX_IMAGE_BYTES {
            return Err(invalid("firmware size is outside supported limits"));
        }
        if self.data.len() != self.metadata.size || crc32fast::hash(&self.data) != self.metadata.crc32 {
            return Err(invalid("firmware image no longer matches its size and CRC-32"));
        }
        if self.encrypted_data.len() < self.data.len()
            || self.encrypted_data.len() > self.data.len().saturating_add(31)
            || !self.encrypted_data.len().is_multiple_of(16)
            || aes_ecb_decrypt_blocks(&self.encrypted_data, MEMORY_READ_KEY)?[..self.data.len()] != self.data
        {
            return Err(invalid("encrypted firmware no longer matches the validated image"));
        }
        for (value, capacity, name) in [
            (&self.metadata.model, 12, "model"),
            (&self.metadata.version, 12, "version"),
            (&self.metadata.date, 12, "date"),
        ] {
            if !value.is_ascii() || value.len() >= capacity {
                return Err(invalid(format!(
                    "firmware {name} must be ASCII and fit in {capacity} bytes"
                )));
            }
        }
        Ok(())
    }

    fn setup_packet(&self, id: u8) -> Result<[u8; 68], KMError> {
        self.validate_for_update()?;
        let mut packet = [0_u8; 68];
        packet[..4].copy_from_slice(&[0x42, id, 0, 4]);
        packet[4..8].copy_from_slice(&APPLICATION_BASE.to_le_bytes());
        let image_size = u32::try_from(self.metadata.size).map_err(|_| invalid("firmware is too large"))?;
        let end = APPLICATION_BASE
            .checked_add(image_size)
            .ok_or_else(|| invalid("firmware end address overflow"))?;
        packet[8..12].copy_from_slice(&end.to_le_bytes());
        packet[12..16].copy_from_slice(&image_size.to_le_bytes());
        packet[16..20].copy_from_slice(&self.metadata.crc32.to_le_bytes());
        packet[20..20 + self.metadata.model.len()].copy_from_slice(self.metadata.model.as_bytes());
        packet[32..32 + self.metadata.version.len()].copy_from_slice(self.metadata.version.as_bytes());
        packet[44..44 + self.metadata.date.len()].copy_from_slice(self.metadata.date.as_bytes());
        packet[56..60].copy_from_slice(&rand::random::<u32>().to_le_bytes());
        Ok(packet)
    }
}

impl KM003C {
    /// Ask the running application to reboot into its DFU bootloader.
    /// The USB handle will become invalid after this command.
    pub async fn jump_to_dfu(&mut self) -> Result<(), KMError> {
        let id = self.next_tid();
        self.send_raw(&[0x09, id, 0, 0]).await
    }

    /// Ask the DFU bootloader to start the application.
    /// The USB handle will become invalid after this command.
    pub async fn jump_to_application(&mut self) -> Result<(), KMError> {
        let id = self.next_tid();
        self.send_raw(&[0x08, id, 0, 0]).await
    }

    /// Write a validated official firmware image through the vendor interface.
    ///
    /// The caller must already have confirmed that the connected KM003C is in
    /// DFU mode. Progress counts encrypted bytes accepted by the bootloader.
    pub async fn update_firmware<F>(&mut self, image: &FirmwareImage, mut progress: F) -> Result<(), KMError>
    where
        F: FnMut(FirmwareUpdateProgress),
    {
        image.validate_for_update()?;
        let total_bytes = image.encrypted_data.len();
        let mut report = |stage, bytes_written| {
            progress(FirmwareUpdateProgress {
                stage,
                bytes_written,
                total_bytes,
            });
        };

        report(FirmwareUpdateStage::Connecting, 0);
        let id = self.next_tid();
        self.send_raw(&[0x02, id, 0, 0]).await?;
        expect_type(&self.receive_raw().await?, 0x05, "DFU connect")?;

        report(FirmwareUpdateStage::CheckingStatus, 0);
        let mut status_request = [0_u8; 20];
        status_request[..4].copy_from_slice(&[0x40, self.next_tid(), 0, 1]);
        self.send_raw(&status_request).await?;
        let status = self.receive_raw().await?;
        let status_code = parse_dfu_status(&status)?;
        if status_code != 0 {
            return Err(KMError::Protocol(format!("DFU reports status 0x{status_code:08X}")));
        }

        report(FirmwareUpdateStage::Erasing, 0);
        let id = self.next_tid();
        self.send_raw(&image.setup_packet(id)?).await?;
        // Mtools initially waits 20 ms, then polls while the bootloader erases.
        // A bounded longer wait avoids treating an ordinary erase delay as failure.
        let mut erased = false;
        for _ in 0..10 {
            match self.receive_raw().await {
                Ok(response) => {
                    expect_type(&response, 0x05, "firmware erase")?;
                    erased = true;
                    break;
                }
                Err(KMError::Timeout(_)) => continue,
                Err(error) => return Err(error),
            }
        }
        if !erased {
            return Err(KMError::Protocol(
                "timed out waiting for firmware erase acknowledgment".into(),
            ));
        }

        report(FirmwareUpdateStage::Writing, 0);
        let mut written = 0;
        for chunk in image.encrypted_data.chunks(WRITE_CHUNK_SIZE) {
            self.send_raw(chunk).await?;
            expect_type(&self.receive_raw().await?, 0x01, "firmware chunk")?;
            written += chunk.len();
            report(FirmwareUpdateStage::Writing, written);
        }

        report(FirmwareUpdateStage::Verifying, written);
        expect_type(&self.receive_raw().await?, 0x07, "firmware verification")?;
        report(FirmwareUpdateStage::Complete, written);
        Ok(())
    }
}

fn expect_type(response: &[u8], expected: u8, step: &str) -> Result<(), KMError> {
    let Some(&first) = response.first() else {
        return Err(KMError::Protocol(format!("empty {step} response")));
    };
    let actual = first & 0x7f;
    if actual != expected {
        return Err(KMError::Protocol(format!(
            "{step} response type 0x{actual:02X}, expected 0x{expected:02X}"
        )));
    }
    Ok(())
}

fn parse_dfu_status(response: &[u8]) -> Result<u32, KMError> {
    expect_type(response, 0x40, "DFU status")?;
    // Mtools accepts any status response longer than 7 bytes and reads the
    // 32-bit bootloader status at offset 4. A KM003C normally returns the
    // 4-byte header plus a 16-byte body (20 bytes total).
    if response.len() < 8 {
        return Err(invalid(format!("DFU status response is only {} bytes", response.len())));
    }
    Ok(u32::from_le_bytes(response[4..8].try_into().expect("four bytes")))
}

fn invalid(message: impl Into<String>) -> KMError {
    KMError::InvalidPacket(message.into())
}

struct Input<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Input<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], KMError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| invalid("firmware package length overflow"))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| invalid("truncated firmware package"))?;
        self.offset = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32, KMError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().expect("four bytes");
        Ok(u32::from_be_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::Aes128;
    use aes::cipher::{BlockCipherEncrypt, KeyInit};

    fn package() -> Vec<u8> {
        let plaintext = [*b"0123456789ABCDEF", *b"0123456789ABCDEF"].concat();
        let fields = [
            "Firmware file".to_owned(),
            "ChargerLab".to_owned(),
            "V1.0".to_owned(),
            "KM003C".to_owned(),
            "2.0.7".to_owned(),
            "2026.9.29".to_owned(),
            format!("{:08X}", crc32fast::hash(&plaintext[..16])),
            "16".to_owned(),
            "notes".to_owned(),
            "notes".to_owned(),
        ];
        let mut bytes = (fields.len() as u32).to_be_bytes().to_vec();
        for field in fields {
            let encoded: Vec<u8> = field.encode_utf16().flat_map(u16::to_be_bytes).collect();
            bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&encoded);
        }
        let cipher = Aes128::new(MEMORY_READ_KEY.into());
        let mut encrypted = plaintext;
        for block in encrypted.as_chunks_mut::<16>().0 {
            cipher.encrypt_block(block.into());
        }
        bytes.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&encrypted);
        bytes
    }

    #[test]
    fn parses_package_and_builds_setup_record() {
        let image = FirmwareImage::parse(&package()).unwrap();
        assert_eq!(image.metadata.model, "KM003C");
        assert_eq!(image.data, b"0123456789ABCDEF");
        let packet = image.setup_packet(7).unwrap();
        assert_eq!(&packet[..4], &[0x42, 7, 0, 4]);
        assert_eq!(u32::from_le_bytes(packet[4..8].try_into().unwrap()), 0x4000);
        assert_eq!(u32::from_le_bytes(packet[8..12].try_into().unwrap()), 0x4010);
        assert_eq!(u32::from_le_bytes(packet[12..16].try_into().unwrap()), 16);
        assert_eq!(&packet[20..26], b"KM003C");
        assert_eq!(&packet[32..37], b"2.0.7");
        assert_eq!(&packet[44..53], b"2026.9.29");
    }

    #[test]
    fn rejects_corrupted_ciphertext() {
        let mut bytes = package();
        let image_start = bytes.len() - 32;
        bytes[image_start] ^= 1;
        assert!(FirmwareImage::parse(&bytes).is_err());
    }

    #[test]
    fn handles_padded_usb_mode_descriptor() {
        assert_eq!(
            parse_mode_string("APP\0\u{ffff}"),
            ("APP".into(), FirmwareUsbMode::Application)
        );
        assert_eq!(parse_mode_string("DFU\0\u{ffff}"), ("DFU".into(), FirmwareUsbMode::Dfu));
    }

    #[test]
    fn accepts_twenty_byte_dfu_status_response() {
        let mut response = [0_u8; 20];
        response[..4].copy_from_slice(&[0x40, 1, 0, 1]);
        assert_eq!(parse_dfu_status(&response).unwrap(), 0);
    }
}
