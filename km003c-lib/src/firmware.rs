//! ChargerLAB firmware packages and the KM003C bootloader update protocol.
//!
//! Package handling builds on the contribution in PR #60. The transfer and
//! validation rules also follow successful USB captures and a bootloader dump.

#[cfg(feature = "firmware-catalog")]
pub mod catalog;
mod install;
pub use install::{
    FirmwareBackup, FirmwareDeviceCheck, FirmwareInstallProgress, FirmwareInstallResult, FirmwareInstallStage,
    InstalledFirmwareInfo, PreparedFirmwareUpdate, check_firmware_device,
};

use crate::auth::{MEMORY_READ_KEY, aes_ecb_decrypt_blocks};
use crate::device::{DeviceSelector, KM003C, PID, VID};
use crate::error::KMError;
use crate::packet::{CtrlHeader, PacketPeek, PacketType};
use std::num::NonZeroU8;
use std::time::Duration;

const FIELD_COUNT: usize = 10;
const MAX_FIELD_BYTES: usize = 64 * 1024;
/// Maximum application size accepted by the inspected KM003C bootloader.
pub const MAX_IMAGE_BYTES: usize = 0x6fffe;
const WRITE_CHUNK_SIZE: usize = 0xFF0;
const APPLICATION_BASE: u32 = 0x4000;
const IMAGE_METADATA_OFFSET: usize = 0x428;

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
    metadata: FirmwareMetadata,
    /// Decrypted firmware, excluding AES alignment padding.
    data: Vec<u8>,
    /// Original encrypted payload sent to the device during an update.
    encrypted_data: Vec<u8>,
    trailer: Vec<u8>,
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
        if !encrypted_len.is_multiple_of(16) || encrypted_len < size || encrypted_len > size.saturating_add(31) {
            return Err(invalid("firmware ciphertext length does not match metadata"));
        }
        let encrypted = input.take(encrypted_len)?;
        // QDataStream reads one QByteArray, not the rest of the file. The
        // independently verified 1.9.9 package has four outer trailer bytes.
        let trailer = input.take(input.bytes.len() - input.offset)?;
        if trailer.len() > MAX_FIELD_BYTES {
            return Err(invalid("firmware package trailer exceeds supported limits"));
        }
        let mut data = aes_ecb_decrypt_blocks(encrypted, &MEMORY_READ_KEY)?;
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
            trailer: trailer.to_vec(),
        })
    }

    /// Validated metadata. Images are immutable after parsing.
    pub fn metadata(&self) -> &FirmwareMetadata {
        &self.metadata
    }

    /// Original plaintext bytes, before the bootloader commits size and CRC.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Original ciphertext; outer container trailer bytes are excluded.
    pub fn encrypted_data(&self) -> &[u8] {
        &self.encrypted_data
    }

    /// Container bytes after the encrypted QByteArray. Never uploaded.
    pub fn trailer(&self) -> &[u8] {
        &self.trailer
    }

    /// Check target, vectors, embedded metadata, application bounds and text.
    /// No version ordering is imposed: the inspected bootloader permits both
    /// upgrades and downgrades. Compatibility of a particular release with the
    /// attached hardware must still be established by its publisher.
    pub fn validate_for_update(&self) -> Result<(), KMError> {
        if self.metadata.model != "KM003C" {
            return Err(invalid(format!("firmware model {} is not KM003C", self.metadata.model)));
        }
        if self.metadata.size < 0x460 || self.metadata.size > MAX_IMAGE_BYTES {
            return Err(invalid("firmware size is outside supported limits"));
        }
        if self.data.len() != self.metadata.size || crc32fast::hash(&self.data) != self.metadata.crc32 {
            return Err(invalid("firmware image no longer matches its size and CRC-32"));
        }
        if self.encrypted_data.len() < self.data.len()
            || self.encrypted_data.len() > self.data.len().saturating_add(31)
            || !self.encrypted_data.len().is_multiple_of(16)
            || aes_ecb_decrypt_blocks(&self.encrypted_data, &MEMORY_READ_KEY)?[..self.data.len()] != self.data
        {
            return Err(invalid("encrypted firmware no longer matches the validated image"));
        }
        for (value, capacity, name) in [
            (&self.metadata.model, 12, "model"),
            (&self.metadata.version, 12, "version"),
            (&self.metadata.date, 12, "date"),
        ] {
            if value.is_empty() || !value.is_ascii() || value.contains('\0') || value.len() >= capacity {
                return Err(invalid(format!(
                    "firmware {name} must be ASCII and fit in {capacity} bytes"
                )));
            }
        }
        let word = |offset| u32::from_le_bytes(self.data[offset..offset + 4].try_into().expect("validated size"));
        validate_application_vectors(&self.data)?;
        if word(0x420) != APPLICATION_BASE || self.data[IMAGE_METADATA_OFFSET..IMAGE_METADATA_OFFSET + 8] != [0xff; 8] {
            return Err(invalid("firmware application base or uncommitted metadata is invalid"));
        }
        for (offset, expected) in [
            (0x430, &self.metadata.model),
            (0x43c, &self.metadata.version),
            (0x448, &self.metadata.date),
        ] {
            let actual = &self.data[offset..offset + 12];
            let end = actual.iter().position(|b| *b == 0).unwrap_or(actual.len());
            if &actual[..end] != expected.as_bytes() {
                return Err(invalid(
                    "package metadata does not match the embedded firmware identity",
                ));
            }
        }
        Ok(())
    }

    fn setup_packet(&self, id: u8, random: u32) -> Result<[u8; 68], KMError> {
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
        packet[56..60].copy_from_slice(&random.to_le_bytes());
        Ok(packet)
    }

    /// Expected installed bytes, including the bootloader's final metadata patch.
    pub fn installed_data(&self) -> Result<Vec<u8>, KMError> {
        self.validate_for_update()?;
        let mut installed = self.data.clone();
        installed[IMAGE_METADATA_OFFSET..IMAGE_METADATA_OFFSET + 4]
            .copy_from_slice(&(self.metadata.size as u32).to_le_bytes());
        installed[IMAGE_METADATA_OFFSET + 4..IMAGE_METADATA_OFFSET + 8]
            .copy_from_slice(&self.metadata.crc32.to_le_bytes());
        Ok(installed)
    }
}

fn validate_application_vectors(data: &[u8]) -> Result<(), KMError> {
    if !(8..=MAX_IMAGE_BYTES).contains(&data.len()) {
        return Err(invalid("firmware contains invalid application vectors"));
    }
    let word = |offset| u32::from_le_bytes(data[offset..offset + 4].try_into().expect("validated vector length"));
    let sp = word(0);
    let reset = word(4);
    let end = APPLICATION_BASE + data.len() as u32;
    if sp <= 0x1fff8000
        || sp >= 0x20020000
        || !sp.is_multiple_of(4)
        || reset & 1 == 0
        || (reset & !1) < APPLICATION_BASE
        || (reset & !1) >= end
    {
        return Err(invalid("firmware contains invalid application vectors"));
    }
    Ok(())
}

trait FirmwareTransport {
    fn next_id(&mut self) -> u8;
    async fn write(&mut self, bytes: &[u8]) -> Result<(), KMError>;
    async fn read(&mut self, timeout: Duration) -> Result<Vec<u8>, KMError>;
}

impl FirmwareTransport for KM003C {
    fn next_id(&mut self) -> u8 {
        self.next_tid()
    }

    async fn write(&mut self, bytes: &[u8]) -> Result<(), KMError> {
        // send_raw flushes the logical transfer, including a ZLP at 64-byte
        // multiples. Ciphertext blocks do not receive a protocol header.
        self.send_raw(bytes).await
    }

    async fn read(&mut self, duration: Duration) -> Result<Vec<u8>, KMError> {
        self.read_raw_with_timeout(duration).await
    }
}

impl KM003C {
    /// Read model and hardware identity from a DFU maintenance connection.
    /// Bootloader response IDs are independent of the request IDs.
    pub async fn get_bootloader_info(&mut self) -> Result<crate::auth::DeviceInfo, KMError> {
        if !self.firmware_transport_available() {
            return Err(invalid("bootloader checks require a vendor maintenance connection"));
        }
        bootloader_info(self).await
    }

    /// Reboot the application into DFU. Drop this handle before reopening USB.
    pub async fn jump_to_dfu(&mut self) -> Result<(), KMError> {
        let id = self.next_tid();
        self.send_raw(&[0x09, id, 0, 0]).await
    }

    /// Start the application from DFU. Drop this handle before reopening USB.
    pub async fn jump_to_application(&mut self) -> Result<(), KMError> {
        let id = self.next_tid();
        self.send_raw(&[0x08, id, 0, 0]).await
    }

    /// Erase and write a validated image, which may have an older version.
    ///
    /// Open a fresh vendor maintenance connection and establish DFU mode with
    /// [`find_firmware_device`] first. No data block is retried on failure:
    /// the bootloader has no sequence numbers and may already have advanced
    /// its write cursor. On failure, leave the device in DFU for recovery.
    /// `Complete` means the bootloader reported success; separately reboot and
    /// verify the installed bytes with [`FirmwareImage::installed_data`].
    pub async fn update_firmware<F>(&mut self, image: &FirmwareImage, progress: F) -> Result<(), KMError>
    where
        F: FnMut(FirmwareUpdateProgress),
    {
        if !self.firmware_transport_available() {
            return Err(invalid(
                "firmware updates require a fresh vendor maintenance connection",
            ));
        }
        image.validate_for_update()?;
        let identity = self.get_bootloader_info().await?;
        if identity.model != image.metadata.model {
            return Err(invalid("bootloader model does not match firmware package"));
        }
        transfer_image(self, image, rand::random(), progress).await
    }
}

async fn bootloader_info(transport: &mut impl FirmwareTransport) -> Result<crate::auth::DeviceInfo, KMError> {
    let duration = Duration::from_secs(2);
    let id = transport.next_id();
    transport.write(&[2, id, 0, 0]).await?;
    expect_type(
        &transport.read(duration).await?,
        PacketType::Accept,
        "bootloader identity connect",
    )?;
    let request = crate::auth::build_memory_read_packet(0x420, 64, transport.next_id());
    transport.write(&request).await?;
    let confirmation = transport.read(duration).await?;
    expect_type(&confirmation, PacketType::MemoryRead, "bootloader identity")?;
    if confirmation.len() != 20 || crate::auth::parse_memory_read_confirmation(&confirmation[4..]) != Some((0x420, 64))
    {
        return Err(invalid("invalid bootloader identity memory confirmation"));
    }
    let ciphertext = transport.read(duration).await?;
    if ciphertext.len() != 64 {
        return Err(invalid("invalid bootloader identity data length"));
    }
    let data = aes_ecb_decrypt_blocks(&ciphertext, &MEMORY_READ_KEY)?;
    let mut info = crate::auth::DeviceInfo::default();
    info.parse_device_info(&data);
    if info.model.is_empty() || info.hw_version.is_empty() {
        return Err(invalid("bootloader identity is missing model or hardware version"));
    }
    Ok(info)
}

async fn transfer_image(
    transport: &mut impl FirmwareTransport,
    image: &FirmwareImage,
    random: u32,
    mut progress: impl FnMut(FirmwareUpdateProgress),
) -> Result<(), KMError> {
    image.validate_for_update()?;
    let total_bytes = image.encrypted_data.len();
    let mut report = |stage, bytes_written| {
        progress(FirmwareUpdateProgress {
            stage,
            bytes_written,
            total_bytes,
        })
    };
    let ack_timeout = Duration::from_secs(2);
    report(FirmwareUpdateStage::Connecting, 0);
    let id = transport.next_id();
    transport.write(&[0x02, id, 0, 0]).await?;
    expect_type(&transport.read(ack_timeout).await?, PacketType::Accept, "DFU connect")?;

    report(FirmwareUpdateStage::CheckingStatus, 0);
    let mut head = [0; 20];
    head[..4].copy_from_slice(&[0x40, transport.next_id(), 0, 1]);
    transport.write(&head).await?;
    let reply = transport.read(ack_timeout).await?;
    expect_type(&reply, PacketType::Head, "DFU header")?;
    if reply.len() != 20 || reply[4..8] != [0; 4] {
        return Err(invalid("unexpected DFU header body"));
    }

    report(FirmwareUpdateStage::Erasing, 0);
    let setup = image.setup_packet(transport.next_id(), random)?;
    transport.write(&setup).await?;
    // One receive with an erase-specific deadline accepts both immediate and
    // delayed Accept. It never resends Setup or cancels/restarts partial reads.
    expect_type(
        &transport.read(Duration::from_secs(20)).await?,
        PacketType::Accept,
        "firmware erase",
    )?;

    report(FirmwareUpdateStage::Writing, 0);
    let mut written = 0;
    for chunk in image.encrypted_data.chunks(WRITE_CHUNK_SIZE) {
        transport.write(chunk).await?;
        expect_type(&transport.read(ack_timeout).await?, PacketType::Sync, "firmware block")?;
        written += chunk.len();
        report(FirmwareUpdateStage::Writing, written);
    }
    report(FirmwareUpdateStage::Verifying, written);
    expect_type(
        &transport.read(Duration::from_secs(5)).await?,
        PacketType::Finished,
        "firmware checksum",
    )?;
    report(FirmwareUpdateStage::Complete, written);
    Ok(())
}

fn expect_type(response: &[u8], expected: PacketType, step: &str) -> Result<(), KMError> {
    let peek = PacketPeek::from_bytes(response).ok_or_else(|| invalid(format!("truncated {step} response")))?;
    if matches!(
        peek.packet_type,
        PacketType::Rejected | PacketType::Error | PacketType::NotReadable
    ) {
        let header = CtrlHeader::from_bytes(response[..4].try_into().expect("checked header"));
        return Err(KMError::Protocol(format!(
            "{step}: bootloader {:?}, code {} (attribute 0x{:04X})",
            peek.packet_type,
            header.attribute() >> 5,
            header.attribute()
        )));
    }
    if peek.packet_type != expected {
        return Err(KMError::Protocol(format!(
            "{step}: expected {expected:?}, received {:?}",
            peek.packet_type
        )));
    }
    if expected.is_ctrl_type() && response.len() != 4 {
        return Err(invalid(format!(
            "invalid {step} control response length {}",
            response.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;

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
