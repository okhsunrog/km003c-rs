//! Frontend-independent device checks, backup and complete installation flow.

use super::{
    FirmwareImage, FirmwareMetadata, FirmwareUpdateProgress, FirmwareUsbDevice, FirmwareUsbMode, MAX_IMAGE_BYTES,
    find_firmware_device,
};
use crate::{DeviceSelector, KM003C, Packet, auth::DeviceInfo, error::KMError};
use std::{future::Future, time::Duration};

/// Identity and committed metadata of an installed application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledFirmwareInfo {
    pub version: String,
    pub date: String,
    pub size: usize,
    pub crc32: u32,
}

impl InstalledFirmwareInfo {
    /// Validate exact installed application bytes against committed metadata.
    ///
    /// Checks vectors, model, embedded identity and CRC. The bootloader patches
    /// size/CRC at offsets 0x428..0x430 after verifying the original image, so
    /// those eight bytes are treated as erased when recomputing that CRC.
    /// Transport padding must be removed before calling this method.
    pub fn validate_application(&self, data: &[u8]) -> Result<(), KMError> {
        if !(0x460..=MAX_IMAGE_BYTES).contains(&self.size) || data.len() != self.size {
            return Err(invalid("application backup has an invalid size"));
        }
        super::validate_application_vectors(data)?;
        let actual = Self::parse(&data[0x420..0x460])?;
        let model = data[0x430..0x43c].split(|b| *b == 0).next().unwrap_or_default();
        if actual != *self || model != b"KM003C" {
            return Err(invalid(
                "application backup metadata does not match the installed firmware",
            ));
        }
        let mut crc = crc32fast::Hasher::new();
        crc.update(&data[..super::IMAGE_METADATA_OFFSET]);
        crc.update(&[0xff; 8]);
        crc.update(&data[super::IMAGE_METADATA_OFFSET + 8..]);
        let actual_crc = crc.finalize();
        if actual_crc != self.crc32 {
            return Err(invalid(format!(
                "application backup CRC mismatch: expected {:08X}, got {actual_crc:08X}",
                self.crc32
            )));
        }
        Ok(())
    }

    fn parse(bytes: &[u8]) -> Result<Self, KMError> {
        let bytes: &[u8; 64] = bytes
            .try_into()
            .map_err(|_| invalid("invalid installed firmware metadata length"))?;
        let size = u32::from_le_bytes(bytes[8..12].try_into().expect("fixed metadata field")) as usize;
        if bytes[..4] != 0x4000_u32.to_le_bytes() || !(0x460..=MAX_IMAGE_BYTES).contains(&size) {
            return Err(invalid("current application metadata has an invalid base or size"));
        }
        let mut info = DeviceInfo::default();
        info.parse_firmware_info(bytes);
        if [&info.fw_version, &info.fw_date]
            .iter()
            .any(|s| s.is_empty() || !s.is_ascii() || s.len() >= 12)
        {
            return Err(invalid("current application metadata has an invalid version or date"));
        }
        Ok(Self {
            version: info.fw_version,
            date: info.fw_date,
            size,
            crc32: u32::from_le_bytes(bytes[12..16].try_into().expect("fixed metadata field")),
        })
    }
}

/// Results of checking one specific meter against a validated package.
#[derive(Debug, Clone)]
pub struct FirmwareDeviceCheck {
    pub usb: FirmwareUsbDevice,
    pub selector: DeviceSelector,
    pub info: DeviceInfo,
    pub installed: Option<InstalledFirmwareInfo>,
}

/// Verified installed application bytes; no filesystem or UI policy is imposed.
#[derive(Debug, Clone)]
pub struct FirmwareBackup {
    device: DeviceInfo,
    firmware: InstalledFirmwareInfo,
    data: Vec<u8>,
}

impl FirmwareBackup {
    pub fn device(&self) -> &DeviceInfo {
        &self.device
    }
    pub fn firmware(&self) -> &InstalledFirmwareInfo {
        &self.firmware
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareInstallStage {
    CheckingDevice,
    BackingUp,
    SavingBackup,
    SwitchingToDfu,
    Transfer(super::FirmwareUpdateStage),
    StartingApplication,
    ReadingBack,
    Complete,
}

/// Shared progress events for CLI, desktop GUI and other frontends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareInstallProgress {
    pub stage: FirmwareInstallStage,
    /// Bytes for the current operation: plaintext backup/readback, ciphertext transfer.
    pub bytes_done: usize,
    pub total_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct FirmwareInstallResult {
    pub device: DeviceInfo,
    pub firmware: FirmwareMetadata,
    pub bytes_verified: usize,
}

/// A pinned device, validated package and optional verified application backup.
/// No flash is erased during preparation. Frontends receive the backup through
/// an asynchronous storage callback before the library enters DFU or writes.
pub struct PreparedFirmwareUpdate {
    check: FirmwareDeviceCheck,
    image: FirmwareImage,
    backup: Option<FirmwareBackup>,
    io: UsbInstall,
}

/// Read model, hardware and installed metadata without rebooting or writing flash.
pub async fn check_firmware_device(
    image: &FirmwareImage,
    selector: DeviceSelector,
) -> Result<FirmwareDeviceCheck, KMError> {
    let (mut device, check) = open_checked(image, selector).await?;
    if check.usb.mode == FirmwareUsbMode::Application {
        device.send(Packet::Disconnect).await?;
    }
    Ok(check)
}

impl PreparedFirmwareUpdate {
    /// Check a specific device and acquire two matching application reads.
    /// The caller must release any live measurement session first.
    pub async fn prepare(
        image: FirmwareImage,
        selector: DeviceSelector,
        mut progress: impl FnMut(FirmwareInstallProgress),
    ) -> Result<Self, KMError> {
        report(
            &mut progress,
            FirmwareInstallStage::CheckingDevice,
            0,
            image.metadata().size,
        );
        let (mut device, check) = open_checked(&image, selector).await?;
        let backup = if let Some(installed) = &check.installed {
            let size = installed.size;
            report(&mut progress, FirmwareInstallStage::BackingUp, 0, size * 2);
            let padded = (size as u32).div_ceil(16) * 16;
            let first = device.read_memory_block(0x4000, padded).await?;
            report(&mut progress, FirmwareInstallStage::BackingUp, size, size * 2);
            let second = device.read_memory_block(0x4000, padded).await?;
            let data = verified_backup_data(installed, &first, &second)?;
            report(&mut progress, FirmwareInstallStage::BackingUp, size * 2, size * 2);
            Some(FirmwareBackup {
                device: check.info.clone(),
                firmware: installed.clone(),
                data,
            })
        } else {
            None
        };
        let io = UsbInstall {
            selector: check.selector.clone(),
            device: Some(device),
            mode: check.usb.mode.clone(),
        };
        Ok(Self {
            check,
            image,
            backup,
            io,
        })
    }

    pub fn device(&self) -> &FirmwareDeviceCheck {
        &self.check
    }
    pub fn image(&self) -> &FirmwareImage {
        &self.image
    }
    pub fn backup(&self) -> Option<&FirmwareBackup> {
        self.backup.as_ref()
    }

    /// Save the backup, reboot to DFU, write once, restart and verify full readback.
    ///
    /// Storage is supplied by the frontend: it may write a file, persist an
    /// application attachment or hand bytes to a download UI. A storage error
    /// aborts before any reboot/erase. Already-DFU devices have no application
    /// backup and do not invoke the callback. Transfer failures leave DFU for
    /// a fresh update attempt; no data block is automatically retried.
    ///
    /// ```no_run
    /// # use km003c_lib::{error::KMError, firmware::PreparedFirmwareUpdate};
    /// # async fn install(prepared: PreparedFirmwareUpdate) -> Result<(), KMError> {
    /// let result = prepared.install(|backup| async move {
    ///     // A GUI may use its own asynchronous attachment/download storage.
    ///     // This example supplies a native file adapter.
    ///     use std::io::Write;
    ///     let mut file = std::fs::OpenOptions::new()
    ///         .write(true).create_new(true).open("current-firmware.bin")?;
    ///     file.write_all(backup.data())?;
    ///     file.sync_all()?;
    ///     Ok(())
    /// }, |_progress| {}).await?;
    /// assert_eq!(result.bytes_verified, result.firmware.size);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn install<Save, Saved>(
        self,
        save_backup: Save,
        progress: impl FnMut(FirmwareInstallProgress),
    ) -> Result<FirmwareInstallResult, KMError>
    where
        Save: FnOnce(FirmwareBackup) -> Saved,
        Saved: Future<Output = Result<(), KMError>>,
    {
        install_sequence(self.io, self.check.info, self.image, self.backup, save_backup, progress).await
    }
}

async fn open_checked(
    image: &FirmwareImage,
    selector: DeviceSelector,
) -> Result<(KM003C, FirmwareDeviceCheck), KMError> {
    image.validate_for_update()?;
    let usb = find_firmware_device(&selector).await?;
    let selector = usb
        .port_selector
        .clone()
        .or_else(|| usb.serial_number.clone().map(DeviceSelector::SerialNumber))
        .ok_or_else(|| invalid("device exposes neither a physical port nor a serial for stable selection"))?;
    let mut device = KM003C::open_maintenance(selector.clone()).await?;
    let (info, installed) = match &usb.mode {
        FirmwareUsbMode::Application => {
            connect_application(&mut device).await?;
            let mut info = DeviceInfo::default();
            info.parse_device_info(&device.read_memory_block(0x420, 64).await?);
            let bytes = device.read_memory_block(0x4420, 64).await?;
            info.parse_firmware_info(&bytes);
            (info, Some(InstalledFirmwareInfo::parse(&bytes)?))
        }
        FirmwareUsbMode::Dfu => (device.get_bootloader_info().await?, None),
        FirmwareUsbMode::Other(label) => return Err(invalid(format!("unsupported USB mode {label:?}"))),
    };
    if info.model != image.metadata().model {
        return Err(invalid("device model does not match package"));
    }
    Ok((
        device,
        FirmwareDeviceCheck {
            usb,
            selector,
            info,
            installed,
        },
    ))
}

async fn connect_application(device: &mut KM003C) -> Result<(), KMError> {
    device.send(Packet::Connect).await?;
    if !matches!(device.receive().await?, Packet::Accept { .. }) {
        return Err(invalid("application did not accept Connect"));
    }
    Ok(())
}

async fn wait_for_mode(selector: &DeviceSelector, expected: FirmwareUsbMode) -> Result<(), KMError> {
    let deadline = crate::runtime::Instant::now() + Duration::from_secs(20);
    loop {
        let observation = match find_firmware_device(selector).await {
            Ok(found) if found.mode == expected => return Ok(()),
            Ok(found) => format!("device is still in {:?}", found.mode),
            Err(error) => error.to_string(),
        };
        if crate::runtime::Instant::now() >= deadline {
            return Err(invalid(format!("timed out waiting for {expected:?}: {observation}")));
        }
        crate::runtime::sleep(Duration::from_millis(300)).await;
    }
}

// The real USB backend and scripted orchestration tests share this sequence.
trait InstallIo {
    async fn enter_dfu(&mut self) -> Result<(), KMError>;
    async fn transfer(
        &mut self,
        image: &FirmwareImage,
        progress: impl FnMut(FirmwareUpdateProgress),
    ) -> Result<(), KMError>;
    async fn restart_application(&mut self) -> Result<(), KMError>;
    async fn readback(&mut self, size: usize) -> Result<Vec<u8>, KMError>;
}

struct UsbInstall {
    selector: DeviceSelector,
    device: Option<KM003C>,
    mode: FirmwareUsbMode,
}
impl InstallIo for UsbInstall {
    async fn enter_dfu(&mut self) -> Result<(), KMError> {
        if self.mode == FirmwareUsbMode::Application {
            let mut app = self
                .device
                .take()
                .ok_or_else(|| invalid("application connection missing"))?;
            app.jump_to_dfu().await?;
            drop(app);
            wait_for_mode(&self.selector, FirmwareUsbMode::Dfu).await?;
        }
        let found = find_firmware_device(&self.selector).await?;
        if found.mode != FirmwareUsbMode::Dfu {
            return Err(invalid("selected device is not in DFU mode"));
        }
        // Release the identity-check handle before claiming this interface again.
        drop(self.device.take());
        self.device = Some(KM003C::open_maintenance(self.selector.clone()).await?);
        Ok(())
    }
    async fn transfer(
        &mut self,
        image: &FirmwareImage,
        progress: impl FnMut(FirmwareUpdateProgress),
    ) -> Result<(), KMError> {
        self.device
            .as_mut()
            .ok_or_else(|| invalid("bootloader connection missing"))?
            .update_firmware(image, progress)
            .await
    }
    async fn restart_application(&mut self) -> Result<(), KMError> {
        let mut boot = self
            .device
            .take()
            .ok_or_else(|| invalid("bootloader connection missing"))?;
        boot.jump_to_application().await?;
        drop(boot);
        wait_for_mode(&self.selector, FirmwareUsbMode::Application).await?;
        let mut app = KM003C::open_maintenance(self.selector.clone()).await?;
        connect_application(&mut app).await?;
        self.device = Some(app);
        Ok(())
    }
    async fn readback(&mut self, size: usize) -> Result<Vec<u8>, KMError> {
        let mut app = self
            .device
            .take()
            .ok_or_else(|| invalid("application connection missing"))?;
        let actual = app.read_memory_block(0x4000, (size as u32).div_ceil(16) * 16).await?;
        app.send(Packet::Disconnect).await?;
        Ok(actual)
    }
}

async fn install_sequence<Save, Saved>(
    mut io: impl InstallIo,
    mut info: DeviceInfo,
    image: FirmwareImage,
    backup: Option<FirmwareBackup>,
    save_backup: Save,
    mut progress: impl FnMut(FirmwareInstallProgress),
) -> Result<FirmwareInstallResult, KMError>
where
    Save: FnOnce(FirmwareBackup) -> Saved,
    Saved: Future<Output = Result<(), KMError>>,
{
    if let Some(backup) = backup {
        report(&mut progress, FirmwareInstallStage::SavingBackup, 0, backup.data.len());
        save_backup(backup).await?;
    }
    report(
        &mut progress,
        FirmwareInstallStage::SwitchingToDfu,
        0,
        image.metadata().size,
    );
    io.enter_dfu().await?;
    io.transfer(&image, |p| {
        report(
            &mut progress,
            FirmwareInstallStage::Transfer(p.stage),
            p.bytes_written,
            p.total_bytes,
        )
    })
    .await?;
    report(
        &mut progress,
        FirmwareInstallStage::StartingApplication,
        0,
        image.metadata().size,
    );
    io.restart_application().await?;
    report(
        &mut progress,
        FirmwareInstallStage::ReadingBack,
        0,
        image.metadata().size,
    );
    let expected = image.installed_data()?;
    let actual = io.readback(expected.len()).await?;
    if actual.get(..expected.len()) != Some(expected.as_slice()) {
        return Err(invalid(
            "device restarted, but full application readback does not match the expected installed image",
        ));
    }
    info.parse_firmware_info(&expected[0x420..0x460]);
    report(
        &mut progress,
        FirmwareInstallStage::Complete,
        expected.len(),
        expected.len(),
    );
    Ok(FirmwareInstallResult {
        device: info,
        firmware: image.metadata().clone(),
        bytes_verified: expected.len(),
    })
}

fn verified_backup_data(installed: &InstalledFirmwareInfo, first: &[u8], second: &[u8]) -> Result<Vec<u8>, KMError> {
    if !(0x460..=MAX_IMAGE_BYTES).contains(&installed.size) {
        return Err(invalid("application backup has an invalid size"));
    }
    let padded = installed.size.div_ceil(16) * 16;
    if first.len() != padded || second.len() != padded {
        return Err(invalid("application backup reads have an unexpected length"));
    }
    if first != second {
        return Err(invalid("application backup reads disagree; update aborted"));
    }
    let data = &first[..installed.size];
    installed.validate_application(data)?;
    Ok(data.to_vec())
}

fn report(
    progress: &mut impl FnMut(FirmwareInstallProgress),
    stage: FirmwareInstallStage,
    bytes_done: usize,
    total_bytes: usize,
) {
    progress(FirmwareInstallProgress {
        stage,
        bytes_done,
        total_bytes,
    });
}
fn invalid(message: impl Into<String>) -> KMError {
    KMError::Protocol(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};

    fn backup_read_fixture() -> (InstalledFirmwareInfo, Vec<u8>) {
        let image = crate::firmware::tests::image(4156);
        let mut installed = image.installed_data().unwrap();
        let info = InstalledFirmwareInfo::parse(&installed[0x420..0x460]).unwrap();
        assert_ne!(
            crc32fast::hash(&installed),
            info.crc32,
            "committed fields change the raw CRC"
        );
        installed.resize(installed.len().div_ceil(16) * 16, 0xa5);
        (info, installed)
    }

    #[test]
    fn backup_validation_restores_uncommitted_crc_fields_and_ignores_transport_padding() {
        let (info, installed) = backup_read_fixture();
        let data = verified_backup_data(&info, &installed, &installed).unwrap();
        assert_eq!(data, installed[..info.size]);
        assert_eq!(data.len(), info.size);
        info.validate_application(&data).unwrap();
    }

    #[test]
    fn two_identically_corrupted_reads_are_not_a_valid_backup() {
        let (info, mut bytes) = backup_read_fixture();
        bytes[0x500] ^= 1;
        assert!(
            verified_backup_data(&info, &bytes, &bytes)
                .unwrap_err()
                .to_string()
                .contains("CRC mismatch")
        );
    }

    #[test]
    fn backup_vectors_are_checked_even_when_the_crc_agrees() {
        let (mut info, mut bytes) = backup_read_fixture();
        bytes[..4].fill(0);
        let mut normalized = bytes[..info.size].to_vec();
        normalized[0x428..0x430].fill(0xff);
        info.crc32 = crc32fast::hash(&normalized);
        bytes[0x42c..0x430].copy_from_slice(&info.crc32.to_le_bytes());
        assert!(
            verified_backup_data(&info, &bytes, &bytes)
                .unwrap_err()
                .to_string()
                .contains("vectors")
        );
    }

    #[test]
    fn backup_rejects_changed_identity_short_reads_and_disagreement() {
        let (info, bytes) = backup_read_fixture();
        for offset in [0x430, 0x43c, 0x448] {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            assert!(
                verified_backup_data(&info, &changed, &changed)
                    .unwrap_err()
                    .to_string()
                    .contains("metadata")
            );
        }
        assert!(verified_backup_data(&info, &bytes[..info.size - 1], &bytes[..info.size - 1]).is_err());
        let mut changed = bytes.clone();
        changed[0x500] ^= 1;
        assert!(
            verified_backup_data(&info, &bytes, &changed)
                .unwrap_err()
                .to_string()
                .contains("disagree")
        );
        let mut invalid = info.clone();
        invalid.size = usize::MAX;
        assert!(invalid.validate_application(&bytes).is_err());
        assert!(verified_backup_data(&invalid, &bytes, &bytes).is_err());
    }
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn native_frontends_can_use_worker_futures() {
        fn assert_send(future: impl Future + Send) {
            drop(future);
        }
        assert_send(PreparedFirmwareUpdate::prepare(
            crate::firmware::tests::image(4156),
            DeviceSelector::First,
            |_| {},
        ));
        let check_install: fn(PreparedFirmwareUpdate) = |prepared| {
            assert_send(prepared.install(|_| async { Ok(()) }, |_| {}));
        };
        let _ = check_install;
    }
    struct Fake {
        events: Rc<RefCell<Vec<&'static str>>>,
        readback: Vec<u8>,
        fail_transfer: bool,
    }
    impl InstallIo for Fake {
        async fn enter_dfu(&mut self) -> Result<(), KMError> {
            self.events.borrow_mut().push("dfu");
            Ok(())
        }
        async fn transfer(&mut self, _: &FirmwareImage, _: impl FnMut(FirmwareUpdateProgress)) -> Result<(), KMError> {
            self.events.borrow_mut().push("write");
            if self.fail_transfer {
                Err(invalid("transfer failed"))
            } else {
                Ok(())
            }
        }
        async fn restart_application(&mut self) -> Result<(), KMError> {
            self.events.borrow_mut().push("restart");
            Ok(())
        }
        async fn readback(&mut self, _: usize) -> Result<Vec<u8>, KMError> {
            self.events.borrow_mut().push("readback");
            Ok(self.readback.clone())
        }
    }
    fn backup(image: &FirmwareImage) -> FirmwareBackup {
        FirmwareBackup {
            device: DeviceInfo::default(),
            firmware: InstalledFirmwareInfo {
                version: "1.9.7".into(),
                date: "2025.9.1".into(),
                size: image.data().len(),
                crc32: image.metadata().crc32,
            },
            data: image.installed_data().unwrap(),
        }
    }
    #[tokio::test]
    async fn storage_failure_aborts_before_any_reboot_or_flash() {
        let image = crate::firmware::tests::image(4156);
        let events = Rc::new(RefCell::new(Vec::new()));
        let fake = Fake {
            events: events.clone(),
            readback: Vec::new(),
            fail_transfer: false,
        };
        let result = install_sequence(
            fake,
            DeviceInfo::default(),
            image.clone(),
            Some(backup(&image)),
            |_| async { Err(KMError::Io(std::io::ErrorKind::WriteZero.into())) },
            |_| {},
        )
        .await;
        assert!(result.is_err());
        assert!(events.borrow().is_empty());
    }
    #[tokio::test]
    async fn complete_requires_saved_backup_and_matching_installed_bytes() {
        for corrupt in [false, true] {
            let image = crate::firmware::tests::image(4156);
            let events = Rc::new(RefCell::new(Vec::new()));
            let saved = events.clone();
            let mut readback = image.installed_data().unwrap();
            if corrupt {
                readback[0x500] ^= 1;
            }
            let fake = Fake {
                events: events.clone(),
                readback,
                fail_transfer: false,
            };
            let mut complete = false;
            let result = install_sequence(
                fake,
                DeviceInfo::default(),
                image.clone(),
                Some(backup(&image)),
                move |_| async move {
                    saved.borrow_mut().push("save");
                    Ok(())
                },
                |p| complete |= p.stage == FirmwareInstallStage::Complete,
            )
            .await;
            assert_eq!(result.is_ok(), !corrupt);
            assert_eq!(complete, !corrupt);
            assert_eq!(*events.borrow(), ["save", "dfu", "write", "restart", "readback"]);
        }
    }
    #[tokio::test]
    async fn failed_transfer_is_not_restarted_or_retried() {
        let image = crate::firmware::tests::image(4156);
        let events = Rc::new(RefCell::new(Vec::new()));
        let fake = Fake {
            events: events.clone(),
            readback: Vec::new(),
            fail_transfer: true,
        };
        assert!(
            install_sequence(
                fake,
                DeviceInfo::default(),
                image,
                None,
                |_| async { panic!("DFU recovery has no backup callback") },
                |_| {}
            )
            .await
            .is_err()
        );
        assert_eq!(*events.borrow(), ["dfu", "write"]);
    }
}
