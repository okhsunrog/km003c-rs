use super::*;
use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use std::collections::VecDeque;

pub(super) fn package(size: usize, trailer: &[u8]) -> Vec<u8> {
    let mut data = vec![0x5a; size];
    data[..4].copy_from_slice(&0x200067b0_u32.to_le_bytes());
    data[4..8].copy_from_slice(&0x4101_u32.to_le_bytes());
    data[0x420..0x424].copy_from_slice(&APPLICATION_BASE.to_le_bytes());
    data[0x428..0x430].fill(0xff);
    for (offset, value) in [(0x430, "KM003C"), (0x43c, "1.9.7"), (0x448, "2025.9.1")] {
        data[offset..offset + 12].fill(0);
        data[offset..offset + value.len()].copy_from_slice(value.as_bytes());
    }
    let fields = [
        "Firmware file".into(),
        "ChargerLab".into(),
        "V1.0".into(),
        "KM003C".into(),
        "1.9.7".into(),
        "2025.9.1".into(),
        format!("{:08X}", crc32fast::hash(&data)),
        size.to_string(),
        "修复".into(),
        "Release notes".into(),
    ];
    let mut bytes = (FIELD_COUNT as u32).to_be_bytes().to_vec();
    for field in fields {
        let encoded: Vec<u8> = field.encode_utf16().flat_map(u16::to_be_bytes).collect();
        bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&encoded);
    }
    data.resize(size.div_ceil(16) * 16, 0xff);
    let cipher = Aes128::new((&*MEMORY_READ_KEY).into());
    for block in data.as_chunks_mut::<16>().0 {
        cipher.encrypt_block(block.into());
    }
    bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
    bytes.extend(data);
    bytes.extend_from_slice(trailer);
    bytes
}

pub(super) fn image(size: usize) -> FirmwareImage {
    FirmwareImage::parse(&package(size, &[])).unwrap()
}

#[test]
fn preserves_qt_array_boundary_and_unicode_notes() {
    for trailer in [&[][..], &[0x94, 0xc2, 0xd2, 0xc7]] {
        let image = FirmwareImage::parse(&package(4156, trailer)).unwrap();
        image.validate_for_update().unwrap();
        assert_eq!(image.data.len(), 4156);
        assert_eq!(image.encrypted_data.len(), 4160);
        assert_eq!(image.trailer(), trailer);
        assert_eq!(image.metadata.notes_zh, "修复");
    }
}

#[test]
fn rejects_truncation_corruption_and_malformed_qt_lengths() {
    let bytes = package(4156, &[]);
    for end in [0, 3, 5, 20, 50, bytes.len() - 1, bytes.len() - 16] {
        assert!(FirmwareImage::parse(&bytes[..end]).is_err(), "truncation at {end}");
    }
    for (offset, value) in [(0, 11_u32), (4, 3), (4, u32::MAX)] {
        let mut invalid = bytes.clone();
        invalid[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        assert!(FirmwareImage::parse(&invalid).is_err());
    }
    let mut corrupt = bytes;
    *corrupt.last_mut().unwrap() ^= 0x80;
    assert!(FirmwareImage::parse(&corrupt).is_err());
}

#[test]
fn validates_embedded_identity_vectors_and_uncommitted_metadata() {
    for offset in [0, 4, 0x420, 0x428, 0x430, 0x43c, 0x448] {
        let mut image = image(4156);
        if offset <= 4 {
            image.data[offset..offset + 4].fill(0);
        } else {
            image.data[offset] ^= 0x80;
        }
        // Test semantic checks, rather than only a trivially failing checksum.
        image.metadata.crc32 = crc32fast::hash(&image.data);
        let mut padded = image.data.clone();
        padded.resize(padded.len().div_ceil(16) * 16, 0xff);
        let cipher = Aes128::new((&*MEMORY_READ_KEY).into());
        for block in padded.as_chunks_mut::<16>().0 {
            cipher.encrypt_block(block.into());
        }
        image.encrypted_data = padded;
        assert!(image.validate_for_update().is_err(), "offset {offset:x}");
    }
    let mut image = image(4156);
    image.metadata.model = "KM002C".into();
    assert!(image.validate_for_update().is_err());
}

#[test]
fn descriptor_and_readback_include_correct_lengths_and_crc() {
    let image = image(4156);
    let setup = image.setup_packet(62, 41).unwrap();
    assert_eq!(&setup[..4], &[0x42, 62, 0, 4]);
    assert_eq!(&setup[4..8], &0x4000_u32.to_le_bytes());
    assert_eq!(&setup[8..12], &(0x4000_u32 + 4156).to_le_bytes());
    assert_eq!(&setup[12..16], &4156_u32.to_le_bytes());
    assert_eq!(&setup[56..60], &41_u32.to_le_bytes());
    let installed = image.installed_data().unwrap();
    assert_eq!(&installed[0x428..0x430], &setup[12..20]);
    assert_eq!(&installed[..0x428], &image.data[..0x428]);
    assert_eq!(&installed[0x430..], &image.data[0x430..]);
    assert_ne!(crc32fast::hash(&installed), image.metadata.crc32);
    // This older release is intentionally accepted. No monotonic-version gate.
    assert_eq!(image.metadata.version, "1.9.7");
    image.validate_for_update().unwrap();
}

#[test]
fn handles_padded_modes_and_requires_full_control_frames() {
    assert_eq!(parse_mode_string("APP\0\u{ffff}").1, FirmwareUsbMode::Application);
    assert_eq!(parse_mode_string("DFU\0\u{ffff}").1, FirmwareUsbMode::Dfu);
    assert_eq!(parse_mode_string("BOOT").1, FirmwareUsbMode::Dfu);
    for bytes in [&[][..], &[5], &[5, 7, 0], &[5, 7, 0, 0, 0]] {
        assert!(expect_type(bytes, PacketType::Accept, "test").is_err());
    }
    expect_type(&[5, 234, 0, 0], PacketType::Accept, "test").unwrap();
}

struct FakeTransport {
    replies: VecDeque<Result<Vec<u8>, KMError>>,
    writes: Vec<Vec<u8>>,
    deadlines: Vec<Duration>,
    delay_erase: bool,
    failed_write: Option<usize>,
}

impl FirmwareTransport for FakeTransport {
    fn next_id(&mut self) -> u8 {
        self.writes.len() as u8
    }
    async fn write(&mut self, bytes: &[u8]) -> Result<(), KMError> {
        self.writes.push(bytes.to_vec());
        if self.failed_write == Some(self.writes.len() - 1) {
            return Err(KMError::Io(std::io::ErrorKind::BrokenPipe.into()));
        }
        Ok(())
    }
    async fn read(&mut self, timeout: Duration) -> Result<Vec<u8>, KMError> {
        self.deadlines.push(timeout);
        if self.delay_erase && self.deadlines.len() == 3 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        self.replies.pop_front().expect("unexpected additional receive")
    }
}

fn transport() -> FakeTransport {
    let mut head = vec![0; 20];
    head[..4].copy_from_slice(&[0xc0, 1, 1, 1]);
    FakeTransport {
        replies: [
            vec![5, 0, 0, 0],
            head,
            vec![5, 2, 0, 0],
            vec![1, 3, 0, 0],
            vec![1, 4, 0, 0],
            vec![7, 5, 0, 0],
        ]
        .into_iter()
        .map(Ok)
        .collect(),
        writes: Vec::new(),
        deadlines: Vec::new(),
        delay_erase: false,
        failed_write: None,
    }
}

#[tokio::test]
async fn uploads_original_ciphertext_with_immediate_or_delayed_erase_ack() {
    for delay in [false, true] {
        let image = image(4156);
        let mut usb = transport();
        usb.delay_erase = delay;
        let mut progress = Vec::new();
        transfer_image(&mut usb, &image, 41, |p| progress.push(p))
            .await
            .unwrap();
        assert_eq!(usb.writes.len(), 5);
        assert_eq!(usb.writes[3].len(), 4080);
        assert_eq!(usb.writes[4].len(), 80);
        assert_eq!(
            [usb.writes[3].clone(), usb.writes[4].clone()].concat(),
            image.encrypted_data
        );
        assert_eq!(usb.deadlines[2], Duration::from_secs(20));
        assert_eq!(progress.last().unwrap().stage, FirmwareUpdateStage::Complete);
        assert!(usb.replies.is_empty());
    }
}

#[tokio::test]
async fn never_retries_a_block_after_timeout_or_disconnect() {
    let timeout = crate::runtime::timeout(Duration::ZERO, std::future::pending::<()>())
        .await
        .unwrap_err();
    for error in [
        KMError::Timeout(timeout),
        KMError::Io(std::io::ErrorKind::BrokenPipe.into()),
    ] {
        let mut usb = transport();
        usb.replies[3] = Err(error);
        assert!(transfer_image(&mut usb, &image(4156), 41, |_| {}).await.is_err());
        assert_eq!(usb.writes.len(), 4, "no second block or duplicate send");
    }
}

#[tokio::test]
async fn never_retries_an_uncertain_write_or_a_timed_out_erase() {
    let mut usb = transport();
    usb.failed_write = Some(3);
    assert!(transfer_image(&mut usb, &image(4156), 41, |_| {}).await.is_err());
    assert_eq!(usb.writes.len(), 4);

    let timeout = crate::runtime::timeout(Duration::ZERO, std::future::pending::<()>())
        .await
        .unwrap_err();
    let mut usb = transport();
    usb.replies[2] = Err(KMError::Timeout(timeout));
    assert!(transfer_image(&mut usb, &image(4156), 41, |_| {}).await.is_err());
    assert_eq!(usb.writes.len(), 3, "Setup must not be resent after a timeout");
}

#[tokio::test]
async fn checks_bootloader_identity_with_independent_ids_and_confirmation_crc() {
    let mut data = [0; 64];
    data[16..22].copy_from_slice(b"KM003C");
    data[28..31].copy_from_slice(b"2.1");
    let cipher = Aes128::new((&*MEMORY_READ_KEY).into());
    for block in data.as_chunks_mut::<16>().0 {
        cipher.encrypt_block(block.into());
    }
    let mut confirmation = vec![0xc4, 203, 1, 1];
    confirmation.extend_from_slice(&0x420_u32.to_le_bytes());
    confirmation.extend_from_slice(&64_u32.to_le_bytes());
    confirmation.extend_from_slice(&u32::MAX.to_le_bytes());
    let crc = crc32fast::hash(&confirmation[4..]);
    confirmation.extend_from_slice(&crc.to_le_bytes());
    let mut usb = transport();
    usb.replies = [vec![5, 202, 0, 0], confirmation.clone(), data.to_vec()]
        .into_iter()
        .map(Ok)
        .collect();
    let info = bootloader_info(&mut usb).await.unwrap();
    assert_eq!(info.model, "KM003C");
    assert_eq!(info.hw_version, "2.1");
    assert_eq!(usb.writes.len(), 2);
    assert_eq!(
        crate::auth::parse_memory_read_payload(&usb.writes[1][4..]),
        Some((0x420, 64))
    );

    *confirmation.last_mut().unwrap() ^= 1;
    let mut usb = transport();
    usb.replies = [vec![5, 202, 0, 0], confirmation].into_iter().map(Ok).collect();
    assert!(bootloader_info(&mut usb).await.is_err());
    assert!(usb.replies.is_empty());
}

#[tokio::test]
async fn erase_failure_sends_no_ciphertext_and_crc_error_never_completes() {
    for (index, response) in [(2, vec![6, 2, 0, 0]), (5, vec![11, 5, 0, 3]), (3, vec![1])] {
        let mut usb = transport();
        usb.replies[index] = Ok(response);
        let mut complete = false;
        let error = transfer_image(&mut usb, &image(4156), 41, |p| {
            complete |= p.stage == FirmwareUpdateStage::Complete
        })
        .await
        .unwrap_err();
        assert!(!complete);
        if index == 2 {
            assert_eq!(usb.writes.len(), 3);
        }
        if index == 5 {
            assert!(error.to_string().contains("code 12"));
        }
    }
}
