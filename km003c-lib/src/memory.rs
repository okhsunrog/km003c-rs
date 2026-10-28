//! MemoryRead transactions, independent of USB transport and UI.
//!
//! The inspected 2.0.5 APP marks the response plaintext, but still encrypts
//! every full 0x9f0-byte block. Request at most 0x9e0 bytes so each response has
//! one encoding. Chunk boundaries stay aligned; even plaintext uses 16-byte
//! transport padding, which is removed separately for each response.

use crate::{
    error::KMError,
    packet::{PacketType, RawPacket},
};

const AES_BLOCK_SIZE: usize = 16;
const MAX_CHUNK_BYTES: u32 = 0x9e0;
// Preserve the inspected firmware's single-read limit when splitting requests.
const MAX_READ_BYTES: u32 = 4_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemoryEncoding {
    Plaintext,
    Aes128Ecb,
}

pub(crate) trait MemoryReadIo {
    async fn begin_read(&mut self, address: u32, size: u32) -> Result<(u8, RawPacket), KMError>;
    async fn next_transfer(&mut self) -> Result<Vec<u8>, KMError>;
}

pub(crate) async fn read(io: &mut impl MemoryReadIo, address: u32, size: u32) -> Result<Vec<u8>, KMError> {
    if size > MAX_READ_BYTES {
        return Err(KMError::Protocol("memory read exceeds firmware size limit".into()));
    }
    let padded = memory_response_size(size) as u32;
    if address.checked_add(padded.saturating_sub(1)).is_none() {
        return Err(KMError::Protocol("memory read address range overflows".into()));
    }
    let mut output = Vec::with_capacity(size as usize);
    let mut offset = 0;
    loop {
        let requested = (size - offset).min(MAX_CHUNK_BYTES);
        let chunk_address = address + offset;
        let (id, confirmation) = io.begin_read(chunk_address, requested).await?;
        match confirmation.packet_type() {
            PacketType::Rejected => {
                return Err(KMError::Protocol(format!(
                    "MemoryRead at 0x{chunk_address:08X} was rejected"
                )));
            }
            PacketType::NotReadable => {
                return Err(KMError::Protocol(format!(
                    "Memory address 0x{chunk_address:08X} is not readable"
                )));
            }
            _ => {}
        }
        let encoding = validate_memory_read_confirmation(&confirmation, id, chunk_address, requested)?;
        let expected = memory_response_size(requested);
        let mut data = Vec::with_capacity(expected);
        while data.len() < expected {
            let transfer = io.next_transfer().await?;
            append_memory_chunk(&mut data, &transfer, expected)?;
        }
        // Strip each response's own padding before requesting the next address.
        output.extend(decode_memory_response(&data, requested, encoding)?);
        offset += requested;
        if offset == size {
            return Ok(output);
        }
    }
}

fn memory_response_size(requested_size: u32) -> usize {
    (requested_size as usize).div_ceil(AES_BLOCK_SIZE) * AES_BLOCK_SIZE
}

fn append_memory_chunk(buffer: &mut Vec<u8>, chunk: &[u8], expected_size: usize) -> Result<bool, KMError> {
    if chunk.is_empty() {
        return Err(KMError::Protocol("Received an empty memory chunk".to_string()));
    }

    let remaining = expected_size.saturating_sub(buffer.len());
    if chunk.len() > remaining {
        return Err(KMError::Protocol(format!(
            "Memory response exceeded expected size: expected {expected_size} bytes, got at least {}",
            buffer.len() + chunk.len()
        )));
    }

    buffer.extend_from_slice(chunk);
    Ok(buffer.len() == expected_size)
}

fn decode_memory_response(bytes: &[u8], requested_size: u32, encoding: MemoryEncoding) -> Result<Vec<u8>, KMError> {
    let expected_size = memory_response_size(requested_size);
    if bytes.len() != expected_size {
        return Err(KMError::Protocol(format!(
            "Memory response has the wrong size: expected {expected_size} bytes, got {}",
            bytes.len()
        )));
    }

    if encoding == MemoryEncoding::Plaintext && requested_size >= 0x9f0 {
        return Err(KMError::Protocol(
            "plaintext memory response may contain encrypted blocks; use bounded reads".into(),
        ));
    }
    let mut decrypted = match encoding {
        MemoryEncoding::Aes128Ecb => crate::auth::aes_ecb_decrypt_blocks(bytes, &crate::auth::MEMORY_READ_KEY)?,
        MemoryEncoding::Plaintext => bytes.to_vec(),
    };
    decrypted.truncate(requested_size as usize);
    Ok(decrypted)
}

fn validate_memory_read_confirmation(
    packet: &RawPacket,
    expected_id: u8,
    expected_address: u32,
    expected_size: u32,
) -> Result<MemoryEncoding, KMError> {
    let RawPacket::SimpleData { header, payload } = packet else {
        return Err(KMError::Protocol(
            "MemoryRead confirmation has an unexpected packet layout".to_string(),
        ));
    };

    if header.id() != expected_id || PacketType::from(header.packet_type()) != PacketType::MemoryRead {
        return Err(KMError::Protocol(
            "MemoryRead confirmation does not match the request".to_string(),
        ));
    }
    if payload.len() != crate::auth::MEMORY_READ_CONFIRMATION_SIZE {
        return Err(KMError::Protocol(format!(
            "MemoryRead confirmation must contain {} bytes, got {}",
            crate::auth::MEMORY_READ_CONFIRMATION_SIZE,
            payload.len()
        )));
    }

    let confirmation = crate::auth::MemoryReadConfirmation::from_bytes(payload)
        .ok_or_else(|| KMError::Protocol("MemoryRead confirmation body is truncated".to_string()))?;

    if confirmation.address != expected_address || confirmation.size != expected_size {
        return Err(KMError::Protocol(format!(
            "MemoryRead confirmation echoed address 0x{:08X} and size {}, expected 0x{expected_address:08X} and {expected_size}",
            confirmation.address, confirmation.size
        )));
    }
    if confirmation.magic != u32::MAX {
        return Err(KMError::Protocol(format!(
            "MemoryRead confirmation has invalid magic 0x{:08X}",
            confirmation.magic
        )));
    }
    if confirmation.checksum != confirmation.expected_checksum {
        return Err(KMError::Protocol(format!(
            "MemoryRead confirmation CRC mismatch: expected 0x{:08X}, got 0x{:08X}",
            confirmation.expected_checksum, confirmation.checksum
        )));
    }

    // Byte 2 bit 0 is outside DataHeader's object count, in its skipped flag bits.
    Ok(if header.into_bytes()[2] & 1 == 0 {
        MemoryEncoding::Plaintext
    } else {
        MemoryEncoding::Aes128Ecb
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::{
        Aes128,
        cipher::{BlockCipherEncrypt, KeyInit},
    };
    use bytes::Bytes;
    use std::collections::VecDeque;

    struct Step {
        address: u32,
        size: u32,
        id: u8,
        reply: RawPacket,
        transfers: VecDeque<Result<Vec<u8>, KMError>>,
    }

    #[derive(Default)]
    struct Scripted {
        steps: VecDeque<Step>,
        active: VecDeque<Result<Vec<u8>, KMError>>,
        requests: Vec<(u32, u32)>,
        transfer_reads: usize,
    }

    impl MemoryReadIo for Scripted {
        async fn begin_read(&mut self, address: u32, size: u32) -> Result<(u8, RawPacket), KMError> {
            assert!(self.active.is_empty(), "previous response was not completely consumed");
            let step = self.steps.pop_front().expect("unexpected memory request");
            assert_eq!((address, size), (step.address, step.size));
            self.requests.push((address, size));
            self.active = step.transfers;
            Ok((step.id, step.reply))
        }
        async fn next_transfer(&mut self) -> Result<Vec<u8>, KMError> {
            self.transfer_reads += 1;
            self.active.pop_front().expect("read beyond the response boundary")
        }
    }

    fn confirmation(address: u32, size: u32, id: u8, encoding: MemoryEncoding) -> RawPacket {
        let request = crate::auth::build_memory_read_payload(address, size);
        let body = crate::auth::decrypt_memory_read_response(&request).unwrap();
        let flag = u8::from(encoding == MemoryEncoding::Aes128Ecb);
        let mut bytes = vec![0xc4, id, flag, 1];
        bytes.extend_from_slice(&body[..16]);
        RawPacket::try_from(Bytes::from(bytes)).unwrap()
    }

    fn step(address: u32, id: u8, source: &[u8], encoding: MemoryEncoding) -> Step {
        let size = source.len() as u32;
        let mut data = source.to_vec();
        data.resize(memory_response_size(size), 0xa5);
        if encoding == MemoryEncoding::Aes128Ecb {
            let cipher = Aes128::new((&*crate::auth::MEMORY_READ_KEY).into());
            for block in data.as_chunks_mut::<16>().0 {
                cipher.encrypt_block(block.into());
            }
        }
        Step {
            address,
            size,
            id,
            reply: confirmation(address, size, id, encoding),
            // Exercise buffering across non-AES-aligned transport fragments.
            transfers: data.chunks(127).map(|bytes| Ok(bytes.to_vec())).collect(),
        }
    }

    #[tokio::test]
    async fn bounded_reads_preserve_bytes_padding_and_transaction_boundaries() {
        // Boundaries found by executing the original APP handlers. In 2.0.5,
        // requesting 2544 bytes would enter the encrypted full-block path while
        // the header claims plaintext. These plans must never request that size.
        let cases: &[(usize, &[usize])] = &[
            (0, &[0]),
            (12, &[12]),
            (64, &[64]),
            (2528, &[2528]),
            (2529, &[2528, 1]),
            (2543, &[2528, 15]),
            (2544, &[2528, 16]),
            (2545, &[2528, 17]),
            (5088, &[2528, 2528, 32]),
            (8336, &[2528, 2528, 2528, 752]),
        ];
        for &(size, chunks) in cases {
            let source: Vec<_> = (0..size).map(|i| (i * 17 + 23) as u8).collect();
            for mode in 0..3 {
                let mut io = Scripted::default();
                let mut offset = 0;
                for (index, &chunk) in chunks.iter().enumerate() {
                    let encoding = match mode {
                        0 => MemoryEncoding::Plaintext,
                        1 => MemoryEncoding::Aes128Ecb,
                        _ if index % 2 == 0 => MemoryEncoding::Aes128Ecb,
                        _ => MemoryEncoding::Plaintext,
                    };
                    io.steps.push_back(step(
                        0x98100000 + offset as u32,
                        254_u8.wrapping_add(index as u8),
                        &source[offset..offset + chunk],
                        encoding,
                    ));
                    offset += chunk;
                }
                assert_eq!(read(&mut io, 0x98100000, size as u32).await.unwrap(), source);
                assert!(io.steps.is_empty() && io.active.is_empty());
                assert!(io.requests.iter().all(|(_, n)| *n < 2544));
                if size == 0 {
                    assert_eq!(io.transfer_reads, 0);
                }
            }
        }
    }

    #[tokio::test]
    async fn invalid_ranges_fail_before_sending_a_request() {
        for (address, size) in [(u32::MAX, 1), (u32::MAX - 15, 17), (0x420, 4_000_001)] {
            let mut io = Scripted::default();
            assert!(read(&mut io, address, size).await.is_err());
            assert!(io.requests.is_empty());
        }
    }

    #[tokio::test]
    async fn bad_confirmation_does_not_consume_data_or_send_another_request() {
        let mut first = step(0x4000, 7, &[1; 2528], MemoryEncoding::Plaintext);
        first.reply = confirmation(0x4001, 2528, 7, MemoryEncoding::Plaintext);
        let mut io = Scripted {
            steps: VecDeque::from([first]),
            ..Scripted::default()
        };
        assert!(read(&mut io, 0x4000, 2544).await.is_err());
        assert_eq!(io.requests, [(0x4000, 2528)]);
        assert_eq!(io.transfer_reads, 0);
    }

    #[tokio::test]
    async fn failed_data_read_is_not_retried_or_returned_as_partial_success() {
        let mut first = step(0x4000, 7, &[1; 2528], MemoryEncoding::Aes128Ecb);
        first.transfers = VecDeque::from([Ok(vec![0; 16]), Err(KMError::Protocol("injected read failure".into()))]);
        let mut io = Scripted {
            steps: VecDeque::from([first]),
            ..Scripted::default()
        };
        assert!(
            read(&mut io, 0x4000, 2544)
                .await
                .unwrap_err()
                .to_string()
                .contains("injected")
        );
        assert_eq!(io.requests, [(0x4000, 2528)]);
    }

    #[tokio::test]
    async fn rejection_is_returned_without_waiting_for_unframed_data() {
        for kind in [PacketType::Rejected, PacketType::NotReadable] {
            let mut first = step(0x420, 9, &[1; 64], MemoryEncoding::Plaintext);
            first.reply = RawPacket::try_from(Bytes::from(vec![u8::from(kind), 9, 0, 0])).unwrap();
            let mut io = Scripted {
                steps: VecDeque::from([first]),
                ..Scripted::default()
            };
            assert!(read(&mut io, 0x420, 64).await.is_err());
            assert_eq!(io.transfer_reads, 0);
        }
    }

    #[test]
    fn encoding_flag_does_not_confuse_other_reserved_bits_or_word_count() {
        for encoding in [MemoryEncoding::Plaintext, MemoryEncoding::Aes128Ecb] {
            let RawPacket::SimpleData { header, payload } = confirmation(0x420, 64, 2, encoding) else {
                unreachable!()
            };
            let mut raw = header.into_bytes();
            raw[2] |= 0x3e;
            let packet = RawPacket::SimpleData {
                header: crate::packet::DataHeader::from_bytes(raw),
                payload,
            };
            assert_eq!(
                validate_memory_read_confirmation(&packet, 2, 0x420, 64).unwrap(),
                encoding
            );
        }
    }

    #[test]
    fn replayed_application_responses_keep_the_original_encoding_semantics() {
        let fixtures: &[(&[u8], &[u8])] = &[
            (
                include_bytes!("../tests/fixtures/memory_read/1.9.9-header.bin"),
                include_bytes!("../tests/fixtures/memory_read/1.9.9-data.bin"),
            ),
            (
                include_bytes!("../tests/fixtures/memory_read/2.0.5-header.bin"),
                include_bytes!("../tests/fixtures/memory_read/2.0.5-data.bin"),
            ),
            (
                include_bytes!("../tests/fixtures/memory_read/2.0.6-header.bin"),
                include_bytes!("../tests/fixtures/memory_read/2.0.6-data.bin"),
            ),
            (
                include_bytes!("../tests/fixtures/memory_read/2.0.7-header.bin"),
                include_bytes!("../tests/fixtures/memory_read/2.0.7-data.bin"),
            ),
        ];
        let expected: Vec<_> = (0..12).map(|i| (i * 17 + 23) as u8).collect();
        for &(header, data) in fixtures {
            let packet = RawPacket::try_from(Bytes::copy_from_slice(header)).unwrap();
            let encoding = validate_memory_read_confirmation(&packet, 0x2a, 0x20020000, 12).unwrap();
            assert_eq!(decode_memory_response(data, 12, encoding).unwrap(), expected);
        }
    }

    #[test]
    fn mixed_205_response_is_rejected_instead_of_silently_returning_ciphertext() {
        let packet = RawPacket::try_from(Bytes::from_static(include_bytes!(
            "../tests/fixtures/memory_read/2.0.5-large-header.bin"
        )))
        .unwrap();
        let data = include_bytes!("../tests/fixtures/memory_read/2.0.5-large-data.bin");
        let encoding = validate_memory_read_confirmation(&packet, 0x2a, 0x20020000, 2544).unwrap();
        assert_eq!(encoding, MemoryEncoding::Plaintext);
        assert!(decode_memory_response(data, 2544, encoding).is_err());
    }

    #[tokio::test]
    async fn bounded_read_replays_full_8336_byte_logs_from_four_application_handlers() {
        let fixtures: &[&[u8]] = &[
            include_bytes!("../tests/fixtures/memory_read/1.9.9-8336.bin"),
            include_bytes!("../tests/fixtures/memory_read/2.0.5-8336.bin"),
            include_bytes!("../tests/fixtures/memory_read/2.0.6-8336.bin"),
            include_bytes!("../tests/fixtures/memory_read/2.0.7-8336.bin"),
        ];
        let expected: Vec<_> = (0..8336).map(|i| (i * 17 + 23) as u8).collect();
        for &fixture in fixtures {
            let mut io = Scripted::default();
            let mut bytes = fixture;
            let mut offset = 0;
            for (index, size) in [2528_u32, 2528, 2528, 752].into_iter().enumerate() {
                let (header, tail) = bytes.split_at(20);
                let (payload, tail) = tail.split_at(size as usize);
                bytes = tail;
                io.steps.push_back(Step {
                    address: 0x20020000 + offset,
                    size,
                    id: 42 + index as u8,
                    reply: RawPacket::try_from(Bytes::copy_from_slice(header)).unwrap(),
                    transfers: VecDeque::from([Ok(payload.to_vec())]),
                });
                offset += size;
            }
            assert!(bytes.is_empty());
            assert_eq!(read(&mut io, 0x20020000, 8336).await.unwrap(), expected);
            assert!(io.steps.is_empty() && io.active.is_empty());
        }
    }
    #[test]
    fn memory_response_size_rounds_to_complete_aes_blocks() {
        assert_eq!(memory_response_size(1), 16);
        assert_eq!(memory_response_size(12), 16);
        assert_eq!(memory_response_size(16), 16);
        assert_eq!(memory_response_size(17), 32);
        assert_eq!(memory_response_size(64), 64);
    }

    #[test]
    fn decrypted_memory_response_is_trimmed_to_the_requested_size() {
        let ciphertext = crate::auth::build_memory_read_payload(0x4001_0450, 12);
        let decrypted = decode_memory_response(&ciphertext[..16], 12, MemoryEncoding::Aes128Ecb).unwrap();

        assert_eq!(decrypted.len(), 12);
        assert_eq!(&decrypted[..4], &0x4001_0450_u32.to_le_bytes());
        assert_eq!(&decrypted[4..8], &12_u32.to_le_bytes());
        assert_eq!(&decrypted[8..12], &u32::MAX.to_le_bytes());
    }

    #[test]
    fn decrypted_memory_response_rejects_an_incorrect_ciphertext_size() {
        assert!(decode_memory_response(&[0; 32], 12, MemoryEncoding::Aes128Ecb).is_err());
    }

    #[test]
    fn memory_chunks_accumulate_across_usb_transfers() {
        // Source: reading_logs0.11; a requested 8336-byte log arrived as
        // three 2544-byte USB transfers followed by one 704-byte transfer.
        let mut response = Vec::new();
        assert!(!append_memory_chunk(&mut response, &vec![0x11; 2544], 8336).unwrap());
        assert!(!append_memory_chunk(&mut response, &vec![0x22; 2544], 8336).unwrap());
        assert!(!append_memory_chunk(&mut response, &vec![0x33; 2544], 8336).unwrap());
        assert!(append_memory_chunk(&mut response, &vec![0x44; 704], 8336).unwrap());
        assert_eq!(response.len(), 8336);
    }

    #[test]
    fn memory_chunks_reject_empty_and_oversized_transfers() {
        let mut response = vec![0; 15];
        assert!(append_memory_chunk(&mut response, &[], 16).is_err());
        assert!(append_memory_chunk(&mut response, &[1, 2], 16).is_err());
    }

    #[test]
    fn validates_recorded_memory_read_confirmation() {
        // Source: usb_master_dataset.parquet, orig_adc_1000hz.6, frame 264.
        let bytes = hex::decode("c40201012004000040000000ffffffff1b8c1b24").unwrap();
        let packet = RawPacket::try_from(Bytes::from(bytes)).unwrap();

        validate_memory_read_confirmation(&packet, 2, 0x420, 64).unwrap();
    }

    #[test]
    fn rejects_corrupted_memory_read_confirmation() {
        let mut bytes = hex::decode("c40201012004000040000000ffffffff1b8c1b24").unwrap();
        bytes[8] ^= 1;
        let packet = RawPacket::try_from(Bytes::from(bytes)).unwrap();

        assert!(validate_memory_read_confirmation(&packet, 2, 0x420, 64).is_err());
    }
}
