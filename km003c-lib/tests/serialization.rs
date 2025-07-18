//! Tests for packet serialization functionality

mod common;

use common::*;

#[test]
fn test_rawpacket_to_bytes_ctrl() {
    // Test direct conversion of Ctrl packet to bytes
    let raw_packet = RawPacket::Ctrl {
        header: CtrlHeader::new()
            .with_packet_type(2)
            .with_extend(false)
            .with_id(1)
            .with_attribute(0),
        payload: Bytes::new(),
    };

    let bytes = Bytes::from(raw_packet);
    let expected_bytes = [0x02, 0x01, 0x00, 0x00];

    assert_eq!(
        bytes.as_ref(),
        &expected_bytes,
        "Ctrl packet should convert to [02, 01, 00, 00], got {:02x?}",
        bytes.as_ref()
    );
}

#[test]
fn test_rawpacket_to_bytes_data() {
    // Test direct conversion of Data packet to bytes
    let payload = Bytes::from_static(&[0xAA, 0xBB, 0xCC, 0xDD]);
    let raw_packet = RawPacket::Data {
        header: DataHeader::new()
            .with_packet_type(64)
            .with_extend(false)
            .with_id(1)
            .with_obj_count_words(4),
        payload,
    };

    let bytes = Bytes::from(raw_packet);
    let expected_bytes = [0x40, 0x01, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD];

    assert_eq!(
        bytes.as_ref(),
        &expected_bytes,
        "Data packet should convert to [40, 01, 00, 01, AA, BB, CC, DD], got {:02x?}",
        bytes.as_ref()
    );
}

#[test]
fn test_rawpacket_to_bytes_ctrl_with_payload() {
    // Test Ctrl packet with non-empty payload
    let payload = Bytes::from_static(&[0x12, 0x34]);
    let raw_packet = RawPacket::Ctrl {
        header: CtrlHeader::new()
            .with_packet_type(5)
            .with_extend(true)
            .with_id(7)
            .with_attribute(0x123),
        payload,
    };

    let bytes = Bytes::from(raw_packet.clone());

    // Verify the structure by doing a round-trip conversion
    let original_bytes = bytes.clone();
    let parsed_packet = RawPacket::try_from(original_bytes).expect("Failed to parse generated bytes");

    // Verify the parsed packet matches our original
    match parsed_packet {
        RawPacket::Ctrl {
            header,
            payload: parsed_payload,
        } => {
            assert_eq!(header.packet_type(), 5, "Packet type should be 5");
            assert_eq!(header.extend(), true, "Extend should be true");
            assert_eq!(header.id(), 7, "ID should be 7");
            assert_eq!(header.attribute(), 0x123, "Attribute should be 0x123");
            assert_eq!(parsed_payload.as_ref(), &[0x12, 0x34], "Payload should match");
        }
        _ => panic!("Expected Ctrl packet"),
    }

    // Verify total length (4 byte header + 2 byte payload = 6 bytes)
    assert_eq!(bytes.len(), 6, "Total packet should be 6 bytes");

    // Verify payload is correctly appended
    assert_eq!(&bytes[4..], &[0x12, 0x34], "Payload should be correctly appended");
}

#[test]
fn test_rawpacket_to_bytes_empty_payload() {
    // Test edge case with empty payloads for both packet types
    let ctrl_packet = RawPacket::Ctrl {
        header: CtrlHeader::new()
            .with_packet_type(12)
            .with_extend(false)
            .with_id(0)
            .with_attribute(1),
        payload: Bytes::new(),
    };

    let data_packet = RawPacket::Data {
        header: DataHeader::new()
            .with_packet_type(65)
            .with_extend(false)
            .with_id(0)
            .with_obj_count_words(0),
        payload: Bytes::new(),
    };

    let ctrl_bytes = Bytes::from(ctrl_packet);
    let data_bytes = Bytes::from(data_packet);

    assert_eq!(ctrl_bytes.len(), 4, "Ctrl packet with empty payload should be 4 bytes");
    assert_eq!(data_bytes.len(), 4, "Data packet with empty payload should be 4 bytes");
}

#[test]
fn test_rawpacket_to_bytes_large_payload() {
    // Test with a larger payload to ensure the trait handles size correctly
    let large_payload: Vec<u8> = (0..=255u8).collect();
    let raw_packet = RawPacket::Data {
        header: DataHeader::new()
            .with_packet_type(65)
            .with_extend(true)
            .with_id(42)
            .with_obj_count_words(64), // 256 bytes = 64 words (assuming 4 bytes per word)
        payload: Bytes::from(large_payload.clone()),
    };

    let bytes = Bytes::from(raw_packet);

    // Verify total length (4 byte header + 256 byte payload = 260 bytes)
    assert_eq!(bytes.len(), 260, "Large payload packet should be 260 bytes total");

    // Verify payload is correctly appended
    assert_eq!(
        &bytes[4..],
        &large_payload,
        "Payload should be correctly appended after header"
    );
}
