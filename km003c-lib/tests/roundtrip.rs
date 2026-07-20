//! Tests for round-trip conversion integrity

mod common;

use common::*;

#[test]
fn test_unknown_control_packet_preserves_payload() {
    let original = RawPacket::Ctrl {
        header: CtrlHeader::new()
            .with_packet_type(PacketType::GetStatus.into())
            .with_reserved_flag(false)
            .with_id(7)
            .with_attribute(0),
        payload: vec![0xaa, 0xbb, 0xcc],
    };

    let parsed = Packet::try_from(original.clone()).unwrap();
    assert_eq!(parsed, Packet::Generic(original));
}

#[test]
fn captured_auth_requests_roundtrip_as_semantic_packets() {
    let memory =
        Bytes::from(hex::decode("4402010133f8860c0054288cdc7e52729826872dd18b539a39c407d5c063d91102e36a9e").unwrap());
    let memory_packet = Packet::try_from(RawPacket::try_from(memory.clone()).unwrap()).unwrap();
    assert!(matches!(
        memory_packet,
        Packet::MemoryRead {
            address: 0x420,
            size: 64
        }
    ));
    assert_eq!(Bytes::from(memory_packet.to_raw_packet(2).unwrap()), memory);

    let auth =
        Bytes::from(hex::decode("4c0600025538815b69a452c83e54ef1d70f3bc9ae6aac1b12a6ac07c20fde58c7bf517ca").unwrap());
    let auth_packet = Packet::try_from(RawPacket::try_from(auth).unwrap()).unwrap();
    let Packet::StreamingAuth { hardware_id } = auth_packet else {
        panic!("captured StreamingAuth request did not parse semantically");
    };
    assert_eq!(hardware_id.as_bytes(), b"071KBP\r\xff\x11\n\xff\xff");

    let serialized = Bytes::from(Packet::StreamingAuth { hardware_id }.to_raw_packet(6).unwrap());
    assert_eq!(&serialized[..4], &[0x4c, 0x06, 0x00, 0x02]);
    assert!(matches!(
        Packet::try_from(RawPacket::try_from(serialized).unwrap()).unwrap(),
        Packet::StreamingAuth { .. }
    ));
}

#[test]
fn memory_read_confirmation_is_not_misreported_as_accept() {
    let bytes = Bytes::from(hex::decode("c40201012004000040000000ffffffff1b8c1b24").unwrap());
    let packet = Packet::try_from(RawPacket::try_from(bytes).unwrap()).unwrap();

    assert!(matches!(packet, Packet::Generic(_)));
}

#[test]
fn test_unframed_memory_ciphertext_is_not_misclassified_by_first_byte() {
    let original = Bytes::from_static(&[
        0x75, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    ]);
    let raw = RawPacket::try_from(original.clone()).unwrap();
    let Packet::Generic(generic) = Packet::try_from(raw).unwrap() else {
        panic!("ciphertext must remain generic outside the MemoryRead flow");
    };

    assert_eq!(Bytes::from(generic), original);
}

#[test]
fn ciphertext_derived_values_remain_unknown() {
    assert_eq!(PacketType::from(0x1a), PacketType::Unknown(0x1a));
    assert_eq!(PacketType::from(0x3a), PacketType::Unknown(0x3a));
    assert_eq!(Attribute::from(1609), Attribute::Unknown(1609));
    assert_eq!(Attribute::from(11046), Attribute::Unknown(11046));
    assert_eq!(Attribute::from(26817), Attribute::Unknown(26817));
}

#[test]
fn test_roundtrip_bytes_to_rawpacket_to_bytes_ctrl() {
    // Test round-trip conversion: Bytes → RawPacket → Bytes
    let original_bytes = Bytes::from_static(&[0x02, 0x01, 0x00, 0x00]);

    // Convert to RawPacket
    let raw_packet = RawPacket::try_from(original_bytes.clone()).expect("Failed to parse packet");

    // Convert back to Bytes
    let roundtrip_bytes = Bytes::from(raw_packet);

    assert_eq!(
        original_bytes.as_ref(),
        roundtrip_bytes.as_ref(),
        "Round-trip should preserve bytes exactly. Original: {:02x?}, Got: {:02x?}",
        original_bytes.as_ref(),
        roundtrip_bytes.as_ref()
    );
}

#[test]
fn test_roundtrip_bytes_to_rawpacket_to_bytes_data() {
    // Test round-trip conversion with Data packet
    let original_bytes = Bytes::from_static(&[0x40, 0x01, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD]);

    // Convert to RawPacket
    let raw_packet = RawPacket::try_from(original_bytes.clone()).expect("Failed to parse packet");

    // Convert back to Bytes
    let roundtrip_bytes = Bytes::from(raw_packet);

    assert_eq!(
        original_bytes.as_ref(),
        roundtrip_bytes.as_ref(),
        "Round-trip should preserve bytes exactly. Original: {:02x?}, Got: {:02x?}",
        original_bytes.as_ref(),
        roundtrip_bytes.as_ref()
    );
}

#[test]
fn test_roundtrip_adc_real_data() {
    // Test round-trip with real ADC data to ensure complex packets work
    let original_bytes = Bytes::from_static(REAL_ADC_RESPONSE);

    // Convert to RawPacket
    let raw_packet = RawPacket::try_from(original_bytes.clone()).expect("Failed to parse real ADC packet");

    // Convert back to Bytes
    let roundtrip_bytes = Bytes::from(raw_packet);

    assert_eq!(
        original_bytes.as_ref(),
        roundtrip_bytes.as_ref(),
        "Round-trip should preserve real ADC data exactly"
    );
}
