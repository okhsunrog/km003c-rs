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
