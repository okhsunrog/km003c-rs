//! Tests for round-trip conversion integrity

mod common;

use common::*;

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
    let payload = Bytes::from_static(&[0xAA, 0xBB]);
    let ext = ExtendedHeader::new()
        .with_attribute(0)
        .with_next(false)
        .with_chunk(0)
        .with_size(payload.len() as u16);
    let packet = RawPacket::Data {
        header: DataHeader::new()
            .with_packet_type(65)
            .with_flag(false)
            .with_id(1)
            .with_obj_count_words(0),
        extended: ext,
        payload: payload.clone(),
    };
    let original_bytes: Bytes = packet.clone().into();

    let raw_packet = RawPacket::try_from(original_bytes.clone()).expect("Failed to parse packet");

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
