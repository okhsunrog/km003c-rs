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
