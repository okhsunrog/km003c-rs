//! Tests for basic packet parsing functionality

mod common;

use common::*;

#[test]
fn test_parse_packet_02010000() {
    let hex_data = "02010000";
    let bytes = hex_to_bytes(hex_data);

    assert_eq!(
        RawPacket::try_from(bytes).expect("Failed to parse packet"),
        RawPacket::Ctrl {
            header: CtrlHeader::new()
                .with_packet_type(2)
                .with_flag(false)
                .with_id(1)
                .with_attribute(0),
            payload: Bytes::new(),
        },
        "Parsed packet does not match expected packet",
    );
}

#[test]
fn test_parse_packet_40010001() {
    // Build a simple Data packet and ensure round-trip parsing
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
    let bytes: Bytes = packet.clone().into();

    assert_eq!(
        RawPacket::try_from(bytes).expect("Failed to parse packet"),
        packet,
        "Parsed data packet does not match expected data packet",
    );
}

#[test]
fn test_ctrl0() {
    let hex_data = "c4050101500401400c000000ffffffff74b2334f";
    let bytes = hex_to_bytes(hex_data);
    let packet = RawPacket::try_from(bytes).expect("Failed to parse packet");
    println!(
        "Ctrl0 Auth Packet: {:?}, payload len: {}",
        packet,
        packet.payload().len()
    );
    if let Some(ext_header) = packet.get_extended_header() {
        println!("Extended Header: {:?}", ext_header);
    }
}
