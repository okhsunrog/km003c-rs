use crate::packet::Packet;
use bytes::Bytes;

#[test]
fn test_parse_packet_02010000() {
    let hex_data = "02010000";
    let bytes_data = hex::decode(hex_data).expect("Failed to decode hex");
    let bytes = Bytes::from(bytes_data);

    let packet = Packet::try_from(bytes).expect("Failed to parse packet");

    match packet {
        Packet::Ctrl { header, payload } => {
            assert_eq!(header.packet_type(), 2, "Expected packet_type to be 2");
            assert_eq!(header.extend(), false, "Expected extend to be false");
            assert_eq!(header.id(), 1, "Expected id to be 1");
            assert_eq!(header.attribute(), 0, "Expected attribute to be 0");
            assert!(payload.is_empty(), "Expected payload to be empty");
        }
        Packet::Data { .. } => {
            panic!("Expected a Ctrl packet, but got a Data packet");
        }
    }
}

#[test]
fn test_parse_packet_40010001() {
    let hex_data = "40010001AABBCCDD"; // 4 words = 4 bytes payload (assuming 1 word = 1 byte for payload length calculation)
    let bytes_data = hex::decode(hex_data).expect("Failed to decode hex");
    let bytes = Bytes::from(bytes_data);

    let packet = Packet::try_from(bytes).expect("Failed to parse packet");

    match packet {
        Packet::Ctrl { .. } => {
            panic!("Expected a Data packet, but got a Ctrl packet");
        }
        Packet::Data { header, payload } => {
            assert_eq!(header.packet_type(), 64, "Expected packet_type to be 64");
            assert_eq!(header.extend(), false, "Expected extend to be false");
            assert_eq!(header.id(), 1, "Expected id to be 1");
            assert_eq!(header.obj_count_words(), 4, "Expected obj_count_words to be 4");
            assert_eq!(payload.len(), 4, "Expected payload length to be 4");
            assert_eq!(
                payload.as_ref(),
                &[0xAA, 0xBB, 0xCC, 0xDD],
                "Expected payload to be [0xAA, 0xBB, 0xCC, 0xDD]"
            );
        }
    }
}
