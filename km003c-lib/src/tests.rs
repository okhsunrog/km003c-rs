use crate::packet::{CtrlHeader, DataHeader, Packet};
use bytes::Bytes;

#[test]
fn test_parse_packet_02010000() {
    let hex_data = "02010000";
    let bytes_data = hex::decode(hex_data).expect("Failed to decode hex");
    let bytes = Bytes::from(bytes_data);

    assert_eq!(
        Packet::try_from(bytes).expect("Failed to parse packet"),
        Packet::Ctrl {
            header: CtrlHeader::new()
                .with_packet_type(2)
                .with_extend(false)
                .with_id(1)
                .with_attribute(0),
            payload: Bytes::new(),
        },
        "Parsed packet does not match expected packet"
    );
}

#[test]
fn test_parse_packet_40010001() {
    let hex_data = "40010001AABBCCDD"; // 4 words = 4 bytes payload (assuming 1 word = 1 byte for payload length calculation)
    let bytes_data = hex::decode(hex_data).expect("Failed to decode hex");
    let bytes = Bytes::from(bytes_data);

    assert_eq!(
        Packet::try_from(bytes).expect("Failed to parse packet"),
        Packet::Data {
            header: DataHeader::new()
                .with_packet_type(64)
                .with_extend(false)
                .with_id(1)
                .with_obj_count_words(4),
            payload: Bytes::from_static(&[0xAA, 0xBB, 0xCC, 0xDD]),
        },
        "Parsed data packet does not match expected data packet"
    );
}
