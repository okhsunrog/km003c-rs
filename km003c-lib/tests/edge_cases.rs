//! Tests for edge cases and error handling

mod common;

use common::*;

#[test]
fn test_packet_too_short_for_header() {
    // Test packets that are too short (less than 4 bytes)
    let test_cases = vec![
        (vec![], "Empty packet"),
        (vec![0x01], "1 byte packet"),
        (vec![0x01, 0x02], "2 byte packet"),
        (vec![0x01, 0x02, 0x03], "3 byte packet"),
    ];

    for (bytes_vec, description) in test_cases {
        let bytes = Bytes::from(bytes_vec);
        let result = RawPacket::try_from(bytes);

        match result {
            Err(KMError::InvalidPacket(msg)) => {
                assert!(
                    msg.contains("too short"),
                    "{}: Expected 'too short' error, got: {}",
                    description,
                    msg
                );
            }
            Ok(_) => panic!("{}: Expected error but got Ok", description),
            Err(other) => panic!("{}: Expected InvalidPacket error, got: {:?}", description, other),
        }
    }
}

#[test]
fn test_minimum_valid_packet() {
    // Test the minimum valid packet (exactly 4 bytes - header only)
    let bytes = Bytes::from(vec![0x02, 0x01, 0x00, 0x00]);
    let result = RawPacket::try_from(bytes);

    // Should succeed and create a Ctrl packet with empty payload
    match result {
        Ok(RawPacket::Ctrl { header, payload }) => {
            assert_eq!(header.packet_type(), 2);
            assert_eq!(header.id(), 1);
            assert_eq!(payload.len(), 0);
        }
        Ok(RawPacket::Data { .. }) => panic!("Expected Ctrl packet"),
        Err(e) => panic!("Expected success, got error: {:?}", e),
    }
}
