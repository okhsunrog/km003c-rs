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
        Ok(RawPacket::SimpleData { .. }) => panic!("Expected Ctrl packet"),
        Ok(RawPacket::ExtendedData { .. }) => panic!("Expected Ctrl packet"),
        Err(e) => panic!("Expected success, got error: {:?}", e),
    }
}

#[test]
fn test_extended_header_edge_cases() {
    // Test get_extended_header with various edge cases

    // Test with SimpleData packet that's not PutData (should return None)
    let data_packet = RawPacket::SimpleData {
        header: DataHeader::new()
            .with_packet_type(64) // Head, not PutData
            .with_reserved_flag(false)
            .with_id(0)
            .with_obj_count_words(0),
        payload: Bytes::from_static(&[0x01, 0x02, 0x03, 0x04]),
    };
    assert!(data_packet.get_extended_header().is_none());

    // Test with PutData packet but payload too short
    let short_payload_packet = RawPacket::SimpleData {
        header: DataHeader::new()
            .with_packet_type(65) // PutData
            .with_reserved_flag(false)
            .with_id(0)
            .with_obj_count_words(0),
        payload: Bytes::from_static(&[0x01, 0x02]), // Only 2 bytes
    };
    assert!(short_payload_packet.get_extended_header().is_none());

    // Test with PutData packet and sufficient payload
    let valid_packet = RawPacket::SimpleData {
        header: DataHeader::new()
            .with_packet_type(65) // PutData
            .with_reserved_flag(false)
            .with_id(0)
            .with_obj_count_words(0),
        payload: Bytes::from_static(&[0x01, 0x00, 0x00, 0x2C]), // Valid extended header
    };
    // Extended header is exposed only for ExtendedData variant (produced by parsing)
    assert!(valid_packet.get_extended_header().is_none());
}

#[test]
fn test_get_payload_data_edge_cases() {
    // Test get_payload_data with empty payload
    let empty_payload_packet = RawPacket::Ctrl {
        header: CtrlHeader::new()
            .with_packet_type(12)
            .with_reserved_flag(false)
            .with_id(0)
            .with_attribute(1),
        payload: Bytes::new(),
    };

    let payload_data = empty_payload_packet.get_payload_data();
    assert_eq!(payload_data.len(), 0);

    // Test get_payload_data with PutData packet but short payload
    let short_putdata_packet = RawPacket::SimpleData {
        header: DataHeader::new()
            .with_packet_type(65) // PutData
            .with_reserved_flag(false)
            .with_id(0)
            .with_obj_count_words(0),
        payload: Bytes::from_static(&[0x01, 0x02]), // Too short for extended header
    };

    let payload_data = short_putdata_packet.get_payload_data();
    // Should return the full payload since there's no valid extended header
    assert_eq!(payload_data.len(), 2);
    assert_eq!(payload_data.as_ref(), &[0x01, 0x02]);
}
