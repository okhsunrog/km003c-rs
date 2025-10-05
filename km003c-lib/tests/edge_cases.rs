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
        Ok(RawPacket::Data { .. }) => panic!("Expected Ctrl packet"),
        Err(e) => panic!("Expected success, got error: {:?}", e),
    }
}

#[test]
fn test_logical_packets_edge_cases() {
    // Test logical_packets() with various packet types

    // Ctrl packet - no logical packets
    let ctrl_packet = RawPacket::Ctrl {
        header: CtrlHeader::new()
            .with_packet_type(12)
            .with_reserved_flag(false)
            .with_id(0)
            .with_attribute(1),
        payload: Bytes::new().to_vec(),
    };
    assert!(ctrl_packet.logical_packets().is_none());

    // SimpleData packet - no logical packets
    let simple_data = RawPacket::SimpleData {
        header: DataHeader::new()
            .with_packet_type(64) // Head, not PutData
            .with_reserved_flag(false)
            .with_id(0)
            .with_obj_count_words(0),
        payload: Bytes::from_static(&[0x01, 0x02, 0x03, 0x04]).to_vec(),
    };
    assert!(simple_data.logical_packets().is_none());

    // Data packet with logical packets
    let data_packet = RawPacket::Data {
        header: DataHeader::new()
            .with_packet_type(65)
            .with_reserved_flag(true)
            .with_id(0)
            .with_obj_count_words(1),
        logical_packets: vec![LogicalPacket {
            attribute: Attribute::Adc,
            next: false,
            chunk: 0,
            size: 4,
            payload: Bytes::from_static(&[0x01, 0x02, 0x03, 0x04]).to_vec(),
        }],
    };
    assert!(data_packet.logical_packets().is_some());
    assert_eq!(data_packet.logical_packets().unwrap().len(), 1);
}

#[test]
fn test_empty_payload_handling() {
    // Test empty payload with Ctrl packet
    let empty_payload_packet = RawPacket::Ctrl {
        header: CtrlHeader::new()
            .with_packet_type(12)
            .with_reserved_flag(false)
            .with_id(0)
            .with_attribute(1),
        payload: Bytes::new().to_vec(),
    };

    // Should have no logical packets (it's a Ctrl packet)
    assert!(empty_payload_packet.logical_packets().is_none());

    // Test SimpleData with short payload (not PutData)
    let short_simple_data = RawPacket::SimpleData {
        header: DataHeader::new()
            .with_packet_type(64) // Head, not PutData
            .with_reserved_flag(false)
            .with_id(0)
            .with_obj_count_words(0),
        payload: Bytes::from_static(&[0x01, 0x02]).to_vec(),
    };

    assert!(short_simple_data.logical_packets().is_none());
}

#[test]
fn test_attribute_set_edge_cases() {
    // Test empty attribute set
    let empty_set = AttributeSet::empty();
    assert!(empty_set.is_empty());
    assert_eq!(empty_set.len(), 0);
    assert!(!empty_set.contains(Attribute::Adc));

    // Test single attribute
    let single = AttributeSet::single(Attribute::Adc);
    assert!(!single.is_empty());
    assert_eq!(single.len(), 1);
    assert!(single.contains(Attribute::Adc));

    // Test combining multiple times
    let multi = AttributeSet::empty()
        .with(Attribute::Adc)
        .with(Attribute::PdPacket)
        .with(Attribute::Settings);
    assert_eq!(multi.len(), 3);
    assert!(multi.contains(Attribute::Adc));
    assert!(multi.contains(Attribute::PdPacket));
    assert!(multi.contains(Attribute::Settings));
}
