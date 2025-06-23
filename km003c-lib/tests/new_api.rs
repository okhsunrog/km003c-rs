//! Tests for the new RawPacket API methods

mod common;

use common::*;

#[test]
fn test_get_extended_header() {
    // Test with a PutData packet that has an extended header
    let bytes_data = hex_to_bytes(EXTENDED_ADC_DATA);
    let packet = RawPacket::try_from(bytes_data).unwrap();

    // Should have extended header
    let ext_header = packet.get_extended_header();
    assert!(ext_header.is_some(), "PutData packet should have extended header");

    let ext_header = ext_header.unwrap();
    assert_eq!(ext_header.attribute(), 1, "Extended header attribute should be 1 (ADC)");
    assert_eq!(ext_header.size(), 44, "Extended header size should be 44");

    // Test with a Ctrl packet (should not have extended header)
    let ctrl_packet = RawPacket::Ctrl {
        header: CtrlHeader::new()
            .with_packet_type(12)
            .with_extend(false)
            .with_id(0)
            .with_attribute(1),
        payload: Bytes::new(),
    };

    assert!(
        ctrl_packet.get_extended_header().is_none(),
        "Ctrl packet should not have extended header"
    );

    // Test with Data packet that's not PutData (should not have extended header)
    let data_packet = RawPacket::Data {
        header: DataHeader::new()
            .with_packet_type(64) // Head, not PutData
            .with_extend(false)
            .with_id(0)
            .with_obj_count_words(0),
        payload: Bytes::new(),
    };

    assert!(
        data_packet.get_extended_header().is_none(),
        "Non-PutData packet should not have extended header"
    );
}

#[test]
fn test_get_payload_data() {
    // Test with packet that has extended header
    let bytes_data = hex_to_bytes(EXTENDED_ADC_DATA);
    let packet = RawPacket::try_from(bytes_data).unwrap();

    let payload_data = packet.get_payload_data();
    let full_payload = packet.payload();

    // Payload data should be 4 bytes shorter (skipping extended header)
    assert_eq!(
        payload_data.len(),
        full_payload.len() - 4,
        "Payload data should skip 4-byte extended header"
    );

    // Extended header tells us the actual data size should be 44 bytes
    let ext_header = packet.get_extended_header().unwrap();
    assert_eq!(
        payload_data.len(),
        ext_header.size() as usize,
        "Payload data length should match extended header size"
    );

    // Test with packet without extended header
    let ctrl_packet = RawPacket::Ctrl {
        header: CtrlHeader::new()
            .with_packet_type(12)
            .with_extend(false)
            .with_id(0)
            .with_attribute(1),
        payload: Bytes::from_static(&[0x01, 0x02, 0x03]),
    };

    let ctrl_payload_data = ctrl_packet.get_payload_data();
    let ctrl_full_payload = ctrl_packet.payload();

    // Should be the same since no extended header
    assert_eq!(
        ctrl_payload_data.len(),
        ctrl_full_payload.len(),
        "Payload data should be same as full payload when no extended header"
    );
    assert_eq!(
        ctrl_payload_data.as_ref(),
        ctrl_full_payload.as_ref(),
        "Payload data should match full payload when no extended header"
    );
}

#[test]
fn test_get_attribute() {
    // Test Ctrl packet attribute
    let ctrl_packet = RawPacket::Ctrl {
        header: CtrlHeader::new()
            .with_packet_type(12)
            .with_extend(false)
            .with_id(0)
            .with_attribute(1), // ADC attribute
        payload: Bytes::new(),
    };

    let attribute = ctrl_packet.get_attribute();
    assert!(attribute.is_some(), "Ctrl packet should have attribute");
    assert_eq!(
        attribute.unwrap(),
        Attribute::Adc,
        "Ctrl packet should have ADC attribute"
    );

    // Test Data packet with extended header (ADC data)
    let bytes_data = hex_to_bytes(EXTENDED_ADC_DATA);
    let data_packet = RawPacket::try_from(bytes_data).unwrap();

    let data_attribute = data_packet.get_attribute();
    assert!(
        data_attribute.is_some(),
        "Data packet with extended header should have attribute"
    );
    assert_eq!(
        data_attribute.unwrap(),
        Attribute::Adc,
        "Data packet should have ADC attribute from extended header"
    );

    // Test Data packet without extended header
    let data_no_ext = RawPacket::Data {
        header: DataHeader::new()
            .with_packet_type(64) // Head, not PutData
            .with_extend(false)
            .with_id(0)
            .with_obj_count_words(0),
        payload: Bytes::new(),
    };

    let no_ext_attribute = data_no_ext.get_attribute();
    assert!(
        no_ext_attribute.is_none(),
        "Data packet without extended header should have no attribute"
    );
}

#[test]
fn test_tuple_matching_pattern() {
    // Test the new tuple matching pattern works as expected

    // Test ADC request (Ctrl packet)
    let adc_request = RawPacket::Ctrl {
        header: CtrlHeader::new()
            .with_packet_type(12) // GetData
            .with_extend(false)
            .with_id(0)
            .with_attribute(1), // ADC
        payload: Bytes::new(),
    };

    match (adc_request.packet_type(), adc_request.get_attribute()) {
        (PacketType::GetData, Some(Attribute::Adc)) => {
            // Expected path
        }
        _ => panic!("ADC request should match (GetData, Some(Adc))"),
    }

    // Test ADC data response (Data packet with extended header)
    let bytes_data = hex_to_bytes(EXTENDED_ADC_DATA);
    let adc_data = RawPacket::try_from(bytes_data).unwrap();

    match (adc_data.packet_type(), adc_data.get_attribute()) {
        (PacketType::PutData, Some(Attribute::Adc)) => {
            // Expected path
        }
        _ => panic!("ADC data should match (PutData, Some(Adc))"),
    }

    // Test generic packet
    let generic_packet = RawPacket::Data {
        header: DataHeader::new()
            .with_packet_type(64) // Head
            .with_extend(false)
            .with_id(0)
            .with_obj_count_words(0),
        payload: Bytes::new(),
    };

    match (generic_packet.packet_type(), generic_packet.get_attribute()) {
        (PacketType::Head, None) => {
            // Expected path for generic packet
        }
        _ => panic!("Generic packet should match (Head, None)"),
    }
}
