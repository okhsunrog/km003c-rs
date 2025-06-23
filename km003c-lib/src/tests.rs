use crate::adc::SampleRate;
use crate::message::Packet;
use crate::packet::{Attribute, CtrlHeader, DataHeader, PacketType, RawPacket};
use bytes::Bytes;
use num_enum::FromPrimitive;

#[test]
fn test_parse_packet_02010000() {
    let hex_data = "02010000";
    let bytes_data = hex::decode(hex_data).expect("Failed to decode hex");
    let bytes = Bytes::from(bytes_data);

    assert_eq!(
        RawPacket::try_from(bytes).expect("Failed to parse packet"),
        RawPacket::Ctrl {
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
        RawPacket::try_from(bytes).expect("Failed to parse packet"),
        RawPacket::Data {
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

#[test]
fn test_adc() {
    let hex_data =
        "410c82020100000be08d4d001e000000218e4d00eaffffff278e4d00480000001c0c9502737e000001007b7e0080a40c00000000";
    let bytes_data = Bytes::from(hex::decode(hex_data).unwrap());
    let packet = RawPacket::try_from(bytes_data).unwrap();
    let ext_header = packet.get_extended_header().unwrap();
    assert_eq!(ext_header.size(), packet.get_payload_data().len() as u16);
    assert!(matches!(
        Attribute::from_primitive(ext_header.attribute()),
        Attribute::Adc
    ));
    assert!(matches!(packet.packet_type(), PacketType::PutData));
    assert_eq!(packet.is_extended(), false);
    assert_eq!(ext_header.size(), 44);

    println!("ADC Packet: {:?}, payload len: {}", packet, packet.payload().len());
    println!("ADC Extended Header: {:?}", ext_header);
    println!("Type: {:?}", packet.packet_type());
}

#[test]
fn test_adc_data_packet() {
    let hex_data =
        "410c82020100000be08d4d001e000000218e4d00eaffffff278e4d00480000001c0c9502737e000001007b7e0080a40c00000000";
    let bytes_data = Bytes::from(hex::decode(hex_data).unwrap());

    // Parse as RawPacket
    let raw_packet = RawPacket::try_from(bytes_data).unwrap();

    // Convert to high-level Packet
    let packet = Packet::try_from(raw_packet).unwrap();

    // Check if it's a SimpleAdcData packet
    match packet {
        Packet::SimpleAdcData(adc_data) => {
            // Check some values
            assert!(adc_data.vbus_v > 0.0);
            assert!(adc_data.ibus_a > 0.0);
            assert!(adc_data.power_w > 0.0);

            // Check sample rate
            assert_eq!(adc_data.sample_rate, SampleRate::Sps1);

            println!("ADC Data: {}", adc_data);
        }
        Packet::CmdGetSimpleAdcData => panic!("Expected SimpleAdcData packet, got CmdGetSimpleAdcData"),
        Packet::Generic(_) => panic!("Expected SimpleAdcData packet, got Generic"),
    }
}

#[test]
fn test_ctrl0() {
    let hex_data = "c4050101500401400c000000ffffffff74b2334f";
    let bytes_data = hex::decode(hex_data).expect("Failed to decode hex");
    let bytes = Bytes::from(bytes_data);
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

#[test]
fn test_adc_request_generation() {
    // Test that CmdGetSimpleAdcData generates the correct request bytes
    let packet = Packet::CmdGetSimpleAdcData;
    let raw_packet = packet.to_raw_packet(0);

    // Convert to bytes manually to verify the exact output
    let header_bytes = match &raw_packet {
        RawPacket::Ctrl { header, .. } => header.into_bytes(),
        _ => panic!("Expected Ctrl packet"),
    };

    let expected_bytes = [0x0c, 0x00, 0x02, 0x00];
    assert_eq!(
        header_bytes, expected_bytes,
        "ADC request should generate [0c, 00, 02, 00], got {:02x?}",
        header_bytes
    );

    // Also verify packet structure
    match raw_packet {
        RawPacket::Ctrl { header, payload } => {
            assert_eq!(header.packet_type(), 12); // CMD_GET_DATA
            assert_eq!(header.extend(), false);
            assert_eq!(header.id(), 0);
            assert_eq!(header.attribute(), 1); // ATT_ADC
            assert_eq!(payload.len(), 0);
        }
        _ => panic!("Expected Ctrl packet"),
    }
}

#[test]
fn test_adc_response_parsing_real_data() {
    // Real captured ADC response data from device
    let raw_bytes = [
        0x41, 0x00, 0x80, 0x02, 0x01, 0x00, 0x00, 0x0b, 0x45, 0x1c, 0x4d, 0x00, 0xae, 0x9e, 0xfe, 0xff, 0xdb, 0x1c,
        0x4d, 0x00, 0x23, 0x9f, 0xfe, 0xff, 0xe1, 0x1c, 0x4d, 0x00, 0x81, 0x9f, 0xfe, 0xff, 0xc9, 0x0c, 0x8a, 0x10,
        0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x7e, 0x00, 0x80, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let bytes = Bytes::from(raw_bytes.to_vec());

    // Parse as RawPacket
    let raw_packet = RawPacket::try_from(bytes).expect("Failed to parse raw packet");

    // Verify raw packet structure
    match &raw_packet {
        RawPacket::Data { header, payload } => {
            assert_eq!(header.packet_type(), 65); // CMD_PUT_DATA
            assert_eq!(header.extend(), false);
            assert_eq!(header.id(), 0);
            assert_eq!(header.obj_count_words(), 10);
            assert_eq!(payload.len(), 48);
        }
        _ => panic!("Expected Data packet"),
    }

    // Convert to high-level Packet
    let packet = Packet::try_from(raw_packet).expect("Failed to parse packet");

    // Verify it's parsed as ADC data
    match packet {
        Packet::SimpleAdcData(adc_data) => {
            // Test main measurements (with floating point tolerance)
            assert!(
                (adc_data.vbus_v - 5.054).abs() < 0.001,
                "Voltage should be ~5.054V, got {}",
                adc_data.vbus_v
            );
            assert!(
                (adc_data.ibus_a - (-0.090)).abs() < 0.001,
                "Current should be ~-0.090A, got {}",
                adc_data.ibus_a
            );
            assert!(
                (adc_data.power_w - (-0.457)).abs() < 0.001,
                "Power should be ~-0.457W, got {}",
                adc_data.power_w
            );
            assert!(
                (adc_data.temp_c - 25.0).abs() < 0.1,
                "Temperature should be ~25.0°C, got {}",
                adc_data.temp_c
            );

            // Test absolute value methods
            assert!(
                (adc_data.current_abs_a() - 0.090).abs() < 0.001,
                "Absolute current should be ~0.090A, got {}",
                adc_data.current_abs_a()
            );
            assert!(
                (adc_data.power_abs_w() - 0.457).abs() < 0.001,
                "Absolute power should be ~0.457W, got {}",
                adc_data.power_abs_w()
            );

            // Test sample rate
            assert_eq!(adc_data.sample_rate, SampleRate::Sps1, "Sample rate should be 1 SPS");

            // Test USB data lines (should be ~0.000V)
            assert!(
                adc_data.vdp_v.abs() < 0.001,
                "D+ should be ~0.000V, got {}",
                adc_data.vdp_v
            );
            assert!(
                adc_data.vdm_v.abs() < 0.001,
                "D- should be ~0.000V, got {}",
                adc_data.vdm_v
            );

            // Test USB CC lines
            assert!(
                (adc_data.cc1_v - 0.423).abs() < 0.001,
                "CC1 should be ~0.423V, got {}",
                adc_data.cc1_v
            );
            assert!(
                (adc_data.cc2_v - 0.001).abs() < 0.001,
                "CC2 should be ~0.001V, got {}",
                adc_data.cc2_v
            );

            println!("Successfully parsed ADC data: {}", adc_data);
        }
        _ => panic!("Expected SimpleAdcData packet, got {:?}", packet),
    }
}

#[test]
fn test_rawpacket_to_bytes_ctrl() {
    // Test direct conversion of Ctrl packet to bytes
    let raw_packet = RawPacket::Ctrl {
        header: CtrlHeader::new()
            .with_packet_type(2)
            .with_extend(false)
            .with_id(1)
            .with_attribute(0),
        payload: Bytes::new(),
    };

    let bytes = Bytes::from(raw_packet);
    let expected_bytes = [0x02, 0x01, 0x00, 0x00];

    assert_eq!(
        bytes.as_ref(),
        &expected_bytes,
        "Ctrl packet should convert to [02, 01, 00, 00], got {:02x?}",
        bytes.as_ref()
    );
}

#[test]
fn test_rawpacket_to_bytes_data() {
    // Test direct conversion of Data packet to bytes
    let payload = Bytes::from_static(&[0xAA, 0xBB, 0xCC, 0xDD]);
    let raw_packet = RawPacket::Data {
        header: DataHeader::new()
            .with_packet_type(64)
            .with_extend(false)
            .with_id(1)
            .with_obj_count_words(4),
        payload,
    };

    let bytes = Bytes::from(raw_packet);
    let expected_bytes = [0x40, 0x01, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD];

    assert_eq!(
        bytes.as_ref(),
        &expected_bytes,
        "Data packet should convert to [40, 01, 00, 01, AA, BB, CC, DD], got {:02x?}",
        bytes.as_ref()
    );
}

#[test]
fn test_rawpacket_to_bytes_ctrl_with_payload() {
    // Test Ctrl packet with non-empty payload
    let payload = Bytes::from_static(&[0x12, 0x34]);
    let raw_packet = RawPacket::Ctrl {
        header: CtrlHeader::new()
            .with_packet_type(5)
            .with_extend(true)
            .with_id(7)
            .with_attribute(0x123),
        payload,
    };

    let bytes = Bytes::from(raw_packet.clone());

    // Verify the structure by doing a round-trip conversion
    let original_bytes = bytes.clone();
    let parsed_packet = RawPacket::try_from(original_bytes).expect("Failed to parse generated bytes");

    // Verify the parsed packet matches our original
    match parsed_packet {
        RawPacket::Ctrl {
            header,
            payload: parsed_payload,
        } => {
            assert_eq!(header.packet_type(), 5, "Packet type should be 5");
            assert_eq!(header.extend(), true, "Extend should be true");
            assert_eq!(header.id(), 7, "ID should be 7");
            assert_eq!(header.attribute(), 0x123, "Attribute should be 0x123");
            assert_eq!(parsed_payload.as_ref(), &[0x12, 0x34], "Payload should match");
        }
        _ => panic!("Expected Ctrl packet"),
    }

    // Verify total length (4 byte header + 2 byte payload = 6 bytes)
    assert_eq!(bytes.len(), 6, "Total packet should be 6 bytes");

    // Verify payload is correctly appended
    assert_eq!(&bytes[4..], &[0x12, 0x34], "Payload should be correctly appended");
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
    let original_bytes = Bytes::from_static(&[
        0x41, 0x00, 0x80, 0x02, 0x01, 0x00, 0x00, 0x0b, 0x45, 0x1c, 0x4d, 0x00, 0xae, 0x9e, 0xfe, 0xff, 0xdb, 0x1c,
        0x4d, 0x00, 0x23, 0x9f, 0xfe, 0xff, 0xe1, 0x1c, 0x4d, 0x00, 0x81, 0x9f, 0xfe, 0xff, 0xc9, 0x0c, 0x8a, 0x10,
        0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x7e, 0x00, 0x80, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

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

#[test]
fn test_rawpacket_to_bytes_empty_payload() {
    // Test edge case with empty payloads for both packet types
    let ctrl_packet = RawPacket::Ctrl {
        header: CtrlHeader::new()
            .with_packet_type(12)
            .with_extend(false)
            .with_id(0)
            .with_attribute(1),
        payload: Bytes::new(),
    };

    let data_packet = RawPacket::Data {
        header: DataHeader::new()
            .with_packet_type(65)
            .with_extend(false)
            .with_id(0)
            .with_obj_count_words(0),
        payload: Bytes::new(),
    };

    let ctrl_bytes = Bytes::from(ctrl_packet);
    let data_bytes = Bytes::from(data_packet);

    assert_eq!(ctrl_bytes.len(), 4, "Ctrl packet with empty payload should be 4 bytes");
    assert_eq!(data_bytes.len(), 4, "Data packet with empty payload should be 4 bytes");
}

#[test]
fn test_adc_request_generation_with_new_trait() {
    // Enhanced version of test_adc_request_generation using the new trait
    let packet = Packet::CmdGetSimpleAdcData;
    let raw_packet = packet.to_raw_packet(0);

    // Use the new trait to convert to bytes
    let bytes = Bytes::from(raw_packet.clone());
    let expected_bytes = [0x0c, 0x00, 0x02, 0x00];

    assert_eq!(
        bytes.as_ref(),
        &expected_bytes,
        "ADC request should generate [0c, 00, 02, 00] using new trait, got {:02x?}",
        bytes.as_ref()
    );

    // Verify we can round-trip it
    let parsed_packet = RawPacket::try_from(bytes).expect("Failed to parse generated bytes");
    assert_eq!(parsed_packet, raw_packet, "Round-trip should preserve packet structure");
}

#[test]
fn test_rawpacket_to_bytes_large_payload() {
    // Test with a larger payload to ensure the trait handles size correctly
    let large_payload: Vec<u8> = (0..=255u8).collect();
    let raw_packet = RawPacket::Data {
        header: DataHeader::new()
            .with_packet_type(65)
            .with_extend(true)
            .with_id(42)
            .with_obj_count_words(64), // 256 bytes = 64 words (assuming 4 bytes per word)
        payload: Bytes::from(large_payload.clone()),
    };

    let bytes = Bytes::from(raw_packet);

    // Verify total length (4 byte header + 256 byte payload = 260 bytes)
    assert_eq!(bytes.len(), 260, "Large payload packet should be 260 bytes total");

    // Verify payload is correctly appended
    assert_eq!(
        &bytes[4..],
        &large_payload,
        "Payload should be correctly appended after header"
    );
}

#[test]
fn test_get_extended_header() {
    // Test with a PutData packet that has an extended header
    let hex_data =
        "410c82020100000be08d4d001e000000218e4d00eaffffff278e4d00480000001c0c9502737e000001007b7e0080a40c00000000";
    let bytes_data = Bytes::from(hex::decode(hex_data).unwrap());
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

    assert!(ctrl_packet.get_extended_header().is_none(), "Ctrl packet should not have extended header");

    // Test with Data packet that's not PutData (should not have extended header)
    let data_packet = RawPacket::Data {
        header: DataHeader::new()
            .with_packet_type(64) // Head, not PutData
            .with_extend(false)
            .with_id(0)
            .with_obj_count_words(0),
        payload: Bytes::new(),
    };

    assert!(data_packet.get_extended_header().is_none(), "Non-PutData packet should not have extended header");
}

#[test]
fn test_get_payload_data() {
    // Test with packet that has extended header
    let hex_data =
        "410c82020100000be08d4d001e000000218e4d00eaffffff278e4d00480000001c0c9502737e000001007b7e0080a40c00000000";
    let bytes_data = Bytes::from(hex::decode(hex_data).unwrap());
    let packet = RawPacket::try_from(bytes_data).unwrap();

    let payload_data = packet.get_payload_data();
    let full_payload = packet.payload();

    // Payload data should be 4 bytes shorter (skipping extended header)
    assert_eq!(payload_data.len(), full_payload.len() - 4, 
               "Payload data should skip 4-byte extended header");
    
    // Extended header tells us the actual data size should be 44 bytes
    let ext_header = packet.get_extended_header().unwrap();
    assert_eq!(payload_data.len(), ext_header.size() as usize,
               "Payload data length should match extended header size");

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
    assert_eq!(ctrl_payload_data.len(), ctrl_full_payload.len(),
               "Payload data should be same as full payload when no extended header");
    assert_eq!(ctrl_payload_data.as_ref(), ctrl_full_payload.as_ref(),
               "Payload data should match full payload when no extended header");
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
    assert_eq!(attribute.unwrap(), Attribute::Adc, "Ctrl packet should have ADC attribute");

    // Test Data packet with extended header (ADC data)
    let hex_data =
        "410c82020100000be08d4d001e000000218e4d00eaffffff278e4d00480000001c0c9502737e000001007b7e0080a40c00000000";
    let bytes_data = Bytes::from(hex::decode(hex_data).unwrap());
    let data_packet = RawPacket::try_from(bytes_data).unwrap();

    let data_attribute = data_packet.get_attribute();
    assert!(data_attribute.is_some(), "Data packet with extended header should have attribute");
    assert_eq!(data_attribute.unwrap(), Attribute::Adc, "Data packet should have ADC attribute from extended header");

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
    assert!(no_ext_attribute.is_none(), "Data packet without extended header should have no attribute");
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
    let hex_data =
        "410c82020100000be08d4d001e000000218e4d00eaffffff278e4d00480000001c0c9502737e000001007b7e0080a40c00000000";
    let bytes_data = Bytes::from(hex::decode(hex_data).unwrap());
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
