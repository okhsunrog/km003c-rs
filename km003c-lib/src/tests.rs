use crate::adc::SampleRate;
use crate::message::Packet;
use crate::packet::{Attribute, CtrlHeader, DataHeader, ExtendedHeader, PacketType, RawPacket};
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
    let mut packet = RawPacket::try_from(bytes_data).unwrap();
    let ext_header = packet.get_ext_header().unwrap();
    assert_eq!(ext_header.size(), packet.payload().len() as u16);
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
    if packet.is_extended() {
        let ext_header_bytes: [u8; 4] = packet.payload().split_to(4).as_ref().try_into().unwrap();
        let ext_header = ExtendedHeader::from_bytes(ext_header_bytes);
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
