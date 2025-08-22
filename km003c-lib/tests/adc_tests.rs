//! Tests for ADC data handling functionality

mod common;

use common::*;

#[test]
fn test_adc() {
    let bytes_data = hex_to_bytes(EXTENDED_ADC_DATA);
    let packet = RawPacket::try_from(bytes_data).unwrap();
    let ext_header = packet.get_extended_header().unwrap();
    assert_eq!(ext_header.size(), packet.get_payload_data().len() as u16);
    assert!(matches!(
        Attribute::from_primitive(ext_header.attribute()),
        Attribute::Adc
    ));
    assert!(matches!(packet.packet_type(), PacketType::PutData));
    assert_eq!(packet.flag(), false);
    assert_eq!(ext_header.size(), 44);

    println!("ADC Packet: {:?}, payload len: {}", packet, packet.payload().len());
    println!("ADC Extended Header: {:?}", ext_header);
    println!("Type: {:?}", packet.packet_type());
}

#[test]
fn test_adc_data_packet() {
    let bytes_data = hex_to_bytes(EXTENDED_ADC_DATA);

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
        Packet::PdRawData(_) => panic!("Expected SimpleAdcData packet, got PdRawData"),
        Packet::PdStatusData(_) => panic!("Expected SimpleAdcData packet, got PdStatusData"),
        Packet::CmdGetPdData => panic!("Expected SimpleAdcData packet, got CmdGetPdData"),
        Packet::CmdGetPdStatus => panic!("Expected SimpleAdcData packet, got CmdGetPdStatus"),
        Packet::Generic(_) => panic!("Expected SimpleAdcData packet, got Generic"),
        _ => panic!("Packet was not SimpleAdcData"),
    }
}

#[test]
fn test_combined_adc_pd_packet_parsing() {
    let bytes_data = hex_to_bytes(COMBINED_ADC_PD_DATA);
    let packet = RawPacket::try_from(bytes_data).unwrap();

    // Ensure the extended header has the `next` flag set
    let ext_header = packet.get_extended_header().unwrap();
    assert!(ext_header.next(), "Combined packet's extended header should have `next` flag set");

    let parsed = Packet::try_from(packet).unwrap();

    match parsed {
        Packet::CombinedAdcPdData { adc, pd } => {
            // Check ADC data for plausible values
            assert!((adc.vbus_v - 0.004089).abs() < 1e-6, "Parsed ADC voltage is incorrect");
            assert!((adc.ibus_a - (-0.000002)).abs() < 1e-6, "Parsed ADC current is incorrect");
            assert_eq!(adc.sample_rate, SampleRate::Sps1, "Parsed ADC sample rate is incorrect");

            // Check that the PD data is the correct remaining part of the payload
            let expected_pd_bytes = hex::decode("10000003e9480800050000000000a50c").unwrap();
            assert_eq!(pd.as_ref(), expected_pd_bytes.as_slice(), "Parsed PD data is incorrect");

            println!("Successfully parsed combined packet.");
            println!("  ADC: {}", adc);
            println!("  PD:  {}", hex::encode(pd));
        }
        _ => panic!("Expected CombinedAdcPdData packet, got {:?}", parsed),
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
            assert_eq!(header.flag(), false);
            assert_eq!(header.id(), 0);
            assert_eq!(header.attribute(), 1); // ATT_ADC
            assert_eq!(payload.len(), 0);
        }
        _ => panic!("Expected Ctrl packet"),
    }
}

#[test]
fn test_adc_response_parsing_real_data() {
    let bytes = Bytes::from(REAL_ADC_RESPONSE.to_vec());

    // Parse as RawPacket
    let raw_packet = RawPacket::try_from(bytes).expect("Failed to parse raw packet");

    // Verify raw packet structure
    match &raw_packet {
        RawPacket::Data {
            header,
            extended: _,
            payload,
        } => {
            assert_eq!(header.packet_type(), 65); // CMD_PUT_DATA
            assert_eq!(header.flag(), false);
            assert_eq!(header.id(), 0);
            assert_eq!(header.obj_count_words(), 10);
            assert_eq!(payload.len(), 44);
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
