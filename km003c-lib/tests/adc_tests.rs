//! Tests for ADC data handling functionality

mod common;

use common::*;

#[test]
fn test_adc() {
    let bytes_data = hex_to_bytes(EXTENDED_ADC_DATA);
    let packet = RawPacket::try_from(bytes_data).unwrap();

    // Should be a Data packet with logical packets
    assert!(matches!(packet.packet_type(), PacketType::PutData));

    let logical_packets = packet.logical_packets().expect("Should have logical packets");
    assert_eq!(logical_packets.len(), 1);

    let lp = &logical_packets[0];
    assert_eq!(lp.attribute, Attribute::Adc);
    assert_eq!(lp.size, 44);
    assert!(!lp.next);

    // Check reserved flag
    let reserved_flag = match &packet {
        RawPacket::Ctrl { header, .. } => header.reserved_flag(),
        RawPacket::SimpleData { header, .. } => header.reserved_flag(),
        RawPacket::Data { header, .. } => header.reserved_flag(),
    };
    assert!(!reserved_flag);

    println!("ADC Packet: {:?}", packet);
    println!("Logical packet: attr={:?}, size={}", lp.attribute, lp.size);
    println!("Type: {:?}", packet.packet_type());
}

#[test]
fn test_adc_data_packet() {
    let bytes_data = hex_to_bytes(EXTENDED_ADC_DATA);

    // Parse as RawPacket
    let raw_packet = RawPacket::try_from(bytes_data).unwrap();

    // Convert to high-level Packet
    let packet = Packet::try_from(raw_packet).unwrap();

    // Check if it's a DataResponse with ADC
    match packet {
        Packet::DataResponse { payloads } => {
            assert_eq!(payloads.len(), 1);
            match &payloads[0] {
                PayloadData::Adc(adc) => {
                    // Check some values
                    assert!(adc.vbus_v > 0.0);
                    assert!(adc.ibus_a > 0.0);
                    assert!(adc.power_w > 0.0);

                    // Check sample rate
                    assert_eq!(adc.sample_rate, SampleRate::Sps1);

                    println!("ADC Data: {}", adc);
                }
                _ => panic!("Expected ADC payload"),
            }
        }
        _ => panic!("Expected DataResponse packet, got {:?}", packet),
    }
}

#[test]
fn test_adc_request_generation() {
    // Test that GetData with ADC attribute generates the correct request bytes
    let packet = Packet::GetData {
        attribute_mask: AttributeSet::single(Attribute::Adc).raw(),
    };
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
            assert!(!header.reserved_flag());
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
            logical_packets,
        } => {
            assert_eq!(header.packet_type(), 65); // PutData
            assert_eq!(logical_packets.len(), 1);

            let lp = &logical_packets[0];
            assert_eq!(lp.attribute, Attribute::Adc);
            assert_eq!(lp.size, 44);
            assert_eq!(lp.payload.len(), 44);
        }
        _ => panic!("Expected Data packet"),
    }

    // Convert to high-level Packet
    let packet = Packet::try_from(raw_packet).expect("Failed to parse packet");

    // Verify it's parsed as ADC data
    match packet {
        Packet::DataResponse { payloads } => {
            assert_eq!(payloads.len(), 1);
            match &payloads[0] {
                PayloadData::Adc(adc_data) => {
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
                    // Temperature LSB is 1/128 °C; expected value from this sample is ~25.57 °C
                    assert!(
                        (adc_data.temp_c - 25.5703125).abs() < 0.02,
                        "Temperature should be ~25.57°C, got {}",
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
                _ => panic!("Expected ADC payload"),
            }
        }
        _ => panic!("Expected DataResponse packet, got {:?}", packet),
    }
}

#[test]
fn test_adc_request_generation_with_new_trait() {
    // Enhanced version of test_adc_request_generation using the new trait
    let packet = Packet::GetData {
        attribute_mask: AttributeSet::single(Attribute::Adc).raw(),
    };
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
