use crate::packet::{RawPacket, Attribute, PacketType, CtrlHeader, DataHeader, ExtendedHeader};
use crate::adc::SampleRate;
use crate::message::Packet;
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
    let hex_data = "410c82020100000be08d4d001e000000218e4d00eaffffff278e4d00480000001c0c9502737e000001007b7e0080a40c00000000";
    let bytes_data = Bytes::from(hex::decode(hex_data).unwrap());
    let mut packet = RawPacket::try_from(bytes_data).unwrap();
    let ext_header = packet.get_ext_header().unwrap();
    assert_eq!(ext_header.size(), packet.payload().len() as u16);
    assert!(matches!(Attribute::from_primitive(ext_header.attribute()), Attribute::Adc));
    assert!(matches!(packet.packet_type(), PacketType::PutData));
    assert_eq!(packet.is_extended(), false);
    assert_eq!(ext_header.size(), 44);

    println!("ADC Packet: {:?}, payload len: {}", packet, packet.payload().len());
    println!("ADC Extended Header: {:?}", ext_header);
    println!("Type: {:?}", packet.packet_type());
    
}

#[test]
fn test_adc_data_packet() {
    let hex_data = "410c82020100000be08d4d001e000000218e4d00eaffffff278e4d00480000001c0c9502737e000001007b7e0080a40c00000000";
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
        },
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
    println!("Ctrl0 Auth Packet: {:?}, payload len: {}", packet, packet.payload().len());
    if packet.is_extended() {
            let ext_header_bytes: [u8; 4] = packet.payload()
            .split_to(4)
            .as_ref()
            .try_into().unwrap();
            let ext_header = ExtendedHeader::from_bytes(ext_header_bytes);
            println!("Extended Header: {:?}", ext_header);
    }
}
