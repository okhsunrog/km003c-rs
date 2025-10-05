//! Tests for the new LogicalPacket-based API

mod common;

use common::*;

#[test]
fn test_logical_packets_single() {
    // Test with a PutData packet that has a single logical packet
    let bytes_data = hex_to_bytes(EXTENDED_ADC_DATA);
    let packet = RawPacket::try_from(bytes_data).unwrap();

    // Should have logical packets
    let logical_packets = packet.logical_packets();
    assert!(logical_packets.is_some(), "PutData packet should have logical packets");

    let logical_packets = logical_packets.unwrap();
    assert_eq!(logical_packets.len(), 1, "Should have exactly 1 logical packet");

    let lp = &logical_packets[0];
    assert_eq!(lp.attribute, Attribute::Adc, "Should be ADC attribute");
    assert_eq!(lp.size, 44, "ADC payload size should be 44");
    assert!(!lp.next, "Single packet should have next=false");
}

#[test]
fn test_logical_packets_chained() {
    // Test with chained logical packets (ADC + PD)
    // Create a packet manually with 2 chained logical packets
    let adc_payload = vec![0u8; 44]; // 44 bytes of ADC data
    let pd_payload = vec![1u8; 12]; // 12 bytes of PD status

    let logical_packets = vec![
        LogicalPacket {
            attribute: Attribute::Adc,
            next: true, // Has next packet
            chunk: 0,
            size: 44,
            payload: Bytes::from(adc_payload).to_vec(),
        },
        LogicalPacket {
            attribute: Attribute::PdPacket,
            next: false, // Last packet
            chunk: 0,
            size: 12,
            payload: Bytes::from(pd_payload).to_vec(),
        },
    ];

    let packet = RawPacket::Data {
        header: DataHeader::new()
            .with_packet_type(65)
            .with_reserved_flag(true)
            .with_id(1)
            .with_obj_count_words(15), // (8 + 44 + 12) / 4
        logical_packets,
    };

    // Convert to bytes and back
    let bytes = Bytes::from(packet);
    let parsed = RawPacket::try_from(bytes).unwrap();

    let parsed_lps = parsed.logical_packets().unwrap();
    assert_eq!(parsed_lps.len(), 2, "Should have 2 chained logical packets");

    assert_eq!(parsed_lps[0].attribute, Attribute::Adc);
    assert!(parsed_lps[0].next, "First packet should have next=true");
    assert_eq!(parsed_lps[0].size, 44);

    assert_eq!(parsed_lps[1].attribute, Attribute::PdPacket);
    assert!(!parsed_lps[1].next, "Last packet should have next=false");
    assert_eq!(parsed_lps[1].size, 12);
}

#[test]
fn test_get_attribute_ctrl() {
    // Test Ctrl packet attribute
    let ctrl_packet = RawPacket::Ctrl {
        header: CtrlHeader::new()
            .with_packet_type(12)
            .with_reserved_flag(false)
            .with_id(0)
            .with_attribute(1), // ADC attribute
        payload: Bytes::new().to_vec(),
    };

    let attribute = ctrl_packet.get_attribute();
    assert!(attribute.is_some(), "Ctrl packet should have attribute");
    assert_eq!(
        attribute.unwrap(),
        Attribute::Adc,
        "Ctrl packet should have ADC attribute"
    );
}

#[test]
fn test_get_attribute_set() {
    // Test AttributeSet extraction from Ctrl packet
    let ctrl_packet = RawPacket::Ctrl {
        header: CtrlHeader::new()
            .with_packet_type(12)
            .with_reserved_flag(false)
            .with_id(0)
            .with_attribute(0x0011), // ADC + PD combined
        payload: Bytes::new().to_vec(),
    };

    let attr_set = ctrl_packet.get_attribute_set();
    assert!(attr_set.is_some(), "Ctrl packet should have attribute set");

    let attr_set = attr_set.unwrap();
    assert!(attr_set.contains(Attribute::Adc), "Should contain ADC attribute");
    assert!(attr_set.contains(Attribute::PdPacket), "Should contain PD attribute");
    assert_eq!(attr_set.len(), 2, "Should have 2 attributes");
}

#[test]
fn test_data_packet_no_logical_packets() {
    // Test that SimpleData has no logical packets
    let data_packet = RawPacket::SimpleData {
        header: DataHeader::new()
            .with_packet_type(64) // Head, not PutData
            .with_reserved_flag(false)
            .with_id(0)
            .with_obj_count_words(0),
        payload: Bytes::new().to_vec(),
    };

    assert!(
        data_packet.logical_packets().is_none(),
        "SimpleData should have no logical packets"
    );
}

#[test]
fn test_attribute_set_operations() {
    // Test AttributeSet construction and operations
    let set1 = AttributeSet::single(Attribute::Adc);
    assert!(set1.contains(Attribute::Adc));
    assert!(!set1.contains(Attribute::PdPacket));
    assert_eq!(set1.len(), 1);

    let set2 = set1.with(Attribute::PdPacket);
    assert!(set2.contains(Attribute::Adc));
    assert!(set2.contains(Attribute::PdPacket));
    assert_eq!(set2.len(), 2);

    let set3 = AttributeSet::from_raw(0x0011);
    assert_eq!(set3.raw(), 0x0011);
    assert!(set3.contains(Attribute::Adc));
    assert!(set3.contains(Attribute::PdPacket));
}
