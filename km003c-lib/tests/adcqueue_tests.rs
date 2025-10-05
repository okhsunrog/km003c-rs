use bytes::Bytes;
use km003c_lib::{AdcQueueData, Packet, RawPacket};

#[test]
fn test_adcqueue_parsing() {
    // Real AdcQueue packet from pd_adcqueue_new.11 (modern firmware)
    // Main header (4) + Extended header (4) + 2 samples (2×20=40) = 48 bytes
    // This uses 0.1mV scale for voltage fields (CC1, CC2, D+, D-)
    let hex = "413e0202020002050de80800d5c38c00598ce8ffdc401f015b17581701ea0800\
               0bac8c000255e9ff92401e0158175417";

    let bytes = Bytes::from(hex::decode(hex).unwrap());
    let raw_packet = RawPacket::try_from(bytes).unwrap();

    // Verify it's PutData with AdcQueue
    assert!(matches!(raw_packet, RawPacket::Data { .. }));

    let logical_packets = raw_packet.logical_packets().unwrap();
    assert_eq!(logical_packets.len(), 1);
    assert_eq!(u16::from(logical_packets[0].attribute), 2); // AdcQueue

    // Parse to high-level packet
    let packet = Packet::try_from(raw_packet).unwrap();

    match packet {
        Packet::DataResponse(payloads) => {
            assert_eq!(payloads.len(), 1);

            match &payloads[0] {
                km003c_lib::PayloadData::AdcQueue(queue) => {
                    // Should have 2 samples (40 bytes / 20)
                    assert_eq!(queue.samples.len(), 2);

                    // Check first sample (modern firmware with all fields)
                    let sample0 = &queue.samples[0];
                    assert_eq!(sample0.sequence, 59405);
                    assert!((sample0.vbus_v - 9.225).abs() < 0.01); // 9225173 µV
                    assert!((sample0.ibus_a + 1.537).abs() < 0.01); // -1536935 µA
                    assert!((sample0.cc1_v - 1.660).abs() < 0.01); // 16604×0.1mV = 1.66V
                    assert!((sample0.cc2_v - 0.029).abs() < 0.01); // 287×0.1mV = 29mV
                    assert!((sample0.vdp_v - 0.598).abs() < 0.01); // 5979×0.1mV
                    assert!((sample0.vdm_v - 0.598).abs() < 0.01); // 5976×0.1mV

                    // Check second sample
                    let sample1 = &queue.samples[1];
                    assert_eq!(sample1.sequence, 59905);
                    assert!((sample1.vbus_v - 9.220).abs() < 0.01);

                    println!("✅ AdcQueue parsing successful!");
                    println!(
                        "   Sample 0: seq={} vbus={:.3}V ibus={:.3}A cc1={:.3}V d+={:.3}V",
                        sample0.sequence, sample0.vbus_v, sample0.ibus_a, sample0.cc1_v, sample0.vdp_v
                    );
                    println!(
                        "   Sample 1: seq={} vbus={:.3}V ibus={:.3}A",
                        sample1.sequence, sample1.vbus_v, sample1.ibus_a
                    );
                }
                other => panic!("Expected AdcQueue, got {:?}", other),
            }
        }
        _ => panic!("Expected DataResponse"),
    }
}

#[test]
fn test_adcqueue_sequence_check() {
    // Create test data with sequence gap
    let mut raw_bytes = vec![0u8; 40]; // 2 samples

    // Sample 0: sequence 10
    raw_bytes[0..2].copy_from_slice(&10u16.to_le_bytes());
    raw_bytes[2..4].copy_from_slice(&60u16.to_le_bytes()); // marker

    // Sample 1: sequence 12 (gap! should be 11)
    raw_bytes[20..22].copy_from_slice(&12u16.to_le_bytes());
    raw_bytes[22..24].copy_from_slice(&60u16.to_le_bytes());

    let queue = AdcQueueData::from_bytes(&raw_bytes).unwrap();
    assert!(queue.has_dropped_samples());

    println!("✅ Dropped sample detection works");
}
