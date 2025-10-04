use bytes::Bytes;
use km003c_lib::{AdcQueueData, Packet, RawPacket};

#[test]
fn test_adcqueue_parsing() {
    // Real AdcQueue packet from dataset (first 48 bytes)
    // Main header (4) + Extended header (4) + 2 samples (2×20=40) = 48 bytes
    let hex = "411d8230020027054e003c00a98b4d00d20000004300a30c000000004f003c00a98b4d00d20000004300a50c00000000";

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

                    // Check first sample
                    let sample0 = &queue.samples[0];
                    assert_eq!(sample0.sequence, 78);
                    assert!((sample0.vbus_v - 5.082).abs() < 0.001); // ~5.082V
                    assert!(sample0.ibus_a < 0.001); // ~0.21mA
                    assert!((sample0.cc1_v - 0.067).abs() < 0.001); // 67mV
                    assert!((sample0.cc2_v - 3.235).abs() < 0.01); // 3235mV

                    // Check second sample
                    let sample1 = &queue.samples[1];
                    assert_eq!(sample1.sequence, 79);

                    println!("✅ AdcQueue parsing successful!");
                    println!(
                        "   Sample 0: seq={} vbus={:.3}V ibus={:.3}mA",
                        sample0.sequence,
                        sample0.vbus_v,
                        sample0.ibus_a * 1000.0
                    );
                    println!(
                        "   Sample 1: seq={} vbus={:.3}V ibus={:.3}mA",
                        sample1.sequence,
                        sample1.vbus_v,
                        sample1.ibus_a * 1000.0
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
