use bytes::Bytes;
use km003c_lib::{AdcQueueData, GraphSampleRate, Packet, RawPacket, sequence_elapsed};
use uom::si::electric_current::ampere;
use uom::si::electric_potential::volt;
use uom::si::time::millisecond;

#[test]
fn test_adcqueue_parsing() {
    // Real AdcQueue packet from pd_adcqueue_new.11 (modern firmware)
    // Main header (4) + Extended header (4) + 2 samples (2×20=40) = 48 bytes
    // The 500-tick sequence step identifies 2 SPS and its 0.1mV scale.
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
        Packet::DataResponse { payloads } => {
            assert_eq!(payloads.len(), 1);

            match &payloads[0] {
                km003c_lib::PayloadData::AdcQueue(queue) => {
                    // Should have 2 samples (40 bytes / 20)
                    assert_eq!(queue.samples.len(), 2);

                    // Check first sample (modern firmware with all fields)
                    let sample0 = &queue.samples[0];
                    assert_eq!(sample0.sequence, 59405);
                    assert!((sample0.vbus.get::<volt>() - 9.225).abs() < 0.01); // 9225173 µV
                    assert!((sample0.ibus.get::<ampere>() + 1.537).abs() < 0.01); // -1536935 µA
                    assert!((sample0.cc1.get::<volt>() - 1.660).abs() < 0.01); // 16604×0.1mV = 1.66V
                    assert!((sample0.cc2.get::<volt>() - 0.029).abs() < 0.01); // 287×0.1mV = 29mV
                    assert!((sample0.vdp.get::<volt>() - 0.598).abs() < 0.01); // 5979×0.1mV
                    assert!((sample0.vdm.get::<volt>() - 0.598).abs() < 0.01); // 5976×0.1mV

                    // Check second sample
                    let sample1 = &queue.samples[1];
                    assert_eq!(sample1.sequence, 59905);
                    assert!((sample1.vbus.get::<volt>() - 9.220).abs() < 0.01);

                    println!("✅ AdcQueue parsing successful!");
                    println!(
                        "   Sample 0: seq={} vbus={:.3}V ibus={:.3}A cc1={:.3}V d+={:.3}V",
                        sample0.sequence,
                        sample0.vbus.get::<volt>(),
                        sample0.ibus.get::<ampere>(),
                        sample0.cc1.get::<volt>(),
                        sample0.vdp.get::<volt>()
                    );
                    println!(
                        "   Sample 1: seq={} vbus={:.3}V ibus={:.3}A",
                        sample1.sequence,
                        sample1.vbus.get::<volt>(),
                        sample1.ibus.get::<ampere>()
                    );
                }
                other => panic!("Expected AdcQueue, got {:?}", other),
            }
        }
        _ => panic!("Expected DataResponse"),
    }
}

#[test]
fn test_adcqueue_with_following_pd_status() {
    // Main header + AdcQueue header + 2 samples + PD header + PD status.
    let hex = "410a420302800205ae3f0600b0ec300170cd1800ee01c706c900c500\
               af3f0600b0ec300170cd1800ee01c606c500ba0010000003\
               b43f0600074e0e08ef01c606";
    let raw_packet = RawPacket::try_from(Bytes::from(hex::decode(hex).unwrap())).unwrap();
    let packet = Packet::try_from(raw_packet).unwrap();

    assert_eq!(packet.get_adc_queue().unwrap().samples.len(), 2);
    assert!(packet.get_pd_status().is_some());
}

#[test]
fn test_adcqueue_fast_rate_auxiliary_voltage_scale() {
    // Recorded ADC + AdcQueue response from pd_adcqueue_new.11. The queue
    // sequence advances by 20 ticks (50 SPS), and its auxiliary readings use
    // 1mV units. The simultaneously captured ADC values provide ground truth.
    let hex = "414702050180000b30f88b00ba07ecff1fee8b00cee7ebff25ee8b00d9f0ebff3d0fd840110146174417957e00801a005302520202000205d75a09006ff68b00df02ecff7c061c0052024f02eb5a0900bdf68b00d702ecff7a061a0051025002ff5a09006df78b003d05ecff79061a0059025102135b090094f78b00be06ecff7b061b0054024e02275b090030f88b00ba07ecff7a061a0051025002";
    let raw_packet = RawPacket::try_from(Bytes::from(hex::decode(hex).unwrap())).unwrap();
    let packet = Packet::try_from(raw_packet).unwrap();

    let adc = packet.get_adc().unwrap();
    let queue = packet.get_adc_queue().unwrap();
    let sample = queue.samples.first().unwrap();

    assert_eq!(queue.samples[1].sequence.wrapping_sub(sample.sequence), 20);
    assert!((sample.cc1 - adc.cc1).abs().get::<volt>() < 0.01);
    assert!((sample.cc2 - adc.cc2).abs().get::<volt>() < 0.01);
    assert!((sample.vdp - adc.vdp).abs().get::<volt>() < 0.01);
    assert!((sample.vdm - adc.vdm).abs().get::<volt>() < 0.01);
}

#[test]
fn test_explicit_rate_controls_auxiliary_voltage_scale() {
    let mut raw_bytes = vec![0_u8; 20];
    raw_bytes[12..14].copy_from_slice(&1_632_u16.to_le_bytes());

    let slow = AdcQueueData::from_bytes_with_rate(&raw_bytes, GraphSampleRate::Sps2).unwrap();
    let fast = AdcQueueData::from_bytes_with_rate(&raw_bytes, GraphSampleRate::Sps50).unwrap();

    assert!((slow.samples[0].cc1.get::<volt>() - 0.1632).abs() < 1e-12);
    assert!((fast.samples[0].cc1.get::<volt>() - 1.632).abs() < 1e-12);
}

#[test]
fn test_adcqueue_sequence_check() {
    // At 50 SPS the sequence counter advances by 20 ticks per sample.
    let mut raw_bytes = vec![0u8; 40]; // 2 samples

    // Sample 0: sequence 10
    raw_bytes[0..2].copy_from_slice(&10u16.to_le_bytes());
    raw_bytes[2..4].copy_from_slice(&60u16.to_le_bytes()); // marker

    // Sample 1: sequence 50 (one missing sample; contiguous would be 30)
    raw_bytes[20..22].copy_from_slice(&50u16.to_le_bytes());
    raw_bytes[22..24].copy_from_slice(&60u16.to_le_bytes());

    let queue = AdcQueueData::from_bytes(&raw_bytes).unwrap();
    assert!(queue.has_dropped_samples(GraphSampleRate::Sps50));

    println!("✅ Dropped sample detection works");
}

#[test]
fn test_adcqueue_sequence_steps_follow_sample_rate() {
    assert_eq!(GraphSampleRate::Sps2.sequence_step(), 500);
    assert_eq!(GraphSampleRate::Sps10.sequence_step(), 100);
    assert_eq!(GraphSampleRate::Sps50.sequence_step(), 20);
    assert_eq!(GraphSampleRate::Sps1000.sequence_step(), 1);

    assert_eq!(GraphSampleRate::from_sequence_step(500), Some(GraphSampleRate::Sps2));
    assert_eq!(GraphSampleRate::from_sequence_step(20), Some(GraphSampleRate::Sps50));
    assert_eq!(GraphSampleRate::from_sequence_step(40), None);

    assert_eq!(GraphSampleRate::Sps2.missing_samples(65_300, 264), 0);
    assert_eq!(GraphSampleRate::Sps50.missing_samples(100, 140), 1);
    assert_eq!(sequence_elapsed(65_300, 264).get::<millisecond>(), 500.0);
}
