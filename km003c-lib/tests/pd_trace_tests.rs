use bytes::Bytes;
use km003c_lib::packet::{DataHeader, ExtendedHeader, PacketType};
use km003c_lib::uom::si::time::second;
use km003c_lib::{Attribute, Packet, PayloadData, PdTrace, PdTypeCState, RawPacket};

fn trace_payload() -> Vec<u8> {
    vec![10, 1, 100, 0, 0, 0, 4, 105, 0, 0, 0, 5, 0x82, 110, 0, 0, 0]
}

#[test]
fn parses_two_firmware_trace_queues() {
    let trace = PdTrace::from_bytes(&trace_payload()).unwrap();

    assert_eq!(trace.state_events.len(), 2);
    assert_eq!(trace.state_events[0].state, PdTypeCState::DelayUnattached);
    assert_eq!(trace.state_events[0].timestamp.get::<second>(), 100.0);
    assert_eq!(trace.state_events[1].state, PdTypeCState::AttachedDebSource);
    assert_eq!(trace.protocol_events.len(), 1);
    assert_eq!(trace.protocol_events[0].code, 0x82);
    assert_eq!(trace.protocol_events[0].timestamp.get::<second>(), 110.0);
    assert_eq!(trace.to_bytes().unwrap(), trace_payload());
}

#[test]
fn rejects_malformed_trace_queues() {
    assert!(PdTrace::from_bytes(&[]).is_err());
    assert!(PdTrace::from_bytes(&[4, 0, 0, 0, 0, 0]).is_err());
    assert!(PdTrace::from_bytes(&[5, 1, 0, 0, 0, 0]).is_err());

    let oversized = vec![205; 207];
    assert!(PdTrace::from_bytes(&oversized).is_err());
}

#[test]
fn splits_zero_sized_trace_before_a_chained_payload() {
    let mut bytes = DataHeader::new()
        .with_packet_type(PacketType::PutData.into())
        .with_id(7)
        .with_obj_count_words(1)
        .into_bytes()
        .to_vec();
    bytes.extend_from_slice(
        &ExtendedHeader::new()
            .with_attribute(Attribute::PdTrace.into())
            .with_next(true)
            .with_size(0)
            .into_bytes(),
    );
    bytes.extend_from_slice(&trace_payload());
    bytes.extend_from_slice(
        &ExtendedHeader::new()
            .with_attribute(Attribute::PdPacket.into())
            .with_next(false)
            .with_size(12)
            .into_bytes(),
    );
    bytes.extend_from_slice(&[0; 12]);

    let raw = RawPacket::try_from(Bytes::from(bytes)).unwrap();
    let packet = Packet::try_from(raw).unwrap();
    let Packet::DataResponse { payloads } = packet else {
        panic!("expected data response");
    };

    assert!(matches!(payloads[0], PayloadData::PdTrace(_)));
    assert!(matches!(payloads[1], PayloadData::PdStatus(_)));
}

#[test]
fn semantic_trace_round_trips_through_a_put_data_packet() {
    let trace = PdTrace::from_bytes(&trace_payload()).unwrap();
    let raw = Packet::DataResponse {
        payloads: vec![PayloadData::PdTrace(trace.clone())],
    }
    .to_raw_packet(3)
    .unwrap();
    let reparsed = Packet::try_from(RawPacket::try_from(Bytes::from(raw)).unwrap()).unwrap();

    assert_eq!(reparsed.get_pd_trace(), Some(&trace));
}
