use bytes::Bytes;
use km003c_lib::packet::{DataHeader, ExtendedHeader, PacketType};
use km003c_lib::uom::si::time::second;
use km003c_lib::{Attribute, Packet, PayloadData, PdProtocolTraceEventKind, PdTrace, PdTypeCState, RawPacket};

fn trace_payload() -> Vec<u8> {
    vec![10, 1, 100, 0, 0, 0, 4, 105, 0, 0, 0, 5, 0x82, 110, 0, 0, 0]
}

fn parse_recorded_trace(frame: &str) -> PdTrace {
    let raw = RawPacket::try_from(Bytes::from(hex::decode(frame).unwrap())).unwrap();
    Packet::try_from(raw).unwrap().get_pd_trace().unwrap().clone()
}

#[test]
fn parses_two_firmware_trace_queues() {
    let trace = PdTrace::from_bytes(&trace_payload()).unwrap();

    assert_eq!(trace.state_events.len(), 2);
    assert_eq!(trace.state_events[0].state, PdTypeCState::DelayUnattached);
    assert_eq!(trace.state_events[0].timestamp.get::<second>(), 100.0);
    assert_eq!(trace.state_events[1].state, PdTypeCState::AttachedDebSource);
    assert_eq!(trace.protocol_events.len(), 1);
    assert_eq!(trace.protocol_events[0].kind, PdProtocolTraceEventKind::ReceivedMessage);
    assert_eq!(trace.protocol_events[0].timestamp.get::<second>(), 110.0);
    assert_eq!(trace.to_bytes().unwrap(), trace_payload());
}

#[test]
fn types_confirmed_protocol_markers_and_preserves_unknown_states() {
    let payload = vec![0, 15, 0x82, 1, 0, 0, 0, 0x83, 2, 0, 0, 0, 0x52, 3, 0, 0, 0];
    let trace = PdTrace::from_bytes(&payload).unwrap();

    assert_eq!(trace.protocol_events[0].kind, PdProtocolTraceEventKind::ReceivedMessage);
    assert_eq!(
        trace.protocol_events[1].kind,
        PdProtocolTraceEventKind::ExtendedChunkRequest
    );
    assert_eq!(trace.protocol_events[2].kind, PdProtocolTraceEventKind::Unknown(0x52));
    assert_eq!(trace.to_bytes().unwrap(), payload);
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

#[test]
fn parses_recorded_single_event_response_with_zero_top_level_count() {
    // Captured from KM003C V1.9.9 while a Pixel 8 Pro was connected. The
    // top-level obj_count_words field decodes to zero even though one complete
    // PdTrace logical packet follows.
    let trace = parse_recorded_trace("410a020020000000000582b9000000");

    assert!(trace.state_events.is_empty());
    assert_eq!(trace.protocol_events.len(), 1);
    assert_eq!(trace.protocol_events[0].kind, PdProtocolTraceEventKind::ReceivedMessage);
    assert_eq!(trace.protocol_events[0].timestamp.get::<second>(), 185.0);
}

#[test]
fn parses_recorded_phone_disconnect_response() {
    let trace = parse_recorded_trace("410682002000000005020b01000005000b010000");

    assert_eq!(trace.state_events.len(), 1);
    assert_eq!(trace.state_events[0].state, PdTypeCState::AttachedResistance);
    assert_eq!(trace.state_events[0].timestamp.get::<second>(), 267.0);
    assert_eq!(trace.protocol_events.len(), 1);
    assert_eq!(trace.protocol_events[0].kind, PdProtocolTraceEventKind::Disabled);
    assert_eq!(trace.protocol_events[0].timestamp.get::<second>(), 267.0);
}

#[test]
fn parses_recorded_phone_connect_response_with_a_full_protocol_queue() {
    let trace = parse_recorded_trace(concat!(
        "4106020d200000000f12ab00000005ab00000007ab000000c876ab00000077",
        "ab00000082ab00000078ab00000082ab00000082ac00000082ac00000082",
        "ac00000082ac00000082ac00000082ac00000082ac00000082ac00000052",
        "ac00000078ac00000082ac00000082ac00000082ac00000082ac00000082",
        "ac00000082ad00000082ae00000082ae00000082ae00000082ae00000082",
        "b000000082b000000082b000000082b000000082b000000082b000000082",
        "b000000082b000000082b000000082b100000082b100000082b100000082",
        "b100000082b100000082b1000000"
    ));

    assert_eq!(trace.state_events.len(), 3);
    assert_eq!(trace.state_events[0].state, PdTypeCState::AttachedLightningPlug);
    assert_eq!(trace.state_events[1].state, PdTypeCState::UnattachedDebSource);
    assert_eq!(trace.state_events[2].state, PdTypeCState::TryDebSource);
    assert_eq!(trace.protocol_events.len(), 40);
    assert_eq!(trace.protocol_events[0].kind, PdProtocolTraceEventKind::Unknown(0x76));
    assert_eq!(trace.protocol_events[1].kind, PdProtocolTraceEventKind::Unknown(0x77));
    assert_eq!(trace.protocol_events[2].kind, PdProtocolTraceEventKind::ReceivedMessage);
    assert_eq!(trace.protocol_events.last().unwrap().timestamp.get::<second>(), 177.0);
}

#[test]
fn splits_recorded_zero_sized_trace_before_a_chained_attribute() {
    // Captured from KM003C V1.9.9 with the phone disconnected. PdTrace reports
    // an extended-header size of zero, contains two empty queue prefixes, and
    // is followed by attribute 0x0080 in the same PutData response.
    let raw = RawPacket::try_from(Bytes::from(
        hex::decode("4106820020800000000080000002eefe050000000000").unwrap(),
    ))
    .unwrap();

    let RawPacket::Data { logical_packets, .. } = &raw else {
        panic!("expected a data packet");
    };
    assert_eq!(logical_packets.len(), 2);
    assert_eq!(logical_packets[0].attribute, Attribute::PdTrace);
    assert_eq!(logical_packets[0].payload.as_slice(), &[0, 0]);
    assert_eq!(logical_packets[1].attribute, Attribute::Unknown(0x80));
    assert_eq!(
        logical_packets[1].payload.as_slice(),
        &[0xee, 0xfe, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00]
    );

    let packet = Packet::try_from(raw).unwrap();
    let trace = packet.get_pd_trace().unwrap();
    assert!(trace.state_events.is_empty());
    assert!(trace.protocol_events.is_empty());
    assert!(packet.has_payload(Attribute::Unknown(0x80)));
}
