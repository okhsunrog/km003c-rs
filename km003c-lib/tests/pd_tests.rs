use bytes::Bytes;
use km003c_lib::{Packet, PayloadData, PdEventData, PdEventStream, RawPacket};
use uom::si::electric_current::milliampere;
use uom::si::electric_potential::volt;
use uom::si::time::millisecond;

#[cfg(feature = "usbpd")]
use km003c_lib::usbpd::protocol_layer::message::Payload;
#[cfg(feature = "usbpd")]
use km003c_lib::usbpd::protocol_layer::message::data::Data;
#[cfg(feature = "usbpd")]
use km003c_lib::usbpd::protocol_layer::message::data::request::PowerSource;
#[cfg(feature = "usbpd")]
use km003c_lib::usbpd::protocol_layer::message::extended::Extended;
#[cfg(feature = "usbpd")]
use km003c_lib::{DecodedPdEvent, PdChunkState, PdEvent, PdSessionDecoder};

fn parse_pd_events(frame: &str) -> km003c_lib::PdEventStream {
    let raw = RawPacket::try_from(Bytes::from(hex::decode(frame).unwrap())).unwrap();
    Packet::try_from(raw).unwrap().get_pd_events().unwrap().clone()
}

fn assert_milliseconds(timestamp: uom::si::f64::Time, expected: f64) {
    assert!((timestamp.get::<millisecond>() - expected).abs() < 1e-6);
}

fn parse_pd_status(frame: &str) -> km003c_lib::PdStatus {
    let raw = RawPacket::try_from(Bytes::from(hex::decode(frame).unwrap())).unwrap();
    *Packet::try_from(raw).unwrap().get_pd_status().unwrap()
}

#[test]
fn parses_recorded_standalone_pd_status_timestamp() {
    // Source: usb_master_dataset.parquet, orig_with_pd.13, frame 150.
    let status = parse_pd_status("411c820010000003d6e7120003000000a50c7d00");

    assert_milliseconds(status.timestamp, 1_238_998.0);
    assert_eq!(status.ibus.get::<milliampere>(), 0.0);
}

#[test]
fn parses_recorded_chained_pd_status_timestamp() {
    // Source: usb_master_dataset.parquet, orig_with_pd.13, frame 166.
    let raw = RawPacket::try_from(Bytes::from(
        hex::decode("412082030180000bc1100000160000009a10000010000000fe1000006e000000dd0f837ed8041b0310038b7e008078004d004c001000000376e8120003000000a50c7b00").unwrap(),
    ))
    .unwrap();
    let Packet::DataResponse { payloads } = Packet::try_from(raw).unwrap() else {
        panic!("expected data response");
    };
    let status = payloads
        .iter()
        .find_map(|payload| match payload {
            PayloadData::PdStatus(status) => Some(status),
            _ => None,
        })
        .unwrap();

    assert_milliseconds(status.timestamp, 1_239_158.0);
    assert_eq!(status.ibus.get::<milliampere>(), 0.0);
}

#[test]
fn parses_recorded_pd_message_stream() {
    // Source: usb_master_dataset.parquet, orig_with_pd.13, frame 714.
    let frame = "41a90205100000168bfa1200de130000750602009f80fa120000a1632c9101082cd102002cc103002cb10400454106003c21dcc08781fa12000041028b85fa1200008210dc7003238786fa1200002101878afa120000a305878afa1200004104";
    let stream = parse_pd_events(frame);

    assert_milliseconds(stream.preamble.timestamp, 1_243_787.0);
    assert_eq!(stream.preamble.vbus.get::<volt>(), 5.086);
    assert_eq!(stream.events.len(), 6);

    let expected = [
        (1_243_776, "a1632c9101082cd102002cc103002cb10400454106003c21dcc0"),
        (1_243_777, "4102"),
        (1_243_781, "8210dc700323"),
        (1_243_782, "2101"),
        (1_243_786, "a305"),
        (1_243_786, "4104"),
    ];

    for (event, (timestamp, wire_hex)) in stream.events.iter().zip(expected) {
        assert_milliseconds(event.timestamp, f64::from(timestamp));
        assert_eq!(
            event.data,
            PdEventData::PdMessage {
                sop: 0,
                wire_data: hex::decode(wire_hex).unwrap(),
            }
        );
    }
}

#[test]
fn recognizes_legacy_recorded_connection_events() {
    // Source: usb_master_dataset.parquet, orig_with_pd.13, frames 666 and 1298.
    let connect = parse_pd_events("419dc20010008004def81200000000007406020045d4f8120011");
    let disconnect = parse_pd_events("413bc20010008004eb0d1300f1130000a80c7f0045cc0d130012");

    assert_milliseconds(connect.events[0].timestamp, 1_243_348.0);
    assert_eq!(connect.events[0].data, PdEventData::Connect(()));
    assert_milliseconds(disconnect.events[0].timestamp, 1_248_716.0);
    assert_eq!(disconnect.events[0].data, PdEventData::Disconnect(()));
}

#[test]
fn recognizes_current_recorded_connection_event() {
    // Source: usb_master_dataset.parquet, pd_epr0.9, frame 887.
    let connect = parse_pd_events("4194c20010008004fba90100030000000000200645efa9010021");

    assert_milliseconds(connect.events[0].timestamp, 109_039.0);
    assert_eq!(connect.events[0].data, PdEventData::Connect(()));
}

#[test]
fn rejects_incomplete_event_header() {
    let mut payload = vec![0; km003c_lib::constants::PD_STATUS_SIZE];
    payload.push(0x87);

    let error = PdEventStream::from_bytes(Bytes::from(payload)).unwrap_err();
    assert!(error.to_string().contains("Incomplete PD event header"));
}

#[test]
fn rejects_event_size_smaller_than_protocol_offset() {
    let mut payload = vec![0; km003c_lib::constants::PD_STATUS_SIZE];
    payload.extend_from_slice(&[0x04, 0, 0, 0, 0, 0]);

    let error = PdEventStream::from_bytes(Bytes::from(payload)).unwrap_err();
    assert!(error.to_string().contains("Invalid PD event size"));
}

#[cfg(feature = "usbpd")]
#[test]
fn semantically_decodes_recorded_pd_negotiation_with_source_state() {
    // Source: usb_master_dataset.parquet, orig_with_pd.13, frame 714.
    let stream = parse_pd_events(
        "41a90205100000168bfa1200de130000750602009f80fa120000a1632c9101082cd102002cc103002cb10400454106003c21dcc08781fa12000041028b85fa1200008210dc7003238786fa1200002101878afa120000a305878afa1200004104",
    );
    let mut decoder = PdSessionDecoder::new();

    let DecodedPdEvent::Message(source_caps) = decoder.decode_event(&stream.events[0]) else {
        panic!("expected SourceCapabilities message");
    };
    assert!(matches!(
        source_caps.message.payload,
        Some(Payload::Data(Data::SourceCapabilities(_)))
    ));
    assert!(decoder.source_capabilities().is_some());

    let DecodedPdEvent::Message(request) = decoder.decode_event(&stream.events[2]) else {
        panic!("expected Request message");
    };
    assert!(matches!(
        request.message.payload,
        Some(Payload::Data(Data::Request(
            PowerSource::FixedVariableSupply(_) | PowerSource::Battery(_) | PowerSource::Pps(_) | PowerSource::Avs(_)
        )))
    ));
}

#[cfg(feature = "usbpd")]
#[test]
fn connection_events_reset_semantic_decoder_state() {
    let stream = parse_pd_events(
        "41a90205100000168bfa1200de130000750602009f80fa120000a1632c9101082cd102002cc103002cb10400454106003c21dcc08781fa12000041028b85fa1200008210dc7003238786fa1200002101878afa120000a305878afa1200004104",
    );
    let mut decoder = PdSessionDecoder::new();
    decoder.decode_event(&stream.events[0]);
    assert!(decoder.source_capabilities().is_some());

    let connect = PdEvent {
        timestamp: uom::si::f64::Time::new::<millisecond>(1_250_000.0),
        data: PdEventData::Connect(()),
    };
    assert!(matches!(decoder.decode_event(&connect), DecodedPdEvent::Connect { .. }));
    assert!(decoder.source_capabilities().is_none());

    decoder.decode_event(&stream.events[0]);
    assert!(decoder.source_capabilities().is_some());
    let disconnect = PdEvent {
        timestamp: uom::si::f64::Time::new::<millisecond>(1_250_001.0),
        data: PdEventData::Disconnect(()),
    };
    assert!(matches!(
        decoder.decode_event(&disconnect),
        DecodedPdEvent::Disconnect { .. }
    ));
    assert!(decoder.source_capabilities().is_none());
}

#[cfg(feature = "usbpd")]
#[test]
fn assembles_recorded_chunked_epr_source_capabilities() {
    // Captured EPR Source Capabilities split into two USB PD extended-message chunks.
    let chunks = [
        vec![
            0xB1, 0xFD, 0x28, 0x80, 0x2C, 0x91, 0x91, 0x0A, 0x2C, 0xD1, 0x12, 0x00, 0x2C, 0xC1, 0x13, 0x00, 0x2C, 0xB1,
            0x14, 0x00, 0xF4, 0x41, 0x16, 0x00, 0x64, 0x32, 0xA4, 0xC9, 0x00, 0x00,
        ],
        vec![
            0xB1, 0xCF, 0x28, 0x88, 0x00, 0x00, 0xF4, 0xC1, 0x18, 0x00, 0xF4, 0x41, 0x1B, 0x00, 0xF4, 0x01, 0x1F, 0x00,
        ],
    ];
    let mut decoder = PdSessionDecoder::new();

    let first = PdEvent {
        timestamp: uom::si::f64::Time::new::<millisecond>(1.0),
        data: PdEventData::PdMessage {
            sop: 0,
            wire_data: chunks[0].clone(),
        },
    };
    let DecodedPdEvent::Chunk(status) = decoder.decode_event(&first) else {
        panic!("expected pending chunk status");
    };
    assert_eq!(
        status.state,
        PdChunkState::Pending {
            received_chunk: 0,
            next_chunk: 1,
        }
    );

    let second = PdEvent {
        timestamp: uom::si::f64::Time::new::<millisecond>(2.0),
        data: PdEventData::PdMessage {
            sop: 0,
            wire_data: chunks[1].clone(),
        },
    };
    let DecodedPdEvent::Message(message) = decoder.decode_event(&second) else {
        panic!("expected assembled EPR SourceCapabilities");
    };
    let Some(Payload::Extended(Extended::EprSourceCapabilities(pdos))) = message.message.payload else {
        panic!("expected EPR SourceCapabilities payload");
    };
    assert_eq!(pdos.len(), 10);
}

#[cfg(feature = "usbpd")]
#[test]
fn reports_short_wire_messages_without_panicking() {
    let event = PdEvent {
        timestamp: uom::si::f64::Time::new::<millisecond>(1.0),
        data: PdEventData::PdMessage {
            sop: 0,
            wire_data: vec![0x01],
        },
    };
    let mut decoder = PdSessionDecoder::new();

    let DecodedPdEvent::Error(failure) = decoder.decode_event(&event) else {
        panic!("expected decode failure");
    };
    assert!(failure.error.to_string().contains("expected 2"));
    assert_eq!(failure.wire_data, vec![0x01]);
}
