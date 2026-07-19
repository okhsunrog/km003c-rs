use bytes::Bytes;
use km003c_lib::{Packet, PdEventData, PdEventStream, RawPacket};
use uom::si::electric_potential::volt;
use uom::si::time::millisecond;

fn parse_pd_events(frame: &str) -> km003c_lib::PdEventStream {
    let raw = RawPacket::try_from(Bytes::from(hex::decode(frame).unwrap())).unwrap();
    Packet::try_from(raw).unwrap().get_pd_events().unwrap().clone()
}

fn assert_milliseconds(timestamp: uom::si::f64::Time, expected: f64) {
    assert!((timestamp.get::<millisecond>() - expected).abs() < 1e-6);
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
    let mut payload = vec![0; km003c_lib::constants::PD_PREAMBLE_SIZE];
    payload.push(0x87);

    let error = PdEventStream::from_bytes(Bytes::from(payload)).unwrap_err();
    assert!(error.to_string().contains("Incomplete PD event header"));
}

#[test]
fn rejects_event_size_smaller_than_protocol_offset() {
    let mut payload = vec![0; km003c_lib::constants::PD_PREAMBLE_SIZE];
    payload.extend_from_slice(&[0x04, 0, 0, 0, 0, 0]);

    let error = PdEventStream::from_bytes(Bytes::from(payload)).unwrap_err();
    assert!(error.to_string().contains("Invalid PD event size"));
}
