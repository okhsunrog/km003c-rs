use bytes::Bytes;
use km003c_lib::packet::{Attribute, RawPacket};
use km003c_lib::pd::{EventPacket, ParseError, parse_event_stream};

#[test]
fn test_parse_pcap_payloads_all_lines_parse() {
    let payloads = include_str!("extracted_pd_payloads.txt");
    for (idx, line) in payloads.lines().enumerate() {
        let buf = hex::decode(line).expect("invalid hex in extracted payloads");
        // Parse top-level packet to ensure it's a PD carrying Data packet
        let raw = match RawPacket::try_from(Bytes::from(buf.clone())) {
            Ok(r) => r,
            Err(_) => continue, // skip non-packets or truncated frames
        };
        if let Some(attr) = raw.get_attribute() {
            match attr {
                Attribute::PdPacket | Attribute::PdStatus => {
                    let payload = raw.get_payload_data();
                    if payload.len() <= 12 { continue; }
                    let bytes = payload.as_ref();
                    let mut offset = 12usize; // skip 12-byte ADC snapshot header
                    while offset < bytes.len() {
                        match EventPacket::from_slice(&bytes[offset..]) {
                            Ok((_packet, consumed)) => {
                                assert!(consumed > 0, "zero-length consumption at line {}", idx);
                                offset += consumed;
                            }
                            Err(ParseError::UnexpectedEof) => {
                                panic!("Unexpected EOF while parsing line {} at offset {}", idx, offset);
                            }
                        }
                    }
                    // Also ensure the convenience parser returns Ok and non-empty
                    let parsed = parse_event_stream(&bytes[12..]).expect("parse_event_stream failed");
                    assert!(parsed.len() > 0, "no records parsed for line {}", idx);
                }
                _ => continue,
            }
        }
    }
}
