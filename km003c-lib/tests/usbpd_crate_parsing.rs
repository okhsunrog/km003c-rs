use km003c_lib::packet::{Attribute, RawPacket};
use std::fs;
use usbpd::protocol_layer::message::Message;
use usbpd::protocol_layer::message::header::Header;

#[test]
fn test_parse_pd_payloads_with_usbpd_crate() {
    println!("hello!");
    let payloads =
        fs::read_to_string("tests/extracted_pd_payloads.txt").expect("Unable to read file");

    println!("ready to iterate");
    for line in payloads.lines() {
        println!("iterating");
        let bytes = hex::decode(line).expect("Unable to decode hex string");
        let packet = RawPacket::try_from(bytes::Bytes::from(bytes)).unwrap();

        println!("Packet attribute: {:?}", packet.get_attribute());

        if packet.get_attribute() == Some(Attribute::PdPacket) {
            let pd_payload = packet.get_payload_data();
            println!("Attempting to parse payload: {:x?}", pd_payload);

            if pd_payload.len() < 2 {
                println!("Payload too short to be a valid PD message");
                continue;
            }

            let header_bytes: [u8; 2] = pd_payload[0..2].try_into().unwrap();
            let header = Header::from_bytes(&header_bytes).unwrap();
            let num_data_objects = header.num_objects();
            let expected_len = 2 + num_data_objects as usize * 4;

            if pd_payload.len() < expected_len {
                println!(
                    "Payload length {} is less than expected length {}",
                    pd_payload.len(),
                    expected_len
                );
                continue;
            }

            let message = Message::from_bytes(&pd_payload[..expected_len]);

            match &message {
                Ok(msg) => print!("Parsed message: {:#?}
", msg),
                Err(e) => print!("Failed to parse message: {:?}
", e),
            }

            assert!(message.is_ok(), "Failed to parse PD message");
        }
    }
}
