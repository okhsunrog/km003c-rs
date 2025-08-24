
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[test]
fn test_parse_pd_payloads() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/extracted_pd_payloads.txt");
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);

    let line = reader.lines().nth(1).unwrap().unwrap();
    let bytes = hex::decode(line).unwrap();
    println!("bytes: {:?}", bytes);
    let message = usbpd::protocol_layer::message::Message::from_bytes(&bytes).unwrap();
    println!("{:#?}", message);
}
