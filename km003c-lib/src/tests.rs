use crate::packet::Packet;
use bytes::Bytes;

#[test]
fn test_parse_packet_02010000() {
    let hex_data = "02010000";
    let bytes_data = hex::decode(hex_data).expect("Failed to decode hex");
    let bytes = Bytes::from(bytes_data);
    
    println!("Parsing hex data: {}", hex_data);
    println!("Raw bytes: {:02x?}", bytes);
    
    match Packet::try_from(bytes) {
        Ok(packet) => {
            println!("Successfully parsed packet: {:?}", packet);
        }
        Err(e) => {
            println!("Failed to parse packet: {:?}", e);
        }
    }
}