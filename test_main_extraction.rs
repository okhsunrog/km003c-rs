use km003c_lib::packet::{Attribute, RawPacket};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{*, Block};
use std::fs::File;
use bytes::Bytes;

fn main() {
    let file = File::open("matching_record/wireshark_0.7.pcapng").unwrap();
    let mut reader = PcapNGReader::new(65536, file).expect("PcapNGReader");
    let mut total_packets = 0;
    let mut pd_packets = 0;
    
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                        if epb.data.len() > 27 {
                            if epb.data[16] == 0x81 {
                                total_packets += 1;
                                let km_payload = epb.data[27..].to_vec();
                                
                                // Try to parse as KM003C packet
                                match RawPacket::try_from(Bytes::from(km_payload)) {
                                    Ok(packet) => {
                                        let attr = packet.get_attribute();
                                        println!("Packet {}: attribute = {:?}", total_packets, attr);
                                        
                                        // Check if this is a PD packet
                                        if attr == Some(Attribute::PdPacket) {
                                            pd_packets += 1;
                                            println!("Found PD packet! Payload length: {}", packet.get_payload_data().len());
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("Failed to parse KM packet: {}", e);
                                    }
                                }
                            }
                        }
                    }
                    _ => (),
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().unwrap();
                continue;
            }
            Err(e) => panic!("Error: {:?}", e),
        }
    }

    println!("Processed {} total KM packets", total_packets);
    println!("Found {} PD packets", pd_packets);
}