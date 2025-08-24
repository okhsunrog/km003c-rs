use km003c_lib::packet::{Attribute, RawPacket};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{*, Block};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use bytes::Bytes;

fn main() {
    let mut args = std::env::args().skip(1);
    let pcap_path = args.next().expect("Usage: cargo run --example extract_pd_payloads <path_to_pcapng> [--out <path>]");
    let mut out_path = PathBuf::from("km003c-lib/tests/extracted_pd_payloads.txt");
    while let Some(arg) = args.next() {
        if arg == "--out" {
            if let Some(p) = args.next() { out_path = PathBuf::from(p); }
        }
    }
    if let Some(parent) = out_path.parent() { let _ = std::fs::create_dir_all(parent); }
    let mut out_file = File::create(&out_path).expect("Failed to create output file");

    let file = File::open(pcap_path).unwrap();
    let mut reader = PcapNGReader::new(65536, file).expect("PcapNGReader");
    let mut payloads = BTreeMap::new();
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
                                        println!("Found packet with attribute: {:?}", attr);
                                        
                                        // Check if this is a PD packet
                                        if attr == Some(Attribute::PdPacket) {
                                            pd_packets += 1;
                                            let pd_payload = packet.get_payload_data();
                                            *payloads.entry(pd_payload.to_vec()).or_insert(0) += 1;
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

    for (payload, count) in &payloads {
        writeln!(out_file, "{}", hex::encode(payload)).unwrap();
    }

    println!("Processed {} total KM packets", total_packets);
    println!("Found {} PD packets", pd_packets);
    println!("Extracted {} unique PD payloads to {}", payloads.len(), out_path.display());
}
