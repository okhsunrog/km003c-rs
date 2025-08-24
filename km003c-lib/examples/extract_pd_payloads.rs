use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{*, Block};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    let pcap_path = std::env::args().nth(1).expect("Usage: cargo run --example extract_pd_payloads <path_to_pcapng>");
    let out_path = Path::new("extracted_pd_payloads.txt");
    let mut out_file = File::create(out_path).expect("Failed to create output file");

    let file = File::open(pcap_path).unwrap();
    let mut reader = PcapNGReader::new(65536, file).expect("PcapNGReader");
    let mut payloads = BTreeMap::new();
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                        if epb.data.len() > 27 {
                            if epb.data[16] == 0x81 {
                                let payload = epb.data[27..].to_vec();
                                *payloads.entry(payload).or_insert(0) += 1;
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

    for (payload, _) in &payloads {
        writeln!(out_file, "{}", hex::encode(payload)).unwrap();
    }

    println!("Extracted {} unique payloads to {}", payloads.len(), out_path.display());
}
