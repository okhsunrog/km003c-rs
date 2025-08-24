use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{*, Block};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

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
