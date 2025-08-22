use clap::Parser;
use km003c_lib::capture::CaptureCollection;
use km003c_lib::packet::RawPacket;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    input: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let collection = CaptureCollection::load_from_parquet(&args.input)?;
    let mut counts: BTreeMap<(u8, Option<u16>, bool), usize> = BTreeMap::new();
    for cap in collection.captures() {
        if let Ok(pkt) = RawPacket::try_from(bytes::Bytes::from(cap.raw_bytes.clone())) {
            let ptype: u8 = pkt.packet_type().into();
            let attr = pkt.get_attribute().map(|a| a.into());
            let flg = pkt.flag();
            *counts.entry((ptype, attr, flg)).or_default() += 1;
        } else {
            *counts.entry((255, None, false)).or_default() += 1;
        }
    }
    for ((ptype, attr, flg), c) in counts {
        println!("type 0x{:02x} attr {:?} flag {} -> {}", ptype, attr, flg, c);
    }
    Ok(())
}
