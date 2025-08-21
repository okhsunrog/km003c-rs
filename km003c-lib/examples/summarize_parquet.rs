use km003c_lib::capture::CaptureCollection;
use km003c_lib::packet::RawPacket;
use std::path::PathBuf;
use clap::Parser;
use std::collections::BTreeMap;

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
            let ext = pkt.is_extended();
            *counts.entry((ptype, attr, ext)).or_default() += 1;
        } else {
            *counts.entry((255, None, false)).or_default() += 1;
        }
    }
    for ((ptype, attr, ext), c) in counts {
        println!("type 0x{:02x} attr {:?} ext {} -> {}", ptype, attr, ext, c);
    }
    Ok(())
}
