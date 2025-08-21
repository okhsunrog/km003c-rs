use clap::Parser;
use km003c_lib::capture::CaptureCollection;
use km003c_lib::packet::{ExtendedHeader, RawPacket};
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    input: PathBuf,
    #[arg(long, default_value_t = 20)]
    limit: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let collection = CaptureCollection::load_from_parquet(&args.input)?;
    println!("Loaded {} captures from {:?}", collection.len(), args.input);
    for cap in collection.captures().iter().take(args.limit) {
        match RawPacket::try_from(bytes::Bytes::from(cap.raw_bytes.clone())) {
            Ok(pkt) => {
                let ptype: u8 = pkt.packet_type().into();
                let payload = pkt.payload();
                println!(
                    "Frame {} {:?} type 0x{:02x} payload_len {}",
                    cap.frame_number,
                    cap.direction,
                    ptype,
                    payload.len()
                );

                // Try normal parsing first
                if let Some(ext) = pkt.get_extended_header() {
                    println!(
                        "  Extended header: attribute=0x{:x} next={} chunk={} size={} ",
                        ext.attribute(),
                        ext.next(),
                        ext.chunk(),
                        ext.size()
                    );
                }

                // Always attempt to interpret the first four bytes as an extended header
                if payload.len() >= 4 {
                    if let Ok(bytes) = payload[..4].try_into() {
                        let raw_ext = ExtendedHeader::from_bytes(bytes);
                        let data_len = payload.len().saturating_sub(4);
                        let matches = raw_ext.size() as usize == data_len;
                        println!(
                            "  Raw ext header: attribute=0x{:x} next={} chunk={} size={} (matches payload: {})",
                            raw_ext.attribute(),
                            raw_ext.next(),
                            raw_ext.chunk(),
                            raw_ext.size(),
                            matches
                        );
                    }
                }
            }
            Err(e) => {
                println!("Frame {} parse error: {}", cap.frame_number, e);
            }
        }
    }
    Ok(())
}
