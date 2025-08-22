use clap::Parser;
use km003c_lib::capture::CaptureCollection;
use km003c_lib::packet::RawPacket;
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

                if let Some(ext) = pkt.get_extended_header() {
                    println!(
                        "  Extended header: attribute=0x{:x} next={} chunk={} size={} ",
                        ext.attribute(),
                        ext.next(),
                        ext.chunk(),
                        ext.size()
                    );
                }
            }
            Err(e) => {
                println!("Frame {} parse error: {}", cap.frame_number, e);
            }
        }
    }
    Ok(())
}
