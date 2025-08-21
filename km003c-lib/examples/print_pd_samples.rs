use bytes::Bytes;
use clap::Parser;
use rtshark::{Packet as RtSharkPacket, RTSharkBuilder};
use std::collections::HashSet;
use std::path::PathBuf;

use km003c_lib::packet::RawPacket;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    device_address: Option<u8>,
    #[arg(short, long, help = "Read from a .pcapng file")]
    file: PathBuf,
}

fn main() -> Result<()> {
    let mut cli = Cli::parse();

    // Try to infer device address from filename if not provided
    if cli.device_address.is_none() {
        let filename = cli.file.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if let Some(dot_pos) = filename.rfind('.') {
            let before_ext = &filename[..dot_pos];
            if let Some(second_dot_pos) = before_ext.rfind('.') {
                let potential_id = &before_ext[second_dot_pos + 1..];
                if let Ok(id) = potential_id.parse::<u8>() {
                    println!("[INFO] Inferred device address from filename: {}", id);
                    cli.device_address = Some(id);
                }
            }
        }
    }

    let device_address = cli.device_address.ok_or("Device address is required. Provide it with -d/--device-address or name the input file like 'capture.<id>.pcapng'")?;
    let file_path = cli.file.to_str().ok_or("File path is not valid UTF-8")?;

    // We only care about PutData packets coming FROM the device
    let display_filter = format!(
        "usb.device_address == {} && usb.endpoint_address.direction == 1 && usb.transfer_type == 0x03 && usb.capdata",
        device_address
    );

    let mut rtshark = RTSharkBuilder::builder()
        .input_path(file_path)
        .display_filter(&display_filter)
        .spawn()?;

    println!("[INFO] Reading from file: {:?}", cli.file);
    println!("[INFO] Filtering for USB device address: {}", device_address);
    println!("[INFO] Collecting up to 10 unique samples of each inner packet type...");
    println!("----------------------------------------");

    // --- State Management for collecting samples ---
    const MAX_SAMPLES: usize = 10;
    let mut samples_type_a = HashSet::new(); // Connection Events (6 bytes)
    let mut samples_type_b = HashSet::new(); // Periodic Status (12 bytes)
    let mut samples_type_c = HashSet::new(); // Wrapped PD Msgs (variable length)

    while let Some(packet) = rtshark.read()? {
        process_and_collect(
            packet,
            &mut samples_type_a,
            &mut samples_type_b,
            &mut samples_type_c,
            MAX_SAMPLES,
        )?;

        // Check if we have collected enough samples for all types
        if samples_type_a.len() >= MAX_SAMPLES
            && samples_type_b.len() >= MAX_SAMPLES
            && samples_type_c.len() >= MAX_SAMPLES
        {
            println!("[INFO] Collected enough samples for all types. Stopping read.");
            break;
        }
    }

    // --- Print the collected samples ---
    println!("\n--- Collected Samples ---");
    print_samples("Type A: Connection Events (6 bytes)", &samples_type_a);
    print_samples("Type B: Periodic Status (12 bytes)", &samples_type_b);
    print_samples("Type C: Wrapped PD Messages (variable length)", &samples_type_c);
    println!("----------------------------------------");

    Ok(())
}

fn process_and_collect(
    packet: RtSharkPacket,
    samples_a: &mut HashSet<Vec<u8>>,
    samples_b: &mut HashSet<Vec<u8>>,
    samples_c: &mut HashSet<Vec<u8>>,
    max_samples: usize,
) -> Result<()> {
    let usb_layer = packet.layer_name("usb").ok_or("Missing USB layer")?;
    let payload_hex = usb_layer.metadata("usb.capdata").ok_or("Missing usb.capdata")?.value();
    let clean_hex = payload_hex.replace(':', "");
    let data = hex::decode(&clean_hex)?;
    let bytes = Bytes::from(data);

    if let Ok(parsed_packet) = RawPacket::try_from(bytes) {
        // We only care about PutData packets, which contain the inner stream
        if parsed_packet.packet_type() == km003c_lib::packet::PacketType::PutData {
            // Get the inner payload, skipping the Extended Header
            let mut inner_stream = parsed_packet.get_payload_data();

            // The inner payload can contain multiple concatenated event packets.
            // We loop through it and parse each one.
            while !inner_stream.is_empty() {
                let first_byte = inner_stream[0];
                let consumed_len = match first_byte {
                    0x45 => {
                        let len = 6;
                        if inner_stream.len() < len {
                            break;
                        }
                        if samples_a.len() < max_samples {
                            samples_a.insert(inner_stream[..len].to_vec());
                        }
                        len
                    }
                    0x80..=0x9F => {
                        let wrapper_len = 6;
                        if inner_stream.len() < wrapper_len + 2 {
                            break;
                        }

                        let pd_header_bytes: [u8; 2] = inner_stream[wrapper_len..wrapper_len + 2].try_into()?;
                        let pd_header_val = u16::from_le_bytes(pd_header_bytes);
                        let num_objects = ((pd_header_val >> 12) & 0x07) as usize;
                        let pd_message_len = 2 + (num_objects * 4);
                        let total_chunk_len = wrapper_len + pd_message_len;

                        if inner_stream.len() < total_chunk_len {
                            break;
                        }
                        if samples_c.len() < max_samples {
                            samples_c.insert(inner_stream[..total_chunk_len].to_vec());
                        }
                        total_chunk_len
                    }
                    _ => {
                        let len = 12;
                        if inner_stream.len() < len {
                            break;
                        }
                        if samples_b.len() < max_samples {
                            samples_b.insert(inner_stream[..len].to_vec());
                        }
                        len
                    }
                };

                if consumed_len > 0 {
                    inner_stream = inner_stream.slice(consumed_len..);
                } else {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Helper function to print collected samples in a test-friendly format.
fn print_samples(title: &str, samples: &HashSet<Vec<u8>>) {
    println!("\n// {}", title);
    println!("// Count: {}", samples.len());
    println!("[");
    for sample in samples {
        println!("    \"{}\",", hex::encode(sample));
    }
    println!("]");
}
