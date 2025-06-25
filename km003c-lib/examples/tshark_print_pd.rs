use bytes::Bytes;
use km003c_lib::{message::Packet, packet::RawPacket};
use rtshark::RTSharkBuilder;
use std::fmt::Write;
use usbpd::protocol_layer::message::{
    Message,
    pdo::{Augmented, PowerDataObject, SourceCapabilities},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    let mut device_address: Option<u8> = None;
    let filename = "wireshark/orig_with_pd.13.pcapng";
    if let Some(dot_pos) = filename.rfind('.') {
        let before_ext = &filename[..dot_pos];
        if let Some(second_dot_pos) = before_ext.rfind('.') {
            let potential_id = &before_ext[second_dot_pos + 1..];
            if let Ok(id) = potential_id.parse::<u8>() {
                println!("Inferred device address from filename: {}", id);
                device_address = Some(id);
            }
        }
    }

    let device_address = device_address.unwrap();

    // Set up tshark with USB filter
    let display_filter = format!(
        "usb.device_address == {} && usb.transfer_type == 0x03 && usb.capdata",
        device_address
    );

    let mut rtshark = RTSharkBuilder::builder()
        .input_path(filename)
        .display_filter(&display_filter)
        .spawn()?;

    while let Some(packet) = rtshark.read()? {
        let usb_layer = packet.layer_name("usb").unwrap();

        let payload_hex = usb_layer.metadata("usb.capdata").ok_or("Missing usb.capdata")?.value();
        let clean_hex = payload_hex.replace(':', "");
        let data = hex::decode(&clean_hex).map_err(|e| format!("Failed to decode hex payload: {}", e))?;
        let bytes = Bytes::from(data);

        if let Ok(raw_packet) = RawPacket::try_from(bytes) {
            if let Ok(packet) = Packet::try_from(raw_packet) {
                match packet {
                    Packet::PdRawData(data) => {
                        // This is the new stream parsing logic
                        parse_km003c_stream(&data);
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

// Add this new helper function to your file
fn parse_km003c_stream(mut stream: &[u8]) {
    const KM003C_HEADER_LEN: usize = 6;
    const POLLING_PACKET_LEN: usize = 12; // Assumed length of non-PD status packets

    while !stream.is_empty() {
        if stream.len() < KM003C_HEADER_LEN {
            // Not enough data for even a wrapper header
            // println!("[STREAM] Remaining truncated data: {}", hex::encode(stream));
            break;
        }

        let wrapper_header = &stream[..KM003C_HEADER_LEN];
        let potential_payload = &stream[KM003C_HEADER_LEN..];

        // Check the SOP packet flag (MSB of the first byte of the wrapper header)
        let is_sop_packet = (wrapper_header[0] & 0x80) != 0;

        if is_sop_packet && potential_payload.len() >= 2 {
            // It's flagged as a PD message, let's try to determine its length
            // from the actual PD header.
            let pd_header_bytes: [u8; 2] = potential_payload[0..2].try_into().unwrap();
            let pd_header_val = u16::from_le_bytes(pd_header_bytes);

            // Check if it's a valid message type to avoid parsing garbage
            let message_type = pd_header_val & 0x1F;
            if message_type > 0 && message_type <= 0x16 {
                // Valid range for PD messages
                let num_objects = ((pd_header_val >> 12) & 0x07) as usize;
                let pd_message_len = 2 + num_objects * 4;
                let total_chunk_len = KM003C_HEADER_LEN + pd_message_len;

                if stream.len() >= total_chunk_len {
                    // We have enough data for the full chunk
                    let pd_message_bytes = &stream[KM003C_HEADER_LEN..total_chunk_len];

                    println!("[PD MSG] Raw wrapped: {}", hex::encode(&stream[..total_chunk_len]));
                    let message = Message::from_bytes(pd_message_bytes);

                    // Check if the message data is a SourceCapabilities variant
                    if let Some(usbpd::protocol_layer::message::Data::SourceCapabilities(caps)) = &message.data {
                        // If it is, use our new pretty-printing function
                        let formatted_caps = format_source_capabilities(caps);
                        println!("  -> Parsed:\n{}", formatted_caps);
                    } else {
                        // Otherwise, use the default debug print for other message types
                        println!("  -> Parsed: {:?}\n", message);
                    }

                    // Advance the stream past this entire chunk
                    stream = &stream[total_chunk_len..];
                    continue; // Continue to the next chunk in the stream
                }
            }
        }

        // If it's not a valid SOP packet we can parse, assume it's a fixed-size status packet
        // and advance the stream to look for the next valid chunk.
        // println!("[STATUS] Skipping non-PD packet: {}", hex::encode(&stream[..std::cmp::min(stream.len(), POLLING_PACKET_LEN)]));
        if stream.len() >= POLLING_PACKET_LEN {
            stream = &stream[POLLING_PACKET_LEN..];
        } else {
            // Can't advance by the full polling packet length, so we are done
            break;
        }
    }
}

/// Formats the SourceCapabilities into a human-readable string.
///
/// # Arguments
/// * `caps` - A reference to the `SourceCapabilities` struct to format.
///
/// # Returns
/// A `String` containing the formatted capabilities list.

pub fn format_source_capabilities(caps: &SourceCapabilities) -> String {
    let mut output = String::new();

    writeln!(&mut output, "Source Power Capabilities:").unwrap();

    writeln!(
        &mut output,
        "  Flags: DRP: {}, Unconstrained: {}, USB Comm: {}, USB Suspend: {}, EPR Capable: {}",
        caps.dual_role_power(),
        caps.unconstrained_power(),
        caps.vsafe_5v().map_or(false, |p| p.usb_communications_capable()),
        caps.usb_suspend_supported(),
        caps.epr_mode_capable()
    )
    .unwrap();

    for (i, pdo) in caps.pdos().iter().enumerate() {
        let pdo_index = i + 1;

        // Use raw value methods and apply scaling factors manually.
        let line = match pdo {
            PowerDataObject::FixedSupply(p) => {
                let voltage = p.raw_voltage() as f32 * 50.0 / 1000.0;
                let current = p.raw_max_current() as f32 * 10.0 / 1000.0;
                format!("Fixed:       {:.2} V @ {:.2} A", voltage, current)
            }
            PowerDataObject::VariableSupply(p) => {
                let min_v = p.raw_min_voltage() as f32 * 50.0 / 1000.0;
                let max_v = p.raw_max_voltage() as f32 * 50.0 / 1000.0;
                let current = p.raw_max_current() as f32 * 10.0 / 1000.0;
                format!("Variable:    {:.2} - {:.2} V @ {:.2} A", min_v, max_v, current)
            }
            PowerDataObject::Battery(p) => {
                let min_v = p.raw_min_voltage() as f32 * 50.0 / 1000.0;
                let max_v = p.raw_max_voltage() as f32 * 50.0 / 1000.0;
                let power = p.raw_max_power() as f32 * 250.0 / 1000.0;
                format!("Battery:     {:.2} - {:.2} V @ {:.2} W", min_v, max_v, power)
            }
            PowerDataObject::Augmented(augmented) => match augmented {
                Augmented::Spr(p) => {
                    let min_v = p.raw_min_voltage() as f32 * 100.0 / 1000.0;
                    let max_v = p.raw_max_voltage() as f32 * 100.0 / 1000.0;
                    let current = p.raw_max_current() as f32 * 50.0 / 1000.0;
                    let mut pps_str = format!("PPS:         {:.2} - {:.2} V @ {:.2} A", min_v, max_v, current);
                    if p.pps_power_limited() {
                        pps_str.push_str(" (Power Limited)");
                    }
                    pps_str
                }
                Augmented::Epr(p) => {
                    let min_v = p.raw_min_voltage() as f32 * 100.0 / 1000.0;
                    let max_v = p.raw_max_voltage() as f32 * 100.0 / 1000.0;
                    let power = p.raw_pd_power() as f32; // This is already in full Watts
                    format!("AVS (EPR):   {:.2} - {:.2} V up to {:.2} W", min_v, max_v, power)
                }
                Augmented::Unknown(raw) => format!("Unknown Augmented PDO (raw: 0x{:08x})", raw),
            },
            PowerDataObject::Unknown(raw) => format!("Unknown PDO (raw: 0x{:08x})", raw.0),
        };

        writeln!(&mut output, "  [{}] {}", pdo_index, line).unwrap();
    }

    output
}
