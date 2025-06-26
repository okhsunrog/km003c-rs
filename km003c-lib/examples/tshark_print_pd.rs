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
    let filename = "pd_analisys/pd_capture_new.9.pcapng";
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

fn parse_km003c_stream(mut stream: &[u8]) {
    const WRAPPER_LEN: usize = 6;

    println!("\n==================================================");
    println!("[STREAM START] Parsing new USB payload ({} bytes): {}", stream.len(), hex::encode(stream));
    println!("==================================================");

    let mut chunk_index = 0;
    while !stream.is_empty() {
        println!("\n[CHUNK {}] Remaining buffer ({} bytes): {}", chunk_index, stream.len(), hex::encode(stream));

        if stream.len() < WRAPPER_LEN {
            println!("[STREAM END] Remaining data is too short ({len} bytes) to be a valid packet. Stopping.", len=stream.len());
            break;
        }

        // Decide how to parse based on the first byte of the current chunk
        let first_byte = stream[0];
        match first_byte {
            // Case 1: Connection Status Event (Attach/Detach)
            0x45 => {
                println!("[PARSE DECISION] First byte is 0x45. Parsing as Connection Event.");
                let event_packet = &stream[..WRAPPER_LEN];
                
                // Decode the event data byte (the last byte of the 6-byte packet)
                let event_data = event_packet[5];
                let cc_pin = (event_data >> 4) & 0x0F;
                let action = event_data & 0x0F;

                let cc_str = match cc_pin { 1 => "CC1", 2 => "CC2", _ => "Unknown CC" };
                let action_str = match action { 1 => "Attach", 2 => "Detach", _ => "Unknown Action" };

                println!("[EVENT] Raw: {}", hex::encode(event_packet));
                println!("[EVENT] Parsed: {}: {}", action_str, cc_str);
                
                // Advance the stream by the known, fixed length of this packet type
                stream = &stream[WRAPPER_LEN..];
            }

            // Case 2: PD Message (wrapped)
            0x80..=0x9F => {
                println!("[PARSE DECISION] First byte is 0x{:02X}. Parsing as wrapped PD message.", first_byte);
                
                let wrapper = &stream[..WRAPPER_LEN];
                let payload = &stream[WRAPPER_LEN..];

                // Decode the direction from the first byte of the wrapper
                let direction_str = if (wrapper[0] & 0x04) != 0 { "SRC -> SNK" } else { "SRC <- SNK" };

                if payload.len() < 2 {
                    println!("[WARN] PD message chunk has wrapper but not enough data for a PD header (needs 2, has {}). Stopping.", payload.len());
                    break;
                }

                // Dynamically calculate length from the PD header itself
                let pd_header_bytes: [u8; 2] = payload[..2].try_into().unwrap();
                let pd_header_val = u16::from_le_bytes(pd_header_bytes);
                let num_objects = ((pd_header_val >> 12) & 0x07) as usize;
                let pd_message_len = 2 + num_objects * 4;
                let total_chunk_len = WRAPPER_LEN + pd_message_len;

                println!("[PD DECODE] PD Header: 0x{:04X}. Num Objects: {}, Calculated PD Msg Len: {} bytes.", pd_header_val, num_objects, pd_message_len);
                
                if stream.len() < total_chunk_len {
                    println!("[WARN] Stream is truncated. Needed {} bytes for full message, have {}. Stopping.", total_chunk_len, stream.len());
                    break;
                }

                let pd_message_bytes = &payload[..pd_message_len];
                let full_chunk_bytes = &stream[..total_chunk_len];

                println!("[PD MSG] Direction: {}", direction_str);
                println!("[PD MSG] Raw chunk ({} bytes): {}", total_chunk_len, hex::encode(full_chunk_bytes));
                println!("[PD MSG]   -> Wrapper: {}", hex::encode(wrapper));
                println!("[PD MSG]   -> PD Data: {}", hex::encode(pd_message_bytes));
                
                // Parse using the external usbpd crate
                let message = Message::from_bytes(pd_message_bytes);

                // You can uncomment your pretty-printing logic here if you want
                if let Some(usbpd::protocol_layer::message::Data::SourceCapabilities(caps)) = &message.data {
                    let formatted_caps = format_source_capabilities(caps);
                    println!("  -> Parsed:\n{}\n", formatted_caps);
                } else {
                    println!("  -> Parsed: {:?}\n", message);
                }
                
                // Advance the stream by the accurately calculated length
                stream = &stream[total_chunk_len..];
            }

            // Case 3: Unknown packet type
            _ => {
                println!("[FATAL] Unrecognized packet type with first byte 0x{:02X}. Cannot determine length. Stopping parse of this USB payload.", first_byte);
                // The only safe action is to stop. Advancing by a guessed amount is wrong.
                break;
            }
        }
        chunk_index += 1;
    }
    println!("[STREAM END] Finished parsing USB payload.");
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
