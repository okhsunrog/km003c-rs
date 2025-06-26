use bytes::Bytes;
use km003c_lib::pd::{EventPacket, parse_event_stream};
use km003c_lib::{message::Packet, packet::RawPacket};
use rtshark::RTSharkBuilder;
use std::fmt::Write;
use usbpd::protocol_layer::message::{
    Message,
    pdo::{Augmented, PowerDataObject, SourceCapabilities},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
                        let events = parse_event_stream(&data);
                        for event in events {
                            println!("[PD EVENT] {}", event);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
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
