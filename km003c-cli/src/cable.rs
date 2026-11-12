use std::time::{Duration, Instant};

use clap::Args;
use km003c_lib::packet::{Attribute, AttributeSet};
use km003c_lib::pd::PdEventData;
use km003c_lib::uom::si::electric_current::ampere;
use km003c_lib::uom::si::electric_potential::volt;
use km003c_lib::{CableIdentity, CableProductType, KM003C, UsbHighestSpeed};
use serde_json::json;

use crate::Result;

#[derive(Debug, Args)]
pub struct CableArgs {
    /// Seconds to wait for the cable's answer.
    #[arg(short, long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout: u64,
    /// Print the identity as JSON.
    #[arg(long)]
    pub json: bool,
}

/// Wait for the seated cable's Discover Identity answer and print it.
///
/// The meter queries the cable's e-marker itself when its USB-C eMarker module
/// runs; this command only listens for the answer on the PD stream.
pub async fn identify(device: &mut KM003C, args: CableArgs) -> Result {
    device.enable_pd_monitor().await?;
    if !args.json {
        println!("Waiting up to {} seconds for a cable identity.", args.timeout);
        println!("Seat the cable in the meter's socket and run Application > Modules > USB-C eMarker on the meter.");
    }

    let identity = {
        let wait = watch_for_identity(device, Duration::from_secs(args.timeout));
        tokio::select! {
            result = wait => result,
            signal = tokio::signal::ctrl_c() => signal.map(|()| None).map_err(Into::into),
        }
    };
    // Stop the stream after a timeout, an error or Ctrl+C alike.
    let stopped = device.disable_pd_monitor().await;
    let identity = identity?;
    stopped?;

    let Some(identity) = identity else {
        return Err(format!(
            "no cable identity seen within {} seconds; is the USB-C eMarker module running with a cable seated?",
            args.timeout
        )
        .into());
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&identity_json(&identity))?);
    } else {
        print_identity(&identity);
    }
    Ok(())
}

async fn watch_for_identity(device: &mut KM003C, timeout: Duration) -> Result<Option<CableIdentity>> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let packet = device.request_data(AttributeSet::single(Attribute::PdPacket)).await?;
        if let Some(stream) = KM003C::extract_pd_events(&packet) {
            for event in &stream.events {
                if let PdEventData::PdMessage { sop, wire_data } = &event.data
                    && let Some(identity) = CableIdentity::from_wire_message(*sop, wire_data)
                {
                    return Ok(Some(identity));
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    Ok(None)
}

fn print_identity(identity: &CableIdentity) {
    println!("Cable identity (SOP{}):", identity.sop);
    println!("  Product type:  {}", identity.product_type);
    println!("  Vendor ID:     0x{:04X}", identity.vendor_id);
    println!("  Product ID:    0x{:04X}", identity.product_id);
    println!("  Device (BCD):  0x{:04X}", identity.bcd_device);
    println!("  XID:           0x{:08X}", identity.xid);
    if let Some(cable) = &identity.cable {
        println!("  Cable VDO:     0x{:08X}", cable.raw);
        println!("  USB speed:     {}", cable.highest_speed);
        match cable.max_vbus_current {
            Some(current) => println!("  VBUS current:  {:.0} A", current.get::<ampere>()),
            None => println!("  VBUS current:  not stated"),
        }
        println!("  VBUS voltage:  {:.0} V max", cable.max_vbus_voltage.get::<volt>());
        println!("  Latency code:  {}", cable.latency_code);
        match cable.epr_mode_capable {
            Some(epr) => println!("  EPR capable:   {}", if epr { "yes" } else { "no" }),
            None => println!("  EPR capable:   not in this VDO"),
        }
        println!(
            "  HW / FW:       {} / {}",
            cable.hardware_version, cable.firmware_version
        );
    }
    println!(
        "  Raw words:     {}",
        identity
            .words
            .iter()
            .map(|word| format!("0x{word:08X}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
}

fn identity_json(identity: &CableIdentity) -> serde_json::Value {
    let product_type = match identity.product_type {
        CableProductType::PassiveCable => "passive_cable",
        CableProductType::ActiveCable => "active_cable",
        CableProductType::VconnPoweredDevice => "vconn_powered_device",
        CableProductType::Other(_) => "other",
    };
    let cable = identity.cable.as_ref().map(|cable| {
        json!({
            "raw": format!("0x{:08X}", cable.raw),
            "usb_highest_speed": speed_json(cable.highest_speed),
            "usb_highest_speed_name": cable.highest_speed.to_string(),
            "max_vbus_current_a": cable.max_vbus_current.map(|current| current.get::<ampere>()),
            "max_vbus_voltage_v": cable.max_vbus_voltage.get::<volt>(),
            "latency_code": cable.latency_code,
            "epr_mode_capable": cable.epr_mode_capable,
            "hardware_version": cable.hardware_version,
            "firmware_version": cable.firmware_version,
        })
    });
    json!({
        "sop": identity.sop,
        "product_type": product_type,
        "product_type_name": identity.product_type.to_string(),
        "vendor_id": format!("0x{:04X}", identity.vendor_id),
        "product_id": format!("0x{:04X}", identity.product_id),
        "bcd_device": format!("0x{:04X}", identity.bcd_device),
        "xid": format!("0x{:08X}", identity.xid),
        "cable": cable,
        "words": identity.words.iter().map(|word| format!("0x{word:08X}")).collect::<Vec<_>>(),
    })
}

fn speed_json(speed: UsbHighestSpeed) -> serde_json::Value {
    match speed {
        UsbHighestSpeed::Usb2 => json!("usb2"),
        UsbHighestSpeed::Usb32Gen1 => json!("usb32_gen1"),
        UsbHighestSpeed::Usb32Gen2 => json!("usb32_gen2_usb4_gen2"),
        UsbHighestSpeed::Usb4Gen3 => json!("usb4_gen3"),
        UsbHighestSpeed::Usb4Gen4 => json!("usb4_gen4"),
        UsbHighestSpeed::Reserved(code) => json!(format!("reserved_{code}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_names_every_field_of_a_captured_cable() {
        let wire = hex::decode("8f5141a000ff3e16001800010000b602e90c41480800").unwrap();
        let identity = CableIdentity::from_wire_message(1, &wire).unwrap();
        let value = identity_json(&identity);

        assert_eq!(value["product_type"], "passive_cable");
        assert_eq!(value["vendor_id"], "0x163E");
        assert_eq!(value["product_id"], "0x0CE9");
        assert_eq!(value["cable"]["usb_highest_speed"], "usb32_gen1");
        assert_eq!(value["cable"]["max_vbus_current_a"], 5.0);
        assert_eq!(value["cable"]["max_vbus_voltage_v"], 20.0);
        assert_eq!(value["cable"]["epr_mode_capable"], false);
        assert_eq!(value["words"][4], "0x00084841");
        print_identity(&identity);
    }
}
