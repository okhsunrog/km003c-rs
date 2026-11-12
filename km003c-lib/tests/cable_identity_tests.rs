//! Cable identity decoding from Discover Identity ACKs a KM003C captured on
//! SOP' while its USB-C eMarker module queried the seated cable (firmware
//! 1.9.5, `km003c pd capture --raw`).

use km003c_lib::uom::si::electric_current::ampere;
use km003c_lib::uom::si::electric_potential::volt;
use km003c_lib::{CableIdentity, CableProductType, UsbHighestSpeed};

/// `RAW[22]: 8F 51 41 A0 00 FF 00 00 00 18 00 00 00 00 00 00 00 00 42 40 08 00`
/// An uncertified 5 A, USB 3.2 Gen 2 / USB4 Gen 2 passive cable without a vendor ID.
const UNBRANDED_CABLE: &str = "8f5141a000ff00000018000000000000000042400800";

/// `RAW[22]: 8F 51 41 A0 00 FF 3E 16 00 18 00 01 00 00 B6 02 E9 0C 41 48 08 00`
/// A 5 A, USB 3.2 Gen 1 passive cable from vendor 0x163E.
const BRANDED_CABLE: &str = "8f5141a000ff3e16001800010000b602e90c41480800";

/// `RAW[6]: 8F 10 01 A0 00 FF`, the tester's own Discover Identity request.
const DISCOVER_IDENTITY_REQUEST: &str = "8f1041a000ff";

fn wire(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap()
}

#[test]
fn decodes_an_unbranded_passive_cable() {
    let identity = CableIdentity::from_wire_message(1, &wire(UNBRANDED_CABLE)).unwrap();

    assert_eq!(identity.sop, 1);
    assert_eq!(identity.product_type, CableProductType::PassiveCable);
    assert_eq!(identity.vendor_id, 0);
    assert_eq!(identity.xid, 0);
    assert_eq!(identity.product_id, 0);
    assert_eq!(identity.words, vec![0xFF00_A041, 0x1800_0000, 0, 0, 0x0008_4042]);

    let cable = identity.cable.unwrap();
    assert_eq!(cable.raw, 0x0008_4042);
    assert_eq!(cable.highest_speed, UsbHighestSpeed::Usb32Gen2);
    assert_eq!(cable.max_vbus_current.unwrap().get::<ampere>(), 5.0);
    assert_eq!(cable.max_vbus_voltage.get::<volt>(), 20.0);
    assert_eq!(cable.latency_code, 2);
    assert_eq!(cable.epr_mode_capable, Some(false));
    assert_eq!((cable.hardware_version, cable.firmware_version), (0, 0));
}

#[test]
fn decodes_a_branded_passive_cable() {
    let identity = CableIdentity::from_wire_message(1, &wire(BRANDED_CABLE)).unwrap();

    assert_eq!(identity.product_type, CableProductType::PassiveCable);
    assert_eq!(identity.vendor_id, 0x163E);
    assert_eq!(identity.xid, 0x0000_0100);
    assert_eq!(identity.product_id, 0x0CE9);
    assert_eq!(identity.bcd_device, 0x02B6);

    let cable = identity.cable.unwrap();
    assert_eq!(cable.raw, 0x0008_4841);
    assert_eq!(cable.highest_speed, UsbHighestSpeed::Usb32Gen1);
    assert_eq!(cable.max_vbus_current.unwrap().get::<ampere>(), 5.0);
    assert_eq!(cable.epr_mode_capable, Some(false));
    assert_eq!(
        identity.to_string(),
        "Passive cable, VID 0x163E, PID 0x0CE9: USB 3.2 Gen 1 (5 Gb/s), 5 A, 20 V max, latency code 2, EPR no, HW 0 FW 0"
    );
    assert_eq!(identity.describe().len(), 2);
}

#[test]
fn decodes_the_same_ack_from_vdm_words() {
    let from_words =
        CableIdentity::from_vdm_words(2, &[0xFF00_A041, 0x1800_163E, 0x100, 0x0CE9_02B6, 0x0008_4841]).unwrap();
    let from_wire = CableIdentity::from_wire_message(2, &wire(BRANDED_CABLE)).unwrap();
    assert_eq!(from_words, from_wire);
}

#[test]
fn an_active_cable_uses_its_own_vdo_layout() {
    // Active Cable VDO 1: speed code 3, 5 A, max voltage bits 11:10 = 1 (30 V),
    // latency bits 17:14 = 3; bit 17 is part of the latency field here.
    let vdo = 0b11 | (2 << 5) | (1 << 10) | (3 << 14);
    let identity = CableIdentity::from_vdm_words(1, &[0xFF00_A041, 4 << 27 | 0x1234, 0, 0, vdo]).unwrap();

    assert_eq!(identity.product_type, CableProductType::ActiveCable);
    let cable = identity.cable.unwrap();
    assert_eq!(cable.highest_speed, UsbHighestSpeed::Usb4Gen3);
    assert_eq!(cable.max_vbus_voltage.get::<volt>(), 30.0);
    assert_eq!(cable.latency_code, 3);
    assert_eq!(cable.epr_mode_capable, None);
}

#[test]
fn epr_and_reserved_fields_are_read_from_a_passive_vdo() {
    let vdo = 0b100 | (3 << 5) | (3 << 9) | (1 << 17) | (0xA << 24) | (0xB << 28);
    let identity = CableIdentity::from_vdm_words(1, &[0xFF00_A041, 3 << 27, 0, 0, vdo]).unwrap();
    let cable = identity.cable.unwrap();

    assert_eq!(cable.highest_speed, UsbHighestSpeed::Usb4Gen4);
    assert_eq!(cable.max_vbus_current, None, "code 3 is reserved");
    assert_eq!(cable.max_vbus_voltage.get::<volt>(), 50.0);
    assert_eq!(cable.epr_mode_capable, Some(true));
    assert_eq!((cable.hardware_version, cable.firmware_version), (0xB, 0xA));
    assert_eq!(
        CableIdentity::from_vdm_words(1, &[0xFF00_A041, 7 << 27, 0, 0, vdo])
            .unwrap()
            .product_type,
        CableProductType::Other(7)
    );
}

#[test]
fn a_vconn_powered_device_has_no_cable_vdo() {
    let identity =
        CableIdentity::from_vdm_words(1, &[0xFF00_A041, 6 << 27 | 0x0001, 0, 0x4321_0000, 0xFFFF_FFFF]).unwrap();
    assert_eq!(identity.product_type, CableProductType::VconnPoweredDevice);
    assert_eq!(identity.product_id, 0x4321);
    assert!(identity.cable.is_none());
}

#[test]
fn other_messages_are_not_cable_identities() {
    let ack = wire(BRANDED_CABLE);
    // The request, a GoodCRC, an SOP answer, and truncated or non-VDM data.
    assert!(CableIdentity::from_wire_message(1, &wire(DISCOVER_IDENTITY_REQUEST)).is_none());
    assert!(CableIdentity::from_wire_message(1, &[0x41, 0x00]).is_none());
    assert!(CableIdentity::from_wire_message(0, &ack).is_none());
    assert!(CableIdentity::from_wire_message(1, &ack[..ack.len() - 1]).is_none());
    assert!(CableIdentity::from_wire_message(1, &[]).is_none());
    assert!(
        CableIdentity::from_wire_message(
            1,
            &hex::decode("a1612c9101082cd102002cc103002cb10400454106003c21dcc0").unwrap()
        )
        .is_none()
    );
    // A NAK, an unstructured VDM, a vendor SVID, and a Discover SVIDs ACK.
    assert!(CableIdentity::from_vdm_words(1, &[0xFF00_A081, 0, 0, 0, 0]).is_none());
    assert!(CableIdentity::from_vdm_words(1, &[0xFF00_2041, 0, 0, 0, 0]).is_none());
    assert!(CableIdentity::from_vdm_words(1, &[0x163E_A041, 0, 0, 0, 0]).is_none());
    assert!(CableIdentity::from_vdm_words(1, &[0xFF00_A042, 0, 0, 0, 0]).is_none());
    // Too few objects for an identity.
    assert!(CableIdentity::from_vdm_words(1, &[0xFF00_A041, 0, 0]).is_none());
}
