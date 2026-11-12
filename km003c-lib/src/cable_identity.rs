//! The identity a USB-C cable's e-marker reports.
//!
//! A DFP or VCONN source learns about the cable in its receptacle with a
//! Discover Identity request on SOP' (the near plug) or SOP'' (the far plug).
//! The e-marker answers with an ACK that carries an ID Header, a Cert Stat
//! VDO, a Product VDO and, for a cable, a Cable VDO (USB PD 3.x, section 6.4.4).
//! [`CableIdentity`] decodes that ACK from the wire bytes the KM003C captures.
//!
//! The KM003C sends such a request itself when its on-screen module
//! *Application > Modules > USB-C eMarker* runs with a cable seated in the
//! socket, so a host reading the PD stream sees both the request and the
//! answer (observed with firmware 1.9.5).
//!
//! The field positions follow the USB PD R3.1 Passive Cable VDO (Table 6-42)
//! and Active Cable VDO 1 (Table 6-43). The two layouts differ, so the Cable
//! VDO is decoded according to the product type in the ID Header.

use std::fmt;

use uom::si::electric_current::ampere;
use uom::si::electric_potential::volt;
use uom::si::f64::{ElectricCurrent, ElectricPotential};

/// USB PD data message type `Vendor_Defined`.
const VENDOR_DEFINED_MESSAGE_TYPE: u16 = 0x0F;
/// The USB PD standard ID, carried in a structured VDM header's SVID field.
const PD_STANDARD_ID: u32 = 0xFF00;
/// Structured VDM command `Discover Identity`.
const DISCOVER_IDENTITY_COMMAND: u32 = 1;
/// Structured VDM command type `Responder ACK`.
const RESPONDER_ACK: u32 = 1;

/// What answered the Discover Identity request, from the ID Header's cable
/// plug product type (bits 29:27).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CableProductType {
    /// A passive cable: the e-marker is the only electronics in it.
    PassiveCable,
    /// An active cable with signal conditioning in the plugs.
    ActiveCable,
    /// A VCONN-powered USB device.
    VconnPoweredDevice,
    /// A value the specification does not assign to a cable plug.
    Other(u8),
}

impl CableProductType {
    const fn from_code(code: u8) -> Self {
        match code {
            3 => Self::PassiveCable,
            4 => Self::ActiveCable,
            6 => Self::VconnPoweredDevice,
            other => Self::Other(other),
        }
    }

    /// Whether the ACK carries a Cable VDO after the Product VDO.
    pub const fn is_cable(self) -> bool {
        matches!(self, Self::PassiveCable | Self::ActiveCable)
    }
}

impl fmt::Display for CableProductType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PassiveCable => f.write_str("Passive cable"),
            Self::ActiveCable => f.write_str("Active cable"),
            Self::VconnPoweredDevice => f.write_str("VCONN-powered device"),
            Self::Other(code) => write!(f, "Product type {code}"),
        }
    }
}

/// The highest USB signalling the cable supports (Cable VDO bits 2:0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbHighestSpeed {
    /// USB 2.0 only.
    Usb2,
    /// USB 3.2 Gen 1, 5 Gb/s.
    Usb32Gen1,
    /// USB 3.2 Gen 2 at 10 Gb/s and USB4 Gen 2 at 20 Gb/s. The KM003C shows
    /// this code as "USB 3.2/USB4 Gen2 (10Gb/20Gb)".
    Usb32Gen2,
    /// USB4 Gen 3, 40 Gb/s.
    Usb4Gen3,
    /// USB4 Gen 4, 80 Gb/s.
    Usb4Gen4,
    /// A reserved code.
    Reserved(u8),
}

impl UsbHighestSpeed {
    const fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Usb2,
            1 => Self::Usb32Gen1,
            2 => Self::Usb32Gen2,
            3 => Self::Usb4Gen3,
            4 => Self::Usb4Gen4,
            other => Self::Reserved(other),
        }
    }
}

impl fmt::Display for UsbHighestSpeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usb2 => f.write_str("USB 2.0 (480 Mb/s)"),
            Self::Usb32Gen1 => f.write_str("USB 3.2 Gen 1 (5 Gb/s)"),
            Self::Usb32Gen2 => f.write_str("USB 3.2 Gen 2 / USB4 Gen 2 (10/20 Gb/s)"),
            Self::Usb4Gen3 => f.write_str("USB4 Gen 3 (40 Gb/s)"),
            Self::Usb4Gen4 => f.write_str("USB4 Gen 4 (80 Gb/s)"),
            Self::Reserved(code) => write!(f, "Reserved speed code {code}"),
        }
    }
}

/// The electrical ratings in a Passive Cable VDO or Active Cable VDO 1.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CableVdo {
    /// The word as sent.
    pub raw: u32,
    /// Hardware version assigned by the vendor (bits 31:28).
    pub hardware_version: u8,
    /// Firmware version assigned by the vendor (bits 27:24).
    pub firmware_version: u8,
    /// The highest USB signalling the cable supports.
    pub highest_speed: UsbHighestSpeed,
    /// The VBUS current the cable is rated for: 3 A or 5 A. `None` when the
    /// field is zero (VBUS not carried, or not stated) or reserved.
    pub max_vbus_current: Option<ElectricCurrent>,
    /// The highest VBUS voltage the cable is rated for: 20, 30, 40 or 50 V.
    pub max_vbus_voltage: ElectricPotential,
    /// Cable latency code: 1 is under 10 ns (about 1 m), each step adds 10 ns
    /// (about 1 m), 8 is over 70 ns.
    pub latency_code: u8,
    /// Whether the cable supports EPR mode (bit 17 of the Passive Cable VDO,
    /// USB PD 3.1). `None` for an active cable, where this word has no such
    /// bit.
    pub epr_mode_capable: Option<bool>,
}

impl CableVdo {
    fn decode(raw: u32, product_type: CableProductType) -> Self {
        let bits = |low: u32, width: u32| (raw >> low) & ((1 << width) - 1);
        // The passive and active layouts place the voltage and latency
        // fields two bits apart; the active layout uses bits 3 and 4 for
        // SOP'' presence and VBUS through cable.
        let (voltage_low, latency_low) = match product_type {
            CableProductType::ActiveCable => (10, 14),
            _ => (9, 13),
        };
        let current = match bits(5, 2) {
            1 => Some(ElectricCurrent::new::<ampere>(3.0)),
            2 => Some(ElectricCurrent::new::<ampere>(5.0)),
            _ => None,
        };
        let voltage = ElectricPotential::new::<volt>(20.0 + 10.0 * bits(voltage_low, 2) as f64);
        Self {
            raw,
            hardware_version: bits(28, 4) as u8,
            firmware_version: bits(24, 4) as u8,
            highest_speed: UsbHighestSpeed::from_code(bits(0, 3) as u8),
            max_vbus_current: current,
            max_vbus_voltage: voltage,
            latency_code: bits(latency_low, 4) as u8,
            epr_mode_capable: match product_type {
                CableProductType::ActiveCable => None,
                _ => Some(bits(17, 1) == 1),
            },
        }
    }
}

impl fmt::Display for CableVdo {
    /// One line: `USB 3.2 Gen 1 (5 Gb/s), 5 A, 20 V max, latency code 1, EPR no, HW 0 FW 0`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, ", self.highest_speed)?;
        match self.max_vbus_current {
            Some(current) => write!(f, "{:.0} A", current.get::<ampere>())?,
            None => f.write_str("current not stated")?,
        }
        write!(
            f,
            ", {:.0} V max, latency code {}",
            self.max_vbus_voltage.get::<volt>(),
            self.latency_code
        )?;
        match self.epr_mode_capable {
            Some(true) => f.write_str(", EPR yes")?,
            Some(false) => f.write_str(", EPR no")?,
            None => {}
        }
        write!(f, ", HW {} FW {}", self.hardware_version, self.firmware_version)
    }
}

/// A cable plug's answer to Discover Identity.
#[derive(Debug, Clone, PartialEq)]
pub struct CableIdentity {
    /// Which plug answered: 1 for SOP', 2 for SOP''.
    pub sop: u8,
    pub product_type: CableProductType,
    /// USB-IF vendor ID (ID Header bits 15:0).
    pub vendor_id: u16,
    /// USB-IF XID from the Cert Stat VDO; 0 when the product is not certified.
    pub xid: u32,
    /// Product ID (Product VDO bits 31:16).
    pub product_id: u16,
    /// Device release number in BCD (Product VDO bits 15:0).
    pub bcd_device: u16,
    /// The Cable VDO, present for passive and active cables.
    pub cable: Option<CableVdo>,
    /// Every data object of the ACK as sent, the VDM header first.
    pub words: Vec<u32>,
}

impl CableIdentity {
    /// Decode a captured wire message (2-byte header and data objects) on
    /// SOP' or SOP''. Returns `None` for any other message, including the
    /// Discover Identity request itself and port-partner answers on SOP.
    pub fn from_wire_message(sop: u8, wire_data: &[u8]) -> Option<Self> {
        let header = u16::from_le_bytes([*wire_data.first()?, *wire_data.get(1)?]);
        let extended = header & 0x8000 != 0;
        let message_type = header & 0x1F;
        let object_count = usize::from((header >> 12) & 0x7);
        if extended || message_type != VENDOR_DEFINED_MESSAGE_TYPE {
            return None;
        }
        let objects = wire_data.get(2..2 + 4 * object_count)?;
        let words = objects
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes(*word))
            .collect::<Vec<_>>();
        Self::from_vdm_words(sop, &words)
    }

    /// Decode the data objects of a `Vendor_Defined` message, the VDM header
    /// first, received on SOP' or SOP''.
    pub fn from_vdm_words(sop: u8, words: &[u32]) -> Option<Self> {
        if sop == 0 {
            return None;
        }
        let (&vdm_header, objects) = words.split_first()?;
        let structured = vdm_header & 0x8000 != 0;
        if !structured
            || vdm_header >> 16 != PD_STANDARD_ID
            || vdm_header & 0x1F != DISCOVER_IDENTITY_COMMAND
            || (vdm_header >> 6) & 0x3 != RESPONDER_ACK
        {
            return None;
        }
        let [id_header, cert_stat, product, rest @ ..] = objects else {
            return None;
        };
        let product_type = CableProductType::from_code(((id_header >> 27) & 0x7) as u8);
        let cable = match (product_type.is_cable(), rest.first()) {
            (true, Some(&vdo)) => Some(CableVdo::decode(vdo, product_type)),
            _ => None,
        };
        Some(Self {
            sop,
            product_type,
            vendor_id: (id_header & 0xFFFF) as u16,
            xid: *cert_stat,
            product_id: (product >> 16) as u16,
            bcd_device: (product & 0xFFFF) as u16,
            cable,
            words: words.to_vec(),
        })
    }

    /// Lines for display: the identity, then the cable ratings when present.
    pub fn describe(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "Discover Identity ACK: {}, VID 0x{:04X}, PID 0x{:04X}, XID 0x{:08X}",
            self.product_type, self.vendor_id, self.product_id, self.xid
        )];
        if let Some(cable) = &self.cable {
            lines.push(format!("Cable VDO 0x{:08X}: {cable}", cable.raw));
        }
        lines
    }
}

impl fmt::Display for CableIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}, VID 0x{:04X}, PID 0x{:04X}",
            self.product_type, self.vendor_id, self.product_id
        )?;
        if let Some(cable) = &self.cable {
            write!(f, ": {cable}")?;
        }
        Ok(())
    }
}
