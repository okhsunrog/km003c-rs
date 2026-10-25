//! Passive decoding of cable identity VDOs observed on SOP' and SOP'' traffic.

use std::fmt;

use usbpd::protocol_layer::message::header::SpecificationRevision;

/// Cable product type reported by the SOP' ID Header VDO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdCableKind {
    Passive,
    Active,
}

impl fmt::Display for PdCableKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Passive => "Passive",
            Self::Active => "Active",
        })
    }
}

/// Connector at the far end of the cable assembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdCableConnector {
    UsbTypeC,
    Captive,
    Reserved(u8),
}

impl fmt::Display for PdCableConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UsbTypeC => f.write_str("USB Type-C"),
            Self::Captive => f.write_str("Captive"),
            Self::Reserved(value) => write!(f, "Reserved ({value:#04b})"),
        }
    }
}

/// Maximum VBUS current advertised by a cable VDO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdCableCurrent {
    Amps3,
    Amps5,
    Reserved(u8),
}

impl fmt::Display for PdCableCurrent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Amps3 => f.write_str("3 A"),
            Self::Amps5 => f.write_str("5 A"),
            Self::Reserved(value) => write!(f, "Reserved ({value:#04b})"),
        }
    }
}

/// Maximum VBUS voltage advertised by a PD 3.x cable VDO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdCableVoltage {
    Volts20,
    Volts30,
    Volts40,
    Volts50,
}

impl PdCableVoltage {
    pub const fn volts(self) -> u8 {
        match self {
            Self::Volts20 => 20,
            Self::Volts30 => 30,
            Self::Volts40 => 40,
            Self::Volts50 => 50,
        }
    }
}

impl fmt::Display for PdCableVoltage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} V", self.volts())
    }
}

/// Highest USB signaling generation advertised by the cable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdCableSpeed {
    Usb2Only,
    Usb32Gen1,
    Usb32Usb4Gen2,
    Usb4Gen3,
    Usb4Gen4,
    Reserved(u8),
}

impl fmt::Display for PdCableSpeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usb2Only => f.write_str("USB 2.0 only"),
            Self::Usb32Gen1 => f.write_str("USB 3.2 Gen 1"),
            Self::Usb32Usb4Gen2 => f.write_str("USB 3.2 / USB4 Gen 2"),
            Self::Usb4Gen3 => f.write_str("USB4 Gen 3 (40 Gbps)"),
            Self::Usb4Gen4 => f.write_str("USB4 Gen 4 (80 Gbps)"),
            Self::Reserved(value) => write!(f, "Reserved ({value:#05b})"),
        }
    }
}

/// Approximate latency/length class advertised by a cable VDO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdCableLatency {
    LessThan10Ns,
    Nanoseconds10To20,
    Nanoseconds20To30,
    Nanoseconds30To40,
    Nanoseconds40To50,
    Nanoseconds50To60,
    Nanoseconds60To70,
    GreaterThan70Ns,
    Reserved(u8),
}

impl fmt::Display for PdCableLatency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LessThan10Ns => f.write_str("<10 ns (~1 m)"),
            Self::Nanoseconds10To20 => f.write_str("10-20 ns (~2 m)"),
            Self::Nanoseconds20To30 => f.write_str("20-30 ns (~3 m)"),
            Self::Nanoseconds30To40 => f.write_str("30-40 ns (~4 m)"),
            Self::Nanoseconds40To50 => f.write_str("40-50 ns (~5 m)"),
            Self::Nanoseconds50To60 => f.write_str("50-60 ns (~6 m)"),
            Self::Nanoseconds60To70 => f.write_str("60-70 ns (~7 m)"),
            Self::GreaterThan70Ns => f.write_str(">70 ns (>~7 m)"),
            Self::Reserved(value) => write!(f, "Reserved ({value:#06b})"),
        }
    }
}

/// VCONN termination behavior reported by the cable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdCableTermination {
    VconnNotRequired,
    VconnRequired,
    OneEndActive,
    BothEndsActive,
    Reserved(u8),
}

impl fmt::Display for PdCableTermination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VconnNotRequired => f.write_str("VCONN not required"),
            Self::VconnRequired => f.write_str("VCONN required"),
            Self::OneEndActive => f.write_str("One end active"),
            Self::BothEndsActive => f.write_str("Both ends active"),
            Self::Reserved(value) => write!(f, "Reserved ({value:#04b})"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdCableMedium {
    Copper,
    Optical,
}

impl fmt::Display for PdCableMedium {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Copper => "Copper",
            Self::Optical => "Optical",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdCableActiveElement {
    Redriver,
    Retimer,
}

impl fmt::Display for PdCableActiveElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Redriver => "Redriver",
            Self::Retimer => "Retimer",
        })
    }
}

/// Additional information contained in Active Cable VDO 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PdActiveCableDetails {
    pub maximum_operating_temperature_c: u8,
    pub shutdown_temperature_c: u8,
    pub medium: PdCableMedium,
    pub active_element: PdCableActiveElement,
    pub usb4_supported: bool,
    pub usb2_supported: bool,
    pub usb32_supported: bool,
    pub lanes: u8,
    pub optically_isolated: bool,
}

/// Identity and capabilities returned by a cable-plug Discover Identity ACK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdCableIdentity {
    /// Raw KM003C SOP selector so unknown encodings remain lossless.
    pub sop: u8,
    pub kind: PdCableKind,
    pub vendor_id: u16,
    pub xid: u32,
    pub product_id: u16,
    pub device_bcd: u16,
    pub hardware_version: u8,
    pub firmware_version: u8,
    /// Cable VDO version encoded as 1.x; absent for PD 2.0 cable VDOs.
    pub vdo_version: Option<u8>,
    pub connector: PdCableConnector,
    /// Absent for PD 2.0 cable VDOs, which predate EPR.
    pub epr_capable: Option<bool>,
    pub latency: PdCableLatency,
    pub termination: PdCableTermination,
    /// Absent for PD 2.0 cable VDOs.
    pub maximum_vbus_voltage: Option<PdCableVoltage>,
    pub vbus_current: PdCableCurrent,
    pub highest_speed: PdCableSpeed,
    pub vbus_through_cable: Option<bool>,
    pub sop_double_prime_present: Option<bool>,
    pub sbu_supported: Option<bool>,
    pub sbu_active: Option<bool>,
    pub active_details: Option<PdActiveCableDetails>,
    pub raw_vdo1: u32,
    pub raw_vdo2: Option<u32>,
}

pub(crate) fn decode_cable_identity(sop: u8, revision: SpecificationRevision, data: &[u32]) -> Option<PdCableIdentity> {
    let id_header = *data.first()?;
    let kind = match ((id_header >> 27) & 0x7) as u8 {
        3 => PdCableKind::Passive,
        4 => PdCableKind::Active,
        _ => return None,
    };
    let xid = *data.get(1)?;
    let product = *data.get(2)?;
    let vdo1 = *data.get(3)?;
    let pd3 = matches!(revision, SpecificationRevision::R3_X);
    let connector = match ((vdo1 >> 18) & 0x3) as u8 {
        2 => PdCableConnector::UsbTypeC,
        3 => PdCableConnector::Captive,
        value => PdCableConnector::Reserved(value),
    };
    // PD 2.0 reserves bit 16 and uses a three-bit latency field. PD 3.x
    // extends that field to four bits.
    let latency_bits = if pd3 { (vdo1 >> 13) & 0xf } else { (vdo1 >> 13) & 0x7 } as u8;
    let latency = match latency_bits {
        1 => PdCableLatency::LessThan10Ns,
        2 => PdCableLatency::Nanoseconds10To20,
        3 => PdCableLatency::Nanoseconds20To30,
        4 => PdCableLatency::Nanoseconds30To40,
        5 => PdCableLatency::Nanoseconds40To50,
        6 => PdCableLatency::Nanoseconds50To60,
        7 => PdCableLatency::Nanoseconds60To70,
        8 => PdCableLatency::GreaterThan70Ns,
        value => PdCableLatency::Reserved(value),
    };
    let termination_bits = ((vdo1 >> 11) & 0x3) as u8;
    let termination = match (kind, termination_bits) {
        (PdCableKind::Passive, 0) => PdCableTermination::VconnNotRequired,
        (PdCableKind::Passive, 1) => PdCableTermination::VconnRequired,
        (PdCableKind::Active, 2) => PdCableTermination::OneEndActive,
        (PdCableKind::Active, 3) => PdCableTermination::BothEndsActive,
        (_, value) => PdCableTermination::Reserved(value),
    };
    let vbus_current = match ((vdo1 >> 5) & 0x3) as u8 {
        1 => PdCableCurrent::Amps3,
        2 => PdCableCurrent::Amps5,
        value => PdCableCurrent::Reserved(value),
    };
    let speed_bits = (vdo1 & 0x7) as u8;
    let highest_speed = match (pd3, speed_bits) {
        (_, 0) => PdCableSpeed::Usb2Only,
        (_, 1) => PdCableSpeed::Usb32Gen1,
        (_, 2) => PdCableSpeed::Usb32Usb4Gen2,
        (true, 3) => PdCableSpeed::Usb4Gen3,
        (true, 4) => PdCableSpeed::Usb4Gen4,
        (_, value) => PdCableSpeed::Reserved(value),
    };
    let maximum_vbus_voltage = pd3.then_some(match (vdo1 >> 9) & 0x3 {
        0 => PdCableVoltage::Volts20,
        1 => PdCableVoltage::Volts30,
        2 => PdCableVoltage::Volts40,
        _ => PdCableVoltage::Volts50,
    });
    // Active Cable VDO 2 was introduced with the PD 3.x cable VDO layout.
    // Do not reinterpret an unexpected fifth PD 2.0 VDO using that format.
    let raw_vdo2 = (kind == PdCableKind::Active && pd3)
        .then_some(data.get(4).copied())
        .flatten();
    let active_details = raw_vdo2.map(|vdo2| PdActiveCableDetails {
        maximum_operating_temperature_c: (vdo2 >> 24) as u8,
        shutdown_temperature_c: (vdo2 >> 16) as u8,
        medium: if vdo2 & (1 << 10) == 0 {
            PdCableMedium::Copper
        } else {
            PdCableMedium::Optical
        },
        active_element: if vdo2 & (1 << 9) == 0 {
            PdCableActiveElement::Redriver
        } else {
            PdCableActiveElement::Retimer
        },
        usb4_supported: vdo2 & (1 << 8) == 0,
        usb2_supported: vdo2 & (1 << 5) == 0,
        usb32_supported: vdo2 & (1 << 4) == 0,
        lanes: if vdo2 & (1 << 3) == 0 { 1 } else { 2 },
        optically_isolated: vdo2 & (1 << 2) != 0,
    });

    Some(PdCableIdentity {
        sop,
        kind,
        vendor_id: id_header as u16,
        xid,
        product_id: (product >> 16) as u16,
        device_bcd: product as u16,
        hardware_version: (vdo1 >> 28) as u8,
        firmware_version: ((vdo1 >> 24) & 0xf) as u8,
        vdo_version: pd3.then_some(((vdo1 >> 21) & 0x7) as u8),
        connector,
        epr_capable: pd3.then_some(vdo1 & (1 << 17) != 0),
        latency,
        termination,
        maximum_vbus_voltage,
        vbus_current,
        highest_speed,
        vbus_through_cable: (kind == PdCableKind::Active || !pd3).then_some(vdo1 & (1 << 4) != 0),
        sop_double_prime_present: (kind == PdCableKind::Active || !pd3).then_some(vdo1 & (1 << 3) != 0),
        sbu_supported: (kind == PdCableKind::Active && pd3).then_some(vdo1 & (1 << 8) == 0),
        sbu_active: (kind == PdCableKind::Active && pd3).then_some(vdo1 & (1 << 7) != 0),
        active_details,
        raw_vdo1: vdo1,
        raw_vdo2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_pd3_passive_cable_vdo() {
        let cable = decode_cable_identity(
            1,
            SpecificationRevision::R3_X,
            &[0x1800_413c, 0x1122_3344, 0x1234_0100, 0x120a_2644],
        )
        .unwrap();

        assert_eq!(cable.kind, PdCableKind::Passive);
        assert_eq!(cable.vendor_id, 0x413c);
        assert_eq!(cable.xid, 0x1122_3344);
        assert_eq!(cable.product_id, 0x1234);
        assert_eq!(cable.connector, PdCableConnector::UsbTypeC);
        assert_eq!(cable.epr_capable, Some(true));
        assert_eq!(cable.maximum_vbus_voltage, Some(PdCableVoltage::Volts50));
        assert_eq!(cable.vbus_current, PdCableCurrent::Amps5);
        assert_eq!(cable.highest_speed, PdCableSpeed::Usb4Gen4);
        assert_eq!(cable.active_details, None);
    }

    #[test]
    fn decodes_pd3_active_cable_vdos() {
        let cable = decode_cable_identity(
            2,
            SpecificationRevision::R3_X,
            &[0x2000_413c, 0x1122_3344, 0x1234_0100, 0x126a_36d3, 0x3c50_0249],
        )
        .unwrap();

        assert_eq!(cable.kind, PdCableKind::Active);
        assert_eq!(cable.vdo_version, Some(3));
        assert_eq!(cable.termination, PdCableTermination::OneEndActive);
        assert_eq!(cable.sbu_supported, Some(true));
        assert_eq!(cable.sbu_active, Some(true));
        let active = cable.active_details.unwrap();
        assert_eq!(active.medium, PdCableMedium::Copper);
        assert_eq!(active.active_element, PdCableActiveElement::Retimer);
        assert!(active.usb4_supported);
        assert_eq!(active.lanes, 2);
        assert_eq!(active.maximum_operating_temperature_c, 60);
        assert_eq!(active.shutdown_temperature_c, 80);
    }

    #[test]
    fn keeps_pd2_reserved_latency_bit_and_extra_vdo_out_of_pd3_fields() {
        let cable = decode_cable_identity(
            1,
            SpecificationRevision::R2_0,
            &[0x2000_413c, 0x1122_3344, 0x1234_0100, 0x1209_2052, 0xffff_ffff],
        )
        .unwrap();

        assert_eq!(cable.kind, PdCableKind::Active);
        assert_eq!(cable.latency, PdCableLatency::LessThan10Ns);
        assert_eq!(cable.vdo_version, None);
        assert_eq!(cable.maximum_vbus_voltage, None);
        assert_eq!(cable.raw_vdo2, None);
        assert_eq!(cable.active_details, None);
    }
}
