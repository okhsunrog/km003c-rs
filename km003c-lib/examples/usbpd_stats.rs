use bytes::Bytes;
use km003c_lib::packet::{Attribute, RawPacket};
use km003c_lib::pd::{parse_event_stream, EventPacket};
use std::collections::BTreeMap;

fn main() {
    let data = include_str!("../tests/extracted_pd_payloads.txt");

    let mut total_lines = 0usize;
    let mut pkt_ok = 0usize;
    let mut pd_records = 0usize;
    let mut usbpd_ok = 0usize;
    let mut usbpd_err = 0usize;

    let mut by_ndo: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_ext: BTreeMap<bool, usize> = BTreeMap::new();
    let mut fail_header: BTreeMap<String, usize> = BTreeMap::new();

    for (idx, line) in data.lines().enumerate() {
        total_lines += 1;
        let Ok(buf) = hex::decode(line) else { continue };
        let Ok(raw) = RawPacket::try_from(Bytes::from(buf)) else { continue };
        pkt_ok += 1;
        let Some(attr) = raw.get_attribute() else { continue };
        if !matches!(attr, Attribute::PdPacket | Attribute::PdStatus) { continue; }
        let payload = raw.get_payload_data();
        if payload.len() <= 12 { continue; }
        let stream = &payload.as_ref()[12..];
        let Ok(events) = parse_event_stream(stream) else { continue };
        for ev in events {
            if let EventPacket::PdMessage(pd, _ts) = ev {
                pd_records += 1;
                let bytes = pd.pd_bytes.as_ref();
                if bytes.len() < 2 { continue; }
                let hdr = u16::from_le_bytes([bytes[0], bytes[1]]);
                let ndo = ((hdr >> 12) & 0x07) as usize;
                let ext = (hdr & 0x8000) != 0;
                *by_ndo.entry(format!("ndo={}", ndo)).or_default() += 1;
                *by_ext.entry(ext).or_default() += 1;
                match usbpd::protocol_layer::message::Message::from_bytes(bytes) {
                    Ok(_m) => {
                        usbpd_ok += 1;
                    }
                    Err(e) => {
                        usbpd_err += 1;
                        *fail_header.entry(format!("hdr=0x{hdr:04x} err={e:?}")).or_default() += 1;
                    }
                }
            }
        }
    }

    println!("Lines:          {}", total_lines);
    println!("Packets parsed: {}", pkt_ok);
    println!("PD records:     {}", pd_records);
    println!("usbpd OK:       {}", usbpd_ok);
    println!("usbpd ERR:      {}", usbpd_err);
    if pd_records > 0 {
        let rate = (usbpd_ok as f64) / (pd_records as f64) * 100.0;
        println!("usbpd success:  {:.2}%", rate);
    }

    println!("\nBy NDO (data objects):");
    for (k, v) in by_ndo.iter() { println!("  {:>8}: {}", k, v); }
    println!("\nExtended flag:");
    for (k, v) in by_ext.iter() { println!("  {:>8}: {}", if *k {"extended"} else {"base"}, v); }
    if !fail_header.is_empty() {
        println!("\nTop failures (by PD header/error):");
        for (k, v) in fail_header.iter() { println!("  {} -> {}", k, v); }
    }
}

