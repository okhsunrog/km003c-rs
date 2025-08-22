use km003c_lib::pd::parse_event_stream;
use rusqlite::{Connection, Result};

fn main() -> Result<()> {
    let conn = Connection::open("pd_analisys/pd_new.sqlite")?;
    let mut stmt = conn.prepare("SELECT Time, Vbus, Ibus, Raw FROM pd_table")?;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, f64>(0)?,     // Time
            row.get::<_, f64>(1)?,     // Vbus
            row.get::<_, f64>(2)?,     // Ibus
            row.get::<_, Vec<u8>>(3)?, // Raw blob
        ))
    })?;

    for row in rows {
        let (time, vbus, ibus, raw) = row?;
        let raw_hex = hex::encode(&raw);
        println!(
            "Time: {:.6}, Vbus: {:.3}V, Ibus: {:.3}A, Raw (hex): {}",
            time, vbus, ibus, raw_hex
        );
        match parse_event_stream(&raw) {
            Ok(events) => {
                for (i, event) in events.iter().enumerate() {
                    println!("  -> {}", event);
                    match event {
                        km003c_lib::pd::EventPacket::Connection(ev) => {
                            println!("     [parsed ConnectionEvent] type_id {:02x} ts_bytes {:?} reserved {:02x} event_data {:02x}", ev.type_id, ev.timestamp_bytes, ev._reserved, ev.event_data);
                        }
                        km003c_lib::pd::EventPacket::Status(stat) => {
                            println!("     [parsed StatusPacket] type_id {:02x} ts_bytes {:?} vbus_raw {:04x} ibus_raw {:04x} cc1_raw {:04x} cc2_raw {:04x}", stat.type_id, stat.timestamp_bytes, stat.vbus_raw.get(), stat.ibus_raw.get(), stat.cc1_raw.get(), stat.cc2_raw.get());
                        }
                        km003c_lib::pd::EventPacket::PdMessage(pd) => {
                            println!("     [parsed PdMessage] is_src_to_snk {} timestamp {} pd_bytes {:02x?}", pd.is_src_to_snk, pd.timestamp, pd.pd_bytes);
                        }
                    }
                }
            }
            Err(e) => {
                println!("  -> Error parsing events: {:?}", e);
            }
        }
    }
    Ok(())
}
