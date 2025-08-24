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
                        km003c_lib::pd::EventPacket::Connection(ev, ts) => {
                            println!("     [parsed ConnectionEvent @{}] action={} cc_pin={}", ts, ev.action(), ev.cc_pin());
                        }
                        km003c_lib::pd::EventPacket::Status(stat, ts) => {
                            println!("     [parsed StatusPacket @{}] vbus={} ibus={} cc1={} cc2={}", ts, stat.vbus_raw.get(), stat.ibus_raw.get(), stat.cc1_raw.get(), stat.cc2_raw.get());
                        }
                        km003c_lib::pd::EventPacket::PdMessage(pd, ts) => {
                            println!("     [parsed PdMessage @{}] dir={} len={} bytes {:02x?}", ts, if pd.is_src_to_snk {"->"} else {"<-"}, pd.pd_bytes.len(), pd.pd_bytes);
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
