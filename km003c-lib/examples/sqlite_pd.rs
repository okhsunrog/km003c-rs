use km003c_lib::pd::{EventPacket, parse_event_stream};
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
        let events = parse_event_stream(&raw);
        for event in events {
            println!("  -> {}", event);
        }
    }
    Ok(())
}
