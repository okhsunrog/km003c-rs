use rusqlite::{Connection, Result};
use usbpd::protocol_layer::message::Message;

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
        // if raw.len() > 6 {
        //     // Slice the raw bytes to skip the 6-byte proprietary header.
        //     let pd_message_bytes = &raw[6..];
        //     let message = Message::from_bytes(pd_message_bytes);
        //     println!("  -> Parsed PD Message: {:?}", message);
        // } else {
        //     println!("  -> Malformed packet (too short to be a wrapped PD message)");
        // }
    }
    Ok(())
}
