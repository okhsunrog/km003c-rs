use rusqlite::{Connection, Result};
use hex; // Add hex crate for encoding

fn main() -> Result<()> {
    // Open the SQLite database file
    let conn = Connection::open("wireshark/orig_with_pd.sqlite")?;

    // Prepare a query to select all rows from pd_table
    let mut stmt = conn.prepare("SELECT Time, Vbus, Ibus, Raw FROM pd_table")?;

    // Execute the query and iterate over the rows
    let rows = stmt.query_map([], |row| {
        let time: f64 = row.get(0)?; // Time (real)
        let vbus: f64 = row.get(1)?; // Vbus (real)
        let ibus: f64 = row.get(2)?; // Ibus (real)
        let raw: Vec<u8> = row.get(3)?; // Raw (blob)
        Ok((time, vbus, ibus, raw))
    })?;

    // Print each row
    for row in rows {
        let (time, vbus, ibus, raw) = row?;
        // Convert Raw blob to hex string
        let raw_hex = hex::encode(&raw);
        println!(
            "Time: {}, Vbus: {}, Ibus: {}, Raw (hex): {}",
            time,
            vbus,
            ibus,
            raw_hex
        );
    }

    Ok(())
}