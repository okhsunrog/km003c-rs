# POWER-Z KM003C SQLite Database (`pd_new.sqlite`)

This document describes the structure and content of the `pd_new.sqlite` database file, which is an export from the original POWER-Z KM003C Windows application.

## Database Schema

The database consists of three tables: `pd_chart`, `pd_table`, and `pd_table_key`.

### `pd_chart` table

This table contains the data for the voltage/current chart.

```sql
CREATE TABLE pd_chart(
    Time real,
    VBUS real,
    IBUS real,
    CC1 real,
    CC2 real
);
```

- `Time`: The timestamp of the reading in seconds.
- `VBUS`: The VBUS voltage in Volts.
- `IBUS`: The IBUS current in Amps.
- `CC1`: The CC1 voltage in Volts.
- `CC2`: The CC2 voltage in Volts.

### `pd_table` table

This table contains the raw Power Delivery (PD) packet data.

```sql
CREATE TABLE pd_table(
    Time real,
    Vbus real,
    Ibus real,
    Raw Blob
);
```

- `Time`: The timestamp of the PD packet in seconds.
- `Vbus`: The VBUS voltage at the time of the PD packet.
- `Ibus`: The IBUS current at the time of the PD packet.
- `Raw`: A `BLOB` containing the raw "inner event stream" of a PD data packet.

### `pd_table_key` table

This table contains a single integer key. Its purpose is not fully understood, but it may be related to indexing or session management within the original application.

```sql
CREATE TABLE pd_table_key(key integer);
```

## Parsing the `Raw` Data

The `Raw` column of the `pd_table` is the most interesting part of the database. It contains the raw "inner event stream" that is also found in the payload of `PutData` packets with the `PdPacket` attribute in the USB protocol.

This data can be parsed using the `km003c-lib` library, specifically the `parse_event_stream` function. The `sqlite_pd.rs` example demonstrates how to do this:

```rust
use km003c_lib::pd::{EventPacket, parse_event_stream};
use rusqlite::{Connection, Result};

fn main() -> Result<()> {
    let conn = Connection::open("pd_analisys/pd_new.sqlite")?;
    let mut stmt = conn.prepare("SELECT Time, Vbus, Ibus, Raw FROM pd_table")?;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, f64>(0)?,
            row.get::<_, Vec<u8>>(3)?,
        ))
    })?;

    for row in rows {
        let (time, raw) = row?;
        let raw_hex = hex::encode(&raw);
        println!("Time: {:.6}, Raw (hex): {}", time, raw_hex);
        match parse_event_stream(&raw) {
            Ok(events) => {
                for event in events {
                    println!("  -> {}", event);
                }
            }
            Err(e) => {
                println!("  -> Error parsing events: {:?}", e);
            }
        }
    }
    Ok(())
}
```

### Example

Here is an example of a row from the `pd_table` and its parsed output:

**Raw data (hex):**
`9f9918000000a1612c9101082cd102002cc103002cb10400454106003c21dcc0`

**Parsed output:**
```
[PD ->] SourceCapabilities:
  [1] Fixed:       5.00 V @ 3.00 A
  [2] Fixed:       9.00 V @ 3.00 A
  [3] Fixed:       12.00 V @ 3.00 A
  [4] Fixed:       15.00 V @ 3.00 A
  [5] Fixed:       20.00 V @ 3.25 A
  [6] PPS:         3.30 - 11.00 V @ 3.00 A
```

## Relation to the Protocol

The data in the `pd_new.sqlite` database directly corresponds to the data transmitted over USB using the reverse-engineered protocol.

- The `pd_table.Raw` data is the payload of the `PutData` packets with the `PdPacket` attribute.
- The `pd_chart` data corresponds to the data from `PutData` packets with the `Adc` attribute, which is then processed and simplified into `AdcDataSimple` by the library.

This database provides a valuable source of known-good data for testing and verifying the correctness of the `km003c-lib` parsing logic.
