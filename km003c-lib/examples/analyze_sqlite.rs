use clap::Parser;
use rusqlite::{Connection, Result};

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    file: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let conn = Connection::open(&args.file)?;

    let mut stmt = conn.prepare("SELECT name FROM sqlite_master WHERE type='table'")?;
    let tables = stmt.query_map([], |row| row.get::<_, String>(0))?;

    println!("Tables in {}:
", args.file);
    println!("\nData from pd_table:");
    let mut stmt = conn.prepare("SELECT Time, Raw FROM pd_table")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let time: f64 = row.get(0)?;
        let raw: Vec<u8> = row.get(1)?;
        println!("  - Time: {}, Raw: {}", time, hex::encode(&raw));
    }

    Ok(())
}