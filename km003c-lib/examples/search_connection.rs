use clap::Parser;
use rusqlite::Connection;
use std::fs;

#[derive(Parser, Debug)]
#[command(author, version, about = "Check if connection events from sqlite appear in pcap" )]
struct Cli {
    /// SQLite database with pd_table
    #[arg(short, long, default_value = "matching_record/export.sqlite")]
    db: String,
    /// pcapng file to scan
    #[arg(short, long, default_value = "matching_record/wireshark_0.7.pcapng")]
    pcap: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let conn = Connection::open(cli.db)?;
    let mut stmt = conn.prepare("SELECT hex(Raw) FROM pd_table WHERE substr(hex(Raw),1,2)='45'")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let pcap = fs::read(cli.pcap)?;
    let mut any_found = false;
    for row in rows {
        let hex_str = row?;
        let bytes = hex::decode(&hex_str)?;
        let event_data = bytes[5];
        let mut found = false;
        for i in 0..pcap.len().saturating_sub(6) {
            if pcap[i] == 0x45 && pcap[i + 4] == 0x00 && pcap[i + 5] == event_data {
                found = true;
                break;
            }
        }
        println!(
            "SQLite event {hex_str} (event_data=0x{event_data:02X}) found in pcap: {found}"
        );
        if found {
            any_found = true;
        }
    }
    if !any_found {
        println!("No connection event patterns from sqlite were located in the pcap");
    }
    Ok(())
}
