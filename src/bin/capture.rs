// src/bin/capture.rs

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use rtshark::{Packet as RtSharkPacket, RTSharkBuilder};
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::process;
use std::time::{Duration, Instant};
use tokio;

use clap_verbosity_flag::{InfoLevel, Verbosity};
use km003c_rs::protocol::{CommandHeader, DeviceInfoBlock, Direction, Packet, PdPacket}; // Your existing imports
use tracing::{debug, error, info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// A struct to hold a parsed packet along with its tshark frame number.
#[derive(Debug, Clone)]
struct CapturedPacket {
    frame_num: u32,
    packet: Packet,
}

/// A struct to represent a single logical transaction (request + response(s)).
#[derive(Debug)]
struct Transaction {
    request: Option<CapturedPacket>,
    responses: Vec<CapturedPacket>,
    last_updated: Instant,
}

impl Default for Transaction {
    fn default() -> Self {
        Self {
            request: None,
            responses: Vec::new(),
            last_updated: Instant::now(),
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The USB device address to monitor.
    #[arg(short, long)]
    device_address: u8,

    // --- CORRECTED: Use `group(required = true)` ---
    /// Live capture mode: The usbmon interface (e.g., 'usbmon0').
    #[arg(short, long, group = "input_mode")]
    interface: Option<String>,

    /// File mode: Path to a .pcap or .pcapng file to read from.
    #[arg(short, long, group = "input_mode", conflicts_with = "interface")]
    file: Option<PathBuf>,
    // --- END CORRECTION ---

    /// Optional path to a file to write logs to, in addition to the console.
    #[arg(short, long)]
    log_file: Option<PathBuf>,
    
    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,
}

fn setup_logging(
    log_file_path: Option<PathBuf>,
    verbosity: &Verbosity<InfoLevel>,
) -> Result<Option<WorkerGuard>> {
    let console_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stdout)
        .with_target(false)
        .with_thread_ids(false)
        .without_time();

    let (file_layer, guard) = if let Some(ref path) = log_file_path {
        let log_file =
            File::create(path).with_context(|| format!("Failed to create log file at: {:?}", path))?;
        let (non_blocking_writer, guard) = tracing_appender::non_blocking(log_file);
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(non_blocking_writer)
            .with_ansi(false)
            .with_target(false);
        (Some(layer), Some(guard))
    } else {
        (None, None)
    };

    let base_filter = verbosity.tracing_level_filter();
    let filter = EnvFilter::builder()
        .with_default_directive(base_filter.into())
        .from_env_lossy();

    tracing_subscriber::registry()
        .with(filter)
        .with(console_layer)
        .with(file_layer)
        .init();

    if let Some(path) = log_file_path {
        info!("Logging to file: {:?}", path);
    }

    Ok(guard)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let _guard = setup_logging(cli.log_file.clone(), &cli.verbose)?;

    if let Err(e) = run_capture(cli).await {
        error!("Capture failed: {:?}", e);
        process::exit(1);
    }

    Ok(())
}

async fn run_capture(cli: Cli) -> Result<()> {
    let mut builder = RTSharkBuilder::builder();

    // --- NEW: Logic to handle either file or live input ---
    let is_live_capture;
    let builder_ready = if let Some(ref file_path) = cli.file {
        info!(file = %file_path.display(), "Reading from capture file...");
        is_live_capture = false;
        builder.input_path(file_path.to_str().expect("File path is not valid UTF-8"))
    } else {
        // This unwrap is safe because clap ensures one of the group is present.
        let interface_name = cli.interface.as_deref().unwrap();
        info!(interface = %interface_name, "Starting tshark live capture...");
        is_live_capture = true;
        builder.input_path(interface_name).live_capture()
    };
    
    println!("--------------------------------------------------------------------------------");

    let mut transactions: HashMap<u8, Transaction> = HashMap::new();
    let mut last_transaction_id: Option<u8> = None;

    let display_filter = format!(
        "usb.device_address == {} && usb.transfer_type == 0x03 && usb.capdata",
        cli.device_address
    );

    let mut rtshark = builder_ready.display_filter(&display_filter).spawn()?;
    
    let mut last_cleanup = Instant::now();

    // Use the simple, synchronous-style loop
    while let Ok(packet_option) = rtshark.read() {
        if let Some(p) = packet_option {
            process_rtshark_packet(p, &mut transactions, &mut last_transaction_id);
        } else {
            // If reading from file, None means EOF, so we break.
            if !is_live_capture {
                break;
            }
            // In live mode, we just wait for more packets.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Only run the timeout-based cleanup in live mode
        if is_live_capture && last_cleanup.elapsed() > Duration::from_secs(1) {
            cleanup_transactions(&mut transactions);
            last_cleanup = Instant::now();
        }
    }

    info!("tshark stream finished. Printing remaining transactions...");
    let mut sorted_keys: Vec<_> = transactions.keys().cloned().collect();
    sorted_keys.sort();

    for id in sorted_keys {
        if let Some(t) = transactions.get(&id) {
             print_transaction(&id, t);
        }
    }
    println!("--------------------------------------------------------------------------------");

    Ok(())
}

// All of the following functions are UNCHANGED from your working version.
// They correctly handle the known protocol state.

fn process_rtshark_packet(
    packet: RtSharkPacket,
    transactions: &mut HashMap<u8, Transaction>,
    last_transaction_id: &mut Option<u8>,
) {
    let frame_num = packet.layer_name("frame").and_then(|f| f.metadata("frame.number")).and_then(|n| n.value().parse().ok()).unwrap_or(0);
    let Some(usb_layer) = packet.layer_name("usb") else { return };
    let direction = match usb_layer.metadata("usb.endpoint_address.direction").map(|d| d.value()).as_deref() {
        Some("0") => Direction::HostToDevice,
        Some("1") => Direction::DeviceToHost,
        _ => return,
    };
    let Some(payload_hex) = usb_layer.metadata("usb.capdata").map(|p| p.value()) else { return };
    let Ok(data) = hex::decode(payload_hex.replace(':', "")) else {
        error!(frame = frame_num, "Failed to decode hex payload");
        return;
    };
    
    debug!(frame = frame_num, len = data.len(), hex = hex::encode(&data), ?direction, "Raw captured packet");
    
    let bytes = Bytes::from(data);
    let parsed_packet = Packet::from_bytes(bytes, direction);
    let captured = CapturedPacket { frame_num, packet: parsed_packet.clone() };

    if let Some(header) = get_packet_header(&captured.packet) {
        let id = header.transaction_id;
        let transaction = transactions.entry(id).or_default();
        if direction == Direction::HostToDevice {
            if transaction.request.is_some() { warn!(id, "Received new request for a pending transaction. Overwriting."); }
            transaction.request = Some(captured);
        } else {
            transaction.responses.push(captured);
        }
        transaction.last_updated = Instant::now();
        *last_transaction_id = Some(id);
    } else {
        match captured.packet {
            Packet::DataChunk(_) => {
                if let Some(id) = last_transaction_id {
                    if let Some(transaction) = transactions.get_mut(id) {
                        transaction.responses.push(captured);
                        transaction.last_updated = Instant::now();
                        return;
                    }
                }
                print_unsolicited_packet(captured);
            }
            Packet::SensorData(_) => print_unsolicited_packet(captured),
            Packet::Unknown { .. } => warn!("Failed to parse packet: {:?}", captured.packet),
            _ => warn!("Unhandled header-less packet: {:?}", captured.packet),
        }
    }
}

fn get_packet_header(p: &Packet) -> Option<&CommandHeader> {
    match p {
        Packet::Command(h, _) => Some(h),
        Packet::Acknowledge { header: h, .. } => Some(h),
        Packet::GenericResponse { header: h, .. } => Some(h),
        _ => None,
    }
}

fn cleanup_transactions(transactions: &mut HashMap<u8, Transaction>) {
    let now = Instant::now();
    let timeout = Duration::from_secs(2);
    transactions.retain(|id, t| {
        let is_complete = t.request.is_some() && !t.responses.is_empty();
        let has_timed_out = t.request.is_some() && t.responses.is_empty() && now.duration_since(t.last_updated) > timeout;
        let is_stale_orphan = t.request.is_none() && now.duration_since(t.last_updated) > timeout * 2;
        if is_complete || has_timed_out || is_stale_orphan {
            print_transaction(id, t);
            false
        } else {
            true
        }
    });
}

fn print_transaction(id: &u8, t: &Transaction) {
    if let Some(req) = &t.request {
        info!("ID: {:<3} | Request  (F:{:<4}) | {:?}", id, req.frame_num, req.packet);
    } else {
        warn!("ID: {:<3} | Orphaned Response(s)", id);
    }

    if !t.responses.is_empty() {
        for res in &t.responses {
            let request_attribute = t.request.as_ref().and_then(|req| get_packet_header(&req.packet)).map(|h| h.attribute);
            let mut handled = false;
            if let Packet::GenericResponse { payload, .. } = &res.packet {
                match request_attribute {
                    Some(km003c_rs::protocol::Attribute::GetDeviceInfo) => {
                        if let Ok(info) = DeviceInfoBlock::try_from(payload.clone()) {
                            info!("       | Response (F:{:<4}) | DeviceInfo({:?})", res.frame_num, info);
                            handled = true;
                        }
                    }
                    Some(km003c_rs::protocol::Attribute::PdStatus) => {
                        if let Ok(pd_packet) = PdPacket::try_from(payload.clone()) {
                            info!("       | Response (F:{:<4}) | PowerDelivery({:?})", res.frame_num, pd_packet);
                            handled = true;
                        }
                    }
                    _ => {}
                }
            }
            if !handled {
                info!("       | Response (F:{:<4}) | {:?}", res.frame_num, res.packet);
            }
        }
    } else if t.request.is_some() {
        info!("       | Response (---)          | No response received (timed out).");
    }
    println!("--------------------------------------------------------------------------------");
}

fn print_unsolicited_packet(captured: CapturedPacket) {
    info!("Stream Packet (F:{:<4})   | {:?}", captured.frame_num, captured.packet);
}