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
use tracing::{debug, error, info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use km003c_rs::protocol::{Direction, Packet, PdPacket, DeviceInfoBlock};

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

/// A real-time USB protocol analyzer for the POWER-Z KM003C, powered by tshark.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The USB device address to monitor.
    #[arg(short, long)]
    device_address: u8,
    /// The usbmon interface to capture from (e.g., usbmon3).
    #[arg(short, long, default_value = "usbmon0")]
    interface: String,
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
        let log_file = File::create(path)
            .with_context(|| format!("Failed to create log file at: {:?}", path))?;
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

    // --- FIX FOR DEBUG LOGGING ---
    // We want INFO by default, DEBUG with -v, TRACE with -vv etc.
    // clap_verbosity_flag maps -v to one level higher. Since our base is INFO,
    // -v will give DEBUG.
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
    let _guard = setup_logging(cli.log_file, &cli.verbose)?;

    if let Err(e) = run_capture(cli.device_address, cli.interface).await {
        error!("Capture failed: {:?}", e);
        process::exit(1);
    }

    Ok(())
}

async fn run_capture(device_address: u8, interface: String) -> Result<()> {
    info!(%interface, %device_address, "Starting tshark live capture...");
    println!("--------------------------------------------------------------------------------");

    let mut transactions: HashMap<u8, Transaction> = HashMap::new();
    let mut last_transaction_id: Option<u8> = None; // <-- NEW: Track the last ID seen

    let display_filter = format!(
        "usb.device_address == {} && usb.transfer_type == 0x03 && usb.capdata",
        device_address
    );

    let builder = RTSharkBuilder::builder()
        .input_path(&interface)
        .live_capture()
        .display_filter(&display_filter);

    let mut rtshark = builder.spawn()?;
    let mut last_cleanup = Instant::now();

    while let Ok(packet_option) = rtshark.read() {
        if let Some(p) = packet_option {
            // Pass the mutable Option to the processor
            process_rtshark_packet(p, &mut transactions, &mut last_transaction_id);
        } else {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        if last_cleanup.elapsed() > Duration::from_secs(1) {
            cleanup_transactions(&mut transactions);
            last_cleanup = Instant::now();
        }
    }

    info!("tshark stream finished. Printing remaining transactions...");
    transactions.retain(|id, t| {
        print_transaction(id, t);
        false
    });
    println!("--------------------------------------------------------------------------------");

    Ok(())
}

// In capture.rs

fn process_rtshark_packet(
    packet: RtSharkPacket,
    transactions: &mut HashMap<u8, Transaction>,
    last_transaction_id: &mut Option<u8>, // Now mutable to update it
) {
    // 1. Extract raw data from the tshark packet
    let frame_num = packet
        .layer_name("frame")
        .and_then(|f| f.metadata("frame.number"))
        .and_then(|n| n.value().parse().ok())
        .unwrap_or(0);

    let Some(usb_layer) = packet.layer_name("usb") else {
        return;
    };

    let direction = match usb_layer
        .metadata("usb.endpoint_address.direction")
        .map(|d| d.value())
        .as_deref()
    {
        Some("0") => Direction::HostToDevice,
        Some("1") => Direction::DeviceToHost,
        _ => return,
    };

    let Some(payload_hex) = usb_layer.metadata("usb.capdata").map(|p| p.value()) else {
        return;
    };

    let Ok(data) = hex::decode(payload_hex.replace(':', "")) else {
        error!(frame = frame_num, "Failed to decode hex payload");
        return;
    };

    // 2. Log the raw bytes at DEBUG level (for -v flag)
    debug!(
        frame = frame_num,
        len = data.len(),
        hex = hex::encode(&data),
        ?direction,
        "Raw captured packet"
    );

    // 3. Parse the raw bytes into our high-level `Packet` enum
    let bytes = Bytes::from(data);
    let parsed_packet = Packet::from_bytes(bytes, direction);

    let captured = CapturedPacket {
        frame_num,
        packet: parsed_packet,
    };

    // 4. Determine how to handle the packet based on whether it has a header
    if let Some(header) = get_packet_header(&captured.packet) {
        // --- CASE A: The packet HAS a header ---
        // This is the easy case. We use the header's ID to find the transaction.
        let id = header.transaction_id;
        let transaction = transactions.entry(id).or_default();

        if direction == Direction::HostToDevice {
            if transaction.request.is_some() {
                warn!(
                    id,
                    "Received a new request for a pending transaction. Overwriting."
                );
            }
            transaction.request = Some(captured);
        } else {
            transaction.responses.push(captured);
        }
        transaction.last_updated = Instant::now();

        // IMPORTANT: We remember this ID as the most recently seen one.
        *last_transaction_id = Some(id);
    } else {
        // --- CASE B: The packet does NOT have a header ---
        // This applies to unsolicited streams and header-less continuation packets.
        match captured.packet {
            Packet::DataChunk(_) => {
                // It's a DataChunk. Let's try to associate it with the last known transaction.
                // This is the key for grouping multi-part handshake responses.
                if let Some(id) = last_transaction_id {
                    if let Some(transaction) = transactions.get_mut(id) {
                        transaction.responses.push(captured);
                        transaction.last_updated = Instant::now();
                        // Early return since we've handled it.
                        return;
                    }
                }
                // If we couldn't associate it, it's truly an orphan.
                // Fall through to print it as an unsolicited packet.
                print_unsolicited_packet(captured);
            }
            Packet::SensorData(_) => {
                // SensorData packets from the stream have no header and are always unsolicited.
                print_unsolicited_packet(captured);
            }
            Packet::Unknown { .. } => {
                // A truly unknown packet format.
                warn!("Failed to parse packet: {:?}", captured.packet);
            }
            // Other cases without headers (like Command, Acknowledge) are not logically
            // possible due to the parser's design, but we can handle them defensively.
            _ => {
                warn!("Unhandled header-less packet: {:?}", captured.packet);
            }
        }
    }
}

/// Helper to get the header from packets that might have one.
fn get_packet_header(p: &Packet) -> Option<&km003c_rs::protocol::CommandHeader> {
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
        let has_timed_out = t.request.is_some()
            && t.responses.is_empty()
            && now.duration_since(t.last_updated) > timeout;
        let is_stale_orphan =
            t.request.is_none() && now.duration_since(t.last_updated) > timeout * 2;

        if is_complete || has_timed_out || is_stale_orphan {
            print_transaction(id, t);
            false
        } else {
            true
        }
    });
}

fn print_transaction(id: &u8, t: &Transaction) {
    // Print the request as before
    if let Some(req) = &t.request {
        info!("ID: {:<3} | Request  (F:{:<4}) | {:?}", id, req.frame_num, req.packet);
    } else {
        warn!("ID: {:<3} | Orphaned Response(s)", id);
    }

    if !t.responses.is_empty() {
        for res in &t.responses {
            // Get the attribute from the original request to give context to the response.
            let request_attribute = t.request.as_ref()
                .and_then(|req| get_packet_header(&req.packet))
                .map(|h| h.attribute);

            // --- NEW CONTEXT-AWARE PARSING LOGIC ---
            let mut handled = false;
            if let Packet::GenericResponse { payload, .. } = &res.packet {
                match request_attribute {
                    // If the request was to get device info...
                    Some(km003c_rs::protocol::Attribute::GetDeviceInfo) => {
                        if let Ok(info) = DeviceInfoBlock::try_from(payload.clone()) {
                            info!("       | Response (F:{:<4}) | DeviceInfo({:?})", res.frame_num, info);
                            handled = true;
                        }
                    }
                    // If the request was to poll for PD events or status...
                    Some(km003c_rs::protocol::Attribute::PollPdEvents) 
                    | Some(km003c_rs::protocol::Attribute::PdStatus) => {
                        if let Ok(pd_packet) = PdPacket::try_from(payload.clone()) {
                            info!("       | Response (F:{:<4}) | PowerDelivery({:?})", res.frame_num, pd_packet);
                            handled = true;
                        }
                    }
                    // Add more context-aware cases here in the future
                    _ => {}
                }
            }

            // If the packet wasn't handled by a special case, print its generic form.
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
    info!(
        "Stream Packet (F:{:<4})   | {:?}",
        captured.frame_num, captured.packet
    );
}
