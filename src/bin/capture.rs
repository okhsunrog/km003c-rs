use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use rtshark::RTSharkBuilder;
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::process;
use std::time::{Duration, Instant};
use tokio;
// Make sure to use Verbosity from the crate
use clap_verbosity_flag::{Verbosity, InfoLevel};
use tracing::{debug, error, info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use km003c_rs::protocol::{CommandType, SensorDataPacket};

#[derive(Debug, Clone)]
struct Request {
    frame_num: u32,
    command: String,
    attribute: u16,
}

// CORRECT: No `#[derive(Default)]` here
#[derive(Debug)]
struct Transaction {
    request: Option<Request>,
    response_fragments: Vec<(u32, Vec<u8>)>,
    last_updated: Instant,
}

// CORRECT: Manual implementation is the only one.
impl Default for Transaction {
    fn default() -> Self {
        Self {
            request: None,
            response_fragments: Vec::new(),
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

fn setup_logging(log_file_path: Option<PathBuf>, verbosity: &Verbosity<InfoLevel>) -> Result<Option<WorkerGuard>> {
        let console_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stdout)
        .with_target(false)
        .with_thread_ids(false)
        .without_time();

    // --- THE FIX: Use `ref` to borrow the PathBuf instead of moving it ---
    let (file_layer, guard) = if let Some(ref path) = log_file_path {
        let log_file = File::create(path) // `path` is now a reference, which is fine
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
    
    let filter = EnvFilter::builder()
        .with_default_directive(verbosity.tracing_level_filter().into())
        .from_env_lossy();

    tracing_subscriber::registry()
        .with(filter)
        .with(console_layer)
        .with(file_layer)
        .init();
    
    // This is now valid because `log_file_path` was not moved.
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
         match packet_option {
            Some(packet) => {
                 let mut direction: Option<String> = None;
                 let mut frame_num: Option<u32> = None;
                 let mut payload_hex: Option<String> = None;

                 if let Some(frame_layer) = packet.layer_name("frame") {
                     frame_num = frame_layer.metadata("frame.number").and_then(|f| f.value().parse().ok());
                 }

                 if let Some(usb_layer) = packet.layer_name("usb") {
                    if let Some(ep) = usb_layer.metadata("usb.endpoint_address.direction") {
                        direction = Some(ep.value().to_string());
                    }
                    if let Some(pd) = usb_layer.metadata("usb.capdata") {
                        payload_hex = Some(pd.value().to_string());
                    }
                 }

                 if let (Some(frame), Some(dir), Some(hex)) = (frame_num, direction, payload_hex) {
                      match hex::decode(hex.replace(':', "")) {
                         Ok(data) => process_packet(frame, &dir, data, &mut transactions),
                         Err(e) => error!(error = %e, "Failed to decode hex payload"),
                     }
                 }
            },
            None => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        if last_cleanup.elapsed() > Duration::from_millis(200) {
            cleanup_transactions(&mut transactions);
            last_cleanup = Instant::now();
        }
    }

    info!("tshark stream finished.");
    cleanup_transactions(&mut transactions);
    for (id, t) in transactions {
        print_transaction(&id, &t);
    }
    println!("--------------------------------------------------------------------------------");

    Ok(())
}


fn process_packet(frame_num: u32, direction: &str, data: Vec<u8>, transactions: &mut HashMap<u8, Transaction>) {
    if data.len() < 4 { return; }

    let command_val = data[0];
    let is_sensor_packet = data.len() == 52 && command_val != (CommandType::Accept as u8);
    
    if direction == "1" && is_sensor_packet {
        print_unsolicited_packet(frame_num, data);
        return;
    }

    let transaction_id = data[1];
    let transaction = transactions.entry(transaction_id).or_default();
    transaction.last_updated = Instant::now();

    if direction == "0" {
        let command_type_val = data[0];
        let attribute_val = u16::from_le_bytes([data[2], data[3]]);
        let command_str = match CommandType::try_from(command_type_val) {
            Ok(cmd) => format!("{:?}", cmd),
            Err(_) => format!("Unknown({:#04x})", command_type_val),
        };
        transaction.request = Some(Request {
            frame_num,
            command: command_str,
            attribute: attribute_val,
        });
    } else {
        transaction.response_fragments.push((frame_num, data));
    }
}

fn cleanup_transactions(transactions: &mut HashMap<u8, Transaction>) {
    let now = Instant::now();
    let timeout = Duration::from_millis(500);
    
    transactions.retain(|id, t| {
        if now.duration_since(t.last_updated) > timeout {
            print_transaction(id, t);
            false 
        } else {
            true
        }
    });
}

fn print_transaction(id: &u8, t: &Transaction) {
    if let Some(req) = &t.request {
        info!(
            "ID: {:<3} | Request  (Frame {:<4}) | Cmd: {:<20} | Attr: {:#06x}",
            id, req.frame_num, req.command, req.attribute
        );
    } else {
        warn!("ID: {:<3} | Orphaned Response(s)", id);
    }

    if !t.response_fragments.is_empty() {
        let mut full_payload = Vec::new();
        let mut frame_nums = Vec::new();
        for (frame_num, data) in &t.response_fragments {
            full_payload.extend_from_slice(data);
            frame_nums.push(frame_num.to_string());
        }
        let frame_nums_str = frame_nums.join(", ");
        
        debug!("       | Raw Response Payload: {}", hex::encode(&full_payload));

        let bytes = Bytes::from(full_payload);
        if bytes.len() >= 56 && bytes.get(0) == Some(&(CommandType::StatusA as u8)) {
             let sensor_bytes = Bytes::from(bytes.slice(4..));
             if let Ok(packet) = SensorDataPacket::try_from(sensor_bytes) {
                  info!("       | Response (Frames {}) | Sensor (StatusA): {:?}", frame_nums_str, packet);
             } else {
                 info!(
                    "       | Response (Frames {}) | StatusA + Generic (len {}): {}",
                    frame_nums_str,
                    bytes.len(),
                    hex::encode(bytes)
                 );
             }
        } else if bytes.len() == 4 && t.response_fragments.len() == 1 {
             let response_type_val = bytes[0];
             let response = match CommandType::try_from(response_type_val) {
                Ok(cmd) => format!("{:?}", cmd),
                Err(_) => format!("Unknown({:#04x})", response_type_val),
            };
             info!("       | Response (Frame  {:<4}) | ACK: {}", frame_nums_str, response);
        }
        else {
            info!(
                "       | Response (Frames {}) | Reassembled Data (len {})",
                frame_nums_str,
                bytes.len()
            );
        }
    } else if t.request.is_some() {
        info!("       | Response (---)          | No response received (timed out).");
    }
    println!("--------------------------------------------------------------------------------");
}

fn print_unsolicited_packet(frame_num: u32, data: Vec<u8>) {
    debug!("       | Raw Unsolicited Payload: {}", hex::encode(&data));
    let bytes = Bytes::from(data);
    if let Ok(packet) = SensorDataPacket::try_from(bytes) {
        info!("Stream Packet (Frame {:<4}) | Sensor: {:?}", frame_num, packet);
    } else {
        warn!("Stream Packet (Frame {:<4}) | Failed to parse as SensorData", frame_num);
    }
}