// src/bin/capture.rs

// src/bin/capture.rs

use anyhow::Result;
use bytes::Bytes;
use clap::Parser;
use rtshark::RTSharkBuilder; // <- Corrected: RTShark is not directly used
use std::path::PathBuf;
use std::process;
use tokio;
use tracing::{error, info, warn}; // <- Corrected: Level is not directly used
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
// Use our shared library for parsing.
use km003c_rs::protocol::{CommandType, SensorDataPacket};

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
}


fn setup_logging(log_file_path: Option<PathBuf>) -> Result<Option<WorkerGuard>> {
    let console_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stdout)
        .with_span_events(FmtSpan::CLOSE)
        .with_thread_ids(true);

    let (file_layer, guard) = if let Some(path) = log_file_path {
        info!("Logging to file: {:?}", path);

        // --- CORRECTED LOGIC ---
        // 1. Get the parent directory of the provided path.
        let log_dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));

        // 2. Get the filename from the provided path.
        let file_name = path.file_name().unwrap_or_else(|| std::ffi::OsStr::new("capture.log"));

        // 3. Ensure the directory exists.
        std::fs::create_dir_all(log_dir)?;

        // 4. Set up the rolling file appender.
        let file_appender = tracing_appender::rolling::daily(log_dir, file_name);
        let (non_blocking_writer, guard) = tracing_appender::non_blocking(file_appender);
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(non_blocking_writer)
            .with_ansi(false); // No colors in files
        (Some(layer), Some(guard))
    } else {
        (None, None)
    };
    
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))?;

    tracing_subscriber::registry()
        .with(filter)
        .with(console_layer)
        .with(file_layer)
        .init();

    Ok(guard)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // The guard must be held to ensure logs are flushed to the file.
    let _guard = setup_logging(cli.log_file)?;

    if let Err(e) = run_capture(cli.device_address, cli.interface).await {
        error!("Capture failed: {:?}", e);
        process::exit(1);
    }

    Ok(())
}

async fn run_capture(device_address: u8, interface: String) -> Result<()> {
    // Build the tshark command with dynamic filters.
    let display_filter = format!("usb.device_address == {} && usb.transfer_type == 0x03", device_address);
    let builder = RTSharkBuilder::builder()
        .input_path(&interface)
        .live_capture()
        .display_filter(&display_filter);

    info!(%interface, %device_address, "Starting tshark live capture...");

    let mut rtshark = builder.spawn()?;
    
    while let Some(packet) = rtshark.read().unwrap_or(None) {
        let mut direction: Option<u32> = None;
        let mut payload_hex: Option<String> = None;

        if let Some(usb_layer) = packet.layer_name("usb") {
            if let Some(dir_field) = usb_layer.metadata("usb.endpoint_address.direction") {
                direction = dir_field.value().parse().ok();
            }
            if let Some(payload_field) = usb_layer.metadata("usb.capdata") {
                payload_hex = Some(payload_field.value().to_string());
            }
        }

        if let (Some(dir), Some(hex_str)) = (direction, payload_hex) {
            match hex::decode(hex_str.replace(':', "")) {
                Ok(data) => parse_and_log_payload(dir, data),
                Err(e) => error!(error = %e, "Failed to decode hex payload"),
            }
        }
    }

    info!("tshark process finished.");
    Ok(())
}

/// Parses the raw byte payload and logs the structured data.
fn parse_and_log_payload(direction: u32, data: Vec<u8>) {
    if direction == 0 { // Host -> Device (OUT)
        if data.len() < 4 {
            warn!(len = data.len(), "Received OUT packet with < 4 bytes");
            return;
        }
        let command_type_val = data[0];
        let transaction_id = data[1];
        let attribute_val = u16::from_le_bytes([data[2], data[3]]);
        let command = match CommandType::try_from(command_type_val) {
             Ok(cmd) => format!("{:?}", cmd),
             Err(_) => format!("Unknown({:#04x})", command_type_val),
        };

        info!(
            direction = "Host -> Device",
            id = transaction_id,
            command = command.as_str(),
            attribute = format!("{:#06x}", attribute_val),
            "Parsed Command"
        );
    } else { // Device -> Host (IN)
        if data.len() == 52 {
            let bytes = Bytes::from(data);
            match SensorDataPacket::try_from(bytes) {
                Ok(packet) => info!("Parsed Sensor Data Packet:\n{}", packet),
                Err(e) => error!(error = %e, "Failed to parse 52-byte packet as SensorData"),
            }
        } else if data.len() >= 56 && data.get(0) == Some(&(CommandType::StatusA as u8)) {
            // This is a StatusA header followed by sensor data
            let sensor_bytes = Bytes::from(data[4..].to_vec());
             match SensorDataPacket::try_from(sensor_bytes) {
                Ok(packet) => info!("Parsed Sensor Data Packet (from StatusA):\n{}", packet),
                Err(e) => warn!(error = %e, "Failed to parse sensor data from StatusA response"),
             }
        } else if data.len() == 4 {
            let response_type_val = data[0];
            let transaction_id = data[1];
            let response = match CommandType::try_from(response_type_val) {
                 Ok(cmd) => format!("{:?}", cmd),
                 Err(_) => format!("Unknown({:#04x})", response_type_val),
            };
            info!(
                direction = "Device -> Host",
                id = transaction_id,
                response = response.as_str(),
                "Parsed ACK"
            );
        } else {
            // Log any other packets as a generic info message
            info!(
                direction = "Device -> Host",
                len = data.len(),
                data = hex::encode(&data),
                "Received Data"
            );
        }
    }
}