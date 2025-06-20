use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use rtshark::{Packet as RtSharkPacket, RTSharkBuilder};
use std::fs::File;
use std::path::PathBuf;
use std::process;

use clap_verbosity_flag::{InfoLevel, Verbosity};
use km003c_rs::protocol::{CommandHeader, Direction, Packet};
// Correct tracing imports
use tracing::{error, info};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

// --- Command Line Interface ---

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    device_address: Option<u8>,
    #[arg(short, long, group = "input_mode", help = "Live capture from a tshark interface")]
    interface: Option<String>,
    #[arg(
        short,
        long,
        group = "input_mode",
        conflicts_with = "interface",
        help = "Read from a .pcapng file"
    )]
    file: Option<PathBuf>,
    #[arg(short, long)]
    log_file: Option<PathBuf>,
    #[arg(
        long,
        help = "Display packets in raw chronological order without grouping (default for live capture)"
    )]
    raw: bool,
    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,
}

// --- Core Data Structures for This Tool ---

#[derive(Debug, Clone)]
struct CapturedPacket {
    frame_num: u32,
    timestamp: f64,
    packet: Packet,
    raw_hex: String,
    direction: Direction,
}

#[derive(Debug)]
enum DisplayItem {
    Transaction {
        request: CapturedPacket,
        responses: Vec<CapturedPacket>,
    },
    Standalone(CapturedPacket),
}

// --- Main Logic ---

fn main() -> Result<()> {
    let mut cli = Cli::parse();
    // Use your correct, original setup_logging function
    let _guard = setup_logging(cli.log_file.clone(), &cli.verbose)?;

    // --- Input Validation and Configuration ---
    if cli.device_address.is_none() {
        if let Some(ref file_path) = cli.file {
            let filename = file_path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if let Some(captures) = regex::Regex::new(r"\.(\d+)\.pcapn?g$")?.captures(filename) {
                if let Some(id_match) = captures.get(1) {
                    if let Ok(id) = id_match.as_str().parse::<u8>() {
                        info!("Inferred device address from filename: {}", id);
                        cli.device_address = Some(id);
                    }
                }
            }
        }
    }

    if cli.device_address.is_none() {
        error!(
            "Device address is required. Provide it with -d/--device-address or name the input file like 'capture.<id>.pcapng'"
        );
        process::exit(1);
    }
    if cli.file.is_none() && cli.interface.is_none() {
        error!("Input source is required. Provide either a file (-f) or an interface (-i).");
        process::exit(1);
    }

    let is_live_capture = cli.file.is_none();
    let use_raw_mode = cli.raw || is_live_capture;

    if is_live_capture && !cli.raw {
        info!("Live capture always runs in raw chronological mode. Grouping is only available for files.");
    }

    // --- Dispatch to the correct capture mode ---
    let result = if use_raw_mode {
        info!("Running in Raw Chronological Mode.");
        run_raw_chronological_capture(&cli)
    } else {
        info!("Running in Grouped Chronological Mode.");
        run_grouped_file_capture(&cli)
    };

    if let Err(e) = result {
        error!("Capture failed: {}", e);
        process::exit(1);
    }

    Ok(())
}

/// Mode 1: Simple, live-compatible, prints every packet as it arrives.
fn run_raw_chronological_capture(cli: &Cli) -> Result<()> {
    let mut builder = RTSharkBuilder::builder();
    let display_filter = format!(
        "usb.device_address == {} && usb.transfer_type == 0x03 && usb.capdata",
        cli.device_address.unwrap()
    );

    let builder_ready = if let Some(file_path) = &cli.file {
        builder.input_path(file_path.to_str().context("File path is not valid UTF-8")?)
    } else {
        builder.input_path(cli.interface.as_deref().unwrap()).live_capture()
    };

    let mut rtshark = builder_ready.display_filter(&display_filter).spawn()?;

    println!("--- Raw Chronological Log ---");
    println!("--------------------------------------------------------------------------------");

    while let Some(p) = rtshark.read()? {
        if let Ok(captured_packet) = parse_rtshark_packet(p) {
            print_single_packet(&captured_packet, "[RAW]"); // <-- Change here
        }
    }
    Ok(())
}

// In src/bin/capture.rs

/// Mode 2: File-only, reads all packets, groups them, then prints a contextual log.
fn run_grouped_file_capture(cli: &Cli) -> Result<()> {
    const RESPONSE_WINDOW: usize = 20;

    // --- PHASE 1: INGEST ALL PACKETS FROM FILE (Unchanged) ---
    let mut all_packets: Vec<CapturedPacket> = Vec::new();
    let display_filter = format!(
        "usb.device_address == {} && usb.transfer_type == 0x03 && usb.capdata",
        cli.device_address.unwrap()
    );

    let mut rtshark = RTSharkBuilder::builder()
        .input_path(
            cli.file
                .as_ref()
                .unwrap()
                .to_str()
                .context("File path is not valid UTF-8")?,
        )
        .display_filter(&display_filter)
        .spawn()?;

    while let Some(p) = rtshark.read()? {
        if let Ok(packet) = parse_rtshark_packet(p) {
            all_packets.push(packet);
        }
    }
    info!("Ingested {} packets. Grouping transactions...", all_packets.len());

    // --- PHASE 2: GROUPING LOGIC (The updated part) ---
    let mut display_items: Vec<DisplayItem> = Vec::new();
    let mut consumed_indices = vec![false; all_packets.len()];

    for i in 0..all_packets.len() {
        if consumed_indices[i] {
            continue;
        }

        let mut was_grouped = false;
        let request_candidate = &all_packets[i];

        // Only `Command` packets can be requests.
        if let Packet::Command(req_header, _) = &request_candidate.packet {
            let search_end = (i + 1 + RESPONSE_WINDOW).min(all_packets.len());
            'response_search: for j in (i + 1)..search_end {
                if consumed_indices[j] {
                    continue;
                }

                let response_candidate = &all_packets[j];
                let mut is_match = false;

                // --- NEW UNIFIED MATCHING LOGIC ---
                // RULE 1: Check for standard response with a matching ID.
                if let Some(res_header) = get_packet_header(&response_candidate.packet) {
                    if res_header.transaction_id == req_header.transaction_id {
                        is_match = true;
                    }
                }
                // RULE 2: Check for a SensorData response with a matching ID in its packed header.
                else if let Packet::SensorData(sd) = &response_candidate.packet {
                    if sd.header.transaction_id == req_header.transaction_id {
                        is_match = true;
                    }
                }

                // If a match was found by ANY rule, group the transaction.
                if is_match {
                    let mut responses = vec![response_candidate.clone()];
                    consumed_indices[j] = true;

                    // Now look for subsequent DataChunk continuations.
                    let continuation_end = (j + 1 + RESPONSE_WINDOW).min(all_packets.len());
                    for k in (j + 1)..continuation_end {
                        if consumed_indices[k] {
                            continue;
                        }
                        if matches!(all_packets[k].packet, Packet::DataChunk(_)) {
                            responses.push(all_packets[k].clone());
                            consumed_indices[k] = true;
                        } else {
                            break; // The chain of continuations is broken.
                        }
                    }

                    display_items.push(DisplayItem::Transaction {
                        request: request_candidate.clone(),
                        responses,
                    });
                    was_grouped = true;
                    break 'response_search; // Found our transaction, stop searching.
                }
            }
        }

        // If the packet at `i` was not grouped, add it as a standalone item.
        if !was_grouped {
            display_items.push(DisplayItem::Standalone(request_candidate.clone()));
        }
        consumed_indices[i] = true;
    }

    // --- PHASE 3: RENDER THE GROUPED LOG (Unchanged) ---
    println!("--- Grouped Chronological Log ---");
    for item in &display_items {
        print_display_item(item); // <-- Change here
    }

    Ok(())
}

// --- Helper Functions ---

fn parse_rtshark_packet(p: RtSharkPacket) -> Result<CapturedPacket> {
    let frame_num = p
        .layer_name("frame")
        .and_then(|f| f.metadata("frame.number"))
        .and_then(|n| n.value().parse().ok())
        .unwrap_or(0);
    let timestamp = p
        .layer_name("frame")
        .and_then(|f| f.metadata("frame.time_relative"))
        .and_then(|n| n.value().parse().ok())
        .unwrap_or(0.0);
    let usb_layer = p.layer_name("usb").context("Missing USB layer")?;
    let direction = match usb_layer.metadata("usb.endpoint_address.direction").map(|d| d.value()) {
        Some("0") => Direction::HostToDevice,
        Some("1") => Direction::DeviceToHost,
        _ => anyhow::bail!("Unknown USB direction"),
    };
    let payload_hex = usb_layer
        .metadata("usb.capdata")
        .context("Missing usb.capdata")?
        .value();
    let raw_hex = payload_hex.replace(':', "");
    let data = hex::decode(&raw_hex).context("Failed to decode hex payload")?;
    let bytes = Bytes::from(data);
    let parsed_packet = Packet::from_bytes(bytes, direction);
    Ok(CapturedPacket {
        frame_num,
        timestamp,
        packet: parsed_packet,
        raw_hex,
        direction,
    })
}

// In src/bin/capture.rs
fn print_display_item(item: &DisplayItem) {
    println!("--------------------------------------------------------------------------------");
    match item {
        DisplayItem::Transaction { request, responses } => {
            print_single_packet(request, "[TXN-REQ]");
            for res in responses {
                print_single_packet(res, "[TXN-RSP]");
            }
        }
        DisplayItem::Standalone(packet) => {
            print_single_packet(packet, "[PKT]");
        }
    }
}

fn print_single_packet(p: &CapturedPacket, prefix: &str) {
    // <-- Change here: remove is_debug
    let dir_str = match p.direction {
        Direction::HostToDevice => "H->D",
        Direction::DeviceToHost => "D->H",
    };

    // Always log the parsed version at INFO level.
    info!(
        "{} {} F:{:<4} @ {:>8.6}s | {:?}",
        prefix, dir_str, p.frame_num, p.timestamp, p.packet
    );

    // Always log the raw hex at DEBUG level.
    // This will only be displayed if the log level is DEBUG or lower (e.g., with -v).
    tracing::debug!(
        "{} {} F:{:<4} @ {:>8.6}s | {}",
        prefix,
        dir_str,
        p.frame_num,
        p.timestamp,
        p.raw_hex
    );
}

fn get_packet_header(p: &Packet) -> Option<&CommandHeader> {
    match p {
        Packet::Command(h, _) => Some(h),
        Packet::Acknowledge { header: h, .. } => Some(h),
        Packet::GenericResponse { header: h, .. } => Some(h),
        _ => None,
    }
}

// Your original, correct setup_logging function
fn setup_logging(log_file_path: Option<PathBuf>, verbosity: &Verbosity<InfoLevel>) -> Result<Option<WorkerGuard>> {
    let console_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stdout)
        .with_target(false)
        .with_thread_ids(false)
        .without_time();

    let (file_layer, guard) = if let Some(ref path) = log_file_path {
        let log_file = File::create(path).with_context(|| format!("Failed to create log file at: {:?}", path))?;
        let (non_blocking_writer, guard) = tracing_appender::non_blocking(log_file);
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(non_blocking_writer)
            .with_ansi(false)
            .with_target(false);
        (Some(layer), Some(guard))
    } else {
        (None, None)
    };

    // This is the correct way to use the verbosity flag with tracing
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
