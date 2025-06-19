use anyhow::{Context, Result, bail};
use bytes::{Bytes, BytesMut};
use clap::Parser;
use nusb::{Interface, transfer::RequestBuffer};
use std::time::Duration;
use tokio::{signal, time::sleep};
use tracing::{debug, error, info, warn};
use tracing_subscriber;

// Use the clean, powerful protocol types
use km003c_rs::protocol::{
    Attribute, CommandType, Direction, ENDPOINT_IN, ENDPOINT_OUT, PID, Packet, VID,
};

// Handshake payloads are just the data part, the header is built dynamically.
const AUTH_PAYLOAD_1: &[u8] = &[
    0x33, 0xf8, 0x86, 0x0c, 0x00, 0x54, 0x28, 0x8c, 0xdc, 0x7e, 0x52, 0x72, 0x98, 0x26, 0x87, 0x2d,
    0xd1, 0x8b, 0x53, 0x9a, 0x39, 0xc4, 0x07, 0xd5, 0xc0, 0x63, 0xd9, 0x11, 0x02, 0xe3, 0x6a, 0x9e,
];
const AUTH_PAYLOAD_2: &[u8] = &[
    0x63, 0x6b, 0xea, 0xf3, 0xf0, 0x85, 0x65, 0x06, 0xee, 0xe9, 0xa2, 0x7e, 0x89, 0x72, 0x2d, 0xcf,
    0xd1, 0x8b, 0x53, 0x9a, 0x39, 0xc4, 0x07, 0xd5, 0xc0, 0x63, 0xd9, 0x11, 0x02, 0xe3, 0x6a, 0x9e,
];
const AUTH_PAYLOAD_3: &[u8] = &[
    0xc5, 0x11, 0x67, 0xae, 0x61, 0x3a, 0x6d, 0x46, 0xec, 0x84, 0xa6, 0xbd, 0xe8, 0xbd, 0x46, 0x2a,
    0xd1, 0x8b, 0x53, 0x9a, 0x39, 0xc4, 0x07, 0xd5, 0xc0, 0x63, 0xd9, 0x11, 0x02, 0xe3, 0x6a, 0x9e,
];
const AUTH_PAYLOAD_4: &[u8] = &[
    0x9c, 0x40, 0x9d, 0xeb, 0xc8, 0xdf, 0x53, 0xb8, 0x3b, 0x06, 0x6c, 0x31, 0x52, 0x50, 0xd0, 0x5c,
    0xd1, 0x8b, 0x53, 0x9a, 0x39, 0xc4, 0x07, 0xd5, 0xc0, 0x63, 0xd9, 0x11, 0x02, 0xe3, 0x6a, 0x9e,
];
const SET_RECORDER_MODE_PAYLOAD: &[u8] = &[
    0x4b, 0xe3, 0x63, 0x6c, 0x40, 0xbc, 0x10, 0x29, 0x89, 0x50, 0x96, 0xaa, 0xa3, 0xd2, 0x4f, 0xb7,
    0xf0, 0x9b, 0x3f, 0xfb, 0x91, 0xb6, 0x51, 0xf1, 0x58, 0x2d, 0x0c, 0x27, 0xe4, 0x8d, 0x43, 0xa2,
];

/// A simple logger to stream and display ADC data from a POWER-Z KM003C.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Run continuously until Ctrl+C is pressed.
    #[arg(short, long)]
    continuous: bool,
    /// Number of samples to fetch if not running continuously.
    #[arg(short, long, default_value_t = 10)]
    samples: u32,
    /// Polling interval in milliseconds.
    #[arg(short, long, default_value_t = 200)]
    interval_ms: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt().with_target(false).init();

    tokio::select! {
        res = run(cli) => {
            if let Err(e) = res {
                error!("Application failed: {:?}", e);
                std::process::exit(1);
            }
        }
        _ = signal::ctrl_c() => {
            info!("Ctrl+C received, shutting down gracefully.");
        }
    }
    Ok(())
}

async fn run(cli: Cli) -> Result<()> {
    info!("Searching for POWER-Z KM003C...");
    let device_info = nusb::list_devices()
        .context("Failed to list USB devices")?
        .find(|d| d.vendor_id() == VID && d.product_id() == PID)
        .context("POWER-Z KM003C not found. Is it connected?")?;
    info!(
        bus = device_info.bus_number(),
        addr = device_info.device_address(),
        "Found device"
    );

    let device = device_info.open().context("Failed to open USB device")?;
    info!("Performing USB device reset to ensure a clean state...");
    device.reset().context("Failed to reset the USB device.")?;
    sleep(Duration::from_millis(100)).await;

    let interface = device
        .detach_and_claim_interface(0)
        .context("Failed to claim interface")?;
    info!("Interface claimed successfully.");

    let mut comms = DeviceComms::new(interface);
    perform_startup_sequence(&mut comms).await?;

    info!("--- Entering Data Polling Loop ---");
    let iterations = if cli.continuous {
        u32::MAX
    } else {
        cli.samples
    };

    for i in 0..iterations {
        let response_packets = comms
            .transact(CommandType::GetData, Attribute::AdcQueue, None)
            .await?;
        if let Some(Packet::SensorData(sensor_packet)) = response_packets.first() {
            info!("[Sample {}] Parsed Sensor Data:\n{}", i + 1, sensor_packet);
        } else {
            warn!(
                "Received unexpected response during polling: {:?}",
                response_packets
            );
        }
        sleep(Duration::from_millis(cli.interval_ms)).await;
    }

    info!("Finished polling.");
    Ok(())
}

async fn perform_startup_sequence(comms: &mut DeviceComms) -> Result<()> {
    info!("--- Starting Connection Handshake ---");
    comms
        .transact_and_discard(CommandType::Connect, Attribute::None, None)
        .await?;

    info!("--- Starting Authentication Replay ---");
    comms
        .transact_and_discard(
            CommandType::Authenticate,
            Attribute::Unknown(0x0101),
            Some(AUTH_PAYLOAD_1),
        )
        .await?;
    comms
        .transact_and_discard(
            CommandType::Authenticate,
            Attribute::Unknown(0x0101),
            Some(AUTH_PAYLOAD_2),
        )
        .await?;
    comms
        .transact_and_discard(
            CommandType::Authenticate,
            Attribute::Unknown(0x0101),
            Some(AUTH_PAYLOAD_3),
        )
        .await?;
    comms
        .transact_and_discard(
            CommandType::Authenticate,
            Attribute::Unknown(0x0101),
            Some(AUTH_PAYLOAD_4),
        )
        .await?;
    info!("--- Authentication Replay Complete ---");

    info!("--- Setting Recorder Mode ---");
    // THIS IS THE CORRECT, EXPLICIT HANDLING
    // We call a special version of transact because we know this command has a non-standard response ID.
    comms
        .transact_with_expected_id(
            CommandType::CommandWithPayload,
            Attribute::Unknown(0x0200),
            Some(SET_RECORDER_MODE_PAYLOAD),
            0, // We explicitly expect the response to have transaction ID 0
        )
        .await?;

    info!("--- Initial Info Dump ---");
    comms.transact_and_discard(CommandType::GetData, Attribute::GetDeviceInfo, None).await?;
    comms.transact_and_discard(CommandType::GetData, Attribute::Unknown(0x0400), None).await?;

    info!("--- Stopping Stream for Clean State ---");
    comms
        .transact_and_discard(CommandType::StopStream, Attribute::None, None)
        .await?;

    Ok(())
}

/// A helper struct to manage stateful communication with the device.
struct DeviceComms {
    interface: Interface,
    transaction_id: u8,
}

impl DeviceComms {
    // ... new, next_id, build_command_bytes, send_bytes are correct ...
    fn new(interface: Interface) -> Self {
        Self {
            interface,
            transaction_id: 0,
        }
    }

    fn next_id(&mut self) -> u8 {
        self.transaction_id = self.transaction_id.wrapping_add(1);
        self.transaction_id
    }

    fn build_command_bytes(
        id: u8,
        cmd: CommandType,
        attr: Attribute,
        payload: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut command = BytesMut::with_capacity(64);
        command.extend_from_slice(&[cmd as u8, id]);
        command.extend_from_slice(&u16::from(attr).to_le_bytes());
        if let Some(p) = payload {
            command.extend_from_slice(p);
        }
        command.to_vec()
    }

    async fn send_bytes(&self, data: Vec<u8>) -> Result<()> {
        debug!(bytes = hex::encode(&data), "USB Write");
        let write_transfer = self.interface.bulk_out(ENDPOINT_OUT, data);
        match tokio::time::timeout(Duration::from_secs(1), write_transfer).await {
            Ok(completion) => completion
                .into_result()
                .context("USB write transfer failed")?,
            Err(_) => bail!("Timeout during USB write operation"),
        };
        Ok(())
    }

    // A helper for transact_and_discard
    pub async fn transact(
        &mut self,
        cmd: CommandType,
        attr: Attribute,
        payload: Option<&[u8]>,
    ) -> Result<Vec<Packet>> {
        let id = self.next_id();
        self.transact_with_expected_id(cmd, attr, payload, id).await
    }

    // A helper to just run a transaction and ignore the result, used for most of the startup sequence.
    async fn transact_and_discard(
        &mut self,
        cmd: CommandType,
        attr: Attribute,
        payload: Option<&[u8]>,
    ) -> Result<()> {
        self.transact(cmd, attr, payload).await?;
        Ok(())
    }

    // THE MAIN TRANSACTION FUNCTION, NOW WITH AN EXPECTED ID
    pub async fn transact_with_expected_id(
        &mut self,
        cmd: CommandType,
        attr: Attribute,
        payload: Option<&[u8]>,
        expected_id: u8,
    ) -> Result<Vec<Packet>> {
        let send_id = if cmd == CommandType::CommandWithPayload {
            self.next_id() // Use a real ID for the command itself
        } else {
            expected_id
        };

        let command_bytes = Self::build_command_bytes(send_id, cmd, attr, payload);
        self.send_bytes(command_bytes).await?;

        let mut responses = Vec::new();

        // Loop to read all parts of a response.
        loop {
            let packet =
                match tokio::time::timeout(Duration::from_secs(1), self.read_raw_packet()).await {
                    Ok(Ok(p)) => p,              // Got packet successfully
                    Ok(Err(e)) => return Err(e), // USB error
                    Err(_) => {
                        // Timeout
                        if !responses.is_empty() {
                            // Timeout after getting at least one response is OK.
                            break;
                        } else {
                            // Timeout waiting for the very first response.
                            bail!(
                                "Timeout waiting for response to {:?} (sent ID {}, expected ID {})",
                                cmd,
                                send_id,
                                expected_id
                            );
                        }
                    }
                };

            let is_relevant = match &packet {
                Packet::Acknowledge { header, .. } => header.transaction_id == expected_id,
                Packet::GenericResponse { header, .. } => header.transaction_id == expected_id,
                Packet::SensorData(sd) => sd.header.to_le_bytes().get(1) == Some(&expected_id),
                Packet::DataChunk(_) => true, // Always keep associated data chunks.
                _ => false,
            };

            if is_relevant {
                responses.push(packet);
            } else {
                warn!(
                    "Discarding unexpected packet during transaction: {:?}",
                    packet
                );
            }

            // If the relevant packet is not a DataChunk, we can stop.
            if is_relevant && !matches!(responses.last().unwrap(), Packet::DataChunk(_)) {
                // But wait a tiny bit to see if a DataChunk follows
                if tokio::time::timeout(Duration::from_millis(50), self.read_raw_packet())
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }

        info!(
            ?cmd,
            ?attr,
            "Transaction complete, received {} relevant response packet(s)",
            responses.len()
        );
        Ok(responses)
    }

    async fn read_raw_packet(&self) -> Result<Packet> {
        let read_transfer = self.interface.bulk_in(ENDPOINT_IN, RequestBuffer::new(512));
        let data = read_transfer.await.into_result()?;
        debug!(bytes = hex::encode(&data), "USB Read");
        Ok(Packet::from_bytes(
            Bytes::from(data),
            Direction::DeviceToHost,
        ))
    }
}
