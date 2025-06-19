// src/bin/simple_logger.rs

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use clap::Parser;
use nusb::{Interface, transfer::RequestBuffer};
use std::time::Duration;
use tokio::{signal, time::sleep};
use tracing::{error, info, warn};
use tracing_subscriber;

use km003c_rs::protocol::{
    Attribute, CommandType, ENDPOINT_IN, ENDPOINT_OUT, PID, SensorDataPacket, VID,
};

// Captured payloads are still needed for the handshake.
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
    /// Run continuously until Ctrl+C is pressed, instead of for a fixed number of samples.
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

    // The select! macro allows us to run our main logic but also listen
    // for a Ctrl+C signal at the same time.
    tokio::select! {
        // Branch 1: The main application logic.
        res = run(cli) => {
            if let Err(e) = res {
                error!("Application failed: {:?}", e);
                std::process::exit(1);
            }
        }

        // Branch 2: The Ctrl+C signal handler.
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

    // Perform the full, captured startup sequence.
    perform_startup_sequence(&mut comms).await?;

    info!("--- Entering Data Polling Loop ---");
    let iterations = if cli.continuous {
        u32::MAX
    } else {
        cli.samples
    };

    for i in 0..iterations {
        comms
            .send_command(CommandType::GetData, Attribute::AdcQueue, None)
            .await?;
        let response = comms.read_response().await?;

        if response.len() == 52 {
            let sensor_bytes = Bytes::from(response.slice(..));
            match SensorDataPacket::try_from(sensor_bytes) {
                Ok(packet) => info!("[Sample {}] Parsed Sensor Data:\n{}", i + 1, packet),
                Err(e) => warn!(error = %e, "Failed to parse 52-byte polling response"),
            }
        } else {
            warn!(len=response.len(), data=?format!("{response:02x?}"), "Received unexpected response during polling");
        }
        sleep(Duration::from_millis(cli.interval_ms)).await;
    }

    info!("Finished polling.");
    Ok(())
}

/// Executes the full, captured startup sequence to prepare the device for data streaming.
async fn perform_startup_sequence(comms: &mut DeviceComms) -> Result<()> {
    info!("--- Starting Connection Handshake ---");
    comms
        .send_command(CommandType::Connect, Attribute::None, None)
        .await?;
    comms.expect_response(CommandType::Accept).await?;

    info!("--- Starting Authentication Replay ---");
    comms
        .send_command(
            CommandType::Authenticate,
            Attribute::from_u16(0x0101),
            Some(AUTH_PAYLOAD_1),
        )
        .await?;
    comms.read_and_discard().await?;
    comms.read_and_discard().await?;
    comms
        .send_command(
            CommandType::Authenticate,
            Attribute::from_u16(0x0101),
            Some(AUTH_PAYLOAD_2),
        )
        .await?;
    comms.read_and_discard().await?;
    comms.read_and_discard().await?;
    comms
        .send_command(
            CommandType::Authenticate,
            Attribute::from_u16(0x0101),
            Some(AUTH_PAYLOAD_3),
        )
        .await?;
    comms.read_and_discard().await?;
    comms.read_and_discard().await?;
    comms
        .send_command(
            CommandType::Authenticate,
            Attribute::from_u16(0x0101),
            Some(AUTH_PAYLOAD_4),
        )
        .await?;
    comms.read_and_discard().await?;
    comms.read_and_discard().await?;
    info!("--- Authentication Replay Complete ---");

    info!("--- Setting Recorder Mode ---");
    comms
        .send_command(
            CommandType::SetRecorderMode,
            Attribute::from_u16(0x0200),
            Some(SET_RECORDER_MODE_PAYLOAD),
        )
        .await?;
    comms.read_and_discard().await?;

    info!("--- Initial Info Dump ---");
    comms
        .send_command(CommandType::GetData, Attribute::PdPacket, None)
        .await?;
    comms.read_and_discard().await?;
    comms
        .send_command(CommandType::GetData, Attribute::from_u16(0x0400), None)
        .await?;
    comms.read_and_discard().await?;

    info!("--- Stopping Stream for Clean State ---");
    comms
        .send_command(CommandType::StopStream, Attribute::None, None)
        .await?;
    comms.expect_response(CommandType::Accept).await?;

    Ok(())
}

/// A helper struct to manage stateful communication with the device.
struct DeviceComms {
    interface: Interface,
    transaction_id: u8,
}
impl DeviceComms {
    fn new(interface: Interface) -> Self {
        Self {
            interface,
            transaction_id: 0,
        }
    }
    async fn send_command(
        &mut self,
        cmd: CommandType,
        attr: Attribute,
        payload: Option<&[u8]>,
    ) -> Result<()> {
        self.transaction_id = self.transaction_id.wrapping_add(1);
        let mut command = vec![cmd as u8, self.transaction_id];
        command.extend_from_slice(&attr.to_u16().to_le_bytes());
        if let Some(p) = payload {
            command.extend_from_slice(p);
        }
        let write_transfer = self.interface.bulk_out(ENDPOINT_OUT, command);
        match tokio::time::timeout(Duration::from_secs(1), write_transfer).await {
            Ok(completion) => completion
                .into_result()
                .context("USB write transfer failed")?,
            Err(_) => bail!("Timeout during USB write operation"),
        };
        Ok(())
    }
    async fn read_response(&self) -> Result<Bytes> {
        let read_transfer = self.interface.bulk_in(ENDPOINT_IN, RequestBuffer::new(512));
        let data = match tokio::time::timeout(Duration::from_secs(1), read_transfer).await {
            Ok(completion) => completion
                .into_result()
                .context("USB read transfer failed")?,
            Err(_) => bail!("Timeout during USB read operation"),
        };
        Ok(Bytes::from(data))
    }
    async fn expect_response(&mut self, expected_cmd: CommandType) -> Result<Bytes> {
        let response = self.read_response().await?;
        if response.len() < 4 {
            bail!("Response too short: {} bytes", response.len());
        }
        if response[0] != expected_cmd as u8 {
            bail!(
                "Expected response {:?}, but got {:#04x}",
                expected_cmd,
                response[0]
            );
        }
        if response[1] != self.transaction_id {
            warn!(
                "Mismatched transaction ID. Expected {}, got {}",
                self.transaction_id, response[1]
            );
        }
        info!(id=response[1], response=?expected_cmd, "Received expected response");
        Ok(response)
    }
    async fn read_and_discard(&self) -> Result<()> {
        let response = self.read_response().await?;
        info!(len = response.len(), "Discarding response packet.");
        Ok(())
    }
}
