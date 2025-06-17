// src/bin/hello_adc.rs

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use nusb::{transfer::RequestBuffer, Device, Interface};
use std::time::Duration;
use tracing::{error, info, warn};
use tracing_subscriber;

use km003c_rs::protocol::{
    Attribute, CommandType, SensorDataPacket, ENDPOINT_IN, ENDPOINT_OUT, PID, VID,
};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    if let Err(e) = run().await {
        error!("Application failed: {:?}", e);
        std::process::exit(1);
    }
    Ok(())
}


async fn run() -> Result<()> {
    info!("Searching for POWER-Z KM003C...");
    let device_info = nusb::list_devices()
        .context("Failed to list USB devices")?
        .find(|d| d.vendor_id() == VID && d.product_id() == PID)
        .context("POWER-Z KM003C not found. Is it connected?")?;
    info!(bus = device_info.bus_number(), addr = device_info.device_address(), "Found device");

    let device = device_info.open().context("Failed to open USB device")?;
    let interface = device.detach_and_claim_interface(0).context("Failed to claim interface")?;
    info!("Interface claimed successfully.");

    let mut comms = DeviceComms::new(interface);

    // --- Step 1: Connect ---
    comms.send_command(CommandType::Connect, Attribute::None, None).await?;
    comms.expect_response(CommandType::Accept).await?;
    info!("Handshake complete.");

    // --- Step 2: Request Data (First part of a two-part request) ---
    info!("Requesting data (part 1)...");
    comms.send_command(CommandType::GetData, Attribute::Adc, None).await?;
    let ack_response = comms.expect_response(CommandType::StatusA).await?;
    info!(data=?format!("{ack_response:02x?}"), "Received ACK from device. It should now be ready to send data.");

    // --- Step 3: Fetch the Prepared Data (Hypothesis) ---
    // Let's try sending the exact same command again to see if it now returns the data.
    info!("Fetching prepared data (part 2)...");
    comms.send_command(CommandType::GetData, Attribute::Adc, None).await?;
    let data_response = comms.read_response().await?;

    // Now, we expect the 52-byte sensor data packet (still prefixed with a StatusA header)
    if data_response.len() >= 56 && data_response[0] == CommandType::StatusA as u8 {
        let sensor_bytes = Bytes::from(data_response.slice(4..));
        match SensorDataPacket::try_from(sensor_bytes) {
           Ok(packet) => {
               info!("Successfully parsed Sensor Data Packet:\n{}", packet);
           }
           Err(e) => {
               bail!("Failed to parse sensor data from response: {}", e);
           }
        }
    } else {
        bail!("Received unexpected response when fetching data: len={}, data={:02x?}", data_response.len(), data_response);
    }

    info!("Communication finished successfully.");
    Ok(())
}

/// A helper struct to manage stateful communication with the device.
struct DeviceComms {
    interface: Interface,
    transaction_id: u8,
}

impl DeviceComms {
    fn new(interface: Interface) -> Self {
        Self { interface, transaction_id: 0 }
    }

// ... inside impl DeviceComms ...

    async fn send_command(&mut self, cmd: CommandType, attr: Attribute, payload: Option<&[u8]>) -> Result<()> {
        self.transaction_id = self.transaction_id.wrapping_add(1);
        let mut command = vec![cmd as u8, self.transaction_id];
        command.extend_from_slice(&(attr as u16).to_le_bytes());
        if let Some(p) = payload {
            command.extend_from_slice(p);
        }

        info!(id=self.transaction_id, command=?cmd, attribute=?attr, "Sending command");
        let write_transfer = self.interface.bulk_out(ENDPOINT_OUT, command);
        match tokio::time::timeout(Duration::from_secs(1), write_transfer).await {
            Ok(completion) => completion.into_result().context("USB write transfer failed")?,
            Err(_) => bail!("Timeout during USB write operation"),
        }; // <--- ADD THE SEMICOLON HERE

        Ok(())
    }
    async fn read_response(&self) -> Result<Bytes> {
        let read_transfer = self.interface.bulk_in(ENDPOINT_IN, RequestBuffer::new(512));
        let data = match tokio::time::timeout(Duration::from_secs(1), read_transfer).await {
            Ok(completion) => completion.into_result().context("USB read transfer failed")?,
            Err(_) => bail!("Timeout during USB read operation"),
        };
        Ok(Bytes::from(data))
    }

    async fn expect_response(&self, expected_cmd: CommandType) -> Result<Bytes> {
        let response = self.read_response().await?;
        if response.len() < 4 {
            bail!("Response too short: {} bytes", response.len());
        }
        if response[0] != expected_cmd as u8 {
            bail!("Expected response {:?}, but got {:#04x}", expected_cmd, response[0]);
        }
        if response[1] != self.transaction_id {
            bail!("Mismatched transaction ID. Expected {}, got {}", self.transaction_id, response[1]);
        }
        info!(id=response[1], response=?expected_cmd, "Received expected response");
        Ok(response)
    }
}