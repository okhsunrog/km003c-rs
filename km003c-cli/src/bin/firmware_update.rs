use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use km003c_lib::device::{DeviceConfig, DeviceSelector, KM003C};
use km003c_lib::error::KMError;
use km003c_lib::firmware::{FirmwareImage, FirmwareUpdateStage, FirmwareUsbMode, find_firmware_device};
use std::error::Error;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(name = "firmware-update", about = "Verify and update POWER-Z KM003C firmware")]
struct Args {
    /// Official ChargerLAB .mencrypt firmware file
    firmware: PathBuf,
    /// USB serial number when more than one KM003C is connected
    #[arg(long)]
    serial: Option<String>,
    /// Validate and describe the firmware file without connecting to USB
    #[arg(long)]
    verify_only: bool,
    /// Check the package and connected device, then exit before confirmation
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let bytes = std::fs::read(&args.firmware)?;
    let image = FirmwareImage::parse(&bytes)?;
    println!(
        "Firmware: {} {} ({})",
        image.metadata.model, image.metadata.version, image.metadata.date
    );
    println!(
        "Image: {} bytes, CRC-32 {:08X}",
        image.metadata.size, image.metadata.crc32
    );
    if !image.metadata.notes_en.is_empty() {
        println!("\nRelease notes:\n{}", image.metadata.notes_en.trim());
    }
    if args.verify_only {
        println!("\nFirmware image CRC-32 verification passed.");
        return Ok(());
    }
    if image.metadata.model != "KM003C" {
        return Err(other(format!("firmware targets {}, not KM003C", image.metadata.model)).into());
    }

    let mut selector = args.serial.map(DeviceSelector::SerialNumber).unwrap_or_default();
    let device = find_firmware_device(&selector).await?;
    if let Some(port_selector) = &device.port_selector {
        selector = port_selector.clone();
    } else if selector == DeviceSelector::First
        && let Some(serial) = &device.serial_number
    {
        selector = DeviceSelector::SerialNumber(serial.clone());
    }
    println!(
        "\nDevice USB serial: {}",
        device.serial_number.as_deref().unwrap_or("unavailable")
    );
    println!("Device mode: {:?}", device.mode);

    let config = DeviceConfig::vendor().skip_reset().select(selector.clone());
    let mut app_connection = None;
    match device.mode {
        FirmwareUsbMode::Application => {
            let connected = KM003C::new(config.clone()).await?;
            let state = connected
                .state()
                .ok_or_else(|| other("device information is unavailable"))?;
            if state.model() != image.metadata.model {
                return Err(other(format!("connected model {} does not match firmware", state.model())).into());
            }
            println!("Current firmware: {}", state.firmware_version());
            println!("Target firmware: {}", image.metadata.version);
            app_connection = Some(connected);
        }
        FirmwareUsbMode::Dfu => {
            println!("Current firmware version is unavailable in DFU mode.");
            println!("Target firmware: {}", image.metadata.version);
        }
        FirmwareUsbMode::Other(ref label) => {
            return Err(other(format!("unrecognized device USB mode {label:?}; expected APP or DFU")).into());
        }
    }

    if args.check {
        println!("\nFirmware and device compatibility checks passed.");
        return Ok(());
    }

    print!("\nType UPDATE to erase and flash this device: ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if answer.trim() != "UPDATE" {
        println!("Cancelled.");
        return Ok(());
    }

    if let Some(mut connected) = app_connection {
        println!("Switching device to DFU mode...");
        connected.jump_to_dfu().await?;
        drop(connected);
        wait_for_mode(&selector, FirmwareUsbMode::Dfu, Duration::from_secs(20)).await?;
    }

    let mut updater = KM003C::open_maintenance(config.clone()).await?;
    let progress = ProgressBar::new(image.encrypted_data.len() as u64);
    progress.set_style(
        ProgressStyle::with_template("{msg:>12} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
            .progress_chars("=>-"),
    );
    progress.set_message("Connecting");
    let result = updater
        .update_firmware(&image, |update| {
            progress.set_position(update.bytes_written as u64);
            progress.set_message(match update.stage {
                FirmwareUpdateStage::Connecting => "Connecting",
                FirmwareUpdateStage::CheckingStatus => "Checking",
                FirmwareUpdateStage::Erasing => "Erasing",
                FirmwareUpdateStage::Writing => "Writing",
                FirmwareUpdateStage::Verifying => "Verifying",
                FirmwareUpdateStage::Complete => "Complete",
            });
        })
        .await;
    if let Err(error) = result {
        progress.abandon_with_message("Update failed");
        return Err(error.into());
    }
    progress.finish_with_message("Transfer complete");
    drop(updater);

    if wait_for_mode(&selector, FirmwareUsbMode::Application, Duration::from_secs(8))
        .await
        .is_err()
    {
        match find_firmware_device(&selector).await {
            Ok(device) if device.mode == FirmwareUsbMode::Dfu => {
                println!("Starting the updated application...");
                let mut bootloader = KM003C::open_maintenance(config.clone()).await?;
                bootloader.jump_to_application().await?;
            }
            Ok(_) | Err(KMError::DeviceNotFound) => {}
            Err(error) => return Err(error.into()),
        }
        wait_for_mode(&selector, FirmwareUsbMode::Application, Duration::from_secs(20)).await?;
    }

    let verified = KM003C::new(config).await?;
    let state = verified
        .state()
        .ok_or_else(|| other("updated device information is unavailable"))?;
    if state.firmware_version() != image.metadata.version {
        return Err(other(format!(
            "device restarted, but reports firmware {} instead of {}",
            state.firmware_version(),
            image.metadata.version
        ))
        .into());
    }
    println!("Update verified: {} {}", state.model(), state.firmware_version());
    Ok(())
}

async fn wait_for_mode(
    selector: &DeviceSelector,
    expected: FirmwareUsbMode,
    timeout: Duration,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        match find_firmware_device(selector).await {
            Ok(device) if device.mode == expected => return Ok(()),
            Ok(_) | Err(KMError::DeviceNotFound) => {}
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            return Err(other(format!("timed out waiting for USB mode {expected:?}")).into());
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

fn other(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}
