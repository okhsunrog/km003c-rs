use crate::{Result, cli::ConnectionOptions};
use clap::{Args, Subcommand};
use km003c_lib::firmware::catalog::FirmwareCatalogClient;
use km003c_lib::firmware::{
    FirmwareDeviceCheck, FirmwareImage, FirmwareInstallProgress, PreparedFirmwareUpdate, check_firmware_device,
};
use km003c_lib::{DeviceSelector, error::KMError};
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Validate a local .mencrypt package and show release notes, without USB.
    Inspect(PackageArgs),
    /// Check package and attached device, without rebooting or writing flash.
    Check(PackageArgs),
    /// Erase and install a package; older versions are also accepted.
    Update {
        #[command(flatten)]
        package: PackageArgs,
        /// Save the current application here before flashing (required in APP mode).
        #[arg(long)]
        backup: Option<PathBuf>,
        /// Confirm erasing and flashing the selected meter.
        #[arg(long, required = true)]
        yes: bool,
    },
    /// List official releases and descriptions, without USB.
    List,
    /// Download and validate an official release, without USB.
    Download {
        /// Exact catalog version, including older releases.
        version: String,
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[derive(Debug, Args)]
pub struct PackageArgs {
    /// ChargerLAB .mencrypt package.
    pub file: PathBuf,
}

fn read_image(path: &Path) -> Result<FirmwareImage> {
    // Bound allocation before decrypting input supplied on the command line.
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err("firmware package exceeds 2 MiB".into());
    }
    let image = FirmwareImage::parse(&bytes)?;
    image.validate_for_update()?;
    Ok(image)
}

pub async fn run(connection: ConnectionOptions, command: Command) -> Result {
    let (package, update) = match command {
        Command::List => return list().await,
        Command::Download { version, output } => return download(&version, &output).await,
        Command::Inspect(package) => {
            describe(&read_image(&package.file)?);
            return Ok(());
        }
        Command::Check(package) => (package, None),
        Command::Update {
            package,
            backup,
            yes: _,
        } => (package, Some(backup)),
    };
    let image = read_image(&package.file)?;
    describe(&image);
    let selector = connection.serial.map(DeviceSelector::SerialNumber).unwrap_or_default();
    let Some(backup_path) = update else {
        let check = check_firmware_device(&image, selector).await?;
        describe_device(&check, &image.metadata().version);
        println!("Package and device checks passed. No reboot or flash write performed.");
        return Ok(());
    };
    let prepared = PreparedFirmwareUpdate::prepare(image, selector, progress).await?;
    describe_device(prepared.device(), &prepared.image().metadata().version);
    let installed = prepared
        .install(
            move |backup| async move {
                let path = backup_path.ok_or_else(|| {
                    KMError::Protocol(
                        "--backup PATH is required to preserve the current application before updating".into(),
                    )
                })?;
                save_new(&path, backup.data())?;
                println!("Verified backup saved to {}", path.display());
                Ok(())
            },
            progress,
        )
        .await?;
    eprintln!();
    println!(
        "Verified installed firmware {} by full readback ({} bytes, including committed size and CRC).",
        installed.firmware.version, installed.bytes_verified
    );
    Ok(())
}

fn progress(p: FirmwareInstallProgress) {
    eprint!("\r{:?}: {}/{} bytes           ", p.stage, p.bytes_done, p.total_bytes);
}
fn describe_device(check: &FirmwareDeviceCheck, target: &str) {
    println!(
        "Device: serial {}, mode {:?}",
        check.usb.serial_number.as_deref().unwrap_or("unavailable"),
        check.usb.mode
    );
    println!(
        "Hardware: {}; current firmware: {}; target: {}",
        check.info.hw_version,
        check
            .installed
            .as_ref()
            .map(|i| i.version.as_str())
            .unwrap_or("unavailable in DFU"),
        target
    );
}

async fn list() -> Result {
    let catalog = FirmwareCatalogClient::new()?.fetch().await?;
    for release in catalog.releases() {
        println!(
            "{}  {}  {} bytes  CRC32 {:08X}{}{}",
            release.version,
            release.date,
            release.size,
            release.crc32,
            if release.latest { "  latest" } else { "" },
            if release.stable { "  stable" } else { "" }
        );
        if !release.notes_en.is_empty() {
            println!("{}", release.notes_en);
        }
        if !release.notes_zh.is_empty() {
            println!("{}", release.notes_zh);
        }
        println!();
    }
    Ok(())
}
async fn download(version: &str, output: &Path) -> Result {
    let client = FirmwareCatalogClient::new()?;
    let catalog = client.fetch().await?;
    let release = catalog
        .release(version)
        .ok_or("version not present in official catalog")?;
    let package = client.download(release).await?;
    save_new(output, package.package())?;
    println!(
        "Downloaded and validated {} to {} (SHA256 {})",
        package.image().metadata().version,
        output.display(),
        hex::encode(package.sha256())
    );
    Ok(())
}

fn describe(image: &FirmwareImage) {
    let m = image.metadata();
    println!(
        "Firmware: {} {} ({})\nImage: {} bytes; CRC32 {:08X}; ciphertext: {} bytes; outer trailer: {} bytes",
        m.model,
        m.version,
        m.date,
        m.size,
        m.crc32,
        image.encrypted_data().len(),
        image.trailer().len()
    );
    if !m.notes_en.is_empty() {
        println!("\n{}", m.notes_en);
    }
    if !m.notes_zh.is_empty() {
        println!("\n{}", m.notes_zh);
    }
}

fn save_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
    output.write_all(bytes)?;
    output.sync_all()
}
