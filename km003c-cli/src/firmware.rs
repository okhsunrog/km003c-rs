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
    /// Download and install a release; defaults to the latest available build.
    Install {
        /// Catalog version or build ID. Omit to install the latest release.
        version: Option<String>,
        /// Save the current application here before flashing (required in APP mode).
        #[arg(long)]
        backup: Option<PathBuf>,
        /// Confirm erasing and flashing the selected meter.
        #[arg(long, required = true)]
        yes: bool,
    },
    /// List archived manufacturer releases and descriptions, without USB.
    List,
    /// Download and validate a release from the public mirror, without USB.
    Download {
        /// Catalog version or build ID (required when a version has multiple builds).
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
    let (image, update) = match command {
        Command::List => return list().await,
        Command::Download { version, output } => return download(&version, &output).await,
        Command::Inspect(package) => {
            describe(&read_image(&package.file)?);
            return Ok(());
        }
        Command::Check(package) => (read_image(&package.file)?, None),
        Command::Update {
            package,
            backup,
            yes: _,
        } => (read_image(&package.file)?, Some(backup)),
        Command::Install {
            version,
            backup,
            yes: _,
        } => {
            let client = FirmwareCatalogClient::new()?;
            let package = if let Some(version) = version {
                client.download_selected(&version).await?
            } else {
                let catalog = client.fetch().await?;
                if let Some(reason) = catalog.fallback_reason() {
                    eprintln!("Official catalog unavailable: {reason}; using the archive mirror.");
                }
                let release = catalog.latest_release()?;
                println!("Selected latest release {} (build ID: {})", release.version, release.id);
                client.download(release).await?
            };
            println!(
                "Downloaded and validated package (source: {}; SHA256 {})",
                package.source().label(),
                hex::encode(package.sha256())
            );
            if let Some(reason) = package.fallback_reason() {
                eprintln!("Official download unavailable: {reason}; used the archive mirror.");
            }
            let (_, image) = package.into_parts();
            (image, Some(backup))
        }
    };
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
    println!("Source: {}", catalog.source().label());
    if let Some(reason) = catalog.fallback_reason() {
        eprintln!("Official catalog unavailable: {reason}; using the archive mirror.");
    }
    match catalog.latest_release() {
        Ok(release) => println!("Default installation: {} (build ID: {})", release.version, release.id),
        Err(error) => eprintln!("Cannot select a default release: {error}"),
    }
    for release in catalog.releases() {
        println!(
            "{}  {}  {} bytes  CRC32 {:08X}{}{}\n  Build ID: {}",
            release.version,
            release.date,
            release.size,
            release.crc32,
            if release.latest { "  latest" } else { "" },
            if release.stable { "  stable" } else { "" },
            release.id,
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
    let package = client.download_selected(version).await?;
    save_new(output, package.package())?;
    println!(
        "Downloaded and validated {} to {} (source: {}; SHA256 {})",
        package.image().metadata().version,
        output.display(),
        package.source().label(),
        hex::encode(package.sha256())
    );
    if let Some(reason) = package.fallback_reason() {
        eprintln!("Official download unavailable: {reason}; used the archive mirror.");
    }
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
