use std::error::Error;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use km003c_lib::uom::si::electric_charge::milliampere_hour;
use km003c_lib::uom::si::electric_current::ampere;
use km003c_lib::uom::si::electric_potential::volt;
use km003c_lib::uom::si::energy::milliwatt_hour;
use km003c_lib::uom::si::power::watt;
use km003c_lib::uom::si::time::{millisecond, second};
use km003c_lib::{DeviceConfig, KM003C, LogMetadata, OfflineLog};
use serde_json::json;

/// Inspect or download the selected offline recording from a POWER-Z KM003C.
#[derive(Debug, Parser)]
#[command(
    version,
    about = "Inspect or download offline recordings from a POWER-Z KM003C",
    long_about = None
)]
struct Args {
    #[command(subcommand)]
    command: Command,

    /// Show protocol and USB debug logs.
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Skip USB reset (defaults to true on macOS for compatibility).
    #[arg(long, default_value_t = cfg!(target_os = "macos"), global = true)]
    no_reset: bool,

    /// Force USB reset even on macOS (overrides --no-reset).
    #[arg(long, global = true)]
    reset: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Display metadata without downloading sample data.
    Metadata {
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Download all samples and write them to a file.
    Download {
        /// Output format.
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Csv)]
        format: OutputFormat,

        /// Output path. Defaults to <device-filename>.csv or .json.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Csv,
    Json,
}

impl OutputFormat {
    const fn extension(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Json => "json",
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let log_level = if args.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::WARN
    };
    tracing_subscriber::fmt().with_max_level(log_level).init();

    let mut config = DeviceConfig::vendor();
    if args.no_reset && !args.reset {
        config = config.skip_reset();
    }
    let mut device = KM003C::new(config).await?;

    match args.command {
        Command::Metadata { json } => {
            let Some(metadata) = device.request_log_metadata().await? else {
                println!("No offline log is selected on the device.");
                return Ok(());
            };
            print_metadata(&metadata, json)?;
        }
        Command::Download { format, output } => {
            let Some(metadata) = device.request_log_metadata().await? else {
                println!("No offline log is selected on the device.");
                return Ok(());
            };
            let path = output.unwrap_or_else(|| default_output_path(&metadata, format));
            let log = device.download_offline_log(metadata).await?;
            write_log(&path, format, &log)?;
            println!("Wrote {} samples to {}", log.samples.len(), path.display());
        }
    }

    Ok(())
}

fn metadata_json(metadata: &LogMetadata) -> serde_json::Value {
    json!({
        "filename": metadata.filename_lossy(),
        "filename_raw": metadata.filename_raw,
        "sample_count": metadata.sample_count,
        "interval_ms": metadata.interval.get::<millisecond>(),
        "flags": metadata.flags,
        "recorded_duration_seconds": metadata.recorded_duration.get::<second>(),
        "calculated_duration_seconds": metadata.calculated_duration().get::<second>(),
        "unknown_0x10": metadata.unknown_0x10,
        "opaque_tail": hex::encode(metadata.opaque_tail),
    })
}

fn print_metadata(metadata: &LogMetadata, as_json: bool) -> Result<(), Box<dyn Error>> {
    if as_json {
        println!("{}", serde_json::to_string_pretty(&metadata_json(metadata))?);
    } else {
        println!("Filename:            {}", metadata.filename_lossy());
        println!("Samples:             {}", metadata.sample_count);
        println!("Interval:            {} ms", metadata.interval.get::<millisecond>());
        println!("Recorded duration:   {} s", metadata.recorded_duration.get::<second>());
        println!(
            "Calculated duration: {} s",
            metadata.calculated_duration().get::<second>()
        );
        println!("Data size:           {} bytes", metadata.data_size());
        println!("Flags:               0x{:04x}", metadata.flags);
        println!("Unknown field 0x10:  0x{:04x}", metadata.unknown_0x10);
        println!("Opaque tail:         {}", hex::encode(metadata.opaque_tail));
    }
    Ok(())
}

fn default_output_path(metadata: &LogMetadata, format: OutputFormat) -> PathBuf {
    let device_filename = metadata.filename_lossy();
    let filename = Path::new(device_filename.as_ref())
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("offline-log");
    PathBuf::from(format!("{filename}.{}", format.extension()))
}

fn write_log(path: &Path, format: OutputFormat, log: &OfflineLog) -> Result<(), Box<dyn Error>> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    match format {
        OutputFormat::Csv => write_csv(&mut writer, log)?,
        OutputFormat::Json => write_json(&mut writer, log)?,
    }
    writer.flush()?;
    Ok(())
}

fn write_csv(mut writer: impl Write, log: &OfflineLog) -> Result<(), std::io::Error> {
    writeln!(
        writer,
        "index,elapsed_seconds,voltage_uv,current_ua,power_w,charge_uah,energy_uwh,voltage_v,current_a,charge_mah,energy_mwh"
    )?;
    let interval_seconds = log.metadata.interval.get::<second>();
    for (index, sample) in log.samples.iter().enumerate() {
        let raw = sample.raw();
        writeln!(
            writer,
            "{index},{},{},{},{},{},{},{},{},{},{}",
            index as f64 * interval_seconds,
            raw.voltage_uv,
            raw.current_ua,
            sample.power.get::<watt>(),
            raw.charge_uah,
            raw.energy_uwh,
            sample.voltage.get::<volt>(),
            sample.current.get::<ampere>(),
            sample.charge.get::<milliampere_hour>(),
            sample.energy.get::<milliwatt_hour>(),
        )?;
    }
    Ok(())
}

fn write_json(mut writer: impl Write, log: &OfflineLog) -> Result<(), Box<dyn Error>> {
    let interval_seconds = log.metadata.interval.get::<second>();
    let samples = log
        .samples
        .iter()
        .enumerate()
        .map(|(index, sample)| {
            let raw = sample.raw();
            json!({
                "index": index,
                "elapsed_seconds": index as f64 * interval_seconds,
                "voltage_uv": raw.voltage_uv,
                "current_ua": raw.current_ua,
                "power_w": sample.power.get::<watt>(),
                "charge_uah": raw.charge_uah,
                "energy_uwh": raw.energy_uwh,
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_writer_pretty(
        &mut writer,
        &json!({
            "metadata": metadata_json(&log.metadata),
            "samples": samples,
        }),
    )?;
    writeln!(writer)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use km003c_lib::LogMetadata;
    use km003c_lib::uom::si::f64::Time;

    use super::*;

    fn metadata(filename: &[u8]) -> LogMetadata {
        let mut filename_raw = [0; 16];
        filename_raw[..filename.len()].copy_from_slice(filename);
        LogMetadata {
            filename_raw,
            unknown_0x10: 0,
            sample_count: 0,
            interval: Time::new::<millisecond>(1_000.0),
            flags: 0,
            recorded_duration: Time::new::<second>(0.0),
            opaque_tail: [0; 20],
        }
    }

    #[test]
    fn default_path_preserves_the_device_extension() {
        assert_eq!(
            default_output_path(&metadata(b"A01.d"), OutputFormat::Csv),
            PathBuf::from("A01.d.csv")
        );
    }

    #[test]
    fn default_path_drops_device_directories() {
        assert_eq!(
            default_output_path(&metadata(b"../A01.d"), OutputFormat::Json),
            PathBuf::from("A01.d.json")
        );
    }

    #[test]
    fn exports_exact_raw_sample_values() {
        let mut metadata = metadata(b"A01.d");
        metadata.sample_count = 1;
        let bytes = hex::decode("81494c0021f0e2ff56ebffffb998ffff").unwrap();
        let log = OfflineLog::from_bytes(metadata, &bytes).unwrap();

        let mut csv = Vec::new();
        write_csv(&mut csv, &log).unwrap();
        let csv = String::from_utf8(csv).unwrap();
        assert!(csv.contains("0,0,4999553,-1904607,"));
        assert!(csv.contains(",-5290,-26439,"));

        let mut json = Vec::new();
        write_json(&mut json, &log).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(value["samples"][0]["voltage_uv"], 4_999_553);
        assert_eq!(value["samples"][0]["current_ua"], -1_904_607);
        assert_eq!(value["samples"][0]["charge_uah"], -5_290);
        assert_eq!(value["samples"][0]["energy_uwh"], -26_439);
    }
}
