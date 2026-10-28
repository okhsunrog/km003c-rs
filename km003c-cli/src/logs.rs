use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand, ValueEnum};
use km003c_lib::recording::{RecordingFormat, RecordingMetadata, write_offline_recording};
use km003c_lib::uom::si::power::watt;
use km003c_lib::uom::si::time::{millisecond, second};
use km003c_lib::{KM003C, LogMetadata, OfflineLog, OfflineRecordingView};
use serde_json::json;

use crate::Result;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List the recordings stored on the meter.
    List {
        /// Print machine-readable metadata.
        #[arg(long)]
        json: bool,
    },
    /// Download a recording as CSV, Parquet, or JSON.
    Download(DownloadArgs),
}

#[derive(Debug, Args)]
pub struct DownloadArgs {
    #[command(flatten)]
    pub selection: Selection,
    /// Output format; inferred from --output, otherwise CSV.
    #[arg(short, long, value_enum)]
    pub format: Option<OutputFormat>,
    /// Output path; defaults to `<device-filename>.<format>`.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct Selection {
    /// Zero-based index printed by `logs list`.
    #[arg(short, long)]
    pub index: Option<usize>,
    /// Select the highest numbered `A<number>.d` recording; no timestamps are available.
    #[arg(long)]
    pub latest: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Csv,
    Parquet,
    Json,
}

impl OutputFormat {
    const fn extension(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Parquet => "parquet",
            Self::Json => "json",
        }
    }
}

impl DownloadArgs {
    pub fn output_format(&self) -> Result<OutputFormat> {
        let extension_format = self
            .output
            .as_deref()
            .and_then(Path::extension)
            .and_then(|extension| extension.to_str())
            .and_then(|extension| {
                OutputFormat::value_variants()
                    .iter()
                    .copied()
                    .find(|format| extension.eq_ignore_ascii_case(format.extension()))
            });
        if let (Some(explicit), Some(extension)) = (self.format, extension_format)
            && explicit != extension
        {
            return Err("--format does not match the output filename extension".into());
        }
        Ok(self.format.or(extension_format).unwrap_or(OutputFormat::Csv))
    }
}

pub async fn run(device: &mut KM003C, command: Command) -> Result {
    let catalog = device.request_log_metadata().await?;
    match command {
        Command::List { json } => {
            if !json && catalog.is_empty() {
                println!("No offline logs are stored on the device.");
            } else {
                print_metadata_list(&catalog, json)?;
            }
        }
        Command::Download(args) => {
            let format = args.output_format()?;
            let metadata = select_log(&catalog, &args.selection)?.clone();
            let path = args.output.unwrap_or_else(|| default_output_path(&metadata, format));
            let log = device.download_offline_log(metadata).await?;
            let count = log.samples.len();
            let metadata = RecordingMetadata::from(device.state().ok_or("device information is unavailable")?);
            write_log(&path, format, &metadata, log)?;
            println!("Wrote {count} samples to {}", path.display());
        }
    }
    Ok(())
}

fn write_log(path: &Path, format: OutputFormat, metadata: &RecordingMetadata, log: OfflineLog) -> Result {
    match format {
        OutputFormat::Json => {
            let mut writer = BufWriter::new(File::create(path)?);
            write_json(&mut writer, &log)?;
            writer.flush()?;
        }
        OutputFormat::Csv | OutputFormat::Parquet => {
            let format = match format {
                OutputFormat::Csv => RecordingFormat::Csv,
                _ => RecordingFormat::Parquet,
            };
            write_offline_recording(path, format, metadata, &OfflineRecordingView::new(log))?;
        }
    }
    Ok(())
}

fn select_log<'a>(catalog: &'a [LogMetadata], selection: &Selection) -> Result<&'a LogMetadata> {
    if catalog.is_empty() {
        return Err("no offline logs are stored on the device".into());
    }
    if let Some(index) = selection.index {
        return catalog.get(index).ok_or_else(|| {
            format!(
                "offline log index {index} is out of range; device reported {} logs",
                catalog.len()
            )
            .into()
        });
    }
    let mut numbered = Vec::with_capacity(catalog.len());
    for metadata in catalog {
        let filename = metadata.filename()?;
        let number = filename
            .strip_prefix('A')
            .and_then(|name| name.strip_suffix(".d"))
            .and_then(|number| number.parse::<u32>().ok())
            .ok_or_else(|| format!("cannot determine latest recording from filename {filename:?}; use --index"))?;
        numbered.push((number, metadata));
    }
    numbered
        .into_iter()
        .max_by_key(|(number, _)| *number)
        .map(|(_, metadata)| metadata)
        .ok_or_else(|| "no offline logs are stored on the device".into())
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
        "final_charge_uah": metadata.final_charge_raw_uah(),
        "final_energy_uwh": metadata.final_energy_raw_uwh(),
        "data_offset": metadata.data_offset,
        "data_address": metadata.data_address().ok(),
        "reserved_tail": hex::encode(metadata.reserved_tail),
    })
}

fn print_metadata(metadata: &LogMetadata) -> Result {
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
    println!("Final charge:        {} µAh", metadata.final_charge_raw_uah());
    println!("Final energy:        {} µWh", metadata.final_energy_raw_uwh());
    println!("Data offset:         0x{:08x}", metadata.data_offset);
    println!("Data address:        0x{:08x}", metadata.data_address()?);
    println!("Reserved tail:       {}", hex::encode(metadata.reserved_tail));
    Ok(())
}

fn print_metadata_list(metadata: &[LogMetadata], as_json: bool) -> Result {
    if as_json {
        let entries = metadata.iter().map(metadata_json).collect::<Vec<_>>();
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        for (index, entry) in metadata.iter().enumerate() {
            if index > 0 {
                println!();
            }
            println!("Offline log #{index}");
            print_metadata(entry)?;
        }
    }
    Ok(())
}

pub(crate) fn default_output_path(metadata: &LogMetadata, format: OutputFormat) -> PathBuf {
    let device_filename = metadata.filename_lossy();
    let filename = Path::new(device_filename.as_ref())
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("offline-log");
    PathBuf::from(format!("{filename}.{}", format.extension()))
}

fn write_json(mut writer: impl Write, log: &OfflineLog) -> Result {
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
    use km003c_lib::recording::read_recording;
    use km003c_lib::uom::si::electric_charge::microampere_hour;
    use km003c_lib::uom::si::energy::microwatt_hour;
    use km003c_lib::uom::si::f64::{ElectricCharge, Energy, Time};

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
            final_charge: ElectricCharge::new::<microampere_hour>(0.0),
            final_energy: Energy::new::<microwatt_hour>(0.0),
            data_offset: 0,
            reserved_tail: [0; 8],
        }
    }

    fn captured_log() -> OfflineLog {
        let mut metadata = metadata(b"A01.d");
        metadata.sample_count = 1;
        metadata.final_charge = ElectricCharge::new::<microampere_hour>(-5_290.0);
        metadata.final_energy = Energy::new::<microwatt_hour>(-26_439.0);
        let bytes = hex::decode("81494c0021f0e2ff56ebffffb998ffff").unwrap();
        OfflineLog::from_bytes(metadata, &bytes).unwrap()
    }

    #[test]
    fn latest_uses_numeric_filenames_rather_than_catalog_or_lexical_order() {
        let catalog = [metadata(b"A9.d"), metadata(b"A10.d"), metadata(b"A02.d")];
        let latest = Selection {
            index: None,
            latest: true,
        };
        assert_eq!(select_log(&catalog, &latest).unwrap().filename_bytes(), b"A10.d");
        let index = Selection {
            index: Some(2),
            latest: false,
        };
        assert_eq!(select_log(&catalog, &index).unwrap().filename_bytes(), b"A02.d");
    }

    #[test]
    fn selection_reports_empty_catalog_invalid_index_and_unknown_filenames() {
        let latest = Selection {
            index: None,
            latest: true,
        };
        assert!(select_log(&[], &latest).is_err());
        let catalog = [metadata(b"unknown.d")];
        assert!(
            select_log(&catalog, &latest)
                .unwrap_err()
                .to_string()
                .contains("--index")
        );
        assert!(
            select_log(
                &catalog,
                &Selection {
                    index: Some(1),
                    latest: false
                }
            )
            .is_err()
        );
        assert!(
            select_log(
                &catalog,
                &Selection {
                    index: Some(0),
                    latest: false
                }
            )
            .is_ok()
        );
    }

    #[test]
    fn format_is_inferred_from_the_output_path_and_explicit_conflicts_fail() {
        for (filename, expected) in [
            ("recording.csv", OutputFormat::Csv),
            ("recording.PARQUET", OutputFormat::Parquet),
            ("recording.json", OutputFormat::Json),
            ("recording", OutputFormat::Csv),
        ] {
            let mut args = DownloadArgs {
                selection: Selection {
                    index: None,
                    latest: true,
                },
                format: None,
                output: Some(filename.into()),
            };
            assert_eq!(args.output_format().unwrap(), expected);
            if expected != OutputFormat::Csv {
                args.format = Some(OutputFormat::Csv);
                assert!(args.output_format().is_err());
            }
        }
    }

    #[test]
    fn default_path_preserves_extension_and_drops_device_directories() {
        assert_eq!(
            default_output_path(&metadata(b"A01.d"), OutputFormat::Csv),
            PathBuf::from("A01.d.csv")
        );
        assert_eq!(
            default_output_path(&metadata(b"../A01.d"), OutputFormat::Json),
            PathBuf::from("A01.d.json")
        );
    }

    #[test]
    fn json_preserves_signed_raw_sample_values() {
        let mut output = Vec::new();
        write_json(&mut output, &captured_log()).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["samples"][0]["voltage_uv"], 4_999_553);
        assert_eq!(value["samples"][0]["current_ua"], -1_904_607);
        assert_eq!(value["samples"][0]["charge_uah"], -5_290);
        assert_eq!(value["samples"][0]["energy_uwh"], -26_439);
    }

    #[test]
    fn csv_and_parquet_use_the_shared_recording_schema_and_preserve_values() {
        let device = RecordingMetadata::new("KM003C", "test", "123");
        for format in [OutputFormat::Csv, OutputFormat::Parquet] {
            let path =
                std::env::temp_dir().join(format!("km003c-export-{}.{}", std::process::id(), format.extension()));
            write_log(&path, format, &device, captured_log()).unwrap();
            let frame = read_recording(&path).unwrap();
            assert_eq!(frame.shape(), (1, 23));
            assert_eq!(frame.column("vbus_uv").unwrap().i64().unwrap().get(0), Some(4_999_553));
            assert_eq!(frame.column("ibus_ua").unwrap().i64().unwrap().get(0), Some(-1_904_607));
            assert_eq!(
                frame.column("charge_uah").unwrap().f64().unwrap().get(0),
                Some(-5_290.0)
            );
            assert_eq!(
                frame.column("energy_uwh").unwrap().f64().unwrap().get(0),
                Some(-26_439.0)
            );
            assert_eq!(frame.column("cc1_uv").unwrap().null_count(), 1);
            std::fs::remove_file(path).unwrap();
        }
    }
}
