use std::error::Error;
use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread::{self, JoinHandle};

use polars::df;
use polars::prelude::{CsvWriter, DataFrame, KeyValueMetadata, ParquetWriter, SerWriter};

use crate::measurement::MeasurementSample;
pub(crate) const RECORDING_SCHEMA_VERSION: &str = "1";
const ROW_GROUP_SIZE: usize = 8_192;
const CHANNEL_CAPACITY: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordingFormat {
    Parquet,
    Csv,
}

impl RecordingFormat {
    pub(crate) const ALL: [Self; 2] = [Self::Parquet, Self::Csv];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Parquet => "Parquet",
            Self::Csv => "CSV",
        }
    }

    pub(crate) const fn extension(self) -> &'static str {
        match self {
            Self::Parquet => "parquet",
            Self::Csv => "csv",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RecordingMetadata {
    pub(crate) model: String,
    pub(crate) firmware: String,
    pub(crate) serial: String,
}

#[derive(Debug, Clone, Copy)]
struct RecordingOrigin {
    elapsed_us: u64,
    charge_uah: f64,
    energy_uwh: f64,
    charge_throughput_uah: f64,
    energy_throughput_uwh: f64,
    cumulative_missing_samples: u64,
    cumulative_interpolated_duration_us: u64,
    cumulative_discarded_sequence_samples: u64,
}

impl From<Option<MeasurementSample>> for RecordingOrigin {
    fn from(sample: Option<MeasurementSample>) -> Self {
        sample.map_or(
            Self {
                elapsed_us: 0,
                charge_uah: 0.0,
                energy_uwh: 0.0,
                charge_throughput_uah: 0.0,
                energy_throughput_uwh: 0.0,
                cumulative_missing_samples: 0,
                cumulative_interpolated_duration_us: 0,
                cumulative_discarded_sequence_samples: 0,
            },
            |sample| Self {
                elapsed_us: sample.elapsed_us,
                charge_uah: sample.charge_uah,
                energy_uwh: sample.energy_uwh,
                charge_throughput_uah: sample.charge_throughput_uah,
                energy_throughput_uwh: sample.energy_throughput_uwh,
                cumulative_missing_samples: sample.cumulative_missing_samples,
                cumulative_interpolated_duration_us: sample.cumulative_interpolated_duration_us,
                cumulative_discarded_sequence_samples: sample.cumulative_discarded_sequence_samples,
            },
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct RecordingRow {
    elapsed_us: u64,
    sample_index: u64,
    sequence: u32,
    marker: u32,
    sample_rate_hz: u32,
    missing_samples: u32,
    gap_duration_us: u64,
    interpolated: bool,
    cumulative_missing_samples: u64,
    cumulative_interpolated_duration_us: u64,
    discarded_sequence_samples: u32,
    cumulative_discarded_sequence_samples: u64,
    vbus_uv: i64,
    ibus_ua: i64,
    power_uw: i64,
    charge_uah: f64,
    energy_uwh: f64,
    charge_throughput_uah: f64,
    energy_throughput_uwh: f64,
    cc1_uv: i64,
    cc2_uv: i64,
    dp_uv: i64,
    dm_uv: i64,
}

impl RecordingRow {
    fn from_sample(sample: MeasurementSample, origin: RecordingOrigin, sample_index: u64) -> Self {
        Self {
            elapsed_us: sample.elapsed_us.saturating_sub(origin.elapsed_us),
            sample_index,
            sequence: u32::from(sample.sequence),
            marker: u32::from(sample.marker),
            sample_rate_hz: u32::from(sample.sample_rate_hz),
            missing_samples: u32::from(sample.missing_samples),
            gap_duration_us: sample.gap_duration_us,
            interpolated: sample.interpolated,
            cumulative_missing_samples: sample
                .cumulative_missing_samples
                .saturating_sub(origin.cumulative_missing_samples),
            cumulative_interpolated_duration_us: sample
                .cumulative_interpolated_duration_us
                .saturating_sub(origin.cumulative_interpolated_duration_us),
            discarded_sequence_samples: sample.discarded_sequence_samples,
            cumulative_discarded_sequence_samples: sample
                .cumulative_discarded_sequence_samples
                .saturating_sub(origin.cumulative_discarded_sequence_samples),
            vbus_uv: sample.vbus_uv,
            ibus_ua: sample.ibus_ua,
            power_uw: sample.power_uw,
            charge_uah: sample.charge_uah - origin.charge_uah,
            energy_uwh: sample.energy_uwh - origin.energy_uwh,
            charge_throughput_uah: sample.charge_throughput_uah - origin.charge_throughput_uah,
            energy_throughput_uwh: sample.energy_throughput_uwh - origin.energy_throughput_uwh,
            cc1_uv: sample.cc1_uv,
            cc2_uv: sample.cc2_uv,
            dp_uv: sample.dp_uv,
            dm_uv: sample.dm_uv,
        }
    }
}

enum WriterCommand {
    Rows(Vec<RecordingRow>),
    Finish,
}

#[derive(Debug)]
pub(crate) enum RecordingEvent {
    Finished(RecordingSummary),
    Interrupted(RecordingSummary, String),
    Failed(String),
}

#[derive(Debug, Clone)]
pub(crate) struct RecordingSummary {
    pub(crate) path: PathBuf,
    pub(crate) rows: u64,
    pub(crate) elapsed_us: u64,
    pub(crate) missing_samples: u64,
    pub(crate) interpolated_duration_us: u64,
    pub(crate) discarded_sequence_samples: u64,
}

impl RecordingSummary {
    pub(crate) fn completeness_percent(&self) -> f64 {
        if self.elapsed_us == 0 {
            100.0
        } else {
            (1.0 - self.interpolated_duration_us as f64 / self.elapsed_us as f64).max(0.0) * 100.0
        }
    }
}

pub(crate) struct Recorder {
    command_tx: SyncSender<WriterCommand>,
    event_rx: Receiver<RecordingEvent>,
    handle: Option<JoinHandle<()>>,
    origin: RecordingOrigin,
    next_sample_index: u64,
    finishing: bool,
    interrupted: Option<String>,
    pub(crate) path: PathBuf,
    pub(crate) rows: u64,
    pub(crate) elapsed_us: u64,
    pub(crate) missing_samples: u64,
    pub(crate) interpolated_duration_us: u64,
    pub(crate) discarded_sequence_samples: u64,
}

impl Recorder {
    pub(crate) fn start(
        path: PathBuf,
        format: RecordingFormat,
        metadata: RecordingMetadata,
        origin: Option<MeasurementSample>,
    ) -> Result<Self, String> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        if !parent.exists() {
            return Err(format!("output directory does not exist: {}", parent.display()));
        }

        let partial_path = partial_path(&path);
        let (command_tx, command_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let (event_tx, event_rx) = mpsc::channel();
        let final_path = path.clone();
        let handle = thread::Builder::new()
            .name("km003c-recorder".to_string())
            .spawn(move || {
                let result = run_writer(&partial_path, format, metadata, command_rx).and_then(|summary| {
                    replace_file(&partial_path, &final_path)?;
                    Ok(RecordingSummary {
                        path: final_path,
                        ..summary
                    })
                });
                let event = match result {
                    Ok(summary) => RecordingEvent::Finished(summary),
                    Err(error) => RecordingEvent::Failed(format!(
                        "{error}; incomplete recording remains at {}",
                        partial_path.display()
                    )),
                };
                let _ = event_tx.send(event);
            })
            .map_err(|error| format!("failed to start recording thread: {error}"))?;

        Ok(Self {
            command_tx,
            event_rx,
            handle: Some(handle),
            origin: origin.into(),
            next_sample_index: 0,
            finishing: false,
            interrupted: None,
            path,
            rows: 0,
            elapsed_us: 0,
            missing_samples: 0,
            interpolated_duration_us: 0,
            discarded_sequence_samples: 0,
        })
    }

    pub(crate) fn push(&mut self, samples: &[MeasurementSample]) -> Result<(), String> {
        if self.finishing || samples.is_empty() {
            return Ok(());
        }

        let first_sample_index = self.next_sample_index;
        let rows = samples
            .iter()
            .copied()
            .enumerate()
            .map(|(offset, sample)| RecordingRow::from_sample(sample, self.origin, first_sample_index + offset as u64))
            .collect::<Vec<_>>();

        match self.command_tx.try_send(WriterCommand::Rows(rows)) {
            Ok(()) => {
                self.next_sample_index += samples.len() as u64;
                if let Some(last) = samples.last() {
                    let last = RecordingRow::from_sample(*last, self.origin, self.next_sample_index - 1);
                    self.rows = self.next_sample_index;
                    self.elapsed_us = last.elapsed_us;
                    self.missing_samples = last.cumulative_missing_samples;
                    self.interpolated_duration_us = last.cumulative_interpolated_duration_us;
                    self.discarded_sequence_samples = last.cumulative_discarded_sequence_samples;
                }
                Ok(())
            }
            Err(TrySendError::Full(_)) => {
                let error = "recording writer could not keep up; capture stopped rather than dropping rows".to_string();
                self.interrupted = Some(error.clone());
                Err(error)
            }
            Err(TrySendError::Disconnected(_)) => {
                let error = "recording writer stopped unexpectedly".to_string();
                self.interrupted = Some(error.clone());
                Err(error)
            }
        }
    }

    pub(crate) fn request_finish(&mut self) -> Result<(), String> {
        if !self.finishing {
            self.command_tx
                .send(WriterCommand::Finish)
                .map_err(|_| "recording writer stopped unexpectedly".to_string())?;
            self.finishing = true;
        }
        Ok(())
    }

    pub(crate) const fn is_finishing(&self) -> bool {
        self.finishing
    }

    pub(crate) fn poll_event(&mut self) -> Option<RecordingEvent> {
        match self.event_rx.try_recv() {
            Ok(mut event) => {
                if let Some(handle) = self.handle.take() {
                    let _ = handle.join();
                }
                if let (RecordingEvent::Finished(summary), Some(reason)) = (&event, self.interrupted.take()) {
                    event = RecordingEvent::Interrupted(summary.clone(), reason);
                }
                Some(event)
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(RecordingEvent::Failed(
                "recording writer exited without reporting a result".to_string(),
            )),
        }
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        if !self.finishing {
            let _ = self.command_tx.send(WriterCommand::Finish);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn run_writer(
    partial_path: &Path,
    format: RecordingFormat,
    metadata: RecordingMetadata,
    command_rx: Receiver<WriterCommand>,
) -> Result<RecordingSummary, Box<dyn Error + Send + Sync>> {
    let file = File::create(partial_path)?;
    match format {
        RecordingFormat::Parquet => write_parquet(file, metadata, command_rx, partial_path),
        RecordingFormat::Csv => write_csv(file, command_rx, partial_path),
    }
}

fn write_parquet(
    file: File,
    metadata: RecordingMetadata,
    command_rx: Receiver<WriterCommand>,
    partial_path: &Path,
) -> Result<RecordingSummary, Box<dyn Error + Send + Sync>> {
    let metadata = KeyValueMetadata::from_static(vec![
        (
            "km003c.schema_version".to_string(),
            RECORDING_SCHEMA_VERSION.to_string(),
        ),
        ("km003c.source".to_string(), "live".to_string()),
        ("km003c.accumulator_source".to_string(), "host_trapezoidal".to_string()),
        ("km003c.model".to_string(), metadata.model),
        ("km003c.firmware".to_string(), metadata.firmware),
        ("km003c.serial".to_string(), metadata.serial),
    ]);
    let empty = rows_to_dataframe(&[])?;
    let mut writer = ParquetWriter::new(BufWriter::new(file))
        .with_key_value_metadata(Some(metadata))
        .with_row_group_size(Some(ROW_GROUP_SIZE))
        .batched(empty.schema())?;
    let summary = consume_rows(
        command_rx,
        |rows| {
            let dataframe = rows_to_dataframe(rows)?;
            writer.write_batch(&dataframe)?;
            Ok(())
        },
        partial_path,
    )?;
    writer.finish()?;
    Ok(summary)
}

fn write_csv(
    file: File,
    command_rx: Receiver<WriterCommand>,
    partial_path: &Path,
) -> Result<RecordingSummary, Box<dyn Error + Send + Sync>> {
    let empty = rows_to_dataframe(&[])?;
    let mut writer = CsvWriter::new(BufWriter::new(file)).batched(empty.schema())?;
    let summary = consume_rows(
        command_rx,
        |rows| {
            let dataframe = rows_to_dataframe(rows)?;
            writer.write_batch(&dataframe)?;
            Ok(())
        },
        partial_path,
    )?;
    writer.finish()?;
    Ok(summary)
}

fn consume_rows<F>(
    command_rx: Receiver<WriterCommand>,
    mut write: F,
    partial_path: &Path,
) -> Result<RecordingSummary, Box<dyn Error + Send + Sync>>
where
    F: FnMut(&[RecordingRow]) -> Result<(), Box<dyn Error + Send + Sync>>,
{
    let mut buffered = Vec::with_capacity(ROW_GROUP_SIZE);
    let mut summary = RecordingSummary {
        path: partial_path.to_path_buf(),
        rows: 0,
        elapsed_us: 0,
        missing_samples: 0,
        interpolated_duration_us: 0,
        discarded_sequence_samples: 0,
    };

    loop {
        match command_rx.recv()? {
            WriterCommand::Rows(mut rows) => {
                if let Some(last) = rows.last() {
                    summary.rows = last.sample_index + 1;
                    summary.elapsed_us = last.elapsed_us;
                    summary.missing_samples = last.cumulative_missing_samples;
                    summary.interpolated_duration_us = last.cumulative_interpolated_duration_us;
                    summary.discarded_sequence_samples = last.cumulative_discarded_sequence_samples;
                }
                buffered.append(&mut rows);
                if buffered.len() >= ROW_GROUP_SIZE {
                    write(&buffered)?;
                    buffered.clear();
                }
            }
            WriterCommand::Finish => {
                if !buffered.is_empty() {
                    write(&buffered)?;
                }
                return Ok(summary);
            }
        }
    }
}

fn rows_to_dataframe(rows: &[RecordingRow]) -> Result<DataFrame, polars::error::PolarsError> {
    df!(
        "elapsed_us" => rows.iter().map(|row| row.elapsed_us).collect::<Vec<_>>(),
        "sample_index" => rows.iter().map(|row| row.sample_index).collect::<Vec<_>>(),
        "sequence" => rows.iter().map(|row| row.sequence).collect::<Vec<_>>(),
        "marker" => rows.iter().map(|row| row.marker).collect::<Vec<_>>(),
        "sample_rate_hz" => rows.iter().map(|row| row.sample_rate_hz).collect::<Vec<_>>(),
        "missing_samples" => rows.iter().map(|row| row.missing_samples).collect::<Vec<_>>(),
        "gap_duration_us" => rows.iter().map(|row| row.gap_duration_us).collect::<Vec<_>>(),
        "interpolated" => rows.iter().map(|row| row.interpolated).collect::<Vec<_>>(),
        "cumulative_missing_samples" => rows.iter().map(|row| row.cumulative_missing_samples).collect::<Vec<_>>(),
        "cumulative_interpolated_duration_us" => rows.iter().map(|row| row.cumulative_interpolated_duration_us).collect::<Vec<_>>(),
        "discarded_sequence_samples" => rows.iter().map(|row| row.discarded_sequence_samples).collect::<Vec<_>>(),
        "cumulative_discarded_sequence_samples" => rows.iter().map(|row| row.cumulative_discarded_sequence_samples).collect::<Vec<_>>(),
        "vbus_uv" => rows.iter().map(|row| row.vbus_uv).collect::<Vec<_>>(),
        "ibus_ua" => rows.iter().map(|row| row.ibus_ua).collect::<Vec<_>>(),
        "power_uw" => rows.iter().map(|row| row.power_uw).collect::<Vec<_>>(),
        "charge_uah" => rows.iter().map(|row| row.charge_uah).collect::<Vec<_>>(),
        "energy_uwh" => rows.iter().map(|row| row.energy_uwh).collect::<Vec<_>>(),
        "charge_throughput_uah" => rows.iter().map(|row| row.charge_throughput_uah).collect::<Vec<_>>(),
        "energy_throughput_uwh" => rows.iter().map(|row| row.energy_throughput_uwh).collect::<Vec<_>>(),
        "cc1_uv" => rows.iter().map(|row| row.cc1_uv).collect::<Vec<_>>(),
        "cc2_uv" => rows.iter().map(|row| row.cc2_uv).collect::<Vec<_>>(),
        "dp_uv" => rows.iter().map(|row| row.dp_uv).collect::<Vec<_>>(),
        "dm_uv" => rows.iter().map(|row| row.dm_uv).collect::<Vec<_>>(),
    )
}

fn partial_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".partial");
    PathBuf::from(name)
}

fn replace_file(partial: &Path, final_path: &Path) -> std::io::Result<()> {
    if final_path.exists() {
        std::fs::remove_file(final_path)?;
    }
    std::fs::rename(partial, final_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::measurement::MeasurementAccumulator;
    use km003c_lib::{
        DeviceConfig, GraphSampleRate, KM003C,
        packet::{Attribute, AttributeSet},
    };
    use polars::prelude::{ChunkAgg, CsvReader, ParquetReader, SerReader};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    static NEXT_TEST_FILE: AtomicU64 = AtomicU64::new(0);

    fn sample(elapsed_us: u64, missing: u64, interpolated_us: u64) -> MeasurementSample {
        MeasurementSample {
            elapsed_us,
            sample_index: 100,
            sequence: 42,
            marker: 7,
            sample_rate_hz: 50,
            missing_samples: missing as u16,
            gap_duration_us: interpolated_us,
            interpolated: missing > 0,
            cumulative_missing_samples: missing,
            cumulative_interpolated_duration_us: interpolated_us,
            discarded_sequence_samples: 0,
            cumulative_discarded_sequence_samples: 0,
            vbus_uv: 5_000_000,
            ibus_ua: -1_000_000,
            power_uw: -5_000_000,
            charge_uah: -100.0,
            energy_uwh: -500.0,
            charge_throughput_uah: 100.0,
            energy_throughput_uwh: 500.0,
            cc1_uv: 1_000_000,
            cc2_uv: 0,
            dp_uv: 600_000,
            dm_uv: 500_000,
        }
    }

    #[test]
    fn recording_rows_are_relative_to_the_start() {
        let origin = RecordingOrigin::from(Some(sample(1_000_000, 2, 40_000)));
        let row = RecordingRow::from_sample(sample(2_000_000, 3, 60_000), origin, 0);

        assert_eq!(row.elapsed_us, 1_000_000);
        assert_eq!(row.sample_index, 0);
        assert_eq!(row.cumulative_missing_samples, 1);
        assert_eq!(row.cumulative_interpolated_duration_us, 20_000);
        assert_eq!(row.charge_uah, 0.0);
    }

    #[test]
    fn completeness_reports_interpolated_time_fraction() {
        let summary = RecordingSummary {
            path: PathBuf::new(),
            rows: 10,
            elapsed_us: 1_000_000,
            missing_samples: 2,
            interpolated_duration_us: 10_000,
            discarded_sequence_samples: 0,
        };
        assert_eq!(summary.completeness_percent(), 99.0);
    }

    #[test]
    fn dataframe_uses_the_stable_recording_schema() {
        let row = RecordingRow::from_sample(sample(1_000, 0, 0), RecordingOrigin::from(None), 0);
        let dataframe = rows_to_dataframe(&[row]).unwrap();

        assert_eq!(dataframe.height(), 1);
        assert_eq!(dataframe.width(), 23);
        assert_eq!(
            dataframe.column("vbus_uv").unwrap().i64().unwrap().get(0),
            Some(5_000_000)
        );
    }

    #[test]
    fn parquet_writer_produces_a_readable_recording() {
        let path = test_path("parquet");
        let summary = write_test_recording(&path, RecordingFormat::Parquet);
        let dataframe = ParquetReader::new(File::open(&path).unwrap()).finish().unwrap();

        assert_eq!(summary.rows, 2);
        assert_eq!(dataframe.shape(), (2, 23));
        assert_eq!(
            dataframe.column("elapsed_us").unwrap().u64().unwrap().get(1),
            Some(20_000)
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn csv_writer_produces_a_readable_recording() {
        let path = test_path("csv");
        let summary = write_test_recording(&path, RecordingFormat::Csv);
        let dataframe = CsvReader::new(File::open(&path).unwrap()).finish().unwrap();

        assert_eq!(summary.rows, 2);
        assert_eq!(dataframe.shape(), (2, 23));
        assert_eq!(
            dataframe.column("vbus_uv").unwrap().i64().unwrap().get(0),
            Some(5_000_000)
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    #[ignore = "requires a connected KM003C"]
    fn records_live_adcqueue_to_parquet() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut device = KM003C::new(DeviceConfig::vendor()).await.unwrap();
            let state = device.state().unwrap();
            let metadata = RecordingMetadata {
                model: state.info.model.clone(),
                firmware: state.info.fw_version.clone(),
                serial: state.info.serial_id.clone(),
            };
            let path = test_path("hardware.parquet");
            let mut recorder = Recorder::start(path.clone(), RecordingFormat::Parquet, metadata, None).unwrap();
            let rate = GraphSampleRate::Sps1000;
            let mut accumulator = MeasurementAccumulator::default();
            let mut recorded = 0_u64;

            device.start_graph_mode(rate).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            let deadline = Instant::now() + Duration::from_secs(5);
            while recorded < 1_500 && Instant::now() < deadline {
                let packet = device
                    .request_data(AttributeSet::single(Attribute::AdcQueue))
                    .await
                    .unwrap();
                let Some(queue) = packet.get_adc_queue() else {
                    continue;
                };
                let measurements = queue
                    .samples
                    .iter()
                    .copied()
                    .filter_map(|sample| accumulator.push(sample, rate))
                    .collect::<Vec<_>>();
                recorder.push(&measurements).unwrap();
                recorded += measurements.len() as u64;
            }
            device.stop_graph_mode().await.unwrap();
            assert!(
                recorded >= 1_500,
                "received only {recorded} samples before the deadline"
            );

            recorder.request_finish().unwrap();
            let summary = loop {
                match recorder.poll_event() {
                    Some(RecordingEvent::Finished(summary)) => break summary,
                    Some(event) => panic!("recording failed: {event:?}"),
                    None if Instant::now() < deadline + Duration::from_secs(5) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    None => panic!("recording did not finish before the deadline"),
                }
            };

            let dataframe = ParquetReader::new(File::open(&path).unwrap()).finish().unwrap();
            assert_eq!(summary.rows, recorded);
            assert_eq!(dataframe.shape(), (recorded as usize, 23));
            assert!(dataframe.column("vbus_uv").unwrap().i64().unwrap().min().unwrap() > 0);
            assert_eq!(
                dataframe.column("sample_rate_hz").unwrap().u32().unwrap().min(),
                Some(1_000)
            );
            for column in ["vbus_uv", "ibus_ua", "power_uw", "cc1_uv", "cc2_uv", "dp_uv", "dm_uv"] {
                assert_eq!(
                    dataframe.column(column).unwrap().null_count(),
                    0,
                    "{column} contains nulls"
                );
            }

            let elapsed = dataframe.column("elapsed_us").unwrap().u64().unwrap();
            let current = dataframe.column("ibus_ua").unwrap().i64().unwrap();
            let power = dataframe.column("power_uw").unwrap().i64().unwrap();
            let mut expected_charge_uah = 0.0;
            let mut expected_energy_uwh = 0.0;
            let mut expected_charge_throughput_uah = 0.0;
            let mut expected_energy_throughput_uwh = 0.0;
            for index in 1..dataframe.height() {
                let delta_us = (elapsed.get(index).unwrap() - elapsed.get(index - 1).unwrap()) as f64;
                expected_charge_uah +=
                    (current.get(index - 1).unwrap() + current.get(index).unwrap()) as f64 * delta_us / 7_200_000_000.0;
                expected_energy_uwh +=
                    (power.get(index - 1).unwrap() + power.get(index).unwrap()) as f64 * delta_us / 7_200_000_000.0;
                expected_charge_throughput_uah +=
                    (current.get(index - 1).unwrap().abs() + current.get(index).unwrap().abs()) as f64 * delta_us
                        / 7_200_000_000.0;
                expected_energy_throughput_uwh +=
                    (power.get(index - 1).unwrap().abs() + power.get(index).unwrap().abs()) as f64 * delta_us
                        / 7_200_000_000.0;
            }
            let last = dataframe.height() - 1;
            let charge_uah = dataframe
                .column("charge_uah")
                .unwrap()
                .f64()
                .unwrap()
                .get(last)
                .unwrap();
            let energy_uwh = dataframe
                .column("energy_uwh")
                .unwrap()
                .f64()
                .unwrap()
                .get(last)
                .unwrap();
            let charge_throughput_uah = dataframe
                .column("charge_throughput_uah")
                .unwrap()
                .f64()
                .unwrap()
                .get(last)
                .unwrap();
            let energy_throughput_uwh = dataframe
                .column("energy_throughput_uwh")
                .unwrap()
                .f64()
                .unwrap()
                .get(last)
                .unwrap();
            assert!((charge_uah - expected_charge_uah).abs() < 1e-9);
            assert!((energy_uwh - expected_energy_uwh).abs() < 1e-9);
            assert!((charge_throughput_uah - expected_charge_throughput_uah).abs() < 1e-9);
            assert!((energy_throughput_uwh - expected_energy_throughput_uwh).abs() < 1e-9);
            println!(
                "recorded={} missing={} discarded={} completeness={:.6}% charge={charge_uah:.6} uAh energy={energy_uwh:.6} uWh",
                summary.rows,
                summary.missing_samples,
                summary.discarded_sequence_samples,
                summary.completeness_percent()
            );
            std::fs::remove_file(path).unwrap();
        });
    }

    fn write_test_recording(path: &Path, format: RecordingFormat) -> RecordingSummary {
        let (command_tx, command_rx) = mpsc::sync_channel(2);
        let rows = vec![
            RecordingRow::from_sample(sample(0, 0, 0), RecordingOrigin::from(None), 0),
            RecordingRow::from_sample(sample(20_000, 1, 20_000), RecordingOrigin::from(None), 1),
        ];
        command_tx.send(WriterCommand::Rows(rows)).unwrap();
        command_tx.send(WriterCommand::Finish).unwrap();

        run_writer(
            path,
            format,
            RecordingMetadata {
                model: "KM003C".to_string(),
                firmware: "1.9.9".to_string(),
                serial: "test".to_string(),
            },
            command_rx,
        )
        .unwrap()
    }

    fn test_path(extension: &str) -> PathBuf {
        let unique = NEXT_TEST_FILE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "km003c-recording-test-{}-{unique}.{extension}",
            std::process::id()
        ))
    }
}
