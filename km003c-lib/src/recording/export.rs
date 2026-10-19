//! DataFrames in the recording schema, and the files written from them.

use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread::{self, JoinHandle};

use polars::df;
use polars::prelude::{
    CsvReadOptions, CsvWriter, DataFrame, KeyValueMetadata, ParquetReader, ParquetWriter, PolarsResult, Schema,
    SerReader, SerWriter,
};
use uom::si::time::microsecond;

use super::row::{RecordingOrigin, RecordingRow};
use super::writer::RecordingError;
use super::{RECORDING_SCHEMA_VERSION, RecordingFormat, RecordingMetadata};
use crate::measurement::MeasurementSample;
use crate::offline_view::OfflineRecordingView;

const ROW_GROUP_SIZE: usize = 8_192;

/// The 23 columns every recording and export has, with their types.
pub fn recording_schema() -> Schema {
    rows_to_dataframe(&[])
        .expect("an empty frame")
        .schema()
        .as_ref()
        .clone()
}

/// Measurements as a frame in the recording schema, on their own timeline:
/// times and totals are the accumulator's, not relative to the first sample.
pub fn measurements_to_dataframe(samples: &[MeasurementSample]) -> PolarsResult<DataFrame> {
    let rows = samples
        .iter()
        .map(|&sample| RecordingRow::from_sample(sample, RecordingOrigin::default(), sample.sample_index))
        .collect::<Vec<_>>();
    rows_to_dataframe(&rows)
}

impl OfflineRecordingView {
    /// The recording as a frame in the recording schema. Columns the device
    /// does not store (sequence, gap quality, CC1/CC2 and D+/D-) are null
    /// rather than zero.
    pub fn to_dataframe(&self) -> PolarsResult<DataFrame> {
        let rows = &self.samples;
        let unavailable_u32 = vec![None::<u32>; rows.len()];
        let unavailable_u64 = vec![None::<u64>; rows.len()];
        let unavailable_i64 = vec![None::<i64>; rows.len()];
        df!(
            "elapsed_us" => rows.iter().map(|row| row.elapsed_us).collect::<Vec<_>>(),
            "sample_index" => rows.iter().map(|row| row.sample_index).collect::<Vec<_>>(),
            "sequence" => unavailable_u32.clone(),
            "marker" => unavailable_u32.clone(),
            "sample_rate_hz" => unavailable_u32.clone(),
            "missing_samples" => unavailable_u32.clone(),
            "gap_duration_us" => unavailable_u64.clone(),
            "interpolated" => vec![None::<bool>; rows.len()],
            "cumulative_missing_samples" => unavailable_u64.clone(),
            "cumulative_interpolated_duration_us" => unavailable_u64.clone(),
            "discarded_sequence_samples" => unavailable_u32,
            "cumulative_discarded_sequence_samples" => unavailable_u64,
            "vbus_uv" => rows.iter().map(|row| row.vbus_uv).collect::<Vec<_>>(),
            "ibus_ua" => rows.iter().map(|row| row.ibus_ua).collect::<Vec<_>>(),
            "power_uw" => rows.iter().map(|row| row.power_uw).collect::<Vec<_>>(),
            "charge_uah" => rows.iter().map(|row| row.charge_uah).collect::<Vec<_>>(),
            "energy_uwh" => rows.iter().map(|row| row.energy_uwh).collect::<Vec<_>>(),
            "charge_throughput_uah" => rows.iter().map(|row| row.charge_throughput_uah).collect::<Vec<_>>(),
            "energy_throughput_uwh" => rows.iter().map(|row| row.energy_throughput_uwh).collect::<Vec<_>>(),
            "cc1_uv" => unavailable_i64.clone(),
            "cc2_uv" => unavailable_i64.clone(),
            "dp_uv" => unavailable_i64.clone(),
            "dm_uv" => unavailable_i64,
        )
    }
}

/// Read a Parquet or CSV recording, choosing the format by extension. CSV
/// columns get the recording schema's types.
pub fn read_recording(path: &Path) -> Result<DataFrame, RecordingError> {
    match RecordingFormat::from_path(path) {
        Some(RecordingFormat::Parquet) => Ok(ParquetReader::new(File::open(path)?).finish()?),
        Some(RecordingFormat::Csv) => Ok(CsvReadOptions::default()
            .with_has_header(true)
            .with_schema(Some(Arc::new(recording_schema())))
            .try_into_reader_with_file_path(Some(path.to_path_buf()))?
            .finish()?),
        None => Err(RecordingError::UnknownFormat(path.to_path_buf())),
    }
}

/// Write a downloaded offline recording in one go.
pub fn write_offline_recording(
    path: &Path,
    format: RecordingFormat,
    metadata: &RecordingMetadata,
    view: &OfflineRecordingView,
) -> Result<(), RecordingError> {
    let mut entries = parquet_metadata(metadata, "offline", "device");
    entries.extend([
        (
            "km003c.offline.filename".to_string(),
            view.log.metadata.filename_lossy().into_owned(),
        ),
        (
            "km003c.offline.interval_us".to_string(),
            view.log.metadata.interval.get::<microsecond>().round().to_string(),
        ),
        (
            "km003c.offline.flags".to_string(),
            format!("0x{:04x}", view.log.metadata.flags),
        ),
    ]);
    write_atomically(path, |partial| {
        let mut output = OutputFile::create(partial, format, entries)?;
        output.write(&view.to_dataframe()?)?;
        output.finish()
    })
}

pub(crate) fn rows_to_dataframe(rows: &[RecordingRow]) -> PolarsResult<DataFrame> {
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

/// Parquet key-value metadata shared by live and offline files.
pub(crate) fn parquet_metadata(
    metadata: &RecordingMetadata,
    source: &str,
    accumulator_source: &str,
) -> Vec<(String, String)> {
    vec![
        (
            "km003c.schema_version".to_string(),
            RECORDING_SCHEMA_VERSION.to_string(),
        ),
        ("km003c.source".to_string(), source.to_string()),
        ("km003c.accumulator_source".to_string(), accumulator_source.to_string()),
        ("km003c.model".to_string(), metadata.model.clone()),
        ("km003c.firmware".to_string(), metadata.firmware.clone()),
        ("km003c.serial".to_string(), metadata.serial.clone()),
    ]
}

/// A Parquet or CSV file written batch by batch.
pub(crate) enum OutputFile {
    Parquet(Box<polars::io::parquet::write::BatchedWriter<BufWriter<File>>>),
    Csv(polars::io::csv::write::BatchedWriter<BufWriter<File>>),
}

impl OutputFile {
    pub(crate) fn create(
        path: &Path,
        format: RecordingFormat,
        parquet_metadata: Vec<(String, String)>,
    ) -> Result<Self, RecordingError> {
        let file = BufWriter::new(File::create(path)?);
        let schema = recording_schema();
        Ok(match format {
            RecordingFormat::Parquet => Self::Parquet(Box::new(
                ParquetWriter::new(file)
                    .with_key_value_metadata(Some(KeyValueMetadata::from_static(parquet_metadata)))
                    .with_row_group_size(Some(ROW_GROUP_SIZE))
                    .batched(&schema)?,
            )),
            RecordingFormat::Csv => Self::Csv(CsvWriter::new(file).batched(&schema)?),
        })
    }

    pub(crate) fn write(&mut self, frame: &DataFrame) -> Result<(), RecordingError> {
        match self {
            Self::Parquet(writer) => writer.write_batch(frame)?,
            Self::Csv(writer) => writer.write_batch(frame)?,
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<(), RecordingError> {
        match self {
            Self::Parquet(writer) => {
                writer.finish()?;
            }
            Self::Csv(mut writer) => writer.finish()?,
        }
        Ok(())
    }
}

/// Write `path` through a `.partial` file renamed into place on success, so an
/// existing file is only replaced by a complete one.
pub(crate) fn write_atomically(
    path: &Path,
    write: impl FnOnce(&Path) -> Result<(), RecordingError>,
) -> Result<(), RecordingError> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    if !parent.is_dir() {
        return Err(RecordingError::MissingDirectory(parent.to_path_buf()));
    }
    let mut partial = path.as_os_str().to_os_string();
    partial.push(".partial");
    let partial = PathBuf::from(partial);
    let result = write(&partial).and_then(|()| {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(std::fs::rename(&partial, path)?)
    });
    if result.is_err() {
        let _ = std::fs::remove_file(&partial);
    }
    result
}

/// What an [`OfflineExport`] reports when it ends.
#[derive(Debug)]
#[non_exhaustive]
pub enum OfflineExportEvent {
    Finished { path: PathBuf, rows: usize },
    Failed(RecordingError),
}

/// A downloaded offline recording written on a background thread.
pub struct OfflineExport {
    event_rx: Receiver<OfflineExportEvent>,
    handle: Option<JoinHandle<()>>,
    path: PathBuf,
}

impl OfflineExport {
    pub fn start(
        path: PathBuf,
        format: RecordingFormat,
        metadata: RecordingMetadata,
        view: Arc<OfflineRecordingView>,
    ) -> Result<Self, RecordingError> {
        let (event_tx, event_rx) = mpsc::channel();
        let output = path.clone();
        let handle = thread::Builder::new()
            .name("km003c-offline-export".to_string())
            .spawn(move || {
                let event = match write_offline_recording(&output, format, &metadata, &view) {
                    Ok(()) => OfflineExportEvent::Finished {
                        path: output,
                        rows: view.samples.len(),
                    },
                    Err(error) => OfflineExportEvent::Failed(error),
                };
                let _ = event_tx.send(event);
            })?;
        Ok(Self {
            event_rx,
            handle: Some(handle),
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The result, once the export has ended.
    pub fn poll_event(&mut self) -> Option<OfflineExportEvent> {
        match self.event_rx.try_recv() {
            Ok(event) => {
                if let Some(handle) = self.handle.take() {
                    let _ = handle.join();
                }
                Some(event)
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(OfflineExportEvent::Failed(RecordingError::WriterStopped)),
        }
    }
}

impl Drop for OfflineExport {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offline_view::captured_test_view;
    use crate::recording::row::test_sample;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_FILE: AtomicU64 = AtomicU64::new(0);

    pub(crate) fn test_path(extension: &str) -> PathBuf {
        let sequence = NEXT_TEST_FILE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "km003c-export-test-{}-{sequence}.{extension}",
            std::process::id()
        ))
    }

    #[test]
    fn the_schema_has_the_documented_columns() {
        let schema = recording_schema();
        assert_eq!(schema.len(), 23);
        assert_eq!(schema.get_at_index(0).unwrap().0.as_str(), "elapsed_us");
        assert_eq!(schema.get_at_index(22).unwrap().0.as_str(), "dm_uv");
    }

    #[test]
    fn measurements_keep_their_own_timeline() {
        let frame = measurements_to_dataframe(&[test_sample(1_000, 0, 0)]).unwrap();

        assert_eq!(frame.shape(), (1, 23));
        assert_eq!(frame.column("elapsed_us").unwrap().u64().unwrap().get(0), Some(1_000));
        assert_eq!(frame.column("sample_index").unwrap().u64().unwrap().get(0), Some(100));
        assert_eq!(frame.column("vbus_uv").unwrap().i64().unwrap().get(0), Some(5_000_000));
    }

    #[test]
    fn offline_frames_mark_unavailable_channels_null() {
        let frame = captured_test_view().to_dataframe().unwrap();

        assert_eq!(frame.shape(), (3, 23));
        assert_eq!(frame.column("sequence").unwrap().null_count(), 3);
        assert_eq!(frame.column("cc1_uv").unwrap().null_count(), 3);
        assert_eq!(frame.column("vbus_uv").unwrap().i64().unwrap().get(0), Some(4_999_553));
        assert_eq!(
            frame.column("energy_throughput_uwh").unwrap().f64().unwrap().get(2),
            Some(5_747_232.0)
        );
    }

    #[test]
    fn offline_exports_read_back_in_both_formats() {
        let view = captured_test_view();
        let metadata = RecordingMetadata::new("KM003C", "1.9.9", "test");

        for format in RecordingFormat::ALL {
            let path = test_path(format.extension());
            write_offline_recording(&path, format, &metadata, &view).unwrap();
            let frame = read_recording(&path).unwrap();

            assert_eq!(frame.shape(), (3, 23));
            assert_eq!(frame.column("sequence").unwrap().null_count(), 3);
            assert_eq!(
                frame.column("charge_uah").unwrap().f64().unwrap().get(2),
                Some(-810_335.0)
            );
            assert_eq!(frame.schema().as_ref(), &recording_schema());
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn a_failed_write_leaves_the_existing_file() {
        let path = test_path("csv");
        std::fs::write(&path, "previous").unwrap();

        let result = write_atomically(&path, |_| Err(RecordingError::WriterStopped));

        assert!(result.is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "previous");
        std::fs::remove_file(path).unwrap();
    }
}
