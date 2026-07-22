use std::error::Error;
use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread::{self, JoinHandle};

use polars::df;
use polars::prelude::{CsvWriter, DataFrame, KeyValueMetadata, ParquetWriter, SerWriter};

use crate::offline_view::OfflineRecordingView;
use crate::recording::{RECORDING_SCHEMA_VERSION, RecordingFormat, RecordingMetadata};

const ROW_GROUP_SIZE: usize = 8_192;

#[derive(Debug)]
pub(crate) enum OfflineExportEvent {
    Finished { path: PathBuf, rows: usize },
    Failed(String),
}

pub(crate) struct OfflineExportTask {
    event_rx: Receiver<OfflineExportEvent>,
    handle: Option<JoinHandle<()>>,
    pub(crate) path: PathBuf,
}

impl OfflineExportTask {
    pub(crate) fn start(
        path: PathBuf,
        format: RecordingFormat,
        device: RecordingMetadata,
        view: Arc<OfflineRecordingView>,
    ) -> Result<Self, String> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        if !parent.exists() {
            return Err(format!("output directory does not exist: {}", parent.display()));
        }

        let partial_path = partial_path(&path);
        let final_path = path.clone();
        let (event_tx, event_rx) = mpsc::channel();
        let handle = thread::Builder::new()
            .name("km003c-offline-export".to_string())
            .spawn(move || {
                let rows = view.samples.len();
                let result = write_offline_file(&partial_path, format, &device, &view).and_then(|()| {
                    replace_file(&partial_path, &final_path)?;
                    Ok(())
                });
                let event = match result {
                    Ok(()) => OfflineExportEvent::Finished { path: final_path, rows },
                    Err(error) => OfflineExportEvent::Failed(format!(
                        "{error}; incomplete export remains at {}",
                        partial_path.display()
                    )),
                };
                let _ = event_tx.send(event);
            })
            .map_err(|error| format!("failed to start offline export thread: {error}"))?;
        Ok(Self {
            event_rx,
            handle: Some(handle),
            path,
        })
    }

    pub(crate) fn poll_event(&mut self) -> Option<OfflineExportEvent> {
        match self.event_rx.try_recv() {
            Ok(event) => {
                if let Some(handle) = self.handle.take() {
                    let _ = handle.join();
                }
                Some(event)
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(OfflineExportEvent::Failed(
                "offline export thread exited without reporting a result".to_string(),
            )),
        }
    }
}

impl Drop for OfflineExportTask {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn write_offline_file(
    path: &Path,
    format: RecordingFormat,
    device: &RecordingMetadata,
    view: &OfflineRecordingView,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let file = File::create(path)?;
    let mut dataframe = offline_to_dataframe(view)?;
    match format {
        RecordingFormat::Parquet => {
            let metadata = KeyValueMetadata::from_static(vec![
                (
                    "km003c.schema_version".to_string(),
                    RECORDING_SCHEMA_VERSION.to_string(),
                ),
                ("km003c.source".to_string(), "offline".to_string()),
                ("km003c.accumulator_source".to_string(), "device".to_string()),
                ("km003c.model".to_string(), device.model.clone()),
                ("km003c.firmware".to_string(), device.firmware.clone()),
                ("km003c.serial".to_string(), device.serial.clone()),
                (
                    "km003c.offline.filename".to_string(),
                    view.log.metadata.filename_lossy().into_owned(),
                ),
                (
                    "km003c.offline.interval_us".to_string(),
                    view.log
                        .metadata
                        .interval
                        .get::<km003c_lib::uom::si::time::microsecond>()
                        .round()
                        .to_string(),
                ),
                (
                    "km003c.offline.flags".to_string(),
                    format!("0x{:04x}", view.log.metadata.flags),
                ),
            ]);
            ParquetWriter::new(BufWriter::new(file))
                .with_key_value_metadata(Some(metadata))
                .with_row_group_size(Some(ROW_GROUP_SIZE))
                .finish(&mut dataframe)?;
        }
        RecordingFormat::Csv => {
            CsvWriter::new(BufWriter::new(file)).finish(&mut dataframe)?;
        }
    }
    Ok(())
}

fn offline_to_dataframe(view: &OfflineRecordingView) -> Result<DataFrame, polars::error::PolarsError> {
    let rows = &view.samples;
    let unavailable_u32 = vec![None::<u32>; rows.len()];
    let unavailable_u64 = vec![None::<u64>; rows.len()];
    let unavailable_i64 = vec![None::<i64>; rows.len()];
    let unavailable_bool = vec![None::<bool>; rows.len()];
    df!(
        "elapsed_us" => rows.iter().map(|row| row.elapsed_us).collect::<Vec<_>>(),
        "sample_index" => rows.iter().map(|row| row.sample_index).collect::<Vec<_>>(),
        "sequence" => unavailable_u32.clone(),
        "marker" => unavailable_u32.clone(),
        "sample_rate_hz" => unavailable_u32.clone(),
        "missing_samples" => unavailable_u32.clone(),
        "gap_duration_us" => unavailable_u64.clone(),
        "interpolated" => unavailable_bool,
        "cumulative_missing_samples" => unavailable_u64.clone(),
        "cumulative_interpolated_duration_us" => unavailable_u64,
        "discarded_sequence_samples" => unavailable_u32,
        "cumulative_discarded_sequence_samples" => vec![None::<u64>; rows.len()],
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
    use crate::offline_view::captured_test_view;
    use polars::prelude::{CsvReader, ParquetReader, SerReader};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_FILE: AtomicU64 = AtomicU64::new(0);

    fn test_path(extension: &str) -> PathBuf {
        let sequence = NEXT_TEST_FILE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "km003c-egui-offline-export-{}-{sequence}.{extension}",
            std::process::id()
        ))
    }

    fn test_metadata() -> RecordingMetadata {
        RecordingMetadata {
            model: "KM003C".to_string(),
            firmware: "1.9.9".to_string(),
            serial: "test".to_string(),
        }
    }

    #[test]
    fn dataframe_preserves_values_and_marks_unavailable_channels_null() {
        let view = captured_test_view();
        let dataframe = offline_to_dataframe(&view).unwrap();

        assert_eq!(dataframe.shape(), (3, 23));
        assert_eq!(dataframe.column("sequence").unwrap().null_count(), 3);
        assert_eq!(dataframe.column("cc1_uv").unwrap().null_count(), 3);
        assert_eq!(
            dataframe.column("vbus_uv").unwrap().i64().unwrap().get(0),
            Some(4_999_553)
        );
        assert_eq!(
            dataframe.column("energy_throughput_uwh").unwrap().f64().unwrap().get(2),
            Some(5_747_232.0)
        );
    }

    #[test]
    fn parquet_and_csv_exports_are_readable() {
        let view = captured_test_view();
        let metadata = test_metadata();

        let parquet_path = test_path("parquet");
        write_offline_file(&parquet_path, RecordingFormat::Parquet, &metadata, &view).unwrap();
        let parquet = ParquetReader::new(File::open(&parquet_path).unwrap()).finish().unwrap();
        assert_eq!(parquet.shape(), (3, 23));
        assert_eq!(parquet.column("sequence").unwrap().null_count(), 3);
        std::fs::remove_file(parquet_path).unwrap();

        let csv_path = test_path("csv");
        write_offline_file(&csv_path, RecordingFormat::Csv, &metadata, &view).unwrap();
        let csv = CsvReader::new(File::open(&csv_path).unwrap()).finish().unwrap();
        assert_eq!(csv.shape(), (3, 23));
        assert_eq!(
            csv.column("charge_uah").unwrap().f64().unwrap().get(2),
            Some(-810_335.0)
        );
        std::fs::remove_file(csv_path).unwrap();
    }
}
