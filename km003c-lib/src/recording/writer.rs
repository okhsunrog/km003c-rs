//! The live recorder and the recovery of interrupted captures.

use std::fs::{File, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread::{self, JoinHandle};

use polars::prelude::PolarsError;
use thiserror::Error;
use tracing::warn;

use super::export::{OutputFile, parquet_metadata, rows_to_dataframe, write_atomically};
use super::journal::{self, JournalHeader, JournalReader, JournalWriter};
use super::row::{RecordingOrigin, RecordingRow};
use super::{RecordingFormat, RecordingMetadata, RecordingSummary};
use crate::measurement::MeasurementSample;

/// Rows per Parquet row group and per conversion step.
const CHUNK_ROWS: usize = 8_192;
/// Batches the UI may queue before the writer counts as behind.
const CHANNEL_CAPACITY: usize = 32;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RecordingError {
    #[error("output directory does not exist: {}", .0.display())]
    MissingDirectory(PathBuf),
    #[error("recording paths must be UTF-8: {}", .0.display())]
    NonUtf8Path(PathBuf),
    #[error("no recording format uses the extension of {}", .0.display())]
    UnknownFormat(PathBuf),
    #[error("the recording writer could not keep up; capture stopped rather than dropping rows")]
    WriterBehind,
    #[error("the recording writer stopped unexpectedly")]
    WriterStopped,
    #[error("{} is not a recording journal: {reason}", path.display())]
    InvalidJournal { path: PathBuf, reason: String },
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Polars(#[from] PolarsError),
}

/// What a [`Recorder`] reports when it ends.
#[derive(Debug)]
#[non_exhaustive]
pub enum RecordingEvent {
    /// The file is complete.
    Finished(RecordingSummary),
    /// The capture stopped early; the file holds the rows up to the error.
    Interrupted(RecordingSummary, RecordingError),
    /// No file was written. The rows remain in `journal`, when there is one,
    /// for [`recover_interrupted`] to convert later.
    Failed {
        error: RecordingError,
        journal: Option<PathBuf>,
    },
}

/// A live capture written on a background thread.
///
/// Rows are journaled as they arrive and become a Parquet or CSV file when
/// the capture finishes; see [`recover_interrupted`] for captures that never
/// do.
pub struct Recorder {
    command_tx: Option<SyncSender<Vec<RecordingRow>>>,
    event_rx: Receiver<RecordingEvent>,
    handle: Option<JoinHandle<()>>,
    origin: RecordingOrigin,
    finishing: bool,
    interrupted: Option<RecordingError>,
    summary: RecordingSummary,
}

impl Recorder {
    /// Start a capture into `path`, journaling in `journal_dir`.
    ///
    /// Rows are relative to `origin`, normally the last sample before the
    /// capture, so the file starts at zero time, charge and energy.
    /// `journal_dir` should be a directory the app owns; it is created when
    /// missing.
    pub fn start(
        path: PathBuf,
        format: RecordingFormat,
        metadata: RecordingMetadata,
        origin: Option<MeasurementSample>,
        journal_dir: &Path,
    ) -> Result<Self, RecordingError> {
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        if !parent.is_dir() {
            return Err(RecordingError::MissingDirectory(parent.to_path_buf()));
        }
        let header = JournalHeader {
            path: path.clone(),
            format,
            metadata,
        };
        let mut journal = JournalWriter::create(journal_dir, &header)?;

        let (command_tx, command_rx) = mpsc::sync_channel::<Vec<RecordingRow>>(CHANNEL_CAPACITY);
        let (event_tx, event_rx) = mpsc::channel();
        let handle = thread::Builder::new()
            .name("km003c-recorder".to_string())
            .spawn(move || {
                let journaled = command_rx
                    .iter()
                    .try_for_each(|rows| journal.append(&rows))
                    .and_then(|()| journal.sync());
                let journal_path = journal.path().to_path_buf();
                let result = journaled
                    .map_err(RecordingError::from)
                    .and_then(|()| JournalReader::new(File::open(&journal_path)?, &journal_path))
                    .and_then(convert);
                // Unlock before deleting; Windows cannot remove an open file.
                drop(journal);
                let event = match result {
                    Ok(summary) => {
                        if let Err(error) = std::fs::remove_file(&journal_path) {
                            warn!("Could not remove recording journal {}: {error}", journal_path.display());
                        }
                        RecordingEvent::Finished(summary)
                    }
                    Err(error) => RecordingEvent::Failed {
                        error,
                        journal: Some(journal_path),
                    },
                };
                let _ = event_tx.send(event);
            })?;

        Ok(Self {
            command_tx: Some(command_tx),
            event_rx,
            handle: Some(handle),
            origin: origin.into(),
            finishing: false,
            interrupted: None,
            summary: RecordingSummary::new(path),
        })
    }

    /// Queue samples for writing. When the writer falls behind the capture
    /// stops, keeping what was written, rather than dropping rows.
    pub fn push(&mut self, samples: &[MeasurementSample]) -> Result<(), RecordingError> {
        if self.finishing || samples.is_empty() {
            return Ok(());
        }
        let Some(command_tx) = &self.command_tx else {
            return Ok(());
        };

        let first = self.summary.rows;
        let rows = samples
            .iter()
            .enumerate()
            .map(|(offset, &sample)| RecordingRow::from_sample(sample, self.origin, first + offset as u64))
            .collect::<Vec<_>>();
        let last = *rows.last().expect("samples is not empty");
        let behind = match command_tx.try_send(rows) {
            Ok(()) => {
                update_summary(&mut self.summary, &last);
                return Ok(());
            }
            Err(TrySendError::Full(_)) => true,
            Err(TrySendError::Disconnected(_)) => false,
        };
        let stop_reason = || {
            if behind {
                RecordingError::WriterBehind
            } else {
                RecordingError::WriterStopped
            }
        };
        self.interrupted = Some(stop_reason());
        Err(stop_reason())
    }

    /// Stop accepting samples and write the file. The UI does not block: the
    /// writer drains its queue and reports through [`Self::poll_event`].
    pub fn request_finish(&mut self) {
        if !self.finishing {
            self.command_tx.take();
            self.finishing = true;
        }
    }

    pub const fn is_finishing(&self) -> bool {
        self.finishing
    }

    /// The capture so far.
    pub const fn summary(&self) -> &RecordingSummary {
        &self.summary
    }

    pub fn path(&self) -> &Path {
        &self.summary.path
    }

    /// The result, once the file is written.
    pub fn poll_event(&mut self) -> Option<RecordingEvent> {
        match self.event_rx.try_recv() {
            Ok(event) => {
                if let Some(handle) = self.handle.take() {
                    let _ = handle.join();
                }
                Some(match (event, self.interrupted.take()) {
                    (RecordingEvent::Finished(summary), Some(reason)) => RecordingEvent::Interrupted(summary, reason),
                    (event, _) => event,
                })
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(RecordingEvent::Failed {
                error: RecordingError::WriterStopped,
                journal: None,
            }),
        }
    }
}

impl Drop for Recorder {
    /// Finish the file before going away.
    fn drop(&mut self) {
        self.command_tx.take();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// One journal found by [`recover_interrupted`].
#[derive(Debug)]
#[non_exhaustive]
pub struct RecoveryOutcome {
    pub journal: PathBuf,
    /// The recovered file, or why the journal was kept.
    pub result: Result<RecordingSummary, RecordingError>,
}

/// Convert the journals that captures in `journal_dir` left behind, such as
/// after a crash, into their Parquet or CSV files.
///
/// A converted journal is deleted; one that fails stays for a later attempt.
/// Journals of captures still running are locked and skipped where the file
/// system supports locking. A missing directory has nothing to recover.
pub fn recover_interrupted(journal_dir: &Path) -> io::Result<Vec<RecoveryOutcome>> {
    let entries = match std::fs::read_dir(journal_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut journals = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == journal::EXTENSION)
        })
        .collect::<Vec<_>>();
    journals.sort();

    let mut outcomes = Vec::new();
    for path in journals {
        let file = File::open(&path)?;
        match file.try_lock() {
            Ok(()) | Err(TryLockError::Error(_)) => {}
            Err(TryLockError::WouldBlock) => continue,
        }
        // The reader keeps the file, and with it the lock, until converted.
        let result = JournalReader::new(file, &path).and_then(convert);
        if result.is_ok() {
            std::fs::remove_file(&path)?;
        }
        outcomes.push(RecoveryOutcome { journal: path, result });
    }
    Ok(outcomes)
}

/// Write the file a journal is for, in chunks.
fn convert(mut reader: JournalReader) -> Result<RecordingSummary, RecordingError> {
    let header = reader.header().clone();
    let mut summary = RecordingSummary::new(header.path.clone());
    write_atomically(&header.path, |partial| {
        let mut output = OutputFile::create(
            partial,
            header.format,
            parquet_metadata(&header.metadata, "live", "host_trapezoidal"),
        )?;
        loop {
            let rows = reader.next_chunk(CHUNK_ROWS)?;
            let Some(last) = rows.last() else {
                break;
            };
            update_summary(&mut summary, last);
            output.write(&rows_to_dataframe(&rows)?)?;
        }
        output.finish()
    })?;
    Ok(summary)
}

fn update_summary(summary: &mut RecordingSummary, last: &RecordingRow) {
    summary.rows = last.sample_index + 1;
    summary.elapsed_us = last.elapsed_us;
    summary.missing_samples = last.cumulative_missing_samples;
    summary.interpolated_duration_us = last.cumulative_interpolated_duration_us;
    summary.discarded_sequence_samples = last.cumulative_discarded_sequence_samples;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recording::read_recording;
    use crate::recording::row::test_sample;
    use std::time::{Duration, Instant};

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("km003c-recorder-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn metadata() -> RecordingMetadata {
        RecordingMetadata::new("KM003C", "1.9.9", "test")
    }

    fn wait_for(recorder: &mut Recorder) -> RecordingEvent {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(event) = recorder.poll_event() {
                return event;
            }
            assert!(Instant::now() < deadline, "the recorder did not finish");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn a_capture_becomes_a_readable_file_in_both_formats() {
        let dir = test_dir("capture");
        for format in RecordingFormat::ALL {
            let path = dir.join(format!("capture.{}", format.extension()));
            let journals = dir.join("journal");
            let origin = test_sample(0, 0, 0);
            let mut recorder = Recorder::start(path.clone(), format, metadata(), Some(origin), &journals).unwrap();
            recorder
                .push(&[test_sample(20_000, 0, 0), test_sample(40_000, 1, 20_000)])
                .unwrap();
            assert_eq!(recorder.summary().rows, 2);
            recorder.request_finish();

            let RecordingEvent::Finished(summary) = wait_for(&mut recorder) else {
                panic!("the capture did not finish");
            };
            let frame = read_recording(&path).unwrap();

            assert_eq!(summary.rows, 2);
            assert_eq!(summary.missing_samples, 1);
            assert_eq!(frame.shape(), (2, 23));
            assert_eq!(frame.column("elapsed_us").unwrap().u64().unwrap().get(1), Some(40_000));
            assert_eq!(std::fs::read_dir(&journals).unwrap().count(), 0, "journal left behind");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recovery_converts_a_journal_left_by_a_crash() {
        let dir = test_dir("recovery");
        let journals = dir.join("journal");
        let path = dir.join("crashed.parquet");
        let header = JournalHeader {
            path: path.clone(),
            format: RecordingFormat::Parquet,
            metadata: metadata(),
        };
        let mut journal = JournalWriter::create(&journals, &header).unwrap();
        let rows = (0..3)
            .map(|index| {
                RecordingRow::from_sample(test_sample(index * 20_000, 0, 0), RecordingOrigin::default(), index)
            })
            .collect::<Vec<_>>();
        journal.append(&rows).unwrap();
        // The app dies here: the journal is never converted.
        drop(journal);

        let outcomes = recover_interrupted(&journals).unwrap();

        assert_eq!(outcomes.len(), 1);
        let summary = outcomes[0].result.as_ref().unwrap();
        assert_eq!(summary.rows, 3);
        assert_eq!(summary.path, path);
        assert_eq!(read_recording(&path).unwrap().shape(), (3, 23));
        assert!(recover_interrupted(&journals).unwrap().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recovery_skips_a_running_capture() {
        let dir = test_dir("running");
        let journals = dir.join("journal");
        let mut recorder = Recorder::start(
            dir.join("running.csv"),
            RecordingFormat::Csv,
            metadata(),
            None,
            &journals,
        )
        .unwrap();
        recorder.push(&[test_sample(0, 0, 0)]).unwrap();

        assert!(recover_interrupted(&journals).unwrap().is_empty());

        recorder.request_finish();
        assert!(matches!(wait_for(&mut recorder), RecordingEvent::Finished(_)));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[ignore = "requires a connected KM003C"]
    fn records_live_adcqueue_to_parquet() {
        use crate::packet::{Attribute, AttributeSet};
        use crate::{DeviceConfig, GraphSampleRate, KM003C, MeasurementAccumulator};
        use polars::prelude::ChunkAgg;

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut device = KM003C::new(DeviceConfig::vendor()).await.unwrap();
            let metadata = RecordingMetadata::from(device.state().unwrap());
            let dir = test_dir("hardware");
            let path = dir.join("hardware.parquet");
            let mut recorder = Recorder::start(
                path.clone(),
                RecordingFormat::Parquet,
                metadata,
                None,
                &dir.join("journal"),
            )
            .unwrap();
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

            recorder.request_finish();
            let RecordingEvent::Finished(summary) = wait_for(&mut recorder) else {
                panic!("the recording failed");
            };
            let frame = read_recording(&path).unwrap();
            assert_eq!(summary.rows, recorded);
            assert_eq!(frame.shape(), (recorded as usize, 23));
            assert!(frame.column("vbus_uv").unwrap().i64().unwrap().min().unwrap() > 0);
            assert_eq!(
                frame.column("sample_rate_hz").unwrap().u32().unwrap().min(),
                Some(1_000)
            );
            for column in ["vbus_uv", "ibus_ua", "power_uw", "cc1_uv", "cc2_uv", "dp_uv", "dm_uv"] {
                assert_eq!(frame.column(column).unwrap().null_count(), 0, "{column} contains nulls");
            }

            // Charge and energy are trapezoidal integrals over the device clock.
            let elapsed = frame.column("elapsed_us").unwrap().u64().unwrap();
            let current = frame.column("ibus_ua").unwrap().i64().unwrap();
            let power = frame.column("power_uw").unwrap().i64().unwrap();
            let (mut charge_uah, mut energy_uwh) = (0.0, 0.0);
            for index in 1..frame.height() {
                let delta_us = (elapsed.get(index).unwrap() - elapsed.get(index - 1).unwrap()) as f64;
                charge_uah +=
                    (current.get(index - 1).unwrap() + current.get(index).unwrap()) as f64 * delta_us / 7_200_000_000.0;
                energy_uwh +=
                    (power.get(index - 1).unwrap() + power.get(index).unwrap()) as f64 * delta_us / 7_200_000_000.0;
            }
            let last = |column: &str| {
                frame
                    .column(column)
                    .unwrap()
                    .f64()
                    .unwrap()
                    .get(frame.height() - 1)
                    .unwrap()
            };
            assert!((last("charge_uah") - charge_uah).abs() < 1e-9);
            assert!((last("energy_uwh") - energy_uwh).abs() < 1e-9);
            println!(
                "recorded={} missing={} discarded={} completeness={:.6}%",
                summary.rows,
                summary.missing_samples,
                summary.discarded_sequence_samples,
                summary.completeness_percent()
            );
            std::fs::remove_dir_all(dir).unwrap();
        });
    }

    #[test]
    fn a_missing_output_directory_fails_before_recording() {
        let dir = test_dir("missing");
        let result = Recorder::start(
            dir.join("absent/out.csv"),
            RecordingFormat::Csv,
            metadata(),
            None,
            &dir.join("journal"),
        );

        assert!(matches!(result, Err(RecordingError::MissingDirectory(_))));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
