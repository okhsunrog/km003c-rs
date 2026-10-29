//! Browser recording: bounded memory, cooperative encoding, browser download.
use super::row::{RecordingOrigin, RecordingRow};
use super::{RecordingFormat, RecordingMetadata, RecordingSummary};
use crate::MeasurementSample;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

const MAX_ROWS: usize = 128 * 1024 * 1024 / std::mem::size_of::<RecordingRow>();

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct RecordingError(pub String);

#[derive(Debug)]
#[non_exhaustive]
pub enum RecordingEvent {
    Finished(RecordingSummary),
    Interrupted(RecordingSummary, RecordingError),
    Failed {
        error: RecordingError,
        journal: Option<PathBuf>,
    },
}

/// A browser capture held in memory until it is downloaded.
pub struct Recorder {
    summary: RecordingSummary,
    origin: RecordingOrigin,
    data: Vec<RecordingRow>,
    format: RecordingFormat,
    metadata: RecordingMetadata,
    finishing: bool,
    event_rx: Option<mpsc::UnboundedReceiver<RecordingEvent>>,
    interrupted: Option<String>,
    unload_guard: Option<crate::runtime::UnloadGuard>,
}

impl Recorder {
    /// Start an in-memory capture. Browsers do not use a filesystem journal.
    pub fn start(
        path: PathBuf,
        format: RecordingFormat,
        metadata: RecordingMetadata,
        origin: Option<MeasurementSample>,
        _journal_dir: &Path,
    ) -> Result<Self, RecordingError> {
        Ok(Self {
            summary: RecordingSummary::new(path),
            format,
            metadata,
            origin: RecordingOrigin::from(origin),
            data: Vec::new(),
            finishing: false,
            event_rx: None,
            interrupted: None,
            unload_guard: Some(crate::runtime::UnloadGuard::new()),
        })
    }

    pub fn path(&self) -> &Path {
        &self.summary.path
    }
    pub fn summary(&self) -> &RecordingSummary {
        &self.summary
    }

    pub fn push(&mut self, samples: &[MeasurementSample]) -> Result<(), RecordingError> {
        if self.finishing {
            return Ok(());
        }
        if self.data.len().saturating_add(samples.len()) > MAX_ROWS {
            let message = "Browser recording memory limit reached; saving collected samples".to_string();
            self.interrupted = Some(message.clone());
            return Err(RecordingError(message));
        }
        for sample in samples {
            let row = RecordingRow::from_sample(*sample, self.origin, self.summary.rows);
            self.summary.rows += 1;
            self.summary.elapsed_us = row.elapsed_us;
            self.summary.missing_samples = row.cumulative_missing_samples;
            self.summary.interpolated_duration_us = row.cumulative_interpolated_duration_us;
            self.summary.discarded_sequence_samples = row.cumulative_discarded_sequence_samples;
            self.data.push(row);
        }
        Ok(())
    }

    pub fn request_finish(&mut self) {
        if self.finishing {
            return;
        }
        self.finishing = true;
        let (tx, rx) = mpsc::unbounded_channel();
        self.event_rx = Some(rx);
        let rows = std::mem::take(&mut self.data);
        let format = self.format;
        let metadata = self.metadata.clone();
        let interrupted = self.interrupted.take();
        let summary = self.summary.clone();
        let unload_guard = self.unload_guard.take();
        wasm_bindgen_futures::spawn_local(async move {
            // Keep protection through encoding and download even if the caller
            // drops the Recorder while this task is still running.
            let _unload_guard = unload_guard;
            let event = match super::web_export::save_live(&summary.path, format, metadata, &rows).await {
                Ok(()) => match interrupted {
                    Some(reason) => RecordingEvent::Interrupted(summary, RecordingError(reason)),
                    None => RecordingEvent::Finished(summary),
                },
                Err(error) => RecordingEvent::Failed {
                    error: RecordingError(error),
                    journal: None,
                },
            };
            let _ = tx.send(event);
        });
    }

    pub fn is_finishing(&self) -> bool {
        self.finishing
    }
    pub fn poll_event(&mut self) -> Option<RecordingEvent> {
        self.event_rx.as_mut().and_then(|rx| rx.try_recv().ok())
    }
}
