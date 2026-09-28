//! The Files tab: live recording, recovery of interrupted recordings, and
//! export of the recordings stored on the meter.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use km003c_lib::uom::si::electric_charge::milliampere_hour;
use km003c_lib::uom::si::energy::milliwatt_hour;
use km003c_lib::uom::si::time::second;
use km003c_lib::{
    DeviceState, LogMetadata, MeasurementSample, OfflineExport, OfflineExportEvent, OfflineLog, OfflineRecordingView,
    Recorder, RecordingEvent, RecordingFormat, RecordingMetadata, RecoveryOutcome, Session,
};

use crate::OfflineRow;

/// Where the app keeps its files.
#[derive(Debug, Clone)]
pub struct Dirs {
    pub preferences: PathBuf,
    /// Journals of running captures; see [`km003c_lib::Recorder`].
    pub journal: PathBuf,
    /// Recordings and exports.
    pub recordings: PathBuf,
}

/// Changes to the Files tab.
#[derive(Debug, Default)]
pub struct FilesUpdate {
    pub recording: Option<bool>,
    pub progress: Option<String>,
    pub status: Option<String>,
    pub offline_busy: Option<bool>,
    pub offline_status: Option<String>,
    pub offline_rows: Option<Vec<OfflineRow>>,
}

impl FilesUpdate {
    fn status(status: impl Into<String>) -> Self {
        Self {
            status: Some(status.into()),
            ..Self::default()
        }
    }

    fn offline_status(status: impl Into<String>, busy: bool) -> Self {
        Self {
            offline_status: Some(status.into()),
            offline_busy: Some(busy),
            ..Self::default()
        }
    }
}

pub struct Files {
    dirs: Arc<Dirs>,
    recorder: Option<Recorder>,
    catalog: Vec<LogMetadata>,
    export: Option<OfflineExport>,
    export_format: RecordingFormat,
    offline_busy: bool,
}

impl Files {
    pub fn new(dirs: Arc<Dirs>) -> Self {
        Self {
            dirs,
            recorder: None,
            catalog: Vec::new(),
            export: None,
            export_format: RecordingFormat::default(),
            offline_busy: false,
        }
    }

    pub fn start_recording(
        &mut self,
        format: RecordingFormat,
        device: Option<&DeviceState>,
        origin: Option<MeasurementSample>,
    ) -> FilesUpdate {
        let Some(device) = device else {
            return FilesUpdate::status("Connect the KM003C before recording");
        };
        if self.recorder.is_some() {
            return FilesUpdate::default();
        }
        if self.offline_busy {
            return FilesUpdate::status("Wait for the meter's recording to finish downloading");
        }
        if let Err(error) = std::fs::create_dir_all(&self.dirs.recordings) {
            return FilesUpdate::status(format!("Cannot create {}: {error}", self.dirs.recordings.display()));
        }
        let path = self.dirs.recordings.join(file_name("km003c-live", format));
        match Recorder::start(
            path,
            format,
            RecordingMetadata::from(device),
            origin,
            &self.dirs.journal,
        ) {
            Ok(recorder) => {
                let status = format!("Recording to {}", display_name(recorder.path()));
                self.recorder = Some(recorder);
                FilesUpdate {
                    recording: Some(true),
                    progress: Some("0 samples".to_string()),
                    status: Some(status),
                    ..FilesUpdate::default()
                }
            }
            Err(error) => FilesUpdate::status(format!("Could not start recording: {error}")),
        }
    }

    pub fn stop_recording(&mut self) -> FilesUpdate {
        let Some(recorder) = &mut self.recorder else {
            return FilesUpdate::default();
        };
        recorder.request_finish();
        FilesUpdate {
            recording: Some(false),
            status: Some(format!("Writing {}…", display_name(recorder.path()))),
            ..FilesUpdate::default()
        }
    }

    pub fn push(&mut self, samples: &[MeasurementSample]) -> FilesUpdate {
        let Some(recorder) = &mut self.recorder else {
            return FilesUpdate::default();
        };
        match recorder.push(samples) {
            Ok(()) => FilesUpdate::default(),
            Err(error) => {
                recorder.request_finish();
                FilesUpdate {
                    recording: Some(false),
                    status: Some(error.to_string()),
                    ..FilesUpdate::default()
                }
            }
        }
    }

    /// Ask the session for the catalog. The session drops offline requests
    /// while no meter is connected, so they would never be answered.
    pub fn request_catalog(&mut self, session: &Session, connected: bool) -> FilesUpdate {
        if self.offline_busy || self.recorder.is_some() {
            return FilesUpdate::default();
        }
        if !connected {
            return FilesUpdate::offline_status("Connect the KM003C to load its recordings", false);
        }
        self.offline_busy = true;
        if session.request_offline_catalog().is_err() {
            self.offline_busy = false;
            return FilesUpdate::offline_status("The device session has stopped", false);
        }
        FilesUpdate::offline_status("Loading the catalog…", true)
    }

    pub fn catalog(&mut self, catalog: Vec<LogMetadata>) -> FilesUpdate {
        self.offline_busy = false;
        let status = match catalog.len() {
            0 => "No recordings stored on the meter".to_string(),
            1 => "1 recording".to_string(),
            count => format!("{count} recordings"),
        };
        let rows = catalog.iter().map(offline_row).collect();
        self.catalog = catalog;
        FilesUpdate {
            offline_rows: Some(rows),
            ..FilesUpdate::offline_status(status, false)
        }
    }

    /// Download a catalog entry; [`Self::downloaded`] then writes the file.
    pub fn export(&mut self, index: usize, format: RecordingFormat, session: &Session, connected: bool) -> FilesUpdate {
        if self.offline_busy || self.recorder.is_some() {
            return FilesUpdate::default();
        }
        if !connected {
            return FilesUpdate::offline_status("Connect the KM003C to export its recordings", false);
        }
        let Some(metadata) = self.catalog.get(index).cloned() else {
            return FilesUpdate::default();
        };
        let name = metadata.filename_lossy().into_owned();
        self.offline_busy = true;
        self.export_format = format;
        if session.download_offline_log(metadata).is_err() {
            self.offline_busy = false;
            return FilesUpdate::offline_status("The device session has stopped", false);
        }
        FilesUpdate::offline_status(format!("Downloading {name}…"), true)
    }

    pub fn downloaded(&mut self, log: OfflineLog, device: Option<&DeviceState>) -> FilesUpdate {
        let Some(device) = device else {
            self.offline_busy = false;
            return FilesUpdate::offline_status("The meter disconnected during the download", false);
        };
        let view = Arc::new(OfflineRecordingView::new(log));
        let stem = format!(
            "km003c-{}",
            sanitize(&view.log.metadata.filename_lossy()).trim_end_matches(".d")
        );
        if let Err(error) = std::fs::create_dir_all(&self.dirs.recordings) {
            self.offline_busy = false;
            return FilesUpdate::offline_status(
                format!("Cannot create {}: {error}", self.dirs.recordings.display()),
                false,
            );
        }
        let path = self.dirs.recordings.join(file_name(&stem, self.export_format));
        match OfflineExport::start(path, self.export_format, RecordingMetadata::from(device), view) {
            Ok(export) => {
                let status = format!("Writing {}…", display_name(export.path()));
                self.export = Some(export);
                FilesUpdate::offline_status(status, true)
            }
            Err(error) => {
                self.offline_busy = false;
                FilesUpdate::offline_status(format!("Could not export: {error}"), false)
            }
        }
    }

    pub fn offline_failed(&mut self, error: String) -> FilesUpdate {
        self.offline_busy = false;
        FilesUpdate::offline_status(error, false)
    }

    /// The meter went away: stop recording and forget its catalog.
    pub fn device_disconnected(&mut self) -> FilesUpdate {
        let mut update = self.stop_recording();
        if self.offline_busy && self.export.is_none() {
            self.offline_busy = false;
            update.offline_busy = Some(false);
            update.offline_status = Some("The meter disconnected".to_string());
        }
        self.catalog.clear();
        update.offline_rows = Some(Vec::new());
        update
    }

    /// Report progress and finished files.
    pub fn poll(&mut self) -> FilesUpdate {
        let mut update = FilesUpdate::default();
        if let Some(recorder) = &mut self.recorder {
            match recorder.poll_event() {
                None => {
                    if !recorder.is_finishing() {
                        let summary = recorder.summary();
                        update.progress = Some(format!(
                            "{} samples · {:.1} s · {:.3}% complete",
                            summary.rows,
                            summary.elapsed_us as f64 / 1e6,
                            summary.completeness_percent()
                        ));
                    }
                }
                Some(event) => {
                    self.recorder = None;
                    update.recording = Some(false);
                    update.progress = Some(String::new());
                    update.status = Some(match event {
                        RecordingEvent::Finished(summary) => format!(
                            "Saved {} samples to {} ({:.3}% complete)",
                            summary.rows,
                            display_name(&summary.path),
                            summary.completeness_percent()
                        ),
                        RecordingEvent::Interrupted(summary, reason) => format!(
                            "{reason}; saved {} samples to {}",
                            summary.rows,
                            display_name(&summary.path)
                        ),
                        RecordingEvent::Failed {
                            error,
                            journal: Some(_),
                        } => format!("{error}; the samples are kept and recovered on the next start"),
                        RecordingEvent::Failed { error, journal: None } => error.to_string(),
                        event => format!("Recording ended: {event:?}"),
                    });
                }
            }
        }
        if let Some(event) = self.export.as_mut().and_then(OfflineExport::poll_event) {
            self.export = None;
            self.offline_busy = false;
            update.offline_busy = Some(false);
            update.offline_status = Some(match event {
                OfflineExportEvent::Finished { path, rows } => {
                    format!("Saved {rows} samples to {}", display_name(&path))
                }
                OfflineExportEvent::Failed(error) => format!("Could not export: {error}"),
                event => format!("Export ended: {event:?}"),
            });
        }
        update
    }
}

/// One line about the journals an earlier run left behind.
pub fn recovery_message(outcomes: &[RecoveryOutcome]) -> Option<String> {
    let recovered = outcomes
        .iter()
        .filter_map(|outcome| outcome.result.as_ref().ok())
        .map(|summary| format!("{} ({} samples)", display_name(&summary.path), summary.rows))
        .collect::<Vec<_>>();
    let failed = outcomes.iter().filter(|outcome| outcome.result.is_err()).count();
    let mut parts = Vec::new();
    if !recovered.is_empty() {
        parts.push(format!("Recovered an interrupted recording: {}", recovered.join(", ")));
    }
    if failed > 0 {
        parts.push(format!("{failed} interrupted recording(s) could not be recovered"));
    }
    (!parts.is_empty()).then(|| parts.join(". "))
}

fn offline_row(metadata: &LogMetadata) -> OfflineRow {
    OfflineRow {
        name: metadata.filename_lossy().as_ref().into(),
        detail: format!(
            "{} samples · every {} s · {:.0} s · {:.1} mAh · {:.1} mWh",
            metadata.sample_count,
            metadata.interval.get::<second>(),
            metadata.recorded_duration.get::<second>(),
            metadata.final_charge.get::<milliampere_hour>(),
            metadata.final_energy.get::<milliwatt_hour>()
        )
        .into(),
    }
}

fn file_name(stem: &str, format: RecordingFormat) -> String {
    let unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    format!("{stem}-{unix_seconds}.{}", format.extension())
}

/// A device file name made safe for the local file system.
fn sanitize(name: &str) -> String {
    let name = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let clean = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();
    if clean.is_empty() { "offline".to_string() } else { clean }
}

fn display_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_file_names_become_safe_file_names() {
        assert_eq!(sanitize("A01.d"), "A01.d");
        assert_eq!(sanitize("../logs/A 01.d"), "A_01.d");
        assert_eq!(sanitize(""), "offline");
    }

    #[test]
    fn the_catalog_needs_a_connected_meter() {
        let (session, mut commands) = Session::detached();
        let mut files = Files::new(Arc::new(Dirs {
            preferences: PathBuf::new(),
            journal: PathBuf::new(),
            recordings: PathBuf::new(),
        }));

        let update = files.request_catalog(&session, false);

        assert_eq!(update.offline_busy, Some(false));
        assert!(commands.try_recv().is_err(), "nothing would answer the request");
        assert_eq!(files.request_catalog(&session, true).offline_busy, Some(true));
        assert!(commands.try_recv().is_ok());
    }

    #[test]
    fn recording_needs_a_connected_meter() {
        let dir = std::env::temp_dir().join(format!("km003c-slint-files-{}", std::process::id()));
        let mut files = Files::new(Arc::new(Dirs {
            preferences: dir.join("preferences.json"),
            journal: dir.join("journal"),
            recordings: dir.join("recordings"),
        }));

        let update = files.start_recording(RecordingFormat::Parquet, None, None);

        assert!(files.recorder.is_none());
        assert_eq!(update.recording, None);
        assert_eq!(update.status.as_deref(), Some("Connect the KM003C before recording"));
    }
}
