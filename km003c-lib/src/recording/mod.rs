//! Recording measurements to Parquet or CSV, and exporting offline logs.
//!
//! Every file shares one 23-column schema, [`RECORDING_SCHEMA_VERSION`]:
//! device-relative time and sequence information, VBUS, current and power,
//! the CC and D+/D- voltages, and cumulative charge and energy. Integer
//! electrical columns carry their unit in the name (`*_uv`, `*_ua`, `*_uw`).
//!
//! With the `polars` feature, [`Recorder`] writes a live capture on a
//! background thread. Rows go first to a journal that survives a crash; when
//! the capture finishes the journal becomes the Parquet or CSV file.
//! [`recover_interrupted`] turns the journals of captures that never finished
//! into files. The same feature converts measurements and offline logs to
//! polars `DataFrame`s and reads recordings back.

use std::path::{Path, PathBuf};

use crate::device::DeviceState;

#[cfg(feature = "polars")]
mod export;
#[cfg(feature = "polars")]
mod journal;
#[cfg(feature = "polars")]
mod row;
#[cfg(feature = "polars")]
mod writer;

#[cfg(feature = "polars")]
pub use export::{
    OfflineExport, OfflineExportEvent, measurements_to_dataframe, read_recording, recording_schema,
    write_offline_recording,
};
#[cfg(feature = "polars")]
pub use writer::{Recorder, RecordingError, RecordingEvent, RecoveryOutcome, recover_interrupted};

/// Version of the column layout, stored in Parquet metadata.
pub const RECORDING_SCHEMA_VERSION: &str = "1";

/// File format of a recording or export.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum RecordingFormat {
    /// Typed columns and device metadata; the default.
    #[default]
    Parquet,
    /// Plain text for tools without Parquet support.
    Csv,
}

impl RecordingFormat {
    pub const ALL: [Self; 2] = [Self::Parquet, Self::Csv];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Parquet => "Parquet",
            Self::Csv => "CSV",
        }
    }

    pub const fn extension(self) -> &'static str {
        match self {
            Self::Parquet => "parquet",
            Self::Csv => "csv",
        }
    }

    /// The format a file name's extension names, ignoring case.
    pub fn from_path(path: &Path) -> Option<Self> {
        let extension = path.extension()?.to_str()?;
        Self::ALL
            .into_iter()
            .find(|format| format.extension().eq_ignore_ascii_case(extension))
    }
}

/// The meter a recording came from, stored in Parquet metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecordingMetadata {
    pub model: String,
    pub firmware: String,
    pub serial: String,
}

impl RecordingMetadata {
    pub fn new(model: impl Into<String>, firmware: impl Into<String>, serial: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            firmware: firmware.into(),
            serial: serial.into(),
        }
    }
}

impl From<&DeviceState> for RecordingMetadata {
    fn from(state: &DeviceState) -> Self {
        Self::new(&state.info.model, &state.info.fw_version, &state.info.serial_id)
    }
}

/// Size and quality of a recording.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct RecordingSummary {
    /// The output file.
    pub path: PathBuf,
    pub rows: u64,
    /// Time covered, from the first row to the last.
    pub elapsed_us: u64,
    /// Samples the meter skipped, bridged by interpolation.
    pub missing_samples: u64,
    /// Time covered by interpolated intervals.
    pub interpolated_duration_us: u64,
    /// Duplicate, stale or out-of-sequence samples left out.
    pub discarded_sequence_samples: u64,
}

impl RecordingSummary {
    /// An empty recording to `path`.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            rows: 0,
            elapsed_us: 0,
            missing_samples: 0,
            interpolated_duration_us: 0,
            discarded_sequence_samples: 0,
        }
    }

    /// The share of the elapsed time covered by received rather than
    /// interpolated intervals, in percent.
    pub fn completeness_percent(&self) -> f64 {
        if self.elapsed_us == 0 {
            100.0
        } else {
            (1.0 - self.interpolated_duration_us as f64 / self.elapsed_us as f64).max(0.0) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completeness_reports_interpolated_time_fraction() {
        let summary = RecordingSummary {
            rows: 10,
            elapsed_us: 1_000_000,
            missing_samples: 2,
            interpolated_duration_us: 10_000,
            ..RecordingSummary::new(PathBuf::new())
        };
        assert_eq!(summary.completeness_percent(), 99.0);
    }

    #[test]
    fn format_follows_the_extension() {
        assert_eq!(
            RecordingFormat::from_path(Path::new("a/b.PARQUET")),
            Some(RecordingFormat::Parquet)
        );
        assert_eq!(
            RecordingFormat::from_path(Path::new("b.csv")),
            Some(RecordingFormat::Csv)
        );
        assert_eq!(RecordingFormat::from_path(Path::new("b.txt")), None);
    }
}
