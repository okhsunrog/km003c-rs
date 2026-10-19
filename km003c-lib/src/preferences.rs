//! Settings the front ends remember between runs.
//!
//! Every GUI keeps the same [`Preferences`] as JSON in a file of its choice,
//! so the sample rate, plots and PD log filters stay as the user left them.
//! Unknown fields are ignored and missing ones take their defaults, so older
//! and newer versions can share a file.

use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

use crate::adcqueue::GraphSampleRate;
use crate::measurement::Metric;
use crate::recording::RecordingFormat;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Preferences {
    pub sample_rate: GraphSampleRate,
    /// Width of the plotted time window, `None` for all data.
    pub time_window_seconds: Option<f64>,
    /// The quantity each of the three plots shows.
    pub plot_metrics: [Metric; 3],
    pub recording_format: RecordingFormat,
    /// Also read the firmware's Type-C and protocol-engine trace.
    pub pd_trace_enabled: bool,
    /// Leave GoodCRC acknowledgements out of the PD log.
    pub pd_hide_good_crc: bool,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            sample_rate: GraphSampleRate::Sps50,
            time_window_seconds: Some(30.0),
            plot_metrics: [Metric::Voltage, Metric::Current, Metric::Power],
            recording_format: RecordingFormat::Parquet,
            pd_trace_enabled: false,
            pd_hide_good_crc: true,
        }
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PreferencesError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("invalid preferences file: {0}")]
    Json(#[from] serde_json::Error),
}

impl Preferences {
    /// Read `path`, or the defaults when it is missing or unreadable.
    pub fn load(path: &Path) -> Self {
        match Self::try_load(path) {
            Ok(preferences) => preferences,
            Err(PreferencesError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Self::default(),
            Err(error) => {
                warn!("Using default preferences; {} is unusable: {error}", path.display());
                Self::default()
            }
        }
    }

    pub fn try_load(path: &Path) -> Result<Self, PreferencesError> {
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }

    /// Write `path`, creating its directory. The file is replaced whole, so a
    /// crash mid-write leaves the previous version.
    pub fn save(&self, path: &Path) -> Result<(), PreferencesError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut partial = path.as_os_str().to_os_string();
        partial.push(".partial");
        std::fs::write(&partial, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&partial, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferences_round_trip_through_a_file() {
        let dir = std::env::temp_dir().join(format!("km003c-preferences-{}", std::process::id()));
        let path = dir.join("nested/preferences.json");
        let preferences = Preferences {
            sample_rate: GraphSampleRate::Sps1000,
            time_window_seconds: None,
            plot_metrics: [Metric::SignedPower, Metric::Cc1, Metric::Energy],
            recording_format: RecordingFormat::Csv,
            pd_trace_enabled: true,
            pd_hide_good_crc: false,
        };

        preferences.save(&path).unwrap();

        assert_eq!(Preferences::try_load(&path).unwrap(), preferences);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_fields_take_their_defaults_and_unknown_ones_are_ignored() {
        let preferences: Preferences = serde_json::from_str(r#"{"sample_rate": "Sps10", "added_later": 1}"#).unwrap();

        assert_eq!(preferences.sample_rate, GraphSampleRate::Sps10);
        assert_eq!(preferences.plot_metrics, Preferences::default().plot_metrics);
    }

    #[test]
    fn an_unreadable_file_gives_the_defaults() {
        let path = std::env::temp_dir().join(format!("km003c-bad-preferences-{}.json", std::process::id()));
        std::fs::write(&path, "not json").unwrap();

        assert_eq!(Preferences::load(&path), Preferences::default());
        assert_eq!(
            Preferences::load(Path::new("/nonexistent/km003c.json")),
            Preferences::default()
        );
        std::fs::remove_file(path).unwrap();
    }
}
