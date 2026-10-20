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

/// How a frontend chooses a chart's vertical range.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlotScaleMode {
    #[default]
    Stepped,
    Fit,
    Manual,
}

/// Per-chart vertical scale; manual limits use the selected metric's units.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PlotScaleSettings {
    pub mode: PlotScaleMode,
    pub min: f64,
    pub max: f64,
}

impl Default for PlotScaleSettings {
    fn default() -> Self {
        Self {
            mode: PlotScaleMode::Stepped,
            min: 0.0,
            max: 6.0,
        }
    }
}

impl PlotScaleSettings {
    /// Ignore invalid persisted limits without losing the other preferences.
    pub fn sanitized(self) -> Self {
        if self.min.is_finite() && self.max.is_finite() && self.min < self.max {
            self
        } else {
            Self {
                mode: self.mode,
                ..Self::default()
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Preferences {
    pub sample_rate: GraphSampleRate,
    /// Width of the plotted time window, `None` for all data.
    pub time_window_seconds: Option<f64>,
    /// The quantity each of the three plots shows.
    pub plot_metrics: [Metric; 3],
    pub plot_scales: [PlotScaleSettings; 3],
    /// USB serial of the browser's last selected, previously permitted meter.
    pub last_device_serial: Option<String>,
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
            plot_scales: [PlotScaleSettings::default(); 3],
            last_device_serial: None,
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
            plot_scales: [PlotScaleSettings {
                mode: PlotScaleMode::Manual,
                min: -2.0,
                max: 2.0,
            }; 3],
            last_device_serial: Some("meter-test".into()),
            recording_format: RecordingFormat::Csv,
            pd_trace_enabled: true,
            pd_hide_good_crc: false,
        };

        preferences.save(&path).unwrap();

        assert_eq!(Preferences::try_load(&path).unwrap(), preferences);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn invalid_manual_limits_do_not_reach_the_renderer() {
        for (min, max) in [(5.0, 5.0), (10.0, -10.0), (f64::NAN, 1.0), (0.0, f64::INFINITY)] {
            let scale = PlotScaleSettings {
                mode: PlotScaleMode::Manual,
                min,
                max,
            }
            .sanitized();
            assert_eq!(scale.mode, PlotScaleMode::Manual);
            assert_eq!([scale.min, scale.max], [0.0, 6.0]);
        }
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
