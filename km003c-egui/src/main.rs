mod metric_color;
#[cfg(any(target_arch = "wasm32", test))]
mod plot_sampling;

use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints};
#[cfg(not(target_arch = "wasm32"))]
use km003c_lib::RecoveryOutcome;
use km003c_lib::runtime::Instant;
use km003c_lib::uom::si::electric_charge::milliampere_hour;
use km003c_lib::uom::si::electric_potential::volt;
use km003c_lib::uom::si::energy::milliwatt_hour;
use km003c_lib::uom::si::time::{millisecond, second};
use km003c_lib::{
    DeviceState, GraphSampleRate, LogMetadata, MeasurementAccumulator, MeasurementSample, Metric, OfflineExport,
    OfflineExportEvent, OfflineRecordingView, PdConnectionTracker, PdContract, PdLogCategory, PdLogEntry, PdLogger,
    PdTraceCategory, PdTraceEntry, Preferences, Recorder, RecordingEvent, RecordingFormat, RecordingMetadata,
    RecordingSummary, Session, SessionEvent,
    pd::{PdEventData, PdStatus},
};
use metric_color::MetricColor;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Bound browser drawing work; desktop plots retain every supplied sample.
fn display_plot_points(
    points: impl Iterator<Item = [f64; 2]>,
    _x_bounds: [f64; 2],
    _columns: usize,
) -> PlotPoints<'static> {
    #[cfg(target_arch = "wasm32")]
    {
        plot_sampling::sample_line(points, _x_bounds, _columns).into()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        points.collect()
    }
}

/// Where the app keeps its files. The Slint GUI uses the same ones on the
/// desktop, so both remember the same settings.
struct AppDirs {
    #[cfg(not(target_arch = "wasm32"))]
    preferences: Option<PathBuf>,
    journal: PathBuf,
}

impl AppDirs {
    #[cfg(not(target_arch = "wasm32"))]
    fn locate() -> Self {
        Self {
            preferences: dirs::config_dir().map(|dir| dir.join("km003c").join("preferences.json")),
            journal: dirs::data_local_dir()
                .unwrap_or_else(std::env::temp_dir)
                .join("km003c")
                .join("journal"),
        }
    }
    #[cfg(target_arch = "wasm32")]
    fn locate() -> Self {
        Self {
            journal: PathBuf::new(),
        }
    }

    fn load_preferences(&self) -> Preferences {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.preferences.as_deref().map(Preferences::load).unwrap_or_default()
        }
        #[cfg(target_arch = "wasm32")]
        {
            web_sys::window()
                .and_then(|w| w.local_storage().ok().flatten())
                .and_then(|storage| storage.get_item("km003c.preferences").ok().flatten())
                .and_then(|json| serde_json::from_str(&json).ok())
                .unwrap_or_default()
        }
    }
}

#[cfg(target_arch = "wasm32")]
type BrowserDeviceResult = Result<(nusb::Device, Option<String>), String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlotSource {
    Live,
    Offline,
}

enum PdTimelineEntry<'a> {
    Protocol(&'a PdLogEntry),
    FirmwareTrace(&'a PdTraceEntry),
}

impl PdTimelineEntry<'_> {
    fn timestamp_seconds(&self) -> f64 {
        match self {
            Self::Protocol(entry) => entry.timestamp_seconds,
            Self::FirmwareTrace(entry) => entry.timestamp_seconds,
        }
    }
}

/// Which entries the PD timeline shows.
#[derive(Debug, Clone, Copy)]
struct TimelineFilter {
    protocol: bool,
    good_crc: bool,
    trace: bool,
}

fn pd_timeline_entries<'a>(
    protocol_log: &'a VecDeque<PdLogEntry>,
    trace_log: &'a VecDeque<PdTraceEntry>,
    filter: TimelineFilter,
) -> Vec<PdTimelineEntry<'a>> {
    let mut timeline = Vec::with_capacity(protocol_log.len() + trace_log.len());
    if filter.protocol {
        timeline.extend(
            protocol_log
                .iter()
                .filter(|entry| filter.good_crc || !entry.is_good_crc())
                .map(PdTimelineEntry::Protocol),
        );
    }
    if filter.trace {
        timeline.extend(trace_log.iter().map(PdTimelineEntry::FirmwareTrace));
    }
    timeline.sort_by(|left, right| left.timestamp_seconds().total_cmp(&right.timestamp_seconds()));
    timeline
}

/// Sample rate options for the UI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SampleRateOption {
    Sps2,
    Sps10,
    Sps50,
    Sps1000,
}

impl SampleRateOption {
    fn to_graph_rate(self) -> GraphSampleRate {
        match self {
            Self::Sps2 => GraphSampleRate::Sps2,
            Self::Sps10 => GraphSampleRate::Sps10,
            Self::Sps50 => GraphSampleRate::Sps50,
            Self::Sps1000 => GraphSampleRate::Sps1000,
        }
    }

    fn from_graph_rate(rate: GraphSampleRate) -> Self {
        match rate {
            GraphSampleRate::Sps2 => Self::Sps2,
            GraphSampleRate::Sps10 => Self::Sps10,
            GraphSampleRate::Sps50 => Self::Sps50,
            GraphSampleRate::Sps1000 => Self::Sps1000,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Sps2 => "2 SPS",
            Self::Sps10 => "10 SPS",
            Self::Sps50 => "50 SPS",
            Self::Sps1000 => "1000 SPS",
        }
    }

    fn all() -> &'static [Self] {
        &[Self::Sps2, Self::Sps10, Self::Sps50, Self::Sps1000]
    }
}

/// Time window for plot display
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimeWindow {
    Sec2,
    Sec10,
    Sec30,
    Min1,
    Min5,
    All,
}

impl TimeWindow {
    fn seconds(self) -> Option<f64> {
        match self {
            Self::Sec2 => Some(2.0),
            Self::Sec10 => Some(10.0),
            Self::Sec30 => Some(30.0),
            Self::Min1 => Some(60.0),
            Self::Min5 => Some(300.0),
            Self::All => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Sec2 => "2 sec",
            Self::Sec10 => "10 sec",
            Self::Sec30 => "30 sec",
            Self::Min1 => "1 min",
            Self::Min5 => "5 min",
            Self::All => "All",
        }
    }

    fn all() -> &'static [Self] {
        &[Self::Sec2, Self::Sec10, Self::Sec30, Self::Min1, Self::Min5, Self::All]
    }

    /// The option for a saved window width, 30 s when none matches.
    fn from_seconds(seconds: Option<f64>) -> Self {
        Self::all()
            .iter()
            .copied()
            .find(|window| window.seconds() == seconds)
            .unwrap_or(Self::Sec30)
    }
}

struct PowerMonitorApp {
    /// Complete live samples retained for plotting
    data_points: VecDeque<MeasurementSample>,
    /// Unwraps device time and integrates charge and energy
    measurement_accumulator: MeasurementAccumulator,
    /// Events from the device session
    session_events: mpsc::UnboundedReceiver<SessionEvent>,
    /// Command handle of the device session
    session: Session,
    /// Device state (available after connection)
    device_state: Option<Arc<DeviceState>>,
    /// Connection status string
    status: String,
    /// Is streaming active
    streaming: bool,
    /// Current sample rate (synced with device)
    current_rate: SampleRateOption,
    /// Selected sample rate in UI (may differ while changing)
    selected_rate: SampleRateOption,
    /// Time window for plot display
    time_window: TimeWindow,
    /// Maximum data points to keep (safety cap)
    max_points: usize,
    /// Total samples received
    total_samples: u64,
    /// Dropped sample count
    dropped_samples: u64,
    /// Duplicate, stale, or invalid-sequence samples excluded from measurements
    discarded_sequence_samples: u64,
    /// Current readings for display
    current_voltage: f64,
    current_current: f64,
    current_power: f64,
    /// Metric selected independently for each plot
    plot_metrics: [Metric; 3],
    /// Preferred output format for live capture
    recording_format: RecordingFormat,
    /// Active or finalizing background recorder
    recorder: Option<Recorder>,
    /// Last recorder status shown to the user
    recording_status: String,
    /// Summary of the last completed recording
    last_recording: Option<RecordingSummary>,
    /// Device-side offline recording catalog
    offline_catalog: Vec<LogMetadata>,
    /// Selected catalog row
    offline_selected: Option<usize>,
    /// Downloaded offline recording and plot data
    offline_view: Option<Arc<OfflineRecordingView>>,
    /// Device identity retained with the downloaded recording for export
    offline_device_metadata: Option<RecordingMetadata>,
    /// Whether a device catalog or download operation is running
    offline_busy: bool,
    /// Offline browser and export status
    offline_status: String,
    /// Background export of a downloaded offline recording
    offline_export: Option<OfflineExport>,
    /// Data source currently rendered by the three plots
    plot_source: PlotSource,
    /// PD protocol decoder
    pd_decoder: PdLogger,
    /// Decoded PD log entries
    pd_log: VecDeque<PdLogEntry>,
    /// Max PD log entries
    max_pd_entries: usize,
    /// Current PD status
    pd_status: Option<PdStatus>,
    /// Debounced phone connection state
    pd_connection: PdConnectionTracker,
    /// Power contract from the negotiation messages
    pd_contract: PdContract,
    /// Leave GoodCRC acknowledgements out of the timeline
    pd_hide_good_crc: bool,
    /// Auto-scroll PD log
    pd_auto_scroll: bool,
    /// PD panel visible
    pd_panel_visible: bool,
    /// Show decoded wire-protocol events in the shared timeline
    pd_protocol_visible: bool,
    /// Whether the USB task should drain the firmware PD trace queues
    pd_trace_enabled: bool,
    /// Firmware PD trace entries
    pd_trace_log: VecDeque<PdTraceEntry>,
    /// Max firmware PD trace entries
    max_pd_trace_entries: usize,
    /// Whether to perform USB reset on connect
    #[cfg(not(target_arch = "wasm32"))]
    usb_reset: bool,
    /// An attempted connection has not yet produced a result.
    connection_attempt_in_flight: bool,
    #[cfg(target_arch = "wasm32")]
    chooser: Option<mpsc::UnboundedReceiver<BrowserDeviceResult>>,
    #[cfg(target_arch = "wasm32")]
    selected_serial: Option<String>,
    /// User intent, retained while a connection or disconnect is in progress.
    auto_connect_enabled: bool,
    /// Time of the next automatic probe while the KM003C is absent.
    reconnect_at: Option<Instant>,
    /// Preference file and recording journal locations
    dirs: AppDirs,
    /// Preferences as last written, to save only changes
    saved_preferences: Preferences,
    /// Conversion of journals that earlier runs left behind
    #[cfg(not(target_arch = "wasm32"))]
    recovery: Option<JoinHandle<std::io::Result<Vec<RecoveryOutcome>>>>,
}

impl PowerMonitorApp {
    const RECONNECT_DELAY: Duration = Duration::from_secs(1);

    fn new(
        session: Session,
        session_events: mpsc::UnboundedReceiver<SessionEvent>,
        preferences: Preferences,
        dirs: AppDirs,
    ) -> Self {
        let rate = SampleRateOption::from_graph_rate(preferences.sample_rate);
        #[cfg(not(target_arch = "wasm32"))]
        let journal = dirs.journal.clone();
        #[cfg(not(target_arch = "wasm32"))]
        let recovery = std::thread::Builder::new()
            .name("km003c-recovery".to_string())
            .spawn(move || km003c_lib::recover_interrupted(&journal))
            .map_err(|error| warn!("Could not start recording recovery: {error}"))
            .ok();
        Self {
            data_points: VecDeque::new(),
            measurement_accumulator: MeasurementAccumulator::default(),
            session_events,
            session,
            device_state: None,
            status: if cfg!(target_arch = "wasm32") {
                "Click Connect to select KM003C"
            } else {
                "Connecting..."
            }
            .to_string(),
            streaming: false,
            current_rate: rate,
            selected_rate: rate,
            time_window: TimeWindow::from_seconds(preferences.time_window_seconds),
            max_points: 100000, // Safety cap for memory
            total_samples: 0,
            dropped_samples: 0,
            discarded_sequence_samples: 0,
            current_voltage: 0.0,
            current_current: 0.0,
            current_power: 0.0,
            plot_metrics: preferences.plot_metrics,
            recording_format: preferences.recording_format,
            recorder: None,
            recording_status: "Not recording".to_string(),
            last_recording: None,
            offline_catalog: Vec::new(),
            offline_selected: None,
            offline_view: None,
            offline_device_metadata: None,
            offline_busy: false,
            offline_status: "Catalog not loaded".to_string(),
            offline_export: None,
            plot_source: PlotSource::Live,
            pd_decoder: PdLogger::new(),
            pd_log: VecDeque::new(),
            max_pd_entries: 1000,
            pd_status: None,
            pd_connection: PdConnectionTracker::default(),
            pd_contract: PdContract::default(),
            pd_hide_good_crc: preferences.pd_hide_good_crc,
            pd_auto_scroll: true,
            pd_panel_visible: true,
            pd_protocol_visible: true,
            pd_trace_enabled: preferences.pd_trace_enabled,
            pd_trace_log: VecDeque::new(),
            max_pd_trace_entries: 2000,
            #[cfg(not(target_arch = "wasm32"))]
            usb_reset: !cfg!(target_os = "macos"),
            connection_attempt_in_flight: !cfg!(target_arch = "wasm32"),
            #[cfg(target_arch = "wasm32")]
            chooser: None,
            #[cfg(target_arch = "wasm32")]
            selected_serial: None,
            auto_connect_enabled: true,
            reconnect_at: None,
            dirs,
            saved_preferences: preferences,
            #[cfg(not(target_arch = "wasm32"))]
            recovery,
        }
    }

    fn preferences(&self) -> Preferences {
        let mut preferences = self.saved_preferences.clone();
        preferences.sample_rate = self.selected_rate.to_graph_rate();
        preferences.time_window_seconds = self.time_window.seconds();
        preferences.plot_metrics = self.plot_metrics;
        preferences.recording_format = self.recording_format;
        preferences.pd_trace_enabled = self.pd_trace_enabled;
        preferences.pd_hide_good_crc = self.pd_hide_good_crc;
        preferences
    }

    /// Write the preferences when a setting changed.
    fn save_preferences(&mut self) {
        let preferences = self.preferences();
        if preferences == self.saved_preferences {
            return;
        }
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(path) = &self.dirs.preferences
            && let Err(error) = preferences.save(path)
        {
            warn!("Could not save preferences to {}: {error}", path.display());
        }
        #[cfg(target_arch = "wasm32")]
        if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten())
            && let Ok(json) = serde_json::to_string(&preferences)
        {
            let _ = storage.set_item("km003c.preferences", &json);
        }
        self.saved_preferences = preferences;
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn poll_recovery(&mut self) {
        if !self.recovery.as_ref().is_some_and(JoinHandle::is_finished) {
            return;
        }
        let outcomes = match self.recovery.take().map(JoinHandle::join) {
            Some(Ok(Ok(outcomes))) => outcomes,
            Some(Ok(Err(error))) => {
                self.recording_status = format!("Could not look for interrupted recordings: {error}");
                return;
            }
            _ => return,
        };
        let messages = outcomes
            .iter()
            .map(|outcome| match &outcome.result {
                Ok(summary) => format!(
                    "Recovered an interrupted recording: {} samples in {}",
                    summary.rows,
                    summary.path.display()
                ),
                Err(error) => format!(
                    "Could not recover {}: {error}; the journal is kept",
                    outcome.journal.display()
                ),
            })
            .collect::<Vec<_>>();
        for message in &messages {
            info!("{message}");
        }
        if !messages.is_empty() {
            self.recording_status = messages.join("\n");
        }
    }

    fn request_connection(&mut self, show_connecting: bool) {
        if self.connection_attempt_in_flight || self.device_state.is_some() {
            return;
        }

        self.connection_attempt_in_flight = true;
        self.reconnect_at = None;
        if show_connecting {
            self.auto_connect_enabled = true;
            self.status = "Connecting...".to_string();
        }
        #[cfg(not(target_arch = "wasm32"))]
        let result = self.session.connect(self.selected_rate.to_graph_rate(), self.usb_reset);
        #[cfg(target_arch = "wasm32")]
        let result = self.session.connect_selected(
            self.selected_rate.to_graph_rate(),
            false,
            self.selected_serial
                .clone()
                .map(km003c_lib::DeviceSelector::SerialNumber)
                .unwrap_or_default(),
        );
        if let Err(error) = result {
            self.connection_attempt_in_flight = false;
            self.status = error.to_string();
        }
    }

    fn retry_connection_if_due(&mut self, now: Instant) {
        if self.reconnect_at.is_some_and(|retry_at| now >= retry_at) {
            self.request_connection(false);
        }
    }

    fn process_messages(&mut self) {
        #[cfg(target_arch = "wasm32")]
        if let Some(result) = self.chooser.as_mut().and_then(|rx| rx.try_recv().ok()) {
            self.chooser = None;
            match result {
                Ok((device, serial)) => {
                    self.selected_serial = serial;
                    if let Err(error) = self.session.connect_device(device, self.selected_rate.to_graph_rate()) {
                        self.connection_attempt_in_flight = false;
                        self.status = error.to_string();
                    }
                }
                Err(error) => {
                    self.connection_attempt_in_flight = false;
                    self.status = error;
                }
            }
        }
        while let Ok(msg) = self.session_events.try_recv() {
            match msg {
                SessionEvent::WaitingForDevice => {
                    self.status = "Waiting for POWER-Z KM003C...".to_string();
                }
                SessionEvent::Connected(state) => {
                    self.connection_attempt_in_flight = false;
                    self.reconnect_at = None;
                    self.status = format!("Connected: {}", state.model());
                    self.device_state = Some(state);
                    self.offline_catalog.clear();
                    self.offline_selected = None;
                    self.offline_status = "Catalog not loaded".to_string();
                    self.pd_connection = PdConnectionTracker::default();
                    self.pd_decoder = PdLogger::new();
                    // Keep the contract; messages sent in between were missed.
                    self.pd_contract.device_reconnected();
                    if self.pd_trace_enabled {
                        let _ = self.session.set_pd_trace_enabled(true);
                    }
                }
                SessionEvent::ConnectionFailed {
                    error,
                    retry_when_present,
                } => {
                    self.connection_attempt_in_flight = false;
                    self.reconnect_at = None;
                    if retry_when_present && self.auto_connect_enabled {
                        self.reconnect_at = Some(Instant::now() + Self::RECONNECT_DELAY);
                        self.status = "Waiting for POWER-Z KM003C...".to_string();
                    } else {
                        self.status = format!("Connection failed: {}", error);
                    }
                }
                SessionEvent::Samples(samples) => {
                    let rate = self.current_rate.to_graph_rate();
                    let measurements = samples
                        .into_iter()
                        .filter_map(|sample| self.measurement_accumulator.push(sample, rate))
                        .collect::<Vec<_>>();
                    self.discarded_sequence_samples =
                        self.measurement_accumulator.cumulative_discarded_sequence_samples();

                    for measurement in &measurements {
                        self.data_points.push_back(*measurement);
                        self.dropped_samples = measurement.cumulative_missing_samples;

                        // Update current readings
                        self.current_voltage = measurement.vbus_uv as f64 / 1_000_000.0;
                        self.current_current = measurement.ibus_ua as f64 / 1_000_000.0;
                        self.current_power = measurement.power_uw as f64 / 1_000_000.0;

                        self.total_samples += 1;

                        // Limit data points
                        while self.data_points.len() > self.max_points {
                            self.data_points.pop_front();
                        }
                    }

                    if let Some(recorder) = &mut self.recorder
                        && let Err(error) = recorder.push(&measurements)
                    {
                        self.recording_status = error.to_string();
                        recorder.request_finish();
                    }
                }
                SessionEvent::StreamingStarted(rate) => {
                    self.streaming = true;
                    self.current_rate = SampleRateOption::from_graph_rate(rate);
                    self.selected_rate = self.current_rate;
                    self.status = format!("Streaming at {}", self.current_rate.label());
                    // A rate change starts a new continuity segment without
                    // inventing an interval across StopGraph/StartGraph.
                    self.measurement_accumulator.reset_continuity();
                }
                SessionEvent::PdEvents(events) => {
                    for event in &events {
                        match &event.data {
                            PdEventData::Connect => {
                                self.pd_connection.observe_event(true, Instant::now());
                            }
                            PdEventData::Disconnect => {
                                self.pd_connection.observe_event(false, Instant::now());
                            }
                            PdEventData::PdMessage { .. } => {}
                        }

                        let entry = self.pd_decoder.log_event(event);
                        self.pd_contract.observe(&entry);
                        self.pd_log.push_back(entry);
                        while self.pd_log.len() > self.max_pd_entries {
                            self.pd_log.pop_front();
                        }
                    }
                }
                SessionEvent::PdStatusUpdate(status) => {
                    self.pd_connection.observe_status(&status, Instant::now());
                    self.pd_status = Some(status);
                }
                SessionEvent::PdTrace(trace) => {
                    for entry in trace.entries() {
                        self.pd_trace_log.push_back(entry);
                        while self.pd_trace_log.len() > self.max_pd_trace_entries {
                            self.pd_trace_log.pop_front();
                        }
                    }
                }
                SessionEvent::OfflineCatalog(catalog) => {
                    self.offline_busy = false;
                    self.offline_status = if catalog.is_empty() {
                        "No offline recordings stored on the device".to_string()
                    } else {
                        format!("Loaded {} offline recording(s)", catalog.len())
                    };
                    self.offline_selected = (!catalog.is_empty()).then_some(0);
                    self.offline_catalog = catalog;
                }
                SessionEvent::OfflineLogDownloaded(log) => {
                    let samples = log.samples.len();
                    let filename = log.metadata.filename_lossy().into_owned();
                    self.offline_view = Some(Arc::new(OfflineRecordingView::new(log)));
                    self.offline_device_metadata = self.device_state.as_deref().map(RecordingMetadata::from);
                    self.offline_busy = false;
                    self.offline_status = format!("Downloaded {samples} samples from {filename}");
                    self.plot_source = PlotSource::Offline;
                    self.time_window = TimeWindow::All;
                    for metric in &mut self.plot_metrics {
                        if !metric.supports_offline() {
                            *metric = Metric::Voltage;
                        }
                    }
                }
                SessionEvent::OfflineOperationFailed(error) => {
                    self.offline_busy = false;
                    self.offline_status = error;
                }
                SessionEvent::StreamingStopped => {
                    self.streaming = false;
                    self.status = "Stopped".to_string();
                }
                SessionEvent::Error(err) => {
                    self.status = format!("Error: {}", err);
                }
                SessionEvent::Disconnected { retry_when_present } => {
                    self.connection_attempt_in_flight = false;
                    self.status = if retry_when_present && self.auto_connect_enabled {
                        self.reconnect_at = Some(Instant::now() + Self::RECONNECT_DELAY);
                        "Waiting for POWER-Z KM003C...".to_string()
                    } else {
                        self.reconnect_at = None;
                        "Disconnected".to_string()
                    };
                    self.streaming = false;
                    self.device_state = None;
                    self.pd_status = None;
                    self.pd_connection = PdConnectionTracker::default();
                    self.pd_decoder = PdLogger::new();
                    self.offline_busy = false;
                    self.stop_recording();
                }
                _ => {}
            }
        }

        self.retry_connection_if_due(Instant::now());
        self.pd_connection.update(Instant::now());
        self.pd_contract.observe_sink(self.pd_connection.connected());
        self.poll_recording();
        self.poll_offline_export();
        #[cfg(not(target_arch = "wasm32"))]
        self.poll_recovery();
        self.save_preferences();
    }

    fn clear_data(&mut self) {
        self.data_points.clear();
        self.total_samples = 0;
        self.dropped_samples = 0;
        self.discarded_sequence_samples = 0;
        self.measurement_accumulator.reset();
        info!("Data cleared");
    }

    fn clear_pd_log(&mut self) {
        self.pd_log.clear();
        self.pd_trace_log.clear();
        info!("PD timeline cleared");
    }

    fn start_recording(&mut self) {
        let Some(state) = &self.device_state else {
            self.recording_status = "Connect the KM003C before starting a recording".to_string();
            return;
        };
        if self.recorder.is_some() {
            return;
        }

        let metadata = RecordingMetadata::from(state.as_ref());
        let Some(path) = self.select_recording_path("km003c-live", "Save KM003C live recording") else {
            return;
        };
        match Recorder::start(
            path.clone(),
            self.recording_format,
            metadata,
            self.data_points.back().copied(),
            &self.dirs.journal,
        ) {
            Ok(recorder) => {
                self.recording_status = format!("Recording to {}", path.display());
                self.last_recording = None;
                self.recorder = Some(recorder);
            }
            Err(error) => self.recording_status = error.to_string(),
        }
    }

    fn export_buffer(&mut self) {
        let Some(state) = &self.device_state else {
            self.recording_status = "Connect the KM003C before exporting data".to_string();
            return;
        };
        let Some(first) = self.data_points.front().copied() else {
            self.recording_status = "The plot buffer is empty".to_string();
            return;
        };
        let metadata = RecordingMetadata::from(state.as_ref());
        let Some(path) = self.select_recording_path("km003c-buffer", "Export KM003C plot buffer") else {
            return;
        };

        match Recorder::start(
            path.clone(),
            self.recording_format,
            metadata,
            Some(first),
            &self.dirs.journal,
        ) {
            Ok(mut recorder) => {
                let samples = self.data_points.iter().copied().collect::<Vec<_>>();
                match recorder.push(&samples) {
                    Ok(()) => {
                        recorder.request_finish();
                        self.recording_status = format!("Exporting {}", path.display());
                        self.last_recording = None;
                        self.recorder = Some(recorder);
                    }
                    Err(error) => self.recording_status = error.to_string(),
                }
            }
            Err(error) => self.recording_status = error.to_string(),
        }
    }

    fn select_recording_path(&self, prefix: &str, title: &str) -> Option<std::path::PathBuf> {
        let unix_seconds = km003c_lib::runtime::SystemTime::now()
            .duration_since(km003c_lib::runtime::SystemTime::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let filename = format!("{prefix}-{unix_seconds}.{}", self.recording_format.extension());
        #[cfg(target_arch = "wasm32")]
        {
            let _ = title;
            Some(filename.into())
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut path = rfd::FileDialog::new()
                .set_title(title)
                .add_filter(self.recording_format.label(), &[self.recording_format.extension()])
                .set_file_name(filename)
                .save_file()?;
            path.set_extension(self.recording_format.extension());
            Some(path)
        }
    }

    fn stop_recording(&mut self) {
        let Some(recorder) = &mut self.recorder else {
            return;
        };
        recorder.request_finish();
        self.recording_status = format!("Finalizing {}", recorder.path().display());
    }

    fn poll_recording(&mut self) {
        let event = self.recorder.as_mut().and_then(Recorder::poll_event);
        match event {
            Some(RecordingEvent::Finished(summary)) => {
                self.recording_status = format!(
                    "Saved {} samples to {} ({:.6}% complete)",
                    summary.rows,
                    summary.path.display(),
                    summary.completeness_percent()
                );
                self.last_recording = Some(summary);
                self.recorder = None;
            }
            Some(RecordingEvent::Interrupted(summary, reason)) => {
                self.recording_status =
                    format!("{reason}; saved {} samples to {}", summary.rows, summary.path.display());
                self.last_recording = Some(summary);
                self.recorder = None;
            }
            Some(RecordingEvent::Failed { error, journal }) => {
                self.recording_status = match journal {
                    Some(journal) => format!(
                        "{error}; the samples are kept in {} and are recovered on the next start",
                        journal.display()
                    ),
                    None => error.to_string(),
                };
                self.recorder = None;
            }
            Some(event) => {
                warn!("Unhandled recording event: {event:?}");
                self.recorder = None;
            }
            None => {}
        }
    }

    fn request_offline_catalog(&mut self) {
        if self.device_state.is_none() {
            self.offline_status = "Connect the KM003C before loading its offline catalog".to_string();
            return;
        }
        if self.offline_busy || self.recorder.is_some() || self.offline_export.is_some() {
            return;
        }
        self.offline_busy = true;
        self.offline_status = "Loading offline recording catalog...".to_string();
        if self.session.request_offline_catalog().is_err() {
            self.offline_busy = false;
            self.offline_status = "USB task is not available".to_string();
        }
    }

    fn download_selected_offline_log(&mut self) {
        if self.device_state.is_none() {
            self.offline_status = "Connect the KM003C before downloading an offline recording".to_string();
            return;
        }
        if self.offline_busy || self.recorder.is_some() || self.offline_export.is_some() {
            return;
        }
        let Some(metadata) = self
            .offline_selected
            .and_then(|index| self.offline_catalog.get(index))
            .cloned()
        else {
            self.offline_status = "Select an offline recording first".to_string();
            return;
        };
        self.offline_busy = true;
        self.offline_status = format!(
            "Downloading {} samples from {}...",
            metadata.sample_count,
            metadata.filename_lossy()
        );
        if self.session.download_offline_log(metadata).is_err() {
            self.offline_busy = false;
            self.offline_status = "USB task is not available".to_string();
        }
    }

    fn export_offline_log(&mut self) {
        if self.offline_export.is_some() {
            return;
        }
        let (Some(view), Some(device)) = (&self.offline_view, &self.offline_device_metadata) else {
            self.offline_status = "Download an offline recording before exporting it".to_string();
            return;
        };
        let device_filename = view.log.metadata.filename_lossy();
        let prefix = std::path::Path::new(device_filename.as_ref())
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .unwrap_or("offline-log");
        let Some(path) = self.select_recording_path(prefix, "Export KM003C offline recording") else {
            return;
        };
        match OfflineExport::start(path.clone(), self.recording_format, device.clone(), Arc::clone(view)) {
            Ok(task) => {
                self.offline_status = format!("Exporting to {}", path.display());
                self.offline_export = Some(task);
            }
            Err(error) => self.offline_status = error.to_string(),
        }
    }

    fn poll_offline_export(&mut self) {
        let event = self.offline_export.as_mut().and_then(OfflineExport::poll_event);
        match event {
            Some(OfflineExportEvent::Finished { path, rows }) => {
                self.offline_status = format!("Exported {rows} samples to {}", path.display());
                self.offline_export = None;
            }
            Some(OfflineExportEvent::Failed(error)) => {
                self.offline_status = error.to_string();
                self.offline_export = None;
            }
            Some(event) => {
                warn!("Unhandled export event: {event:?}");
                self.offline_export = None;
            }
            None => {}
        }
    }
}

/// Rendering of the individual panels and side-panel sections.
///
/// `eframe::App::ui` below owns only the window layout; each section here owns
/// one block of the side panel, so neither grows into a single unreadable
/// function.
fn configure_appearance(ctx: &egui::Context) {
    ctx.set_theme(egui::ThemePreference::Dark);
    ctx.set_zoom_factor(1.5);
    ctx.style_mut_of(egui::Theme::Dark, |style| {
        style.visuals.override_text_color = Some(egui::Color32::from_gray(220));
        style.visuals.weak_text_color = Some(egui::Color32::from_gray(180));
    });
}

fn readable_color(ui: &egui::Ui, dark: egui::Color32) -> egui::Color32 {
    if ui.visuals().dark_mode {
        return dark;
    }
    let [r, g, b, _] = dark.to_array();
    if r.max(g).max(b) <= 140 {
        return dark;
    }
    egui::Color32::from_rgb(
        (r as f32 * 0.45) as u8,
        (g as f32 * 0.45) as u8,
        (b as f32 * 0.45) as u8,
    )
}

impl PowerMonitorApp {
    fn header_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("POWER-Z KM003C Monitor");
            ui.separator();

            let status_color = if self.streaming {
                readable_color(ui, egui::Color32::GREEN)
            } else if self.device_state.is_some() {
                readable_color(ui, egui::Color32::YELLOW)
            } else {
                readable_color(ui, egui::Color32::RED)
            };
            ui.colored_label(readable_color(ui, status_color), &self.status);
            ui.separator();
            egui::widgets::global_theme_preference_buttons(ui);
            ui.menu_button("Scale", |ui| {
                for (label, scale) in [
                    ("100%", 1.0),
                    ("125%", 1.25),
                    ("150%", 1.5),
                    ("175%", 1.75),
                    ("200%", 2.0),
                ] {
                    if ui
                        .selectable_label((ui.ctx().zoom_factor() - scale).abs() < 0.01, label)
                        .clicked()
                    {
                        ui.ctx().set_zoom_factor(scale);
                        ui.close();
                    }
                }
            });
        });
    }

    /// Every side-panel section, in display order.
    fn side_panel(&mut self, ui: &mut egui::Ui) {
        self.connection_section(ui);
        self.device_info_section(ui);
        self.current_readings_section(ui);
        self.pd_status_section(ui);
        self.pd_timeline_controls_section(ui);
        self.live_statistics_section(ui);
        self.controls_section(ui);
        self.live_capture_section(ui);
        self.offline_recordings_section(ui);
        #[cfg(target_arch = "wasm32")]
        ui.small("Browser recording uses memory (128 MiB limit). Stop to download. Keep this tab open and active; background tabs may be throttled.");
    }

    fn device_info_section(&mut self, ui: &mut egui::Ui) {
        ui.heading("Device Info");
        ui.separator();

        {
            if let Some(state) = &self.device_state {
                egui::Grid::new("device_info_grid")
                    .num_columns(2)
                    .max_col_width((ui.available_width() - 110.0).max(100.0))
                    .spacing([10.0, 4.0])
                    .show(ui, |ui| {
                        ui.label("Model:");
                        ui.label(&state.info.model);
                        ui.end_row();

                        ui.label("Firmware:");
                        ui.label(&state.info.fw_version);
                        ui.end_row();

                        ui.label("FW Date:");
                        ui.label(&state.info.fw_date);
                        ui.end_row();

                        ui.label("HW Version:");
                        ui.label(&state.info.hw_version);
                        ui.end_row();

                        ui.label("Mfg Date:");
                        ui.label(&state.info.mfg_date);
                        ui.end_row();

                        ui.label("Serial:");
                        ui.label(&state.info.serial_id);
                        ui.end_row();

                        ui.label("Hardware ID:");
                        ui.add(egui::Label::new(state.hardware_id.to_string()).wrap());
                        ui.end_row();

                        ui.label("Auth Level:");
                        ui.label(format!("{}", state.auth_level));
                        ui.end_row();

                        ui.label("AdcQueue:");
                        ui.colored_label(
                            if state.adcqueue_enabled {
                                readable_color(ui, egui::Color32::GREEN)
                            } else {
                                readable_color(ui, egui::Color32::RED)
                            },
                            if state.adcqueue_enabled { "Enabled" } else { "Disabled" },
                        );
                        ui.end_row();
                    });
            } else {
                ui.label("Not connected");
            }
        }
    }

    fn current_readings_section(&mut self, ui: &mut egui::Ui) {
        {
            ui.add_space(20.0);
            ui.separator();
            ui.heading("Current Readings");
            ui.separator();

            egui::Grid::new("readings_grid")
                .num_columns(2)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    ui.label("Voltage:");
                    ui.label(format!("{:.3} V", self.current_voltage));
                    ui.end_row();

                    ui.label("Current:");
                    ui.label(format!("{:.3} A", self.current_current.abs()));
                    ui.end_row();

                    ui.label("Power:");
                    ui.label(format!("{:.3} W", self.current_power.abs()));
                    ui.end_row();
                });
        }
    }

    fn pd_status_section(&mut self, ui: &mut egui::Ui) {
        {
            ui.add_space(20.0);
            ui.separator();
            ui.heading("PD Status");
            ui.separator();

            if let Some(pd) = &self.pd_status {
                egui::Grid::new("pd_status_grid")
                    .num_columns(2)
                    .max_col_width((ui.available_width() - 110.0).max(100.0))
                    .spacing([10.0, 4.0])
                    .show(ui, |ui| {
                        ui.label("CC1:");
                        let cc1_v = pd.cc1.get::<volt>();
                        let cc1_color = if self.pd_connection.connected() == Some(true) && cc1_v > 0.2 {
                            readable_color(ui, egui::Color32::GREEN)
                        } else {
                            egui::Color32::GRAY
                        };
                        ui.colored_label(cc1_color, format!("{cc1_v:.3} V"));
                        ui.end_row();

                        ui.label("CC2:");
                        let cc2_v = pd.cc2.get::<volt>();
                        let cc2_color = if self.pd_connection.connected() == Some(true) && cc2_v > 0.2 {
                            readable_color(ui, egui::Color32::GREEN)
                        } else {
                            egui::Color32::GRAY
                        };
                        ui.colored_label(cc2_color, format!("{cc2_v:.3} V"));
                        ui.end_row();

                        ui.label("Type-C sink:");
                        let (color, label) = match self.pd_connection.connected() {
                            Some(true) => (readable_color(ui, egui::Color32::GREEN), "Attached"),
                            Some(false) => (readable_color(ui, egui::Color32::RED), "Not attached"),
                            None => (readable_color(ui, egui::Color32::YELLOW), "Detecting..."),
                        };
                        ui.colored_label(color, label);
                        ui.end_row();

                        ui.label("Contract:");
                        ui.add(egui::Label::new(self.pd_contract.to_string()).wrap());
                        ui.end_row();
                    });
            } else {
                ui.label("No PD data");
            }
        }
    }

    fn pd_timeline_controls_section(&mut self, ui: &mut egui::Ui) {
        {
            ui.add_space(20.0);
            ui.separator();
            ui.heading("PD Timeline");
            ui.separator();

            ui.checkbox(&mut self.pd_panel_visible, "Show PD Panel");
            ui.label("Filters:");
            ui.checkbox(&mut self.pd_protocol_visible, "Protocol messages");
            ui.add_enabled(
                self.pd_protocol_visible,
                egui::Checkbox::new(&mut self.pd_hide_good_crc, "Hide GoodCRC"),
            );
            let trace_changed = ui
                .checkbox(&mut self.pd_trace_enabled, "Firmware trace")
                .on_hover_text(
                    "Also drains the diagnostic Type-C and protocol-engine queues reverse engineered from KM003C firmware V1.9.9",
                )
                .changed();
            if trace_changed && self.device_state.is_some() {
                let _ = self.session.set_pd_trace_enabled(self.pd_trace_enabled);
            }

            ui.horizontal(|ui| {
                ui.checkbox(&mut self.pd_auto_scroll, "Auto-scroll");
                if ui.button("Clear Timeline").clicked() {
                    self.clear_pd_log();
                }
            });
            ui.label(format!(
                "Protocol: {}  |  Trace: {}",
                self.pd_log.len(),
                self.pd_trace_log.len()
            ));
        }
    }

    fn live_statistics_section(&mut self, ui: &mut egui::Ui) {
        {
            ui.add_space(20.0);
            ui.separator();
            ui.heading("Live Statistics");
            ui.separator();

            egui::Grid::new("stats_grid")
                .num_columns(2)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    ui.label("Samples:");
                    ui.label(format!("{}", self.total_samples));
                    ui.end_row();

                    ui.label("Dropped:");
                    ui.colored_label(
                        if self.dropped_samples > 0 {
                            readable_color(ui, egui::Color32::RED)
                        } else {
                            readable_color(ui, egui::Color32::GREEN)
                        },
                        format!("{}", self.dropped_samples),
                    );
                    ui.end_row();

                    ui.label("Discarded:");
                    ui.colored_label(
                        if self.discarded_sequence_samples > 0 {
                            readable_color(ui, egui::Color32::YELLOW)
                        } else {
                            readable_color(ui, egui::Color32::GREEN)
                        },
                        format!("{}", self.discarded_sequence_samples),
                    );
                    ui.end_row();

                    ui.label("Buffer:");
                    ui.label(format!("{} pts", self.data_points.len()));
                    ui.end_row();
                });
        }
    }

    fn recording_busy(&self) -> bool {
        self.recorder.is_some()
    }

    fn controls_section(&mut self, ui: &mut egui::Ui) {
        {
            ui.add_space(20.0);
            ui.separator();
            ui.heading("Controls");
            ui.separator();

            // Sample rate selector
            ui.add_enabled_ui(!self.recording_busy(), |ui| {
                ui.horizontal(|ui| {
                    ui.label("Sample Rate:");
                    let prev_rate = self.selected_rate;
                    egui::ComboBox::from_id_salt("sample_rate")
                        .selected_text(self.selected_rate.label())
                        .show_ui(ui, |ui| {
                            for rate in SampleRateOption::all() {
                                ui.selectable_value(&mut self.selected_rate, *rate, rate.label());
                            }
                        });

                    if self.selected_rate != prev_rate
                        && (self.device_state.is_some() || self.connection_attempt_in_flight)
                    {
                        info!("Sample rate changed to {}", self.selected_rate.label());
                        let _ = self.session.set_sample_rate(self.selected_rate.to_graph_rate());
                    }
                });
            });

            ui.add_space(5.0);

            // Time window selector
            ui.horizontal(|ui| {
                ui.label("Time Window:");
                egui::ComboBox::from_id_salt("time_window")
                    .selected_text(self.time_window.label())
                    .show_ui(ui, |ui| {
                        for window in TimeWindow::all() {
                            ui.selectable_value(&mut self.time_window, *window, window.label());
                        }
                    });
            });

            ui.add_space(10.0);
            ui.label("Plot metrics:");
            for (index, metric) in self.plot_metrics.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(format!("{}:", index + 1));
                    egui::ComboBox::from_id_salt(("plot_metric", index))
                        .selected_text(metric.label())
                        .show_ui(ui, |ui| {
                            for option in Metric::ALL {
                                if self.plot_source == PlotSource::Live || option.supports_offline() {
                                    ui.selectable_value(metric, option, option.label());
                                }
                            }
                        });
                });
            }

            ui.add_space(10.0);

            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!self.recording_busy(), egui::Button::new("Clear Live Data"))
                    .clicked()
                {
                    self.clear_data();
                }
            });
        }
    }

    fn live_capture_section(&mut self, ui: &mut egui::Ui) {
        {
            ui.add_space(20.0);
            ui.separator();
            ui.heading("Live Capture");
            ui.separator();

            ui.add_enabled_ui(self.recorder.is_none(), |ui| {
                ui.horizontal(|ui| {
                    ui.label("Format:");
                    egui::ComboBox::from_id_salt("recording_format")
                        .selected_text(self.recording_format.label())
                        .show_ui(ui, |ui| {
                            for format in RecordingFormat::ALL {
                                ui.selectable_value(&mut self.recording_format, format, format.label());
                            }
                        });
                });
            });

            match &self.recorder {
                Some(recorder) if recorder.is_finishing() => {
                    ui.add_enabled(false, egui::Button::new("Finalizing..."));
                }
                Some(_) => {
                    if ui.button("Stop Recording").clicked() {
                        self.stop_recording();
                    }
                }
                None => {
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(self.streaming, egui::Button::new("Start Recording"))
                            .clicked()
                        {
                            self.start_recording();
                        }
                        if ui
                            .add_enabled(!self.data_points.is_empty(), egui::Button::new("Export Buffer"))
                            .clicked()
                        {
                            self.export_buffer();
                        }
                    });
                }
            }

            if let Some(recorder) = &self.recorder {
                let progress = recorder.summary();
                ui.label(format!("Samples: {}", progress.rows));
                ui.label(format!("Missing: {}", progress.missing_samples));
                ui.label(format!("Discarded: {}", progress.discarded_sequence_samples));
                ui.label(format!("Completeness: {:.6}%", progress.completeness_percent()));
            } else if let Some(summary) = &self.last_recording {
                ui.label(format!("Last capture: {} samples", summary.rows));
                ui.label(format!("Missing: {}", summary.missing_samples));
                ui.label(format!("Discarded: {}", summary.discarded_sequence_samples));
                ui.label(format!("Completeness: {:.6}%", summary.completeness_percent()));
            }
            ui.small(&self.recording_status);
        }
    }

    fn offline_recordings_section(&mut self, ui: &mut egui::Ui) {
        {
            ui.add_space(20.0);
            ui.separator();
            ui.heading("Offline Recordings");
            ui.separator();

            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        self.device_state.is_some()
                            && !self.offline_busy
                            && self.recorder.is_none()
                            && self.offline_export.is_none(),
                        egui::Button::new("Refresh Catalog"),
                    )
                    .clicked()
                {
                    self.request_offline_catalog();
                }
                if self.offline_busy {
                    ui.spinner();
                }
            });

            if !self.offline_catalog.is_empty() {
                let selected_text = self
                    .offline_selected
                    .and_then(|index| self.offline_catalog.get(index))
                    .map_or_else(
                        || "Select a recording".to_string(),
                        |metadata| metadata.filename_lossy().into_owned(),
                    );
                egui::ComboBox::from_id_salt("offline_recording")
                    .selected_text(selected_text)
                    .show_ui(ui, |ui| {
                        for (index, metadata) in self.offline_catalog.iter().enumerate() {
                            ui.selectable_value(
                                &mut self.offline_selected,
                                Some(index),
                                format!(
                                    "#{} {} ({} samples)",
                                    index,
                                    metadata.filename_lossy(),
                                    metadata.sample_count
                                ),
                            );
                        }
                    });

                if let Some(metadata) = self.offline_selected.and_then(|index| self.offline_catalog.get(index)) {
                    egui::Grid::new("offline_metadata_grid")
                        .num_columns(2)
                        .spacing([10.0, 4.0])
                        .show(ui, |ui| {
                            ui.label("Samples:");
                            ui.label(metadata.sample_count.to_string());
                            ui.end_row();
                            ui.label("Interval:");
                            ui.label(format!("{} ms", metadata.interval.get::<millisecond>()));
                            ui.end_row();
                            ui.label("Duration:");
                            ui.label(format!("{:.1} s", metadata.recorded_duration.get::<second>()));
                            ui.end_row();
                            ui.label("Final charge:");
                            ui.label(format!("{:.3} mAh", metadata.final_charge.get::<milliampere_hour>()));
                            ui.end_row();
                            ui.label("Final energy:");
                            ui.label(format!("{:.3} mWh", metadata.final_energy.get::<milliwatt_hour>()));
                            ui.end_row();
                        });
                }

                if ui
                    .add_enabled(
                        self.device_state.is_some()
                            && self.offline_selected.is_some()
                            && !self.offline_busy
                            && self.recorder.is_none()
                            && self.offline_export.is_none(),
                        egui::Button::new("Download and View"),
                    )
                    .clicked()
                {
                    self.download_selected_offline_log();
                }
            }

            if let Some(view) = &self.offline_view {
                ui.label(format!(
                    "Loaded: {} ({} samples)",
                    view.log.metadata.filename_lossy(),
                    view.samples.len()
                ));
                let previous_source = self.plot_source;
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.plot_source, PlotSource::Live, "View Live");
                    ui.selectable_value(&mut self.plot_source, PlotSource::Offline, "View Offline");
                });
                if previous_source != self.plot_source && self.plot_source == PlotSource::Offline {
                    self.time_window = TimeWindow::All;
                    for metric in &mut self.plot_metrics {
                        if !metric.supports_offline() {
                            *metric = Metric::Voltage;
                        }
                    }
                }
                ui.add_enabled_ui(self.offline_export.is_none() && self.recorder.is_none(), |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Export format:");
                        egui::ComboBox::from_id_salt("offline_recording_format")
                            .selected_text(self.recording_format.label())
                            .show_ui(ui, |ui| {
                                for format in RecordingFormat::ALL {
                                    ui.selectable_value(&mut self.recording_format, format, format.label());
                                }
                            });
                    });
                });
                if let Some(export) = &self.offline_export {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(format!("Exporting {}", export.path().display()));
                    });
                } else if ui.button("Export Downloaded").clicked() {
                    self.export_offline_log();
                }
            }
            ui.small(&self.offline_status);
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn choose_device(&mut self) {
        let window = web_sys::window().unwrap();
        if !window.is_secure_context()
            || !js_sys::Reflect::get(&window.navigator(), &"usb".into())
                .is_ok_and(|usb| !usb.is_null() && !usb.is_undefined())
        {
            self.status = "WebUSB needs desktop Chrome/Edge on HTTPS or localhost.".into();
            return;
        }
        let (tx, rx) = mpsc::unbounded_channel();
        self.chooser = Some(rx);
        self.connection_attempt_in_flight = true;
        self.status = "Select KM003C in the browser permission dialog...".into();
        self.auto_connect_enabled = true;
        // No asynchronous work before request_device: preserve user activation.
        wasm_bindgen_futures::spawn_local(async move {
            let filters = [nusb::DeviceSelector::all().with_vid_pid(0x5fc9, 0x0063)];
            let result = async {
                let info = nusb::request_device(&filters)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| {
                        "No device selected: permission denied or dialog cancelled. Click Connect to retry.".to_string()
                    })?;
                let serial = info.serial_number().map(str::to_owned);
                let device = km003c_lib::runtime::timeout(Duration::from_secs(10), async { info.open().await })
                    .await
                    .map_err(|e| e.to_string())?
                    .map_err(|e| e.to_string())?;
                Ok((device, serial))
            }
            .await;
            let _ = tx.send(result);
        });
    }

    fn connection_section(&mut self, ui: &mut egui::Ui) {
        {
            ui.add_space(5.0);

            if self.device_state.is_some() || self.connection_attempt_in_flight || self.reconnect_at.is_some() {
                if ui.button("Disconnect").clicked() {
                    info!("Disconnect requested");
                    self.auto_connect_enabled = false;
                    #[cfg(target_arch = "wasm32")]
                    {
                        self.chooser = None;
                    }
                    self.reconnect_at = None;
                    let _ = self.session.disconnect();
                }
            } else if self.device_state.is_none() {
                #[cfg(not(target_arch = "wasm32"))]
                ui.checkbox(&mut self.usb_reset, "USB reset on connect");
                if ui.button("Connect").clicked() {
                    info!("Connect requested");
                    #[cfg(not(target_arch = "wasm32"))]
                    self.request_connection(true);
                    #[cfg(target_arch = "wasm32")]
                    self.choose_device();
                }
            }
        }
    }

    fn pd_timeline_panel(&mut self, ui: &mut egui::Ui) {
        {
            {
                {
                    ui.heading("USB PD Timeline");
                    if self.pd_trace_enabled {
                        ui.small(
                            "[FW] timestamps have one-second resolution; same-second ordering relative to [WIRE] events is approximate.",
                        );
                    }
                    ui.separator();

                    let text_style = egui::TextStyle::Monospace;
                    let row_height = ui.text_style_height(&text_style);
                    let timeline = pd_timeline_entries(
                        &self.pd_log,
                        &self.pd_trace_log,
                        TimelineFilter {
                            protocol: self.pd_protocol_visible,
                            good_crc: !self.pd_hide_good_crc,
                            trace: self.pd_trace_enabled,
                        },
                    );

                    egui::ScrollArea::vertical()
                        .auto_shrink([false; 2])
                        .stick_to_bottom(self.pd_auto_scroll)
                        .show(ui, |ui| {
                            for timeline_entry in timeline {
                                match timeline_entry {
                                    PdTimelineEntry::Protocol(entry) => {
                                        let color = match entry.category {
                                            PdLogCategory::Connect => readable_color(ui, egui::Color32::GREEN),
                                            PdLogCategory::Disconnect => readable_color(ui, egui::Color32::RED),
                                            PdLogCategory::SourceCaps => egui::Color32::from_rgb(100, 149, 237),
                                            PdLogCategory::Request => readable_color(ui, egui::Color32::YELLOW),
                                            PdLogCategory::Control => egui::Color32::GRAY,
                                            PdLogCategory::Extended => egui::Color32::from_rgb(255, 165, 0),
                                            PdLogCategory::Error => egui::Color32::from_rgb(255, 80, 80),
                                        };

                                        ui.colored_label(
                                            readable_color(ui, color),
                                            egui::RichText::new(format!("[WIRE] {}", entry.summary()))
                                                .monospace()
                                                .size(row_height),
                                        );
                                        for detail in &entry.details {
                                            ui.colored_label(
                                                readable_color(ui, color),
                                                egui::RichText::new(format!("       {detail}"))
                                                    .monospace()
                                                    .size(row_height),
                                            );
                                        }
                                    }
                                    PdTimelineEntry::FirmwareTrace(entry) => {
                                        let color = match entry.category {
                                            PdTraceCategory::TypeCState => egui::Color32::from_rgb(100, 200, 255),
                                            PdTraceCategory::ProtocolEvent => {
                                                readable_color(ui, egui::Color32::LIGHT_GREEN)
                                            }
                                            _ => readable_color(ui, egui::Color32::YELLOW),
                                        };
                                        ui.colored_label(
                                            readable_color(ui, color),
                                            egui::RichText::new(format!("[FW]   {}", entry.summary()))
                                                .monospace()
                                                .size(row_height),
                                        );
                                    }
                                }
                            }
                        });
                }
            }
        }
    }

    fn plots_panel(&mut self, ui: &mut egui::Ui) {
        {
            match self.plot_source {
                PlotSource::Live => ui.small("Plot source: live AdcQueue"),
                PlotSource::Offline => {
                    let filename = self
                        .offline_view
                        .as_ref()
                        .map_or_else(|| "not loaded".into(), |view| view.log.metadata.filename_lossy());
                    ui.small(format!("Plot source: offline recording {filename}"))
                }
            };
            let available_height = ui.available_height();
            let plot_height = (available_height - 30.0) / 3.0;

            let current_time = match self.plot_source {
                PlotSource::Live => self.data_points.back().map_or(0.0, |sample| sample.elapsed_seconds()),
                PlotSource::Offline => self
                    .offline_view
                    .as_ref()
                    .and_then(|view| view.samples.last())
                    .map_or(0.0, |sample| sample.elapsed_seconds()),
            };
            let min_time = self
                .time_window
                .seconds()
                .map(|window| (current_time - window).max(0.0));
            let live_start = min_time.map_or(0, |min| {
                self.data_points
                    .partition_point(|sample| sample.elapsed_seconds() < min)
            });

            for (index, metric) in self.plot_metrics.into_iter().enumerate() {
                ui.label(format!("{} ({})", metric.label(), metric.unit()));
                Plot::new(("measurement_plot", index))
                    .height(plot_height)
                    .show_axes([true, true])
                    .show_grid(true)
                    .allow_boxed_zoom(true)
                    .allow_drag(true)
                    .allow_scroll(true)
                    .show(ui, |plot_ui| {
                        let bounds = plot_ui.plot_bounds();
                        let x_bounds = [bounds.min()[0], bounds.max()[0]];
                        let columns = plot_ui.transform().frame().width().ceil() as usize;
                        let points: PlotPoints = match self.plot_source {
                            PlotSource::Live => display_plot_points(
                                self.data_points
                                    .iter()
                                    .skip(live_start)
                                    .map(|sample| [sample.elapsed_seconds(), metric.value(sample)]),
                                x_bounds,
                                columns,
                            ),
                            PlotSource::Offline => display_plot_points(
                                self.offline_view
                                    .iter()
                                    .flat_map(|view| &view.samples)
                                    .filter(|sample| min_time.is_none_or(|min| sample.elapsed_seconds() >= min))
                                    .filter_map(|sample| {
                                        sample
                                            .metric_value(metric)
                                            .map(|value| [sample.elapsed_seconds(), value])
                                    }),
                                x_bounds,
                                columns,
                            ),
                        };
                        plot_ui.line(Line::new(metric.label(), points).color(metric.color()).width(1.5_f32));
                    });
            }
        }
    }
}

impl eframe::App for PowerMonitorApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.process_messages();

        // Request repaints - fast when streaming, slower when idle
        if self.streaming && self.plot_source == PlotSource::Live {
            ui.ctx().request_repaint_after(Duration::from_millis(16)); // ~60fps when streaming
        } else {
            ui.ctx().request_repaint_after(Duration::from_millis(100)); // 10fps when idle
        }

        egui::Panel::top("header").show(ui, |ui| self.header_bar(ui));

        egui::Panel::left("info_panel").exact_size(280.0).show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .show(ui, |ui| self.side_panel(ui));
        });

        if self.pd_panel_visible {
            egui::Panel::bottom("pd_panel")
                .resizable(true)
                .min_size(100.0)
                .default_size(200.0)
                .show(ui, |ui| self.pd_timeline_panel(ui));
        }

        egui::CentralPanel::default().show(ui, |ui| self.plots_panel(ui));
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    info!("Starting POWER-Z KM003C GUI application");

    let dirs = AppDirs::locate();
    let preferences = dirs.load_preferences();
    let (session, session_events) = Session::spawn();

    // Auto-connect on startup
    let _ = session.connect(preferences.sample_rate, !cfg!(target_os = "macos"));

    // Run egui application
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1024.0, 768.0])
            .with_title("POWER-Z KM003C Monitor"),
        ..Default::default()
    };

    let app = PowerMonitorApp::new(session, session_events, preferences, dirs);

    eframe::run_native(
        "POWER-Z KM003C Monitor",
        options,
        Box::new(|cc| {
            configure_appearance(&cc.egui_ctx);
            Ok(Box::new(app))
        }),
    )
    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use km003c_lib::{OfflineLog, read_recording};

    #[test]
    fn desktop_plot_retains_every_sample_even_at_small_width() {
        let samples: Vec<_> = (0..10_000).map(|i| [f64::from(i), f64::from(i % 17)]).collect();
        let displayed = display_plot_points(samples.iter().copied(), [0.0, 10_000.0], 10);
        assert_eq!(displayed.points().len(), samples.len());
        for (actual, expected) in displayed.points().iter().zip(samples) {
            assert_eq!([actual.x, actual.y], expected);
        }
    }

    /// An app whose session has no device task behind it. It saves no
    /// preferences and journals into a directory of its own.
    fn test_app() -> (PowerMonitorApp, mpsc::UnboundedSender<SessionEvent>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (session, _commands) = Session::detached();
        let dirs = AppDirs {
            preferences: None,
            journal: std::env::temp_dir().join(format!("km003c-egui-test-journal-{}", std::process::id())),
        };
        (
            PowerMonitorApp::new(session, event_rx, Preferences::default(), dirs),
            event_tx,
        )
    }

    /// Three samples captured from a KM003C.
    fn captured_offline_log() -> OfflineLog {
        use km003c_lib::uom::si::electric_charge::microampere_hour;
        use km003c_lib::uom::si::energy::microwatt_hour;
        use km003c_lib::uom::si::f64::{ElectricCharge, Energy, Time};

        let bytes = [
            "81494c0021f0e2ff56ebffffb998ffff",
            "bcaa89006e25f2ff2dd5f8fff7fdd6ff",
            "cf2a8900947dfeffa1a2f3ffe04da8ff",
        ]
        .into_iter()
        .flat_map(|sample| hex::decode(sample).unwrap())
        .collect::<Vec<_>>();
        let mut filename_raw = [0; 16];
        filename_raw[..5].copy_from_slice(b"A01.d");
        OfflineLog::from_bytes(
            LogMetadata {
                filename_raw,
                unknown_0x10: 0x0a45,
                sample_count: 3,
                interval: Time::new::<millisecond>(10_000.0),
                flags: 0,
                recorded_duration: Time::new::<second>(20.0),
                final_charge: ElectricCharge::new::<microampere_hour>(-810_335.0),
                final_energy: Energy::new::<microwatt_hour>(-5_747_232.0),
                data_offset: 0,
                reserved_tail: [0; 8],
            },
            &bytes,
        )
        .unwrap()
    }

    #[test]
    fn pd_timeline_filters_and_orders_both_sources() {
        let wire = |title: &str| PdLogEntry {
            timestamp_seconds: 12.25,
            category: PdLogCategory::Control,
            sop: Some(0),
            title: title.to_string(),
            header: None,
            details: Vec::new(),
        };
        let protocol_log = VecDeque::from([wire("Accept"), wire("GoodCRC")]);
        let trace = km003c_lib::PdTrace {
            state_events: vec![km003c_lib::PdTraceStateEvent {
                state: km003c_lib::PdTypeCState::AttachedSink,
                timestamp: km003c_lib::uom::si::f64::Time::new::<second>(11.0),
            }],
            protocol_events: Vec::new(),
        };
        let trace_log = VecDeque::from(trace.entries());
        let all = TimelineFilter {
            protocol: true,
            good_crc: true,
            trace: true,
        };

        let combined = pd_timeline_entries(&protocol_log, &trace_log, all);
        assert_eq!(combined.len(), 3);
        assert!(matches!(combined[0], PdTimelineEntry::FirmwareTrace(_)));
        assert!(matches!(combined[1], PdTimelineEntry::Protocol(_)));

        let protocol_only = pd_timeline_entries(&protocol_log, &trace_log, TimelineFilter { trace: false, ..all });
        assert_eq!(protocol_only.len(), 2);
        assert!(matches!(protocol_only[0], PdTimelineEntry::Protocol(_)));

        let without_good_crc =
            pd_timeline_entries(&protocol_log, &trace_log, TimelineFilter { good_crc: false, ..all });
        assert_eq!(without_good_crc.len(), 2);
        assert!(
            without_good_crc
                .iter()
                .all(|entry| !matches!(entry, PdTimelineEntry::Protocol(entry) if entry.is_good_crc()))
        );
    }

    #[test]
    fn a_contract_survives_a_meter_reconnect() {
        let (mut app, usb_tx) = test_app();
        let message = |hex_data: &str| km003c_lib::PdEvent {
            timestamp: km003c_lib::uom::si::f64::Time::new::<millisecond>(0.0),
            data: PdEventData::PdMessage {
                sop: 0,
                wire_data: hex::decode(hex_data).unwrap(),
            },
        };
        usb_tx
            .send(SessionEvent::PdEvents(vec![
                message("a1612c9101082cd102002cc103002cb10400454106003c21dcc0"),
                message("8210dc700323"),
                message("a305"),
                message("a607"),
            ]))
            .unwrap();
        app.process_messages();
        assert_eq!(app.pd_contract.to_string(), "PDO#2 (Fixed 9V @ 3.0A (27W)) @ 2.2A");

        usb_tx
            .send(SessionEvent::Disconnected {
                retry_when_present: true,
            })
            .unwrap();
        app.process_messages();

        assert_eq!(app.pd_contract.stage(), km003c_lib::PdContractStage::Active);
    }

    #[test]
    fn preferences_follow_the_controls() {
        let (mut app, _usb_tx) = test_app();
        app.selected_rate = SampleRateOption::Sps1000;
        app.time_window = TimeWindow::All;
        app.pd_hide_good_crc = false;

        let preferences = app.preferences();

        assert_eq!(preferences.sample_rate, GraphSampleRate::Sps1000);
        assert_eq!(preferences.time_window_seconds, None);
        assert!(!preferences.pd_hide_good_crc);
        assert_eq!(
            TimeWindow::from_seconds(preferences.time_window_seconds),
            TimeWindow::All
        );
    }

    #[test]
    fn downloaded_offline_log_becomes_the_active_plot_source() {
        let (mut app, usb_tx) = test_app();
        app.plot_metrics[0] = Metric::Cc1;

        usb_tx
            .send(SessionEvent::OfflineLogDownloaded(captured_offline_log()))
            .unwrap();
        app.process_messages();

        assert_eq!(app.plot_source, PlotSource::Offline);
        assert_eq!(app.time_window, TimeWindow::All);
        assert_eq!(app.plot_metrics[0], Metric::Voltage);
        assert_eq!(app.offline_view.as_ref().unwrap().samples.len(), 3);
        assert!(!app.offline_busy);
    }

    #[test]
    fn empty_offline_catalog_clears_selection() {
        let (mut app, usb_tx) = test_app();
        app.offline_selected = Some(2);

        usb_tx.send(SessionEvent::OfflineCatalog(Vec::new())).unwrap();
        app.process_messages();

        assert!(app.offline_catalog.is_empty());
        assert_eq!(app.offline_selected, None);
        assert!(app.offline_status.contains("No offline recordings"));
    }

    #[test]
    #[ignore = "requires a connected KM003C"]
    fn hardware_offline_flow_pauses_and_resumes_streaming() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (session, mut usb_rx) = Session::spawn();
            session.connect(GraphSampleRate::Sps50, false).unwrap();

            let startup_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            let mut device_state = None;
            let mut streaming = false;
            while !(device_state.is_some() && streaming) {
                let message = tokio::time::timeout_at(startup_deadline, usb_rx.recv())
                    .await
                    .expect("device did not connect before the deadline")
                    .expect("USB task exited during connection");
                match message {
                    SessionEvent::Connected(state) => device_state = Some(state),
                    SessionEvent::StreamingStarted(GraphSampleRate::Sps50) => streaming = true,
                    _ => {}
                }
            }

            session.request_offline_catalog().unwrap();
            let operation_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            let mut stopped = false;
            let catalog = loop {
                let message = tokio::time::timeout_at(operation_deadline, usb_rx.recv())
                    .await
                    .expect("offline catalog request did not finish before the deadline")
                    .expect("USB task exited during offline catalog request");
                match message {
                    SessionEvent::StreamingStopped => stopped = true,
                    SessionEvent::OfflineCatalog(catalog) => {
                        assert!(stopped, "catalog arrived before streaming was paused");
                        break catalog;
                    }
                    SessionEvent::OfflineOperationFailed(error) => panic!("offline catalog failed: {error}"),
                    _ => {}
                }
            };
            loop {
                let message = tokio::time::timeout_at(operation_deadline, usb_rx.recv())
                    .await
                    .expect("streaming did not resume after catalog request")
                    .expect("USB task exited before streaming resumed");
                if matches!(message, SessionEvent::StreamingStarted(GraphSampleRate::Sps50)) {
                    break;
                }
            }

            let mut downloaded_log = None;
            if let Some(metadata) = catalog.first().cloned() {
                session.download_offline_log(metadata.clone()).unwrap();
                let download_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
                let mut stopped = false;
                let mut downloaded = false;
                let mut resumed = false;
                while !(downloaded && resumed) {
                    let message = tokio::time::timeout_at(download_deadline, usb_rx.recv())
                        .await
                        .expect("offline download did not finish before the deadline")
                        .expect("USB task exited during offline download");
                    match message {
                        SessionEvent::StreamingStopped => stopped = true,
                        SessionEvent::OfflineLogDownloaded(log) => {
                            assert!(stopped, "offline log arrived before streaming was paused");
                            assert_eq!(log.metadata, metadata);
                            assert_eq!(log.samples.len(), usize::from(metadata.sample_count));
                            downloaded_log = Some(log);
                            downloaded = true;
                        }
                        SessionEvent::StreamingStarted(GraphSampleRate::Sps50) => resumed = true,
                        SessionEvent::OfflineOperationFailed(error) => panic!("offline download failed: {error}"),
                        _ => {}
                    }
                }
            }

            session.disconnect().unwrap();
            drop(session);
            // The event channel closes once the session task has exited.
            tokio::time::timeout(Duration::from_secs(5), async { while usb_rx.recv().await.is_some() {} })
                .await
                .expect("USB task did not stop after disconnect");

            if let Some(log) = downloaded_log {
                let device_state = device_state.expect("connected device state was not retained");
                let recording_metadata = RecordingMetadata::from(device_state.as_ref());
                let expected_rows = log.samples.len();
                let expected_charge_uah = log
                    .metadata
                    .final_charge
                    .get::<km003c_lib::uom::si::electric_charge::microampere_hour>();
                let expected_energy_uwh = log
                    .metadata
                    .final_energy
                    .get::<km003c_lib::uom::si::energy::microwatt_hour>();
                let view = Arc::new(OfflineRecordingView::new(log));
                assert_eq!(view.samples.last().unwrap().charge_uah, expected_charge_uah);
                assert_eq!(view.samples.last().unwrap().energy_uwh, expected_energy_uwh);

                for format in RecordingFormat::ALL {
                    let path = std::env::temp_dir().join(format!(
                        "km003c-egui-hardware-offline-{}.{}",
                        std::process::id(),
                        format.extension()
                    ));
                    let mut export =
                        OfflineExport::start(path.clone(), format, recording_metadata.clone(), Arc::clone(&view))
                            .unwrap();
                    let export_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                    let rows = loop {
                        match export.poll_event() {
                            Some(OfflineExportEvent::Finished { rows, .. }) => break rows,
                            Some(OfflineExportEvent::Failed(error)) => panic!("offline export failed: {error}"),
                            Some(event) => panic!("unexpected export event: {event:?}"),
                            None => {
                                assert!(
                                    tokio::time::Instant::now() < export_deadline,
                                    "offline export did not finish before the deadline"
                                );
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                        }
                    };
                    assert_eq!(rows, expected_rows);
                    let dataframe = read_recording(&path).unwrap();
                    assert_eq!(dataframe.shape(), (expected_rows, 23));
                    assert_eq!(
                        dataframe
                            .column("charge_uah")
                            .unwrap()
                            .f64()
                            .unwrap()
                            .get(expected_rows - 1),
                        Some(expected_charge_uah)
                    );
                    assert_eq!(
                        dataframe
                            .column("energy_uwh")
                            .unwrap()
                            .f64()
                            .unwrap()
                            .get(expected_rows - 1),
                        Some(expected_energy_uwh)
                    );
                    std::fs::remove_file(path).unwrap();
                }
            }
        });
    }
}

#[cfg(target_arch = "wasm32")]
fn main() {
    use wasm_bindgen::JsCast;
    let _ = eframe::WebLogger::init(log::LevelFilter::Info);
    wasm_bindgen_futures::spawn_local(async {
        let canvas = web_sys::window()
            .unwrap()
            .document()
            .unwrap()
            .get_element_by_id("km003c")
            .unwrap()
            .dyn_into::<web_sys::HtmlCanvasElement>()
            .unwrap();
        let (session, events) = Session::spawn();
        let result = eframe::WebRunner::new()
            .start(
                canvas,
                eframe::WebOptions::default(),
                Box::new(move |cc| {
                    configure_appearance(&cc.egui_ctx);
                    let dirs = AppDirs::locate();
                    let preferences = dirs.load_preferences();
                    Ok(Box::new(PowerMonitorApp::new(session, events, preferences, dirs)))
                }),
            )
            .await;
        if let Some(notice) = web_sys::window()
            .unwrap()
            .document()
            .unwrap()
            .get_element_by_id("notice")
        {
            match result {
                Ok(()) => notice.remove(),
                Err(error) => {
                    notice.set_text_content(Some(&format!("Could not start egui (WebGL2 required): {error:?}")))
                }
            }
        }
    });
}
