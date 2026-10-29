#[cfg(target_arch = "wasm32")]
mod browser_devices;
mod chart_view;
mod firmware_io;
mod firmware_ui;
mod gpu_plot;
mod measurement_ui;
mod metric_color;
mod pd_timeline;

use chart_view::{TimeView, VerticalScale};
use eframe::egui;
use egui_plot::{Plot, PlotBounds};
use gpu_plot::{GpuPlot, GpuPlotItem, Series};
#[cfg(not(target_arch = "wasm32"))]
use km003c_lib::RecoveryOutcome;
use km003c_lib::runtime::Instant;
use km003c_lib::uom::si::electric_charge::milliampere_hour;
use km003c_lib::uom::si::electric_potential::volt;
use km003c_lib::uom::si::energy::milliwatt_hour;
use km003c_lib::uom::si::time::{millisecond, second};
use km003c_lib::{
    DeviceState, GraphSampleRate, LogMetadata, MeasurementAccumulator, MeasurementSample, Metric, OfflineExport,
    OfflineExportEvent, OfflineRecordingView, PdConnectionTracker, PdContract, PdLogCategory, PdLogger,
    PdTraceCategory, PdTraceEntry, PlotScaleMode, PlotScaleSettings, Preferences, Recorder, RecordingEvent,
    RecordingFormat, RecordingMetadata, RecordingSummary, Session, SessionEvent,
    pd::{PdEventData, PdStatus},
};
use pd_timeline::PdLogRow;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppTab {
    Charts,
    Pd,
    Recordings,
    Firmware,
}

enum PdTimelineEntry<'a> {
    Protocol(&'a PdLogRow),
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
    protocol_log: &'a VecDeque<PdLogRow>,
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
    firmware: firmware_ui::FirmwareUi,
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
    /// Identity and firmware associated with live data, retained across detach.
    measurement_source: Option<Arc<DeviceState>>,
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
    gpu_plots: Option<[RefCell<GpuPlot>; 3]>,
    plot_scales: [PlotScaleSettings; 3],
    vertical_scales: [VerticalScale; 3],
    time_view: TimeView,
    paused_view: Option<(VecDeque<MeasurementSample>, u64)>,
    chart_rects: [Option<egui::Rect>; 3],
    dragging_plot: bool,
    shared_cursor: Option<f64>,
    active_tab: AppTab,
    settings_open: bool,
    stream_command_pending: bool,
    acquisition_requested: bool,
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
    pd_log: VecDeque<PdLogRow>,
    pd_wire_messages: u64,
    pd_show_diagnostics: bool,
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
    #[cfg(target_arch = "wasm32")]
    browser_devices: browser_devices::BrowserDevices,
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
            firmware: firmware_ui::FirmwareUi::default(),
            data_points: VecDeque::new(),
            measurement_accumulator: MeasurementAccumulator::default(),
            session_events,
            session,
            device_state: None,
            measurement_source: None,
            status: if cfg!(target_arch = "wasm32") {
                "Press Start to begin measuring"
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
            gpu_plots: None,
            plot_scales: preferences.plot_scales.map(PlotScaleSettings::sanitized),
            vertical_scales: std::array::from_fn(|_| VerticalScale::default()),
            time_view: TimeView::default(),
            paused_view: None,
            chart_rects: [None; 3],
            dragging_plot: false,
            shared_cursor: None,
            active_tab: AppTab::Charts,
            settings_open: false,
            stream_command_pending: false,
            acquisition_requested: !cfg!(target_arch = "wasm32"),
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
            pd_wire_messages: 0,
            pd_show_diagnostics: false,
            max_pd_entries: 1000,
            pd_status: None,
            pd_connection: PdConnectionTracker::default(),
            pd_contract: PdContract::default(),
            pd_hide_good_crc: preferences.pd_hide_good_crc,
            pd_auto_scroll: true,
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
            selected_serial: preferences.last_device_serial.clone(),
            #[cfg(target_arch = "wasm32")]
            browser_devices: browser_devices::BrowserDevices::new(),
            auto_connect_enabled: true,
            reconnect_at: None,
            dirs,
            saved_preferences: preferences,
            #[cfg(not(target_arch = "wasm32"))]
            recovery,
        }
    }

    fn init_gpu(&mut self, cc: &eframe::CreationContext<'_>) {
        let state = cc.wgpu_render_state.as_ref().expect("wgpu renderer is required");
        self.gpu_plots = Some(std::array::from_fn(|_| RefCell::new(GpuPlot::new(state.clone()))));
    }

    fn preferences(&self) -> Preferences {
        let mut preferences = self.saved_preferences.clone();
        preferences.sample_rate = self.selected_rate.to_graph_rate();
        preferences.time_window_seconds = self.time_window.seconds();
        preferences.plot_metrics = self.plot_metrics;
        preferences.plot_scales = self.plot_scales.map(PlotScaleSettings::sanitized);
        #[cfg(target_arch = "wasm32")]
        {
            preferences.last_device_serial = self.selected_serial.clone();
        }
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
            self.acquisition_requested = true;
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
        self.browser_devices.poll(self.selected_serial.as_deref());
        #[cfg(target_arch = "wasm32")]
        if let Some(result) = self.chooser.as_mut().and_then(|rx| rx.try_recv().ok()) {
            self.chooser = None;
            self.browser_devices.refresh();
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
                    self.stream_command_pending = false;
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
                    self.accept_measurement_source(&state);
                    self.pd_wire_messages = 0;
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
                    self.stream_command_pending = false;
                    if !self.acquisition_requested {
                        let _ = self.session.set_streaming(false);
                    }
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
                            PdEventData::PdMessage { .. } | PdEventData::DeviceStatus { .. } => {}
                        }

                        let entry = self.pd_decoder.log_event(event);
                        self.pd_contract.observe(&entry);
                        if matches!(event.data, PdEventData::PdMessage { .. }) && entry.category != PdLogCategory::Error
                        {
                            self.pd_wire_messages += 1;
                        }
                        pd_timeline::push(&mut self.pd_log, entry, self.max_pd_entries);
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
                    self.active_tab = AppTab::Charts;
                    self.reset_view();
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
                    self.stream_command_pending = false;
                    self.status = "Connected · acquisition stopped".to_string();
                }
                SessionEvent::Error(err) => {
                    self.status = format!("Error: {}", err);
                }
                SessionEvent::Disconnected { retry_when_present } => {
                    self.stream_command_pending = false;
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

    fn reset_view(&mut self) {
        self.time_view.live();
        self.paused_view = None;
        self.shared_cursor = None;
        for scale in &mut self.vertical_scales {
            scale.reset();
        }
    }

    fn accept_measurement_source(&mut self, state: &Arc<DeviceState>) {
        let same_source = self.measurement_source.as_ref().is_some_and(|previous| {
            previous.hardware_id == state.hardware_id
                && RecordingMetadata::from(previous.as_ref()) == RecordingMetadata::from(state.as_ref())
                && previous.info.fw_date == state.info.fw_date
        });
        if !same_source {
            self.stop_recording();
            self.clear_data();
            self.clear_pd_log();
            self.pd_contract = PdContract::default();
            self.current_voltage = 0.0;
            self.current_current = 0.0;
            self.current_power = 0.0;
        }
        self.measurement_source = Some(Arc::clone(state));
    }

    fn clear_data(&mut self) {
        self.reset_view();
        self.data_points.clear();
        if let Some(plots) = &self.gpu_plots {
            for plot in plots {
                plot.borrow_mut().invalidate();
            }
        }
        self.total_samples = 0;
        self.dropped_samples = 0;
        self.discarded_sequence_samples = 0;
        self.measurement_accumulator.reset();
        info!("Data cleared");
    }

    fn clear_pd_log(&mut self) {
        self.pd_log.clear();
        self.pd_wire_messages = 0;
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
        let Some(state) = &self.measurement_source else {
            self.recording_status = "No live measurement source is available".to_string();
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

/// Draw `text` in the current grid cell at a fixed two-line height.
///
/// The width is the cell's available width, which the grid already caps, and
/// the label does not report the unwrapped string width. A longer contract
/// stays two lines, with the rest on hover, so the sidebar neither grows
/// sideways nor pushes the sections below.
fn contract_label(ui: &mut egui::Ui, text: &str) -> egui::Response {
    const ROWS: usize = 2;
    let width = ui.available_width();
    let width = if width.is_finite() { width } else { 0.0 };
    let color = ui.visuals().text_color();
    let font_id = egui::TextStyle::Body.resolve(ui.style());
    let row_height = ui.text_style_height(&egui::TextStyle::Body);
    let mut job = egui::text::LayoutJob::simple(text.to_owned(), font_id, color, width);
    job.wrap.max_rows = ROWS;
    let galley = ui.fonts_mut(|fonts| fonts.layout_job(job));
    let show_full_text = galley.elided || galley.rect.width() > width + 1.0;
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, row_height * ROWS as f32), egui::Sense::hover());
    ui.painter_at(rect).galley(rect.left_top(), galley, color);
    if show_full_text {
        response.on_hover_text(text)
    } else {
        response
    }
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
        ui.horizontal_wrapped(|ui| {
            ui.heading("POWER-Z KM003C Monitor");
            ui.separator();

            if ui.button("Settings").clicked() {
                self.settings_open = !self.settings_open;
            }
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
        let status_color = if self.streaming {
            egui::Color32::LIGHT_GREEN
        } else if self.device_state.is_some() {
            egui::Color32::YELLOW
        } else {
            ui.visuals().text_color()
        };
        ui.add(egui::Label::new(egui::RichText::new(&self.status).color(readable_color(ui, status_color))).truncate())
            .on_hover_text(&self.status);
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
                        contract_label(ui, &self.pd_contract.to_string());
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

            ui.checkbox(&mut self.pd_show_diagnostics, "Show device diagnostics");
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

    fn recording_busy(&self) -> bool {
        self.recorder.is_some()
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
                if previous_source != self.plot_source {
                    self.reset_view();
                    self.active_tab = AppTab::Charts;
                }
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
    fn choose_device(&mut self, force_chooser: bool) {
        let cached = (!force_chooser)
            .then(|| self.browser_devices.selected_device())
            .flatten();
        self.acquisition_requested = true;
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
        self.reconnect_at = None;
        self.status = if cached.is_some() {
            "Opening the permitted KM003C…"
        } else {
            "Select KM003C in the browser permission dialog..."
        }
        .into();
        self.auto_connect_enabled = true;
        // No asynchronous work before request_device: preserve user activation.
        wasm_bindgen_futures::spawn_local(async move {
            let filters = [nusb::DeviceSelector::all().with_vid_pid(0x5fc9, 0x0063)];
            let result = async {
                let info = if let Some(info) = cached {
                    info
                } else {
                    nusb::request_device(&filters)
                        .await
                        .map_err(|e| e.to_string())?
                        .ok_or_else(|| {
                            "No device selected: permission denied or dialog cancelled. Press Start to retry."
                                .to_string()
                        })?
                };
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
                                        if entry.category == PdLogCategory::Diagnostic && !self.pd_show_diagnostics {
                                            continue;
                                        }
                                        let color = match entry.category {
                                            PdLogCategory::Connect => readable_color(ui, egui::Color32::GREEN),
                                            PdLogCategory::Disconnect => readable_color(ui, egui::Color32::RED),
                                            PdLogCategory::SourceCaps => egui::Color32::from_rgb(100, 149, 237),
                                            PdLogCategory::Request => readable_color(ui, egui::Color32::YELLOW),
                                            PdLogCategory::Diagnostic => egui::Color32::GRAY,
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
                                        for detail in entry.details.iter().chain(entry.latest_raw.iter()) {
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
}

impl PowerMonitorApp {
    fn render_ui(&mut self, ui: &mut egui::Ui) {
        self.process_messages();
        self.firmware.poll();
        if self.firmware.installing && ui.ctx().input(|i| i.viewport().close_requested()) {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }

        // Request repaints - fast when streaming, slower when idle
        if self.streaming && self.plot_source == PlotSource::Live {
            ui.ctx().request_repaint_after(Duration::from_millis(16)); // ~60fps when streaming
        } else {
            ui.ctx().request_repaint_after(Duration::from_millis(100)); // 10fps when idle
        }

        egui::Panel::top("header").show(ui, |ui| {
            self.header_bar(ui);
            self.measurement_cards(ui);
            ui.add_enabled_ui(!self.firmware.usb_busy, |ui| self.acquisition_controls(ui));
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.active_tab, AppTab::Charts, "Charts");
                ui.selectable_value(&mut self.active_tab, AppTab::Pd, "USB PD");
                ui.selectable_value(&mut self.active_tab, AppTab::Recordings, "Recordings");
                ui.selectable_value(&mut self.active_tab, AppTab::Firmware, "Firmware");
            });
        });
        egui::Panel::bottom("status").show(ui, |ui| {
            ui.small(format!(
                "{} samples · {} missing · {} discarded · {}",
                self.total_samples, self.dropped_samples, self.discarded_sequence_samples, self.recording_status
            ));
        });
        egui::CentralPanel::default().show(ui, |ui| match self.active_tab {
            AppTab::Charts => self.plots_panel(ui),
            AppTab::Pd => {
                if self.pd_wire_messages == 0 {
                    ui.label("No USB PD packets observed. This is normal for USB-A connections.");
                }
                self.pd_status_section(ui);
                self.pd_timeline_controls_section(ui);
                self.pd_timeline_panel(ui);
            }
            AppTab::Recordings => {
                ui.add_enabled_ui(!self.firmware.usb_busy, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        self.live_capture_section(ui);
                        self.offline_recordings_section(ui);
                    })
                });
            }
            AppTab::Firmware => self.firmware_panel(ui),
        });
        if !self.firmware.usb_busy {
            self.settings_window(ui.ctx());
        }
    }
}

impl eframe::App for PowerMonitorApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.render_ui(ui);
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

    // Run egui application
    let options = eframe::NativeOptions {
        renderer: eframe::Renderer::Wgpu,
        wgpu_options: gpu_plot::wgpu_options(),
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1024.0, 768.0])
            .with_title("POWER-Z KM003C Monitor"),
        ..Default::default()
    };

    let mut app = PowerMonitorApp::new(session, session_events, preferences, dirs);

    eframe::run_native(
        "POWER-Z KM003C Monitor",
        options,
        Box::new(|cc| {
            configure_appearance(&cc.egui_ctx);
            app.init_gpu(cc);
            // Open USB only after window initialization succeeds.
            let _ = app.session.connect(app.current_rate.to_graph_rate(), app.usb_reset);
            Ok(Box::new(app))
        }),
    )
    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use eframe::egui;
    use km003c_lib::{OfflineLog, PdLogEntry, read_recording};

    /// An app whose session has no device task behind it. It saves no
    /// preferences and journals into a directory of its own.
    pub(super) fn test_app() -> (PowerMonitorApp, mpsc::UnboundedSender<SessionEvent>) {
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
    pub(super) fn captured_offline_log() -> OfflineLog {
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
        let protocol_log = VecDeque::from([wire("Accept").into(), wire("GoodCRC").into()]);
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

    fn test_negotiation() -> Vec<km003c_lib::PdEvent> {
        [
            "a1612c9101082cd102002cc103002cb10400454106003c21dcc0",
            "8210dc700323",
            "a305",
            "a607",
        ]
        .into_iter()
        .map(|hex_data| km003c_lib::PdEvent {
            timestamp: km003c_lib::uom::si::f64::Time::new::<millisecond>(0.0),
            data: PdEventData::PdMessage {
                sop: 0,
                wire_data: hex::decode(hex_data).unwrap(),
            },
        })
        .collect()
    }

    #[test]
    fn a_contract_survives_a_meter_reconnect() {
        let (mut app, usb_tx) = test_app();
        usb_tx.send(SessionEvent::PdEvents(test_negotiation())).unwrap();
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

    fn test_device(serial: &str, hardware: u8, version: &str, date: &str) -> Arc<DeviceState> {
        Arc::new(DeviceState {
            info: km003c_lib::DeviceInfo {
                model: "KM003C".into(),
                serial_id: serial.into(),
                fw_version: version.into(),
                fw_date: date.into(),
                ..Default::default()
            },
            hardware_id: km003c_lib::HardwareId::from_bytes([hardware; 12]),
            auth_level: 1,
            adcqueue_enabled: true,
        })
    }

    fn test_measurement(sequence: u16) -> km003c_lib::AdcQueueSample {
        km003c_lib::AdcQueueSample::from_raw(
            km003c_lib::AdcQueueSampleRaw {
                sequence,
                marker: 0,
                vbus_uv: 5_000_000,
                ibus_ua: 1_000_000,
                cc1_raw: 0,
                cc2_raw: 0,
                vdp_raw: 0,
                vdm_raw: 0,
            },
            GraphSampleRate::Sps50,
        )
    }

    #[test]
    fn different_meter_or_firmware_starts_a_new_measurement_history() {
        for replacement in [
            test_device("B", 2, "2.0.7", "2026.1.1"),
            test_device("A", 2, "2.0.7", "2026.1.1"),
            test_device("B", 1, "2.0.7", "2026.1.1"),
            test_device("A", 1, "2.0.6", "2026.1.1"),
            test_device("A", 1, "2.0.7", "2026.1.2"),
        ] {
            let (mut app, tx) = test_app();
            tx.send(SessionEvent::Connected(test_device("A", 1, "2.0.7", "2026.1.1")))
                .unwrap();
            tx.send(SessionEvent::Samples(vec![
                test_measurement(100),
                test_measurement(120),
            ]))
            .unwrap();
            tx.send(SessionEvent::PdEvents(test_negotiation())).unwrap();
            app.process_messages();
            assert!(app.data_points.back().unwrap().energy_uwh > 0.0);
            assert_eq!(app.pd_contract.stage(), km003c_lib::PdContractStage::Active);
            app.toggle_view_pause();
            tx.send(SessionEvent::Disconnected {
                retry_when_present: false,
            })
            .unwrap();
            app.process_messages();
            tx.send(SessionEvent::Connected(Arc::clone(&replacement))).unwrap();
            app.process_messages();
            assert!(app.data_points.is_empty());
            assert!(app.paused_view.is_none());
            assert_eq!(app.total_samples, 0);
            assert_eq!(app.current_voltage, 0.0);
            assert_eq!(app.pd_contract.stage(), km003c_lib::PdContractStage::None);
            assert!(app.pd_log.is_empty());
            tx.send(SessionEvent::Samples(vec![test_measurement(500)])).unwrap();
            app.process_messages();
            let sample = app.data_points.back().unwrap();
            assert_eq!(sample.elapsed_us, 0);
            assert_eq!(sample.sample_index, 0);
            assert_eq!(sample.energy_uwh, 0.0);
            assert_eq!(
                RecordingMetadata::from(app.measurement_source.as_ref().unwrap().as_ref()),
                RecordingMetadata::from(replacement.as_ref())
            );
        }
    }

    #[test]
    fn reconnecting_the_same_meter_keeps_the_buffer_identity_and_integrals() {
        let (mut app, tx) = test_app();
        let meter = test_device("A", 1, "2.0.7", "2026.1.1");
        tx.send(SessionEvent::Connected(Arc::clone(&meter))).unwrap();
        tx.send(SessionEvent::Samples(vec![
            test_measurement(100),
            test_measurement(120),
        ]))
        .unwrap();
        tx.send(SessionEvent::PdEvents(test_negotiation())).unwrap();
        app.process_messages();
        let last = *app.data_points.back().unwrap();
        tx.send(SessionEvent::Disconnected {
            retry_when_present: false,
        })
        .unwrap();
        app.process_messages();
        assert!(app.measurement_source.is_some());
        tx.send(SessionEvent::Connected(meter)).unwrap();
        tx.send(SessionEvent::StreamingStarted(GraphSampleRate::Sps50)).unwrap();
        tx.send(SessionEvent::Samples(vec![test_measurement(500)])).unwrap();
        app.process_messages();
        assert_eq!(app.data_points.len(), 3);
        assert_eq!(app.pd_contract.stage(), km003c_lib::PdContractStage::Active);
        assert!(app.pd_contract.is_carried_over());
        let resumed = app.data_points.back().unwrap();
        assert_eq!(resumed.elapsed_us, last.elapsed_us);
        assert_eq!(resumed.energy_uwh, last.energy_uwh);
        assert_eq!(resumed.sample_index, last.sample_index + 1);
    }

    #[test]
    fn paused_view_keeps_samples_while_acquisition_continues() {
        use km003c_lib::AdcQueueSample;
        use km003c_lib::uom::si::{
            electric_current::ampere,
            f64::{ElectricCurrent, ElectricPotential},
        };
        let (mut app, tx) = test_app();
        let sample = |sequence| {
            let vbus = ElectricPotential::new::<volt>(5.1);
            let ibus = ElectricCurrent::new::<ampere>(-0.5);
            AdcQueueSample {
                sequence,
                marker: 0,
                vbus,
                ibus,
                power: vbus * ibus,
                cc1: vbus,
                cc2: vbus,
                vdp: vbus,
                vdm: vbus,
            }
        };
        tx.send(SessionEvent::Samples(vec![sample(0), sample(20)])).unwrap();
        app.process_messages();
        app.toggle_view_pause();
        let frozen_range = app.time_view.history;
        tx.send(SessionEvent::Samples(vec![sample(40), sample(60)])).unwrap();
        app.process_messages();
        assert_eq!(app.total_samples, 4);
        assert_eq!(app.paused_view.as_ref().unwrap().0.len(), 2);
        assert_eq!(app.time_view.history, frozen_range);
        assert_eq!(app.current_voltage, 5.1);
        app.toggle_view_pause();
        assert!(app.paused_view.is_none());
        assert!(app.time_view.history.is_none());
    }

    #[test]
    fn chart_input_zooms_only_time_and_synchronizes_all_three_axes() {
        let (mut app, _tx) = test_app();
        app.time_window = TimeWindow::Min5;
        let ctx = egui::Context::default();
        configure_appearance(&ctx);
        let frame = |app: &mut PowerMonitorApp, events, time| {
            let output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(853.0, 666.0))),
                    time: Some(time),
                    events,
                    ..Default::default()
                },
                |ui| app.render_ui(ui),
            );
            output.drop_without_applying_deltas();
        };
        frame(&mut app, vec![], 0.0);
        frame(&mut app, vec![], 0.1);
        let bounds = || {
            std::array::from_fn::<_, 3, _>(|index| {
                *egui_plot::PlotMemory::load(&ctx, egui::Id::new(("measurement_plot", index)))
                    .unwrap()
                    .transform()
                    .bounds()
            })
        };
        let before = bounds();
        let pointer = app.chart_rects[1].unwrap().center();
        frame(
            &mut app,
            vec![
                egui::Event::PointerMoved(pointer),
                egui::Event::MouseWheel {
                    unit: egui::MouseWheelUnit::Point,
                    phase: egui::TouchPhase::Move,
                    delta: egui::vec2(0.0, 50.0),
                    modifiers: egui::Modifiers::NONE,
                },
            ],
            0.2,
        );
        let after = bounds();
        assert!(after[0].width() < before[0].width());
        assert!(
            after[0].width() > 120.0,
            "zoom must not jump to a shorter range when the stream is new"
        );
        for index in 0..3 {
            assert_eq!(after[index].range_x(), after[0].range_x());
            assert_eq!(after[index].range_y(), before[index].range_y());
        }
        assert!(app.shared_cursor.is_some());
        // A typical laptop at the default 150% UI scale must show all charts.
        assert!(app.chart_rects[2].unwrap().bottom() <= 666.0);
        for time in [1.0, 1.1] {
            ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(682.0, 512.0))),
                    time: Some(time),
                    ..Default::default()
                },
                |ui| app.render_ui(ui),
            )
            .drop_without_applying_deltas();
        }
        assert!(app.chart_rects[2].unwrap().bottom() <= 512.0);
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
    fn contract_label_stays_two_lines_inside_the_sidebar_column() {
        let ctx = egui::Context::default();
        let short = contract_label_size(&ctx, "—");
        let long = contract_label_size(&ctx, "Requesting PDO#6 (Raw=0x6303A83B) · accepted, waiting for PS_RDY");

        let column_cap = (280.0_f32 - 110.0).max(100.0);
        assert_eq!(short, long);
        assert!(
            (short.x - column_cap).abs() < 1.0,
            "contract column should stay at the sidebar cap {column_cap}, got {short:?}"
        );
        assert!(
            (24.0..40.0).contains(&short.y),
            "expected a fixed two-line row, got short={short:?} long={long:?}"
        );
    }

    fn contract_label_size(ctx: &egui::Context, text: &str) -> egui::Vec2 {
        let mut size = egui::Vec2::ZERO;
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 600.0))),
            ..Default::default()
        };
        for _ in 0..3 {
            ctx.run_ui(input.clone(), |ui| {
                let origin = ui.cursor().min;
                let mut column = ui.new_child(
                    egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(origin, egui::vec2(280.0, 400.0))),
                );
                let max_col_width = (column.available_width() - 110.0).max(100.0);
                egui::Grid::new("pd_status_grid")
                    .num_columns(2)
                    .max_col_width(max_col_width)
                    .spacing([10.0, 4.0])
                    .show(&mut column, |ui| {
                        ui.label("Contract:");
                        size = super::contract_label(ui, text).rect.size();
                        ui.end_row();
                    });
            })
            .drop_without_applying_deltas();
        }
        size
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
                eframe::WebOptions {
                    wgpu_options: gpu_plot::wgpu_options(),
                    ..Default::default()
                },
                Box::new(move |cc| {
                    configure_appearance(&cc.egui_ctx);
                    let dirs = AppDirs::locate();
                    let preferences = dirs.load_preferences();
                    let mut app = PowerMonitorApp::new(session, events, preferences, dirs);
                    app.init_gpu(cc);
                    Ok(Box::new(app))
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
                    notice.set_text_content(Some(&format!("Could not start egui (WebGPU required): {error:?}")))
                }
            }
        }
    });
}
