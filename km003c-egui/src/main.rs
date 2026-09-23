mod metric_color;
mod offline_export;
mod offline_view;
mod pd_decoder;
mod pd_trace_view;
mod recording;

use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints};
use km003c_lib::uom::si::electric_charge::milliampere_hour;
use km003c_lib::uom::si::electric_potential::volt;
use km003c_lib::uom::si::energy::milliwatt_hour;
use km003c_lib::uom::si::time::{millisecond, second};
use km003c_lib::{
    DeviceState, GraphSampleRate, LogMetadata, MeasurementAccumulator, MeasurementSample, Metric, PdConnectionTracker,
    Session, SessionEvent,
    pd::{PdEventData, PdStatus},
};
use metric_color::MetricColor;
use offline_export::{OfflineExportEvent, OfflineExportTask};
use offline_view::OfflineRecordingView;
use pd_decoder::{DecodedPdEntry, PdCategory, PdDecoder};
use pd_trace_view::{PdTraceCategory, PdTraceEntry, decode_trace};
use recording::{Recorder, RecordingEvent, RecordingFormat, RecordingMetadata, RecordingSummary};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlotSource {
    Live,
    Offline,
}

enum PdTimelineEntry<'a> {
    Protocol(&'a DecodedPdEntry),
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

fn pd_timeline_entries<'a>(
    protocol_log: &'a VecDeque<DecodedPdEntry>,
    trace_log: &'a VecDeque<PdTraceEntry>,
    show_protocol: bool,
    show_trace: bool,
) -> Vec<PdTimelineEntry<'a>> {
    let mut timeline = Vec::with_capacity(protocol_log.len() + trace_log.len());
    if show_protocol {
        timeline.extend(protocol_log.iter().map(PdTimelineEntry::Protocol));
    }
    if show_trace {
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
    offline_export: Option<OfflineExportTask>,
    /// Data source currently rendered by the three plots
    plot_source: PlotSource,
    /// PD protocol decoder
    pd_decoder: PdDecoder,
    /// Decoded PD log entries
    pd_log: VecDeque<DecodedPdEntry>,
    /// Max PD log entries
    max_pd_entries: usize,
    /// Current PD status
    pd_status: Option<PdStatus>,
    /// Debounced phone connection state
    pd_connection: PdConnectionTracker,
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
    usb_reset: bool,
    /// An attempted connection has not yet produced a result.
    connection_attempt_in_flight: bool,
    /// User intent, retained while a connection or disconnect is in progress.
    auto_connect_enabled: bool,
    /// Time of the next automatic probe while the KM003C is absent.
    reconnect_at: Option<Instant>,
}

impl PowerMonitorApp {
    const RECONNECT_DELAY: Duration = Duration::from_secs(1);

    fn new(session: Session, session_events: mpsc::UnboundedReceiver<SessionEvent>) -> Self {
        Self {
            data_points: VecDeque::new(),
            measurement_accumulator: MeasurementAccumulator::default(),
            session_events,
            session,
            device_state: None,
            status: "Connecting...".to_string(),
            streaming: false,
            current_rate: SampleRateOption::Sps50,
            selected_rate: SampleRateOption::Sps50,
            time_window: TimeWindow::Sec30,
            max_points: 100000, // Safety cap for memory
            total_samples: 0,
            dropped_samples: 0,
            discarded_sequence_samples: 0,
            current_voltage: 0.0,
            current_current: 0.0,
            current_power: 0.0,
            plot_metrics: [Metric::Voltage, Metric::Current, Metric::Power],
            recording_format: RecordingFormat::Parquet,
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
            pd_decoder: PdDecoder::new(),
            pd_log: VecDeque::new(),
            max_pd_entries: 1000,
            pd_status: None,
            pd_connection: PdConnectionTracker::default(),
            pd_auto_scroll: true,
            pd_panel_visible: true,
            pd_protocol_visible: true,
            pd_trace_enabled: false,
            pd_trace_log: VecDeque::new(),
            max_pd_trace_entries: 2000,
            usb_reset: !cfg!(target_os = "macos"),
            connection_attempt_in_flight: true,
            auto_connect_enabled: true,
            reconnect_at: None,
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
        let _ = self.session.connect(self.selected_rate.to_graph_rate(), self.usb_reset);
    }

    fn retry_connection_if_due(&mut self, now: Instant) {
        if self.reconnect_at.is_some_and(|retry_at| now >= retry_at) {
            self.request_connection(false);
        }
    }

    fn process_messages(&mut self) {
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
                    self.pd_decoder = PdDecoder::new();
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
                        self.recording_status = error;
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
                                self.pd_connection.observe_event(true, std::time::Instant::now());
                            }
                            PdEventData::Disconnect => {
                                self.pd_connection.observe_event(false, std::time::Instant::now());
                            }
                            PdEventData::PdMessage { .. } => {}
                        }

                        let entries = self.pd_decoder.decode_event(event);
                        for entry in entries {
                            self.pd_log.push_back(entry);
                            while self.pd_log.len() > self.max_pd_entries {
                                self.pd_log.pop_front();
                            }
                        }
                    }
                }
                SessionEvent::PdStatusUpdate(status) => {
                    self.pd_connection.observe_status(&status, std::time::Instant::now());
                    self.pd_status = Some(status);
                }
                SessionEvent::PdTrace(trace) => {
                    for entry in decode_trace(&trace) {
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
                    self.offline_device_metadata = self.device_state.as_ref().map(|state| RecordingMetadata {
                        model: state.info.model.clone(),
                        firmware: state.info.fw_version.clone(),
                        serial: state.info.serial_id.clone(),
                    });
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
                    self.pd_decoder = PdDecoder::new();
                    self.offline_busy = false;
                    self.stop_recording();
                }
                _ => {}
            }
        }

        self.retry_connection_if_due(Instant::now());
        self.pd_connection.update(std::time::Instant::now());
        self.poll_recording();
        self.poll_offline_export();
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

        let metadata = RecordingMetadata {
            model: state.info.model.clone(),
            firmware: state.info.fw_version.clone(),
            serial: state.info.serial_id.clone(),
        };
        let Some(path) = self.select_recording_path("km003c-live", "Save KM003C live recording") else {
            return;
        };
        match Recorder::start(
            path.clone(),
            self.recording_format,
            metadata,
            self.data_points.back().copied(),
        ) {
            Ok(recorder) => {
                self.recording_status = format!("Recording to {}", path.display());
                self.last_recording = None;
                self.recorder = Some(recorder);
            }
            Err(error) => self.recording_status = error,
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
        let metadata = RecordingMetadata {
            model: state.info.model.clone(),
            firmware: state.info.fw_version.clone(),
            serial: state.info.serial_id.clone(),
        };
        let Some(path) = self.select_recording_path("km003c-buffer", "Export KM003C plot buffer") else {
            return;
        };

        match Recorder::start(path.clone(), self.recording_format, metadata, Some(first)) {
            Ok(mut recorder) => {
                let samples = self.data_points.iter().copied().collect::<Vec<_>>();
                match recorder.push(&samples) {
                    Ok(()) => {
                        recorder.request_finish();
                        self.recording_status = format!("Exporting {}", path.display());
                        self.last_recording = None;
                        self.recorder = Some(recorder);
                    }
                    Err(error) => self.recording_status = error,
                }
            }
            Err(error) => self.recording_status = error,
        }
    }

    fn select_recording_path(&self, prefix: &str, title: &str) -> Option<std::path::PathBuf> {
        let unix_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let filename = format!("{prefix}-{unix_seconds}.{}", self.recording_format.extension());
        let mut path = rfd::FileDialog::new()
            .set_title(title)
            .add_filter(self.recording_format.label(), &[self.recording_format.extension()])
            .set_file_name(filename)
            .save_file()?;
        path.set_extension(self.recording_format.extension());
        Some(path)
    }

    fn stop_recording(&mut self) {
        let Some(recorder) = &mut self.recorder else {
            return;
        };
        recorder.request_finish();
        self.recording_status = format!("Finalizing {}", recorder.path.display());
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
            Some(RecordingEvent::Failed(error)) => {
                self.recording_status = error;
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
        match OfflineExportTask::start(path.clone(), self.recording_format, device.clone(), Arc::clone(view)) {
            Ok(task) => {
                self.offline_status = format!("Exporting to {}", path.display());
                self.offline_export = Some(task);
            }
            Err(error) => self.offline_status = error,
        }
    }

    fn poll_offline_export(&mut self) {
        let event = self.offline_export.as_mut().and_then(OfflineExportTask::poll_event);
        match event {
            Some(OfflineExportEvent::Finished { path, rows }) => {
                self.offline_status = format!("Exported {rows} samples to {}", path.display());
                self.offline_export = None;
            }
            Some(OfflineExportEvent::Failed(error)) => {
                self.offline_status = error;
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
impl PowerMonitorApp {
    fn header_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("POWER-Z KM003C Monitor");
            ui.separator();

            let status_color = if self.streaming {
                egui::Color32::GREEN
            } else if self.device_state.is_some() {
                egui::Color32::YELLOW
            } else {
                egui::Color32::RED
            };
            ui.colored_label(status_color, &self.status);
        });
    }

    /// Every side-panel section, in display order.
    fn side_panel(&mut self, ui: &mut egui::Ui) {
        self.device_info_section(ui);
        self.current_readings_section(ui);
        self.pd_status_section(ui);
        self.pd_timeline_controls_section(ui);
        self.live_statistics_section(ui);
        self.controls_section(ui);
        self.live_capture_section(ui);
        self.offline_recordings_section(ui);
        self.connection_section(ui);
    }

    fn device_info_section(&mut self, ui: &mut egui::Ui) {
        ui.heading("Device Info");
        ui.separator();

        {
            if let Some(state) = &self.device_state {
                egui::Grid::new("device_info_grid")
                    .num_columns(2)
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
                        ui.label(format!("{}", state.hardware_id));
                        ui.end_row();

                        ui.label("Auth Level:");
                        ui.label(format!("{}", state.auth_level));
                        ui.end_row();

                        ui.label("AdcQueue:");
                        ui.colored_label(
                            if state.adcqueue_enabled {
                                egui::Color32::GREEN
                            } else {
                                egui::Color32::RED
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
                    .spacing([10.0, 4.0])
                    .show(ui, |ui| {
                        ui.label("CC1:");
                        let cc1_v = pd.cc1.get::<volt>();
                        let cc1_color = if self.pd_connection.connected() == Some(true) && cc1_v > 0.2 {
                            egui::Color32::GREEN
                        } else {
                            egui::Color32::GRAY
                        };
                        ui.colored_label(cc1_color, format!("{cc1_v:.3} V"));
                        ui.end_row();

                        ui.label("CC2:");
                        let cc2_v = pd.cc2.get::<volt>();
                        let cc2_color = if self.pd_connection.connected() == Some(true) && cc2_v > 0.2 {
                            egui::Color32::GREEN
                        } else {
                            egui::Color32::GRAY
                        };
                        ui.colored_label(cc2_color, format!("{cc2_v:.3} V"));
                        ui.end_row();

                        ui.label("Type-C sink:");
                        let (color, label) = match self.pd_connection.connected() {
                            Some(true) => (egui::Color32::GREEN, "Attached"),
                            Some(false) => (egui::Color32::RED, "Not attached"),
                            None => (egui::Color32::YELLOW, "Detecting..."),
                        };
                        ui.colored_label(color, label);
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
                            egui::Color32::RED
                        } else {
                            egui::Color32::GREEN
                        },
                        format!("{}", self.dropped_samples),
                    );
                    ui.end_row();

                    ui.label("Discarded:");
                    ui.colored_label(
                        if self.discarded_sequence_samples > 0 {
                            egui::Color32::YELLOW
                        } else {
                            egui::Color32::GREEN
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

    fn controls_section(&mut self, ui: &mut egui::Ui) {
        {
            ui.add_space(20.0);
            ui.separator();
            ui.heading("Controls");
            ui.separator();

            // Sample rate selector
            ui.add_enabled_ui(self.recorder.is_none(), |ui| {
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
                    .add_enabled(self.recorder.is_none(), egui::Button::new("Clear Live Data"))
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
                ui.label(format!("Samples: {}", recorder.rows));
                ui.label(format!("Missing: {}", recorder.missing_samples));
                ui.label(format!("Discarded: {}", recorder.discarded_sequence_samples));
                let completeness = if recorder.elapsed_us == 0 {
                    100.0
                } else {
                    (1.0 - recorder.interpolated_duration_us as f64 / recorder.elapsed_us as f64).max(0.0) * 100.0
                };
                ui.label(format!("Completeness: {completeness:.6}%"));
            } else if let Some(summary) = &self.last_recording {
                ui.label(format!("Last capture: {} samples", summary.rows));
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
                        ui.label(format!("Exporting {}", export.path.display()));
                    });
                } else if ui.button("Export Downloaded").clicked() {
                    self.export_offline_log();
                }
            }
            ui.small(&self.offline_status);
        }
    }

    fn connection_section(&mut self, ui: &mut egui::Ui) {
        {
            ui.add_space(5.0);

            if self.device_state.is_some() || self.connection_attempt_in_flight || self.reconnect_at.is_some() {
                if ui.button("Disconnect").clicked() {
                    info!("Disconnect requested");
                    self.auto_connect_enabled = false;
                    self.reconnect_at = None;
                    let _ = self.session.disconnect();
                }
            } else if self.device_state.is_none() {
                ui.checkbox(&mut self.usb_reset, "USB reset on connect");
                if ui.button("Connect").clicked() {
                    info!("Connect requested");
                    self.request_connection(true);
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
                        self.pd_protocol_visible,
                        self.pd_trace_enabled,
                    );

                    egui::ScrollArea::vertical()
                        .auto_shrink([false; 2])
                        .stick_to_bottom(self.pd_auto_scroll)
                        .show(ui, |ui| {
                            for timeline_entry in timeline {
                                match timeline_entry {
                                    PdTimelineEntry::Protocol(entry) => {
                                        let color = match entry.category {
                                            PdCategory::Connect => egui::Color32::GREEN,
                                            PdCategory::Disconnect => egui::Color32::RED,
                                            PdCategory::SourceCaps => egui::Color32::from_rgb(100, 149, 237),
                                            PdCategory::Request => egui::Color32::YELLOW,
                                            PdCategory::Control => egui::Color32::GRAY,
                                            PdCategory::Extended => egui::Color32::from_rgb(255, 165, 0),
                                            PdCategory::Error => egui::Color32::from_rgb(255, 80, 80),
                                        };

                                        ui.colored_label(
                                            color,
                                            egui::RichText::new(format!("[WIRE] {}", entry.summary))
                                                .monospace()
                                                .size(row_height),
                                        );
                                        for detail in &entry.details {
                                            ui.colored_label(
                                                color.gamma_multiply(0.8),
                                                egui::RichText::new(format!("       {detail}"))
                                                    .monospace()
                                                    .size(row_height),
                                            );
                                        }
                                    }
                                    PdTimelineEntry::FirmwareTrace(entry) => {
                                        let color = match entry.category {
                                            PdTraceCategory::TypeCState => egui::Color32::from_rgb(100, 200, 255),
                                            PdTraceCategory::ProtocolEvent => egui::Color32::LIGHT_GREEN,
                                            PdTraceCategory::Unknown => egui::Color32::YELLOW,
                                        };
                                        ui.colored_label(
                                            color,
                                            egui::RichText::new(format!("[FW]   {}", entry.summary))
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
                        let points: PlotPoints = match self.plot_source {
                            PlotSource::Live => self
                                .data_points
                                .iter()
                                .filter(|sample| min_time.is_none_or(|min| sample.elapsed_seconds() >= min))
                                .map(|sample| [sample.elapsed_seconds(), metric.value(sample)])
                                .collect(),
                            PlotSource::Offline => self
                                .offline_view
                                .iter()
                                .flat_map(|view| &view.samples)
                                .filter(|sample| min_time.is_none_or(|min| sample.elapsed_seconds() >= min))
                                .filter_map(|sample| {
                                    sample
                                        .metric_value(metric)
                                        .map(|value| [sample.elapsed_seconds(), value])
                                })
                                .collect(),
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

        egui::Panel::left("info_panel").min_size(220.0).show(ui, |ui| {
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    info!("Starting POWER-Z KM003C GUI application");

    let (session, session_events) = Session::spawn();

    // Auto-connect on startup
    let _ = session.connect(GraphSampleRate::Sps50, !cfg!(target_os = "macos"));

    // Run egui application
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1024.0, 768.0])
            .with_title("POWER-Z KM003C Monitor"),
        ..Default::default()
    };

    let app = PowerMonitorApp::new(session, session_events);

    eframe::run_native("POWER-Z KM003C Monitor", options, Box::new(|_cc| Ok(Box::new(app))))
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offline_view::captured_test_view;
    use polars::prelude::{CsvReader, ParquetReader, SerReader};

    /// An app whose session has no device task behind it.
    fn test_app() -> (PowerMonitorApp, mpsc::UnboundedSender<SessionEvent>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (session, _commands) = Session::detached();
        (PowerMonitorApp::new(session, event_rx), event_tx)
    }

    #[test]
    fn pd_timeline_filters_and_orders_both_sources() {
        let protocol_log = VecDeque::from([DecodedPdEntry {
            timestamp_seconds: 12.25,
            category: PdCategory::Control,
            summary: "wire".to_string(),
            details: Vec::new(),
        }]);
        let trace_log = VecDeque::from([PdTraceEntry {
            timestamp_seconds: 11.0,
            category: PdTraceCategory::TypeCState,
            summary: "trace".to_string(),
        }]);

        let combined = pd_timeline_entries(&protocol_log, &trace_log, true, true);
        assert!(matches!(combined[0], PdTimelineEntry::FirmwareTrace(_)));
        assert!(matches!(combined[1], PdTimelineEntry::Protocol(_)));

        let protocol_only = pd_timeline_entries(&protocol_log, &trace_log, true, false);
        assert_eq!(protocol_only.len(), 1);
        assert!(matches!(protocol_only[0], PdTimelineEntry::Protocol(_)));
    }

    #[test]
    fn downloaded_offline_log_becomes_the_active_plot_source() {
        let (mut app, usb_tx) = test_app();
        app.plot_metrics[0] = Metric::Cc1;
        let fixture = captured_test_view();

        usb_tx
            .send(SessionEvent::OfflineLogDownloaded(fixture.log.as_ref().clone()))
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
                let recording_metadata = RecordingMetadata {
                    model: device_state.info.model.clone(),
                    firmware: device_state.info.fw_version.clone(),
                    serial: device_state.info.serial_id.clone(),
                };
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
                        OfflineExportTask::start(path.clone(), format, recording_metadata.clone(), Arc::clone(&view))
                            .unwrap();
                    let export_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                    let rows = loop {
                        match export.poll_event() {
                            Some(OfflineExportEvent::Finished { rows, .. }) => break rows,
                            Some(OfflineExportEvent::Failed(error)) => panic!("offline export failed: {error}"),
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
                    let dataframe = match format {
                        RecordingFormat::Parquet => ParquetReader::new(std::fs::File::open(&path).unwrap())
                            .finish()
                            .unwrap(),
                        RecordingFormat::Csv => CsvReader::new(std::fs::File::open(&path).unwrap()).finish().unwrap(),
                    };
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
