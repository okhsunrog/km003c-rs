//! Experimental Slint front end for the KM003C, on desktop and Android.
//!
//! The device session from km003c-lib runs on a Tokio runtime. Its samples go
//! through the shared [`MeasurementAccumulator`] into lock-protected ring
//! buffers, which `slint-realtime-plot` renders on the GPU each frame.
//! Recording, offline export, the PD contract and the preferences come from
//! km003c-lib as well, so they behave as in the egui app.

slint::include_modules!();

mod dynamic_colors;
mod files;
mod pd;

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use km003c_lib::{
    DeviceState, GraphSampleRate, MeasurementAccumulator, MeasurementSample, Metric, Preferences, RecordingFormat,
    Session, SessionEvent,
};
use slint::wgpu_30::WGPUConfiguration;
use slint::{FilterModel, Model, VecModel};
use slint_realtime_plot::{PlotBuffer, PlotConfig, PlotRenderer, required_wgpu_settings};
use tokio::sync::mpsc;
use tracing::{info, warn};

use files::{Dirs, Files, FilesUpdate};

/// Ring capacity per chart: 4.4 minutes at 1000 SPS, 87 minutes at 50 SPS.
const CAPACITY: usize = 1 << 18;
const RATES: [GraphSampleRate; 4] = [
    GraphSampleRate::Sps2,
    GraphSampleRate::Sps10,
    GraphSampleRate::Sps50,
    GraphSampleRate::Sps1000,
];
const RECONNECT_DELAY: Duration = Duration::from_secs(1);
const READOUT_INTERVAL: Duration = Duration::from_millis(100);
/// PD status arrives with every poll; the CC readout does not need that rate.
const PD_STATUS_INTERVAL: Duration = Duration::from_millis(250);
/// How often recording progress and finished files are checked.
const FILES_INTERVAL: Duration = Duration::from_millis(250);
/// How often changed settings are written.
const PREFERENCES_INTERVAL: Duration = Duration::from_secs(2);

/// A USB reset re-enumerates the device. On Android that would need a new
/// permission grant, and macOS handles it badly, so only reset elsewhere.
const USB_RESET: bool = !cfg!(any(target_os = "android", target_os = "macos"));

/// Charts in display order: voltage, current, power.
/// Current and power are absolute, as in the egui app's default plots.
const CHART_METRICS: [Metric; 3] = [Metric::Voltage, Metric::Current, Metric::Power];
const CHART_COLORS: [[f32; 4]; 3] = [
    [0.133, 0.773, 0.369, 1.0], // #22c55e
    [0.231, 0.510, 0.965, 1.0], // #3b82f6
    [0.961, 0.620, 0.043, 1.0], // #f59e0b
];

/// The three chart rings plus a count of frames pushed into each.
///
/// The count lets a paused view hold still: new frames shift the live edge, so
/// the view offset has to grow by the same amount.
struct Charts {
    buffers: [PlotBuffer; 3],
    pushed: AtomicU64,
}

type Buffers = Arc<Charts>;

/// Requests from the UI thread to the task that owns the files.
enum UiCommand {
    StartRecording(RecordingFormat),
    StopRecording,
    LoadCatalog,
    ExportOffline(usize, RecordingFormat),
    SetPdTrace(bool),
}

fn rate_hz(rate: GraphSampleRate) -> f32 {
    match rate {
        GraphSampleRate::Sps2 => 2.0,
        GraphSampleRate::Sps10 => 10.0,
        GraphSampleRate::Sps50 => 50.0,
        GraphSampleRate::Sps1000 => 1000.0,
    }
}

fn rate_index(rate: GraphSampleRate) -> usize {
    RATES.iter().position(|&r| r == rate).unwrap_or(2)
}

fn format_index(format: RecordingFormat) -> i32 {
    RecordingFormat::ALL.iter().position(|&f| f == format).unwrap_or(0) as i32
}

fn format_at(index: i32) -> RecordingFormat {
    RecordingFormat::ALL
        .get(index.max(0) as usize)
        .copied()
        .unwrap_or_default()
}

pub fn main() {
    #[cfg(not(target_os = "android"))]
    tracing_subscriber::fmt::init();
    run(desktop_dirs(), |_| {});
}

/// The egui app uses the same preferences file and journal directory.
#[cfg(not(target_os = "android"))]
fn desktop_dirs() -> Dirs {
    let config = dirs::config_dir().unwrap_or_else(std::env::temp_dir).join("km003c");
    let data = dirs::data_local_dir().unwrap_or_else(std::env::temp_dir).join("km003c");
    let documents = dirs::document_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(std::env::temp_dir);
    Dirs {
        preferences: config.join("preferences.json"),
        journal: data.join("journal"),
        recordings: documents.join("KM003C"),
    }
}

#[cfg(target_os = "android")]
fn desktop_dirs() -> Dirs {
    unreachable!("Android starts in android_main")
}

/// The UI's settings as preferences, keeping the fields it has no control for.
fn current_preferences(app: &App, saved: &Preferences) -> Preferences {
    let mut preferences = saved.clone();
    if let Some(&rate) = RATES.get(app.get_rate_index().max(0) as usize) {
        preferences.sample_rate = rate;
    }
    preferences.time_window_seconds = Some(f64::from(app.get_time_window()));
    preferences.recording_format = format_at(app.get_recording_format_index());
    preferences.pd_hide_good_crc = app.get_pd_hide_good_crc();
    preferences.pd_trace_enabled = app.get_pd_trace_enabled();
    preferences
}

/// Run the app; `customize` adjusts the window before it is shown.
fn run(dirs: Dirs, customize: impl FnOnce(&App)) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("failed to start the Tokio runtime");

    slint::BackendSelector::new()
        .require_wgpu_30(WGPUConfiguration::Automatic(required_wgpu_settings(CAPACITY, 1)))
        .select()
        .expect("Unable to create Slint backend with WGPU renderer");

    let dirs = Arc::new(dirs);
    let preferences = Preferences::load(&dirs.preferences);
    let initial_rate = preferences.sample_rate;

    let app = App::new().expect("failed to create the window");
    customize(&app);
    app.set_capacity(CAPACITY as i32);
    app.set_rate_index(rate_index(initial_rate) as i32);
    app.set_sample_rate(rate_hz(initial_rate));
    if let Some(seconds) = preferences.time_window_seconds {
        app.set_time_window(seconds as f32);
    }
    app.set_recording_format_index(format_index(preferences.recording_format));
    app.set_pd_hide_good_crc(preferences.pd_hide_good_crc);
    app.set_pd_trace_enabled(preferences.pd_trace_enabled);
    app.set_recordings_dir(dirs.recordings.display().to_string().into());

    let buffers: Buffers = Arc::new(Charts {
        buffers: std::array::from_fn(|_| PlotBuffer::new(1, CAPACITY)),
        pushed: AtomicU64::new(0),
    });

    let (session, events) = {
        let _guard = runtime.enter();
        Session::spawn()
    };
    let (commands, command_rx) = mpsc::unbounded_channel();
    let pump = Pump::new(
        session.clone(),
        buffers.clone(),
        app.as_weak(),
        dirs.clone(),
        initial_rate,
        preferences.pd_trace_enabled,
    );
    runtime.spawn(pump.run(events, command_rx));
    let _ = session.connect(initial_rate, USB_RESET);

    {
        let session = session.clone();
        app.on_rate_selected(move |index| {
            if let Some(&rate) = RATES.get(index as usize) {
                let _ = session.set_sample_rate(rate);
            }
        });
    }
    {
        let session = session.clone();
        let weak = app.as_weak();
        app.on_reconnect(move || {
            let rate = weak
                .upgrade()
                .and_then(|app| RATES.get(app.get_rate_index().max(0) as usize).copied())
                .unwrap_or(initial_rate);
            let _ = session.disconnect();
            let _ = session.connect(rate, USB_RESET);
        });
    }
    {
        let commands = commands.clone();
        let weak = app.as_weak();
        app.on_start_recording(move || {
            if let Some(app) = weak.upgrade() {
                let format = format_at(app.get_recording_format_index());
                let _ = commands.send(UiCommand::StartRecording(format));
            }
        });
    }
    {
        let commands = commands.clone();
        app.on_stop_recording(move || {
            let _ = commands.send(UiCommand::StopRecording);
        });
    }
    // The format applies when the next recording or export starts.
    app.on_recording_format_selected(|_| {});
    {
        let commands = commands.clone();
        app.on_offline_load(move || {
            let _ = commands.send(UiCommand::LoadCatalog);
        });
    }
    {
        let commands = commands.clone();
        let weak = app.as_weak();
        app.on_offline_export(move |index| {
            if let Some(app) = weak.upgrade() {
                let format = format_at(app.get_recording_format_index());
                let _ = commands.send(UiCommand::ExportOffline(index.max(0) as usize, format));
            }
        });
    }
    {
        let commands = commands.clone();
        app.on_pd_trace_changed(move |enabled| {
            let _ = commands.send(UiCommand::SetPdTrace(enabled));
        });
    }

    // Every row is kept; the view filters out GoodCRC while the box is ticked.
    let pd_rows = Rc::new(VecModel::<PdRow>::default());
    PD_ROWS.set(Some(pd_rows.clone()));
    let hide_good_crc = Rc::new(Cell::new(app.get_pd_hide_good_crc()));
    let visible_rows = Rc::new(FilterModel::new(pd_rows.clone(), {
        let hide_good_crc = hide_good_crc.clone();
        move |row: &PdRow| !(hide_good_crc.get() && row.good_crc)
    }));
    app.set_pd_rows(visible_rows.clone().into());
    {
        let visible_rows = visible_rows.clone();
        app.on_pd_filter_changed(move |hide| {
            hide_good_crc.set(hide);
            visible_rows.reset();
        });
    }
    {
        let pd_rows = pd_rows.clone();
        app.on_pd_clear(move || pd_rows.set_vec(Vec::new()));
    }
    app.on_pd_row_toggled(move |index| {
        let source = visible_rows.unfiltered_row(index as usize);
        if let Some(mut row) = pd_rows.row_data(source) {
            row.expanded = !row.expanded;
            pd_rows.set_row_data(source, row);
        }
    });

    // Settings are written when they change, checked on a timer so a pinch
    // zoom does not write the file on every frame.
    let saved_preferences = Rc::new(RefCell::new(preferences));
    let save_preferences = {
        let weak = app.as_weak();
        let saved = saved_preferences.clone();
        let path = dirs.preferences.clone();
        move || {
            let Some(app) = weak.upgrade() else {
                return;
            };
            let current = current_preferences(&app, &saved.borrow());
            if current == *saved.borrow() {
                return;
            }
            if let Err(error) = current.save(&path) {
                warn!("Could not save preferences to {}: {error}", path.display());
            }
            *saved.borrow_mut() = current;
        }
    };
    let preferences_timer = slint::Timer::default();
    preferences_timer.start(
        slint::TimerMode::Repeated,
        PREFERENCES_INTERVAL,
        save_preferences.clone(),
    );

    install_renderer(&app, buffers);
    app.run().expect("event loop failed");

    save_preferences();
    let _ = session.disconnect();
    // Dropping the runtime drops a running recorder, which writes its file.
    runtime.shutdown_timeout(Duration::from_secs(5));
}

/// Render the three charts from their ring buffers before every frame.
fn install_renderer(app: &App, buffers: Buffers) {
    let mut renderers: Option<[PlotRenderer; 3]> = None;
    let mut last_pushed = 0u64;
    let weak = app.as_weak();
    app.window()
        .set_rendering_notifier(move |state, graphics_api| match state {
            slint::RenderingState::RenderingSetup => {
                if let slint::GraphicsAPI::WGPU30 { device, queue, .. } = graphics_api {
                    renderers = Some(std::array::from_fn(|chart| {
                        PlotRenderer::new(
                            device,
                            queue,
                            PlotConfig {
                                num_channels: 1,
                                capacity: CAPACITY,
                                y_min: 0.0,
                                y_max: 1.0,
                                auto_range: true,
                                channel_colors: vec![CHART_COLORS[chart]],
                            },
                        )
                    }));
                }
            }
            slint::RenderingState::BeforeRendering => {
                let (Some(renderers), Some(app)) = (renderers.as_mut(), weak.upgrade()) else {
                    return;
                };
                app.set_available_samples(buffers.buffers[0].available_samples() as i32);
                let pushed = buffers.pushed.load(Ordering::Relaxed);
                let new_frames = pushed.saturating_sub(last_pushed);
                last_pushed = pushed;
                if !app.get_paused() {
                    app.set_paused_shift(0);
                } else if new_frames > 0 {
                    // Keep the paused view on the same samples while data
                    // arrives, and the time labels on the pause moment.
                    let grow = |value: i32| (i64::from(value) + new_frames as i64).min(CAPACITY as i64) as i32;
                    app.set_view_offset(grow(app.get_view_offset()));
                    app.set_paused_shift(grow(app.get_paused_shift()));
                }
                let visible = app.get_visible_samples().max(2) as u32;
                let offset = app.get_effective_view_offset().max(0) as u32;
                let scale = app.window().scale_factor();
                let sizes = [
                    (app.get_voltage_texture_width(), app.get_voltage_texture_height()),
                    (app.get_current_texture_width(), app.get_current_texture_height()),
                    (app.get_power_texture_width(), app.get_power_texture_height()),
                ];

                let mut rendered = false;
                for (chart, renderer) in renderers.iter_mut().enumerate() {
                    let (width, height) = sizes[chart];
                    let output = renderer.render(
                        &buffers.buffers[chart],
                        width.max(1) as u32,
                        height.max(1) as u32,
                        visible,
                        offset,
                        scale,
                    );
                    if !output.rendered {
                        continue;
                    }
                    rendered = true;
                    let texture = slint::Image::try_from(output.texture).unwrap();
                    let divisions = output.y_divisions as i32;
                    match chart {
                        0 => {
                            app.set_voltage_texture(texture);
                            app.set_voltage_y_min(output.y_min);
                            app.set_voltage_y_max(output.y_max);
                            app.set_voltage_y_divisions(divisions);
                        }
                        1 => {
                            app.set_current_texture(texture);
                            app.set_current_y_min(output.y_min);
                            app.set_current_y_max(output.y_max);
                            app.set_current_y_divisions(divisions);
                        }
                        _ => {
                            app.set_power_texture(texture);
                            app.set_power_y_min(output.y_min);
                            app.set_power_y_max(output.y_max);
                            app.set_power_y_divisions(divisions);
                        }
                    }
                }

                // Keep redrawing while live; when paused, stop once settled.
                if !app.get_paused() || rendered {
                    app.window().request_redraw();
                }
            }
            slint::RenderingState::RenderingTeardown => renderers = None,
            _ => {}
        })
        .expect("Unable to set rendering notifier");
}

/// Readout values handed to the UI thread.
#[derive(Default)]
struct Readout {
    status: Option<String>,
    device: Option<String>,
    sample_rate: Option<(f32, i32)>,
    measurement: Option<MeasurementSample>,
}

fn update_ui(app: &slint::Weak<App>, readout: Readout) {
    let _ = app.upgrade_in_event_loop(move |app| {
        if let Some(status) = readout.status {
            app.set_status(status.into());
        }
        if let Some(device) = readout.device {
            app.set_device(device.into());
        }
        if let Some((hz, index)) = readout.sample_rate {
            app.set_sample_rate(hz);
            app.set_rate_index(index);
            app.set_view_offset(0);
        }
        if let Some(sample) = readout.measurement {
            let [voltage, current, power] = CHART_METRICS.map(|metric| metric.value(&sample));
            app.set_voltage_text(format!("{voltage:.3} V").into());
            app.set_current_text(format!("{current:.3} A").into());
            app.set_power_text(format!("{power:.3} W").into());
            app.set_quality_text(
                format!(
                    "{:.1} s · {} samples · {} missing · {} discarded",
                    sample.elapsed_seconds(),
                    sample.sample_index + 1,
                    sample.cumulative_missing_samples,
                    sample.cumulative_discarded_sequence_samples
                )
                .into(),
            );
        }
        app.window().request_redraw();
    });
}

fn apply_files(app: &slint::Weak<App>, update: FilesUpdate) {
    let FilesUpdate {
        recording,
        progress,
        status,
        offline_busy,
        offline_status,
        offline_rows,
    } = update;
    if recording.is_none()
        && progress.is_none()
        && status.is_none()
        && offline_busy.is_none()
        && offline_status.is_none()
        && offline_rows.is_none()
    {
        return;
    }
    let _ = app.upgrade_in_event_loop(move |app| {
        if let Some(recording) = recording {
            app.set_recording(recording);
        }
        if let Some(progress) = progress {
            app.set_recording_progress(progress.into());
        }
        if let Some(status) = status {
            app.set_recording_status(status.into());
        }
        if let Some(busy) = offline_busy {
            app.set_offline_busy(busy);
        }
        if let Some(status) = offline_status {
            app.set_offline_status(status.into());
        }
        if let Some(rows) = offline_rows {
            app.set_offline_rows(Rc::new(VecModel::from(rows)).into());
        }
    });
}

thread_local! {
    /// The unfiltered PD log, owned by the UI thread.
    static PD_ROWS: Cell<Option<Rc<VecModel<PdRow>>>> = const { Cell::new(None) };
}

/// Append new PD rows to the log, dropping the oldest past the limit.
fn apply_pd_update(app: &slint::Weak<App>, update: pd::PdUpdate) {
    let _ = app.upgrade_in_event_loop(move |app| {
        let rows = PD_ROWS.take();
        if let Some(model) = &rows {
            for row in update.rows {
                model.push(row);
            }
            while model.row_count() > pd::MAX_ROWS {
                model.remove(0);
            }
        }
        PD_ROWS.set(rows);
        if let Some(contract) = update.contract {
            app.set_pd_contract(contract.into());
        }
    });
}

fn set_pd_status(app: &slint::Weak<App>, lines: pd::PdStatusLines) {
    let _ = app.upgrade_in_event_loop(move |app| {
        app.set_pd_sink(lines.sink.into());
        app.set_pd_lines(lines.lines.into());
        if let Some(contract) = lines.contract {
            app.set_pd_contract(contract.into());
        }
    });
}

/// Turns session events into plot samples, files and UI updates.
struct Pump {
    session: Session,
    buffers: Buffers,
    app: slint::Weak<App>,
    dirs: Arc<Dirs>,
    accumulator: MeasurementAccumulator,
    rate: GraphSampleRate,
    last_readout: Instant,
    pd: pd::PdState,
    last_pd_status: Instant,
    pd_trace_enabled: bool,
    device: Option<Arc<DeviceState>>,
    latest: Option<MeasurementSample>,
    files: Files,
}

impl Pump {
    fn new(
        session: Session,
        buffers: Buffers,
        app: slint::Weak<App>,
        dirs: Arc<Dirs>,
        rate: GraphSampleRate,
        pd_trace_enabled: bool,
    ) -> Self {
        Self {
            session,
            buffers,
            app,
            files: Files::new(dirs.clone()),
            dirs,
            accumulator: MeasurementAccumulator::default(),
            rate,
            last_readout: Instant::now() - READOUT_INTERVAL,
            pd: pd::PdState::default(),
            last_pd_status: Instant::now() - PD_STATUS_INTERVAL,
            pd_trace_enabled,
            device: None,
            latest: None,
        }
    }

    async fn run(
        mut self,
        mut events: mpsc::UnboundedReceiver<SessionEvent>,
        mut commands: mpsc::UnboundedReceiver<UiCommand>,
    ) {
        self.recover();
        let mut files_tick = tokio::time::interval(FILES_INTERVAL);
        loop {
            tokio::select! {
                event = events.recv() => match event {
                    Some(event) => self.event(event),
                    None => break,
                },
                Some(command) = commands.recv() => self.command(command),
                _ = files_tick.tick() => apply_files(&self.app, self.files.poll()),
            }
        }
    }

    /// Convert the journals of recordings an earlier run did not finish.
    fn recover(&self) {
        let journal = self.dirs.journal.clone();
        let app = self.app.clone();
        tokio::task::spawn_blocking(move || match km003c_lib::recover_interrupted(&journal) {
            Ok(outcomes) => {
                for outcome in &outcomes {
                    match &outcome.result {
                        Ok(summary) => info!("Recovered {} samples to {}", summary.rows, summary.path.display()),
                        Err(error) => warn!("Could not recover {}: {error}", outcome.journal.display()),
                    }
                }
                if let Some(message) = files::recovery_message(&outcomes) {
                    apply_files(
                        &app,
                        FilesUpdate {
                            status: Some(message),
                            ..FilesUpdate::default()
                        },
                    );
                }
            }
            Err(error) => warn!("Could not look for interrupted recordings: {error}"),
        });
    }

    fn command(&mut self, command: UiCommand) {
        let update = match command {
            UiCommand::StartRecording(format) => {
                self.files.start_recording(format, self.device.as_deref(), self.latest)
            }
            UiCommand::StopRecording => self.files.stop_recording(),
            UiCommand::LoadCatalog => self.files.request_catalog(&self.session, self.device.is_some()),
            UiCommand::ExportOffline(index, format) => {
                self.files.export(index, format, &self.session, self.device.is_some())
            }
            UiCommand::SetPdTrace(enabled) => {
                self.pd_trace_enabled = enabled;
                if self.device.is_some() {
                    let _ = self.session.set_pd_trace_enabled(enabled);
                }
                FilesUpdate::default()
            }
        };
        apply_files(&self.app, update);
    }

    fn event(&mut self, event: SessionEvent) {
        let status = |text: String| Readout {
            status: Some(text),
            ..Readout::default()
        };
        match event {
            SessionEvent::Samples(samples) => self.samples(samples),
            SessionEvent::StreamingStarted(new_rate) => {
                // Samples are placed by index, so a new rate starts a new series.
                if new_rate != self.rate {
                    for buffer in &self.buffers.buffers {
                        buffer.clear();
                    }
                    self.accumulator.reset();
                } else {
                    self.accumulator.reset_continuity();
                }
                self.rate = new_rate;
                update_ui(
                    &self.app,
                    Readout {
                        status: Some(format!("Streaming at {} SPS", rate_hz(new_rate))),
                        sample_rate: Some((rate_hz(new_rate), rate_index(new_rate) as i32)),
                        ..Readout::default()
                    },
                );
            }
            SessionEvent::PdEvents(events) => apply_pd_update(&self.app, self.pd.events(&events, Instant::now())),
            SessionEvent::PdStatusUpdate(status) => {
                let now = Instant::now();
                let lines = self.pd.status(&status, now);
                if lines.contract.is_some() || now.duration_since(self.last_pd_status) >= PD_STATUS_INTERVAL {
                    self.last_pd_status = now;
                    set_pd_status(&self.app, lines);
                }
            }
            SessionEvent::PdTrace(trace) => {
                let rows = self.pd.trace(&trace);
                apply_pd_update(&self.app, pd::PdUpdate { rows, contract: None });
            }
            SessionEvent::Connected(state) => {
                info!("Connected to {} (FW {})", state.model(), state.firmware_version());
                let contract = self.pd.device_reconnected();
                apply_pd_update(
                    &self.app,
                    pd::PdUpdate {
                        rows: Vec::new(),
                        contract: Some(contract),
                    },
                );
                if self.pd_trace_enabled {
                    let _ = self.session.set_pd_trace_enabled(true);
                }
                update_ui(
                    &self.app,
                    Readout {
                        status: Some("Connected".to_string()),
                        device: Some(format!(
                            "{} · FW {} · SN {}",
                            state.model(),
                            state.firmware_version(),
                            state.info.serial_id
                        )),
                        ..Readout::default()
                    },
                );
                self.device = Some(state);
            }
            SessionEvent::WaitingForDevice => update_ui(&self.app, status("Waiting for the KM003C...".to_string())),
            SessionEvent::ConnectionFailed {
                error,
                retry_when_present,
            } => {
                warn!("Connection failed: {error}");
                update_ui(&self.app, status(format!("Connection failed: {error}")));
                if retry_when_present {
                    schedule_reconnect(&self.session, self.rate);
                }
            }
            SessionEvent::Disconnected { retry_when_present } => {
                update_ui(&self.app, status("Disconnected".to_string()));
                self.device = None;
                apply_files(&self.app, self.files.device_disconnected());
                // The contract stays: the sink may still be plugged in.
                set_pd_status(
                    &self.app,
                    pd::PdStatusLines {
                        sink: "—".to_string(),
                        lines: "—".to_string(),
                        contract: None,
                    },
                );
                if retry_when_present {
                    schedule_reconnect(&self.session, self.rate);
                }
            }
            SessionEvent::OfflineCatalog(catalog) => apply_files(&self.app, self.files.catalog(catalog)),
            SessionEvent::OfflineLogDownloaded(log) => {
                apply_files(&self.app, self.files.downloaded(log, self.device.as_deref()));
            }
            SessionEvent::OfflineOperationFailed(error) => apply_files(&self.app, self.files.offline_failed(error)),
            SessionEvent::Error(error) => {
                warn!("Session error: {error}");
                update_ui(&self.app, status(format!("Error: {error}")));
            }
            _ => {}
        }
    }

    fn samples(&mut self, samples: Vec<km003c_lib::AdcQueueSample>) {
        let mut measurements = Vec::with_capacity(samples.len());
        for sample in samples {
            let Some(measurement) = self.accumulator.push(sample, self.rate) else {
                continue;
            };
            // The plot's X axis is the sample index, so a gap has to occupy
            // its slots; NaN renders as a break in the line.
            let gap = usize::from(measurement.missing_samples).min(CAPACITY);
            for (chart, metric) in CHART_METRICS.iter().enumerate() {
                let buffer = &self.buffers.buffers[chart];
                for _ in 0..gap {
                    buffer.push_frame(&[f32::NAN]);
                }
                buffer.push_frame(&[metric.value(&measurement) as f32]);
            }
            self.buffers.pushed.fetch_add(gap as u64 + 1, Ordering::Relaxed);
            measurements.push(measurement);
        }
        let Some(&latest) = measurements.last() else {
            return;
        };
        self.latest = Some(latest);
        apply_files(&self.app, self.files.push(&measurements));
        if self.last_readout.elapsed() >= READOUT_INTERVAL {
            self.last_readout = Instant::now();
            update_ui(
                &self.app,
                Readout {
                    measurement: Some(latest),
                    ..Readout::default()
                },
            );
        }
    }
}

fn schedule_reconnect(session: &Session, rate: GraphSampleRate) {
    let session = session.clone();
    tokio::spawn(async move {
        tokio::time::sleep(RECONNECT_DELAY).await;
        let _ = session.connect(rate, USB_RESET);
    });
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
fn android_main(app: slint::android::AndroidApp) {
    // Android recreates the activity on configuration changes such as a theme
    // switch, calling android_main again in the same process. The tracing
    // subscriber is process-global and panics if installed twice.
    static LOGGING: std::sync::Once = std::sync::Once::new();
    LOGGING.call_once(|| {
        use tracing_subscriber::layer::SubscriberExt as _;
        use tracing_subscriber::util::SubscriberInitExt as _;
        use tracing_subscriber::{Layer as _, filter::LevelFilter, filter::Targets};

        // Debug and trace log every USB packet, hundreds per second at 1000 SPS.
        // nusb warns on every connection that Android refuses zero-copy
        // buffers, then falls back to ordinary ones.
        let filter = Targets::new()
            .with_default(LevelFilter::INFO)
            .with_target("nusb", LevelFilter::ERROR);
        tracing_subscriber::registry()
            .with(paranoid_android::layer("km003c").with_ansi(false).with_filter(filter))
            .init();
    });
    // A meter is watched rather than touched, so keep the screen on while the
    // app is in front. The flag only affects this window.
    use slint::android::android_activity::WindowManagerFlags;
    app.set_window_flags(WindowManagerFlags::KEEP_SCREEN_ON, WindowManagerFlags::empty());

    // Settings and journals stay private to the app. Recordings go to its
    // external files directory, which adb and file managers can read.
    let internal = app.internal_data_path().unwrap_or_else(std::env::temp_dir);
    let dirs = Dirs {
        preferences: internal.join("preferences.json"),
        journal: internal.join("journal"),
        recordings: app
            .external_data_path()
            .unwrap_or_else(|| internal.clone())
            .join("recordings"),
    };

    slint::android::init(app.clone()).expect("failed to initialize the Slint Android backend");
    run(dirs, |ui| dynamic_colors::apply(ui, &app));
}
