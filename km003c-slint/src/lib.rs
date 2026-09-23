//! Experimental Slint front end for the KM003C, on desktop and Android.
//!
//! The device session from km003c-lib runs on a Tokio runtime. Its samples go
//! through the shared [`MeasurementAccumulator`] into lock-protected ring
//! buffers, which `slint-realtime-plot` renders on the GPU each frame.

slint::include_modules!();

mod dynamic_colors;
mod pd;

use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use km003c_lib::{GraphSampleRate, MeasurementAccumulator, MeasurementSample, Metric, Session, SessionEvent};
use slint::wgpu_30::WGPUConfiguration;
use slint::{FilterModel, Model, VecModel};
use slint_realtime_plot::{PlotBuffer, PlotConfig, PlotRenderer, required_wgpu_settings};
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Ring capacity per chart: 4.4 minutes at 1000 SPS, 87 minutes at 50 SPS.
const CAPACITY: usize = 1 << 18;
const RATES: [GraphSampleRate; 4] = [
    GraphSampleRate::Sps2,
    GraphSampleRate::Sps10,
    GraphSampleRate::Sps50,
    GraphSampleRate::Sps1000,
];
const INITIAL_RATE_INDEX: usize = 2;
const RECONNECT_DELAY: Duration = Duration::from_secs(1);
const READOUT_INTERVAL: Duration = Duration::from_millis(100);
/// PD status arrives with every poll; the CC readout does not need that rate.
const PD_STATUS_INTERVAL: Duration = Duration::from_millis(250);

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

fn rate_hz(rate: GraphSampleRate) -> f32 {
    match rate {
        GraphSampleRate::Sps2 => 2.0,
        GraphSampleRate::Sps10 => 10.0,
        GraphSampleRate::Sps50 => 50.0,
        GraphSampleRate::Sps1000 => 1000.0,
    }
}

pub fn main() {
    run(|_| {});
}

/// Run the app; `customize` adjusts the window before it is shown.
fn run(customize: impl FnOnce(&App)) {
    #[cfg(not(target_os = "android"))]
    tracing_subscriber::fmt::init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("failed to start the Tokio runtime");

    slint::BackendSelector::new()
        .require_wgpu_30(WGPUConfiguration::Automatic(required_wgpu_settings(CAPACITY, 1)))
        .select()
        .expect("Unable to create Slint backend with WGPU renderer");

    let app = App::new().expect("failed to create the window");
    customize(&app);
    app.set_capacity(CAPACITY as i32);
    app.set_rate_index(INITIAL_RATE_INDEX as i32);
    app.set_sample_rate(rate_hz(RATES[INITIAL_RATE_INDEX]));

    let buffers: Buffers = Arc::new(Charts {
        buffers: std::array::from_fn(|_| PlotBuffer::new(1, CAPACITY)),
        pushed: AtomicU64::new(0),
    });

    let (session, events) = {
        let _guard = runtime.enter();
        Session::spawn()
    };
    runtime.spawn(pump_events(events, session.clone(), buffers.clone(), app.as_weak()));
    let _ = session.connect(RATES[INITIAL_RATE_INDEX], USB_RESET);

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
        app.on_reconnect(move || {
            let _ = session.disconnect();
            let _ = session.connect(RATES[INITIAL_RATE_INDEX], USB_RESET);
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

    install_renderer(&app, buffers);
    app.run().expect("event loop failed");

    let _ = session.disconnect();
    runtime.shutdown_timeout(Duration::from_secs(2));
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

fn set_pd_status(app: &slint::Weak<App>, sink: String, lines: String) {
    let _ = app.upgrade_in_event_loop(move |app| {
        app.set_pd_sink(sink.into());
        app.set_pd_lines(lines.into());
    });
}

/// Turn session events into plot samples and UI updates.
async fn pump_events(
    mut events: mpsc::UnboundedReceiver<SessionEvent>,
    session: Session,
    buffers: Buffers,
    app: slint::Weak<App>,
) {
    let mut accumulator = MeasurementAccumulator::default();
    let mut rate = RATES[INITIAL_RATE_INDEX];
    let mut last_readout = Instant::now() - READOUT_INTERVAL;
    let mut pd = pd::PdState::default();
    let mut last_pd_status = Instant::now() - PD_STATUS_INTERVAL;
    let status = |text: String| Readout {
        status: Some(text),
        ..Readout::default()
    };

    while let Some(event) = events.recv().await {
        match event {
            SessionEvent::Samples(samples) => {
                let mut latest = None;
                for sample in samples {
                    let Some(measurement) = accumulator.push(sample, rate) else {
                        continue;
                    };
                    // The plot's X axis is the sample index, so a gap has to
                    // occupy its slots; NaN renders as a break in the line.
                    let gap = usize::from(measurement.missing_samples).min(CAPACITY);
                    for (chart, metric) in CHART_METRICS.iter().enumerate() {
                        let buffer = &buffers.buffers[chart];
                        for _ in 0..gap {
                            buffer.push_frame(&[f32::NAN]);
                        }
                        buffer.push_frame(&[metric.value(&measurement) as f32]);
                    }
                    buffers.pushed.fetch_add(gap as u64 + 1, Ordering::Relaxed);
                    latest = Some(measurement);
                }
                if latest.is_some() && last_readout.elapsed() >= READOUT_INTERVAL {
                    last_readout = Instant::now();
                    update_ui(
                        &app,
                        Readout {
                            measurement: latest,
                            ..Readout::default()
                        },
                    );
                }
            }
            SessionEvent::StreamingStarted(new_rate) => {
                // Samples are placed by index, so a new rate starts a new series.
                if new_rate != rate {
                    for buffer in &buffers.buffers {
                        buffer.clear();
                    }
                    accumulator.reset();
                } else {
                    accumulator.reset_continuity();
                }
                rate = new_rate;
                let index = RATES.iter().position(|&r| r == new_rate).unwrap_or(INITIAL_RATE_INDEX);
                update_ui(
                    &app,
                    Readout {
                        status: Some(format!("Streaming at {} SPS", rate_hz(new_rate))),
                        sample_rate: Some((rate_hz(new_rate), index as i32)),
                        ..Readout::default()
                    },
                );
            }
            SessionEvent::PdEvents(events) => apply_pd_update(&app, pd.events(&events, Instant::now())),
            SessionEvent::PdStatusUpdate(status) => {
                let now = Instant::now();
                let (sink, lines) = pd.status(&status, now);
                if now.duration_since(last_pd_status) >= PD_STATUS_INTERVAL {
                    last_pd_status = now;
                    set_pd_status(&app, sink, lines);
                }
            }
            SessionEvent::Connected(state) => {
                info!("Connected to {} (FW {})", state.model(), state.firmware_version());
                pd.reset();
                update_ui(
                    &app,
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
            }
            SessionEvent::WaitingForDevice => update_ui(&app, status("Waiting for the KM003C...".to_string())),
            SessionEvent::ConnectionFailed {
                error,
                retry_when_present,
            } => {
                warn!("Connection failed: {error}");
                update_ui(&app, status(format!("Connection failed: {error}")));
                if retry_when_present {
                    schedule_reconnect(&session, rate);
                }
            }
            SessionEvent::Disconnected { retry_when_present } => {
                update_ui(&app, status("Disconnected".to_string()));
                pd.reset();
                set_pd_status(&app, "—".to_string(), "—".to_string());
                apply_pd_update(
                    &app,
                    pd::PdUpdate {
                        rows: Vec::new(),
                        contract: Some("—".to_string()),
                    },
                );
                if retry_when_present {
                    schedule_reconnect(&session, rate);
                }
            }
            SessionEvent::Error(error) => {
                warn!("Session error: {error}");
                update_ui(&app, status(format!("Error: {error}")));
            }
            _ => {}
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

    slint::android::init(app.clone()).expect("failed to initialize the Slint Android backend");
    run(|ui| dynamic_colors::apply(ui, &app));
}
