//! A small time-domain scope for the KM003C.
//!
//! The left side is split in half: live voltage, current, and power on top,
//! and the connection controls below. The center is three separate 200-pixel
//! strips — voltage, current, and power — at 100 pixels per second.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::ops::{Range, RangeInclusive};
use std::time::Duration;
use std::time::Instant;

use chrono::DateTime;
use chrono::Local;
use chrono::TimeDelta;
use chrono::Utc;
use eframe::egui;
use eframe::egui::Color32;
use eframe::egui::RichText;
use egui_plot::AxisHints;
use egui_plot::GridInput;
use egui_plot::GridMark;
use egui_plot::HPlacement;
use egui_plot::Line;
use egui_plot::Plot;
use egui_plot::PlotPoints;
use km003c_lib::DeviceState;
use km003c_lib::GraphSampleRate;
use km003c_lib::MeasurementAccumulator;
use km003c_lib::MeasurementSample;
use km003c_lib::Metric;
use km003c_lib::PdCableIdentity;
use km003c_lib::PdConnectionTracker;
use km003c_lib::PdContract;
use km003c_lib::PdContractStage;
use km003c_lib::PdEvent;
use km003c_lib::PdEventData;
use km003c_lib::PdIdentity;
use km003c_lib::PdLogCategory;
use km003c_lib::PdLogEntry;
use km003c_lib::PdLogger;
use km003c_lib::PdRevision;
use km003c_lib::PdStatus;
use km003c_lib::Session;
use km003c_lib::SessionEvent;
use km003c_lib::pd_log::format_pdo;
use km003c_lib::uom::si::electric_current::ampere;
use km003c_lib::uom::si::electric_potential::volt;
use km003c_lib::uom::si::frequency::hertz;
use km003c_lib::uom::si::thermodynamic_temperature::degree_celsius;
use km003c_lib::uom::si::time::second;
use tokio::sync::mpsc;
use tracing::{debug, info};
use tracing_subscriber::prelude::*;

const VOLTAGE_COLOR: Color32 = Color32::from_rgb(80, 220, 120);
const CURRENT_COLOR: Color32 = Color32::from_rgb(90, 170, 255);
const POWER_COLOR: Color32 = Color32::from_rgb(255, 176, 64);
/// Shared Y-axis width. Wide enough for a signed engineering tick such as `20.004 V`, so the strips stay aligned.
const AXIS_THICKNESS: f32 = 80.0;
const PIXELS_PER_SECOND: f64 = 100.0;
const MIN_PIXELS_PER_SECOND: f64 = 10.0;
const MAX_PIXELS_PER_SECOND: f64 = 1_000.0;
/// How strongly one point of wheel travel changes the time scale.
const SCROLL_ZOOM_SPEED: f64 = 0.002;
/// Pixels of clear space between the cursor line and its readout.
const CURSOR_LABEL_GAP: f64 = 6.0;
/// Flip the readout to the left of the line when fewer pixels remain on the right.
const CURSOR_LABEL_MARGIN: f64 = 110.0 * 1.3;
/// Largest cursor readout. It is 30% larger than the original 16 px and stays in the bold face.
const CURSOR_LABEL_SIZE: f32 = 16.0 * 1.3;
const INITIAL_SECONDS: f64 = 8.0;
const MIN_SECONDS: f64 = 4.0;
const STRIP_HEIGHT: f32 = 200.0;
/// Full-buffer preview above the event lane, one sixth of a measurement strip.
const OVERVIEW_HEIGHT: f32 = STRIP_HEIGHT / 6.0;
/// Vertical padding around an autoscaled trace, as a fraction of its span.
const Y_MARGIN_FRACTION: f64 = 0.08;
/// Smallest autoscaled voltage span: 8 mV.
const MIN_VOLTAGE_SPAN: f64 = 0.008;
/// Smallest autoscaled current and power span: 2 mA and 2 mW.
const MIN_Y_SPAN: f64 = 0.002;
/// Gap above the voltage strip.
const STRIP_GAP: f32 = 16.0;
/// Gap between voltage and current, and between current and power.
const STRIP_GAP_BETWEEN: f32 = STRIP_GAP * 1.3;
/// Horizontal and vertical inset of egui's central panel frame.
const CENTRAL_PANEL_MARGIN: f32 = 8.0;
/// Space Mono's advance width, in font units per em.
const SPACE_MONO_ADVANCE_EM: f32 = 612.0 / 1000.0;
const METER_VALUE_FONT_SIZE: f32 = 28.0;
const STATUS_FONT_SIZE: f32 = 13.0;
const EVENT_LABEL_SIZE: f32 = 12.0;
const EVENT_CLUSTER_DISTANCE: f32 = 28.0;
const EVENT_LANE_HEIGHT: f32 = 32.0;
const EVENT_LANE_GAP: f32 = 3.0;
const EVENT_TOOLBAR_HEIGHT: f32 = 30.0;
const EVENT_EXPLORER_WIDTH: f32 = 260.0;
const BUFFER_BAR_HEIGHT: f32 = 8.0;
/// Horizontal inset of egui's side-panel frame, on each side.
const SIDE_PANEL_INNER_MARGIN: f32 = 8.0;
/// Padding inside the black meter box, on each side.
const METER_BOX_MARGIN: f32 = 8.0;
/// Room egui reserves for the side panel's separator stroke.
const SIDE_PANEL_SEPARATOR: f32 = 1.0;
/// Newest samples kept, at any rate. This is 10 hours at 50/s and 30 minutes at 1000/s.
const MAX_SAMPLES: usize = 1_800_000;
const USB_RESET_SUPPORTED: bool = !cfg!(target_os = "windows");
include!(concat!(env!("OUT_DIR"), "/usb_vendors.rs"));
const RATES: [GraphSampleRate; 4] = [
    GraphSampleRate::Sps2,
    GraphSampleRate::Sps10,
    GraphSampleRate::Sps50,
    GraphSampleRate::Sps1000,
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let log_filter = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| "info".to_string())
        .parse::<tracing_subscriber::filter::Targets>()
        .unwrap_or_else(|error| {
            eprintln!("Ignoring invalid RUST_LOG filter: {error}");
            "info".parse().expect("the default log filter is valid")
        });
    tracing_subscriber::registry()
        .with(log_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
    info!("Starting KM003C scope");

    let (session, events) = Session::spawn();
    let rate = GraphSampleRate::Sps50;
    // WinUSB cannot reset devices, and macOS handles re-enumeration badly.
    let usb_reset = USB_RESET_SUPPORTED && !cfg!(target_os = "macos");
    let _ = session.connect(rate, usb_reset);

    let app = ScopeApp {
        session,
        events,
        accumulator: MeasurementAccumulator::default(),
        samples: VecDeque::new(),
        markers: VecDeque::new(),
        next_marker_id: 0,
        selected_marker_id: None,
        event_explorer_open: false,
        host_time_origin_utc: None,
        meter: MeterAverage::default(),
        voltage: None,
        current: None,
        power: None,
        cc1: None,
        cc2: None,
        temperature_c: None,
        status: "Connecting...".to_string(),
        device: None,
        device_info_open: false,
        pd: PdView::default(),
        pd_info_open: false,
        connected: false,
        streaming: false,
        rate,
        window_secs: INITIAL_SECONDS,
        pixels_per_second: PIXELS_PER_SECOND,
        view_end: None,
        autoscroll: true,
        cursor_mode: false,
        cursor_time: None,
        plot_width: None,
        plot_left: None,
        overview_frame: None,
        overview_grabbed: false,
        overview_press: None,
        window_has_pointer: false,
        usb_reset,
    };

    let [width, height] = initial_window_size();
    let [min_width, _] = minimum_window_size();
    eframe::run_native(
        "KM003C Scope",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([width, height])
                .with_min_inner_size([min_width, height])
                .with_max_inner_size([16_384.0, height])
                .with_title("KM003C Scope"),
            ..Default::default()
        },
        Box::new(|cc| {
            install_meter_font(&cc.egui_ctx);
            Ok(Box::new(app))
        }),
    )
    .map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
}

struct ScopeApp {
    session: Session,
    events: mpsc::UnboundedReceiver<SessionEvent>,
    accumulator: MeasurementAccumulator,
    samples: VecDeque<MeasurementSample>,
    markers: VecDeque<TimelineMarker>,
    next_marker_id: u64,
    selected_marker_id: Option<u64>,
    event_explorer_open: bool,
    host_time_origin_utc: Option<DateTime<Utc>>,
    meter: MeterAverage,
    voltage: Option<f64>,
    current: Option<f64>,
    power: Option<f64>,
    cc1: Option<f64>,
    cc2: Option<f64>,
    temperature_c: Option<f64>,
    status: String,
    device: Option<DeviceState>,
    device_info_open: bool,
    /// Negotiated USB PD contract and the latest CC measurements.
    pd: PdView,
    pd_info_open: bool,
    connected: bool,
    streaming: bool,
    rate: GraphSampleRate,
    window_secs: f64,
    /// Shared horizontal scale of the three strips. The wheel changes this.
    pixels_per_second: f64,
    /// Right edge of the visible time window, in seconds.
    view_end: Option<f64>,
    /// When set, the strips follow the newest sample.
    autoscroll: bool,
    /// Dragging moves a time cursor instead of the traces.
    cursor_mode: bool,
    /// Cursor position on the shared time axis, in seconds.
    cursor_time: Option<f64>,
    /// Inner plot width from the previous frame, in pixels.
    plot_width: Option<f64>,
    /// Screen position of the inner plot's left edge, from the previous frame.
    plot_left: Option<f32>,
    /// Plot-aligned area of the buffer overview, from the previous frame.
    overview_frame: Option<egui::Rect>,
    /// The current press started on the overview, so it keeps panning until release.
    overview_grabbed: bool,
    /// Press position when the gesture started on the overview.
    overview_press: Option<egui::Pos2>,
    /// The current press started on a floating window, so it must not pan the strips.
    window_has_pointer: bool,
    usb_reset: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimelineCategory {
    Connectivity,
    Protocol,
    Warning,
    Info,
}

impl TimelineCategory {
    const fn color(self) -> Color32 {
        match self {
            Self::Connectivity => Color32::from_rgb(62, 205, 181),
            Self::Protocol => Color32::from_rgb(90, 170, 255),
            Self::Warning => Color32::from_rgb(255, 176, 64),
            Self::Info => Color32::from_gray(170),
        }
    }

    const fn priority(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Protocol => 1,
            Self::Connectivity => 2,
            Self::Warning => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct TimelineMarker {
    id: u64,
    elapsed_seconds: f64,
    category: TimelineCategory,
    label: &'static str,
    name: &'static str,
    details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TimelineMarkerSpec {
    category: TimelineCategory,
    label: &'static str,
    name: &'static str,
}

impl eframe::App for ScopeApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain_events();
        let repaint = if self.streaming { 16 } else { 100 };
        ui.ctx().request_repaint_after(Duration::from_millis(repaint));

        egui::Panel::left("side")
            .resizable(false)
            .exact_size(meter_pane_width())
            .show(ui, |ui| self.side(ui));
        if self.event_explorer_open {
            egui::Panel::right("event_explorer")
                .resizable(false)
                .exact_size(EVENT_EXPLORER_WIDTH)
                .show(ui, |ui| self.event_explorer(ui));
        }
        egui::CentralPanel::default().show(ui, |ui| self.scope(ui));
        self.event_explorer_toggle(ui.ctx());
        self.device_info_dialog(ui.ctx());
        self.pd_info_dialog(ui.ctx());
    }
}

impl ScopeApp {
    fn drain_events(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            match event {
                SessionEvent::WaitingForDevice => {
                    self.status = "Waiting for a KM003C...".to_string();
                }
                SessionEvent::Connected(state) => {
                    self.connected = true;
                    self.device = Some((*state).clone());
                    self.pd.device_reconnected();
                    self.status = "Connected".to_string();
                }
                SessionEvent::ConnectionFailed { error, .. } => {
                    self.mark_disconnected();
                    self.status = format!("Connection failed: {error}");
                }
                SessionEvent::Samples(samples) => {
                    let rate = self.rate;
                    let mut newest_elapsed = None;
                    for sample in samples {
                        let Some(measurement) = self.accumulator.push(sample, rate) else {
                            continue;
                        };
                        newest_elapsed = Some(measurement.elapsed_seconds());
                        self.samples.push_back(measurement);
                        if let Some(reading) = self.meter.push(
                            rate,
                            Metric::Voltage.value(&measurement),
                            Metric::SignedCurrent.value(&measurement),
                            Metric::SignedPower.value(&measurement),
                            Metric::Cc1.value(&measurement),
                            Metric::Cc2.value(&measurement),
                        ) {
                            self.voltage = Some(reading.voltage);
                            self.current = Some(reading.current);
                            self.power = Some(reading.power);
                            self.cc1 = Some(reading.cc1);
                            self.cc2 = Some(reading.cc2);
                        }
                    }
                    if self.host_time_origin_utc.is_none()
                        && let Some(elapsed_seconds) = newest_elapsed
                    {
                        self.host_time_origin_utc = Some(timeline_origin_utc(Utc::now(), elapsed_seconds));
                    }
                    self.trim_window();
                }
                SessionEvent::AdcUpdate(adc) => {
                    self.temperature_c = Some(adc.temperature.get::<degree_celsius>());
                }
                SessionEvent::StreamingStarted(rate) => {
                    if let Some(time) = self.samples.back().map(|sample| sample.elapsed_seconds()) {
                        self.push_marker(
                            time,
                            TimelineMarkerSpec {
                                category: TimelineCategory::Info,
                                label: "RATE",
                                name: "Sample rate",
                            },
                            format!("Streaming changed to {}", rate_label(rate)),
                        );
                    }
                    self.streaming = true;
                    self.rate = rate;
                    // A rate change restarts the device counter. Keep the samples
                    // and the elapsed time so the new points continue the trace.
                    self.accumulator.reset_continuity();
                    self.meter.reset();
                    self.status = format!("Streaming at {}", rate_label(rate));
                }
                SessionEvent::StreamingStopped => {
                    self.streaming = false;
                    self.status = "Streaming stopped".to_string();
                }
                SessionEvent::Error(error) => {
                    self.status = error;
                }
                SessionEvent::Disconnected { .. } => {
                    self.mark_disconnected();
                    self.status = "Disconnected".to_string();
                }
                SessionEvent::PdEvents(events) => self.observe_pd_events(&events),
                SessionEvent::PdStatusUpdate(status) => self.pd.observe_status(status),
                SessionEvent::PdTrace(_)
                | SessionEvent::OfflineCatalog(_)
                | SessionEvent::OfflineLogDownloaded(_)
                | SessionEvent::OfflineOperationFailed(_) => {}
                _ => {}
            }
        }
    }

    fn observe_pd_events(&mut self, events: &[PdEvent]) {
        let entries = self.pd.observe_events(events);
        let Some(timeline_anchor) = self.samples.back().map(|sample| sample.elapsed_seconds()) else {
            return;
        };
        let device_anchor = self
            .pd
            .status
            .map(|status| status.timestamp.get::<second>())
            .or_else(|| events.last().map(|event| event.timestamp.get::<second>()));
        let Some(device_anchor) = device_anchor else {
            return;
        };

        for (event, entry) in events.iter().zip(entries) {
            let Some(spec) = pd_timeline_marker(&entry) else {
                continue;
            };
            let wraps_at_24_bits = matches!(&event.data, PdEventData::Connect | PdEventData::Disconnect);
            let time = pd_timeline_time(
                event.timestamp.get::<second>(),
                device_anchor,
                timeline_anchor,
                wraps_at_24_bits,
            );
            self.push_marker(time, spec, pd_marker_details(&entry));
        }
    }

    fn push_marker(&mut self, elapsed_seconds: f64, spec: TimelineMarkerSpec, details: String) {
        if elapsed_seconds.is_finite() {
            let id = self.next_marker_id;
            self.next_marker_id = self.next_marker_id.wrapping_add(1);
            let elapsed_seconds = elapsed_seconds.max(0.0);
            info!(
                "EVENT {} +{elapsed_seconds:.3}s {} {} | {}",
                format_event_full_time(self.host_time_origin_utc.as_ref(), elapsed_seconds),
                spec.label,
                spec.name,
                details.replace('\n', " | ")
            );
            self.markers.push_back(TimelineMarker {
                id,
                elapsed_seconds,
                category: spec.category,
                label: spec.label,
                name: spec.name,
                details,
            });
        }
    }

    fn mark_disconnected(&mut self) {
        self.connected = false;
        self.streaming = false;
        self.device = None;
        self.device_info_open = false;
        self.pd_info_open = false;
        self.pd.reset();
        self.voltage = None;
        self.current = None;
        self.power = None;
        self.cc1 = None;
        self.cc2 = None;
        self.temperature_c = None;
        self.samples.clear();
        self.markers.clear();
        self.selected_marker_id = None;
        self.host_time_origin_utc = None;
        self.accumulator = MeasurementAccumulator::default();
        self.meter.reset();
    }

    fn trim_window(&mut self) {
        trim_to_max_samples(&mut self.samples, MAX_SAMPLES);
        let Some(oldest) = self.samples.front().map(|sample| sample.elapsed_seconds()) else {
            self.markers.clear();
            self.selected_marker_id = None;
            return;
        };
        while self
            .markers
            .front()
            .is_some_and(|marker| marker.elapsed_seconds < oldest)
        {
            self.markers.pop_front();
        }
        if self
            .selected_marker_id
            .is_some_and(|id| !self.markers.iter().any(|marker| marker.id == id))
        {
            self.selected_marker_id = None;
        }
    }

    fn side(&mut self, ui: &mut egui::Ui) {
        let meter_height = (ui.available_height() - BUFFER_BAR_HEIGHT).max(0.0) * 0.5;
        let width = ui.available_width();
        ui.allocate_ui(egui::vec2(width, meter_height), |ui| self.readings(ui));
        ui.add_space(8.0);
        let controls_height = (ui.available_height() - BUFFER_BAR_HEIGHT).max(0.0);
        egui::ScrollArea::vertical()
            .id_salt("controls")
            .auto_shrink([false, false])
            .max_height(controls_height)
            .show(ui, |ui| self.controls(ui));
        self.buffer_meter(ui);
    }

    fn controls(&mut self, ui: &mut egui::Ui) {
        ui.label(self.status.as_str());
        ui.add_space(8.0);
        ui.add_enabled(
            USB_RESET_SUPPORTED,
            egui::Checkbox::new(&mut self.usb_reset, "USB reset on connect"),
        )
        .on_hover_text(if USB_RESET_SUPPORTED {
            "Applied the next time Connect runs. Leave this off on macOS."
        } else {
            "WinUSB does not support USB device reset."
        });
        ui.add_space(8.0);

        if self.connected {
            if ui.button("Disconnect").clicked() {
                let _ = self.session.disconnect();
            }
        } else if ui.button("Connect").clicked() {
            self.status = "Connecting...".to_string();
            let _ = self.session.connect(self.rate, self.usb_reset);
        }

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(self.device.is_some(), egui::Button::new("Device Info"))
                .clicked()
            {
                self.device_info_open = true;
            }
            if ui
                .add_enabled(self.device.is_some(), egui::Button::new("PD Info"))
                .clicked()
            {
                self.pd_info_open = true;
            }
        });
        ui.add_space(8.0);
        ui.checkbox(&mut self.autoscroll, "Autoscroll");
        let cursor_was_off = !self.cursor_mode;
        ui.checkbox(&mut self.cursor_mode, "Cursor");
        if self.cursor_mode && cursor_was_off {
            self.cursor_time = self.view_end.map(|end| end - self.window_secs * 0.5);
        }

        ui.add_space(8.0);
        ui.label("Sample rate");
        let previous_rate = self.rate;
        egui::ComboBox::from_id_salt("sample_rate")
            .selected_text(rate_label(self.rate))
            .show_ui(ui, |ui| {
                for rate in RATES {
                    ui.selectable_value(&mut self.rate, rate, rate_label(rate));
                }
            });
        if self.streaming && self.rate != previous_rate {
            let _ = self.session.set_sample_rate(self.rate);
        }
    }

    fn event_explorer_toggle(&mut self, ctx: &egui::Context) {
        let clicked = egui::Area::new("event_explorer_toggle".into())
            .anchor(egui::Align2::RIGHT_TOP, egui::vec2(-8.0, 4.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                let (rect, response) = ui.allocate_exact_size(egui::vec2(30.0, 24.0), egui::Sense::click());
                let visuals = ui.style().interact(&response);
                ui.painter().rect_filled(rect, 5.0, visuals.weak_bg_fill);
                ui.painter()
                    .rect_stroke(rect, 5.0, visuals.bg_stroke, egui::StrokeKind::Inside);

                let icon = rect.shrink2(egui::vec2(7.0, 5.0));
                let divider_x = icon.right() - icon.width() * 0.32;
                ui.painter()
                    .rect_stroke(icon, 2.0, visuals.fg_stroke, egui::StrokeKind::Inside);
                ui.painter().line_segment(
                    [egui::pos2(divider_x, icon.top()), egui::pos2(divider_x, icon.bottom())],
                    visuals.fg_stroke,
                );
                ui.painter().rect_filled(
                    egui::Rect::from_min_max(
                        egui::pos2(divider_x + 1.0, icon.top() + 1.0),
                        egui::pos2(icon.right() - 1.0, icon.bottom() - 1.0),
                    ),
                    1.0,
                    visuals.fg_stroke.color.gamma_multiply(0.25),
                );

                let clicked = response.clicked();
                response.on_hover_text("Event Explorer");
                clicked
            })
            .inner;
        if clicked {
            self.toggle_event_explorer(ctx);
        }
    }

    fn toggle_event_explorer(&mut self, ctx: &egui::Context) {
        let opening = !self.event_explorer_open;
        if let Some(current_size) = ctx.input(|input| input.viewport().inner_rect.map(|rect| rect.size())) {
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(explorer_viewport_size(
                current_size,
                opening,
            )));
        }
        self.event_explorer_open = opening;
    }

    fn event_explorer(&mut self, ui: &mut egui::Ui) {
        ui.add_space(EVENT_TOOLBAR_HEIGHT);
        ui.heading("Events");
        ui.separator();

        let mut clicked = None;
        let selected_id = self.selected_marker_id;
        let host_time_origin_utc = self.host_time_origin_utc.as_ref();
        egui::ScrollArea::vertical()
            .id_salt("event_explorer_list")
            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
            .auto_shrink([false, false])
            .stick_to_bottom(selected_id.is_none())
            .show(ui, |ui| {
                if self.markers.is_empty() {
                    ui.weak("No events observed");
                    return;
                }
                for marker in &self.markers {
                    let selected = selected_id == Some(marker.id);
                    let row = format!(
                        "{:>12}  {}",
                        format_event_time(host_time_origin_utc, marker.elapsed_seconds),
                        marker.name
                    );
                    let response = ui.selectable_label(
                        selected,
                        RichText::new(row)
                            .font(egui::FontId::new(12.0, egui::FontFamily::Name("Space Mono".into())))
                            .color(marker.category.color()),
                    );
                    if response.clicked() {
                        clicked = Some(marker.id);
                    }
                    if selected {
                        response.on_hover_ui(|ui| {
                            ui.strong(marker.name);
                            ui.monospace(format_event_full_time(host_time_origin_utc, marker.elapsed_seconds));
                            ui.monospace(format!("Elapsed: {:.3} s", marker.elapsed_seconds));
                            ui.separator();
                            ui.label(&marker.details);
                        });
                    }
                }
            });

        if let Some(id) = clicked {
            self.select_marker(id);
        }
    }

    fn buffer_meter(&self, ui: &mut egui::Ui) {
        let pane = ui.clip_rect();
        let rect = egui::Rect::from_min_max(
            egui::pos2(pane.left(), pane.bottom() - BUFFER_BAR_HEIGHT),
            pane.right_bottom(),
        );
        let fraction = buffer_fraction(self.samples.len(), MAX_SAMPLES);
        let painter = ui.ctx().layer_painter(ui.layer_id());
        painter.rect_filled(rect, 0.0, ui.visuals().extreme_bg_color);
        if fraction > 0.0 {
            let mut filled = rect;
            filled.max.x = rect.left() + rect.width() * fraction;
            painter.rect_filled(filled, 0.0, ui.visuals().selection.bg_fill);
        }
        ui.interact(rect, ui.id().with("buffer_meter"), egui::Sense::hover())
            .on_hover_text(buffer_meter_label(
                self.samples.len(),
                MAX_SAMPLES,
                self.rate.frequency().get::<hertz>(),
            ));
    }

    fn select_marker(&mut self, id: u64) {
        let Some(time) = self
            .markers
            .iter()
            .find(|marker| marker.id == id)
            .map(|marker| marker.elapsed_seconds)
        else {
            return;
        };
        self.selected_marker_id = Some(id);
        self.autoscroll = false;
        self.view_end = Some(centered_view_end(time, self.window_secs));
    }

    fn device_info_dialog(&mut self, ctx: &egui::Context) {
        if self.device.is_none() {
            self.device_info_open = false;
            return;
        }
        let Some(device) = self.device.clone() else {
            return;
        };
        if !self.device_info_open {
            return;
        }
        let close_requested = ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("device_info_viewport"),
            egui::ViewportBuilder::default()
                .with_title("Device Info")
                .with_inner_size([480.0, 280.0])
                .with_min_inner_size([360.0, 220.0]),
            |ui, class| {
                let close_requested = class != egui::ViewportClass::EmbeddedWindow
                    && ui.ctx().input(|input| input.viewport().close_requested());
                egui::CentralPanel::default().show(ui, |ui| {
                    egui::Grid::new("device_info")
                        .num_columns(2)
                        .striped(true)
                        .show(ui, |ui| {
                            let mut row = |label: &str, value: &str| {
                                ui.label(label);
                                ui.label(if value.is_empty() { "—" } else { value });
                                ui.end_row();
                            };
                            row("Model", &device.info.model);
                            row("Serial", &device.info.serial_id);
                            row("Firmware", &device.info.fw_version);
                            row("Firmware date", &device.info.fw_date);
                            row("Hardware", &device.info.hw_version);
                            row("Manufactured", &device.info.mfg_date);
                            row("UUID", &device.info.uuid);
                            row("Hardware ID", &device.hardware_id.to_string());
                        });
                });
                close_requested
            },
        );
        if close_requested {
            self.device_info_open = false;
        }
    }

    fn pd_info_dialog(&mut self, ctx: &egui::Context) {
        if self.device.is_none() {
            self.pd_info_open = false;
            return;
        }
        if !self.pd_info_open {
            return;
        }
        let sink = sink_label(self.pd.tracker.connected());
        let revision = self
            .pd
            .logger
            .revision()
            .map(|revision| revision.to_string())
            .unwrap_or_else(|| "Not observed".to_string());
        let contract = if self.pd.contract.stage() == PdContractStage::None {
            "Not observed".to_string()
        } else {
            self.pd.contract.to_string()
        };
        let source_pdos = self
            .pd
            .logger
            .source_pdo_count()
            .map(|count| count.to_string())
            .unwrap_or_else(|| "Not observed".to_string());
        let max_power = self
            .pd
            .logger
            .source_max_power_w()
            .map(|watts| format!("{watts:.0} W"))
            .unwrap_or_else(|| "Not observed".to_string());
        let identity = self
            .pd
            .logger
            .identity()
            .map(identity_label)
            .unwrap_or_else(|| "Not observed".to_string());
        let cable_rows = cable_info_rows(
            self.pd.logger.cable_discovery_requested(),
            self.pd.logger.cable_identities(),
        );
        let status = self.pd.status;
        let vbus = self.voltage.or_else(|| status.map(|value| value.vbus.get::<volt>()));
        let ibus = self.current.or_else(|| status.map(|value| value.ibus.get::<ampere>()));
        let cc1 = self.cc1.or_else(|| status.map(|value| value.cc1.get::<volt>()));
        let cc2 = self.cc2.or_else(|| status.map(|value| value.cc2.get::<volt>()));
        let offered = self.pd.offered_modes();
        let close_requested = ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("pd_info_viewport"),
            egui::ViewportBuilder::default()
                .with_title("PD Info")
                .with_inner_size([500.0, 650.0])
                .with_min_inner_size([360.0, 260.0]),
            |ui, class| {
                let close_requested = class != egui::ViewportClass::EmbeddedWindow
                    && ui.ctx().input(|input| input.viewport().close_requested());
                egui::CentralPanel::default().show(ui, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        egui::Grid::new("pd_info").num_columns(2).striped(true).show(ui, |ui| {
                            let mut row = |label: &str, value: &str| {
                                ui.label(label);
                                ui.label(if value.is_empty() { "—" } else { value });
                                ui.end_row();
                            };
                            row("PD revision", &revision);
                            row("Contract", &contract);
                            row("Source PDOs", &source_pdos);
                            row("Maximum power", &max_power);
                            row("Identity", &identity);
                            for (label, value) in &cable_rows {
                                row(label, value);
                            }
                            row("Downstream sink", sink);
                            if let (Some(vbus), Some(ibus), Some(cc1), Some(cc2)) = (vbus, ibus, cc1, cc2) {
                                row("VBUS", &format!("{vbus:.3} V"));
                                row("IBUS", &format!("{ibus:.3} A"));
                                row("CC1", &format!("{cc1:.3} V"));
                                row("CC2", &format!("{cc2:.3} V"));
                            }
                            if offered.is_empty() {
                                row("Offered", "Not observed");
                            } else {
                                for (index, offer) in offered.iter().enumerate() {
                                    row(if index == 0 { "Offered" } else { "" }, offer);
                                }
                            }
                        });
                    });
                });
                close_requested
            },
        );
        if close_requested {
            self.pd_info_open = false;
        }
    }

    fn readings(&self, ui: &mut egui::Ui) {
        egui::Frame::new()
            .fill(Color32::BLACK)
            .inner_margin(METER_BOX_MARGIN)
            .corner_radius(4.0)
            .show(ui, |ui| {
                reading(ui, self.voltage, "V", VOLTAGE_COLOR);
                ui.add_space(12.0);
                reading(ui, self.current, "A", CURRENT_COLOR);
                ui.add_space(12.0);
                reading(ui, self.power, "W", POWER_COLOR);
                ui.add_space(10.0);
                ui.separator();
                ui.add_space(4.0);
                status_strip(
                    ui,
                    self.temperature_c,
                    self.pd.logger.revision(),
                    self.pd.logger.source_max_power_w(),
                );
            });
    }

    fn scope(&mut self, ui: &mut egui::Ui) {
        ui.add_space(EVENT_TOOLBAR_HEIGHT);
        self.zoom_time_scale(ui);
        self.follow_plot_width();
        let dragging = self.place_time_window(ui);
        self.clamp_view();
        let width = ui.available_width();
        ui.spacing_mut().item_spacing.y = EVENT_LANE_GAP;
        let (overview_rect, _) = ui.allocate_exact_size(egui::vec2(width, OVERVIEW_HEIGHT), egui::Sense::hover());
        self.paint_overview(ui, overview_rect);
        let (event_lane_rect, _) = ui.allocate_exact_size(egui::vec2(width, EVENT_LANE_HEIGHT), egui::Sense::hover());
        let event_lane_left = self.plot_left.unwrap_or(event_lane_rect.left() + AXIS_THICKNESS);
        paint_event_lane_background(ui, event_lane_rect, event_lane_left);
        ui.spacing_mut().item_spacing.y = STRIP_GAP_BETWEEN;
        let link = ui.id().with("scope_time");
        let time = visible_time(self.view_end, self.window_secs);
        let visible_samples = self
            .view_end
            .map(|end| visible_sample_range(&self.samples, end - self.window_secs, end));
        let strips = [
            Strip::new("scope_voltage", Metric::Voltage, VOLTAGE_COLOR, "V", false),
            Strip::new("scope_current", Metric::SignedCurrent, CURRENT_COLOR, "A", false),
            Strip::new("scope_power", Metric::SignedPower, POWER_COLOR, "W", true),
        ];
        let mut plot_width = None;
        let mut plot_left = None;
        for strip in strips {
            let points = match &visible_samples {
                Some(range) => series(&self.samples, strip.metric, range.clone()),
                None => Vec::new(),
            };
            ui.allocate_ui(egui::vec2(width, STRIP_HEIGHT), |ui| {
                let cursor = self.cursor_mark(strip.metric);
                let marker_lane = (strip.metric == Metric::Voltage).then_some(MarkerLane {
                    markers: &self.markers,
                    rect: event_lane_rect,
                    selected_id: self.selected_marker_id,
                });
                let frame = trace_plot(
                    ui,
                    &strip,
                    &points,
                    link,
                    time.clone(),
                    TraceOverlay {
                        marker_lane,
                        cursor,
                        hide_pointer_lines: self.cursor_mode,
                        host_time_origin_utc: self.host_time_origin_utc.as_ref(),
                    },
                );
                plot_width.get_or_insert(f64::from(frame.width()));
                plot_left.get_or_insert(frame.left());
            });
        }
        if let Some(width) = plot_width {
            self.plot_width = Some(width.max(1.0));
        }
        if let Some(left) = plot_left {
            self.plot_left = Some(left);
        }
        if dragging {
            ui.ctx().set_cursor_icon(egui::CursorIcon::Grabbing);
        }
    }

    /// Wheel over the strips changes pixels per second for every plot.
    ///
    /// Scrolling up shows less time. With Autoscroll on, the newest sample stays
    /// on the right once the trace is longer than the window. Otherwise the time
    /// under the pointer stays where it is.
    fn zoom_time_scale(&mut self, ui: &egui::Ui) {
        let rect = ui.available_rect_before_wrap();
        if !ui.rect_contains_pointer(rect) || pointer_over_floating_window(ui) {
            return;
        }
        let (scroll, pointer_x) =
            ui.input(|input| (input.smooth_scroll_delta.y, input.pointer.latest_pos().map(|pos| pos.x)));
        if scroll == 0.0 {
            return;
        }
        let next_scale = zoomed_pixels_per_second(self.pixels_per_second, scroll);
        if !self.autoscroll
            && let (Some(pointer_x), Some(end), Some(plot_width), Some(plot_left)) =
                (pointer_x, self.view_end, self.plot_width, self.plot_left)
        {
            self.view_end = Some(zoomed_view_end_at_pointer(
                pointer_x,
                plot_left,
                plot_width,
                end,
                self.window_secs,
                self.pixels_per_second,
                next_scale,
            ));
        }
        self.pixels_per_second = next_scale;
    }

    /// Keep the current pixels per second. A wider plot then covers more time.
    fn follow_plot_width(&mut self) {
        let Some(plot_width) = self.plot_width else {
            return;
        };
        self.window_secs = plot_width / self.pixels_per_second;
    }

    /// Dragging moves every strip along time and leaves Autoscroll off.
    ///
    /// Cursor mode keeps Autoscroll. The marker sits on the time under the pointer.
    /// With Autoscroll on, the first sample stays on the left until the trace fills
    /// the window, and then the right edge follows the newest sample.
    fn place_time_window(&mut self, ui: &egui::Ui) -> bool {
        let rect = ui.available_rect_before_wrap();
        let (primary_down, primary_pressed, primary_clicked, delta_x, origin, pointer_x) = ui.input(|input| {
            (
                input.pointer.primary_down(),
                input.pointer.primary_pressed(),
                input.pointer.primary_clicked(),
                input.pointer.delta().x,
                input.pointer.press_origin(),
                input.pointer.latest_pos().map(|pos| pos.x),
            )
        });
        let origin_on_window = origin.is_some_and(|pos| {
            ui.ctx()
                .layer_id_at(pos)
                .is_some_and(|layer| layer_covers_plots(layer.order))
        });
        self.window_has_pointer = pointer_blocks_plots(self.window_has_pointer, primary_down, origin_on_window);
        if !self.window_has_pointer {
            self.begin_overview_gesture(primary_pressed, origin);
        }
        let dragging_overview = self.overview_grabbed && primary_down && delta_x != 0.0 && !self.window_has_pointer;
        let on_overview = self.overview_press.is_some()
            || origin.is_some_and(|pos| self.overview_frame.is_some_and(|frame| frame.contains(pos)));
        let drag_started_on_plots = origin.is_some_and(|origin| rect.contains(origin)) && !on_overview;
        let interacting_with_plots = drag_started_on_plots && !self.window_has_pointer;
        let placing_cursor = self.cursor_mode && primary_down && interacting_with_plots;
        let panning = primary_down && interacting_with_plots && delta_x != 0.0 && !self.cursor_mode;
        if self.autoscroll
            && !panning
            && !dragging_overview
            && let Some(latest) = self.samples.back()
        {
            self.view_end = Some(latest.elapsed_seconds());
        }
        if dragging_overview {
            self.autoscroll = false;
            if let Some((buf_start, buf_end)) = sample_buffer_span(&self.samples)
                && let Some(frame) = self.overview_frame
            {
                let end = self.view_end.unwrap_or(buf_end);
                self.view_end = Some(overview_dragged_view_end(
                    end,
                    delta_x,
                    frame.width(),
                    buf_start,
                    buf_end,
                    self.window_secs,
                ));
            }
            return true;
        }
        if primary_clicked
            && self.overview_grabbed
            && !self.window_has_pointer
            && let Some(press) = self.overview_press
        {
            self.center_overview_at(press.x);
        }
        if !primary_down {
            self.overview_grabbed = false;
            self.overview_press = None;
        }
        if placing_cursor {
            if let (Some(pointer_x), Some(end)) = (pointer_x, self.view_end) {
                let plot_left = self.plot_left.unwrap_or(rect.left() + AXIS_THICKNESS);
                self.cursor_time = Some(time_at_pointer(
                    pointer_x,
                    plot_left,
                    end,
                    self.window_secs,
                    self.pixels_per_second,
                ));
            }
            return true;
        }
        if self.cursor_mode && self.cursor_time.is_none() {
            self.cursor_time = self.view_end.map(|end| end - self.window_secs * 0.5);
        }
        if panning {
            self.autoscroll = false;
            let end = self.view_end.unwrap_or(0.0);
            self.view_end = Some(panned_view_end(end, delta_x, self.pixels_per_second));
            return true;
        }
        false
    }

    /// Keep the visible window from starting before the oldest sample.
    fn clamp_view(&mut self) {
        let Some((buf_start, buf_end)) = sample_buffer_span(&self.samples) else {
            return;
        };
        let Some(end) = self.view_end else {
            return;
        };
        self.view_end = Some(clamped_view_end(end, buf_start, buf_end, self.window_secs));
    }

    fn cursor_mark(&self, metric: Metric) -> Option<CursorMark> {
        if !self.cursor_mode {
            return None;
        }
        let time = self.cursor_time?;
        let label_on_left = self
            .view_end
            .is_some_and(|end| cursor_label_on_left(time, end, self.pixels_per_second));
        Some(CursorMark {
            time,
            value: cursor_value(&self.samples, metric, time),
            label_on_left,
        })
    }

    /// A press anywhere on the overview centers the visible window and grabs it until release.
    ///
    /// A click leaves that centered window in place. A drag keeps panning from there,
    /// on the bright window and on the dimmed buffer alike.
    fn begin_overview_gesture(&mut self, primary_pressed: bool, origin: Option<egui::Pos2>) {
        if !primary_pressed {
            return;
        }
        let Some(origin) = origin else {
            self.overview_grabbed = false;
            self.overview_press = None;
            return;
        };
        if !self.overview_frame.is_some_and(|frame| frame.contains(origin)) {
            self.overview_grabbed = false;
            self.overview_press = None;
            return;
        }
        self.overview_press = Some(origin);
        self.overview_grabbed = true;
        self.center_overview_at(origin.x);
    }

    fn center_overview_at(&mut self, pointer_x: f32) {
        let Some(frame) = self.overview_frame else {
            return;
        };
        let Some((buf_start, buf_end)) = sample_buffer_span(&self.samples) else {
            return;
        };
        let time = overview_time_at_x(pointer_x, frame.left(), frame.width(), buf_start, buf_end);
        self.view_end = Some(overview_centered_view_end(time, buf_start, buf_end, self.window_secs));
        self.autoscroll = false;
    }

    fn paint_overview(&mut self, ui: &egui::Ui, row: egui::Rect) {
        let left = self.plot_left.unwrap_or(row.left() + AXIS_THICKNESS);
        let width = self.plot_width.unwrap_or(f64::from((row.right() - left).max(1.0)));
        let frame = egui::Rect::from_min_size(egui::pos2(left, row.top()), egui::vec2(width as f32, row.height()));
        self.overview_frame = Some(frame);
        let painter = ui.ctx().layer_painter(ui.layer_id());
        painter.rect_filled(frame, 0.0, Color32::BLACK);
        let Some((buf_start, buf_end)) = sample_buffer_span(&self.samples) else {
            return;
        };
        let columns = (frame.width() as usize).clamp(1, 1200);
        for (metric, color) in [
            (Metric::SignedPower, POWER_COLOR),
            (Metric::SignedCurrent, CURRENT_COLOR),
            (Metric::Voltage, VOLTAGE_COLOR),
        ] {
            let points = overview_envelope(&self.samples, metric, columns);
            paint_overview_curve(&painter, frame, &points, buf_start, buf_end, color);
        }
        let view_end = self.view_end.unwrap_or(buf_end);
        let (left_edge, right_edge) =
            overview_window_fraction(view_end - self.window_secs, view_end, buf_start, buf_end);
        let window_left = frame.left() + left_edge as f32 * frame.width();
        let window_right = frame.left() + right_edge as f32 * frame.width();
        let shade = Color32::from_rgba_unmultiplied(176, 176, 176, 150);
        if window_left > frame.left() {
            painter.rect_filled(
                egui::Rect::from_min_max(frame.left_top(), egui::pos2(window_left, frame.bottom())),
                0.0,
                shade,
            );
        }
        if window_right < frame.right() {
            painter.rect_filled(
                egui::Rect::from_min_max(egui::pos2(window_right, frame.top()), frame.right_bottom()),
                0.0,
                shade,
            );
        }
    }
}

fn reading(ui: &mut egui::Ui, value: Option<f64>, unit: &str, color: Color32) {
    ui.add(
        egui::Label::new(meter_text(format_measurement(value, unit), METER_VALUE_FONT_SIZE).color(color))
            .wrap_mode(egui::TextWrapMode::Extend),
    );
}

/// Sign, two integer digits, and six decimal places, so the points line up.
fn format_measurement(value: Option<f64>, unit: &str) -> String {
    let number = match value {
        Some(value) if value.is_finite() => {
            let sign = if value.is_sign_negative() { '-' } else { ' ' };
            format!("{sign}{abs:9.6}", abs = value.abs())
        }
        _ => " ".repeat(10),
    };
    format!("{number} {unit}")
}

fn format_temperature(value: Option<f64>) -> String {
    match value {
        Some(value) if value.is_finite() => format!("{value:.0}°C"),
        _ => "-".to_string(),
    }
}

fn protocol_label(revision: Option<PdRevision>) -> &'static str {
    match revision {
        Some(PdRevision::Revision1) => "PD1.0",
        Some(PdRevision::Revision2) => "PD2.0",
        Some(PdRevision::Revision3) => "PD3.0",
        None => "-",
    }
}

fn format_max_power(watts: Option<f64>) -> String {
    match watts {
        Some(watts) if watts.is_finite() => format!("{watts:.0}W"),
        _ => "-".to_string(),
    }
}

fn status_strip(ui: &mut egui::Ui, temperature_c: Option<f64>, revision: Option<PdRevision>, max_power_w: Option<f64>) {
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), STATUS_FONT_SIZE + 3.0),
        egui::Sense::hover(),
    );
    let font = egui::FontId::new(STATUS_FONT_SIZE, egui::FontFamily::Name("Space Mono".into()));
    let color = Color32::LIGHT_GRAY;
    let text_y = rect.center().y;

    paint_thermometer(ui.painter(), rect);
    let fields = [
        (rect.left() + 12.0, format_temperature(temperature_c)),
        (rect.left() + rect.width() * 0.46, protocol_label(revision).to_string()),
        (rect.left() + rect.width() * 0.75, format_max_power(max_power_w)),
    ];
    for (x, text) in fields {
        ui.painter().text(
            egui::pos2(x, text_y),
            egui::Align2::LEFT_CENTER,
            text,
            font.clone(),
            color,
        );
    }
}

fn paint_thermometer(painter: &egui::Painter, rect: egui::Rect) {
    let color = Color32::from_rgb(255, 145, 96);
    let center_x = rect.left() + 4.0;
    let bulb = egui::pos2(center_x, rect.bottom() - 3.0);
    painter.line_segment(
        [egui::pos2(center_x, rect.top() + 1.0), bulb],
        egui::Stroke::new(2.0, color),
    );
    painter.circle_filled(bulb, 3.0, color);
}

/// Outer width of the left pane: one meter line, the black box, and the panel frame.
fn meter_pane_width() -> f32 {
    let columns = format_measurement(Some(-99.99999), "W").chars().count() as f32;
    let text = columns * SPACE_MONO_ADVANCE_EM * METER_VALUE_FONT_SIZE;
    (text + METER_BOX_MARGIN * 2.0 + SIDE_PANEL_INNER_MARGIN * 2.0 + SIDE_PANEL_SEPARATOR).ceil()
}

fn meter_text(text: impl Into<String>, size: f32) -> RichText {
    RichText::new(text).font(egui::FontId::new(size, egui::FontFamily::Name("Space Mono".into())))
}

/// How many samples make one meter update. The display refreshes twice a second:
/// one sample at 2 SPS, five at 10 SPS, and so on.
fn samples_per_meter_update(rate: GraphSampleRate) -> u32 {
    (rate.frequency().get::<hertz>() as u32) / 2
}

#[derive(Debug, Default)]
struct MeterAverage {
    rate: Option<GraphSampleRate>,
    count: u32,
    voltage: f64,
    current: f64,
    power: f64,
    cc1: f64,
    cc2: f64,
}

#[derive(Debug, PartialEq)]
struct MeterReading {
    voltage: f64,
    current: f64,
    power: f64,
    cc1: f64,
    cc2: f64,
}

impl MeterAverage {
    fn reset(&mut self) {
        *self = Self::default();
    }

    /// Average the next half-second of samples. Returns the mean once the window is full.
    fn push(
        &mut self,
        rate: GraphSampleRate,
        voltage: f64,
        current: f64,
        power: f64,
        cc1: f64,
        cc2: f64,
    ) -> Option<MeterReading> {
        if self.rate != Some(rate) {
            self.rate = Some(rate);
            self.count = 0;
            self.voltage = 0.0;
            self.current = 0.0;
            self.power = 0.0;
            self.cc1 = 0.0;
            self.cc2 = 0.0;
        }
        self.voltage += voltage;
        self.current += current;
        self.power += power;
        self.cc1 += cc1;
        self.cc2 += cc2;
        self.count += 1;
        if self.count < samples_per_meter_update(rate) {
            return None;
        }
        let count = f64::from(self.count);
        let averaged = MeterReading {
            voltage: self.voltage / count,
            current: self.current / count,
            power: self.power / count,
            cc1: self.cc1 / count,
            cc2: self.cc2 / count,
        };
        self.count = 0;
        self.voltage = 0.0;
        self.current = 0.0;
        self.power = 0.0;
        self.cc1 = 0.0;
        self.cc2 = 0.0;
        Some(averaged)
    }
}

fn install_meter_font(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "Space Mono".to_owned(),
        std::sync::Arc::new(egui::FontData::from_static(include_bytes!(
            "../fonts/SpaceMono-Regular.ttf"
        ))),
    );
    fonts.font_data.insert(
        "Space Mono Bold".to_owned(),
        std::sync::Arc::new(egui::FontData::from_static(include_bytes!(
            "../fonts/SpaceMono-Bold.ttf"
        ))),
    );
    let fallbacks = fonts
        .families
        .get(&egui::FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    let mut regular = vec!["Space Mono".to_owned()];
    regular.extend(fallbacks.iter().cloned());
    let mut bold = vec!["Space Mono Bold".to_owned()];
    bold.extend(fallbacks);
    fonts
        .families
        .insert(egui::FontFamily::Name("Space Mono".into()), regular);
    fonts
        .families
        .insert(egui::FontFamily::Name("Space Mono Bold".into()), bold);
    ctx.set_fonts(fonts);
}

fn visible_sample_range(samples: &VecDeque<MeasurementSample>, start: f64, end: f64) -> Range<usize> {
    let first = samples.partition_point(|sample| sample.elapsed_seconds() < start);
    let after_last = samples.partition_point(|sample| sample.elapsed_seconds() <= end);
    first..after_last
}

fn series(samples: &VecDeque<MeasurementSample>, metric: Metric, range: Range<usize>) -> Vec<[f64; 2]> {
    samples
        .range(range)
        .map(|sample| [sample.elapsed_seconds(), metric.value(sample)])
        .collect()
}

struct TraceOverlay<'a> {
    marker_lane: Option<MarkerLane<'a>>,
    cursor: Option<CursorMark>,
    hide_pointer_lines: bool,
    host_time_origin_utc: Option<&'a DateTime<Utc>>,
}

#[derive(Clone, Copy)]
struct MarkerLane<'a> {
    markers: &'a VecDeque<TimelineMarker>,
    rect: egui::Rect,
    selected_id: Option<u64>,
}

/// Draw one 200-pixel strip. The three strips share the time axis.
fn trace_plot(
    ui: &mut egui::Ui,
    strip: &Strip,
    points: &[[f64; 2]],
    link: egui::Id,
    time: Option<RangeInclusive<f64>>,
    overlay: TraceOverlay<'_>,
) -> egui::Rect {
    let width = ui.available_width();
    let mut plot = Plot::new(strip.id)
        .width(width)
        .height(STRIP_HEIGHT)
        .show_grid(true)
        .custom_y_axes(y_axis(strip.unit))
        .show_axes([strip.show_time, true])
        .link_axis(link, [true, false])
        .link_cursor(link, [true, false])
        .auto_bounds([false, true])
        .allow_zoom(false)
        .allow_drag(false)
        .allow_scroll(false)
        .allow_axis_zoom_drag(false)
        .allow_boxed_zoom(false)
        .set_margin_fraction(egui::vec2(0.0, Y_MARGIN_FRACTION as f32));
    let formatter_origin = overlay.host_time_origin_utc.cloned();
    plot = plot.x_axis_formatter(move |mark, range| {
        format_axis_time(formatter_origin.as_ref(), mark.value, mark.step_size, range)
    });
    let grid_origin = overlay.host_time_origin_utc.cloned();
    plot = plot.x_grid_spacer(move |input| host_time_grid_marks(grid_origin.as_ref(), input));
    if overlay.hide_pointer_lines {
        plot = plot.cursor_color(Color32::TRANSPARENT);
    }
    if strip.show_time {
        plot = plot.x_axis_label(format_time_axis_label(overlay.host_time_origin_utc, time.as_ref()));
    }
    let drawn = plot.show(ui, |plot_ui| {
        plot_ui.set_auto_bounds([false, true]);
        if let Some(time) = time {
            plot_ui.set_plot_bounds_x(time);
        }
        if let Some(range) = y_axis_range(
            points,
            overlay.cursor.as_ref().and_then(|mark| mark.value),
            strip.metric,
        ) {
            plot_ui.set_plot_bounds_y(range);
        }
        plot_ui.line(
            Line::new(strip.id, PlotPoints::new(points.to_vec()))
                .color(strip.color)
                .width(1.8),
        );
        if let Some(cursor) = &overlay.cursor {
            plot_ui.vline(
                egui_plot::VLine::new(format!("{}-cursor", strip.id), cursor.time)
                    .color(strip.color)
                    .width(1.5)
                    .allow_hover(false),
            );
        }
    });
    if let Some(lane) = overlay.marker_lane {
        paint_timeline_markers(ui, lane, &drawn.transform);
    }
    if let Some(cursor) = &overlay.cursor {
        paint_cursor_value(ui, strip, cursor, &drawn.transform);
    }
    *drawn.transform.frame()
}

fn paint_timeline_markers(ui: &egui::Ui, lane: MarkerLane<'_>, transform: &egui_plot::PlotTransform) {
    let frame = *transform.frame();
    let mut clusters: Vec<(f32, TimelineCategory, &'static str, usize, bool)> = Vec::new();
    for marker in lane.markers {
        let x = transform.position_from_point_x(marker.elapsed_seconds);
        if x < frame.left() || x > frame.right() {
            continue;
        }
        if let Some(cluster) = clusters.last_mut()
            && x - cluster.0 < EVENT_CLUSTER_DISTANCE
        {
            cluster.3 += 1;
            cluster.4 |= lane.selected_id == Some(marker.id);
            if marker.category.priority() > cluster.1.priority() {
                cluster.1 = marker.category;
            }
            continue;
        }
        clusters.push((x, marker.category, marker.label, 1, lane.selected_id == Some(marker.id)));
    }

    let painter = ui.ctx().layer_painter(ui.layer_id()).with_clip_rect(lane.rect);
    painter.line_segment(
        [
            egui::pos2(frame.left(), lane.rect.bottom() - 1.0),
            egui::pos2(frame.right(), lane.rect.bottom() - 1.0),
        ],
        egui::Stroke::new(1.0, ui.visuals().widgets.noninteractive.bg_stroke.color),
    );
    let label_y = lane.rect.top() + 1.0;
    let triangle_y = label_y + 2.0 + EVENT_LABEL_SIZE + 1.0;
    for (x, category, label, count, selected) in clusters {
        let color = category.color();
        let display = if count == 1 {
            label.to_string()
        } else {
            format!("+{count}")
        };
        painter.text(
            egui::pos2(x.clamp(frame.left() + 12.0, frame.right() - 12.0), label_y),
            egui::Align2::CENTER_TOP,
            display,
            egui::FontId::new(EVENT_LABEL_SIZE, egui::FontFamily::Name("Space Mono Bold".into())),
            if selected { Color32::WHITE } else { color },
        );
        painter.add(egui::Shape::convex_polygon(
            vec![
                egui::pos2(x - 4.0, triangle_y),
                egui::pos2(x + 4.0, triangle_y),
                egui::pos2(x, triangle_y + 6.0),
            ],
            color,
            if selected {
                egui::Stroke::new(1.5, Color32::WHITE)
            } else {
                egui::Stroke::NONE
            },
        ));
    }
}

fn paint_event_lane_background(ui: &egui::Ui, rect: egui::Rect, plot_left: f32) {
    ui.painter()
        .rect_filled(rect, 3.0, ui.visuals().widgets.noninteractive.weak_bg_fill);
    ui.painter().text(
        egui::pos2(plot_left - 4.0, rect.center().y),
        egui::Align2::RIGHT_CENTER,
        "EVENTS",
        egui::FontId::new(9.0, egui::FontFamily::Name("Space Mono".into())),
        ui.visuals().weak_text_color(),
    );
}

/// Bold readout in the gap above the strip, beside the cursor line.
fn paint_cursor_value(ui: &egui::Ui, strip: &Strip, cursor: &CursorMark, transform: &egui_plot::PlotTransform) {
    let Some(value) = cursor.value else {
        return;
    };
    let frame = *transform.frame();
    let room = if strip.metric == Metric::Voltage {
        f32::INFINITY
    } else {
        (STRIP_GAP_BETWEEN - 2.0).max(1.0)
    };
    let text = format!("{value:.3} {}", strip.unit);
    let galley = ui.painter().layout_no_wrap(
        text.clone(),
        egui::FontId::new(CURSOR_LABEL_SIZE, egui::FontFamily::Name("Space Mono Bold".into())),
        strip.color,
    );
    let font_size = fitted_cursor_font_size(CURSOR_LABEL_SIZE, galley.size().y, room);
    let galley = if font_size == CURSOR_LABEL_SIZE {
        galley
    } else {
        ui.painter().layout_no_wrap(
            text,
            egui::FontId::new(font_size, egui::FontFamily::Name("Space Mono Bold".into())),
            strip.color,
        )
    };
    let x = transform.position_from_point_x(cursor.time);
    let text_x = if cursor.label_on_left {
        x - CURSOR_LABEL_GAP as f32 - galley.size().x
    } else {
        x + CURSOR_LABEL_GAP as f32
    };
    let min_x = frame.left();
    let max_x = (frame.right() - galley.size().x).max(min_x);
    let text_y = if strip.metric == Metric::Voltage {
        frame.top() + 4.0
    } else {
        let gap = STRIP_GAP_BETWEEN;
        (frame.top() - gap + (gap - galley.size().y) * 0.5).min(frame.top() - galley.size().y)
    };
    ui.ctx()
        .layer_painter(ui.layer_id())
        .galley(egui::pos2(text_x.clamp(min_x, max_x), text_y), galley, strip.color);
}

/// Shrink `size` so a label of `measured_height` fits in `room`.
fn fitted_cursor_font_size(size: f32, measured_height: f32, room: f32) -> f32 {
    if measured_height <= room || measured_height <= f32::EPSILON {
        size
    } else {
        size * room / measured_height
    }
}

struct Strip {
    id: &'static str,
    metric: Metric,
    color: Color32,
    unit: &'static str,
    show_time: bool,
}

impl Strip {
    fn new(id: &'static str, metric: Metric, color: Color32, unit: &'static str, show_time: bool) -> Self {
        Self {
            id,
            metric,
            color,
            unit,
            show_time,
        }
    }
}

/// Negotiated USB PD state collected while the meter is streaming.
#[derive(Default)]
struct PdView {
    logger: PdLogger,
    tracker: PdConnectionTracker,
    contract: PdContract,
    status: Option<PdStatus>,
}

impl PdView {
    fn reset(&mut self) {
        *self = Self::default();
    }

    /// A new connection missed any negotiation that already finished.
    fn device_reconnected(&mut self) {
        self.logger.reset();
        self.tracker = PdConnectionTracker::default();
        self.contract.device_reconnected();
        self.status = None;
    }

    fn observe_events(&mut self, events: &[PdEvent]) -> Vec<PdLogEntry> {
        let now = Instant::now();
        let mut entries = Vec::with_capacity(events.len());
        for event in events {
            match &event.data {
                PdEventData::Connect => self.tracker.observe_event(true, now),
                PdEventData::Disconnect => self.tracker.observe_event(false, now),
                PdEventData::PdMessage { .. } => {}
            }
            let entry = self.logger.log_event(event);
            log_pd_event(event, &entry);
            self.contract.observe(&entry);
            entries.push(entry);
        }
        entries
    }

    fn observe_status(&mut self, status: PdStatus) {
        let now = Instant::now();
        self.tracker.observe_status(&status, now);
        self.tracker.update(now);
        self.contract.observe_sink(self.tracker.connected());
        self.status = Some(status);
    }

    fn offered_modes(&self) -> Vec<String> {
        let Some(capabilities) = self.logger.source_capabilities() else {
            return Vec::new();
        };
        capabilities
            .pdos()
            .iter()
            .enumerate()
            .map(|(index, pdo)| format!("{}: {}", index + 1, format_pdo(pdo)))
            .collect()
    }
}

fn log_pd_event(event: &PdEvent, entry: &PdLogEntry) {
    let details = if entry.details.is_empty() {
        String::new()
    } else {
        format!(" | {}", entry.details.join(" ; "))
    };
    let raw = match &event.data {
        PdEventData::PdMessage { wire_data, .. } => {
            let mut hex = String::with_capacity(wire_data.len() * 2);
            for byte in wire_data {
                let _ = write!(hex, "{byte:02x}");
            }
            format!(" | raw={hex}")
        }
        PdEventData::Connect | PdEventData::Disconnect => String::new(),
    };
    debug!("PD {}{details}{raw}", entry.summary());
}

fn pd_timeline_marker(entry: &PdLogEntry) -> Option<TimelineMarkerSpec> {
    let (category, label, name) = match (entry.category, entry.title.as_str()) {
        (PdLogCategory::Connect, _) => (TimelineCategory::Connectivity, "ATT", "Attached"),
        (PdLogCategory::Disconnect, _) => (TimelineCategory::Connectivity, "DET", "Detached"),
        (_, "Source_Capabilities" | "EPR_Source_Capabilities") => (TimelineCategory::Protocol, "NEG", "Negotiation"),
        (_, "PS_RDY") => (TimelineCategory::Protocol, "RDY", "Power ready"),
        (_, "Soft_Reset" | "Hard_Reset") => (TimelineCategory::Warning, "RST", "PD reset"),
        (_, "Reject") => (TimelineCategory::Warning, "REJ", "Request rejected"),
        (_, "PR_Swap" | "DR_Swap" | "VCONN_Swap" | "FR_Swap") => (TimelineCategory::Protocol, "SWP", "Role swap"),
        (PdLogCategory::Error, _) => (TimelineCategory::Warning, "ERR", "PD decode error"),
        _ => return None,
    };
    Some(TimelineMarkerSpec { category, label, name })
}

fn pd_marker_details(entry: &PdLogEntry) -> String {
    if entry.details.is_empty() {
        entry.summary()
    } else {
        format!("{}\n{}", entry.summary(), entry.details.join("\n"))
    }
}

fn pd_timeline_time(
    event_device_time: f64,
    anchor_device_time: f64,
    anchor_timeline_time: f64,
    wraps_at_24_bits: bool,
) -> f64 {
    const CONNECTION_TIMESTAMP_WRAP_SECONDS: f64 = (1_u64 << 24) as f64 / 1_000.0;
    let event_device_time = if wraps_at_24_bits {
        let wraps = ((anchor_device_time - event_device_time) / CONNECTION_TIMESTAMP_WRAP_SECONDS).round();
        event_device_time + wraps * CONNECTION_TIMESTAMP_WRAP_SECONDS
    } else {
        event_device_time
    };
    (anchor_timeline_time + event_device_time - anchor_device_time).max(0.0)
}

fn elapsed_delta(elapsed_seconds: f64) -> TimeDelta {
    TimeDelta::microseconds((elapsed_seconds * 1_000_000.0).round() as i64)
}

fn timeline_origin_utc(observed_at: DateTime<Utc>, elapsed_seconds: f64) -> DateTime<Utc> {
    observed_at - elapsed_delta(elapsed_seconds)
}

fn host_time_utc(origin: &DateTime<Utc>, elapsed_seconds: f64) -> DateTime<Utc> {
    *origin + elapsed_delta(elapsed_seconds)
}

fn host_time_local(origin: &DateTime<Utc>, elapsed_seconds: f64) -> DateTime<Local> {
    host_time_utc(origin, elapsed_seconds).with_timezone(&Local)
}

fn clock_grid_steps(base_step_size: f64) -> [f64; 3] {
    const STEPS: [f64; 11] = [
        0.01,
        0.1,
        1.0,
        10.0,
        60.0,
        600.0,
        3_600.0,
        21_600.0,
        86_400.0,
        604_800.0,
        2_592_000.0,
    ];
    let index = STEPS
        .iter()
        .position(|step| *step >= base_step_size.abs())
        .unwrap_or(STEPS.len() - 1)
        .min(STEPS.len() - 3);
    [STEPS[index], STEPS[index + 1], STEPS[index + 2]]
}

fn host_time_grid_marks(origin: Option<&DateTime<Utc>>, input: GridInput) -> Vec<GridMark> {
    if input.base_step_size.abs() < f64::EPSILON {
        return Vec::new();
    }
    let origin_seconds = origin.map_or(0.0, |origin| {
        origin.timestamp() as f64 + f64::from(origin.timestamp_subsec_nanos()) / 1_000_000_000.0
    });
    let bounds = if input.bounds.0 <= input.bounds.1 {
        input.bounds
    } else {
        (input.bounds.1, input.bounds.0)
    };
    let absolute_bounds = (origin_seconds + bounds.0, origin_seconds + bounds.1);
    let steps = clock_grid_steps(input.base_step_size);
    let mut marks = Vec::new();

    for step in steps {
        let first = (absolute_bounds.0 / step).ceil() * step;
        let count = (((absolute_bounds.1 - first) / step).floor() as isize + 1).max(0) as usize;
        for index in 0..count.min(10_000) {
            let absolute = first + index as f64 * step;
            marks.push(GridMark {
                value: absolute - origin_seconds,
                step_size: step,
            });
        }
    }

    marks.sort_by(|left, right| left.value.total_cmp(&right.value));
    let epsilon = steps[0] * 1e-4;
    let mut deduplicated: Vec<GridMark> = Vec::with_capacity(marks.len());
    for mark in marks {
        if let Some(previous) = deduplicated.last_mut()
            && (previous.value - mark.value).abs() < epsilon
        {
            if previous.step_size < mark.step_size {
                *previous = mark;
            }
        } else {
            deduplicated.push(mark);
        }
    }
    deduplicated
}

fn axis_fraction_digits(step_size: f64) -> usize {
    if step_size >= 1.0 {
        0
    } else if step_size >= 0.1 {
        1
    } else {
        2
    }
}

fn format_axis_clock(time: DateTime<Local>, digits: usize) -> String {
    let rounding = match digits {
        0 => TimeDelta::milliseconds(500),
        1 => TimeDelta::milliseconds(50),
        _ => TimeDelta::milliseconds(5),
    };
    let rounded = time + rounding;
    let base = rounded.format("%H:%M:%S");
    if digits == 0 {
        base.to_string()
    } else {
        let fraction = match digits {
            1 => rounded.timestamp_subsec_millis() / 100,
            _ => rounded.timestamp_subsec_millis() / 10,
        };
        format!("{base}.{fraction:0digits$}")
    }
}

fn format_axis_time(
    origin: Option<&DateTime<Utc>>,
    elapsed_seconds: f64,
    step_size: f64,
    visible_range: &RangeInclusive<f64>,
) -> String {
    let digits = axis_fraction_digits(step_size);
    let Some(origin) = origin else {
        return format!("{elapsed_seconds:.digits$}");
    };
    let time = host_time_local(origin, elapsed_seconds);
    let crosses_date = host_time_local(origin, *visible_range.start()).date_naive()
        != host_time_local(origin, *visible_range.end()).date_naive();
    let date = time.format("%m-%d").to_string();
    let formatted = format_axis_clock(time, digits);
    if crosses_date {
        format!("{date} {formatted}")
    } else {
        formatted
    }
}

fn format_time_axis_label(origin: Option<&DateTime<Utc>>, visible_range: Option<&RangeInclusive<f64>>) -> String {
    let (Some(origin), Some(range)) = (origin, visible_range) else {
        return "Elapsed time (s)".to_string();
    };
    let center = (*range.start() + *range.end()) * 0.5;
    format!("Local time · {}", host_time_local(origin, center).format("%b %d, %Y"))
}

fn format_event_time(origin: Option<&DateTime<Utc>>, elapsed_seconds: f64) -> String {
    match origin {
        Some(origin) => host_time_local(origin, elapsed_seconds)
            .format("%H:%M:%S%.3f")
            .to_string(),
        None => format!("+{elapsed_seconds:.3}s"),
    }
}

fn format_event_full_time(origin: Option<&DateTime<Utc>>, elapsed_seconds: f64) -> String {
    match origin {
        Some(origin) => host_time_local(origin, elapsed_seconds)
            .format("%Y-%m-%d %H:%M:%S%.3f %Z")
            .to_string(),
        None => format!("Elapsed +{elapsed_seconds:.3} s"),
    }
}

fn centered_view_end(event_time: f64, window_secs: f64) -> f64 {
    event_time + window_secs * 0.5
}

fn explorer_viewport_size(current: egui::Vec2, opening: bool) -> egui::Vec2 {
    let delta = if opening {
        EVENT_EXPLORER_WIDTH
    } else {
        -EVENT_EXPLORER_WIDTH
    };
    egui::vec2((current.x + delta).max(1.0), current.y)
}

fn sink_label(connected: Option<bool>) -> &'static str {
    match connected {
        Some(true) => "Attached",
        Some(false) => "Not attached",
        None => "Detecting",
    }
}

fn identity_label(identity: PdIdentity) -> String {
    let vendor = usb_vendor_name(identity.vendor_id).unwrap_or("Unknown vendor");
    match identity.product_id {
        Some(product_id) => format!("{vendor} (VID {:04X}, PID {product_id:04X})", identity.vendor_id),
        None => format!("{vendor} (VID {:04X})", identity.vendor_id),
    }
}

fn cable_info_rows(discovery_requested: bool, cables: &[PdCableIdentity]) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    let observation = match (discovery_requested, cables.is_empty()) {
        (false, true) => "Not observed",
        (true, true) => "Host query observed; no response",
        (false, false) => "Cable response observed",
        (true, false) => "Host query and cable response observed",
    };
    rows.push(("Cable discovery".to_string(), observation.to_string()));

    for (index, cable) in cables.iter().enumerate() {
        let suffix = if cables.len() == 1 {
            String::new()
        } else {
            format!(" {}", index + 1)
        };
        let vendor = usb_vendor_name(cable.vendor_id).unwrap_or("Unknown vendor");
        rows.push((
            format!("Cable{suffix}"),
            format!(
                "{} · {vendor} (VID {:04X}, PID {:04X})",
                cable.kind, cable.vendor_id, cable.product_id
            ),
        ));

        let mut power = format!("{}", cable.vbus_current);
        if let Some(voltage) = cable.maximum_vbus_voltage {
            write!(power, " · {voltage}").expect("writing to a String cannot fail");
        }
        if let Some(epr_capable) = cable.epr_capable {
            power.push_str(if epr_capable {
                " · EPR capable"
            } else {
                " · Not EPR capable"
            });
        }
        rows.push((format!("Cable power{suffix}"), power));
        rows.push((format!("Cable data{suffix}"), cable.highest_speed.to_string()));
        rows.push((format!("Cable connector{suffix}"), cable.connector.to_string()));
        rows.push((format!("Cable latency{suffix}"), cable.latency.to_string()));
        rows.push((format!("Cable VCONN{suffix}"), cable.termination.to_string()));

        rows.push((
            format!("Cable identity{suffix}"),
            format!("XID {:08X} · device {:04X}", cable.xid, cable.device_bcd),
        ));

        let mut versions = format!("HW {} · FW {}", cable.hardware_version, cable.firmware_version);
        if let Some(version) = cable.vdo_version {
            write!(versions, " · VDO 1.{version}").expect("writing to a String cannot fail");
        }
        rows.push((format!("Cable versions{suffix}"), versions));

        let mut features = Vec::new();
        if let Some(vbus_through_cable) = cable.vbus_through_cable {
            features.push(if vbus_through_cable {
                "VBUS through cable"
            } else {
                "No VBUS passthrough"
            });
        }
        if let Some(sop_double_prime_present) = cable.sop_double_prime_present {
            features.push(if sop_double_prime_present {
                "SOP'' controller present"
            } else {
                "No SOP'' controller"
            });
        }
        if let Some(sbu_supported) = cable.sbu_supported {
            features.push(if sbu_supported {
                "SBU supported"
            } else {
                "No SBU support"
            });
        }
        if let Some(sbu_active) = cable.sbu_active {
            features.push(if sbu_active { "Active SBU" } else { "Passive SBU" });
        }
        if !features.is_empty() {
            rows.push((format!("Cable features{suffix}"), features.join(" · ")));
        }

        if let Some(active) = cable.active_details {
            rows.push((
                format!("Active cable{suffix}"),
                format!(
                    "{} · {} · {} lane(s) · {}",
                    active.medium,
                    active.active_element,
                    active.lanes,
                    if active.optically_isolated {
                        "optically isolated"
                    } else {
                        "not optically isolated"
                    }
                ),
            ));
            let mut support = Vec::new();
            if active.usb4_supported {
                support.push("USB4");
            }
            if active.usb32_supported {
                support.push("USB 3.2");
            }
            if active.usb2_supported {
                support.push("USB 2.0");
            }
            rows.push((
                format!("Active support{suffix}"),
                if support.is_empty() {
                    "No USB support advertised".to_string()
                } else {
                    support.join(" · ")
                },
            ));
            rows.push((
                format!("Cable thermal{suffix}"),
                format!(
                    "Max {}°C · shutdown {}°C",
                    active.maximum_operating_temperature_c, active.shutdown_temperature_c
                ),
            ));
        }
    }

    rows
}

fn usb_vendor_name(vendor_id: u16) -> Option<&'static str> {
    let index = USB_VENDOR_NAMES
        .binary_search_by_key(&vendor_id, |(candidate, _)| *candidate)
        .ok()?;
    Some(USB_VENDOR_NAMES[index].1)
}

/// Autoscaled Y range. A wider trace keeps its own span.
fn y_axis_range(points: &[[f64; 2]], extra: Option<f64>, metric: Metric) -> Option<RangeInclusive<f64>> {
    let mut min_y = f64::INFINITY;
    let mut max_y = f64::NEG_INFINITY;
    let mut consider = |y: f64| {
        if y.is_finite() {
            min_y = min_y.min(y);
            max_y = max_y.max(y);
        }
    };
    for point in points {
        consider(point[1]);
    }
    if let Some(y) = extra {
        consider(y);
    }
    if !min_y.is_finite() {
        return None;
    }
    Some(scaled_y_range(min_y, max_y, min_y_span(metric)))
}

fn min_y_span(metric: Metric) -> f64 {
    match metric {
        Metric::Voltage => MIN_VOLTAGE_SPAN,
        _ => MIN_Y_SPAN,
    }
}

/// Pad the samples, then refuse to zoom in tighter than `min_span`.
fn scaled_y_range(min_y: f64, max_y: f64, min_span: f64) -> RangeInclusive<f64> {
    let mid = (min_y + max_y) * 0.5;
    let span = (max_y - min_y).max(0.0);
    let padded = span * (1.0 + 2.0 * Y_MARGIN_FRACTION);
    let half = padded.max(min_span) * 0.5;
    (mid - half)..=(mid + half)
}

fn trim_to_max_samples<T>(items: &mut VecDeque<T>, max_samples: usize) {
    let overflow = items.len().saturating_sub(max_samples);
    if overflow > 0 {
        items.drain(..overflow);
    }
}

fn buffer_fraction(len: usize, max_samples: usize) -> f32 {
    if max_samples == 0 {
        0.0
    } else {
        (len as f32 / max_samples as f32).clamp(0.0, 1.0)
    }
}

/// Percent full, and how long the free space lasts at `samples_per_second`.
fn buffer_meter_label(len: usize, max_samples: usize, samples_per_second: f64) -> String {
    let percent = f64::from(buffer_fraction(len, max_samples)) * 100.0;
    let remaining = max_samples.saturating_sub(len);
    let seconds = if samples_per_second > 0.0 {
        remaining as f64 / samples_per_second
    } else {
        0.0
    };
    format!("{percent:.3}% ({})", format_buffer_time(seconds))
}

fn format_buffer_time(seconds: f64) -> String {
    let total = seconds.round().max(0.0) as u64;
    let hours = total / 3600;
    let minutes = (total % 3600) / 60;
    let secs = total % 60;
    if hours > 0 {
        format!("{hours}h {minutes}m {secs}s")
    } else if minutes > 0 {
        format!("{minutes}m {secs}s")
    } else {
        format!("{secs}s")
    }
}

fn sample_buffer_span(samples: &VecDeque<MeasurementSample>) -> Option<(f64, f64)> {
    Some((samples.front()?.elapsed_seconds(), samples.back()?.elapsed_seconds()))
}

/// Fraction of the stored buffer covered by the visible window, clamped to the buffer.
fn overview_window_fraction(view_start: f64, view_end: f64, buf_start: f64, buf_end: f64) -> (f64, f64) {
    if buf_end <= buf_start {
        return (0.0, 1.0);
    }
    let span = buf_end - buf_start;
    (
        ((view_start - buf_start) / span).clamp(0.0, 1.0),
        ((view_end - buf_start) / span).clamp(0.0, 1.0),
    )
}

/// Time in the stored buffer at a horizontal position in the overview.
fn overview_time_at_x(pointer_x: f32, frame_left: f32, frame_width: f32, buf_start: f64, buf_end: f64) -> f64 {
    let fraction = f64::from(pointer_x - frame_left) / f64::from(frame_width.max(1.0));
    buf_start + fraction.clamp(0.0, 1.0) * (buf_end - buf_start)
}

/// Put `time` at the center of the visible window, keeping the window inside the buffer when it fits.
fn overview_centered_view_end(time: f64, buf_start: f64, buf_end: f64, window_secs: f64) -> f64 {
    clamped_view_end(time + window_secs * 0.5, buf_start, buf_end, window_secs)
}

/// Dragging the bright region to the right moves the visible window later in time.
fn overview_dragged_view_end(
    view_end: f64,
    drag_x: f32,
    width: f32,
    buf_start: f64,
    buf_end: f64,
    window_secs: f64,
) -> f64 {
    let span = (buf_end - buf_start).max(f64::EPSILON);
    let moved = view_end + f64::from(drag_x) / f64::from(width.max(1.0)) * span;
    clamped_view_end(moved, buf_start, buf_end, window_secs)
}

/// The left edge never moves before the oldest sample.
///
/// While the recording is shorter than the window, that sample stays on the left
/// and new samples extend toward the right. Once it is longer, the window stays
/// inside the stored span.
fn clamped_view_end(view_end: f64, buf_start: f64, buf_end: f64, window_secs: f64) -> f64 {
    let earliest_end = buf_start + window_secs;
    if buf_end <= earliest_end {
        return earliest_end;
    }
    view_end.clamp(earliest_end, buf_end)
}

/// Min/max of each screen column, so the full buffer stays readable.
fn overview_envelope(samples: &VecDeque<MeasurementSample>, metric: Metric, columns: usize) -> Vec<[f64; 2]> {
    let len = samples.len();
    if len == 0 || columns == 0 {
        return Vec::new();
    }
    let mut points = Vec::with_capacity(columns * 2);
    for column in 0..columns {
        let start = column * len / columns;
        let end = ((column + 1) * len / columns).max(start + 1).min(len);
        let mut min_y = f64::INFINITY;
        let mut max_y = f64::NEG_INFINITY;
        let t0 = samples[start].elapsed_seconds();
        let mut t1 = t0;
        for sample in samples.range(start..end) {
            let y = metric.value(sample);
            t1 = sample.elapsed_seconds();
            if y.is_finite() {
                min_y = min_y.min(y);
                max_y = max_y.max(y);
            }
        }
        if min_y.is_finite() {
            points.push([t0, max_y]);
            if (max_y - min_y).abs() > f64::EPSILON {
                points.push([t1, min_y]);
            }
        }
    }
    points
}

fn paint_overview_curve(
    painter: &egui::Painter,
    frame: egui::Rect,
    points: &[[f64; 2]],
    buf_start: f64,
    buf_end: f64,
    color: Color32,
) {
    if points.len() < 2 {
        return;
    }
    let mut min_y = f64::INFINITY;
    let mut max_y = f64::NEG_INFINITY;
    for point in points {
        min_y = min_y.min(point[1]);
        max_y = max_y.max(point[1]);
    }
    if !min_y.is_finite() {
        return;
    }
    let span_y = (max_y - min_y).max(f64::EPSILON);
    let span_x = (buf_end - buf_start).max(f64::EPSILON);
    let plot = frame.shrink(1.0);
    let screen = points
        .iter()
        .map(|point| {
            let x = plot.left() + ((point[0] - buf_start) / span_x).clamp(0.0, 1.0) as f32 * plot.width();
            let y = plot.bottom() - ((point[1] - min_y) / span_y).clamp(0.0, 1.0) as f32 * plot.height();
            egui::pos2(x, y)
        })
        .collect();
    painter.add(egui::Shape::line(screen, egui::Stroke::new(1.0, color)));
}

/// Visible time span. `view_end` is the right edge.
fn visible_time(view_end: Option<f64>, window_secs: f64) -> Option<RangeInclusive<f64>> {
    let end = view_end?;
    Some((end - window_secs)..=end)
}

/// Dragging right pulls earlier samples into view.
fn panned_view_end(view_end: f64, drag_x: f32, pixels_per_second: f64) -> f64 {
    view_end - f64::from(drag_x) / pixels_per_second
}

/// The root UI is a background layer that covers the strips. Floating windows sit above it.
fn layer_covers_plots(order: egui::Order) -> bool {
    order != egui::Order::Background
}

/// Wheel and drag over a dialog belong to that dialog.
fn pointer_over_floating_window(ui: &egui::Ui) -> bool {
    ui.input(|input| input.pointer.hover_pos()).is_some_and(|pos| {
        ui.ctx()
            .layer_id_at(pos)
            .is_some_and(|layer| layer_covers_plots(layer.order))
    })
}

/// A press that starts on a floating window keeps blocking the strips until release.
fn pointer_blocks_plots(blocked: bool, primary_down: bool, origin_on_window: bool) -> bool {
    primary_down && (blocked || origin_on_window)
}

/// Time at a screen position, clamped to the visible window.
fn time_at_pointer(pointer_x: f32, plot_left: f32, view_end: f64, window_secs: f64, pixels_per_second: f64) -> f64 {
    let from_left = f64::from(pointer_x - plot_left) / pixels_per_second;
    clamped_cursor(view_end - window_secs + from_left, view_end, window_secs)
}

fn clamped_cursor(cursor: f64, view_end: f64, window_secs: f64) -> f64 {
    cursor.clamp(view_end - window_secs, view_end)
}

/// Keep the readout inside the strip when the cursor is near the right edge.
fn cursor_label_on_left(cursor: f64, view_end: f64, pixels_per_second: f64) -> bool {
    (view_end - cursor) * pixels_per_second < CURSOR_LABEL_MARGIN
}

/// Curve value at `time`, linearly between the surrounding samples.
fn cursor_value(samples: &VecDeque<MeasurementSample>, metric: Metric, time: f64) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    let index = samples.partition_point(|sample| sample.elapsed_seconds() < time);
    if index == 0 {
        return Some(metric.value(&samples[0]));
    }
    if index >= samples.len() {
        return samples.back().map(|sample| metric.value(sample));
    }
    let left = &samples[index - 1];
    let right = &samples[index];
    Some(interpolated_value(
        left.elapsed_seconds(),
        metric.value(left),
        right.elapsed_seconds(),
        metric.value(right),
        time,
    ))
}

fn interpolated_value(left_time: f64, left_value: f64, right_time: f64, right_value: f64, time: f64) -> f64 {
    let span = right_time - left_time;
    if span <= f64::EPSILON {
        return left_value;
    }
    let mix = ((time - left_time) / span).clamp(0.0, 1.0);
    left_value + (right_value - left_value) * mix
}

struct CursorMark {
    time: f64,
    value: Option<f64>,
    label_on_left: bool,
}

fn y_axis(unit: &'static str) -> Vec<AxisHints<'static>> {
    vec![
        AxisHints::new_y()
            .min_thickness(AXIS_THICKNESS)
            .placement(HPlacement::Left)
            .formatter(move |mark, range| format_engineering_tick(mark.value, mark.step_size, range, unit)),
    ]
}

/// Tick text in V/mV/µV, A/mA/µA, or W/mW/µW, using one scale for the whole axis.
fn format_engineering_tick(value: f64, step: f64, range: &RangeInclusive<f64>, unit: &str) -> String {
    let reference = range.start().abs().max(range.end().abs());
    let (factor, prefix) = engineering_scale(reference);
    let decimals = tick_decimals(step.abs() / factor);
    let magnitude = format_tick_magnitude(value / factor, decimals);
    format!("{magnitude} {prefix}{unit}")
}

/// Prefix that keeps the larger end of the axis in a familiar range.
fn engineering_scale(reference: f64) -> (f64, &'static str) {
    let magnitude = reference.abs();
    if !magnitude.is_finite() || magnitude == 0.0 || (1.0..1_000.0).contains(&magnitude) {
        (1.0, "")
    } else if magnitude >= 1_000.0 {
        (1_000.0, "k")
    } else if magnitude >= 1.0e-3 {
        (1.0e-3, "m")
    } else {
        (1.0e-6, "µ")
    }
}

fn tick_decimals(step: f64) -> usize {
    if !step.is_finite() || step <= 0.0 {
        return 0;
    }
    (-step.log10().floor()).clamp(0.0, 6.0) as usize
}

fn format_tick_magnitude(value: f64, decimals: usize) -> String {
    let text = format!("{value:.decimals$}");
    if text.chars().all(|ch| matches!(ch, '-' | '0' | '.')) {
        text.trim_start_matches('-').to_string()
    } else {
        text
    }
}

/// Meter pane, central-panel padding, one Y axis, and `seconds` of plot at 100 px/s.
fn window_size(seconds: f64) -> [f32; 2] {
    let plot_inner = (seconds * PIXELS_PER_SECOND) as f32;
    let width = meter_pane_width() + CENTRAL_PANEL_MARGIN * 2.0 + AXIS_THICKNESS + plot_inner;
    let height = EVENT_TOOLBAR_HEIGHT
        + OVERVIEW_HEIGHT
        + EVENT_LANE_GAP
        + EVENT_LANE_HEIGHT
        + EVENT_LANE_GAP
        + STRIP_HEIGHT * 3.0
        + STRIP_GAP_BETWEEN * 2.0
        + CENTRAL_PANEL_MARGIN * 2.0;
    [width, height]
}

fn initial_window_size() -> [f32; 2] {
    window_size(INITIAL_SECONDS)
}

fn minimum_window_size() -> [f32; 2] {
    window_size(MIN_SECONDS)
}

/// Scrolling up increases pixels per second. The result stays inside the zoom limits.
fn zoomed_pixels_per_second(current: f64, scroll_y: f32) -> f64 {
    let factor = (-f64::from(scroll_y) * SCROLL_ZOOM_SPEED).exp();
    (current * factor).clamp(MIN_PIXELS_PER_SECOND, MAX_PIXELS_PER_SECOND)
}

/// Move the right edge so `pointer_x` still marks the same time at `next_scale`.
fn zoomed_view_end_at_pointer(
    pointer_x: f32,
    plot_left: f32,
    plot_width: f64,
    view_end: f64,
    window_secs: f64,
    pixels_per_second: f64,
    next_scale: f64,
) -> f64 {
    let anchor = time_at_pointer(pointer_x, plot_left, view_end, window_secs, pixels_per_second);
    let fraction = (f64::from(pointer_x - plot_left) / plot_width).clamp(0.0, 1.0);
    let next_window = plot_width / next_scale;
    anchor + next_window * (1.0 - fraction)
}

fn rate_label(rate: GraphSampleRate) -> &'static str {
    match rate {
        GraphSampleRate::Sps2 => "2 / s",
        GraphSampleRate::Sps10 => "10 / s",
        GraphSampleRate::Sps50 => "50 / s",
        GraphSampleRate::Sps1000 => "1000 / s",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AXIS_THICKNESS, CENTRAL_PANEL_MARGIN, EVENT_LANE_GAP, EVENT_LANE_HEIGHT, EVENT_TOOLBAR_HEIGHT, GraphSampleRate,
        MAX_PIXELS_PER_SECOND, MAX_SAMPLES, MIN_PIXELS_PER_SECOND, MIN_VOLTAGE_SPAN, MIN_Y_SPAN, MeterAverage,
        OVERVIEW_HEIGHT, PIXELS_PER_SECOND, STRIP_GAP_BETWEEN, STRIP_HEIGHT, TimelineCategory, TimelineMarkerSpec,
        Y_MARGIN_FRACTION, axis_fraction_digits, buffer_fraction, buffer_meter_label, centered_view_end,
        clamped_cursor, clamped_view_end, clock_grid_steps, cursor_label_on_left, cursor_value, explorer_viewport_size,
        fitted_cursor_font_size, format_axis_time, format_engineering_tick, format_event_time, format_max_power,
        format_measurement, format_temperature, host_time_grid_marks, host_time_utc, identity_label,
        initial_window_size, layer_covers_plots, meter_pane_width, minimum_window_size, overview_centered_view_end,
        overview_dragged_view_end, overview_time_at_x, overview_window_fraction, panned_view_end, pd_timeline_marker,
        pd_timeline_time, pointer_blocks_plots, protocol_label, samples_per_meter_update, scaled_y_range, series,
        time_at_pointer, timeline_origin_utc, trim_to_max_samples, usb_vendor_name, visible_sample_range,
        zoomed_pixels_per_second, zoomed_view_end_at_pointer,
    };
    use km003c_lib::MeasurementSample;
    use km003c_lib::Metric;
    use km003c_lib::PdIdentity;
    use km003c_lib::PdLogCategory;
    use km003c_lib::PdLogEntry;
    use km003c_lib::PdRevision;
    use std::collections::VecDeque;

    #[test]
    fn meter_decimals_share_one_column() {
        let samples = [
            (Some(19.714), "V", " 19.714000 V"),
            (Some(-3.149), "A", "- 3.149000 A"),
            (Some(0.00123), "W", "  0.001230 W"),
            (Some(-62.074), "W", "-62.074000 W"),
            (None, "V", "           V"),
        ];
        for (value, unit, expected) in samples {
            let text = format_measurement(value, unit);
            assert_eq!(text, expected);
            assert_eq!(text.find('.'), expected.find('.'));
            assert_eq!(text.chars().count(), 12);
        }
    }

    #[test]
    fn secondary_telemetry_has_compact_labels() {
        assert_eq!(format_temperature(Some(30.6)), "31°C");
        assert_eq!(format_temperature(Some(-255.6)), "-256°C");
        assert_eq!(format_temperature(None), "-");
        assert_eq!(protocol_label(Some(PdRevision::Revision3)), "PD3.0");
        assert_eq!(protocol_label(None), "-");
        assert_eq!(format_max_power(Some(20.0)), "20W");
        assert_eq!(format_max_power(Some(523.0)), "523W");
        assert_eq!(format_max_power(None), "-");
        assert_eq!(usb_vendor_name(0x413c), Some("Dell Computer Corp."));
        assert_eq!(usb_vendor_name(0x0000), None);
        assert_eq!(
            identity_label(PdIdentity {
                vendor_id: 0x413c,
                product_id: Some(0x1234),
                device_bcd: Some(0x0100),
            }),
            "Dell Computer Corp. (VID 413C, PID 1234)"
        );
    }

    #[test]
    fn pd_milestones_map_to_timeline_markers() {
        let entry = |category, title: &str| PdLogEntry {
            timestamp_seconds: 0.0,
            category,
            sop: Some(0),
            title: title.to_string(),
            header: None,
            details: Vec::new(),
        };

        assert_eq!(
            pd_timeline_marker(&entry(PdLogCategory::Connect, "Connect")),
            Some(TimelineMarkerSpec {
                category: TimelineCategory::Connectivity,
                label: "ATT",
                name: "Attached",
            })
        );
        assert_eq!(
            pd_timeline_marker(&entry(PdLogCategory::SourceCaps, "Source_Capabilities")),
            Some(TimelineMarkerSpec {
                category: TimelineCategory::Protocol,
                label: "NEG",
                name: "Negotiation",
            })
        );
        assert_eq!(
            pd_timeline_marker(&entry(PdLogCategory::Control, "Reject")),
            Some(TimelineMarkerSpec {
                category: TimelineCategory::Warning,
                label: "REJ",
                name: "Request rejected",
            })
        );
        assert_eq!(pd_timeline_marker(&entry(PdLogCategory::Control, "GoodCRC")), None);
        assert!((pd_timeline_time(105.25, 106.0, 12.0, false) - 11.25).abs() < 1e-9);
        // Connection event timestamps are 24-bit milliseconds and wrap every
        // 16,777.216 seconds, unlike the wider PD status timestamp.
        assert!((pd_timeline_time(2.5, 16_780.0, 12.0, true) - 11.716).abs() < 1e-9);
        assert_eq!(format_event_time(None, 11.25), "+11.250s");
        assert_eq!(centered_view_end(11.25, 8.0), 15.25);
    }

    #[test]
    fn host_time_axis_uses_adaptive_precision() {
        assert_eq!(clock_grid_steps(0.001), [0.01, 0.1, 1.0]);
        assert_eq!(clock_grid_steps(0.05), [0.1, 1.0, 10.0]);
        assert_eq!(axis_fraction_digits(1.0), 0);
        assert_eq!(axis_fraction_digits(0.1), 1);
        assert_eq!(axis_fraction_digits(0.01), 2);

        let observed = chrono::DateTime::parse_from_rfc3339("2026-10-22T18:46:59.843Z")
            .unwrap()
            .to_utc();
        let origin = timeline_origin_utc(observed, 0.0);
        assert_eq!(host_time_utc(&origin, 0.0), observed);
        assert!(format_event_time(Some(&origin), 0.0).ends_with("59.843"));

        let marks = host_time_grid_marks(
            Some(&origin),
            egui_plot::GridInput {
                bounds: (0.0, 1.2),
                base_step_size: 0.05,
            },
        );
        let tenth = marks.iter().find(|mark| mark.step_size == 0.1).unwrap();
        let whole = marks.iter().find(|mark| mark.step_size == 1.0).unwrap();
        assert!(format_axis_time(Some(&origin), tenth.value, tenth.step_size, &(0.0..=1.2)).ends_with("59.9"));
        let whole_label = format_axis_time(Some(&origin), whole.value, whole.step_size, &(0.0..=1.2));
        let origin_seconds = origin.timestamp() as f64 + f64::from(origin.timestamp_subsec_nanos()) / 1_000_000_000.0;
        let absolute_seconds = origin_seconds + whole.value;
        assert!((absolute_seconds - absolute_seconds.round()).abs() < 1e-6);
        assert!(!whole_label.contains('.'), "{whole_label:?}");

        let fine_marks = host_time_grid_marks(
            Some(&origin),
            egui_plot::GridInput {
                bounds: (0.0, 0.05),
                base_step_size: 0.005,
            },
        );
        let hundredth = fine_marks.iter().find(|mark| mark.step_size == 0.01).unwrap();
        assert!(
            format_axis_time(Some(&origin), hundredth.value, hundredth.step_size, &(0.0..=0.05)).ends_with("59.85")
        );
    }

    #[test]
    fn meter_updates_twice_per_second() {
        assert_eq!(samples_per_meter_update(GraphSampleRate::Sps2), 1);
        assert_eq!(samples_per_meter_update(GraphSampleRate::Sps10), 5);
        assert_eq!(samples_per_meter_update(GraphSampleRate::Sps50), 25);
        assert_eq!(samples_per_meter_update(GraphSampleRate::Sps1000), 500);

        let mut meter = MeterAverage::default();
        assert!(meter.push(GraphSampleRate::Sps2, 1.0, 2.0, 3.0, 4.0, 5.0).is_some());

        let mut meter = MeterAverage::default();
        for sample in 0..4 {
            assert!(
                meter
                    .push(
                        GraphSampleRate::Sps10,
                        f64::from(sample),
                        0.0,
                        0.0,
                        f64::from(sample) * 2.0,
                        f64::from(sample) * 3.0,
                    )
                    .is_none()
            );
        }
        let reading = meter.push(GraphSampleRate::Sps10, 4.0, 0.0, 0.0, 8.0, 12.0).unwrap();
        assert!((reading.voltage - 2.0).abs() < 1e-9);
        assert!((reading.cc1 - 4.0).abs() < 1e-9);
        assert!((reading.cc2 - 6.0).abs() < 1e-9);

        assert!(meter.push(GraphSampleRate::Sps50, 10.0, 0.0, 0.0, 0.0, 0.0).is_none());
    }

    #[test]
    fn default_window_shows_eight_seconds_at_100_pixels_per_second() {
        let [width, height] = initial_window_size();
        let plot_inner = width - meter_pane_width() - CENTRAL_PANEL_MARGIN * 2.0 - AXIS_THICKNESS;
        assert_eq!(plot_inner, 800.0);
        assert_eq!(
            height,
            EVENT_TOOLBAR_HEIGHT
                + OVERVIEW_HEIGHT
                + EVENT_LANE_GAP
                + EVENT_LANE_HEIGHT
                + EVENT_LANE_GAP
                + STRIP_HEIGHT * 3.0
                + STRIP_GAP_BETWEEN * 2.0
                + CENTRAL_PANEL_MARGIN * 2.0
        );

        let [min_width, min_height] = minimum_window_size();
        let min_plot = min_width - meter_pane_width() - CENTRAL_PANEL_MARGIN * 2.0 - AXIS_THICKNESS;
        assert_eq!(min_plot, 400.0);
        assert_eq!(min_height, height);

        let original = eframe::egui::vec2(width, height);
        let expanded = explorer_viewport_size(original, true);
        assert_eq!(explorer_viewport_size(expanded, false), original);
    }

    #[test]
    fn mouse_wheel_changes_pixels_per_second_for_the_whole_scope() {
        let zoomed_in = zoomed_pixels_per_second(PIXELS_PER_SECOND, -100.0);
        let zoomed_out = zoomed_pixels_per_second(PIXELS_PER_SECOND, 100.0);
        assert!(zoomed_in > PIXELS_PER_SECOND);
        assert!(zoomed_out < PIXELS_PER_SECOND);
        assert_eq!(
            zoomed_pixels_per_second(MAX_PIXELS_PER_SECOND, -1_000.0),
            MAX_PIXELS_PER_SECOND
        );
        assert_eq!(
            zoomed_pixels_per_second(MIN_PIXELS_PER_SECOND, 1_000.0),
            MIN_PIXELS_PER_SECOND
        );
    }

    #[test]
    fn zoom_without_autoscroll_keeps_the_time_under_the_pointer() {
        let pointer_x = 500.0;
        let plot_left = 100.0;
        let plot_width = 800.0;
        let view_end = 10.0;
        let pixels_per_second = 100.0;
        let window_secs = plot_width / pixels_per_second;
        let anchor = time_at_pointer(pointer_x, plot_left, view_end, window_secs, pixels_per_second);
        assert!((anchor - 6.0).abs() < 1e-9);

        let next_scale = 200.0;
        let next_end = zoomed_view_end_at_pointer(
            pointer_x,
            plot_left,
            plot_width,
            view_end,
            window_secs,
            pixels_per_second,
            next_scale,
        );
        let next_window = plot_width / next_scale;
        let still_there = time_at_pointer(pointer_x, plot_left, next_end, next_window, next_scale);
        assert!((still_there - anchor).abs() < 1e-9);

        let on_the_right = plot_left + plot_width as f32;
        let right_end = zoomed_view_end_at_pointer(
            on_the_right,
            plot_left,
            plot_width,
            view_end,
            window_secs,
            pixels_per_second,
            next_scale,
        );
        assert!((right_end - view_end).abs() < 1e-9);
    }

    #[test]
    fn cursor_readout_shrinks_to_fit_between_the_plots() {
        let room = STRIP_GAP_BETWEEN - 2.0;
        assert!((fitted_cursor_font_size(16.0, 20.0, room) - 16.0 * room / 20.0).abs() < 1e-5);
        assert_eq!(fitted_cursor_font_size(16.0, 10.0, room), 16.0);
    }

    #[test]
    fn y_axis_does_not_zoom_tighter_than_its_minimum() {
        let voltage = scaled_y_range(5.0, 5.0, MIN_VOLTAGE_SPAN);
        assert!((voltage.end() - voltage.start() - MIN_VOLTAGE_SPAN).abs() < 1e-12);
        assert!(((voltage.start() + voltage.end()) / 2.0 - 5.0).abs() < 1e-12);

        let current = scaled_y_range(1.0, 1.0, MIN_Y_SPAN);
        assert!((current.end() - current.start() - MIN_Y_SPAN).abs() < 1e-12);

        let wide = scaled_y_range(0.0, 10.0, MIN_VOLTAGE_SPAN);
        let pad = 10.0 * Y_MARGIN_FRACTION;
        assert!((wide.start() - (0.0 - pad)).abs() < 1e-9);
        assert!((wide.end() - (10.0 + pad)).abs() < 1e-9);
    }

    #[test]
    fn y_ticks_use_engineering_units() {
        assert_eq!(format_engineering_tick(5.0, 1.0, &(0.0..=20.0), "V"), "5 V");
        assert_eq!(format_engineering_tick(0.008, 0.002, &(0.0..=0.008), "V"), "8 mV");
        assert_eq!(format_engineering_tick(5.002, 0.002, &(4.996..=5.004), "V"), "5.002 V");
        assert_eq!(format_engineering_tick(0.02, 0.005, &(0.0..=0.02), "A"), "20 mA");
        assert_eq!(format_engineering_tick(-0.01, 0.005, &(-0.02..=0.0), "A"), "-10 mA");
        assert_eq!(format_engineering_tick(0.0005, 0.0001, &(0.0..=0.0005), "A"), "500 µA");
        assert_eq!(format_engineering_tick(1_500.0, 500.0, &(0.0..=2_000.0), "W"), "1.5 kW");
        assert_eq!(format_engineering_tick(0.0, 0.002, &(0.0..=0.008), "V"), "0 mV");
        assert_eq!(
            format_engineering_tick(-1.0e-12, 0.002, &(4.996..=5.004), "V"),
            "0.000 V"
        );
    }

    #[test]
    fn dragging_the_device_info_window_does_not_pan_the_strips() {
        assert!(pointer_blocks_plots(false, true, true));
        assert!(pointer_blocks_plots(true, true, false));
        assert!(!pointer_blocks_plots(true, false, true));
        assert!(!pointer_blocks_plots(false, true, false));
        assert!(!layer_covers_plots(eframe::egui::Order::Background));
        assert!(layer_covers_plots(eframe::egui::Order::Middle));
    }

    #[test]
    fn dragging_moves_all_strips_along_time() {
        assert_eq!(panned_view_end(10.0, 100.0, 100.0), 9.0);
        assert_eq!(panned_view_end(10.0, -50.0, 100.0), 10.5);
        assert_eq!(
            clamped_view_end(panned_view_end(8.0, 200.0, 100.0), 0.0, 30.0, 8.0),
            8.0
        );
        assert_eq!(clamped_view_end(2.0, 0.0, 2.0, 8.0), 8.0);
        assert_eq!(clamped_view_end(20.0, 0.0, 20.0, 8.0), 20.0);
        assert_eq!(clamped_view_end(1.5, 1.0, 1.5, 8.0), 9.0);
    }

    #[test]
    fn cursor_follows_the_pointer_in_time() {
        assert_eq!(time_at_pointer(100.0, 100.0, 8.0, 8.0, 100.0), 0.0);
        assert_eq!(time_at_pointer(250.0, 100.0, 8.0, 8.0, 100.0), 1.5);
        assert_eq!(time_at_pointer(900.0, 100.0, 8.0, 8.0, 100.0), 8.0);
        assert_eq!(time_at_pointer(40.0, 100.0, 8.0, 8.0, 100.0), 0.0);
        assert_eq!(time_at_pointer(2_000.0, 100.0, 8.0, 8.0, 100.0), 8.0);
        assert_eq!(clamped_cursor(9.5, 8.0, 4.0), 8.0);
        assert_eq!(clamped_cursor(1.0, 8.0, 4.0), 4.0);
        assert!(cursor_label_on_left(7.5, 8.0, 100.0));
        assert!(!cursor_label_on_left(4.0, 8.0, 100.0));
    }

    #[test]
    fn cursor_reads_the_curve_at_its_time() {
        let samples = VecDeque::from([
            voltage_sample(0, 10.0),
            voltage_sample(1_000_000, 20.0),
            voltage_sample(2_000_000, 0.0),
        ]);
        let at = |time| cursor_value(&samples, Metric::Voltage, time).unwrap();
        assert!((at(0.5) - 15.0).abs() < 1e-9);
        assert!((at(-1.0) - 10.0).abs() < 1e-9);
        assert!((at(3.0) - 0.0).abs() < 1e-9);
        assert!(cursor_value(&VecDeque::new(), Metric::Voltage, 1.0).is_none());
    }

    #[test]
    fn history_keeps_the_newest_fixed_sample_count() {
        assert_eq!(MAX_SAMPLES, 1_800_000);
        let mut samples = (0..5)
            .map(|second| voltage_sample(second * 1_000_000, second as f64))
            .collect::<VecDeque<_>>();
        trim_to_max_samples(&mut samples, 3);
        assert_eq!(samples.len(), 3);
        assert_eq!(samples.front().unwrap().elapsed_us, 2_000_000);
        assert_eq!(samples.back().unwrap().elapsed_us, 4_000_000);
        assert_eq!(buffer_fraction(0, MAX_SAMPLES), 0.0);
        assert!((buffer_fraction(MAX_SAMPLES / 2, MAX_SAMPLES) - 0.5).abs() < 1e-6);
        assert_eq!(buffer_fraction(MAX_SAMPLES, MAX_SAMPLES), 1.0);
        assert_eq!(buffer_meter_label(22_374, MAX_SAMPLES, 50.0), "1.243% (9h 52m 33s)");
        assert_eq!(buffer_meter_label(0, MAX_SAMPLES, 50.0), "0.000% (10h 0m 0s)");
        assert_eq!(buffer_meter_label(MAX_SAMPLES, MAX_SAMPLES, 50.0), "100.000% (0s)");
    }

    #[test]
    fn overview_box_tracks_the_visible_window() {
        let (left, right) = overview_window_fraction(40.0, 50.0, 0.0, 100.0);
        assert!((left - 0.4).abs() < 1e-9);
        assert!((right - 0.5).abs() < 1e-9);
        let (zoomed_out_left, zoomed_out_right) = overview_window_fraction(30.0, 50.0, 0.0, 100.0);
        assert!((zoomed_out_right - zoomed_out_left) > (right - left));
        assert!((overview_dragged_view_end(50.0, 10.0, 100.0, 0.0, 100.0, 10.0) - 60.0).abs() < 1e-9);
        assert!((overview_dragged_view_end(98.0, 10.0, 100.0, 0.0, 100.0, 10.0) - 100.0).abs() < 1e-9);
        assert!((overview_time_at_x(80.0, 0.0, 100.0, 0.0, 100.0) - 80.0).abs() < 1e-9);
        assert!((overview_centered_view_end(80.0, 0.0, 100.0, 10.0) - 85.0).abs() < 1e-9);
        assert!((overview_centered_view_end(2.0, 0.0, 100.0, 10.0) - 10.0).abs() < 1e-9);
        assert!((overview_centered_view_end(98.0, 0.0, 100.0, 10.0) - 100.0).abs() < 1e-9);
    }

    #[test]
    fn plots_only_copy_the_visible_sample_range() {
        let samples = (0..10)
            .map(|second| voltage_sample(second * 1_000_000, second as f64))
            .collect::<VecDeque<_>>();

        let range = visible_sample_range(&samples, 3.0, 6.0);
        assert_eq!(range, 3..7);
        assert_eq!(
            series(&samples, Metric::Voltage, range),
            vec![[3.0, 3.0], [4.0, 4.0], [5.0, 5.0], [6.0, 6.0]]
        );
    }

    fn voltage_sample(elapsed_us: u64, volts: f64) -> MeasurementSample {
        MeasurementSample {
            elapsed_us,
            sample_index: 0,
            sequence: 0,
            marker: 0,
            sample_rate_hz: 0,
            missing_samples: 0,
            gap_duration_us: 0,
            interpolated: false,
            cumulative_missing_samples: 0,
            cumulative_interpolated_duration_us: 0,
            discarded_sequence_samples: 0,
            cumulative_discarded_sequence_samples: 0,
            vbus_uv: (volts * 1_000_000.0) as i64,
            ibus_ua: 0,
            power_uw: 0,
            charge_uah: 0.0,
            energy_uwh: 0.0,
            charge_throughput_uah: 0.0,
            energy_throughput_uwh: 0.0,
            cc1_uv: 0,
            cc2_uv: 0,
            dp_uv: 0,
            dm_uv: 0,
        }
    }
}
