//! A small time-domain scope for the KM003C.
//!
//! The left side is split in half: live voltage, current, and power on top,
//! and the connection controls below. The center is three separate 200-pixel
//! strips — voltage, current, and power — at 100 pixels per second.

use std::collections::VecDeque;
use std::ops::RangeInclusive;
use std::time::Duration;

use eframe::egui;
use eframe::egui::Color32;
use eframe::egui::RichText;
use egui_plot::AxisHints;
use egui_plot::HPlacement;
use egui_plot::Line;
use egui_plot::Plot;
use egui_plot::PlotPoints;
use km003c_lib::DeviceState;
use km003c_lib::GraphSampleRate;
use km003c_lib::MeasurementAccumulator;
use km003c_lib::MeasurementSample;
use km003c_lib::Metric;
use km003c_lib::Session;
use km003c_lib::SessionEvent;
use km003c_lib::uom::si::frequency::hertz;
use tokio::sync::mpsc;
use tracing::info;

const VOLTAGE_COLOR: Color32 = Color32::from_rgb(80, 220, 120);
const CURRENT_COLOR: Color32 = Color32::from_rgb(90, 170, 255);
const POWER_COLOR: Color32 = Color32::from_rgb(255, 176, 64);
const AXIS_THICKNESS: f32 = 100.0;
const PIXELS_PER_SECOND: f64 = 100.0;
const MIN_PIXELS_PER_SECOND: f64 = 10.0;
const MAX_PIXELS_PER_SECOND: f64 = 1_000.0;
/// How strongly one point of wheel travel changes the time scale.
const SCROLL_ZOOM_SPEED: f64 = 0.002;
/// Pixels of clear space between the cursor line and its readout.
const CURSOR_LABEL_GAP: f64 = 6.0;
/// Flip the readout to the left of the line when fewer pixels remain on the right.
const CURSOR_LABEL_MARGIN: f64 = 110.0;
const CURSOR_LABEL_SIZE: f32 = 16.0;
const INITIAL_SECONDS: f64 = 8.0;
const MIN_SECONDS: f64 = 4.0;
const STRIP_HEIGHT: f32 = 200.0;
/// Gap between the voltage, current, and power strips.
const STRIP_GAP: f32 = 16.0;
/// Horizontal and vertical inset of egui's central panel frame.
const CENTRAL_PANEL_MARGIN: f32 = 8.0;
/// Space Mono's advance width, in font units per em.
const SPACE_MONO_ADVANCE_EM: f32 = 612.0 / 1000.0;
const METER_VALUE_FONT_SIZE: f32 = 28.0;
/// Horizontal inset of egui's side-panel frame, on each side.
const SIDE_PANEL_INNER_MARGIN: f32 = 8.0;
/// Padding inside the black meter box, on each side.
const METER_BOX_MARGIN: f32 = 8.0;
/// Room egui reserves for the side panel's separator stroke.
const SIDE_PANEL_SEPARATOR: f32 = 1.0;
/// Samples kept so a wider window can reveal history that has already scrolled off.
const RETAIN_SECS: f64 = 180.0;
const RATES: [GraphSampleRate; 4] = [
    GraphSampleRate::Sps2,
    GraphSampleRate::Sps10,
    GraphSampleRate::Sps50,
    GraphSampleRate::Sps1000,
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    info!("Starting KM003C scope");

    let (session, events) = Session::spawn();
    let rate = GraphSampleRate::Sps50;
    // A USB reset re-enumerates the meter. macOS handles that badly, so leave
    // it off unless the user asks.
    let usb_reset = !cfg!(target_os = "macos");
    let _ = session.connect(rate, usb_reset);

    let app = ScopeApp {
        session,
        events,
        accumulator: MeasurementAccumulator::default(),
        samples: VecDeque::new(),
        meter: MeterAverage::default(),
        voltage: None,
        current: None,
        power: None,
        status: "Connecting...".to_string(),
        device: None,
        device_info_open: false,
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
    meter: MeterAverage,
    voltage: Option<f64>,
    current: Option<f64>,
    power: Option<f64>,
    status: String,
    device: Option<DeviceState>,
    device_info_open: bool,
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
    /// The current press started on a floating window, so it must not pan the strips.
    window_has_pointer: bool,
    usb_reset: bool,
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
        egui::CentralPanel::default().show(ui, |ui| self.scope(ui));
        self.device_info_dialog(ui.ctx());
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
                    self.status = "Connected".to_string();
                }
                SessionEvent::ConnectionFailed { error, .. } => {
                    self.mark_disconnected();
                    self.status = format!("Connection failed: {error}");
                }
                SessionEvent::Samples(samples) => {
                    let rate = self.rate;
                    for sample in samples {
                        let Some(measurement) = self.accumulator.push(sample, rate) else {
                            continue;
                        };
                        self.samples.push_back(measurement);
                        if let Some((voltage, current, power)) = self.meter.push(
                            rate,
                            Metric::Voltage.value(&measurement),
                            Metric::SignedCurrent.value(&measurement),
                            Metric::SignedPower.value(&measurement),
                        ) {
                            self.voltage = Some(voltage);
                            self.current = Some(current);
                            self.power = Some(power);
                        }
                    }
                    self.trim_window();
                }
                SessionEvent::StreamingStarted(rate) => {
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
                SessionEvent::PdEvents(_)
                | SessionEvent::PdStatusUpdate(_)
                | SessionEvent::PdTrace(_)
                | SessionEvent::OfflineCatalog(_)
                | SessionEvent::OfflineLogDownloaded(_)
                | SessionEvent::OfflineOperationFailed(_) => {}
                _ => {}
            }
        }
    }

    fn mark_disconnected(&mut self) {
        self.connected = false;
        self.streaming = false;
        self.device = None;
        self.device_info_open = false;
        self.voltage = None;
        self.current = None;
        self.power = None;
        self.samples.clear();
        self.accumulator = MeasurementAccumulator::default();
        self.meter.reset();
    }

    fn trim_window(&mut self) {
        let Some(latest) = self.samples.back().map(|sample| sample.elapsed_seconds()) else {
            return;
        };
        let oldest = latest - self.window_secs.max(RETAIN_SECS);
        while self
            .samples
            .front()
            .is_some_and(|sample| sample.elapsed_seconds() < oldest)
        {
            self.samples.pop_front();
        }
    }

    fn side(&mut self, ui: &mut egui::Ui) {
        let meter_height = ui.available_height() * 0.5;
        let width = ui.available_width();
        ui.allocate_ui(egui::vec2(width, meter_height), |ui| self.readings(ui));
        ui.add_space(8.0);
        egui::ScrollArea::vertical()
            .id_salt("controls")
            .show(ui, |ui| self.controls(ui));
    }

    fn controls(&mut self, ui: &mut egui::Ui) {
        ui.label(self.status.as_str());
        ui.add_space(8.0);
        ui.checkbox(&mut self.usb_reset, "USB reset on connect")
            .on_hover_text("Applied the next time Connect runs. Leave this off on macOS.");
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
        if ui
            .add_enabled(self.device.is_some(), egui::Button::new("Device Info"))
            .clicked()
        {
            self.device_info_open = true;
        }

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

    fn device_info_dialog(&mut self, ctx: &egui::Context) {
        if self.device.is_none() {
            self.device_info_open = false;
            return;
        }
        let Some(device) = self.device.clone() else {
            return;
        };
        egui::Window::new("Device Info")
            .open(&mut self.device_info_open)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
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
            });
    }

    fn scope(&mut self, ui: &mut egui::Ui) {
        self.zoom_time_scale(ui);
        self.follow_plot_width();
        let dragging = self.place_time_window(ui);
        ui.spacing_mut().item_spacing.y = STRIP_GAP;
        let width = ui.available_width();
        let link = ui.id().with("scope_time");
        let time = visible_time(self.view_end, self.window_secs);
        let strips = [
            Strip::new("scope_voltage", Metric::Voltage, VOLTAGE_COLOR, "V", false),
            Strip::new("scope_current", Metric::SignedCurrent, CURRENT_COLOR, "A", false),
            Strip::new("scope_power", Metric::SignedPower, POWER_COLOR, "W", true),
        ];
        let mut plot_width = None;
        let mut plot_left = None;
        for strip in strips {
            let points = match self.view_end {
                Some(end) => series(&self.samples, strip.metric, end, self.window_secs),
                None => Vec::new(),
            };
            ui.allocate_ui(egui::vec2(width, STRIP_HEIGHT), |ui| {
                let cursor = self.cursor_mark(strip.metric);
                let frame = trace_plot(ui, &strip, &points, link, time.clone(), cursor, self.cursor_mode);
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
    /// Scrolling up shows less time. Autoscroll keeps the newest sample on the
    /// right edge. Otherwise the time under the pointer stays where it is.
    fn zoom_time_scale(&mut self, ui: &egui::Ui) {
        let rect = ui.available_rect_before_wrap();
        if !ui.rect_contains_pointer(rect) {
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
    /// With Autoscroll on, the right edge stays on the newest sample.
    fn place_time_window(&mut self, ui: &egui::Ui) -> bool {
        let rect = ui.available_rect_before_wrap();
        let (primary_down, delta_x, origin, pointer_x) = ui.input(|input| {
            (
                input.pointer.primary_down(),
                input.pointer.delta().x,
                input.pointer.press_origin(),
                input.pointer.latest_pos().map(|pos| pos.x),
            )
        });
        let drag_started_on_plots = origin.is_some_and(|origin| rect.contains(origin));
        let origin_on_window = origin.is_some_and(|pos| {
            ui.ctx()
                .layer_id_at(pos)
                .is_some_and(|layer| layer_covers_plots(layer.order))
        });
        self.window_has_pointer = pointer_blocks_plots(self.window_has_pointer, primary_down, origin_on_window);
        let interacting_with_plots = drag_started_on_plots && !self.window_has_pointer;
        let placing_cursor = self.cursor_mode && primary_down && interacting_with_plots;
        let panning = primary_down && interacting_with_plots && delta_x != 0.0 && !self.cursor_mode;
        if self.autoscroll
            && !panning
            && let Some(latest) = self.samples.back()
        {
            self.view_end = Some(latest.elapsed_seconds());
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
}

impl MeterAverage {
    fn reset(&mut self) {
        *self = Self::default();
    }

    /// Average the next half-second of samples. Returns the mean once the window is full.
    fn push(&mut self, rate: GraphSampleRate, voltage: f64, current: f64, power: f64) -> Option<(f64, f64, f64)> {
        if self.rate != Some(rate) {
            self.rate = Some(rate);
            self.count = 0;
            self.voltage = 0.0;
            self.current = 0.0;
            self.power = 0.0;
        }
        self.voltage += voltage;
        self.current += current;
        self.power += power;
        self.count += 1;
        if self.count < samples_per_meter_update(rate) {
            return None;
        }
        let count = f64::from(self.count);
        let averaged = (self.voltage / count, self.current / count, self.power / count);
        self.count = 0;
        self.voltage = 0.0;
        self.current = 0.0;
        self.power = 0.0;
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

fn series(samples: &VecDeque<MeasurementSample>, metric: Metric, view_end: f64, window_secs: f64) -> Vec<[f64; 2]> {
    let oldest = view_end - window_secs;
    samples
        .iter()
        .filter(|sample| {
            let elapsed = sample.elapsed_seconds();
            elapsed >= oldest && elapsed <= view_end
        })
        .map(|sample| [sample.elapsed_seconds(), metric.value(sample)])
        .collect()
}

/// Draw one 200-pixel strip. The three strips share the time axis.
fn trace_plot(
    ui: &mut egui::Ui,
    strip: &Strip,
    points: &[[f64; 2]],
    link: egui::Id,
    time: Option<RangeInclusive<f64>>,
    cursor: Option<CursorMark>,
    hide_pointer_lines: bool,
) -> egui::Rect {
    let width = ui.available_width();
    let mut plot = Plot::new(strip.id)
        .width(width)
        .height(STRIP_HEIGHT)
        .show_grid(true)
        .custom_y_axes(y_axis())
        .show_axes([strip.show_time, true])
        .link_axis(link, [true, false])
        .link_cursor(link, [true, false])
        .auto_bounds([false, true])
        .allow_zoom(false)
        .allow_drag(false)
        .allow_scroll(false)
        .allow_axis_zoom_drag(false)
        .allow_boxed_zoom(false)
        .set_margin_fraction(egui::vec2(0.0, 0.08));
    if hide_pointer_lines {
        plot = plot.cursor_color(Color32::TRANSPARENT);
    }
    if strip.show_time {
        plot = plot.x_axis_label("Time (s)");
    }
    let drawn = plot.show(ui, |plot_ui| {
        plot_ui.set_auto_bounds([false, true]);
        if let Some(time) = time {
            plot_ui.set_plot_bounds_x(time);
        }
        plot_ui.line(
            Line::new(strip.id, PlotPoints::new(points.to_vec()))
                .color(strip.color)
                .width(1.8),
        );
        if let Some(cursor) = &cursor {
            plot_ui.vline(
                egui_plot::VLine::new(format!("{}-cursor", strip.id), cursor.time)
                    .color(strip.color)
                    .width(1.5)
                    .allow_hover(false),
            );
        }
    });
    paint_upright_unit(ui, strip, *drawn.transform.frame());
    if let Some(cursor) = &cursor {
        paint_cursor_value(ui, strip, cursor, &drawn.transform);
    }
    *drawn.transform.frame()
}

/// Bold readout at the top of the strip, beside the cursor line.
fn paint_cursor_value(ui: &egui::Ui, strip: &Strip, cursor: &CursorMark, transform: &egui_plot::PlotTransform) {
    let Some(value) = cursor.value else {
        return;
    };
    let galley = ui.painter().layout_no_wrap(
        format!("{value:.3} {}", strip.unit),
        egui::FontId::new(CURSOR_LABEL_SIZE, egui::FontFamily::Name("Space Mono Bold".into())),
        strip.color,
    );
    let x = transform.position_from_point_x(cursor.time);
    let text_x = if cursor.label_on_left {
        x - CURSOR_LABEL_GAP as f32 - galley.size().x
    } else {
        x + CURSOR_LABEL_GAP as f32
    };
    let pos = egui::pos2(text_x, transform.frame().top() + 4.0);
    ui.painter().galley(pos, galley, strip.color);
}

/// Upright unit at the left of the strip. The plot's own axis title is rotated.
fn paint_upright_unit(ui: &egui::Ui, strip: &Strip, frame: egui::Rect) {
    let galley = ui
        .painter()
        .layout_no_wrap(strip.unit.to_owned(), egui::FontId::proportional(18.0), strip.color);
    let pos = egui::pos2(
        frame.left() - AXIS_THICKNESS + 8.0,
        frame.center().y - galley.size().y * 0.5,
    );
    ui.painter().galley(pos, galley, strip.color);
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

/// Time span ending at the newest sample. The right edge stays on that sample.
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

fn y_axis() -> Vec<AxisHints<'static>> {
    vec![
        AxisHints::new_y()
            .min_thickness(AXIS_THICKNESS)
            .placement(HPlacement::Left),
    ]
}

/// Meter pane, central-panel padding, one Y axis, and `seconds` of plot at 100 px/s.
fn window_size(seconds: f64) -> [f32; 2] {
    let plot_inner = (seconds * PIXELS_PER_SECOND) as f32;
    let width = meter_pane_width() + CENTRAL_PANEL_MARGIN * 2.0 + AXIS_THICKNESS + plot_inner;
    let height = STRIP_HEIGHT * 3.0 + STRIP_GAP * 2.0 + CENTRAL_PANEL_MARGIN * 2.0;
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
        AXIS_THICKNESS, CENTRAL_PANEL_MARGIN, GraphSampleRate, MAX_PIXELS_PER_SECOND, MIN_PIXELS_PER_SECOND,
        MeterAverage, PIXELS_PER_SECOND, clamped_cursor, cursor_label_on_left, cursor_value, format_measurement,
        initial_window_size, layer_covers_plots, meter_pane_width, minimum_window_size, panned_view_end,
        pointer_blocks_plots, samples_per_meter_update, time_at_pointer, zoomed_pixels_per_second,
        zoomed_view_end_at_pointer,
    };
    use km003c_lib::MeasurementSample;
    use km003c_lib::Metric;
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
    fn meter_updates_twice_per_second() {
        assert_eq!(samples_per_meter_update(GraphSampleRate::Sps2), 1);
        assert_eq!(samples_per_meter_update(GraphSampleRate::Sps10), 5);
        assert_eq!(samples_per_meter_update(GraphSampleRate::Sps50), 25);
        assert_eq!(samples_per_meter_update(GraphSampleRate::Sps1000), 500);

        let mut meter = MeterAverage::default();
        assert!(meter.push(GraphSampleRate::Sps2, 1.0, 2.0, 3.0).is_some());

        let mut meter = MeterAverage::default();
        for sample in 0..4 {
            assert!(
                meter
                    .push(GraphSampleRate::Sps10, f64::from(sample), 0.0, 0.0)
                    .is_none()
            );
        }
        let (voltage, _, _) = meter.push(GraphSampleRate::Sps10, 4.0, 0.0, 0.0).unwrap();
        assert!((voltage - 2.0).abs() < 1e-9);

        assert!(meter.push(GraphSampleRate::Sps50, 10.0, 0.0, 0.0).is_none());
    }

    #[test]
    fn default_window_shows_eight_seconds_at_100_pixels_per_second() {
        let [width, height] = initial_window_size();
        let plot_inner = width - meter_pane_width() - CENTRAL_PANEL_MARGIN * 2.0 - AXIS_THICKNESS;
        assert_eq!(plot_inner, 800.0);
        assert_eq!(height, 648.0);

        let [min_width, min_height] = minimum_window_size();
        let min_plot = min_width - meter_pane_width() - CENTRAL_PANEL_MARGIN * 2.0 - AXIS_THICKNESS;
        assert_eq!(min_plot, 400.0);
        assert_eq!(min_height, height);
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
