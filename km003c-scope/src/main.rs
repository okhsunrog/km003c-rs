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
        model: None,
        connected: false,
        streaming: false,
        rate,
        window_secs: INITIAL_SECONDS,
        plot_width: None,
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
    model: Option<String>,
    connected: bool,
    streaming: bool,
    rate: GraphSampleRate,
    window_secs: f64,
    /// Inner plot width from the previous frame, in pixels.
    plot_width: Option<f64>,
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
                    self.model = Some(state.model().to_string());
                    self.status = format!("Connected to {}", state.model());
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
        self.model = None;
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
        ui.separator();
        egui::ScrollArea::vertical()
            .id_salt("controls")
            .show(ui, |ui| self.controls(ui));
    }

    fn controls(&mut self, ui: &mut egui::Ui) {
        ui.heading("Scope");
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
        ui.label(self.status.as_str());
        if let Some(model) = &self.model {
            ui.weak(model);
        }

        ui.separator();
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

        ui.add_space(8.0);
        ui.checkbox(&mut self.usb_reset, "USB reset on connect")
            .on_hover_text("Applied the next time Connect runs. Leave this off on macOS.");
    }

    fn readings(&self, ui: &mut egui::Ui) {
        reading(ui, self.voltage, "V", VOLTAGE_COLOR);
        reading(ui, self.current, "A", CURRENT_COLOR);
        reading(ui, self.power, "W", POWER_COLOR);
    }

    fn scope(&mut self, ui: &mut egui::Ui) {
        self.follow_plot_width();
        ui.spacing_mut().item_spacing.y = STRIP_GAP;
        let width = ui.available_width();
        let link = ui.id().with("scope_time");
        let time = visible_time(&self.samples, self.window_secs);
        let strips = [
            Strip::new("scope_voltage", Metric::Voltage, VOLTAGE_COLOR, "V", false),
            Strip::new("scope_current", Metric::SignedCurrent, CURRENT_COLOR, "A", false),
            Strip::new("scope_power", Metric::SignedPower, POWER_COLOR, "W", true),
        ];
        let mut plot_width = None;
        for strip in strips {
            let points = series(&self.samples, strip.metric, self.window_secs);
            ui.allocate_ui(egui::vec2(width, STRIP_HEIGHT), |ui| {
                let measured = trace_plot(ui, &strip, &points, link, time.clone());
                plot_width.get_or_insert(f64::from(measured));
            });
        }
        if let Some(width) = plot_width {
            self.plot_width = Some(width.max(1.0));
        }
    }

    /// Keep 100 pixels per second. A wider plot then covers more time.
    fn follow_plot_width(&mut self) {
        let Some(plot_width) = self.plot_width else {
            return;
        };
        self.window_secs = plot_width / PIXELS_PER_SECOND;
    }
}

fn reading(ui: &mut egui::Ui, value: Option<f64>, unit: &str, color: Color32) {
    ui.add(
        egui::Label::new(meter_text(format_measurement(value, unit), METER_VALUE_FONT_SIZE).color(color))
            .wrap_mode(egui::TextWrapMode::Extend),
    );
    ui.add_space(16.0);
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

/// Outer width of the left pane: one meter line, plus the panel frame.
fn meter_pane_width() -> f32 {
    let columns = format_measurement(Some(-99.99999), "W").chars().count() as f32;
    let text = columns * SPACE_MONO_ADVANCE_EM * METER_VALUE_FONT_SIZE;
    (text + SIDE_PANEL_INNER_MARGIN * 2.0 + SIDE_PANEL_SEPARATOR).ceil()
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
    let mut family = vec!["Space Mono".to_owned()];
    if let Some(fallbacks) = fonts.families.get(&egui::FontFamily::Proportional) {
        family.extend(fallbacks.iter().cloned());
    }
    fonts
        .families
        .insert(egui::FontFamily::Name("Space Mono".into()), family);
    ctx.set_fonts(fonts);
}

fn series(samples: &VecDeque<MeasurementSample>, metric: Metric, window_secs: f64) -> Vec<[f64; 2]> {
    let Some(latest) = samples.back().map(|sample| sample.elapsed_seconds()) else {
        return Vec::new();
    };
    let oldest = latest - window_secs;
    samples
        .iter()
        .filter(|sample| sample.elapsed_seconds() >= oldest)
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
) -> f32 {
    let width = ui.available_width();
    let mut plot = Plot::new(strip.id)
        .width(width)
        .height(STRIP_HEIGHT)
        .show_grid(true)
        .custom_y_axes(y_axis(strip.unit, strip.color))
        .show_axes([strip.show_time, true])
        .link_axis(link, [true, false])
        .link_cursor(link, [true, false])
        .auto_bounds([false, true])
        .allow_zoom([false, true])
        .allow_drag([false, true])
        .allow_scroll([false, true])
        .allow_boxed_zoom(false)
        .set_margin_fraction(egui::vec2(0.0, 0.08));
    if strip.show_time {
        plot = plot.x_axis_label("Time (s)");
    }
    plot.show(ui, |plot_ui| {
        if let Some(time) = time {
            plot_ui.set_plot_bounds_x(time);
        }
        plot_ui.line(
            Line::new(strip.id, PlotPoints::new(points.to_vec()))
                .color(strip.color)
                .width(1.8),
        );
    })
    .transform
    .frame()
    .width()
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
fn visible_time(samples: &VecDeque<MeasurementSample>, window_secs: f64) -> Option<RangeInclusive<f64>> {
    let latest = samples.back()?.elapsed_seconds();
    Some((latest - window_secs)..=latest)
}

fn y_axis(unit: &str, color: Color32) -> Vec<AxisHints<'static>> {
    vec![
        AxisHints::new_y()
            .label(RichText::new(unit).color(color))
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
        AXIS_THICKNESS, CENTRAL_PANEL_MARGIN, GraphSampleRate, MeterAverage, format_measurement, initial_window_size,
        meter_pane_width, minimum_window_size, samples_per_meter_update,
    };

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
}
