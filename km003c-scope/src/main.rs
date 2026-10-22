//! A small time-domain scope for the KM003C.
//!
//! The left side is split in half: live voltage, current, and power on top,
//! and the connection controls below. The center overlays voltage and current
//! on one time axis, each with its own scale.

use std::collections::VecDeque;
use std::ops::RangeInclusive;
use std::time::Duration;

use eframe::egui;
use eframe::egui::Color32;
use eframe::egui::RichText;
use eframe::egui::UiBuilder;
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
        window_secs: 10.0,
        pixels_per_second: None,
        plot_width: None,
        usb_reset,
    };

    eframe::run_native(
        "KM003C Scope",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1430.0, 700.0])
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
    /// Horizontal scale of the trace, taken from the opening layout.
    pixels_per_second: Option<f64>,
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
        let rect = ui.available_rect_before_wrap();
        if rect.width() < 2.0 || rect.height() < 2.0 {
            return;
        }
        ui.allocate_rect(rect, egui::Sense::hover());
        self.follow_plot_width();

        let voltage = series(&self.samples, Metric::Voltage, self.window_secs);
        let current = series(&self.samples, Metric::SignedCurrent, self.window_secs);
        let link = ui.id().with("scope_time");
        let time = visible_time(&self.samples, self.window_secs);

        let mut voltage_ui = ui.new_child(UiBuilder::new().max_rect(rect));
        let plot_width = trace_plot(
            &mut voltage_ui,
            "scope_voltage",
            &voltage,
            VOLTAGE_COLOR,
            true,
            link,
            time.clone(),
        );
        let mut current_ui = ui.new_child(UiBuilder::new().max_rect(rect));
        trace_plot(
            &mut current_ui,
            "scope_current",
            &current,
            CURRENT_COLOR,
            false,
            link,
            time,
        );
        self.note_plot_width(plot_width);
    }

    /// Keep the opening pixels/second. A wider plot then covers more time.
    fn follow_plot_width(&mut self) {
        let (Some(pixels_per_second), Some(plot_width)) = (self.pixels_per_second, self.plot_width) else {
            return;
        };
        self.window_secs = plot_width / pixels_per_second;
    }

    fn note_plot_width(&mut self, width: f32) {
        let width = f64::from(width).max(1.0);
        self.plot_width = Some(width);
        if self.pixels_per_second.is_none() {
            self.pixels_per_second = Some(width / self.window_secs.max(1.0e-3));
        }
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

/// Draw one trace into a shared time window.
///
/// Voltage is drawn first and owns the grid. Current is drawn over it without
/// a background, with its scale on the right. Both plots reserve the same axis
/// margins so the traces sit on the same pixels. Only the X axis is linked, so
/// each trace keeps its own vertical scale.
fn trace_plot(
    ui: &mut egui::Ui,
    id: &str,
    points: &[[f64; 2]],
    color: Color32,
    background: bool,
    link: egui::Id,
    time: Option<RangeInclusive<f64>>,
) -> f32 {
    let size = ui.available_size();
    let y_axes = vec![
        y_axis(HPlacement::Left, "Voltage (V)", background),
        y_axis(HPlacement::Right, "Current (A)", !background),
    ];
    Plot::new(id)
        .width(size.x)
        .height(size.y)
        .show_background(background)
        .show_grid(background)
        .custom_y_axes(y_axes)
        .x_axis_label("Time (s)")
        .link_axis(link, [true, false])
        .link_cursor(link, [true, false])
        .auto_bounds([false, true])
        .allow_zoom([false, !background])
        .allow_drag([false, !background])
        .allow_scroll([false, !background])
        .allow_boxed_zoom(false)
        .set_margin_fraction(egui::vec2(0.0, 0.08))
        .show(ui, |plot_ui| {
            if let Some(time) = time {
                plot_ui.set_plot_bounds_x(time);
            }
            plot_ui.line(Line::new(id, PlotPoints::new(points.to_vec())).color(color).width(1.8));
        })
        .transform
        .frame()
        .width()
}

/// Time span ending at the newest sample. The right edge stays on that sample.
fn visible_time(samples: &VecDeque<MeasurementSample>, window_secs: f64) -> Option<RangeInclusive<f64>> {
    let latest = samples.back()?.elapsed_seconds();
    Some((latest - window_secs)..=latest)
}

fn y_axis<'a>(placement: HPlacement, label: &str, visible: bool) -> AxisHints<'a> {
    let color = if visible {
        match placement {
            HPlacement::Left => VOLTAGE_COLOR,
            HPlacement::Right => CURRENT_COLOR,
        }
    } else {
        Color32::TRANSPARENT
    };
    let hints = AxisHints::new_y()
        .label(RichText::new(label).color(color))
        .min_thickness(AXIS_THICKNESS)
        .placement(placement);
    if visible {
        hints
    } else {
        hints.formatter(|_, _| String::new())
    }
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
    use super::{GraphSampleRate, MeterAverage, format_measurement, samples_per_meter_update};

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
}
