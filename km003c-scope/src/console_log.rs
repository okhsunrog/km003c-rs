//! On-page copy of the desktop tracing console.
//!
//! The desktop app prints these lines to the terminal. The browser has no
//! terminal, so the same events are kept here and drawn under the plots.
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::Mutex;

use chrono::Local;
use eframe::egui::Color32;
use tracing::Event;
use tracing::Level;
use tracing::Metadata;
use tracing::Subscriber;
use tracing::field::Field;
use tracing::field::Visit;
use tracing::span;

/// Shortest console. A taller window gives the leftover space under the plots to it.
pub const MIN_HEIGHT: f32 = 140.0;
const MAX_LINES: usize = 500;

struct Line {
    time: String,
    level: String,
    level_color: Color32,
    target: String,
    message: String,
}

static LINES: Mutex<VecDeque<Line>> = Mutex::new(VecDeque::new());

pub struct Entry {
    pub time: String,
    pub level: String,
    pub level_color: Color32,
    pub target: String,
    pub message: String,
}

/// Dim grey used for the timestamp and the module path, matching a terminal's dim text.
pub const DIM: Color32 = Color32::from_rgb(140, 140, 140);
/// Normal message text. The level word is the only part that takes the level color.
pub const MESSAGE: Color32 = Color32::from_rgb(220, 220, 220);

/// Height of the console under a plot stack of `plots` pixels.
pub fn panel_height(available: f32, plots: f32) -> f32 {
    (available - plots).max(MIN_HEIGHT)
}

/// Plain text of the visible console, one line per event, in terminal order.
pub fn plain_text() -> String {
    LINES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .map(format_line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_line(line: &Line) -> String {
    format!("{} {} {}: {}", line.time, line.level, line.target, line.message)
}

pub fn snapshot() -> Vec<Entry> {
    LINES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .map(|line| Entry {
            time: line.time.clone(),
            level: line.level.clone(),
            level_color: line.level_color,
            target: line.target.clone(),
            message: line.message.clone(),
        })
        .collect()
}

pub fn init() {
    let _ = tracing::subscriber::set_global_default(ConsoleSubscriber);
}

struct ConsoleSubscriber;

impl Subscriber for ConsoleSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        *metadata.level() <= Level::INFO
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::INFO)
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let mut message = visitor.message;
        if !visitor.fields.is_empty() {
            message.push(' ');
            message.push_str(&visitor.fields);
        }
        push_line(*event.metadata().level(), event.metadata().target(), &message);
    }

    fn enter(&self, _span: &span::Id) {}

    fn exit(&self, _span: &span::Id) {}
}

#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: String,
}

impl Visit for MessageVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            let _ = write!(self.fields, " {}={value}", field.name());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            if self.message.is_empty() {
                self.message = format!("{value:?}");
            }
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
}

fn push_line(level: Level, target: &str, message: &str) {
    let time = Local::now().format("%H:%M:%S%.3f").to_string();
    let level_label = level_label(level);
    #[cfg(target_arch = "wasm32")]
    web_sys::console::log_1(&format!("{time} {level_label} {target}: {message}").into());
    let mut lines = LINES.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    lines.push_back(Line {
        time,
        level: level_label.to_string(),
        level_color: level_color(level),
        target: target.to_string(),
        message: message.to_string(),
    });
    while lines.len() > MAX_LINES {
        lines.pop_front();
    }
}

fn level_label(level: Level) -> &'static str {
    match level {
        Level::ERROR => "ERROR",
        Level::WARN => " WARN",
        Level::INFO => " INFO",
        Level::DEBUG => "DEBUG",
        Level::TRACE => "TRACE",
    }
}

fn level_color(level: Level) -> Color32 {
    match level {
        Level::ERROR => Color32::from_rgb(230, 70, 70),
        Level::WARN => Color32::from_rgb(230, 180, 40),
        Level::INFO => Color32::from_rgb(50, 190, 80),
        Level::DEBUG => Color32::from_rgb(90, 150, 230),
        Level::TRACE => Color32::from_rgb(180, 120, 220),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_fills_the_space_under_the_plots() {
        assert_eq!(panel_height(1_000.0, 760.0), 240.0);
        assert_eq!(panel_height(800.0, 760.0), MIN_HEIGHT);
    }

    #[test]
    fn copied_console_uses_the_same_line_as_the_screen() {
        let line = Line {
            time: "19:23:34.479".to_string(),
            level: level_label(Level::WARN).to_string(),
            level_color: level_color(Level::WARN),
            target: "km003c_lib::session".to_string(),
            message: "Temperature poll was empty  temperature_c=-256.0".to_string(),
        };
        assert_eq!(
            format_line(&line),
            "19:23:34.479  WARN km003c_lib::session: Temperature poll was empty  temperature_c=-256.0"
        );
    }

    #[test]
    fn console_line_matches_the_desktop_tracing_shape() {
        assert_eq!(level_label(Level::INFO), " INFO");
        assert_eq!(level_label(Level::WARN), " WARN");
        assert_eq!(level_label(Level::ERROR), "ERROR");
        assert_eq!(level_color(Level::ERROR), Color32::from_rgb(230, 70, 70));
        assert_ne!(level_color(Level::WARN), level_color(Level::INFO));
        assert_ne!(level_color(Level::INFO), DIM);
        assert_ne!(MESSAGE, level_color(Level::INFO));
    }

    #[test]
    fn console_drops_lines_past_the_cap() {
        {
            let mut lines = LINES.lock().unwrap();
            lines.clear();
        }
        for index in 0..(MAX_LINES + 3) {
            push_line(Level::INFO, "test", &format!("line {index}"));
        }
        let lines = LINES.lock().unwrap();
        assert_eq!(lines.len(), MAX_LINES);
        assert!(lines.front().unwrap().message.contains("line 3"));
        assert!(
            lines
                .back()
                .unwrap()
                .message
                .contains(&format!("line {}", MAX_LINES + 2))
        );
    }
}
