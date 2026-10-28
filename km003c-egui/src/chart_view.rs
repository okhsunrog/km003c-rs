//! Device-time navigation and stable, metric-specific chart scales.

use km003c_lib::{Metric, PlotScaleMode, PlotScaleSettings};

#[derive(Default, Debug)]
pub struct TimeView {
    /// None follows the latest sample; Some is a shared historical viewport.
    pub history: Option<[f64; 2]>,
}

impl TimeView {
    pub fn live(&mut self) {
        self.history = None;
    }

    pub fn range(&self, first: f64, last: f64, window: Option<f64>) -> [f64; 2] {
        self.history.unwrap_or_else(|| {
            let span = window.unwrap_or((last - first).max(1.0));
            [last - span, last]
        })
    }

    /// Keep device time under the cursor fixed, including empty plot margins.
    pub fn zoom(&mut self, range: [f64; 2], anchor: f64, factor: f64, max_span: f64) {
        if !factor.is_finite() || factor <= 0.0 {
            return;
        }
        let span = ((range[1] - range[0]) / factor).clamp(0.002, max_span.max(0.002));
        let time = range[0] + anchor * (range[1] - range[0]);
        self.history = Some([time - anchor * span, time + (1.0 - anchor) * span]);
    }

    pub fn pan(&mut self, range: [f64; 2], fraction: f64, first: f64, last: f64) {
        let span = range[1] - range[0];
        // Allow a viewport of margin at either end, while keeping history reachable.
        let end = (range[1] + fraction * span).clamp(first, last.max(first) + span);
        self.history = Some([end - span, end]);
    }
}

#[derive(Default)]
pub struct VerticalScale {
    metric: Option<Metric>,
    range: Option<[f64; 2]>,
    smaller_since: Option<f64>,
    smaller_target: Option<[f64; 2]>,
}

impl VerticalScale {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn range(
        &mut self,
        metric: Metric,
        settings: PlotScaleSettings,
        data: Option<[f64; 2]>,
        held: bool,
        now: f64,
    ) -> [f64; 2] {
        if self.metric != Some(metric) {
            self.reset();
            self.metric = Some(metric);
        }
        let data = data.unwrap_or([0.0, 0.0]);
        match settings.mode {
            PlotScaleMode::Manual => {
                let settings = settings.sanitized();
                [settings.min, settings.max]
            }
            PlotScaleMode::Fit => fit_range(data),
            PlotScaleMode::Stepped => {
                let target = stepped_range(metric, data);
                let Some(current) = self.range else {
                    self.range = Some(target);
                    return target;
                };
                if held {
                    self.smaller_since = None;
                    self.smaller_target = None;
                    return current;
                }
                if target[0] < current[0] || target[1] > current[1] {
                    self.range = Some([target[0].min(current[0]), target[1].max(current[1])]);
                    self.smaller_since = None;
                    self.smaller_target = None;
                } else if target != current {
                    if self.smaller_target != Some(target) {
                        self.smaller_target = Some(target);
                        self.smaller_since = Some(now);
                    }
                    if self.smaller_since.is_some_and(|since| now - since >= 15.0) {
                        self.range = Some(target);
                        self.smaller_since = None;
                        self.smaller_target = None;
                    }
                } else {
                    self.smaller_since = None;
                    self.smaller_target = None;
                }
                self.range.unwrap()
            }
        }
    }
}

fn fit_range([lo, hi]: [f64; 2]) -> [f64; 2] {
    let margin = ((hi - lo) * 0.08).max(hi.abs().max(lo.abs()) * 0.001).max(0.001);
    [lo - margin, hi + margin]
}

fn stepped_range(metric: Metric, [lo, hi]: [f64; 2]) -> [f64; 2] {
    let peak = lo.abs().max(hi.abs());
    let steps: &[f64] = match metric {
        Metric::Voltage => &[6., 10., 13., 16., 21., 26., 30., 38., 51., 65.],
        Metric::Current | Metric::SignedCurrent => &[0.1, 0.2, 0.5, 1., 2., 3., 4., 5., 6., 10., 20., 40.],
        Metric::Power | Metric::SignedPower => {
            &[1., 2., 5., 10., 20., 30., 50., 75., 100., 150., 200., 250., 500., 1000.]
        }
        Metric::Cc1 | Metric::Cc2 | Metric::DPlus | Metric::DMinus => &[0.5, 1., 2., 3.3, 5., 6.],
        _ => &[],
    };
    let ceiling = steps
        .iter()
        .copied()
        .find(|&limit| peak <= limit * 0.98)
        .unwrap_or_else(|| {
            let magnitude = 10f64.powf(peak.max(0.001).log10().floor());
            [1., 2., 5., 10.]
                .into_iter()
                .map(|step| step * magnitude)
                .find(|&v| v > peak * 1.05)
                .unwrap_or(20. * magnitude)
        });
    let signed = matches!(
        metric,
        Metric::SignedCurrent | Metric::SignedPower | Metric::SignedCharge | Metric::SignedEnergy
    ) || lo < 0.0;
    [if signed { -ceiling } else { 0.0 }, ceiling]
}

/// egui_plot's default rounding assumes powers of ten; our 1/2/5 ticks
/// also need to distinguish e.g. 0.05 from 0.1, and 0.5 from zero.
pub fn format_tick(value: f64, step: f64) -> String {
    if value != 0.0 && (value.abs() < 1e-6 || value.abs() >= 1e7) {
        return format!("{value:.2e}");
    }
    let precision = ((-step.log10()).ceil().max(0.0) as usize + 1).min(9);
    format!("{value:.precision$}")
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_owned()
}

/// Elapsed device time, not the pointer's Y coordinate or host wall clock.
pub fn timestamp(seconds: f64) -> String {
    let sign = if seconds < 0.0 { "−" } else { "" };
    let millis = (seconds.abs() * 1000.0).round() as u64;
    format!(
        "{sign}{:02}:{:02}:{:02}.{:03}",
        millis / 3_600_000,
        millis / 60_000 % 60,
        millis / 1000 % 60,
        millis % 1000
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fractional_tick_labels_keep_their_values() {
        for (value, step, expected) in [
            (0.05, 0.05, "0.05"),
            (0.5, 0.5, "0.5"),
            (0.25, 0.25, "0.25"),
            (-0.25, 0.25, "-0.25"),
            (20.0, 5.0, "20"),
            (0.0, 0.05, "0"),
        ] {
            assert_eq!(format_tick(value, step), expected);
        }
    }

    #[test]
    fn zoom_preserves_cursor_time_and_live_follows_latest_sample() {
        let mut view = TimeView::default();
        let range = view.range(0.0, 100.0, Some(30.0));
        view.zoom(range, 0.25, 2.0, 100.0);
        let zoomed = view.range(0.0, 101.0, Some(30.0));
        assert_eq!(range[0] + 0.25 * 30.0, zoomed[0] + 0.25 * 15.0);
        assert_eq!(view.range(0.0, 200.0, Some(30.0)), zoomed);
        view.pan(zoomed, -0.5, 0.0, 200.0);
        assert_eq!(view.history.unwrap()[1], zoomed[1] - 7.5);
        view.live();
        assert_eq!(view.range(0.0, 200.0, Some(30.0)), [170.0, 200.0]);
    }

    #[test]
    fn voltage_has_headroom_and_only_shrinks_after_sustained_lower_values() {
        let mut scale = VerticalScale::default();
        let settings = PlotScaleSettings::default();
        assert_eq!(
            scale.range(Metric::Voltage, settings, Some([5.0, 5.1]), false, 0.0),
            [0.0, 6.0]
        );
        assert_eq!(
            scale.range(Metric::Voltage, settings, Some([19.9, 20.1]), false, 1.0),
            [0.0, 21.0]
        );
        assert_eq!(
            scale.range(Metric::Voltage, settings, Some([5.0, 5.1]), false, 2.0),
            [0.0, 21.0]
        );
        assert_eq!(
            scale.range(Metric::Voltage, settings, Some([5.0, 5.1]), false, 16.0),
            [0.0, 21.0]
        );
        assert_eq!(
            scale.range(Metric::Voltage, settings, Some([5.0, 5.1]), false, 17.0),
            [0.0, 6.0]
        );
        assert_eq!(
            scale.range(Metric::Voltage, settings, Some([27.0, 28.1]), true, 18.0),
            [0.0, 6.0]
        );
        let signed = scale.range(Metric::SignedCurrent, settings, Some([-1.2, 0.5]), false, 19.0);
        assert!(signed[0] <= -1.2 && signed[1] >= 1.2);
    }
}
