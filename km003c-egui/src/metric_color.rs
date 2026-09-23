use eframe::egui::Color32;
use km003c_lib::Metric;

/// Plot color of each metric.
pub(crate) trait MetricColor {
    fn color(self) -> Color32;
}

impl MetricColor for Metric {
    fn color(self) -> Color32 {
        match self {
            Self::Voltage => Color32::GREEN,
            Self::Current | Self::SignedCurrent => Color32::BLUE,
            Self::Power | Self::SignedPower => Color32::from_rgb(255, 165, 0),
            Self::Charge | Self::SignedCharge => Color32::from_rgb(180, 120, 255),
            Self::Energy | Self::SignedEnergy => Color32::from_rgb(255, 100, 180),
            Self::Cc1 => Color32::from_rgb(100, 200, 255),
            Self::Cc2 => Color32::from_rgb(80, 220, 180),
            Self::DPlus => Color32::from_rgb(255, 120, 120),
            Self::DMinus => Color32::from_rgb(120, 160, 255),
        }
    }
}
