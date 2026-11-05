use eframe::egui::Color32;
use km003c_lib::Metric;

/// Plot color of each metric.
pub(crate) trait MetricColor {
    fn color(self, dark: bool) -> Color32;
}

impl MetricColor for Metric {
    fn color(self, dark: bool) -> Color32 {
        if !dark {
            return match self {
                Self::Voltage => Color32::from_rgb(0, 117, 67),
                Self::Current | Self::SignedCurrent => Color32::from_rgb(31, 91, 194),
                Self::Power | Self::SignedPower => Color32::from_rgb(157, 79, 0),
                Self::Charge | Self::SignedCharge => Color32::from_rgb(111, 54, 183),
                Self::Energy | Self::SignedEnergy => Color32::from_rgb(163, 41, 106),
                Self::Cc1 => Color32::from_rgb(0, 103, 151),
                Self::Cc2 => Color32::from_rgb(0, 115, 91),
                Self::DPlus => Color32::from_rgb(179, 43, 43),
                Self::DMinus => Color32::from_rgb(65, 86, 181),
            };
        }
        match self {
            Self::Voltage => Color32::from_rgb(83, 218, 143),
            Self::Current | Self::SignedCurrent => Color32::from_rgb(90, 160, 255),
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
