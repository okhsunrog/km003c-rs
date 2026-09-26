//! Offline recordings decoded for plotting and export.
//!
//! [`OfflineRecordingView`] places the samples of a downloaded [`OfflineLog`]
//! on a time axis in the same integer units as live [`MeasurementSample`]s,
//! and derives the transferred charge and energy the device does not store.
//!
//! [`MeasurementSample`]: crate::MeasurementSample

use std::sync::Arc;

use uom::si::power::microwatt;
use uom::si::time::microsecond;

use crate::measurement::Metric;
use crate::offline::{OfflineLog, OfflineLogSample};

/// One offline sample on the recording's time axis.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct OfflineViewSample {
    /// Time since the first sample, from the logging interval.
    pub elapsed_us: u64,
    pub sample_index: u64,
    pub vbus_uv: i64,
    pub ibus_ua: i64,
    pub power_uw: i64,
    /// Signed net charge, as the device accumulated it.
    pub charge_uah: f64,
    /// Signed net energy, as the device accumulated it.
    pub energy_uwh: f64,
    /// Sum of the absolute changes of the device's charge counter.
    pub charge_throughput_uah: f64,
    /// Sum of the absolute changes of the device's energy counter.
    pub energy_throughput_uwh: f64,
}

impl OfflineViewSample {
    pub fn elapsed_seconds(self) -> f64 {
        self.elapsed_us as f64 / 1_000_000.0
    }

    /// The value in [`Metric::unit`], or `None` for the CC and D+/D- lines,
    /// which offline logs do not record.
    pub fn metric_value(self, metric: Metric) -> Option<f64> {
        match metric {
            Metric::Voltage => Some(self.vbus_uv as f64 / 1_000_000.0),
            Metric::Current => Some((self.ibus_ua as f64 / 1_000_000.0).abs()),
            Metric::SignedCurrent => Some(self.ibus_ua as f64 / 1_000_000.0),
            Metric::Power => Some((self.power_uw as f64 / 1_000_000.0).abs()),
            Metric::SignedPower => Some(self.power_uw as f64 / 1_000_000.0),
            Metric::Charge => Some(self.charge_throughput_uah / 1_000.0),
            Metric::SignedCharge => Some(self.charge_uah / 1_000.0),
            Metric::Energy => Some(self.energy_throughput_uwh / 1_000.0),
            Metric::SignedEnergy => Some(self.energy_uwh / 1_000.0),
            Metric::Cc1 | Metric::Cc2 | Metric::DPlus | Metric::DMinus => None,
        }
    }
}

/// A downloaded offline recording and its decoded samples.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OfflineRecordingView {
    pub log: Arc<OfflineLog>,
    pub samples: Vec<OfflineViewSample>,
}

impl OfflineRecordingView {
    pub fn new(log: OfflineLog) -> Self {
        let log = Arc::new(log);
        let interval_us = log.metadata.interval.get::<microsecond>().round() as u64;
        let mut previous_charge_uah = 0_i32;
        let mut previous_energy_uwh = 0_i32;
        let mut charge_throughput_uah = 0_u64;
        let mut energy_throughput_uwh = 0_u64;
        let samples = log
            .samples
            .iter()
            .enumerate()
            .map(|(index, sample)| {
                let raw = sample.raw();
                charge_throughput_uah =
                    charge_throughput_uah.saturating_add(u64::from(raw.charge_uah.abs_diff(previous_charge_uah)));
                energy_throughput_uwh =
                    energy_throughput_uwh.saturating_add(u64::from(raw.energy_uwh.abs_diff(previous_energy_uwh)));
                previous_charge_uah = raw.charge_uah;
                previous_energy_uwh = raw.energy_uwh;
                decode_sample(sample, index, interval_us, charge_throughput_uah, energy_throughput_uwh)
            })
            .collect();
        Self { log, samples }
    }
}

fn decode_sample(
    sample: &OfflineLogSample,
    index: usize,
    interval_us: u64,
    charge_throughput_uah: u64,
    energy_throughput_uwh: u64,
) -> OfflineViewSample {
    let raw = sample.raw();
    OfflineViewSample {
        elapsed_us: (index as u64).saturating_mul(interval_us),
        sample_index: index as u64,
        vbus_uv: i64::from(raw.voltage_uv),
        ibus_ua: i64::from(raw.current_ua),
        power_uw: sample.power.get::<microwatt>().round() as i64,
        charge_uah: f64::from(raw.charge_uah),
        energy_uwh: f64::from(raw.energy_uwh),
        charge_throughput_uah: charge_throughput_uah as f64,
        energy_throughput_uwh: energy_throughput_uwh as f64,
    }
}

/// Three samples captured from a KM003C, for tests.
#[cfg(test)]
pub(crate) fn captured_test_view() -> OfflineRecordingView {
    use crate::offline::LogMetadata;
    use uom::si::electric_charge::microampere_hour;
    use uom::si::energy::microwatt_hour;
    use uom::si::f64::{ElectricCharge, Energy, Time};
    use uom::si::time::{millisecond, second};

    let bytes = [
        "81494c0021f0e2ff56ebffffb998ffff",
        "bcaa89006e25f2ff2dd5f8fff7fdd6ff",
        "cf2a8900947dfeffa1a2f3ffe04da8ff",
    ]
    .into_iter()
    .flat_map(|sample| hex::decode(sample).unwrap())
    .collect::<Vec<_>>();
    let mut filename_raw = [0; 16];
    filename_raw[..5].copy_from_slice(b"A01.d");
    OfflineRecordingView::new(
        OfflineLog::from_bytes(
            LogMetadata {
                filename_raw,
                unknown_0x10: 0x0a45,
                sample_count: 3,
                interval: Time::new::<millisecond>(10_000.0),
                flags: 0,
                recorded_duration: Time::new::<second>(20.0),
                final_charge: ElectricCharge::new::<microampere_hour>(-810_335.0),
                final_energy: Energy::new::<microwatt_hour>(-5_747_232.0),
                data_offset: 0,
                reserved_tail: [0; 8],
            },
            &bytes,
        )
        .unwrap(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_captured_samples_without_inventing_auxiliary_channels() {
        let view = captured_test_view();

        assert_eq!(view.samples.len(), 3);
        assert_eq!(view.samples[1].elapsed_us, 10_000_000);
        assert_eq!(view.samples[0].vbus_uv, 4_999_553);
        assert_eq!(view.samples[0].ibus_ua, -1_904_607);
        assert_eq!(view.samples[0].charge_throughput_uah, 5_290.0);
        assert_eq!(view.samples[2].charge_throughput_uah, 810_335.0);
        assert!(view.samples[0].metric_value(Metric::Cc1).is_none());
    }

    #[test]
    fn throughput_accumulates_absolute_device_counter_changes() {
        let view = captured_test_view();

        assert_eq!(view.samples[0].energy_throughput_uwh, 26_439.0);
        assert_eq!(view.samples[2].energy_throughput_uwh, 5_747_232.0);
        assert_eq!(
            view.samples[2].metric_value(Metric::Energy),
            Some(5_747_232.0 / 1_000.0)
        );
        assert_eq!(
            view.samples[2].metric_value(Metric::SignedEnergy),
            Some(-5_747_232.0 / 1_000.0)
        );
    }
}
