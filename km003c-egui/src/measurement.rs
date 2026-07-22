use eframe::egui;
use km003c_lib::uom::si::electric_current::microampere;
use km003c_lib::uom::si::electric_potential::microvolt;
use km003c_lib::uom::si::power::microwatt;
use km003c_lib::{AdcQueueSample, GraphSampleRate};

const MICROSECONDS_PER_MILLISECOND: u64 = 1_000;
const MICROSECONDS_PER_HOUR: f64 = 3_600_000_000.0;
const MAX_FORWARD_SEQUENCE_TICKS: u16 = i16::MAX as u16;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct MeasurementSample {
    pub(crate) elapsed_us: u64,
    pub(crate) sample_index: u64,
    pub(crate) sequence: u16,
    pub(crate) marker: u16,
    pub(crate) sample_rate_hz: u16,
    pub(crate) missing_samples: u16,
    pub(crate) gap_duration_us: u64,
    pub(crate) interpolated: bool,
    pub(crate) cumulative_missing_samples: u64,
    pub(crate) cumulative_interpolated_duration_us: u64,
    pub(crate) discarded_sequence_samples: u32,
    pub(crate) cumulative_discarded_sequence_samples: u64,
    pub(crate) vbus_uv: i64,
    pub(crate) ibus_ua: i64,
    pub(crate) power_uw: i64,
    pub(crate) charge_uah: f64,
    pub(crate) energy_uwh: f64,
    pub(crate) charge_throughput_uah: f64,
    pub(crate) energy_throughput_uwh: f64,
    pub(crate) cc1_uv: i64,
    pub(crate) cc2_uv: i64,
    pub(crate) dp_uv: i64,
    pub(crate) dm_uv: i64,
}

impl MeasurementSample {
    pub(crate) fn elapsed_seconds(self) -> f64 {
        self.elapsed_us as f64 / 1_000_000.0
    }
}

#[derive(Debug, Default)]
pub(crate) struct MeasurementAccumulator {
    elapsed_us: u64,
    sample_index: u64,
    cumulative_missing_samples: u64,
    cumulative_interpolated_duration_us: u64,
    cumulative_discarded_sequence_samples: u64,
    pending_discarded_sequence_samples: u32,
    charge_twice_ua_us: i128,
    energy_twice_uw_us: i128,
    charge_throughput_twice_ua_us: i128,
    energy_throughput_twice_uw_us: i128,
    previous: Option<PreviousSample>,
}

#[derive(Debug, Clone, Copy)]
struct PreviousSample {
    sequence: u16,
    current_ua: i64,
    power_uw: i64,
}

impl MeasurementAccumulator {
    pub(crate) fn push(&mut self, sample: AdcQueueSample, rate: GraphSampleRate) -> Option<MeasurementSample> {
        let vbus_uv = sample.vbus.get::<microvolt>().round() as i64;
        let ibus_ua = sample.ibus.get::<microampere>().round() as i64;
        let power_uw = sample.power.get::<microwatt>().round() as i64;
        let expected_ticks = u64::from(rate.sequence_step());

        let (missing_samples, delta_us) = self.previous.map_or((0, 0), |previous| {
            let delta_ticks = u64::from(sample.sequence.wrapping_sub(previous.sequence));
            let missing = rate.missing_samples(previous.sequence, sample.sequence);
            (missing, delta_ticks * MICROSECONDS_PER_MILLISECOND)
        });

        if let Some(previous) = self.previous {
            let delta_ticks = sample.sequence.wrapping_sub(previous.sequence);
            if delta_ticks == 0 || delta_ticks > MAX_FORWARD_SEQUENCE_TICKS || delta_ticks % rate.sequence_step() != 0 {
                self.cumulative_discarded_sequence_samples =
                    self.cumulative_discarded_sequence_samples.saturating_add(1);
                self.pending_discarded_sequence_samples = self.pending_discarded_sequence_samples.saturating_add(1);
                return None;
            }
        }
        let gap_duration_us = u64::from(missing_samples) * expected_ticks * MICROSECONDS_PER_MILLISECOND;

        if let Some(previous) = self.previous {
            self.charge_twice_ua_us += (i128::from(previous.current_ua) + i128::from(ibus_ua)) * i128::from(delta_us);
            self.energy_twice_uw_us += (i128::from(previous.power_uw) + i128::from(power_uw)) * i128::from(delta_us);
            self.charge_throughput_twice_ua_us +=
                (i128::from(previous.current_ua).abs() + i128::from(ibus_ua).abs()) * i128::from(delta_us);
            self.energy_throughput_twice_uw_us +=
                (i128::from(previous.power_uw).abs() + i128::from(power_uw).abs()) * i128::from(delta_us);
        }

        self.elapsed_us += delta_us;
        self.cumulative_missing_samples += u64::from(missing_samples);
        self.cumulative_interpolated_duration_us += gap_duration_us;

        let decoded = MeasurementSample {
            elapsed_us: self.elapsed_us,
            sample_index: self.sample_index,
            sequence: sample.sequence,
            marker: sample.marker,
            sample_rate_hz: rate.frequency().get::<km003c_lib::uom::si::frequency::hertz>() as u16,
            missing_samples,
            gap_duration_us,
            interpolated: missing_samples > 0,
            cumulative_missing_samples: self.cumulative_missing_samples,
            cumulative_interpolated_duration_us: self.cumulative_interpolated_duration_us,
            discarded_sequence_samples: self.pending_discarded_sequence_samples,
            cumulative_discarded_sequence_samples: self.cumulative_discarded_sequence_samples,
            vbus_uv,
            ibus_ua,
            power_uw,
            charge_uah: self.charge_twice_ua_us as f64 / (2.0 * MICROSECONDS_PER_HOUR),
            energy_uwh: self.energy_twice_uw_us as f64 / (2.0 * MICROSECONDS_PER_HOUR),
            charge_throughput_uah: self.charge_throughput_twice_ua_us as f64 / (2.0 * MICROSECONDS_PER_HOUR),
            energy_throughput_uwh: self.energy_throughput_twice_uw_us as f64 / (2.0 * MICROSECONDS_PER_HOUR),
            cc1_uv: sample.cc1.get::<microvolt>().round() as i64,
            cc2_uv: sample.cc2.get::<microvolt>().round() as i64,
            dp_uv: sample.vdp.get::<microvolt>().round() as i64,
            dm_uv: sample.vdm.get::<microvolt>().round() as i64,
        };

        self.previous = Some(PreviousSample {
            sequence: sample.sequence,
            current_ua: ibus_ua,
            power_uw,
        });
        self.sample_index += 1;
        self.pending_discarded_sequence_samples = 0;
        Some(decoded)
    }

    pub(crate) fn reset_continuity(&mut self) {
        self.previous = None;
    }

    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }

    pub(crate) const fn cumulative_discarded_sequence_samples(&self) -> u64 {
        self.cumulative_discarded_sequence_samples
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlotMetric {
    Voltage,
    Current,
    SignedCurrent,
    Power,
    SignedPower,
    Charge,
    SignedCharge,
    Energy,
    SignedEnergy,
    Cc1,
    Cc2,
    DPlus,
    DMinus,
}

impl PlotMetric {
    pub(crate) const ALL: [Self; 13] = [
        Self::Voltage,
        Self::Current,
        Self::SignedCurrent,
        Self::Power,
        Self::SignedPower,
        Self::Charge,
        Self::SignedCharge,
        Self::Energy,
        Self::SignedEnergy,
        Self::Cc1,
        Self::Cc2,
        Self::DPlus,
        Self::DMinus,
    ];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Voltage => "Voltage",
            Self::Current => "Current (absolute)",
            Self::SignedCurrent => "Current (signed)",
            Self::Power => "Power (absolute)",
            Self::SignedPower => "Power (signed)",
            Self::Charge => "Charge transferred",
            Self::SignedCharge => "Net charge (signed)",
            Self::Energy => "Energy transferred",
            Self::SignedEnergy => "Net energy (signed)",
            Self::Cc1 => "CC1 voltage",
            Self::Cc2 => "CC2 voltage",
            Self::DPlus => "D+ voltage",
            Self::DMinus => "D- voltage",
        }
    }

    pub(crate) const fn supports_offline(self) -> bool {
        !matches!(self, Self::Cc1 | Self::Cc2 | Self::DPlus | Self::DMinus)
    }

    pub(crate) const fn unit(self) -> &'static str {
        match self {
            Self::Voltage | Self::Cc1 | Self::Cc2 | Self::DPlus | Self::DMinus => "V",
            Self::Current | Self::SignedCurrent => "A",
            Self::Power | Self::SignedPower => "W",
            Self::Charge | Self::SignedCharge => "mAh",
            Self::Energy | Self::SignedEnergy => "mWh",
        }
    }

    pub(crate) fn value(self, sample: &MeasurementSample) -> f64 {
        match self {
            Self::Voltage => sample.vbus_uv as f64 / 1_000_000.0,
            Self::Current => (sample.ibus_ua as f64 / 1_000_000.0).abs(),
            Self::SignedCurrent => sample.ibus_ua as f64 / 1_000_000.0,
            Self::Power => (sample.power_uw as f64 / 1_000_000.0).abs(),
            Self::SignedPower => sample.power_uw as f64 / 1_000_000.0,
            Self::Charge => sample.charge_throughput_uah / 1_000.0,
            Self::SignedCharge => sample.charge_uah / 1_000.0,
            Self::Energy => sample.energy_throughput_uwh / 1_000.0,
            Self::SignedEnergy => sample.energy_uwh / 1_000.0,
            Self::Cc1 => sample.cc1_uv as f64 / 1_000_000.0,
            Self::Cc2 => sample.cc2_uv as f64 / 1_000_000.0,
            Self::DPlus => sample.dp_uv as f64 / 1_000_000.0,
            Self::DMinus => sample.dm_uv as f64 / 1_000_000.0,
        }
    }

    pub(crate) const fn color(self) -> egui::Color32 {
        match self {
            Self::Voltage => egui::Color32::GREEN,
            Self::Current | Self::SignedCurrent => egui::Color32::BLUE,
            Self::Power | Self::SignedPower => egui::Color32::from_rgb(255, 165, 0),
            Self::Charge | Self::SignedCharge => egui::Color32::from_rgb(180, 120, 255),
            Self::Energy | Self::SignedEnergy => egui::Color32::from_rgb(255, 100, 180),
            Self::Cc1 => egui::Color32::from_rgb(100, 200, 255),
            Self::Cc2 => egui::Color32::from_rgb(80, 220, 180),
            Self::DPlus => egui::Color32::from_rgb(255, 120, 120),
            Self::DMinus => egui::Color32::from_rgb(120, 160, 255),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use km003c_lib::uom::si::electric_current::ampere;
    use km003c_lib::uom::si::electric_potential::volt;
    use km003c_lib::uom::si::f64::{ElectricCurrent, ElectricPotential};

    fn sample(sequence: u16, voltage_v: f64, current_a: f64) -> AdcQueueSample {
        let vbus = ElectricPotential::new::<volt>(voltage_v);
        let ibus = ElectricCurrent::new::<ampere>(current_a);
        AdcQueueSample {
            sequence,
            marker: 0x1234,
            vbus,
            ibus,
            power: vbus * ibus,
            cc1: ElectricPotential::new::<volt>(1.0),
            cc2: ElectricPotential::new::<volt>(2.0),
            vdp: ElectricPotential::new::<volt>(0.6),
            vdm: ElectricPotential::new::<volt>(0.5),
        }
    }

    #[test]
    fn integrates_charge_and_energy_from_device_time() {
        let mut accumulator = MeasurementAccumulator::default();
        accumulator.push(sample(0, 10.0, 2.0), GraphSampleRate::Sps2).unwrap();
        let second = accumulator.push(sample(500, 10.0, 2.0), GraphSampleRate::Sps2).unwrap();

        assert_eq!(second.elapsed_us, 500_000);
        assert!((second.charge_uah - 277.777_777).abs() < 0.000_001);
        assert!((second.energy_uwh - 2_777.777_777).abs() < 0.000_001);
        assert!((second.charge_throughput_uah - 277.777_777).abs() < 0.000_001);
        assert!((second.energy_throughput_uwh - 2_777.777_777).abs() < 0.000_001);
        assert_eq!(second.missing_samples, 0);
    }

    #[test]
    fn interpolates_across_gaps_and_records_their_quality() {
        let mut accumulator = MeasurementAccumulator::default();
        accumulator.push(sample(0, 10.0, 1.0), GraphSampleRate::Sps50).unwrap();
        let after_gap = accumulator.push(sample(60, 10.0, 3.0), GraphSampleRate::Sps50).unwrap();

        assert_eq!(after_gap.missing_samples, 2);
        assert_eq!(after_gap.gap_duration_us, 40_000);
        assert_eq!(after_gap.cumulative_missing_samples, 2);
        assert_eq!(after_gap.cumulative_interpolated_duration_us, 40_000);
        assert!(after_gap.interpolated);
        assert!((after_gap.charge_uah - 33.333_333).abs() < 0.000_001);
    }

    #[test]
    fn signed_and_absolute_metrics_are_distinct() {
        let mut accumulator = MeasurementAccumulator::default();
        let measurement = accumulator.push(sample(0, 5.0, -2.0), GraphSampleRate::Sps10).unwrap();

        assert_eq!(PlotMetric::Current.value(&measurement), 2.0);
        assert_eq!(PlotMetric::SignedCurrent.value(&measurement), -2.0);
        assert_eq!(PlotMetric::Power.value(&measurement), 10.0);
        assert_eq!(PlotMetric::SignedPower.value(&measurement), -10.0);
    }

    #[test]
    fn discards_duplicate_and_out_of_order_sequence_samples() {
        let mut accumulator = MeasurementAccumulator::default();
        accumulator
            .push(sample(1_000, 5.0, 1.0), GraphSampleRate::Sps1000)
            .unwrap();

        assert!(
            accumulator
                .push(sample(1_000, 50.0, 10.0), GraphSampleRate::Sps1000)
                .is_none()
        );
        assert!(
            accumulator
                .push(sample(990, 50.0, 10.0), GraphSampleRate::Sps1000)
                .is_none()
        );

        let next = accumulator
            .push(sample(1_001, 5.0, 1.0), GraphSampleRate::Sps1000)
            .unwrap();
        assert_eq!(next.elapsed_us, 1_000);
        assert_eq!(next.discarded_sequence_samples, 2);
        assert_eq!(next.cumulative_discarded_sequence_samples, 2);
        assert!((next.charge_uah - 0.277_777).abs() < 0.000_001);
    }

    #[test]
    fn accepts_sequence_counter_rollover() {
        let mut accumulator = MeasurementAccumulator::default();
        accumulator
            .push(sample(u16::MAX, 5.0, 1.0), GraphSampleRate::Sps1000)
            .unwrap();
        let after_rollover = accumulator.push(sample(0, 5.0, 1.0), GraphSampleRate::Sps1000).unwrap();

        assert_eq!(after_rollover.elapsed_us, 1_000);
        assert_eq!(after_rollover.cumulative_discarded_sequence_samples, 0);
    }

    #[test]
    fn throughput_stays_positive_when_direction_changes() {
        let mut accumulator = MeasurementAccumulator::default();
        accumulator
            .push(sample(0, 5.0, -1.0), GraphSampleRate::Sps1000)
            .unwrap();
        let zero_crossing = accumulator.push(sample(1, 5.0, 1.0), GraphSampleRate::Sps1000).unwrap();

        assert_eq!(zero_crossing.charge_uah, 0.0);
        assert_eq!(zero_crossing.energy_uwh, 0.0);
        assert!((zero_crossing.charge_throughput_uah - 0.277_777).abs() < 0.000_001);
        assert!((zero_crossing.energy_throughput_uwh - 1.388_888).abs() < 0.000_001);
    }
}
