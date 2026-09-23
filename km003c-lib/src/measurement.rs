//! Continuous measurement stream reconstructed from AdcQueue samples.
//!
//! The device timestamps AdcQueue samples with a 16-bit 1 kHz sequence counter.
//! [`MeasurementAccumulator`] turns those samples into a monotonic device-time
//! series: it rejects duplicate and out-of-order samples, reports gaps, and
//! integrates charge and energy over device time rather than host time.

use uom::si::electric_current::microampere;
use uom::si::electric_potential::microvolt;
use uom::si::frequency::hertz;
use uom::si::power::microwatt;

use crate::{AdcQueueSample, GraphSampleRate};

const MICROSECONDS_PER_MILLISECOND: u64 = 1_000;
const MICROSECONDS_PER_HOUR: f64 = 3_600_000_000.0;

/// How many consecutive rejected samples end a continuity run.
///
/// The device sequence counter is a 16-bit 1 kHz tick, so it wraps every 65.5
/// seconds regardless of the sample rate. A long enough stall is therefore
/// indistinguishable from an out-of-order sample; rather than rejecting every
/// following sample forever, the accumulator restarts its continuity run.
const MAX_CONSECUTIVE_REJECTED_SAMPLES: u32 = 8;

/// Largest forward sequence delta accepted as a real gap at a given rate.
///
/// Half of the counter range is the theoretical limit, but a gap can only ever
/// be a whole number of samples, so the bound is expressed in samples and
/// converted back to ticks. Keeping it rate-relative stops a 33-second stall at
/// 2 SPS from being misread as an out-of-order sample.
fn max_forward_sequence_ticks(rate: GraphSampleRate) -> u16 {
    let step = rate.sequence_step();
    (u16::MAX / 2 / step) * step
}

/// One accepted AdcQueue sample placed on the device timeline.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MeasurementSample {
    /// Device time since the start of the stream.
    pub elapsed_us: u64,
    /// Index among accepted samples.
    pub sample_index: u64,
    pub sequence: u16,
    pub marker: u16,
    pub sample_rate_hz: u16,
    /// Samples the device skipped just before this one.
    pub missing_samples: u16,
    /// Duration of that gap, bridged by linear interpolation in the integrals.
    pub gap_duration_us: u64,
    pub interpolated: bool,
    pub cumulative_missing_samples: u64,
    pub cumulative_interpolated_duration_us: u64,
    /// Samples rejected as duplicate or out of order since the previous one.
    pub discarded_sequence_samples: u32,
    pub cumulative_discarded_sequence_samples: u64,
    pub vbus_uv: i64,
    pub ibus_ua: i64,
    pub power_uw: i64,
    /// Net charge; negative when current flows in reverse.
    pub charge_uah: f64,
    /// Net energy; negative when power flows in reverse.
    pub energy_uwh: f64,
    /// Charge transferred in either direction.
    pub charge_throughput_uah: f64,
    /// Energy transferred in either direction.
    pub energy_throughput_uwh: f64,
    pub cc1_uv: i64,
    pub cc2_uv: i64,
    pub dp_uv: i64,
    pub dm_uv: i64,
}

impl MeasurementSample {
    pub fn elapsed_seconds(self) -> f64 {
        self.elapsed_us as f64 / 1_000_000.0
    }
}

/// Builds a [`MeasurementSample`] stream from AdcQueue samples.
#[derive(Debug, Default)]
pub struct MeasurementAccumulator {
    elapsed_us: u64,
    sample_index: u64,
    cumulative_missing_samples: u64,
    cumulative_interpolated_duration_us: u64,
    cumulative_discarded_sequence_samples: u64,
    pending_discarded_sequence_samples: u32,
    consecutive_rejected_samples: u32,
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
    /// Accept the next sample, or return `None` if its sequence number is a
    /// duplicate or out of order.
    pub fn push(&mut self, sample: AdcQueueSample, rate: GraphSampleRate) -> Option<MeasurementSample> {
        let vbus_uv = sample.vbus.get::<microvolt>().round() as i64;
        let ibus_ua = sample.ibus.get::<microampere>().round() as i64;
        let power_uw = sample.power.get::<microwatt>().round() as i64;
        let expected_ticks = u64::from(rate.sequence_step());

        // A single pass over `previous`: reject implausible steps, then use the
        // accepted delta both for the gap accounting and the integrators.
        let (missing_samples, delta_us) = match self.previous {
            None => (0, 0),
            Some(previous) => {
                let delta_ticks = sample.sequence.wrapping_sub(previous.sequence);
                let plausible = delta_ticks != 0
                    && delta_ticks <= max_forward_sequence_ticks(rate)
                    && delta_ticks.is_multiple_of(rate.sequence_step());

                if !plausible {
                    self.cumulative_discarded_sequence_samples =
                        self.cumulative_discarded_sequence_samples.saturating_add(1);
                    self.pending_discarded_sequence_samples = self.pending_discarded_sequence_samples.saturating_add(1);
                    self.consecutive_rejected_samples = self.consecutive_rejected_samples.saturating_add(1);

                    // The counter wraps every 65.5 s, so a long stall looks
                    // exactly like an out-of-order sample. Restart continuity
                    // instead of rejecting every sample from here on.
                    if self.consecutive_rejected_samples >= MAX_CONSECUTIVE_REJECTED_SAMPLES {
                        self.previous = None;
                        self.consecutive_rejected_samples = 0;
                    }
                    return None;
                }

                (
                    rate.missing_samples(previous.sequence, sample.sequence),
                    u64::from(delta_ticks) * MICROSECONDS_PER_MILLISECOND,
                )
            }
        };
        self.consecutive_rejected_samples = 0;
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
            sample_rate_hz: rate.frequency().get::<hertz>() as u16,
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

    /// Start a new continuity run, keeping the elapsed time and the integrals.
    ///
    /// Call this when streaming restarts, for example after a rate change: the
    /// sequence counter of the new stream is unrelated to the old one.
    pub fn reset_continuity(&mut self) {
        self.previous = None;
        self.consecutive_rejected_samples = 0;
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub const fn cumulative_discarded_sequence_samples(&self) -> u64 {
        self.cumulative_discarded_sequence_samples
    }
}

/// A quantity derived from a [`MeasurementSample`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metric {
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

impl Metric {
    pub const ALL: [Self; 13] = [
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

    pub const fn label(self) -> &'static str {
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

    /// Whether offline logs record this quantity. They do not store the CC and
    /// D+/D- lines.
    pub const fn supports_offline(self) -> bool {
        !matches!(self, Self::Cc1 | Self::Cc2 | Self::DPlus | Self::DMinus)
    }

    pub const fn unit(self) -> &'static str {
        match self {
            Self::Voltage | Self::Cc1 | Self::Cc2 | Self::DPlus | Self::DMinus => "V",
            Self::Current | Self::SignedCurrent => "A",
            Self::Power | Self::SignedPower => "W",
            Self::Charge | Self::SignedCharge => "mAh",
            Self::Energy | Self::SignedEnergy => "mWh",
        }
    }

    /// The value in [`Self::unit`].
    pub fn value(self, sample: &MeasurementSample) -> f64 {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use uom::si::electric_current::ampere;
    use uom::si::electric_potential::volt;
    use uom::si::f64::{ElectricCurrent, ElectricPotential};

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

        assert_eq!(Metric::Current.value(&measurement), 2.0);
        assert_eq!(Metric::SignedCurrent.value(&measurement), -2.0);
        assert_eq!(Metric::Power.value(&measurement), 10.0);
        assert_eq!(Metric::SignedPower.value(&measurement), -10.0);
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
    fn a_long_gap_at_the_slowest_rate_is_still_a_gap() {
        // Regression: the accept window used to be a fixed 32767 ticks, so at
        // 2 SPS any stall past ~33 s was misread as an out-of-order sample.
        let mut accumulator = MeasurementAccumulator::default();
        accumulator.push(sample(0, 5.0, 1.0), GraphSampleRate::Sps2).unwrap();

        let after_gap = accumulator
            .push(sample(32_500, 5.0, 1.0), GraphSampleRate::Sps2)
            .unwrap();

        assert_eq!(after_gap.elapsed_us, 32_500_000);
        assert_eq!(after_gap.missing_samples, 64);
        assert_eq!(after_gap.cumulative_discarded_sequence_samples, 0);
    }

    #[test]
    fn continuity_restarts_after_a_run_of_rejected_samples() {
        // Past half the counter range the direction of a step is ambiguous.
        // Without a restart the accumulator rejected every later sample until
        // the counter happened to wrap back into the accept window.
        let mut accumulator = MeasurementAccumulator::default();
        accumulator.push(sample(0, 5.0, 1.0), GraphSampleRate::Sps1000).unwrap();

        for step in 1..=MAX_CONSECUTIVE_REJECTED_SAMPLES {
            assert!(
                accumulator
                    .push(sample(40_000 + step as u16, 5.0, 1.0), GraphSampleRate::Sps1000)
                    .is_none(),
                "ambiguous step {step} must be rejected"
            );
        }

        let resumed = accumulator
            .push(sample(50_000, 5.0, 1.0), GraphSampleRate::Sps1000)
            .unwrap();
        assert_eq!(resumed.missing_samples, 0, "a restarted run reports no false gap");
        assert_eq!(
            accumulator.cumulative_discarded_sequence_samples(),
            u64::from(MAX_CONSECUTIVE_REJECTED_SAMPLES),
            "rejected samples stay visible in the quality counters"
        );
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
