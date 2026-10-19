//! One row of the recording schema, and its fixed-size journal encoding.

use crate::measurement::MeasurementSample;

/// Journal record size: the fields of [`RecordingRow`] in declaration order,
/// little-endian, with `interpolated` as one byte.
pub(crate) const ROW_SIZE: usize = 157;

/// Where a recording starts on the accumulator's timeline and totals.
///
/// Rows are relative to it, so a capture started mid-stream begins at zero.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct RecordingOrigin {
    elapsed_us: u64,
    charge_uah: f64,
    energy_uwh: f64,
    charge_throughput_uah: f64,
    energy_throughput_uwh: f64,
    cumulative_missing_samples: u64,
    cumulative_interpolated_duration_us: u64,
    cumulative_discarded_sequence_samples: u64,
}

impl From<Option<MeasurementSample>> for RecordingOrigin {
    fn from(sample: Option<MeasurementSample>) -> Self {
        sample.map_or_else(Self::default, |sample| Self {
            elapsed_us: sample.elapsed_us,
            charge_uah: sample.charge_uah,
            energy_uwh: sample.energy_uwh,
            charge_throughput_uah: sample.charge_throughput_uah,
            energy_throughput_uwh: sample.energy_throughput_uwh,
            cumulative_missing_samples: sample.cumulative_missing_samples,
            cumulative_interpolated_duration_us: sample.cumulative_interpolated_duration_us,
            cumulative_discarded_sequence_samples: sample.cumulative_discarded_sequence_samples,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct RecordingRow {
    pub(crate) elapsed_us: u64,
    pub(crate) sample_index: u64,
    pub(crate) sequence: u32,
    pub(crate) marker: u32,
    pub(crate) sample_rate_hz: u32,
    pub(crate) missing_samples: u32,
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

impl RecordingRow {
    pub(crate) fn from_sample(sample: MeasurementSample, origin: RecordingOrigin, sample_index: u64) -> Self {
        Self {
            elapsed_us: sample.elapsed_us.saturating_sub(origin.elapsed_us),
            sample_index,
            sequence: u32::from(sample.sequence),
            marker: u32::from(sample.marker),
            sample_rate_hz: u32::from(sample.sample_rate_hz),
            missing_samples: u32::from(sample.missing_samples),
            gap_duration_us: sample.gap_duration_us,
            interpolated: sample.interpolated,
            cumulative_missing_samples: sample
                .cumulative_missing_samples
                .saturating_sub(origin.cumulative_missing_samples),
            cumulative_interpolated_duration_us: sample
                .cumulative_interpolated_duration_us
                .saturating_sub(origin.cumulative_interpolated_duration_us),
            discarded_sequence_samples: sample.discarded_sequence_samples,
            cumulative_discarded_sequence_samples: sample
                .cumulative_discarded_sequence_samples
                .saturating_sub(origin.cumulative_discarded_sequence_samples),
            vbus_uv: sample.vbus_uv,
            ibus_ua: sample.ibus_ua,
            power_uw: sample.power_uw,
            charge_uah: sample.charge_uah - origin.charge_uah,
            energy_uwh: sample.energy_uwh - origin.energy_uwh,
            charge_throughput_uah: sample.charge_throughput_uah - origin.charge_throughput_uah,
            energy_throughput_uwh: sample.energy_throughput_uwh - origin.energy_throughput_uwh,
            cc1_uv: sample.cc1_uv,
            cc2_uv: sample.cc2_uv,
            dp_uv: sample.dp_uv,
            dm_uv: sample.dm_uv,
        }
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.elapsed_us.to_le_bytes());
        out.extend_from_slice(&self.sample_index.to_le_bytes());
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&self.marker.to_le_bytes());
        out.extend_from_slice(&self.sample_rate_hz.to_le_bytes());
        out.extend_from_slice(&self.missing_samples.to_le_bytes());
        out.extend_from_slice(&self.gap_duration_us.to_le_bytes());
        out.push(u8::from(self.interpolated));
        out.extend_from_slice(&self.cumulative_missing_samples.to_le_bytes());
        out.extend_from_slice(&self.cumulative_interpolated_duration_us.to_le_bytes());
        out.extend_from_slice(&self.discarded_sequence_samples.to_le_bytes());
        out.extend_from_slice(&self.cumulative_discarded_sequence_samples.to_le_bytes());
        for value in [self.vbus_uv, self.ibus_ua, self.power_uw] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        for value in [
            self.charge_uah,
            self.energy_uwh,
            self.charge_throughput_uah,
            self.energy_throughput_uwh,
        ] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        for value in [self.cc1_uv, self.cc2_uv, self.dp_uv, self.dm_uv] {
            out.extend_from_slice(&value.to_le_bytes());
        }
    }

    pub(crate) fn decode(record: &[u8; ROW_SIZE]) -> Self {
        let mut fields = Fields(record);
        Self {
            elapsed_us: fields.u64(),
            sample_index: fields.u64(),
            sequence: fields.u32(),
            marker: fields.u32(),
            sample_rate_hz: fields.u32(),
            missing_samples: fields.u32(),
            gap_duration_us: fields.u64(),
            interpolated: fields.take::<1>()[0] != 0,
            cumulative_missing_samples: fields.u64(),
            cumulative_interpolated_duration_us: fields.u64(),
            discarded_sequence_samples: fields.u32(),
            cumulative_discarded_sequence_samples: fields.u64(),
            vbus_uv: fields.i64(),
            ibus_ua: fields.i64(),
            power_uw: fields.i64(),
            charge_uah: fields.f64(),
            energy_uwh: fields.f64(),
            charge_throughput_uah: fields.f64(),
            energy_throughput_uwh: fields.f64(),
            cc1_uv: fields.i64(),
            cc2_uv: fields.i64(),
            dp_uv: fields.i64(),
            dm_uv: fields.i64(),
        }
    }
}

/// Reads a record's fields front to back.
struct Fields<'a>(&'a [u8]);

impl Fields<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let (field, rest) = self.0.split_at(N);
        self.0 = rest;
        field.try_into().expect("split at N")
    }

    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take())
    }

    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take())
    }

    fn i64(&mut self) -> i64 {
        i64::from_le_bytes(self.take())
    }

    fn f64(&mut self) -> f64 {
        f64::from_le_bytes(self.take())
    }
}

#[cfg(test)]
pub(crate) fn test_sample(elapsed_us: u64, missing: u64, interpolated_us: u64) -> MeasurementSample {
    MeasurementSample {
        elapsed_us,
        sample_index: 100,
        sequence: 42,
        marker: 7,
        sample_rate_hz: 50,
        missing_samples: missing as u16,
        gap_duration_us: interpolated_us,
        interpolated: missing > 0,
        cumulative_missing_samples: missing,
        cumulative_interpolated_duration_us: interpolated_us,
        discarded_sequence_samples: 0,
        cumulative_discarded_sequence_samples: 0,
        vbus_uv: 5_000_000,
        ibus_ua: -1_000_000,
        power_uw: -5_000_000,
        charge_uah: -100.0,
        energy_uwh: -500.0,
        charge_throughput_uah: 100.0,
        energy_throughput_uwh: 500.0,
        cc1_uv: 1_000_000,
        cc2_uv: 0,
        dp_uv: 600_000,
        dm_uv: 500_000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_are_relative_to_the_start() {
        let origin = RecordingOrigin::from(Some(test_sample(1_000_000, 2, 40_000)));
        let row = RecordingRow::from_sample(test_sample(2_000_000, 3, 60_000), origin, 0);

        assert_eq!(row.elapsed_us, 1_000_000);
        assert_eq!(row.sample_index, 0);
        assert_eq!(row.cumulative_missing_samples, 1);
        assert_eq!(row.cumulative_interpolated_duration_us, 20_000);
        assert_eq!(row.charge_uah, 0.0);
    }

    #[test]
    fn journal_encoding_round_trips() {
        let row = RecordingRow::from_sample(test_sample(20_000, 1, 20_000), RecordingOrigin::default(), 7);
        let mut bytes = Vec::new();
        row.encode(&mut bytes);

        assert_eq!(bytes.len(), ROW_SIZE);
        assert_eq!(RecordingRow::decode(bytes.as_slice().try_into().unwrap()), row);
    }
}
