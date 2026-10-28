use std::borrow::Cow;

use tracing::warn;
use uom::si::electric_charge::microampere_hour;
use uom::si::electric_current::microampere;
use uom::si::electric_potential::microvolt;
use uom::si::energy::microwatt_hour;
use uom::si::f64::{ElectricCharge, ElectricCurrent, ElectricPotential, Energy, Power, Time};
use uom::si::time::{millisecond, second};
use zerocopy::byteorder::little_endian::{I32, U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::error::KMError;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Current above anything a KM003C records. One sample interval at this current
/// is the most a trailing partial interval can add when the stored samples never
/// saw a larger step.
const OFFLINE_LOG_FULL_SCALE_CURRENT_UA: u64 = 20_000_000;
/// Power at 50 V and [`OFFLINE_LOG_FULL_SCALE_CURRENT_UA`].
const OFFLINE_LOG_FULL_SCALE_POWER_UW: u64 = 1_000_000_000;
const MILLISECONDS_PER_HOUR: u64 = 3_600_000;

/// Device memory address containing the currently selected offline log.
pub const OFFLINE_LOG_ADDRESS: u32 = 0x9810_0000;
/// Size of a `LogMetadata` payload.
pub const LOG_METADATA_SIZE: usize = 48;
/// Size of one offline log sample.
pub const OFFLINE_LOG_SAMPLE_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct LogMetadataWire {
    filename: [u8; 16],
    unknown_0x10: U16,
    sample_count: U16,
    interval_ms: U16,
    flags: U16,
    recorded_duration_seconds: U32,
    final_charge_uah: I32,
    final_energy_uwh: I32,
    data_offset: U32,
    reserved_tail: [u8; 8],
}

/// Metadata describing the offline log selected on the device.
///
/// Fields whose meaning has not been established are preserved verbatim and
/// deliberately named after their wire position rather than guessed.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "python", pyo3::pyclass(skip_from_py_object))]
pub struct LogMetadata {
    pub filename_raw: [u8; 16],
    pub unknown_0x10: u16,
    pub sample_count: u16,
    pub interval: Time,
    pub flags: u16,
    pub recorded_duration: Time,
    pub final_charge: ElectricCharge,
    pub final_energy: Energy,
    /// Offset from `OFFLINE_LOG_ADDRESS` at which this log's samples begin.
    pub data_offset: u32,
    pub reserved_tail: [u8; 8],
}

impl LogMetadata {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KMError> {
        if bytes.len() != LOG_METADATA_SIZE {
            return Err(KMError::InvalidPacket(format!(
                "LogMetadata payload must be exactly {LOG_METADATA_SIZE} bytes, got {}",
                bytes.len()
            )));
        }

        let wire = LogMetadataWire::ref_from_bytes(bytes)
            .map_err(|_| KMError::InvalidPacket("Failed to parse LogMetadata".to_string()))?;

        Ok(Self {
            filename_raw: wire.filename,
            unknown_0x10: wire.unknown_0x10.get(),
            sample_count: wire.sample_count.get(),
            interval: Time::new::<millisecond>(f64::from(wire.interval_ms.get())),
            flags: wire.flags.get(),
            recorded_duration: Time::new::<second>(f64::from(wire.recorded_duration_seconds.get())),
            final_charge: ElectricCharge::new::<microampere_hour>(f64::from(wire.final_charge_uah.get())),
            final_energy: Energy::new::<microwatt_hour>(f64::from(wire.final_energy_uwh.get())),
            data_offset: wire.data_offset.get(),
            reserved_tail: wire.reserved_tail,
        })
    }

    /// Filename bytes up to the first NUL terminator.
    pub fn filename_bytes(&self) -> &[u8] {
        let length = self
            .filename_raw
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(self.filename_raw.len());
        &self.filename_raw[..length]
    }

    pub fn filename(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(self.filename_bytes())
    }

    pub fn filename_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.filename_bytes())
    }

    pub const fn data_size(&self) -> u32 {
        self.sample_count as u32 * OFFLINE_LOG_SAMPLE_SIZE as u32
    }

    pub fn data_address(&self) -> Result<u32, KMError> {
        OFFLINE_LOG_ADDRESS.checked_add(self.data_offset).ok_or_else(|| {
            KMError::Protocol(format!(
                "Offline log data offset 0x{:08X} overflows the base address",
                self.data_offset
            ))
        })
    }

    pub fn final_charge_raw_uah(&self) -> i32 {
        self.final_charge.get::<microampere_hour>().round() as i32
    }

    pub fn final_energy_raw_uwh(&self) -> i32 {
        self.final_energy.get::<microwatt_hour>().round() as i32
    }

    /// Duration implied by the sample count and interval.
    pub fn calculated_duration(&self) -> Time {
        self.interval * f64::from(self.sample_count.saturating_sub(1))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        LogMetadataWire {
            filename: self.filename_raw,
            unknown_0x10: U16::new(self.unknown_0x10),
            sample_count: U16::new(self.sample_count),
            interval_ms: U16::new(self.interval.get::<millisecond>().round() as u16),
            flags: U16::new(self.flags),
            recorded_duration_seconds: U32::new(self.recorded_duration.get::<second>().round() as u32),
            final_charge_uah: I32::new(self.final_charge_raw_uah()),
            final_energy_uwh: I32::new(self.final_energy_raw_uwh()),
            data_offset: U32::new(self.data_offset),
            reserved_tail: self.reserved_tail,
        }
        .as_bytes()
        .to_vec()
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl LogMetadata {
    #[getter(filename)]
    fn py_filename(&self) -> String {
        self.filename_lossy().into_owned()
    }

    #[getter]
    fn filename_raw(&self) -> Vec<u8> {
        self.filename_raw.to_vec()
    }

    #[getter]
    fn unknown_0x10(&self) -> u16 {
        self.unknown_0x10
    }

    #[getter]
    fn sample_count(&self) -> u16 {
        self.sample_count
    }

    #[getter]
    fn interval_ms(&self) -> f64 {
        self.interval.get::<millisecond>()
    }

    #[getter]
    fn flags(&self) -> u16 {
        self.flags
    }

    #[getter]
    fn recorded_duration_s(&self) -> f64 {
        self.recorded_duration.get::<second>()
    }

    #[getter]
    fn calculated_duration_s(&self) -> f64 {
        self.calculated_duration().get::<second>()
    }

    #[getter]
    fn final_charge_uah(&self) -> i32 {
        self.final_charge_raw_uah()
    }

    #[getter]
    fn final_energy_uwh(&self) -> i32 {
        self.final_energy_raw_uwh()
    }

    #[getter]
    fn data_offset(&self) -> u32 {
        self.data_offset
    }

    #[getter(data_size)]
    fn py_data_size(&self) -> u32 {
        self.data_size()
    }

    #[getter(data_address)]
    fn py_data_address(&self) -> pyo3::PyResult<u32> {
        self.data_address()
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))
    }

    #[getter]
    fn reserved_tail(&self) -> Vec<u8> {
        self.reserved_tail.to_vec()
    }

    fn __repr__(&self) -> String {
        format!(
            "LogMetadata(filename={:?}, samples={}, interval={}ms)",
            self.filename_lossy(),
            self.sample_count,
            self.interval.get::<millisecond>()
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}

/// Response to a `LogMetadata` request.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum LogMetadataResponse {
    /// No offline log is currently available.
    Empty,
    Available(Vec<LogMetadata>),
}

#[cfg(feature = "python")]
impl<'py> pyo3::IntoPyObject<'py> for LogMetadataResponse {
    type Target = pyo3::PyAny;
    type Output = pyo3::Bound<'py, Self::Target>;
    type Error = pyo3::PyErr;

    fn into_pyobject(self, py: pyo3::Python<'py>) -> Result<Self::Output, Self::Error> {
        match self {
            Self::Empty => Ok(py.None().into_bound(py)),
            Self::Available(metadata) => Ok(metadata.into_pyobject(py)?.into_any()),
        }
    }
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct OfflineLogSampleWire {
    voltage_uv: I32,
    current_ua: I32,
    charge_uah: I32,
    energy_uwh: I32,
}

/// Lossless wire representation of one offline log sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OfflineLogSampleRaw {
    pub voltage_uv: i32,
    pub current_ua: i32,
    pub charge_uah: i32,
    pub energy_uwh: i32,
}

impl OfflineLogSampleRaw {
    /// Decode one 16-byte wire sample.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, KMError> {
        OfflineLogSampleWire::ref_from_bytes(bytes)
            .map(|wire| Self::from(*wire))
            .map_err(|_| KMError::InvalidPacket("Failed to parse offline log sample".to_string()))
    }

    pub fn decode(self) -> OfflineLogSample {
        let voltage = ElectricPotential::new::<microvolt>(f64::from(self.voltage_uv));
        let current = ElectricCurrent::new::<microampere>(f64::from(self.current_ua));
        OfflineLogSample {
            raw: self,
            voltage,
            current,
            power: voltage * current,
            charge: ElectricCharge::new::<microampere_hour>(f64::from(self.charge_uah)),
            energy: Energy::new::<microwatt_hour>(f64::from(self.energy_uwh)),
        }
    }
}

impl From<OfflineLogSampleWire> for OfflineLogSampleRaw {
    fn from(wire: OfflineLogSampleWire) -> Self {
        Self {
            voltage_uv: wire.voltage_uv.get(),
            current_ua: wire.current_ua.get(),
            charge_uah: wire.charge_uah.get(),
            energy_uwh: wire.energy_uwh.get(),
        }
    }
}

impl From<OfflineLogSampleRaw> for OfflineLogSampleWire {
    fn from(raw: OfflineLogSampleRaw) -> Self {
        Self {
            voltage_uv: I32::new(raw.voltage_uv),
            current_ua: I32::new(raw.current_ua),
            charge_uah: I32::new(raw.charge_uah),
            energy_uwh: I32::new(raw.energy_uwh),
        }
    }
}

/// One decoded offline log sample with typed physical quantities.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OfflineLogSample {
    raw: OfflineLogSampleRaw,
    pub voltage: ElectricPotential,
    pub current: ElectricCurrent,
    pub power: Power,
    pub charge: ElectricCharge,
    pub energy: Energy,
}

impl OfflineLogSample {
    pub const fn raw(&self) -> OfflineLogSampleRaw {
        self.raw
    }
}

/// A complete offline log downloaded from the device.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OfflineLog {
    pub metadata: LogMetadata,
    pub samples: Vec<OfflineLogSample>,
}

impl OfflineLog {
    /// Decode the samples that belong to `metadata`.
    ///
    /// The catalog header holds the live charge and energy at the moment
    /// recording stopped. Samples are written on interval boundaries, so the
    /// last sample can differ from that header by up to one sample interval.
    /// A larger gap means these bytes are not this catalog entry.
    pub fn from_bytes(metadata: LogMetadata, bytes: &[u8]) -> Result<Self, KMError> {
        let expected = metadata.data_size() as usize;
        if bytes.len() != expected {
            return Err(KMError::InvalidPacket(format!(
                "Offline log data length mismatch: metadata expects {expected} bytes, got {}",
                bytes.len()
            )));
        }

        let samples = bytes
            .as_chunks::<OFFLINE_LOG_SAMPLE_SIZE>()
            .0
            .iter()
            .map(|bytes| OfflineLogSampleRaw::from_wire_bytes(bytes).map(OfflineLogSampleRaw::decode))
            .collect::<Result<Vec<_>, _>>()?;

        check_final_accumulators(&metadata, &samples)?;

        Ok(Self { metadata, samples })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.samples.len() * OFFLINE_LOG_SAMPLE_SIZE);
        for sample in &self.samples {
            bytes.extend_from_slice(OfflineLogSampleWire::from(sample.raw()).as_bytes());
        }
        bytes
    }
}

/// µAh or µWh accumulated over `interval_ms` at a per-second rate in µA or µW.
fn micro_hours(rate_micro: u64, interval_ms: u64) -> u64 {
    rate_micro.saturating_mul(interval_ms).div_ceil(MILLISECONDS_PER_HOUR)
}

fn interval_milliseconds(interval: Time) -> u64 {
    let milliseconds = interval.get::<millisecond>().round();
    if !milliseconds.is_finite() || milliseconds <= 0.0 {
        return 0;
    }
    u64::from(milliseconds.min(f64::from(u16::MAX)) as u16)
}

/// Charge and energy one sample interval can add at the full-scale ceiling.
fn full_scale_interval_allowance(interval: Time) -> (u64, u64) {
    let interval_ms = interval_milliseconds(interval);
    (
        micro_hours(OFFLINE_LOG_FULL_SCALE_CURRENT_UA, interval_ms),
        micro_hours(OFFLINE_LOG_FULL_SCALE_POWER_UW, interval_ms),
    )
}

/// Largest charge and energy step already stored between neighboring samples.
fn max_accumulator_step(samples: &[OfflineLogSample]) -> (u64, u64) {
    let mut charge = 0;
    let mut energy = 0;
    for pair in samples.windows(2) {
        let previous = pair[0].raw();
        let current = pair[1].raw();
        charge = charge.max(u64::from(previous.charge_uah.abs_diff(current.charge_uah)));
        energy = energy.max(u64::from(previous.energy_uwh.abs_diff(current.energy_uwh)));
    }
    (charge, energy)
}

fn accumulator_totals(sample_charge: i32, sample_energy: i32, metadata_charge: i32, metadata_energy: i32) -> String {
    format!(
        "sample has charge={sample_charge} µAh and energy={sample_energy} µWh, metadata has charge={metadata_charge} µAh and energy={metadata_energy} µWh"
    )
}

fn check_final_accumulators(metadata: &LogMetadata, samples: &[OfflineLogSample]) -> Result<(), KMError> {
    let Some(last) = samples.last() else {
        return Ok(());
    };
    let raw = last.raw();
    let sample_charge = raw.charge_uah;
    let sample_energy = raw.energy_uwh;
    let metadata_charge = metadata.final_charge_raw_uah();
    let metadata_energy = metadata.final_energy_raw_uwh();
    let charge_gap = u64::from(sample_charge.abs_diff(metadata_charge));
    let energy_gap = u64::from(sample_energy.abs_diff(metadata_energy));
    if charge_gap == 0 && energy_gap == 0 {
        return Ok(());
    }

    let (step_charge, step_energy) = max_accumulator_step(samples);
    let (scale_charge, scale_energy) = full_scale_interval_allowance(metadata.interval);
    if charge_gap > step_charge.max(scale_charge) || energy_gap > step_energy.max(scale_energy) {
        return Err(KMError::InvalidPacket(format!(
            "Offline log final accumulators do not match metadata: {}",
            accumulator_totals(sample_charge, sample_energy, metadata_charge, metadata_energy)
        )));
    }

    warn!(
        "Offline log final accumulators differ from metadata within one sample interval: {}",
        accumulator_totals(sample_charge, sample_energy, metadata_charge, metadata_energy)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use uom::si::electric_charge::{microampere_hour, milliampere_hour};
    use uom::si::electric_current::ampere;
    use uom::si::electric_potential::volt;
    use uom::si::energy::{microwatt_hour, milliwatt_hour};
    use uom::si::f64::{ElectricCharge, Energy};
    use uom::si::time::{millisecond, second};

    use super::*;

    const CAPTURED_METADATA: &str = concat!(
        "4130312e640000000000000000000000",
        "450a09021027000050140000",
        "a1a2f3ffe04da8ff000000000000000000000000"
    );

    #[test]
    fn parses_and_round_trips_captured_metadata() {
        let bytes = hex::decode(CAPTURED_METADATA).unwrap();
        let metadata = LogMetadata::from_bytes(&bytes).unwrap();

        assert_eq!(metadata.filename().unwrap(), "A01.d");
        assert_eq!(metadata.unknown_0x10, 0x0a45);
        assert_eq!(metadata.sample_count, 521);
        assert_eq!(metadata.interval.get::<millisecond>(), 10_000.0);
        assert_eq!(metadata.flags, 0);
        assert_eq!(metadata.recorded_duration.get::<second>(), 5_200.0);
        assert_eq!(metadata.calculated_duration().get::<second>(), 5_200.0);
        assert_eq!(metadata.data_size(), 8_336);
        assert_eq!(metadata.final_charge.get::<microampere_hour>(), -810_335.0);
        assert!((metadata.final_energy.get::<microwatt_hour>() + 5_747_232.0).abs() < 1e-8);
        assert_eq!(metadata.data_offset, 0);
        assert_eq!(metadata.reserved_tail, [0; 8]);
        assert_eq!(metadata.to_bytes(), bytes);
    }

    #[test]
    fn parses_and_round_trips_captured_samples() {
        let raw_samples = [
            "81494c0021f0e2ff56ebffffb998ffff",
            "bcaa89006e25f2ff2dd5f8fff7fdd6ff",
            "cf2a8900947dfeffa1a2f3ffe04da8ff",
        ]
        .into_iter()
        .flat_map(|sample| hex::decode(sample).unwrap())
        .collect::<Vec<_>>();
        let mut metadata = LogMetadata::from_bytes(&hex::decode(CAPTURED_METADATA).unwrap()).unwrap();
        metadata.sample_count = 3;
        let log = OfflineLog::from_bytes(metadata, &raw_samples).unwrap();

        assert_eq!(log.samples[0].voltage.get::<volt>(), 4.999_553);
        assert_eq!(log.samples[0].current.get::<ampere>(), -1.904_607);
        assert_eq!(log.samples[0].charge.get::<milliampere_hour>(), -5.29);
        assert!((log.samples[0].energy.get::<milliwatt_hour>() + 26.439).abs() < 1e-12);
        assert_eq!(log.samples[1].raw().charge_uah, -469_715);
        assert_eq!(log.samples[1].raw().energy_uwh, -2_687_497);
        assert_eq!(log.samples[2].raw().voltage_uv, 8_989_391);
        assert_eq!(log.to_bytes(), raw_samples);
    }

    #[test]
    fn rejects_wrong_metadata_and_log_sizes() {
        assert!(LogMetadata::from_bytes(&[0; LOG_METADATA_SIZE - 1]).is_err());
        let mut metadata = LogMetadata::from_bytes(&hex::decode(CAPTURED_METADATA).unwrap()).unwrap();
        metadata.sample_count = 1;
        assert!(OfflineLog::from_bytes(metadata, &[0; OFFLINE_LOG_SAMPLE_SIZE - 1]).is_err());
    }

    fn encode_sample(
        voltage_uv: i32,
        current_ua: i32,
        charge_uah: i32,
        energy_uwh: i32,
    ) -> [u8; OFFLINE_LOG_SAMPLE_SIZE] {
        let wire = OfflineLogSampleWire::from(OfflineLogSampleRaw {
            voltage_uv,
            current_ua,
            charge_uah,
            energy_uwh,
        });
        wire.as_bytes().try_into().unwrap()
    }

    fn captured_metadata() -> LogMetadata {
        LogMetadata::from_bytes(&hex::decode(CAPTURED_METADATA).unwrap()).unwrap()
    }

    #[test]
    fn rejects_data_from_the_wrong_catalog_entry() {
        let mut metadata = captured_metadata();
        metadata.sample_count = 1;
        let wrong_sample = hex::decode("81494c0021f0e2ff56ebffffb998ffff").unwrap();
        let error = OfflineLog::from_bytes(metadata, &wrong_sample).unwrap_err();
        assert!(error.to_string().contains("final accumulators do not match"));
    }

    #[test]
    fn accepts_header_ahead_of_the_last_sample_by_a_partial_interval() {
        // Firmware 2.0.6, recording A01 from issue 53. The header leads the last
        // sample by 434 µAh and 3880 µWh, about 1.6 s at the recording's average current.
        let mut metadata = captured_metadata();
        metadata.sample_count = 1;
        metadata.final_charge = ElectricCharge::new::<microampere_hour>(-1_475_530.0);
        metadata.final_energy = Energy::new::<microwatt_hour>(-13_105_070.0);
        let bytes = encode_sample(8_989_391, -1_000_000, -1_475_096, -13_101_190);

        let log = OfflineLog::from_bytes(metadata, &bytes).unwrap();

        assert_eq!(log.samples[0].raw().charge_uah, -1_475_096);
        assert_eq!(log.samples[0].raw().energy_uwh, -13_101_190);
        assert_eq!(log.metadata.final_charge_raw_uah(), -1_475_530);
        assert_eq!(log.metadata.final_energy_raw_uwh(), -13_105_070);
    }

    #[test]
    fn rejects_accumulator_gap_beyond_one_interval() {
        let mut metadata = captured_metadata();
        metadata.sample_count = 1;
        let (charge_allowance, energy_allowance) = full_scale_interval_allowance(metadata.interval);
        let charge_gap = i32::try_from(charge_allowance).unwrap() + 1;
        let energy_gap = i32::try_from(energy_allowance).unwrap() + 1;

        metadata.final_charge = ElectricCharge::new::<microampere_hour>(f64::from(-charge_gap));
        metadata.final_energy = Energy::new::<microwatt_hour>(0.0);
        let charge_error = OfflineLog::from_bytes(metadata.clone(), &encode_sample(0, 0, 0, 0)).unwrap_err();
        assert!(charge_error.to_string().contains("final accumulators do not match"));

        metadata.final_charge = ElectricCharge::new::<microampere_hour>(0.0);
        metadata.final_energy = Energy::new::<microwatt_hour>(f64::from(-energy_gap));
        let energy_error = OfflineLog::from_bytes(metadata, &encode_sample(0, 0, 0, 0)).unwrap_err();
        assert!(energy_error.to_string().contains("final accumulators do not match"));
    }

    #[test]
    fn accepts_gap_as_large_as_an_earlier_sample_step() {
        let mut metadata = captured_metadata();
        metadata.sample_count = 2;
        let (charge_allowance, _) = full_scale_interval_allowance(metadata.interval);
        let step = i32::try_from(charge_allowance).unwrap() + 1_000;
        metadata.final_charge = ElectricCharge::new::<microampere_hour>(f64::from(step * 2));
        metadata.final_energy = Energy::new::<microwatt_hour>(0.0);
        let mut bytes = encode_sample(0, 0, 0, 0).to_vec();
        bytes.extend_from_slice(&encode_sample(0, 0, step, 0));

        let log = OfflineLog::from_bytes(metadata.clone(), &bytes).unwrap();

        assert_eq!(log.samples[1].raw().charge_uah, step);
        assert_eq!(log.metadata.final_charge_raw_uah(), step * 2);

        metadata.final_charge = ElectricCharge::new::<microampere_hour>(f64::from(step * 2 + 1));
        let error = OfflineLog::from_bytes(metadata, &bytes).unwrap_err();
        assert!(error.to_string().contains("final accumulators do not match"));
    }

    #[test]
    fn parses_available_and_empty_captured_metadata_responses() {
        use bytes::Bytes;

        use crate::{Packet, RawPacket};

        let available = hex::decode(concat!(
            "4107c2020002000c",
            "4130312e640000000000000000000000",
            "450a09021027000050140000",
            "a1a2f3ffe04da8ff000000000000000000000000"
        ))
        .unwrap();
        let packet = Packet::try_from(RawPacket::try_from(Bytes::from(available)).unwrap()).unwrap();
        assert!(matches!(
            packet.get_log_metadata(),
            Some(LogMetadataResponse::Available(metadata)) if metadata.len() == 1 && metadata[0].sample_count == 521
        ));

        let empty = hex::decode("4108c2ff00020000").unwrap();
        let packet = Packet::try_from(RawPacket::try_from(Bytes::from(empty)).unwrap()).unwrap();
        assert_eq!(packet.get_log_metadata(), Some(&LogMetadataResponse::Empty));
    }
}
