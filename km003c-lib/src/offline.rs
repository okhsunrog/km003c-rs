use std::borrow::Cow;

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
    pub fn from_bytes(metadata: LogMetadata, bytes: &[u8]) -> Result<Self, KMError> {
        let expected = metadata.data_size() as usize;
        if bytes.len() != expected {
            return Err(KMError::InvalidPacket(format!(
                "Offline log data length mismatch: metadata expects {expected} bytes, got {}",
                bytes.len()
            )));
        }

        let samples = bytes
            .chunks_exact(OFFLINE_LOG_SAMPLE_SIZE)
            .map(|bytes| {
                OfflineLogSampleWire::ref_from_bytes(bytes)
                    .map(|wire| OfflineLogSampleRaw::from(*wire).decode())
                    .map_err(|_| KMError::InvalidPacket("Failed to parse offline log sample".to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        if let Some(last) = samples.last() {
            let raw = last.raw();
            if raw.charge_uah != metadata.final_charge_raw_uah() || raw.energy_uwh != metadata.final_energy_raw_uwh() {
                return Err(KMError::InvalidPacket(format!(
                    "Offline log final accumulators do not match metadata: sample has charge={} µAh and energy={} µWh, metadata has charge={} µAh and energy={} µWh",
                    raw.charge_uah,
                    raw.energy_uwh,
                    metadata.final_charge_raw_uah(),
                    metadata.final_energy_raw_uwh()
                )));
            }
        }

        Ok(Self { metadata, samples })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.samples
            .iter()
            .flat_map(|sample| OfflineLogSampleWire::from(sample.raw()).as_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use uom::si::electric_charge::milliampere_hour;
    use uom::si::electric_current::ampere;
    use uom::si::electric_potential::volt;
    use uom::si::energy::milliwatt_hour;
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

    #[test]
    fn rejects_data_from_the_wrong_catalog_entry() {
        let mut metadata = LogMetadata::from_bytes(&hex::decode(CAPTURED_METADATA).unwrap()).unwrap();
        metadata.sample_count = 1;
        let wrong_sample = hex::decode("81494c0021f0e2ff56ebffffb998ffff").unwrap();
        let error = OfflineLog::from_bytes(metadata, &wrong_sample).unwrap_err();
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
