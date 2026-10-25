//! KM003C scope session file.
//!
//! ```text
//! magic            b"KMSS"
//! version          u16 = 1
//! flags            u16   bit 0: host-time origin is present
//! host_origin_us   i64   unix microseconds, zero when the flag is clear
//! sample_count     u64
//! event_count      u64
//! break_count      u32
//! breaks_us        u64 × break_count
//! chunk_count      u32
//! chunks           repeated: sample_count u32, compressed_len u32, zstd payload
//! event_len        u64
//! events           zstd payload
//! ```
//!
//! Each chunk stores up to 65,536 samples. Integer channels are little-endian
//! i64 deltas from the previous sample, and the first sample in a chunk is a
//! delta from zero. Charge and energy are raw little-endian f64 bits.

#[cfg(not(target_arch = "wasm32"))]
use std::fs;
#[cfg(not(target_arch = "wasm32"))]
use std::io::Cursor;
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

use km003c_lib::MeasurementSample;

const MAGIC: &[u8; 4] = b"KMSS";
const VERSION: u16 = 1;
const FLAG_HOST_ORIGIN: u16 = 1;
const ZSTD_LEVEL: i32 = 1;
const CHUNK_SAMPLES: usize = 65_536;
/// Leave this fraction of the buffer free when appending a file onto a live capture.
pub const LIVE_LOAD_FILL: f64 = 0.95;
/// Empty time inserted before the capture that was already on screen.
pub const SESSION_GAP_US: u64 = 1_000_000;
/// A corrupt or hostile file cannot expand past twice the on-screen buffer.
const MAX_SESSION_SAMPLES: u64 = 1_800_000 * 2;

/// How many samples from the end of a file fit in the buffer.
///
/// A live capture stops at 95% so samples that arrive while the file is read
/// have room. A stopped capture can fill the buffer.
pub fn load_sample_budget(current_len: usize, file_len: usize, max_samples: usize, streaming: bool) -> usize {
    let fill = if streaming { LIVE_LOAD_FILL } else { 1.0 };
    let target = ((max_samples as f64) * fill).floor() as usize;
    target.saturating_sub(current_len).min(file_len)
}

/// Where to put a loaded block so it ends one gap before the current capture.
pub struct TimelinePlacement {
    /// Added to every sample already on screen, and to the live clock.
    pub current_pad_us: u64,
    /// `loaded_elapsed' = loaded_base + (loaded_elapsed - loaded_first)`.
    pub loaded_base_us: u64,
}

pub fn place_loaded_before(
    current_first_us: u64,
    loaded_first_us: u64,
    loaded_last_us: u64,
    gap_us: u64,
) -> TimelinePlacement {
    let span = loaded_last_us.saturating_sub(loaded_first_us);
    let need = span.saturating_add(gap_us);
    if current_first_us >= need {
        TimelinePlacement {
            current_pad_us: 0,
            loaded_base_us: current_first_us - need,
        }
    } else {
        TimelinePlacement {
            current_pad_us: need - current_first_us,
            loaded_base_us: 0,
        }
    }
}

pub fn map_loaded_elapsed(elapsed_us: u64, loaded_first_us: u64, loaded_base_us: u64) -> u64 {
    loaded_base_us + elapsed_us.saturating_sub(loaded_first_us)
}

/// Host-time origin plus elapsed microseconds, as a single UTC instant.
pub fn absolute_us(origin_us: i64, elapsed_us: u64) -> i128 {
    i128::from(origin_us).saturating_add(i128::from(elapsed_us))
}

/// Elapsed microseconds from `origin_us` back to a sample's UTC instant.
pub fn elapsed_on_origin(absolute_us: i128, origin_us: i128) -> u64 {
    let delta = absolute_us.saturating_sub(origin_us);
    if delta <= 0 {
        0
    } else {
        u64::try_from(delta).unwrap_or(u64::MAX)
    }
}

pub struct SessionData {
    pub host_origin_utc_us: Option<i64>,
    pub breaks_us: Vec<u64>,
    pub samples: Vec<MeasurementSample>,
    pub events: Vec<StoredEvent>,
}

pub struct StoredEvent {
    pub elapsed_us: u64,
    pub category: u8,
    pub label: String,
    pub name: String,
    pub details: String,
}

#[cfg(not(target_arch = "wasm32"))]
pub fn write_session(path: &Path, data: &SessionData) -> Result<(), String> {
    let bytes = encode(data)?;
    let tmp = path.with_extension("kmss.partial");
    fs::write(&tmp, bytes).map_err(|error| error.to_string())?;
    fs::rename(&tmp, path).map_err(|error| error.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn read_session(path: &Path) -> Result<SessionData, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    decode(&bytes)
}

pub fn encode(data: &SessionData) -> Result<Vec<u8>, String> {
    if data.samples.len() as u64 > MAX_SESSION_SAMPLES {
        return Err("session has too many samples".to_string());
    }
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    write_u16(&mut out, VERSION);
    let mut flags = 0;
    if data.host_origin_utc_us.is_some() {
        flags |= FLAG_HOST_ORIGIN;
    }
    write_u16(&mut out, flags);
    write_i64(&mut out, data.host_origin_utc_us.unwrap_or(0));
    write_u64(&mut out, data.samples.len() as u64);
    write_u64(&mut out, data.events.len() as u64);
    write_u32(&mut out, data.breaks_us.len() as u32);
    for gap in &data.breaks_us {
        write_u64(&mut out, *gap);
    }

    let chunks = encode_chunks(&data.samples)?;
    write_u32(&mut out, chunks.len() as u32);
    for (count, compressed) in chunks {
        write_u32(&mut out, count as u32);
        write_u32(&mut out, compressed.len() as u32);
        out.extend_from_slice(&compressed);
    }

    let events = compress(&encode_events(&data.events)?)?;
    write_u64(&mut out, events.len() as u64);
    out.extend_from_slice(&events);
    Ok(out)
}

pub fn decode(bytes: &[u8]) -> Result<SessionData, String> {
    let mut reader = Reader::new(bytes);
    let magic = reader.take(4)?;
    if magic != MAGIC {
        return Err("not a KM003C session".to_string());
    }
    let version = reader.u16()?;
    if version != VERSION {
        return Err(format!("unsupported session version {version}"));
    }
    let flags = reader.u16()?;
    let origin = reader.i64()?;
    let sample_count = reader.u64()?;
    let event_count = reader.u64()?;
    if sample_count > MAX_SESSION_SAMPLES {
        return Err("session has too many samples".to_string());
    }
    let break_count = reader.u32()? as usize;
    let mut breaks_us = Vec::with_capacity(break_count);
    for _ in 0..break_count {
        breaks_us.push(reader.u64()?);
    }

    let chunk_count = reader.u32()? as usize;
    let mut samples = Vec::with_capacity(sample_count as usize);
    for _ in 0..chunk_count {
        let count = reader.u32()? as usize;
        let compressed_len = reader.u32()? as usize;
        let compressed = reader.take(compressed_len)?;
        let raw = decompress(compressed)?;
        let decoded = decode_samples(&raw, count)?;
        samples.extend(decoded);
    }
    if samples.len() as u64 != sample_count {
        return Err("session sample count does not match its chunks".to_string());
    }

    let event_len = reader.u64()? as usize;
    let event_bytes = decompress(reader.take(event_len)?)?;
    let events = decode_events(&event_bytes, event_count as usize)?;
    samples.sort_by_key(|sample| sample.elapsed_us);
    breaks_us.sort_unstable();
    Ok(SessionData {
        host_origin_utc_us: ((flags & FLAG_HOST_ORIGIN) != 0).then_some(origin),
        breaks_us,
        samples,
        events,
    })
}

fn encode_chunks(samples: &[MeasurementSample]) -> Result<Vec<(usize, Vec<u8>)>, String> {
    let mut chunks = Vec::new();
    let mut offset = 0;
    while offset < samples.len() {
        let (count, raw) = encode_chunk(&samples[offset..])?;
        if count == 0 {
            return Err("could not encode a sample chunk".to_string());
        }
        chunks.push((count, compress(&raw)?));
        offset += count;
    }
    Ok(chunks)
}

fn encode_chunk(samples: &[MeasurementSample]) -> Result<(usize, Vec<u8>), String> {
    let mut raw = Vec::new();
    let mut prev = SampleInts::default();
    let mut count = 0;
    for sample in samples.iter().take(CHUNK_SAMPLES) {
        let Some(record) = encode_sample(sample, &prev) else {
            break;
        };
        raw.extend_from_slice(&record);
        prev = SampleInts::from_sample(sample);
        count += 1;
    }
    if count == 0 {
        return Err("a sample does not fit in the session encoding".to_string());
    }
    Ok((count, raw))
}

fn decode_samples(raw: &[u8], count: usize) -> Result<Vec<MeasurementSample>, String> {
    let mut reader = Reader::new(raw);
    let mut prev = SampleInts::default();
    let mut samples = Vec::with_capacity(count);
    for _ in 0..count {
        let (sample, next) = decode_sample(&mut reader, &prev)?;
        prev = next;
        samples.push(sample);
    }
    if reader.remaining() != 0 {
        return Err("sample chunk has trailing bytes".to_string());
    }
    Ok(samples)
}

#[derive(Clone, Copy, Default)]
struct SampleInts {
    elapsed_us: u64,
    sample_index: u64,
    gap_duration_us: u64,
    cumulative_missing_samples: u64,
    cumulative_interpolated_duration_us: u64,
    cumulative_discarded_sequence_samples: u64,
    vbus_uv: i64,
    ibus_ua: i64,
    power_uw: i64,
    cc1_uv: i64,
    cc2_uv: i64,
    dp_uv: i64,
    dm_uv: i64,
}

impl SampleInts {
    fn from_sample(sample: &MeasurementSample) -> Self {
        Self {
            elapsed_us: sample.elapsed_us,
            sample_index: sample.sample_index,
            gap_duration_us: sample.gap_duration_us,
            cumulative_missing_samples: sample.cumulative_missing_samples,
            cumulative_interpolated_duration_us: sample.cumulative_interpolated_duration_us,
            cumulative_discarded_sequence_samples: sample.cumulative_discarded_sequence_samples,
            vbus_uv: sample.vbus_uv,
            ibus_ua: sample.ibus_ua,
            power_uw: sample.power_uw,
            cc1_uv: sample.cc1_uv,
            cc2_uv: sample.cc2_uv,
            dp_uv: sample.dp_uv,
            dm_uv: sample.dm_uv,
        }
    }
}

fn encode_sample(sample: &MeasurementSample, prev: &SampleInts) -> Option<[u8; 149]> {
    let mut record = [0; 149];
    let mut cursor = 0;
    write_delta_u64(&mut record, &mut cursor, prev.elapsed_us, sample.elapsed_us)?;
    write_delta_u64(&mut record, &mut cursor, prev.sample_index, sample.sample_index)?;
    write_delta_u64(&mut record, &mut cursor, prev.gap_duration_us, sample.gap_duration_us)?;
    write_delta_u64(
        &mut record,
        &mut cursor,
        prev.cumulative_missing_samples,
        sample.cumulative_missing_samples,
    )?;
    write_delta_u64(
        &mut record,
        &mut cursor,
        prev.cumulative_interpolated_duration_us,
        sample.cumulative_interpolated_duration_us,
    )?;
    write_delta_u64(
        &mut record,
        &mut cursor,
        prev.cumulative_discarded_sequence_samples,
        sample.cumulative_discarded_sequence_samples,
    )?;
    write_delta_i64(&mut record, &mut cursor, prev.vbus_uv, sample.vbus_uv)?;
    write_delta_i64(&mut record, &mut cursor, prev.ibus_ua, sample.ibus_ua)?;
    write_delta_i64(&mut record, &mut cursor, prev.power_uw, sample.power_uw)?;
    write_delta_i64(&mut record, &mut cursor, prev.cc1_uv, sample.cc1_uv)?;
    write_delta_i64(&mut record, &mut cursor, prev.cc2_uv, sample.cc2_uv)?;
    write_delta_i64(&mut record, &mut cursor, prev.dp_uv, sample.dp_uv)?;
    write_delta_i64(&mut record, &mut cursor, prev.dm_uv, sample.dm_uv)?;
    record[cursor..cursor + 2].copy_from_slice(&sample.sequence.to_le_bytes());
    cursor += 2;
    record[cursor..cursor + 2].copy_from_slice(&sample.marker.to_le_bytes());
    cursor += 2;
    record[cursor..cursor + 2].copy_from_slice(&sample.sample_rate_hz.to_le_bytes());
    cursor += 2;
    record[cursor..cursor + 2].copy_from_slice(&sample.missing_samples.to_le_bytes());
    cursor += 2;
    record[cursor..cursor + 4].copy_from_slice(&sample.discarded_sequence_samples.to_le_bytes());
    cursor += 4;
    record[cursor] = u8::from(sample.interpolated);
    cursor += 1;
    write_f64(&mut record, &mut cursor, sample.charge_uah);
    write_f64(&mut record, &mut cursor, sample.energy_uwh);
    write_f64(&mut record, &mut cursor, sample.charge_throughput_uah);
    write_f64(&mut record, &mut cursor, sample.energy_throughput_uwh);
    Some(record)
}

fn decode_sample(reader: &mut Reader<'_>, prev: &SampleInts) -> Result<(MeasurementSample, SampleInts), String> {
    let elapsed_us = apply_delta_u64(prev.elapsed_us, reader.i64()?)?;
    let sample_index = apply_delta_u64(prev.sample_index, reader.i64()?)?;
    let gap_duration_us = apply_delta_u64(prev.gap_duration_us, reader.i64()?)?;
    let cumulative_missing_samples = apply_delta_u64(prev.cumulative_missing_samples, reader.i64()?)?;
    let cumulative_interpolated_duration_us = apply_delta_u64(prev.cumulative_interpolated_duration_us, reader.i64()?)?;
    let cumulative_discarded_sequence_samples =
        apply_delta_u64(prev.cumulative_discarded_sequence_samples, reader.i64()?)?;
    let vbus_uv = apply_delta_i64(prev.vbus_uv, reader.i64()?)?;
    let ibus_ua = apply_delta_i64(prev.ibus_ua, reader.i64()?)?;
    let power_uw = apply_delta_i64(prev.power_uw, reader.i64()?)?;
    let cc1_uv = apply_delta_i64(prev.cc1_uv, reader.i64()?)?;
    let cc2_uv = apply_delta_i64(prev.cc2_uv, reader.i64()?)?;
    let dp_uv = apply_delta_i64(prev.dp_uv, reader.i64()?)?;
    let dm_uv = apply_delta_i64(prev.dm_uv, reader.i64()?)?;
    let sequence = reader.u16()?;
    let marker = reader.u16()?;
    let sample_rate_hz = reader.u16()?;
    let missing_samples = reader.u16()?;
    let discarded_sequence_samples = reader.u32()?;
    let interpolated = reader.u8()? != 0;
    let charge_uah = reader.f64()?;
    let energy_uwh = reader.f64()?;
    let charge_throughput_uah = reader.f64()?;
    let energy_throughput_uwh = reader.f64()?;
    let next = SampleInts {
        elapsed_us,
        sample_index,
        gap_duration_us,
        cumulative_missing_samples,
        cumulative_interpolated_duration_us,
        cumulative_discarded_sequence_samples,
        vbus_uv,
        ibus_ua,
        power_uw,
        cc1_uv,
        cc2_uv,
        dp_uv,
        dm_uv,
    };
    let sample = MeasurementSample {
        elapsed_us,
        sample_index,
        sequence,
        marker,
        sample_rate_hz,
        missing_samples,
        gap_duration_us,
        interpolated,
        cumulative_missing_samples,
        cumulative_interpolated_duration_us,
        discarded_sequence_samples,
        cumulative_discarded_sequence_samples,
        vbus_uv,
        ibus_ua,
        power_uw,
        charge_uah,
        energy_uwh,
        charge_throughput_uah,
        energy_throughput_uwh,
        cc1_uv,
        cc2_uv,
        dp_uv,
        dm_uv,
    };
    Ok((sample, next))
}

fn encode_events(events: &[StoredEvent]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for event in events {
        write_u64(&mut out, event.elapsed_us);
        out.push(event.category);
        write_str(&mut out, &event.label, false)?;
        write_str(&mut out, &event.name, false)?;
        write_str(&mut out, &event.details, true)?;
    }
    Ok(out)
}

fn decode_events(bytes: &[u8], count: usize) -> Result<Vec<StoredEvent>, String> {
    let mut reader = Reader::new(bytes);
    let mut events = Vec::with_capacity(count);
    for _ in 0..count {
        events.push(StoredEvent {
            elapsed_us: reader.u64()?,
            category: reader.u8()?,
            label: reader.str(false)?,
            name: reader.str(false)?,
            details: reader.str(true)?,
        });
    }
    if reader.remaining() != 0 {
        return Err("event section has trailing bytes".to_string());
    }
    events.sort_by_key(|event| event.elapsed_us);
    Ok(events)
}

fn write_delta_u64(record: &mut [u8; 149], cursor: &mut usize, prev: u64, next: u64) -> Option<()> {
    let delta = i64::try_from(i128::from(next) - i128::from(prev)).ok()?;
    record[*cursor..*cursor + 8].copy_from_slice(&delta.to_le_bytes());
    *cursor += 8;
    Some(())
}

fn write_delta_i64(record: &mut [u8; 149], cursor: &mut usize, prev: i64, next: i64) -> Option<()> {
    let delta = next.checked_sub(prev)?;
    record[*cursor..*cursor + 8].copy_from_slice(&delta.to_le_bytes());
    *cursor += 8;
    Some(())
}

fn write_f64(record: &mut [u8; 149], cursor: &mut usize, value: f64) {
    record[*cursor..*cursor + 8].copy_from_slice(&value.to_le_bytes());
    *cursor += 8;
}

fn apply_delta_u64(prev: u64, delta: i64) -> Result<u64, String> {
    u64::try_from(i128::from(prev) + i128::from(delta)).map_err(|_| "sample delta is out of range".to_string())
}

fn apply_delta_i64(prev: i64, delta: i64) -> Result<i64, String> {
    prev.checked_add(delta)
        .ok_or_else(|| "sample delta is out of range".to_string())
}

fn compress(bytes: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        zstd::stream::encode_all(Cursor::new(bytes), ZSTD_LEVEL).map_err(|error| error.to_string())
    }
    #[cfg(target_arch = "wasm32")]
    {
        // The browser has no C toolchain for libzstd. This level is the pure-Rust
        // match for the desktop compressor's level 1, and both decoders accept either frame.
        let _ = ZSTD_LEVEL;
        let mut compressed = Vec::new();
        ruzstd::encoding::compress(bytes, &mut compressed, ruzstd::encoding::CompressionLevel::Fastest);
        Ok(compressed)
    }
}

fn decompress(bytes: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        zstd::stream::decode_all(Cursor::new(bytes)).map_err(|error| error.to_string())
    }
    #[cfg(target_arch = "wasm32")]
    {
        let mut source = bytes;
        let mut decoder = ruzstd::decoding::StreamingDecoder::new(&mut source).map_err(|error| error.to_string())?;
        let mut decoded = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut decoded).map_err(|error| error.to_string())?;
        Ok(decoded)
    }
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_str(out: &mut Vec<u8>, value: &str, wide: bool) -> Result<(), String> {
    let bytes = value.as_bytes();
    if wide {
        let len = u32::try_from(bytes.len()).map_err(|_| "event text is too long".to_string())?;
        write_u32(out, len);
    } else {
        let len = u16::try_from(bytes.len()).map_err(|_| "event text is too long".to_string())?;
        write_u16(out, len);
    }
    out.extend_from_slice(bytes);
    Ok(())
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| "truncated session".to_string())?;
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, String> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn i64(&mut self) -> Result<i64, String> {
        let bytes = self.take(8)?;
        Ok(i64::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn f64(&mut self) -> Result<f64, String> {
        let bytes = self.take(8)?;
        Ok(f64::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn str(&mut self, wide: bool) -> Result<String, String> {
        let len = if wide {
            self.u32()? as usize
        } else {
            usize::from(self.u16()?)
        };
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| "event text is not utf-8".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_load_keeps_five_percent_free() {
        let max = 1_800_000;
        let current = (max as f64 * 0.65) as usize;
        let file = (max as f64 * 0.50) as usize;
        let budget = load_sample_budget(current, file, max, true);
        assert_eq!(budget, (max as f64 * 0.30) as usize);
        assert_eq!(budget * 100 / file, 60);
        assert_eq!(load_sample_budget(0, max, max, false), max);
        assert_eq!(load_sample_budget(0, max, max, true), (max as f64 * 0.95) as usize);
        assert_eq!(load_sample_budget(max, file, max, true), 0);
    }

    #[test]
    fn loaded_block_sits_before_the_current_capture() {
        let placed = place_loaded_before(5_000_000, 100, 2_000_100, SESSION_GAP_US);
        assert_eq!(placed.current_pad_us, 0);
        assert_eq!(map_loaded_elapsed(100, 100, placed.loaded_base_us), 2_000_000);
        assert_eq!(map_loaded_elapsed(2_000_100, 100, placed.loaded_base_us), 4_000_000);

        let padded = place_loaded_before(0, 10, 2_000_010, SESSION_GAP_US);
        assert_eq!(padded.loaded_base_us, 0);
        assert_eq!(padded.current_pad_us, 3_000_000);
        assert_eq!(map_loaded_elapsed(2_000_010, 10, padded.loaded_base_us), 2_000_000);
    }

    #[test]
    fn utc_merge_keeps_the_wall_clock_gap() {
        let live_origin = 1_700_000_000_000_000;
        let file_origin = live_origin - 3_600_000_000;
        let earliest = absolute_us(file_origin, 0);
        let file_end = elapsed_on_origin(absolute_us(file_origin, 5_000_000), earliest);
        let live_start = elapsed_on_origin(absolute_us(live_origin, 0), earliest);
        assert_eq!(file_end, 5_000_000);
        assert_eq!(live_start, 3_600_000_000);
        assert_eq!(live_start - file_end, 3_595_000_000);
    }

    #[test]
    fn session_round_trip_keeps_samples_events_and_gaps() {
        let session = SessionData {
            host_origin_utc_us: Some(1_700_000_000_000_000),
            breaks_us: vec![1_000_000],
            samples: vec![
                sample(0, 5_000_000, 100_000),
                sample(1_000_000, 5_100_000, -50_000),
                sample(6_000_000, 4_900_000, 20_000),
            ],
            events: vec![StoredEvent {
                elapsed_us: 1_000_000,
                category: 2,
                label: "ATT".to_string(),
                name: "Attached".to_string(),
                details: "Cable VID 1234\nPD 3.1".to_string(),
            }],
        };
        let decoded = decode(&encode(&session).unwrap()).unwrap();
        assert_eq!(decoded.host_origin_utc_us, session.host_origin_utc_us);
        assert_eq!(decoded.breaks_us, session.breaks_us);
        assert_eq!(decoded.samples, session.samples);
        assert_eq!(decoded.events.len(), 1);
        assert_eq!(decoded.events[0].elapsed_us, 1_000_000);
        assert_eq!(decoded.events[0].label, "ATT");
        assert_eq!(decoded.events[0].details, "Cable VID 1234\nPD 3.1");
        assert!(decode(b"nope").is_err());
    }

    fn sample(elapsed_us: u64, vbus_uv: i64, ibus_ua: i64) -> MeasurementSample {
        MeasurementSample {
            elapsed_us,
            sample_index: elapsed_us / 1_000,
            sequence: (elapsed_us / 1_000) as u16,
            marker: 7,
            sample_rate_hz: 50,
            missing_samples: 0,
            gap_duration_us: 0,
            interpolated: elapsed_us == 6_000_000,
            cumulative_missing_samples: 0,
            cumulative_interpolated_duration_us: 0,
            discarded_sequence_samples: 0,
            cumulative_discarded_sequence_samples: 0,
            vbus_uv,
            ibus_ua,
            power_uw: vbus_uv.saturating_mul(ibus_ua / 1_000),
            charge_uah: 1.5,
            energy_uwh: -2.25,
            charge_throughput_uah: 3.0,
            energy_throughput_uwh: 4.5,
            cc1_uv: 500_000,
            cc2_uv: 0,
            dp_uv: 1,
            dm_uv: -1,
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn browser_zstd_frames_open_on_the_desktop_and_the_reverse() {
        let raw = b"km003c session sample sample sample sample".repeat(32);
        let desktop = zstd::stream::encode_all(Cursor::new(raw.as_slice()), ZSTD_LEVEL).unwrap();
        let mut source = desktop.as_slice();
        let mut browser_decoder = ruzstd::decoding::StreamingDecoder::new(&mut source).unwrap();
        let mut decoded = Vec::new();
        std::io::Read::read_to_end(&mut browser_decoder, &mut decoded).unwrap();
        assert_eq!(decoded, raw);

        let mut browser = Vec::new();
        ruzstd::encoding::compress(
            raw.as_slice(),
            &mut browser,
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        let back = zstd::stream::decode_all(Cursor::new(browser.as_slice())).unwrap();
        assert_eq!(back, raw);
    }
}
