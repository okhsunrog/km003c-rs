//! Cooperative single-thread browser export. The 23-column desktop schema is retained.
use super::row::RecordingRow;
use super::{RECORDING_SCHEMA_VERSION, RecordingFormat, RecordingMetadata};
use crate::offline_view::OfflineRecordingView;
use parquet::file::metadata::KeyValue;
use parquet::{
    data_type::{BoolType, DoubleType, Int32Type, Int64Type},
    file::{properties::WriterProperties, writer::SerializedFileWriter},
    schema::parser::parse_message_type,
};
#[cfg(target_arch = "wasm32")]
use std::path::Path;
use std::{sync::Arc, time::Duration};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;

#[derive(Clone, Copy)]
enum Cell {
    U32(u32),
    U64(u64),
    I64(i64),
    F64(f64),
    Bool(bool),
}
impl std::fmt::Display for Cell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::U32(x) => x.fmt(f),
            Self::U64(x) => x.fmt(f),
            Self::I64(x) => x.fmt(f),
            Self::F64(x) => x.fmt(f),
            Self::Bool(x) => x.fmt(f),
        }
    }
}
type Row = [Option<Cell>; 23];
const HEADERS: [&str; 23] = [
    "elapsed_us",
    "sample_index",
    "sequence",
    "marker",
    "sample_rate_hz",
    "missing_samples",
    "gap_duration_us",
    "interpolated",
    "cumulative_missing_samples",
    "cumulative_interpolated_duration_us",
    "discarded_sequence_samples",
    "cumulative_discarded_sequence_samples",
    "vbus_uv",
    "ibus_ua",
    "power_uw",
    "charge_uah",
    "energy_uwh",
    "charge_throughput_uah",
    "energy_throughput_uwh",
    "cc1_uv",
    "cc2_uv",
    "dp_uv",
    "dm_uv",
];
const SCHEMA: &str = r#"message km003c {
OPTIONAL INT64 elapsed_us (INTEGER(64,false));
OPTIONAL INT64 sample_index (INTEGER(64,false));
OPTIONAL INT32 sequence (INTEGER(32,false));
OPTIONAL INT32 marker (INTEGER(32,false));
OPTIONAL INT32 sample_rate_hz (INTEGER(32,false));
OPTIONAL INT32 missing_samples (INTEGER(32,false));
OPTIONAL INT64 gap_duration_us (INTEGER(64,false));
OPTIONAL BOOLEAN interpolated;
OPTIONAL INT64 cumulative_missing_samples (INTEGER(64,false));
OPTIONAL INT64 cumulative_interpolated_duration_us (INTEGER(64,false));
OPTIONAL INT32 discarded_sequence_samples (INTEGER(32,false));
OPTIONAL INT64 cumulative_discarded_sequence_samples (INTEGER(64,false));
OPTIONAL INT64 vbus_uv;
OPTIONAL INT64 ibus_ua;
OPTIONAL INT64 power_uw;
OPTIONAL DOUBLE charge_uah;
OPTIONAL DOUBLE energy_uwh;
OPTIONAL DOUBLE charge_throughput_uah;
OPTIONAL DOUBLE energy_throughput_uwh;
OPTIONAL INT64 cc1_uv;
OPTIONAL INT64 cc2_uv;
OPTIONAL INT64 dp_uv;
OPTIONAL INT64 dm_uv;
}"#;
fn live_row(row: &RecordingRow) -> Row {
    [
        Some(Cell::U64(row.elapsed_us)),
        Some(Cell::U64(row.sample_index)),
        Some(Cell::U32(row.sequence)),
        Some(Cell::U32(row.marker)),
        Some(Cell::U32(row.sample_rate_hz)),
        Some(Cell::U32(row.missing_samples)),
        Some(Cell::U64(row.gap_duration_us)),
        Some(Cell::Bool(row.interpolated)),
        Some(Cell::U64(row.cumulative_missing_samples)),
        Some(Cell::U64(row.cumulative_interpolated_duration_us)),
        Some(Cell::U32(row.discarded_sequence_samples)),
        Some(Cell::U64(row.cumulative_discarded_sequence_samples)),
        Some(Cell::I64(row.vbus_uv)),
        Some(Cell::I64(row.ibus_ua)),
        Some(Cell::I64(row.power_uw)),
        Some(Cell::F64(row.charge_uah)),
        Some(Cell::F64(row.energy_uwh)),
        Some(Cell::F64(row.charge_throughput_uah)),
        Some(Cell::F64(row.energy_throughput_uwh)),
        Some(Cell::I64(row.cc1_uv)),
        Some(Cell::I64(row.cc2_uv)),
        Some(Cell::I64(row.dp_uv)),
        Some(Cell::I64(row.dm_uv)),
    ]
}
fn offline_row(view: &OfflineRecordingView, index: usize) -> Row {
    let row = &view.samples[index];
    [
        Some(Cell::U64(row.elapsed_us)),
        Some(Cell::U64(row.sample_index)),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(Cell::I64(row.vbus_uv)),
        Some(Cell::I64(row.ibus_ua)),
        Some(Cell::I64(row.power_uw)),
        Some(Cell::F64(row.charge_uah)),
        Some(Cell::F64(row.energy_uwh)),
        Some(Cell::F64(row.charge_throughput_uah)),
        Some(Cell::F64(row.energy_throughput_uwh)),
        None,
        None,
        None,
        None,
    ]
}
fn metadata(device: RecordingMetadata, source: &str) -> Vec<KeyValue> {
    [
        ("schema_version", RECORDING_SCHEMA_VERSION.to_string()),
        ("source", source.into()),
        (
            "accumulator_source",
            if source == "live" { "host_trapezoidal" } else { "device" }.into(),
        ),
        ("model", device.model),
        ("firmware", device.firmware),
        ("serial", device.serial),
    ]
    .into_iter()
    .map(|(key, value)| KeyValue::new(format!("km003c.{key}"), value))
    .collect()
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn save_live(
    path: &Path,
    format: RecordingFormat,
    device: RecordingMetadata,
    rows: &[RecordingRow],
) -> Result<(), String> {
    let bytes = encode(format, metadata(device, "live"), rows.len(), |i| live_row(&rows[i])).await?;
    download(path, &bytes).await
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn save_offline(
    path: &Path,
    format: RecordingFormat,
    device: RecordingMetadata,
    view: &OfflineRecordingView,
) -> Result<(), String> {
    let mut metadata = metadata(device, "offline");
    metadata.extend([
        KeyValue::new(
            "km003c.offline.filename".into(),
            view.log.metadata.filename_lossy().into_owned(),
        ),
        KeyValue::new(
            "km003c.offline.interval_us".into(),
            view.log
                .metadata
                .interval
                .get::<crate::uom::si::time::microsecond>()
                .round()
                .to_string(),
        ),
        KeyValue::new(
            "km003c.offline.flags".into(),
            format!("0x{:04x}", view.log.metadata.flags),
        ),
    ]);
    let bytes = encode(format, metadata, view.samples.len(), |i| offline_row(view, i)).await?;
    download(path, &bytes).await
}

async fn encode(
    format: RecordingFormat,
    metadata: Vec<KeyValue>,
    len: usize,
    row: impl Fn(usize) -> Row,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    match format {
        RecordingFormat::Csv => {
            use std::io::Write;
            writeln!(bytes, "{}", HEADERS.join(",")).map_err(|e| e.to_string())?;
            for start in (0..len).step_by(8192) {
                for i in start..(start + 8192).min(len) {
                    for (column, cell) in row(i).iter().enumerate() {
                        if column > 0 {
                            bytes.push(b',');
                        }
                        if let Some(cell) = cell {
                            write!(bytes, "{cell}").map_err(|e| e.to_string())?;
                        }
                    }
                    bytes.push(b'\n');
                }
                crate::runtime::sleep(Duration::ZERO).await;
            }
        }
        RecordingFormat::Parquet => {
            let schema = Arc::new(parse_message_type(SCHEMA).map_err(|e| e.to_string())?);
            let properties = Arc::new(
                WriterProperties::builder()
                    .set_key_value_metadata(Some(metadata))
                    .build(),
            );
            let mut writer = SerializedFileWriter::new(&mut bytes, schema, properties).map_err(|e| e.to_string())?;
            for start in (0..len).step_by(8192) {
                let rows: Vec<_> = (start..(start + 8192).min(len)).map(&row).collect();
                let mut group = writer.next_row_group().map_err(|e| e.to_string())?;
                for index in 0..23 {
                    let mut column = group
                        .next_column()
                        .map_err(|e| e.to_string())?
                        .ok_or("Missing Parquet column")?;
                    let levels: Vec<i16> = rows.iter().map(|r| i16::from(r[index].is_some())).collect();
                    macro_rules! write_column {
                        ($variant:ident, $kind:ty, $convert:expr) => {{
                            let values: Vec<_> = rows
                                .iter()
                                .filter_map(|r| match r[index] {
                                    Some(Cell::$variant(value)) => Some(($convert)(value)),
                                    _ => None,
                                })
                                .collect();
                            column
                                .typed::<$kind>()
                                .write_batch(&values, Some(&levels), None)
                                .map_err(|e| e.to_string())?;
                        }};
                    }
                    match index {
                        2 | 3 | 4 | 5 | 10 => write_column!(U32, Int32Type, |value: u32| value as i32),
                        0 | 1 | 6 | 8 | 9 | 11 => write_column!(U64, Int64Type, |value: u64| value as i64),
                        12 | 13 | 14 | 19 | 20 | 21 | 22 => write_column!(I64, Int64Type, std::convert::identity),
                        15..=18 => write_column!(F64, DoubleType, std::convert::identity),
                        7 => write_column!(Bool, BoolType, std::convert::identity),
                        _ => unreachable!(),
                    }
                    column.close().map_err(|e| e.to_string())?;
                }
                group.close().map_err(|e| e.to_string())?;
                crate::runtime::sleep(Duration::ZERO).await;
            }
            writer.close().map_err(|e| e.to_string())?;
        }
    }
    Ok(bytes)
}

#[cfg(target_arch = "wasm32")]
async fn download(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let result = (|| -> Result<_, wasm_bindgen::JsValue> {
        let array = js_sys::Uint8Array::from(bytes);
        let parts = js_sys::Array::new();
        parts.push(&array);
        let blob = web_sys::Blob::new_with_u8_array_sequence(&parts)?;
        let url = web_sys::Url::create_object_url_with_blob(&blob)?;
        let document = web_sys::window()
            .ok_or("No browser window")?
            .document()
            .ok_or("No document")?;
        let anchor = document.create_element("a")?.dyn_into::<web_sys::HtmlAnchorElement>()?;
        anchor.set_href(&url);
        anchor.set_download(&path.to_string_lossy());
        document.body().ok_or("No document body")?.append_child(&anchor)?;
        anchor.click();
        anchor.remove();
        Ok(url)
    })();
    let url = result.map_err(|e| format!("Download failed: {e:?}"))?;
    // Give the browser time to consume the object URL before releasing it.
    wasm_bindgen_futures::spawn_local(async move {
        crate::runtime::sleep(Duration::from_secs(30)).await;
        let _ = web_sys::Url::revoke_object_url(&url);
    });
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use parquet::{
        file::reader::{FileReader, SerializedFileReader},
        record::RowAccessor,
    };

    #[test]
    fn live_and_offline_export_use_the_shared_schema() {
        let live = live_row(&RecordingRow {
            sequence: u32::MAX,
            interpolated: true,
            ..Default::default()
        });
        assert!(matches!(live[2], Some(Cell::U32(u32::MAX))));
        assert!(matches!(live[7], Some(Cell::Bool(true))));
        let view = crate::offline_view::captured_test_view();
        let offline = offline_row(&view, 0);
        assert!(offline[2].is_none());
        assert!(matches!(offline[12], Some(Cell::I64(4_999_553))));
        let metadata = metadata(
            RecordingMetadata {
                model: "KM003C".into(),
                firmware: "test".into(),
                serial: "1".into(),
            },
            "live",
        );
        assert_eq!(metadata.len(), 6);
        assert_eq!(metadata[2].value.as_deref(), Some("host_trapezoidal"));
    }

    fn test_row() -> Row {
        let mut row = [None; 23];
        row[0] = Some(Cell::U64(20_000));
        row[1] = Some(Cell::U64(1));
        row[12] = Some(Cell::I64(5_000_000));
        row[13] = Some(Cell::I64(-1_000_000));
        row[15] = Some(Cell::F64(-100.25));
        row
    }

    #[tokio::test]
    async fn browser_parquet_preserves_types_nulls_and_metadata_across_row_groups() {
        let data = encode(
            RecordingFormat::Parquet,
            vec![KeyValue::new("km003c.source".into(), "offline".to_string())],
            8193,
            |_| test_row(),
        )
        .await
        .unwrap();
        let reader = SerializedFileReader::new(bytes::Bytes::from(data)).unwrap();
        assert_eq!(reader.num_row_groups(), 2);
        assert_eq!(reader.metadata().file_metadata().num_rows(), 8193);
        assert_eq!(reader.metadata().file_metadata().schema_descr().num_columns(), 23);
        let row = reader.get_row_iter(None).unwrap().last().unwrap().unwrap();
        assert_eq!(row.get_ulong(0).unwrap(), 20_000);
        assert_eq!(row.get_long(13).unwrap(), -1_000_000);
        assert_eq!(row.get_double(15).unwrap(), -100.25);
        assert!(matches!(
            row.get_column_iter().nth(2).unwrap().1,
            parquet::record::Field::Null
        ));
        assert_eq!(
            reader.metadata().file_metadata().key_value_metadata().unwrap()[0]
                .value
                .as_deref(),
            Some("offline")
        );
    }

    #[tokio::test]
    async fn browser_csv_keeps_all_columns_and_empty_unavailable_values() {
        let data = encode(RecordingFormat::Csv, vec![], 1, |_| test_row()).await.unwrap();
        let text = String::from_utf8(data).unwrap();
        let mut lines = text.lines();
        assert_eq!(lines.next().unwrap().split(',').count(), 23);
        let values: Vec<_> = lines.next().unwrap().split(',').collect();
        assert_eq!(values.len(), 23);
        assert_eq!(values[2], "");
        assert_eq!(values[13], "-1000000");
        assert_eq!(values[15], "-100.25");
    }
}
