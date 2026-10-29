#![cfg(all(target_arch = "wasm32", feature = "browser"))]

use km003c_lib::{Recorder, RecordingFormat, RecordingMetadata, runtime::UnloadGuard};
use std::{path::PathBuf, time::Duration};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen(inline_js = "
export function unloadIsBlocked() {
    return !window.dispatchEvent(new Event('beforeunload', {cancelable: true}));
}
let originalClick;
let downloads = 0;
export function interceptDownloads() {
    downloads = 0;
    originalClick = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = () => { downloads++; };
}
export function downloadCount() { return downloads; }
export function restoreDownloads() { HTMLAnchorElement.prototype.click = originalClick; }
")]
extern "C" {
    #[wasm_bindgen(js_name = unloadIsBlocked)]
    fn unload_is_blocked() -> bool;
    #[wasm_bindgen(js_name = interceptDownloads)]
    fn intercept_downloads();
    #[wasm_bindgen(js_name = downloadCount)]
    fn download_count() -> u32;
    #[wasm_bindgen(js_name = restoreDownloads)]
    fn restore_downloads();
}

#[wasm_bindgen_test]
fn independent_operations_keep_navigation_protected_until_the_last_guard_drops() {
    assert!(!unload_is_blocked());
    let recording = UnloadGuard::new();
    let firmware = UnloadGuard::new();
    assert!(unload_is_blocked());
    drop(firmware);
    assert!(unload_is_blocked());
    drop(recording);
    assert!(!unload_is_blocked());
}

#[wasm_bindgen_test(async)]
async fn recording_and_its_export_keep_navigation_protected() {
    assert!(!unload_is_blocked());
    intercept_downloads();
    let mut recording = Recorder::start(
        PathBuf::from("capture.csv"),
        RecordingFormat::Csv,
        RecordingMetadata::new("KM003C", "test", "test"),
        None,
        std::path::Path::new(""),
    )
    .unwrap();
    assert!(unload_is_blocked());
    let firmware = UnloadGuard::new();
    drop(firmware);
    assert!(unload_is_blocked());
    recording.request_finish();
    // Finishing is asynchronous. Dropping the frontend handle must not release
    // the worker's guard before the download has been initiated.
    drop(recording);
    assert!(unload_is_blocked());
    for _ in 0..100 {
        km003c_lib::runtime::sleep(Duration::from_millis(1)).await;
        if download_count() != 0 {
            break;
        }
    }
    assert_eq!(download_count(), 1);
    assert!(!unload_is_blocked());
    restore_downloads();
}

#[wasm_bindgen_test]
fn dropping_an_unfinished_recording_releases_its_guard() {
    let recording = Recorder::start(
        PathBuf::from("capture.csv"),
        RecordingFormat::Csv,
        RecordingMetadata::new("KM003C", "test", "test"),
        None,
        std::path::Path::new(""),
    )
    .unwrap();
    assert!(unload_is_blocked());
    drop(recording);
    assert!(!unload_is_blocked());
}
