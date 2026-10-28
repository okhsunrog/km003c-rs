//! Frontend file dialogs/storage and HTTP transport. Firmware policy lives in the library.
use km003c_lib::firmware::{
    FirmwareImage,
    catalog::{FirmwareCatalog, FirmwareRelease},
};

const MAX_PACKAGE_BYTES: usize = 2 * 1024 * 1024;

pub fn parse_package(bytes: &[u8]) -> Result<FirmwareImage, String> {
    if bytes.len() > MAX_PACKAGE_BYTES {
        return Err("Firmware package exceeds 2 MiB".into());
    }
    let image = FirmwareImage::parse(bytes).map_err(|e| e.to_string())?;
    image.validate_for_update().map_err(|e| e.to_string())?;
    Ok(image)
}

#[cfg(not(target_arch = "wasm32"))]
pub struct BackupDestination(std::path::PathBuf);

#[cfg(not(target_arch = "wasm32"))]
pub async fn catalog() -> Result<FirmwareCatalog, String> {
    use km003c_lib::firmware::catalog::FirmwareCatalogClient;
    FirmwareCatalogClient::new()
        .map_err(|e| e.to_string())?
        .fetch()
        .await
        .map_err(|e| e.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn download(release: FirmwareRelease) -> Result<FirmwareImage, String> {
    use km003c_lib::firmware::catalog::FirmwareCatalogClient;
    let download = FirmwareCatalogClient::new()
        .map_err(|e| e.to_string())?
        .download(&release)
        .await
        .map_err(|e| e.to_string())?;
    Ok(download.into_parts().1)
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn pick_package() -> Result<Option<FirmwareImage>, String> {
    use std::io::Read;
    let Some(file) = rfd::AsyncFileDialog::new()
        .add_filter("Firmware package", &["mencrypt"])
        .pick_file()
        .await
    else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    std::fs::File::open(file.path())
        .map_err(|e| e.to_string())?
        .take(MAX_PACKAGE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    parse_package(&bytes).map(Some)
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn pick_backup(name: &str) -> Result<Option<BackupDestination>, String> {
    Ok(rfd::AsyncFileDialog::new()
        .set_title("Save verified application backup")
        .set_file_name(name)
        .add_filter("Application backup", &["bin"])
        .save_file()
        .await
        .map(|file| BackupDestination(file.path().to_owned())))
}

#[cfg(not(target_arch = "wasm32"))]
impl BackupDestination {
    pub async fn save(self, bytes: &[u8]) -> Result<(), String> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.0)
            .map_err(|e| format!("Cannot create backup (choose a new filename): {e}"))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("Cannot save backup: {e}"))
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use super::*;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::JsFuture;

    // File dialogs must start from the button's user activation. The save picker
    // returns a real writable handle: a download click cannot prove backup storage.
    #[wasm_bindgen(inline_js = "
export async function firmwareFetch(url) {
    const response = await fetch(url, {redirect: 'error', signal: AbortSignal.timeout(20000)});
    if (!response.ok) throw new Error('HTTP ' + response.status);
    const reader = response.body.getReader();
    const chunks = []; let size = 0;
    while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        size += value.length;
        if (size > 2097152) { await reader.cancel(); throw new Error('Download exceeds 2 MiB'); }
        chunks.push(value);
    }
    const result = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; }
    return result;
}
export function firmwareOpen() {
    return new Promise((resolve, reject) => {
        const input = document.createElement('input'); input.type = 'file'; input.accept = '.mencrypt';
        input.oncancel = () => resolve(null);
        input.onchange = async () => {
            try {
                const file = input.files[0];
                if (!file) return resolve(null);
                if (file.size > 2097152) throw new Error('Firmware package exceeds 2 MiB');
                resolve(new Uint8Array(await file.arrayBuffer()));
            } catch (e) { reject(e); }
        };
        input.click();
    });
}
export async function firmwareBackupPicker(name) {
    if (!window.showSaveFilePicker) throw new Error('Saving a verified backup requires the File System Access API. Use a supported Chromium browser or the desktop app.');
    try {
        return await window.showSaveFilePicker({suggestedName: name, types: [{description: 'Application backup', accept: {'application/octet-stream': ['.bin']}}]});
    } catch (e) { if (e.name === 'AbortError') return null; throw e; }
}
export async function firmwareSave(handle, bytes) {
    const copy = new Uint8Array(bytes);
    const stream = await handle.createWritable();
    try { await stream.write(copy); await stream.close(); }
    catch (e) { try { await stream.abort(); } catch (_) {} throw e; }
}
const guard = event => { event.preventDefault(); event.returnValue = ''; };
export function firmwareGuard(active) {
    if (active) window.addEventListener('beforeunload', guard);
    else window.removeEventListener('beforeunload', guard);
}
")]
    extern "C" {
        #[wasm_bindgen(js_name = firmwareFetch)]
        fn fetch(url: &str) -> js_sys::Promise;
        #[wasm_bindgen(js_name = firmwareOpen)]
        fn open() -> js_sys::Promise;
        #[wasm_bindgen(js_name = firmwareBackupPicker)]
        fn picker(name: &str) -> js_sys::Promise;
        #[wasm_bindgen(js_name = firmwareSave)]
        fn save(handle: &JsValue, bytes: &[u8]) -> js_sys::Promise;
        #[wasm_bindgen(js_name = firmwareGuard)]
        pub fn guard(active: bool);
    }
    fn error(value: JsValue) -> String {
        js_sys::Error::from(value).message().into()
    }
    async fn fetch_bytes(url: &str) -> Result<Vec<u8>, String> {
        let value = JsFuture::from(fetch(url)).await.map_err(error)?;
        Ok(js_sys::Uint8Array::new(&value).to_vec())
    }
    pub async fn catalog() -> Result<FirmwareCatalog, String> {
        let url = format!("{}/catalog.json", km003c_lib::firmware::catalog::FIRMWARE_MIRROR_URL);
        let bytes = fetch_bytes(&url).await?;
        let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
        FirmwareCatalog::parse_json(text).map_err(|e| e.to_string())
    }
    pub async fn download(release: FirmwareRelease) -> Result<FirmwareImage, String> {
        let url = release.download_url().map_err(|e| e.to_string())?;
        let bytes = fetch_bytes(&url).await?;
        Ok(release
            .validate_package(&bytes)
            .map_err(|e| e.to_string())?
            .into_parts()
            .1)
    }
    pub async fn pick_package() -> Result<Option<FirmwareImage>, String> {
        let value = JsFuture::from(open()).await.map_err(error)?;
        if value.is_null() {
            return Ok(None);
        }
        parse_package(&js_sys::Uint8Array::new(&value).to_vec()).map(Some)
    }
    pub struct BackupDestination(JsValue);
    pub async fn pick_backup(name: &str) -> Result<Option<BackupDestination>, String> {
        let value = JsFuture::from(picker(name)).await.map_err(error)?;
        Ok((!value.is_null()).then_some(BackupDestination(value)))
    }
    impl BackupDestination {
        pub async fn save(self, bytes: &[u8]) -> Result<(), String> {
            JsFuture::from(save(&self.0, bytes)).await.map_err(error)?;
            Ok(())
        }
    }
}
#[cfg(target_arch = "wasm32")]
pub use browser::{catalog, download, guard, pick_backup, pick_package};

#[cfg(not(target_arch = "wasm32"))]
pub fn guard(_active: bool) {}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    #[test]
    fn invalid_and_oversized_local_packages_are_rejected() {
        assert!(parse_package(&[]).is_err());
        assert!(
            parse_package(&vec![0; MAX_PACKAGE_BYTES + 1])
                .unwrap_err()
                .contains("2 MiB")
        );
    }

    #[test]
    fn local_package_runs_the_library_update_validation() {
        let bytes = include_bytes!("../tests/fixtures/synthetic.mencrypt");
        let image = parse_package(bytes).unwrap();
        assert_eq!(image.metadata().version, "1.9.7");
        let mut corrupt = bytes.to_vec();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(parse_package(&corrupt).is_err());
    }

    #[tokio::test]
    async fn backup_storage_never_overwrites_an_existing_file() {
        let path = std::env::temp_dir().join(format!("km003c-firmware-backup-{}.bin", std::process::id()));
        BackupDestination(path.clone())
            .save(b"verified application")
            .await
            .unwrap();
        assert!(BackupDestination(path.clone()).save(b"replacement").await.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"verified application");
        std::fs::remove_file(path).unwrap();
    }
}
