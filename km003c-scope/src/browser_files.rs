//! Browser save and load for `.kmss` files.
//!
//! The picker is opened synchronously from the button click so Chrome still
//! treats it as a user action. Compression happens after the user confirms.

use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;

pub enum BrowserFileError {
    Cancelled,
    Message(String),
}

enum SaveKind {
    Picker(js_sys::Promise),
    Download(String),
}

pub struct PendingSave {
    kind: SaveKind,
}

pub enum ConfirmedSave {
    Handle(JsValue),
    Download(String),
}

pub struct PendingOpen {
    promise: js_sys::Promise,
}

pub fn begin_save(name: &str) -> Result<PendingSave, BrowserFileError> {
    let window = window()?;
    let picker =
        js_sys::Reflect::get(window.as_ref(), &JsValue::from_str("showSaveFilePicker")).unwrap_or(JsValue::UNDEFINED);
    if !picker.is_function() {
        return Ok(PendingSave {
            kind: SaveKind::Download(name.to_string()),
        });
    }
    let function = picker
        .dyn_into::<js_sys::Function>()
        .map_err(|_| BrowserFileError::Message("save picker is not available".to_string()))?;
    let promise = function
        .call1(window.as_ref(), &save_options(name))
        .map_err(classify)?
        .dyn_into::<js_sys::Promise>()
        .map_err(|_| BrowserFileError::Message("save picker failed".to_string()))?;
    Ok(PendingSave {
        kind: SaveKind::Picker(promise),
    })
}

pub fn begin_open() -> Result<PendingOpen, BrowserFileError> {
    let window = window()?;
    let function = method(window.as_ref(), "showOpenFilePicker")?;
    let promise = function
        .call1(window.as_ref(), &open_options())
        .map_err(classify)?
        .dyn_into::<js_sys::Promise>()
        .map_err(|_| BrowserFileError::Message("open picker failed".to_string()))?;
    Ok(PendingOpen { promise })
}

impl PendingSave {
    pub async fn confirm(self) -> Result<ConfirmedSave, BrowserFileError> {
        match self.kind {
            SaveKind::Download(name) => Ok(ConfirmedSave::Download(name)),
            SaveKind::Picker(promise) => {
                let handle = JsFuture::from(promise).await.map_err(classify)?;
                Ok(ConfirmedSave::Handle(handle))
            }
        }
    }
}

impl ConfirmedSave {
    pub async fn write(self, bytes: &[u8]) -> Result<String, BrowserFileError> {
        match self {
            Self::Download(name) => {
                download_bytes(&name, bytes)?;
                Ok(name)
            }
            Self::Handle(handle) => write_handle(&handle, bytes).await,
        }
    }
}

impl PendingOpen {
    pub async fn read(self) -> Result<Vec<u8>, BrowserFileError> {
        let handles = JsFuture::from(self.promise).await.map_err(classify)?;
        let handle = js_sys::Array::from(&handles).get(0);
        if handle.is_undefined() || handle.is_null() {
            return Err(BrowserFileError::Cancelled);
        }
        let file = await_method(&handle, "getFile", &[]).await?;
        let buffer = await_method(&file, "arrayBuffer", &[]).await?;
        Ok(js_sys::Uint8Array::new(&buffer).to_vec())
    }
}

async fn write_handle(handle: &JsValue, bytes: &[u8]) -> Result<String, BrowserFileError> {
    let name = js_sys::Reflect::get(handle, &JsValue::from_str("name"))
        .ok()
        .and_then(|value| value.as_string())
        .unwrap_or_else(|| "session.kmss".to_string());
    let writable = await_method(handle, "createWritable", &[]).await?;
    let data = js_sys::Uint8Array::from(bytes);
    if let Err(error) = await_method(&writable, "write", &[data.into()]).await {
        let _ = await_method(&writable, "abort", &[]).await;
        return Err(error);
    }
    await_method(&writable, "close", &[]).await?;
    Ok(name)
}

async fn await_method(target: &JsValue, name: &str, args: &[JsValue]) -> Result<JsValue, BrowserFileError> {
    let function = method(target, name)?;
    let arguments = js_sys::Array::new();
    for arg in args {
        arguments.push(arg);
    }
    let value = function.apply(target, &arguments).map_err(classify)?;
    let promise = value
        .dyn_into::<js_sys::Promise>()
        .map_err(|_| BrowserFileError::Message(format!("{name} failed")))?;
    JsFuture::from(promise).await.map_err(classify)
}

fn method(target: &JsValue, name: &str) -> Result<js_sys::Function, BrowserFileError> {
    js_sys::Reflect::get(target, &JsValue::from_str(name))
        .map_err(classify)?
        .dyn_into()
        .map_err(|_| BrowserFileError::Message(format!("{name} is not available")))
}

fn window() -> Result<web_sys::Window, BrowserFileError> {
    web_sys::window().ok_or_else(|| BrowserFileError::Message("no browser window".to_string()))
}

fn save_options(name: &str) -> JsValue {
    let options = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&options, &JsValue::from_str("suggestedName"), &JsValue::from_str(name));
    let _ = js_sys::Reflect::set(&options, &JsValue::from_str("id"), &JsValue::from_str("km003c-session"));
    let _ = js_sys::Reflect::set(&options, &JsValue::from_str("types"), &picker_types());
    options.into()
}

fn open_options() -> JsValue {
    let options = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&options, &JsValue::from_str("multiple"), &JsValue::FALSE);
    let _ = js_sys::Reflect::set(&options, &JsValue::from_str("id"), &JsValue::from_str("km003c-session"));
    let _ = js_sys::Reflect::set(&options, &JsValue::from_str("types"), &picker_types());
    options.into()
}

fn picker_types() -> JsValue {
    let extensions = js_sys::Array::of1(&JsValue::from_str(".kmss"));
    let accept = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&accept, &JsValue::from_str("application/octet-stream"), &extensions);
    let entry = js_sys::Object::new();
    let _ = js_sys::Reflect::set(
        &entry,
        &JsValue::from_str("description"),
        &JsValue::from_str("KM003C session"),
    );
    let _ = js_sys::Reflect::set(&entry, &JsValue::from_str("accept"), &accept);
    js_sys::Array::of1(&entry).into()
}

fn download_bytes(name: &str, bytes: &[u8]) -> Result<(), BrowserFileError> {
    let window = window()?;
    let document = window
        .document()
        .ok_or_else(|| BrowserFileError::Message("no document".to_string()))?;
    let parts = js_sys::Array::new();
    parts.push(&js_sys::Uint8Array::from(bytes));
    let options = web_sys::BlobPropertyBag::new();
    options.set_type("application/octet-stream");
    let blob = web_sys::Blob::new_with_u8_array_sequence_and_options(&parts, &options)
        .map_err(|_| BrowserFileError::Message("could not prepare the download".to_string()))?;
    let url = web_sys::Url::create_object_url_with_blob(&blob)
        .map_err(|_| BrowserFileError::Message("could not prepare the download".to_string()))?;
    let anchor = document
        .create_element("a")
        .map_err(|_| BrowserFileError::Message("could not prepare the download".to_string()))?
        .dyn_into::<web_sys::HtmlAnchorElement>()
        .map_err(|_| BrowserFileError::Message("could not prepare the download".to_string()))?;
    anchor.set_href(&url);
    anchor.set_download(name);
    document
        .body()
        .ok_or_else(|| BrowserFileError::Message("no document body".to_string()))?
        .append_child(&anchor)
        .map_err(|_| BrowserFileError::Message("could not prepare the download".to_string()))?;
    anchor.click();
    anchor.remove();
    let _ = web_sys::Url::revoke_object_url(&url);
    Ok(())
}

fn classify(value: JsValue) -> BrowserFileError {
    let name = js_sys::Reflect::get(&value, &JsValue::from_str("name"))
        .ok()
        .and_then(|item| item.as_string());
    if name.as_deref() == Some("AbortError") {
        return BrowserFileError::Cancelled;
    }
    let message = js_sys::Reflect::get(&value, &JsValue::from_str("message"))
        .ok()
        .and_then(|item| item.as_string())
        .or_else(|| value.as_string())
        .unwrap_or_else(|| "browser file dialog failed".to_string());
    BrowserFileError::Message(message)
}
