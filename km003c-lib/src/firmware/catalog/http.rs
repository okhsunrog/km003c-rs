//! Bounded platform HTTP adapters. Requests never implement Debug: signed URLs
//! and Authorization headers must not leak into diagnostic output.
use super::*;
use std::future::Future;

pub struct FirmwareHttpRequest {
    source: FirmwareSource,
    key: String,
}
impl FirmwareHttpRequest {
    pub(super) fn official(key: &str) -> Result<Self> {
        if key != "expect.xml" {
            validate_key(key)?;
        }
        Ok(Self {
            source: FirmwareSource::Official,
            key: key.into(),
        })
    }
    pub(super) fn mirror(key: &str) -> Result<Self> {
        if key != "catalog.json" {
            validate_mirror_key(key)?;
        }
        Ok(Self {
            source: FirmwareSource::Mirror,
            key: key.into(),
        })
    }
    pub fn source(&self) -> FirmwareSource {
        self.source
    }
    /// Public resource URL without credentials.
    pub fn url(&self) -> String {
        let endpoint = match self.source {
            FirmwareSource::Official => ENDPOINT,
            FirmwareSource::Mirror => FIRMWARE_MIRROR_URL,
        };
        format!("{endpoint}/{}", self.key)
    }
    /// URL suitable for Fetch, which cannot supply the Date header. Official
    /// requests get a five-minute OSS V1 signature. Never log the returned URL.
    pub fn signed_url(&self) -> Result<String> {
        if self.source == FirmwareSource::Mirror {
            return Ok(self.url());
        }
        let now = crate::runtime::SystemTime::now()
            .duration_since(crate::runtime::SystemTime::UNIX_EPOCH)
            .map_err(|_| invalid("system clock is before the Unix epoch"))?
            .as_secs();
        let expiry = now.checked_add(300).ok_or("signature expiry overflows")?;
        Ok(self.signed_url_at(&Credentials::official(), expiry))
    }
    fn signed_url_at(&self, credentials: &Credentials, expiry: u64) -> String {
        use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
        let signature = credentials.signature(&self.key, &expiry.to_string());
        format!(
            "{}?OSSAccessKeyId={}&Expires={expiry}&Signature={}",
            self.url(),
            utf8_percent_encode(&credentials.id, NON_ALPHANUMERIC),
            utf8_percent_encode(&signature, NON_ALPHANUMERIC)
        )
    }
}

/// Transport seam for bounded HTTP requests, including offline test fixtures.
/// Adapter errors must not contain authorization headers or signed URLs.
#[cfg(not(target_arch = "wasm32"))]
pub trait FirmwareHttpTransport: Send + Sync {
    fn get(&self, request: FirmwareHttpRequest) -> impl Future<Output = Result<Vec<u8>>> + Send;
}
/// Browser transports may hold non-Send JavaScript futures.
#[cfg(target_arch = "wasm32")]
pub trait FirmwareHttpTransport {
    fn get(&self, request: FirmwareHttpRequest) -> impl Future<Output = Result<Vec<u8>>>;
}

pub struct PlatformFirmwareHttp {
    #[cfg(not(target_arch = "wasm32"))]
    client: reqwest::Client,
}
impl PlatformFirmwareHttp {
    pub fn new() -> Result<Self> {
        Ok(Self {
            #[cfg(not(target_arch = "wasm32"))]
            client: reqwest::Client::builder()
                .https_only(true)
                .timeout(std::time::Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl FirmwareHttpTransport for PlatformFirmwareHttp {
    async fn get(&self, request: FirmwareHttpRequest) -> Result<Vec<u8>> {
        let mut builder = self.client.get(request.url());
        if request.source == FirmwareSource::Official {
            let date = httpdate::fmt_http_date(std::time::SystemTime::now());
            let value = Credentials::official().authorization(&request.key, &date);
            let mut authorization = reqwest::header::HeaderValue::from_str(&value)
                .map_err(|_| invalid("invalid firmware authorization header"))?;
            authorization.set_sensitive(true);
            builder = builder
                .header(reqwest::header::DATE, date)
                .header(reqwest::header::AUTHORIZATION, authorization);
        }
        let mut response = builder
            .send()
            .await
            .map_err(|e| e.without_url())?
            .error_for_status()
            .map_err(|e| e.without_url())?;
        if response.content_length().is_some_and(|n| n > MAX_DOWNLOAD as u64) {
            return Err(invalid("firmware download exceeds 2 MiB"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| e.without_url())? {
            if bytes.len() + chunk.len() > MAX_DOWNLOAD {
                return Err(invalid("firmware download exceeds 2 MiB"));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use super::*;
    use wasm_bindgen::prelude::*;
    #[wasm_bindgen(inline_js = "
export async function firmwareHttpGet(url) {
    const response = await fetch(url, {redirect: 'error', signal: AbortSignal.timeout(30000)});
    if (!response.ok) throw new Error('HTTP failure');
    const reader = response.body.getReader(); const chunks = []; let size = 0;
    while (true) {
        const {done, value} = await reader.read(); if (done) break;
        size += value.length;
        if (size > 2097152) { await reader.cancel(); throw new Error('Download limit'); }
        chunks.push(value);
    }
    const result = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; }
    return result;
}
")]
    extern "C" {
        #[wasm_bindgen(js_name = firmwareHttpGet)]
        fn fetch(url: &str) -> js_sys::Promise;
    }
    impl FirmwareHttpTransport for PlatformFirmwareHttp {
        async fn get(&self, request: FirmwareHttpRequest) -> Result<Vec<u8>> {
            let url = request.signed_url()?;
            let result = wasm_bindgen_futures::JsFuture::from(fetch(&url))
                .await
                // Browser errors may contain the signed URL. Never propagate it.
                .map_err(|_| invalid("firmware HTTP request failed (network, CORS or download limit)"))?;
            Ok(js_sys::Uint8Array::new(&result).to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn query_signing_uses_expiry_and_percent_encoding() {
        let credentials = Credentials {
            id: "example/id+".into(),
            secret: b"test-secret".to_vec(),
        };
        let request = FirmwareHttpRequest::official("expect.xml").unwrap();
        let url = request.signed_url_at(&credentials, 1793188800);
        assert_eq!(
            url,
            format!(
                "{ENDPOINT}/expect.xml?OSSAccessKeyId=example%2Fid%2B&Expires=1793188800&Signature=ntmf0AVGAm5BKHZrgqba9U74rNI%3D"
            )
        );
        assert!(!url.contains("test-secret"));
        assert!(url.contains("%3D"));
    }
    #[test]
    fn unsafe_resource_paths_are_rejected_before_transport() {
        assert!(FirmwareHttpRequest::official("../expect.xml").is_err());
        assert!(FirmwareHttpRequest::official("https://other/x.mencrypt").is_err());
        assert!(FirmwareHttpRequest::mirror("../catalog.json").is_err());
    }
}
