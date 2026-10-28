//! Official firmware release catalog and validated package downloads.
//! Native front ends can use `FirmwareCatalogClient`; catalog parsing and
//! package validation are also available without a native HTTP client.

use super::FirmwareImage;
use crate::error::KMError;
#[cfg(not(target_arch = "wasm32"))]
use base64::{Engine, engine::general_purpose::STANDARD};
#[cfg(not(target_arch = "wasm32"))]
use hmac::{Hmac, KeyInit, Mac};
#[cfg(not(target_arch = "wasm32"))]
use sha1::Sha1;
use sha2::{Digest, Sha256};
#[cfg(not(target_arch = "wasm32"))]
use std::time::{Duration, SystemTime};

#[cfg(not(target_arch = "wasm32"))]
const ENDPOINT: &str = "https://product-km003c.oss-cn-hangzhou.aliyuncs.com";
#[cfg(not(target_arch = "wasm32"))]
const BUCKET: &str = "product-km003c";
const MAX_DOWNLOAD: usize = 2 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FirmwareCatalogError {
    #[error("Invalid firmware catalog: {0}")]
    InvalidCatalog(String),
    #[error(transparent)]
    InvalidPackage(#[from] KMError),
    #[cfg(not(target_arch = "wasm32"))]
    #[error("Firmware HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
}
impl From<&str> for FirmwareCatalogError {
    fn from(value: &str) -> Self {
        Self::InvalidCatalog(value.to_owned())
    }
}
impl From<String> for FirmwareCatalogError {
    fn from(value: String) -> Self {
        Self::InvalidCatalog(value)
    }
}
type Result<T = ()> = std::result::Result<T, FirmwareCatalogError>;
fn invalid(message: impl Into<String>) -> FirmwareCatalogError {
    FirmwareCatalogError::InvalidCatalog(message.into())
}

/// A release entry from the official catalog, including both descriptions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareRelease {
    pub version: String,
    pub key: String,
    pub date: String,
    pub notes_zh: String,
    pub notes_en: String,
    pub latest: bool,
    pub stable: bool,
    pub size: usize,
    pub crc32: u32,
}

/// Typed catalog, independent of frontend UI and file storage.
#[derive(Debug, Clone)]
pub struct FirmwareCatalog {
    releases: Vec<FirmwareRelease>,
}
impl FirmwareCatalog {
    pub fn parse_xml(xml: &str) -> Result<Self> {
        Ok(Self {
            releases: parse_catalog(xml)?,
        })
    }
    pub fn releases(&self) -> &[FirmwareRelease] {
        &self.releases
    }
    pub fn release(&self, version: &str) -> Option<&FirmwareRelease> {
        self.releases.iter().find(|r| r.version == version)
    }
}

/// Original container bytes and its independently validated firmware image.
#[derive(Debug)]
pub struct FirmwareDownload {
    package: Vec<u8>,
    image: FirmwareImage,
    sha256: [u8; 32],
}
impl FirmwareDownload {
    pub fn package(&self) -> &[u8] {
        &self.package
    }
    pub fn image(&self) -> &FirmwareImage {
        &self.image
    }
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
    pub fn into_parts(self) -> (Vec<u8>, FirmwareImage) {
        (self.package, self.image)
    }
}
impl FirmwareRelease {
    /// Validate bytes against both the package metadata and this catalog entry.
    /// This can be used with frontend-specific browser/network transports too.
    pub fn validate_package(&self, bytes: &[u8]) -> Result<FirmwareDownload> {
        validate_key(&self.key)?;
        if bytes.len() > MAX_DOWNLOAD {
            return Err("firmware package exceeds 2 MiB".into());
        }
        let image = FirmwareImage::parse(bytes)?;
        image.validate_for_update()?;
        let m = image.metadata();
        if m.model != "KM003C"
            || m.version != self.version
            || m.date != self.date
            || m.size != self.size
            || m.crc32 != self.crc32
        {
            return Err(format!(
                "official catalog mismatch: expected KM003C {} ({}) {} bytes CRC32 {:08X}; \
             received {} {} ({}) {} bytes CRC32 {:08X}",
                self.version, self.date, self.size, self.crc32, m.model, m.version, m.date, m.size, m.crc32
            )
            .into());
        }
        Ok(FirmwareDownload {
            package: bytes.to_vec(),
            image,
            sha256: Sha256::digest(bytes).into(),
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
use crate::embedded_keys::{OSS_ACCESS_KEY_ID, OSS_ACCESS_KEY_SECRET};

// Deliberately no Debug or Serialize implementation: never log credentials.
#[cfg(not(target_arch = "wasm32"))]
struct Credentials {
    id: String,
    secret: Vec<u8>,
}

#[cfg(not(target_arch = "wasm32"))]
impl Credentials {
    fn official() -> Self {
        Self {
            id: String::from_utf8(OSS_ACCESS_KEY_ID.to_vec()).expect("embedded OSS ID is UTF-8"),
            secret: OSS_ACCESS_KEY_SECRET.to_vec(),
        }
    }

    fn authorization(&self, key: &str, date: &str) -> Result<String> {
        let mut mac = Hmac::<Sha1>::new_from_slice(&self.secret).expect("HMAC accepts arbitrary key lengths");
        mac.update(format!("GET\n\n\n{date}\n/{BUCKET}/{key}").as_bytes());
        let signature = STANDARD.encode(mac.finalize().into_bytes());
        Ok(format!("OSS {}:{signature}", self.id))
    }
}

fn parse_catalog(xml: &str) -> Result<Vec<FirmwareRelease>> {
    if xml.len() > MAX_DOWNLOAD {
        return Err("catalog exceeds 2 MiB".into());
    }
    // roxmltree does not fetch external entities; DTDs remain disabled.
    let document = roxmltree::Document::parse(xml).map_err(|e| invalid(e.to_string()))?;
    let root = document.root_element();
    if root.tag_name().name() != "Updateinfo" {
        return Err("unexpected firmware catalog root".into());
    }
    if root
        .children()
        .find(|n| n.has_tag_name("DeviceName"))
        .and_then(|n| n.text())
        != Some("KM003C")
    {
        return Err("catalog is not for KM003C".into());
    }
    let mut releases = Vec::new();
    for title in root.children().filter(|n| n.has_tag_name("Title")) {
        let text = |tag| {
            title
                .children()
                .find(|n| n.has_tag_name(tag))
                .and_then(|n| n.text())
                .unwrap_or_default()
                .trim()
                .to_owned()
        };
        let version = title
            .attribute("version")
            .ok_or("catalog release is missing version")?
            .to_owned();
        if releases.iter().any(|r: &FirmwareRelease| r.version == version) {
            return Err("duplicate firmware version in catalog".into());
        }
        let key = text("Key");
        validate_key(&key)?;
        let size = text("Size")
            .parse()
            .map_err(|e: std::num::ParseIntError| invalid(e.to_string()))?;
        let crc32 = u32::from_str_radix(&text("Crc"), 16).map_err(|e| invalid(e.to_string()))?;
        releases.push(FirmwareRelease {
            version,
            key,
            date: text("LastModified"),
            notes_zh: text("Note"),
            notes_en: text("Note2"),
            latest: text("IsLatest") == "true",
            stable: text("IsStable") == "true",
            size,
            crc32,
        });
    }
    if releases.is_empty() {
        return Err("firmware catalog contains no releases".into());
    }
    Ok(releases)
}

fn validate_key(key: &str) -> Result {
    // Catalog URLs are placeholders in the observed feed. Object keys always
    // refer to this fixed bucket. Never follow server-provided arbitrary URLs.
    if key.is_empty()
        || key.len() > 128
        || !key.ends_with(".mencrypt")
        || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        || key.contains("..")
    {
        return Err("invalid firmware object key".into());
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
async fn get(client: &reqwest::Client, credentials: &Credentials, key: &str) -> Result<Vec<u8>> {
    let date = httpdate::fmt_http_date(SystemTime::now());
    let mut authorization = reqwest::header::HeaderValue::from_str(&credentials.authorization(key, &date)?)
        .map_err(|_| invalid("invalid firmware authorization header"))?;
    authorization.set_sensitive(true);
    let mut response = client
        .get(format!("{ENDPOINT}/{key}"))
        .header(reqwest::header::DATE, date)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .send()
        .await?
        .error_for_status()?;
    if response.content_length().is_some_and(|n| n > MAX_DOWNLOAD as u64) {
        return Err("official download exceeds 2 MiB".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > MAX_DOWNLOAD {
            return Err("official download exceeds 2 MiB".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(not(target_arch = "wasm32"))]
fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

/// Native HTTPS adapter for the official catalog. Parsing, validation and
/// update orchestration remain separate from frontend presentation/storage.
#[cfg(not(target_arch = "wasm32"))]
pub struct FirmwareCatalogClient {
    http: reqwest::Client,
    credentials: Credentials,
}
#[cfg(not(target_arch = "wasm32"))]
impl FirmwareCatalogClient {
    pub fn new() -> Result<Self> {
        Ok(Self {
            http: client()?,
            credentials: Credentials::official(),
        })
    }
    pub async fn fetch(&self) -> Result<FirmwareCatalog> {
        let bytes = get(&self.http, &self.credentials, "expect.xml").await?;
        let xml = std::str::from_utf8(&bytes).map_err(|e| invalid(e.to_string()))?;
        FirmwareCatalog::parse_xml(xml)
    }
    pub async fn download(&self, release: &FirmwareRelease) -> Result<FirmwareDownload> {
        validate_key(&release.key)?;
        let bytes = get(&self.http, &self.credentials, &release.key).await?;
        release.validate_package(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const XML: &str = r#"<Updateinfo><DeviceName>KM003C</DeviceName><Title version="1.9.7"><Key>KM003C_V1.9.7.mencrypt</Key><Size>453828</Size><Crc>7C80B54E</Crc><LastModified>2025.9.1</LastModified><Note>修复</Note><Note2>A &amp; B</Note2><IsStable>true</IsStable><IsLatest>false</IsLatest></Title></Updateinfo>"#;
    #[test]
    fn parses_versions_notes_and_flags_without_discarding_older_releases() {
        let catalog = FirmwareCatalog::parse_xml(XML).unwrap();
        let releases = catalog.releases();
        assert_eq!(releases[0].version, "1.9.7");
        assert_eq!(releases[0].notes_en, "A & B");
        assert_eq!(releases[0].notes_zh, "修复");
        assert!(releases[0].stable);
        assert!(!releases[0].latest);
        assert_eq!(catalog.release("1.9.7"), Some(&releases[0]));
        assert!(catalog.release("missing").is_none());
    }
    #[test]
    fn validates_download_identity_in_the_library_and_rejects_stale_catalog() {
        let bytes = crate::firmware::tests::package(4156, &[]);
        let image = FirmwareImage::parse(&bytes).unwrap();
        let catalog = FirmwareCatalog::parse_xml(XML).unwrap();
        let mut release = catalog.release("1.9.7").unwrap().clone();
        release.size = image.metadata().size;
        release.crc32 = image.metadata().crc32;
        let download = release.validate_package(&bytes).unwrap();
        assert_eq!(download.package(), bytes);
        assert_eq!(download.image().metadata(), image.metadata());
        assert_eq!(*download.sha256(), <[u8; 32]>::from(Sha256::digest(&bytes)));
        release.date = "2025.10.13".into();
        assert!(
            release
                .validate_package(&bytes)
                .unwrap_err()
                .to_string()
                .contains("official catalog mismatch")
        );
    }
    #[test]
    fn rejects_other_models_dtds_and_unsafe_object_keys() {
        assert!(parse_catalog(&XML.replace("<DeviceName>KM003C", "<DeviceName>KM002C")).is_err());
        assert!(
            parse_catalog(&format!(
                "<!DOCTYPE Updateinfo [<!ENTITY a SYSTEM 'file:///etc/passwd'>]>{XML}"
            ))
            .is_err()
        );
        for key in [
            "../x.mencrypt",
            "https://other/a.mencrypt",
            "a/b.mencrypt",
            "x?acl.mencrypt",
            "",
        ] {
            assert!(validate_key(key).is_err());
        }
    }
    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn signs_known_oss_v1_request_without_real_credentials() {
        let credentials = Credentials {
            id: "example".into(),
            secret: b"test-secret".to_vec(),
        };
        assert_eq!(
            credentials
                .authorization("expect.xml", "Wed, 28 Oct 2026 12:00:00 GMT")
                .unwrap(),
            "OSS example:ymwrkiuMt/yPO0x8erDHl2x4HKU="
        );
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn embedded_credentials_match_original_signature() {
        let authorization = Credentials::official()
            .authorization("expect.xml", "Wed, 28 Oct 2026 12:00:00 GMT")
            .unwrap();
        let (id, signature) = authorization.strip_prefix("OSS ").unwrap().split_once(':').unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(id.as_bytes())),
            "703ad8ce5fe727c72b94f692214737afe50850cf42a87916f5f09fd17766c82a"
        );
        assert_eq!(signature, "dr843lzwCizORfsq8cRY+7jJHPY=");
    }
}
