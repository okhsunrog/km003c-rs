//! Official firmware catalog/downloads with a validated archive fallback.
mod http;
pub use http::{FirmwareHttpRequest, FirmwareHttpTransport, PlatformFirmwareHttp};

use super::FirmwareImage;
use crate::error::KMError;
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

const ENDPOINT: &str = "https://product-km003c.oss-cn-hangzhou.aliyuncs.com";
const BUCKET: &str = "product-km003c";
const MAX_DOWNLOAD: usize = 2 * 1024 * 1024;
/// Public mirror base URL, also usable with browser-specific HTTP transports.
pub const FIRMWARE_MIRROR_URL: &str = "https://okhsunrog.github.io/km003c-resources";

/// Source that supplied a catalog or validated download.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareSource {
    Official,
    Mirror,
}
impl FirmwareSource {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Official => "official server",
            Self::Mirror => "archive mirror",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FirmwareCatalogError {
    #[error("Invalid firmware catalog: {0}")]
    InvalidCatalog(String),
    #[error(transparent)]
    InvalidPackage(#[from] KMError),
    #[error("Official firmware source failed: {official}; archive mirror failed: {mirror}")]
    Fallback { official: String, mirror: String },
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

/// A release entry, including both descriptions and optional mirror integrity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareRelease {
    /// Unique build selector. A version can identify multiple builds.
    pub id: String,
    pub version: String,
    pub key: String,
    pub date: String,
    pub notes_zh: String,
    pub notes_en: String,
    pub latest: bool,
    pub stable: bool,
    pub size: usize,
    pub crc32: u32,
    mirror: Option<MirrorIntegrity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MirrorIntegrity {
    sha256: [u8; 32],
    package_size: usize,
}

#[derive(serde::Deserialize)]
struct MirrorCatalog {
    schema_version: u32,
    model: String,
    releases: Vec<MirrorRelease>,
}

#[derive(serde::Deserialize)]
struct MirrorRelease {
    id: String,
    model: String,
    version: String,
    build_date: String,
    path: String,
    url: String,
    sha256: String,
    package_size: usize,
    firmware_size: usize,
    crc32: String,
    notes_en: String,
    notes_zh: String,
}

/// Typed catalog, independent of frontend UI and file storage.
#[derive(Debug, Clone)]
pub struct FirmwareCatalog {
    releases: Vec<FirmwareRelease>,
    source: FirmwareSource,
    fallback_reason: Option<String>,
}
impl FirmwareCatalog {
    /// Parse the public mirror catalog without a native HTTP client.
    pub fn parse_json(json: &str) -> Result<Self> {
        if json.len() > MAX_DOWNLOAD {
            return Err("catalog exceeds 2 MiB".into());
        }
        let catalog: MirrorCatalog = serde_json::from_str(json).map_err(|e| invalid(e.to_string()))?;
        if catalog.schema_version != 1 || catalog.model != "KM003C" {
            return Err("unsupported firmware mirror catalog".into());
        }
        let mut releases = Vec::new();
        let mut ids = std::collections::HashSet::new();
        for r in catalog.releases {
            if r.model != "KM003C"
                || !identity_token(&r.version)
                || !identity_token(&r.build_date)
                || r.sha256.len() != 64
                || r.package_size == 0
                || r.package_size > MAX_DOWNLOAD
                || r.firmware_size == 0
                || r.firmware_size > MAX_DOWNLOAD
            {
                return Err("invalid mirror release identity or size".into());
            }
            let mut sha256 = [0; 32];
            hex::decode_to_slice(&r.sha256, &mut sha256).map_err(|_| invalid("invalid mirror SHA256"))?;
            let hash = hex::encode(sha256);
            let expected_path = format!("firmware/km003c/{}/{}-{hash}.mencrypt", r.version, r.build_date);
            let expected_id = format!("km003c-{}-{}-{}", r.version, r.build_date, &hash[..12]);
            if r.path != expected_path
                || r.id != expected_id
                || r.url != format!("{FIRMWARE_MIRROR_URL}/{expected_path}")
            {
                return Err("mirror path, URL or ID does not match release identity".into());
            }
            if !ids.insert(r.id.clone()) {
                return Err("duplicate firmware build ID".into());
            }
            let crc32 = u32::from_str_radix(&r.crc32, 16).map_err(|e| invalid(e.to_string()))?;
            releases.push(FirmwareRelease {
                id: r.id,
                version: r.version,
                key: r.path,
                date: r.build_date,
                notes_en: r.notes_en,
                notes_zh: r.notes_zh,
                latest: false,
                stable: false,
                size: r.firmware_size,
                crc32,
                mirror: Some(MirrorIntegrity {
                    sha256,
                    package_size: r.package_size,
                }),
            });
        }
        if releases.is_empty() {
            return Err("firmware catalog contains no releases".into());
        }
        Ok(Self {
            releases,
            source: FirmwareSource::Mirror,
            fallback_reason: None,
        })
    }

    pub fn parse_xml(xml: &str) -> Result<Self> {
        Ok(Self {
            releases: parse_catalog(xml)?,
            source: FirmwareSource::Official,
            fallback_reason: None,
        })
    }
    pub fn source(&self) -> FirmwareSource {
        self.source
    }
    pub fn fallback_reason(&self) -> Option<&str> {
        self.fallback_reason.as_deref()
    }
    pub fn releases(&self) -> &[FirmwareRelease] {
        &self.releases
    }
    /// Select the official latest release, or the newest numbered archive build.
    pub fn latest_release(&self) -> Result<&FirmwareRelease> {
        let mut marked = self.releases.iter().filter(|r| r.latest);
        if let Some(latest) = marked.next() {
            if marked.next().is_some() {
                return Err(invalid("catalog marks multiple releases as latest; select a build ID"));
            }
            return Ok(latest);
        }
        fn numbers(value: &str) -> Option<Vec<u32>> {
            value.split('.').map(|part| part.parse().ok()).collect()
        }
        let mut newest: Option<(&FirmwareRelease, Vec<u32>, Vec<u32>)> = None;
        let mut ambiguous = false;
        for release in &self.releases {
            let version = numbers(release.version.split_whitespace().next().unwrap_or(""))
                .ok_or_else(|| invalid("cannot order firmware versions; select a build ID"))?;
            let date = numbers(&release.date)
                .filter(|date| date.len() == 3)
                .ok_or_else(|| invalid("cannot order firmware build dates; select a build ID"))?;
            match &newest {
                Some((_, v, d)) if (&version, &date) < (v, d) => continue,
                Some((_, v, d)) if (&version, &date) == (v, d) => {
                    ambiguous = true;
                }
                _ => {
                    newest = Some((release, version, date));
                    ambiguous = false;
                }
            }
        }
        if ambiguous {
            return Err(invalid("latest firmware build is ambiguous; select a build ID"));
        }
        let release = newest
            .map(|(release, _, _)| release)
            .ok_or_else(|| invalid("firmware catalog contains no releases"))?;
        if release.version.split_whitespace().count() != 1 {
            return Err(invalid("latest firmware has a version suffix; select a build ID"));
        }
        Ok(release)
    }
    /// Find a build ID or an unambiguous version. Duplicate versions return None.
    pub fn release(&self, selector: &str) -> Option<&FirmwareRelease> {
        if let Some(release) = self.releases.iter().find(|r| r.id == selector) {
            return Some(release);
        }
        let mut matching = self.releases.iter().filter(|r| r.version == selector);
        let release = matching.next()?;
        matching.next().is_none().then_some(release)
    }

    /// Resolve a selector with an actionable error for versions with multiple builds.
    pub fn select_release(&self, selector: &str) -> Result<&FirmwareRelease> {
        if let Some(release) = self.release(selector) {
            return Ok(release);
        }
        let matching: Vec<_> = self
            .releases
            .iter()
            .filter(|r| r.version == selector)
            .map(|r| r.id.as_str())
            .collect();
        if matching.len() > 1 {
            return Err(invalid(format!(
                "version {selector} has multiple builds; select a build ID: {}",
                matching.join(", ")
            )));
        }
        Err(invalid(format!("release {selector} is not present in the catalog")))
    }
}

fn identity_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.contains("..")
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Original container bytes and its independently validated firmware image.
#[derive(Debug)]
pub struct FirmwareDownload {
    package: Vec<u8>,
    image: FirmwareImage,
    sha256: [u8; 32],
    source: FirmwareSource,
    fallback_reason: Option<String>,
}
impl FirmwareDownload {
    pub fn source(&self) -> FirmwareSource {
        self.source
    }
    pub fn fallback_reason(&self) -> Option<&str> {
        self.fallback_reason.as_deref()
    }
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
    pub fn source(&self) -> FirmwareSource {
        if self.mirror.is_some() {
            FirmwareSource::Mirror
        } else {
            FirmwareSource::Official
        }
    }
    /// Resource URL without credentials. Use the catalog client for authenticated
    /// official downloads and source fallback.
    pub fn download_url(&self) -> Result<String> {
        if self.mirror.is_some() {
            validate_mirror_key(&self.key)?;
            Ok(format!("{FIRMWARE_MIRROR_URL}/{}", self.key))
        } else {
            validate_key(&self.key)?;
            Ok(format!("{ENDPOINT}/{}", self.key))
        }
    }

    /// Whole-container hash supplied by the mirror, before downloading.
    pub fn expected_sha256(&self) -> Option<&[u8; 32]> {
        self.mirror.as_ref().map(|m| &m.sha256)
    }

    /// Whole-container size supplied by the mirror, including any outer trailer.
    pub fn package_size(&self) -> Option<usize> {
        self.mirror.as_ref().map(|m| m.package_size)
    }

    /// Validate bytes against both the package metadata and this catalog entry.
    /// This can be used with frontend-specific browser/network transports too.
    pub fn validate_package(&self, bytes: &[u8]) -> Result<FirmwareDownload> {
        if let Some(integrity) = &self.mirror {
            validate_mirror_key(&self.key)?;
            if bytes.len() != integrity.package_size || <[u8; 32]>::from(Sha256::digest(bytes)) != integrity.sha256 {
                return Err("mirror package size or SHA256 mismatch".into());
            }
        } else {
            validate_key(&self.key)?;
        }
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
                "firmware catalog mismatch: expected KM003C {} ({}) {} bytes CRC32 {:08X}; \
             received {} {} ({}) {} bytes CRC32 {:08X}",
                self.version, self.date, self.size, self.crc32, m.model, m.version, m.date, m.size, m.crc32
            )
            .into());
        }
        Ok(FirmwareDownload {
            package: bytes.to_vec(),
            image,
            sha256: Sha256::digest(bytes).into(),
            source: self.source(),
            fallback_reason: None,
        })
    }
}

use crate::embedded_keys::{OSS_ACCESS_KEY_ID, OSS_ACCESS_KEY_SECRET};

// Deliberately no Debug or Serialize implementation: never log credentials.
struct Credentials {
    id: String,
    secret: Vec<u8>,
}

impl Credentials {
    fn official() -> Self {
        Self {
            id: String::from_utf8(OSS_ACCESS_KEY_ID.to_vec()).expect("embedded OSS ID is UTF-8"),
            secret: OSS_ACCESS_KEY_SECRET.to_vec(),
        }
    }

    fn signature(&self, key: &str, date_or_expiry: &str) -> String {
        let mut mac = Hmac::<Sha1>::new_from_slice(&self.secret).expect("HMAC accepts arbitrary key lengths");
        mac.update(format!("GET\n\n\n{date_or_expiry}\n/{BUCKET}/{key}").as_bytes());
        STANDARD.encode(mac.finalize().into_bytes())
    }
    #[cfg(not(target_arch = "wasm32"))]
    fn authorization(&self, key: &str, date: &str) -> String {
        format!("OSS {}:{}", self.id, self.signature(key, date))
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
        let key = text("Key");
        validate_key(&key)?;
        if releases.iter().any(|r: &FirmwareRelease| r.key == key) {
            return Err("duplicate firmware build ID in catalog".into());
        }
        let size = text("Size")
            .parse()
            .map_err(|e: std::num::ParseIntError| invalid(e.to_string()))?;
        let crc32 = u32::from_str_radix(&text("Crc"), 16).map_err(|e| invalid(e.to_string()))?;
        releases.push(FirmwareRelease {
            id: key.clone(),
            version,
            key,
            date: text("LastModified"),
            notes_zh: text("Note"),
            notes_en: text("Note2"),
            latest: text("IsLatest") == "true",
            stable: text("IsStable") == "true",
            size,
            crc32,
            mirror: None,
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

fn validate_mirror_key(key: &str) -> Result {
    let parts: Vec<_> = key.split('/').collect();
    if parts.len() != 4
        || parts[..2] != ["firmware", "km003c"]
        || !identity_token(parts[2])
        || !parts[3].ends_with(".mencrypt")
        || parts[3].len() > 160
        || !identity_token_filename(parts[3])
    {
        return Err("invalid firmware mirror path".into());
    }
    Ok(())
}

fn identity_token_filename(value: &str) -> bool {
    !value.is_empty()
        && !value.contains("..")
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Shared official-first orchestration for native and browser transports.
pub struct FirmwareCatalogClient<T = PlatformFirmwareHttp> {
    transport: T,
}
impl FirmwareCatalogClient<PlatformFirmwareHttp> {
    pub fn new() -> Result<Self> {
        Ok(Self::with_transport(PlatformFirmwareHttp::new()?))
    }
}
impl<T: FirmwareHttpTransport> FirmwareCatalogClient<T> {
    /// Supply a frontend HTTP adapter or an offline test transport.
    pub fn with_transport(transport: T) -> Self {
        Self { transport }
    }
    async fn get_bytes(&self, request: FirmwareHttpRequest) -> Result<Vec<u8>> {
        let bytes = self.transport.get(request).await?;
        if bytes.len() > MAX_DOWNLOAD {
            return Err(invalid("firmware download exceeds 2 MiB"));
        }
        Ok(bytes)
    }
    async fn official_catalog(&self) -> Result<FirmwareCatalog> {
        let bytes = self.get_bytes(FirmwareHttpRequest::official("expect.xml")?).await?;
        let xml = std::str::from_utf8(&bytes).map_err(|e| invalid(e.to_string()))?;
        FirmwareCatalog::parse_xml(xml)
    }
    async fn mirror_catalog(&self) -> Result<FirmwareCatalog> {
        let bytes = self.get_bytes(FirmwareHttpRequest::mirror("catalog.json")?).await?;
        let json = std::str::from_utf8(&bytes).map_err(|e| invalid(e.to_string()))?;
        FirmwareCatalog::parse_json(json)
    }
    /// Fetch the official feed first; use the archive if HTTP or parsing fails.
    pub async fn fetch(&self) -> Result<FirmwareCatalog> {
        match self.official_catalog().await {
            Ok(catalog) => Ok(catalog),
            Err(official) => {
                let mut catalog = self
                    .mirror_catalog()
                    .await
                    .map_err(|mirror| fallback_error(&official, mirror))?;
                catalog.fallback_reason = Some(official.to_string());
                Ok(catalog)
            }
        }
    }
    /// Resolve a build ID/version, including mirror-only archived build IDs.
    pub async fn download_selected(&self, selector: &str) -> Result<FirmwareDownload> {
        let catalog = self.fetch().await?;
        match catalog.select_release(selector) {
            Ok(release) => self.download(release).await,
            Err(official)
                if catalog.source() == FirmwareSource::Official
                    && !catalog.releases().iter().any(|release| release.version == selector) =>
            {
                let mirror = self.mirror_catalog().await.map_err(|e| fallback_error(&official, e))?;
                let release = mirror
                    .select_release(selector)
                    .map_err(|e| fallback_error(&official, e))?;
                self.download(release).await
            }
            Err(error) => Err(error),
        }
    }
    /// Try the official object, then the exact matching archived application.
    /// Fallback never changes version, build date, size or firmware CRC.
    pub async fn download(&self, release: &FirmwareRelease) -> Result<FirmwareDownload> {
        match self.official_download(release).await {
            Ok(download) => Ok(download),
            Err(official) => {
                let mut download = self
                    .mirror_download(release)
                    .await
                    .map_err(|mirror| fallback_error(&official, mirror))?;
                download.fallback_reason = Some(official.to_string());
                Ok(download)
            }
        }
    }
    async fn official_download(&self, wanted: &FirmwareRelease) -> Result<FirmwareDownload> {
        let catalog;
        let release = if wanted.source() == FirmwareSource::Official {
            wanted
        } else {
            catalog = self.official_catalog().await?;
            matching_release(&catalog, wanted)?
        };
        let bytes = self.get_bytes(FirmwareHttpRequest::official(&release.key)?).await?;
        let download = release.validate_package(&bytes)?;
        // Mirror-selected builds retain their whole-container SHA256 requirement.
        let mut download = if wanted.source() == FirmwareSource::Mirror {
            wanted.validate_package(&bytes)?
        } else {
            download
        };
        download.source = FirmwareSource::Official;
        Ok(download)
    }
    async fn mirror_download(&self, wanted: &FirmwareRelease) -> Result<FirmwareDownload> {
        let catalog;
        let release = if wanted.source() == FirmwareSource::Mirror {
            wanted
        } else {
            catalog = self.mirror_catalog().await?;
            matching_release(&catalog, wanted)?
        };
        let bytes = self.get_bytes(FirmwareHttpRequest::mirror(&release.key)?).await?;
        release.validate_package(&bytes)
    }
}
fn matching_release<'a>(catalog: &'a FirmwareCatalog, wanted: &FirmwareRelease) -> Result<&'a FirmwareRelease> {
    let mut matches = catalog.releases().iter().filter(|candidate| {
        candidate.version == wanted.version
            && candidate.date == wanted.date
            && candidate.size == wanted.size
            && candidate.crc32 == wanted.crc32
    });
    let release = matches.next().ok_or_else(|| {
        invalid(format!(
            "no matching build for {} ({}) {} bytes CRC32 {:08X}",
            wanted.version, wanted.date, wanted.size, wanted.crc32
        ))
    })?;
    if matches.next().is_some() {
        return Err(invalid("multiple matching builds; select an explicit build ID"));
    }
    Ok(release)
}
fn fallback_error(official: &FirmwareCatalogError, mirror: FirmwareCatalogError) -> FirmwareCatalogError {
    FirmwareCatalogError::Fallback {
        official: official.to_string(),
        mirror: mirror.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, sync::Mutex};

    struct Reply {
        source: FirmwareSource,
        key: String,
        body: Result<Vec<u8>>,
    }
    struct ScriptedHttp(Mutex<VecDeque<Reply>>);
    impl FirmwareHttpTransport for ScriptedHttp {
        async fn get(&self, request: FirmwareHttpRequest) -> Result<Vec<u8>> {
            let reply = self.0.lock().unwrap().pop_front().expect("unexpected HTTP request");
            assert_eq!(request.source(), reply.source);
            let base = match reply.source {
                FirmwareSource::Official => ENDPOINT,
                FirmwareSource::Mirror => FIRMWARE_MIRROR_URL,
            };
            assert_eq!(request.url(), format!("{base}/{}", reply.key));
            reply.body
        }
    }
    fn scripted(replies: Vec<Reply>) -> FirmwareCatalogClient<ScriptedHttp> {
        FirmwareCatalogClient::with_transport(ScriptedHttp(Mutex::new(replies.into())))
    }
    fn reply(source: FirmwareSource, key: &str, body: Result<Vec<u8>>) -> Reply {
        Reply {
            source,
            key: key.into(),
            body,
        }
    }
    fn catalog_fixture(bytes: &[u8]) -> (String, String, FirmwareRelease, FirmwareRelease) {
        let image = FirmwareImage::parse(bytes).unwrap();
        let xml = XML
            .replace("453828", &image.metadata().size.to_string())
            .replace("7C80B54E", &format!("{:08X}", image.metadata().crc32));
        let json = mirror_json(vec![mirror_entry(bytes)]);
        let official = FirmwareCatalog::parse_xml(&xml).unwrap().releases()[0].clone();
        let mirror = FirmwareCatalog::parse_json(&json).unwrap().releases()[0].clone();
        (xml, json, official, mirror)
    }
    fn drained(client: &FirmwareCatalogClient<ScriptedHttp>) {
        assert!(client.transport.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn official_catalog_success_never_queries_the_mirror() {
        let bytes = crate::firmware::tests::package(4156, &[]);
        let (xml, _, _, _) = catalog_fixture(&bytes);
        let client = scripted(vec![reply(
            FirmwareSource::Official,
            "expect.xml",
            Ok(xml.into_bytes()),
        )]);
        let catalog = client.fetch().await.unwrap();
        assert_eq!(catalog.source(), FirmwareSource::Official);
        assert!(catalog.fallback_reason().is_none());
        drained(&client);
    }

    #[tokio::test]
    async fn catalog_fallback_covers_transport_parse_and_size_errors() {
        let bytes = crate::firmware::tests::package(4156, &[]);
        let (_, json, _, _) = catalog_fixture(&bytes);
        for primary in [
            Err(invalid("403 disabled")),
            Ok(b"<broken/>".to_vec()),
            Ok(vec![0; MAX_DOWNLOAD + 1]),
        ] {
            let client = scripted(vec![
                reply(FirmwareSource::Official, "expect.xml", primary),
                reply(FirmwareSource::Mirror, "catalog.json", Ok(json.clone().into_bytes())),
            ]);
            let catalog = client.fetch().await.unwrap();
            assert_eq!(catalog.source(), FirmwareSource::Mirror);
            assert!(catalog.fallback_reason().is_some());
            drained(&client);
        }
    }

    #[tokio::test]
    async fn both_source_failures_are_reported() {
        let client = scripted(vec![
            reply(FirmwareSource::Official, "expect.xml", Err(invalid("primary offline"))),
            reply(FirmwareSource::Mirror, "catalog.json", Err(invalid("mirror offline"))),
        ]);
        let error = client.fetch().await.unwrap_err().to_string();
        assert!(error.contains("primary offline") && error.contains("mirror offline"));
        drained(&client);
    }

    #[tokio::test]
    async fn package_fallback_covers_http_corruption_and_identity_mismatch() {
        let bytes = crate::firmware::tests::package(4156, &[]);
        let (_, json, wanted, mirror) = catalog_fixture(&bytes);
        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 0x80;
        let other = crate::firmware::tests::package(4172, &[]);
        for primary in [Err(invalid("403 disabled")), Ok(corrupt), Ok(other)] {
            let client = scripted(vec![
                reply(FirmwareSource::Official, &wanted.key, primary),
                reply(FirmwareSource::Mirror, "catalog.json", Ok(json.clone().into_bytes())),
                reply(FirmwareSource::Mirror, &mirror.key, Ok(bytes.clone())),
            ]);
            let download = client.download(&wanted).await.unwrap();
            assert_eq!(download.source(), FirmwareSource::Mirror);
            assert_eq!(download.package(), bytes);
            assert!(download.fallback_reason().is_some());
            drained(&client);
        }
    }

    #[tokio::test]
    async fn mirror_selection_still_prefers_the_official_server() {
        let bytes = crate::firmware::tests::package(4156, &[]);
        let (xml, _, official, wanted) = catalog_fixture(&bytes);
        let client = scripted(vec![
            reply(FirmwareSource::Official, "expect.xml", Ok(xml.into_bytes())),
            reply(FirmwareSource::Official, &official.key, Ok(bytes.clone())),
        ]);
        let download = client.download(&wanted).await.unwrap();
        assert_eq!(download.source(), FirmwareSource::Official);
        assert!(download.fallback_reason().is_none());
        assert_eq!(download.package(), bytes);
        drained(&client);
    }

    #[tokio::test]
    async fn mirror_selection_keeps_its_exact_package_hash() {
        let bytes = crate::firmware::tests::package(4156, &[1, 2]);
        let (xml, _, official, wanted) = catalog_fixture(&bytes);
        let other_container = crate::firmware::tests::package(4156, &[3, 4]);
        let client = scripted(vec![
            reply(FirmwareSource::Official, "expect.xml", Ok(xml.into_bytes())),
            reply(FirmwareSource::Official, &official.key, Ok(other_container)),
            reply(FirmwareSource::Mirror, &wanted.key, Ok(bytes.clone())),
        ]);
        let download = client.download(&wanted).await.unwrap();
        assert_eq!(download.source(), FirmwareSource::Mirror);
        assert_eq!(download.package(), bytes);
        drained(&client);
    }

    #[tokio::test]
    async fn fallback_refuses_a_different_build_of_the_same_version() {
        let bytes = crate::firmware::tests::package(4156, &[]);
        let (_, _, wanted, _) = catalog_fixture(&bytes);
        let wrong_build = crate::firmware::tests::package(4172, &[]);
        let json = mirror_json(vec![mirror_entry(&wrong_build)]);
        let client = scripted(vec![
            reply(FirmwareSource::Official, &wanted.key, Err(invalid("missing object"))),
            reply(FirmwareSource::Mirror, "catalog.json", Ok(json.into_bytes())),
        ]);
        assert!(
            client
                .download(&wanted)
                .await
                .unwrap_err()
                .to_string()
                .contains("no matching build")
        );
        drained(&client);
    }

    #[tokio::test]
    async fn mirror_build_ids_still_resolve_with_a_healthy_official_catalog() {
        let bytes = crate::firmware::tests::package(4156, &[]);
        let (xml, json, official, wanted) = catalog_fixture(&bytes);
        let client = scripted(vec![
            reply(FirmwareSource::Official, "expect.xml", Ok(xml.clone().into_bytes())),
            reply(FirmwareSource::Mirror, "catalog.json", Ok(json.into_bytes())),
            reply(FirmwareSource::Official, "expect.xml", Ok(xml.into_bytes())),
            reply(FirmwareSource::Official, &official.key, Ok(bytes.clone())),
        ]);
        let download = client.download_selected(&wanted.id).await.unwrap();
        assert_eq!(download.source(), FirmwareSource::Official);
        assert_eq!(download.package(), bytes);
        drained(&client);
    }

    #[tokio::test]
    async fn ambiguous_official_versions_require_a_build_id_without_substitution() {
        let bytes = crate::firmware::tests::package(4156, &[]);
        let (xml, _, _, _) = catalog_fixture(&bytes);
        let title = xml.split("<Title").nth(1).unwrap().split("</Title>").next().unwrap();
        let second = format!("<Title{title}</Title>").replace("KM003C_V1.9.7.mencrypt", "KM003C_V1.9.7_alt.mencrypt");
        let xml = xml.replace("</Updateinfo>", &format!("{second}</Updateinfo>"));
        let client = scripted(vec![reply(
            FirmwareSource::Official,
            "expect.xml",
            Ok(xml.into_bytes()),
        )]);
        assert!(
            client
                .download_selected("1.9.7")
                .await
                .unwrap_err()
                .to_string()
                .contains("multiple builds")
        );
        drained(&client);
    }
    fn mirror_entry(bytes: &[u8]) -> serde_json::Value {
        let image = FirmwareImage::parse(bytes).unwrap();
        let m = image.metadata();
        let hash = hex::encode(Sha256::digest(bytes));
        let path = format!("firmware/km003c/{}/{}-{hash}.mencrypt", m.version, m.date);
        serde_json::json!({
            "id": format!("km003c-{}-{}-{}", m.version, m.date, &hash[..12]),
            "model": m.model, "version": m.version, "build_date": m.date,
            "path": path, "url": format!("{FIRMWARE_MIRROR_URL}/{path}"),
            "sha256": hash, "package_size": bytes.len(), "firmware_size": m.size,
            "crc32": format!("{:08X}", m.crc32), "notes_en": "", "notes_zh": "",
        })
    }

    fn mirror_json(entries: Vec<serde_json::Value>) -> String {
        serde_json::json!({"schema_version": 1, "model": "KM003C", "releases": entries}).to_string()
    }

    #[test]
    fn mirror_checks_whole_package_hash_including_non_firmware_trailer() {
        let bytes = crate::firmware::tests::package(4156, &[1, 2]);
        let catalog = FirmwareCatalog::parse_json(&mirror_json(vec![mirror_entry(&bytes)])).unwrap();
        let release = &catalog.releases()[0];
        assert_eq!(
            release.download_url().unwrap(),
            format!("{FIRMWARE_MIRROR_URL}/{}", release.key)
        );
        assert_eq!(release.package_size(), Some(bytes.len()));
        assert_eq!(
            release.expected_sha256(),
            Some(&<[u8; 32]>::from(Sha256::digest(&bytes)))
        );
        assert_eq!(release.validate_package(&bytes).unwrap().package(), bytes);
        let mut tampered = bytes.clone();
        *tampered.last_mut().unwrap() ^= 1;
        // The firmware CRC is still valid; the package's external trailer changed.
        FirmwareImage::parse(&tampered).unwrap().validate_for_update().unwrap();
        assert!(
            release
                .validate_package(&tampered)
                .unwrap_err()
                .to_string()
                .contains("SHA256")
        );
    }

    #[test]
    fn duplicate_versions_require_a_build_id_instead_of_selecting_first_entry() {
        let a = crate::firmware::tests::package(4156, &[1]);
        let b = crate::firmware::tests::package(4156, &[2]);
        let catalog = FirmwareCatalog::parse_json(&mirror_json(vec![mirror_entry(&a), mirror_entry(&b)])).unwrap();
        let version = &catalog.releases()[0].version;
        assert!(catalog.release(version).is_none());
        let error = catalog.select_release(version).unwrap_err().to_string();
        for release in catalog.releases() {
            assert!(error.contains(&release.id));
            assert_eq!(catalog.select_release(&release.id).unwrap(), release);
        }
    }

    #[test]
    fn mirror_rejects_redirected_urls_paths_duplicate_ids_and_unknown_schemas() {
        let bytes = crate::firmware::tests::package(4156, &[]);
        let original = mirror_entry(&bytes);
        for (field, value) in [
            ("url", serde_json::json!("https://example.com/firmware.mencrypt")),
            ("path", serde_json::json!("firmware/km003c/../x.mencrypt")),
            ("id", serde_json::json!("wrong-build")),
            ("sha256", serde_json::json!("bad")),
            ("package_size", serde_json::json!(MAX_DOWNLOAD + 1)),
        ] {
            let mut entry = original.clone();
            entry[field] = value;
            assert!(
                FirmwareCatalog::parse_json(&mirror_json(vec![entry])).is_err(),
                "{field}"
            );
        }
        assert!(FirmwareCatalog::parse_json(&mirror_json(vec![original.clone(), original])).is_err());
        assert!(FirmwareCatalog::parse_json(r#"{"schema_version":2,"model":"KM003C","releases":[]}"#).is_err());
    }

    const XML: &str = r#"<Updateinfo><DeviceName>KM003C</DeviceName><Title version="1.9.7"><Key>KM003C_V1.9.7.mencrypt</Key><Size>453828</Size><Crc>7C80B54E</Crc><LastModified>2025.9.1</LastModified><Note>修复</Note><Note2>A &amp; B</Note2><IsStable>true</IsStable><IsLatest>false</IsLatest></Title></Updateinfo>"#;
    #[test]
    fn latest_selection_honors_official_flag_and_orders_archive_builds() {
        let mut catalog = FirmwareCatalog::parse_xml(XML).unwrap();
        let base = catalog.releases[0].clone();
        let mut newer = base.clone();
        newer.version = "1.10.0".into();
        newer.date = "2025.10.2".into();
        catalog.releases.push(newer.clone());
        catalog.releases[0].version = "1.9.7 alpha".into();
        assert_eq!(catalog.latest_release().unwrap(), &newer);
        let mut later_build = newer.clone();
        later_build.date = "2025.10.10".into();
        catalog.releases.push(later_build.clone());
        assert_eq!(catalog.latest_release().unwrap(), &later_build);
        catalog.releases[0].latest = true;
        assert_eq!(catalog.latest_release().unwrap().version, "1.9.7 alpha");
        catalog.releases[1].latest = true;
        assert!(catalog.latest_release().is_err());
    }
    #[test]
    fn latest_selection_rejects_ambiguous_or_unorderable_builds() {
        let mut catalog = FirmwareCatalog::parse_xml(XML).unwrap();
        catalog.releases.push(catalog.releases[0].clone());
        assert!(catalog.latest_release().is_err());
        catalog.releases[1].version = "preview".into();
        assert!(catalog.latest_release().is_err());
    }
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
                .contains("firmware catalog mismatch")
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
            credentials.authorization("expect.xml", "Wed, 28 Oct 2026 12:00:00 GMT"),
            "OSS example:ymwrkiuMt/yPO0x8erDHl2x4HKU="
        );
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn embedded_credentials_match_original_signature() {
        let authorization = Credentials::official().authorization("expect.xml", "Wed, 28 Oct 2026 12:00:00 GMT");
        let (id, signature) = authorization.strip_prefix("OSS ").unwrap().split_once(':').unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(id.as_bytes())),
            "703ad8ce5fe727c72b94f692214737afe50850cf42a87916f5f09fd17766c82a"
        );
        assert_eq!(signature, "dr843lzwCizORfsq8cRY+7jJHPY=");
    }
}
