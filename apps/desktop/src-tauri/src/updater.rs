//! Update checks against GitHub Releases. Downloads happen here, as the
//! user; the daemon verifies the signature and installs (see
//! `portald::update`).

use std::path::PathBuf;
use std::time::Duration;

use portal_core::names::UPDATE_REPO;
use portal_core::package::{PackageFormat, is_newer};
use serde::{Deserialize, Serialize};

const USER_AGENT: &str = concat!("Portal/", env!("CARGO_PKG_VERSION"), " (update check)");

#[derive(Serialize, Clone)]
pub struct UpdateInfo {
    /// Version of this app build.
    pub current: String,
    /// False when this build has no release repository compiled in.
    pub enabled: bool,
    /// Present when a newer release exists.
    pub available: Option<Release>,
}

#[derive(Serialize, Clone)]
pub struct Release {
    pub version: String,
    pub notes: String,
    pub url: String,
    pub published_at: String,
    #[serde(skip)]
    pub package_url: String,
    #[serde(skip)]
    pub sig_url: String,
}

#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    html_url: String,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    assets: Vec<GhAsset>,
}

#[derive(Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| e.to_string())
}

pub async fn check() -> Result<UpdateInfo, String> {
    let current = env!("CARGO_PKG_VERSION").to_string();
    let Some(repo) = UPDATE_REPO else {
        return Ok(UpdateInfo {
            current,
            enabled: false,
            available: None,
        });
    };
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let resp = client()?
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| format!("Couldn't check for updates: {e}"))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(UpdateInfo {
            current,
            enabled: true,
            available: None,
        });
    }
    let rel: GhRelease = resp
        .error_for_status()
        .map_err(|e| format!("Couldn't check for updates: {e}"))?
        .json()
        .await
        .map_err(|e| format!("Unexpected reply from GitHub: {e}"))?;
    if rel.draft || rel.prerelease || !is_newer(&rel.tag_name, &current) {
        return Ok(UpdateInfo {
            current,
            enabled: true,
            available: None,
        });
    }
    let format = PackageFormat::installed();
    let package = format
        .asset_suffix(std::env::consts::ARCH)
        .and_then(|suffix| rel.assets.iter().find(|a| a.name.ends_with(suffix)));
    let sig = package.and_then(|d| {
        rel.assets
            .iter()
            .find(|a| a.name == format!("{}.minisig", d.name))
    });
    let (Some(package), Some(sig)) = (package, sig) else {
        // A release without a package for this machine isn't installable.
        return Ok(UpdateInfo {
            current,
            enabled: true,
            available: None,
        });
    };
    Ok(UpdateInfo {
        current,
        enabled: true,
        available: Some(Release {
            version: rel.tag_name.trim_start_matches('v').to_string(),
            notes: rel.body.unwrap_or_default(),
            url: rel.html_url,
            published_at: rel.published_at.unwrap_or_default(),
            package_url: package.browser_download_url.clone(),
            sig_url: sig.browser_download_url.clone(),
        }),
    })
}

/// Download the package and its signature into the user's cache.
pub async fn download(rel: &Release) -> Result<(PathBuf, String), String> {
    let http = client()?;
    let sig = http
        .get(&rel.sig_url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| format!("Downloading the signature failed: {e}"))?
        .text()
        .await
        .map_err(|e| e.to_string())?;
    let bytes = http
        .get(&rel.package_url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| format!("Downloading the update failed: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("Downloading the update failed: {e}"))?;

    let dir = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir)
        .join("portal");
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| e.to_string())?;
    let ext = PackageFormat::installed().extension();
    let path = dir.join(format!("portal_{}.{ext}", rel.version));
    tokio::fs::write(&path, &bytes)
        .await
        .map_err(|e| e.to_string())?;
    Ok((path, sig))
}
