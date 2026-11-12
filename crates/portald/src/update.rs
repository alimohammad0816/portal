//! Installing app updates. The desktop app downloads a release `.deb` and
//! its minisign signature as the user and hands the daemon an open file
//! descriptor. The daemon (root) only installs packages that are signed by
//! the release key compiled into it, are named `portal`, and are newer than
//! the running version.

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use minisign_verify::{PublicKey, Signature};

/// Public half of the release signing key (`minisign -G`). Only packages
/// signed with the matching secret key, which lives in the GitHub Actions
/// secrets, will be installed.
const RELEASE_PUBLIC_KEY: &str = include_str!("../../../packaging/update-key.pub");

const PACKAGE_NAME: &str = "portal";
const MAX_PACKAGE_BYTES: u64 = 200 * 1024 * 1024;

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn public_key() -> Result<PublicKey> {
    // The .pub file is "untrusted comment: ..." followed by the key line.
    let line = RELEASE_PUBLIC_KEY
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
        .context("release public key is missing")?;
    PublicKey::from_base64(line).map_err(|e| anyhow::anyhow!("bad release public key: {e}"))
}

/// Check `data` against a minisign signature made with the release key.
pub fn verify(data: &[u8], signature: &str) -> Result<()> {
    let sig =
        Signature::decode(signature).map_err(|e| anyhow::anyhow!("malformed signature: {e}"))?;
    public_key()?
        .verify(data, &sig, false)
        .map_err(|_| anyhow::anyhow!("the update's signature doesn't match the release key"))
}

fn dpkg_field(path: &Path, field: &str) -> Result<String> {
    let out = Command::new("dpkg-deb")
        .arg("--field")
        .arg(path)
        .arg(field)
        .output()
        .context("running dpkg-deb")?;
    ensure!(
        out.status.success(),
        "the update isn't a valid .deb package"
    );
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn is_newer(candidate: &str, current: &str) -> Result<bool> {
    let status = Command::new("dpkg")
        .args(["--compare-versions", candidate, "gt", current])
        .status()
        .context("running dpkg")?;
    Ok(status.success())
}

/// Verify the package read from `source` and start installing it in a
/// separate systemd unit, so the install survives the daemon being
/// restarted by the package's own postinst script.
pub fn install(mut source: std::fs::File, signature: &str, cache_dir: &Path) -> Result<String> {
    let meta = source.metadata()?;
    ensure!(meta.is_file(), "the update must be a regular file");
    ensure!(meta.len() <= MAX_PACKAGE_BYTES, "the update is too large");

    let mut data = Vec::with_capacity(meta.len() as usize);
    source
        .by_ref()
        .take(MAX_PACKAGE_BYTES + 1)
        .read_to_end(&mut data)?;
    ensure!(
        data.len() as u64 <= MAX_PACKAGE_BYTES,
        "the update is too large"
    );

    verify(&data, signature)?;

    std::fs::create_dir_all(cache_dir)?;
    let path: PathBuf = cache_dir.join("portal-update.deb");
    let _ = std::fs::remove_file(&path);
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&path)
            .with_context(|| format!("writing {}", path.display()))?;
        f.write_all(&data)?;
        f.sync_all()?;
    }

    let name = dpkg_field(&path, "Package")?;
    if name != PACKAGE_NAME {
        let _ = std::fs::remove_file(&path);
        bail!("the update is for package `{name}`, not `{PACKAGE_NAME}`");
    }
    let version = dpkg_field(&path, "Version")?;
    if !is_newer(&version, current_version())? {
        let _ = std::fs::remove_file(&path);
        bail!(
            "version {version} isn't newer than the installed {}",
            current_version()
        );
    }

    let unit = format!(
        "portal-update-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );
    let status = Command::new("systemd-run")
        .args([
            "--unit",
            &unit,
            "--collect",
            "--description",
            "Install Portal update",
        ])
        .args(["--setenv", "DEBIAN_FRONTEND=noninteractive"])
        .args([
            "/usr/bin/apt-get",
            "install",
            "-y",
            "--no-install-recommends",
        ])
        .arg(&path)
        .status()
        .context("starting the installer")?;
    ensure!(status.success(), "couldn't start the installer");
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_key_parses() {
        public_key().unwrap();
    }

    #[test]
    fn rejects_bad_signatures() {
        assert!(verify(b"data", "not a signature").is_err());
    }

    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/signed.txt");
    const FIXTURE_SIG: &str = include_str!("../tests/fixtures/signed.txt.minisig");

    #[test]
    fn accepts_files_signed_by_the_release_key() {
        verify(FIXTURE, FIXTURE_SIG).unwrap();
    }

    #[test]
    fn rejects_tampered_files() {
        let mut data = FIXTURE.to_vec();
        data[0] ^= 1;
        assert!(verify(&data, FIXTURE_SIG).is_err());
    }
}
