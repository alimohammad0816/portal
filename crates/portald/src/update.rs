//! Installing app updates. The desktop app downloads the release package
//! for this system (`.deb`, `.rpm` or Arch `.pkg.tar.zst`) and its minisign
//! signature as the user and hands the daemon an open file descriptor. The
//! daemon (root) only installs packages that are signed by the release key
//! compiled into it, are named `portal`, and are newer than the running
//! version.

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use minisign_verify::{PublicKey, Signature};
use portal_core::package::{PackageFormat, is_newer};

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

fn run(cmd: &mut Command, what: &str) -> Result<String> {
    let out = cmd.output().with_context(|| format!("running {what}"))?;
    ensure!(
        out.status.success(),
        "the update isn't a valid package ({what} failed)"
    );
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Name and version recorded in the package file.
fn package_info(format: PackageFormat, path: &Path) -> Result<(String, String)> {
    match format {
        PackageFormat::Deb => {
            let field = |f: &str| -> Result<String> {
                Ok(run(
                    Command::new("dpkg-deb").arg("--field").arg(path).arg(f),
                    "dpkg-deb",
                )?
                .trim()
                .to_string())
            };
            Ok((field("Package")?, field("Version")?))
        }
        PackageFormat::Rpm => {
            let out = run(
                Command::new("rpm")
                    .args([
                        "-qp",
                        "--nosignature",
                        "--queryformat",
                        "%{NAME}\\n%{VERSION}\\n",
                    ])
                    .arg(path),
                "rpm",
            )?;
            let mut lines = out.lines();
            Ok((
                lines.next().unwrap_or("").trim().to_string(),
                lines.next().unwrap_or("").trim().to_string(),
            ))
        }
        PackageFormat::Arch => {
            let out = run(Command::new("pacman").arg("-Qip").arg(path), "pacman")?;
            Ok(parse_pacman_info(&out))
        }
    }
}

/// `Name : portal` and `Version : 0.2.0-1` from `pacman -Qip`.
fn parse_pacman_info(text: &str) -> (String, String) {
    let field = |name: &str| {
        text.lines()
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.trim() == name)
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default()
    };
    (field("Name"), field("Version"))
}

/// The package manager command that installs `path`.
fn installer(format: PackageFormat) -> Vec<&'static str> {
    let has = |p: &str| Path::new(p).exists();
    match format {
        PackageFormat::Deb => vec![
            "--setenv",
            "DEBIAN_FRONTEND=noninteractive",
            "/usr/bin/apt-get",
            "install",
            "-y",
            "--no-install-recommends",
        ],
        PackageFormat::Rpm if has("/usr/bin/dnf") => vec!["/usr/bin/dnf", "install", "-y"],
        PackageFormat::Rpm if has("/usr/bin/zypper") => vec![
            "/usr/bin/zypper",
            "--non-interactive",
            "install",
            "--allow-unsigned-rpm",
        ],
        PackageFormat::Rpm => vec!["/usr/bin/rpm", "-U"],
        PackageFormat::Arch => vec!["/usr/bin/pacman", "-U", "--noconfirm"],
    }
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

    let format = PackageFormat::installed();
    std::fs::create_dir_all(cache_dir)?;
    let path: PathBuf = cache_dir.join(format!("portal-update.{}", format.extension()));
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

    let (name, version) = match package_info(format, &path) {
        Ok(info) => info,
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
    };
    if name != PACKAGE_NAME {
        let _ = std::fs::remove_file(&path);
        bail!("the update is for package `{name}`, not `{PACKAGE_NAME}`");
    }
    if !is_newer(&version, current_version()) {
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
        .args(installer(format))
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
    fn reads_pacman_package_info() {
        let text = "Name            : portal\nVersion         : 0.2.0-1\nDescription     : OpenVPN client\n";
        assert_eq!(
            parse_pacman_info(text),
            ("portal".to_string(), "0.2.0-1".to_string())
        );
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
