//! On-disk profile store: one sanitized `<id>.ovpn` per profile plus an
//! `index.json` with the metadata shown in the UI. Everything is 0600 and
//! owned by the daemon's user.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use portal_core::ovpn;
use portal_core::{AuthKind, Profile, ProfileEdit};

pub struct ProfileStore {
    dir: PathBuf,
    profiles: Vec<Profile>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

impl ProfileStore {
    pub fn open(dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        let index = dir.join("index.json");
        let profiles = match fs::read(&index) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("reading index.json")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).context("reading index.json"),
        };
        Ok(Self { dir, profiles })
    }

    fn save_index(&self) -> Result<()> {
        write_private(
            &self.dir.join("index.json"),
            &serde_json::to_vec_pretty(&self.profiles)?,
        )
    }

    pub fn list(&self) -> &[Profile] {
        &self.profiles
    }

    pub fn get(&self, id: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    /// Path of the sanitized config for `id`. The id is checked against the
    /// index, so it can never name a file outside the store.
    pub fn config_path(&self, id: &str) -> Option<PathBuf> {
        self.get(id)
            .map(|p| self.dir.join(format!("{}.ovpn", p.id)))
    }

    pub fn import(&mut self, file_name: &str, content: &str) -> Result<Profile> {
        let parsed = ovpn::sanitize(content)?;
        let id = uuid::Uuid::new_v4().simple().to_string();
        let stem = Path::new(file_name)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Profile")
            .to_string();
        let remote = parsed.primary().clone();
        let country = ovpn::guess_country(&[&remote.host, &stem]);
        let profile = Profile {
            id: id.clone(),
            name: pretty_name(&stem),
            group: "Imported".into(),
            country,
            remote_host: remote.host,
            remote_port: remote.port,
            proto: remote.proto,
            auth: parsed.auth,
            challenge: parsed.challenge,
            source_file: file_name.to_string(),
            imported_at: now(),
            last_connected_at: None,
            key_encrypted: parsed.key_encrypted,
            disable_dco: false,
            extra_directives: String::new(),
        };
        write_private(
            &self.dir.join(format!("{id}.ovpn")),
            parsed.sanitized.as_bytes(),
        )?;
        self.profiles.push(profile.clone());
        self.save_index()?;
        Ok(profile)
    }

    /// The sanitized config text of `id`.
    pub fn config_text(&self, id: &str) -> Result<String> {
        let path = self
            .config_path(id)
            .ok_or_else(|| anyhow::anyhow!("no profile with id {id}"))?;
        fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))
    }

    pub fn update(&mut self, id: &str, edit: &ProfileEdit) -> Result<Profile> {
        // Check everything before changing anything.
        let extra = edit
            .extra_directives
            .as_deref()
            .map(ovpn::sanitize_extra)
            .transpose()
            .map_err(|e| anyhow::anyhow!("Extra options: {e}"))?;
        let Some(p) = self.profiles.iter_mut().find(|p| p.id == id) else {
            bail!("no profile with id {id}");
        };
        if let Some(name) = edit.name.as_deref().map(str::trim)
            && !name.is_empty()
        {
            p.name = name.chars().take(80).collect();
        }
        if let Some(group) = edit.group.as_deref().map(str::trim)
            && !group.is_empty()
        {
            p.group = group.chars().take(60).collect();
        }
        if let Some(country) = edit.country.as_deref().map(str::trim) {
            if country.len() == 2 && country.chars().all(|c| c.is_ascii_alphabetic()) {
                p.country = Some(country.to_ascii_uppercase());
            } else if country == "-" {
                p.country = None;
            }
        }
        if let Some(d) = edit.disable_dco {
            p.disable_dco = d;
        }
        if let Some(extra) = extra {
            p.extra_directives = extra;
        }
        let out = p.clone();
        self.save_index()?;
        Ok(out)
    }

    pub fn remove(&mut self, id: &str) -> Result<()> {
        let before = self.profiles.len();
        self.profiles.retain(|p| p.id != id);
        if self.profiles.len() == before {
            bail!("no profile with id {id}");
        }
        self.save_index()?;
        let _ = fs::remove_file(self.dir.join(format!("{id}.ovpn")));
        Ok(())
    }

    pub fn mark_connected(&mut self, id: &str) {
        if let Some(p) = self.profiles.iter_mut().find(|p| p.id == id) {
            p.last_connected_at = Some(now());
            let _ = self.save_index();
        }
    }

    /// OpenVPN asked for a key passphrase we didn't know about (PKCS#12
    /// files, unusual PEM): remember, so the app asks up front next time.
    pub fn set_key_encrypted(&mut self, id: &str) {
        if let Some(p) = self.profiles.iter_mut().find(|p| p.id == id)
            && !p.key_encrypted
        {
            p.key_encrypted = true;
            let _ = self.save_index();
        }
    }

    pub fn needs_credentials(&self, id: &str) -> bool {
        self.get(id)
            .is_some_and(|p| p.auth != AuthKind::Certificate)
    }
}

/// `de-fra-02` → `De fra 02` is not much better than the raw stem, so only
/// tidy separators and leave the rest to the user.
fn pretty_name(stem: &str) -> String {
    let s: String = stem.replace(['_', '.'], " ").trim().to_string();
    if s.is_empty() {
        "Profile".into()
    } else {
        s.chars().take(80).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = "client\nremote nl-ams-01.example.net 443 tcp\nauth-user-pass\n";

    #[test]
    fn import_update_remove_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ProfileStore::open(dir.path().join("profiles")).unwrap();
        let p = store.import("nl_ams.ovpn", CFG).unwrap();
        assert_eq!(p.country.as_deref(), Some("NL"));
        assert_eq!(p.proto, "tcp");
        assert!(store.needs_credentials(&p.id));
        let path = store.config_path(&p.id).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let reopened = ProfileStore::open(dir.path().join("profiles")).unwrap();
        assert_eq!(reopened.list().len(), 1);

        let u = store
            .update(
                &p.id,
                &ProfileEdit {
                    name: Some("Amsterdam".into()),
                    group: Some("Provider A".into()),
                    country: Some("nl".into()),
                    disable_dco: Some(true),
                    extra_directives: Some("mssfix 1400\n".into()),
                },
            )
            .unwrap();
        assert_eq!(
            (u.name.as_str(), u.group.as_str()),
            ("Amsterdam", "Provider A")
        );
        assert!(u.disable_dco);
        assert_eq!(u.extra_directives, "mssfix 1400\n");
        // Unsafe extra options are refused and nothing changes.
        let bad = ProfileEdit {
            name: Some("Changed".into()),
            extra_directives: Some("up /bin/sh".into()),
            ..Default::default()
        };
        assert!(store.update(&p.id, &bad).is_err());
        assert_eq!(store.get(&p.id).unwrap().name, "Amsterdam");

        store.remove(&p.id).unwrap();
        assert!(store.list().is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn rejects_unsafe_configs() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ProfileStore::open(dir.path().to_path_buf()).unwrap();
        assert!(
            store
                .import("x.ovpn", "client\nremote a\nup /bin/sh\n")
                .is_err()
        );
        assert!(store.list().is_empty());
    }

    #[test]
    fn unknown_ids_have_no_path() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::open(dir.path().to_path_buf()).unwrap();
        assert!(store.config_path("../../etc/passwd").is_none());
    }
}
