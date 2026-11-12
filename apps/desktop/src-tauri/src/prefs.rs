//! Per-user app preferences: starting on login, connecting automatically,
//! trusted networks. Stored as JSON in the app's config directory; the
//! login item is a standard XDG autostart entry.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// Start Tunnel (in the tray) when you log in.
    pub launch_at_login: bool,
    /// Connect when the app starts.
    pub connect_on_launch: bool,
    /// Connect whenever you join a network that isn't trusted.
    pub auto_connect_untrusted: bool,
    /// NetworkManager connection names (Wi-Fi network names) that don't
    /// need the VPN.
    pub trusted_networks: Vec<String>,
    /// Profile for automatic connections; `None` means the last one used.
    pub auto_profile: Option<String>,
    /// Ask a geolocation service where the VPN exits, for the map.
    pub show_exit_location: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            launch_at_login: false,
            connect_on_launch: false,
            auto_connect_untrusted: false,
            trusted_networks: Vec::new(),
            auto_profile: None,
            show_exit_location: true,
        }
    }
}

fn config_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

fn prefs_path() -> PathBuf {
    config_dir().join("tunnel").join("prefs.json")
}

fn autostart_path() -> PathBuf {
    config_dir()
        .join("autostart")
        .join("org.tunnelvpn.Tunnel.desktop")
}

pub fn load() -> Prefs {
    std::fs::read(prefs_path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

pub fn save(p: &Prefs) -> Result<(), String> {
    let path = prefs_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(p).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    set_autostart(p.launch_at_login)
}

fn set_autostart(on: bool) -> Result<(), String> {
    let path = autostart_path();
    if !on {
        let _ = std::fs::remove_file(&path);
        return Ok(());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let entry = format!(
        "[Desktop Entry]\nType=Application\nName=Tunnel\nComment=Start the Tunnel VPN client in the tray\nExec={} --hidden\nIcon=tunnel-desktop\nTerminal=false\nX-GNOME-Autostart-enabled=true\nX-GNOME-Autostart-Delay=2\n",
        exe.display()
    );
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(&path, entry).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_files_get_defaults() {
        let p: Prefs = serde_json::from_str(r#"{"launch_at_login":true}"#).unwrap();
        assert!(p.launch_at_login);
        assert!(p.show_exit_location);
        assert!(p.trusted_networks.is_empty());
    }
}
