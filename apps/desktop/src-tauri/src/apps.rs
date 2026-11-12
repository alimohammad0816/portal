//! Installed desktop apps, for the split tunneling app picker. Reads the
//! `.desktop` files the menus use and resolves each to the executable that
//! will actually run.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct InstalledApp {
    pub name: String,
    pub path: String,
    /// Icon name or path from the desktop file.
    pub icon: Option<String>,
}

fn dirs() -> Vec<PathBuf> {
    let mut d: Vec<PathBuf> = vec![
        "/usr/share/applications".into(),
        "/usr/local/share/applications".into(),
        "/var/lib/flatpak/exports/share/applications".into(),
        "/var/lib/snapd/desktop/applications".into(),
    ];
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        d.push(home.join(".local/share/applications"));
        d.push(home.join(".local/share/flatpak/exports/share/applications"));
    }
    d
}

/// Parse the `[Desktop Entry]` group into key → value.
fn entry(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut in_entry = false;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            in_entry = l == "[Desktop Entry]";
            continue;
        }
        if in_entry && let Some((k, v)) = l.split_once('=') {
            out.entry(k.trim().to_string())
                .or_insert_with(|| v.trim().to_string());
        }
    }
    out
}

fn which(cmd: &str) -> Option<PathBuf> {
    if cmd.contains('/') {
        let p = PathBuf::from(cmd);
        return p.is_file().then_some(p);
    }
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .chain(["/usr/bin".into(), "/snap/bin".into()])
        .map(|d| d.join(cmd))
        .find(|p| p.is_file())
}

/// The program a flatpak app runs, from its metadata (`command=`).
fn flatpak_command(app_id: &str) -> Option<String> {
    let roots = ["/var/lib/flatpak/app".to_string()].into_iter().chain(
        std::env::var("HOME")
            .ok()
            .map(|h| format!("{h}/.local/share/flatpak/app")),
    );
    for root in roots {
        let meta = Path::new(&root)
            .join(app_id)
            .join("current/active/metadata");
        if let Ok(text) = std::fs::read_to_string(meta) {
            for line in text.lines() {
                if let Some(c) = line.strip_prefix("command=") {
                    let c = c.trim();
                    return Some(if c.starts_with('/') {
                        c.to_string()
                    } else {
                        format!("/app/bin/{c}")
                    });
                }
            }
        }
    }
    None
}

/// Resolve an `Exec=` line to the executable path.
pub fn exec_path(exec: &str) -> Option<String> {
    let words: Vec<&str> = exec
        .split_whitespace()
        .map(|w| w.trim_matches('"'))
        .filter(|w| !w.starts_with('%'))
        .collect();
    let mut i = 0;
    if words.first() == Some(&"env") {
        i = 1;
        while words
            .get(i)
            .is_some_and(|w| w.contains('=') || w.starts_with('-'))
        {
            i += 1;
        }
    }
    let cmd = *words.get(i)?;
    if cmd.ends_with("flatpak") && words.get(i + 1) == Some(&"run") {
        let id = words[i + 2..].iter().find(|w| !w.starts_with('-'))?;
        return flatpak_command(id);
    }
    which(cmd).map(|p| p.to_string_lossy().into_owned())
}

pub fn installed() -> Vec<InstalledApp> {
    let mut by_path: BTreeMap<String, InstalledApp> = BTreeMap::new();
    for dir in dirs() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for f in rd.flatten() {
            let p = f.path();
            if p.extension().and_then(|e| e.to_str()) != Some("desktop") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&p) else {
                continue;
            };
            let e = entry(&text);
            let shown = e.get("Type").map(String::as_str) == Some("Application")
                && e.get("NoDisplay").map(String::as_str) != Some("true")
                && e.get("Hidden").map(String::as_str) != Some("true");
            if !shown {
                continue;
            }
            let (Some(name), Some(exec)) = (e.get("Name"), e.get("Exec")) else {
                continue;
            };
            let Some(path) = exec_path(exec) else {
                continue;
            };
            by_path.entry(path.clone()).or_insert(InstalledApp {
                name: name.clone(),
                path,
                icon: e.get("Icon").cloned(),
            });
        }
    }
    let mut apps: Vec<InstalledApp> = by_path.into_values().collect();
    apps.sort_by_key(|a| a.name.to_lowercase());
    apps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_desktop_entries() {
        let e = entry(
            "[Desktop Entry]\nName=Telegram\nName[fa]=تلگرام\nExec=telegram-desktop -- %u\n[Desktop Action x]\nName=Other\n",
        );
        assert_eq!(e.get("Name").map(String::as_str), Some("Telegram"));
        assert_eq!(
            e.get("Exec").map(String::as_str),
            Some("telegram-desktop -- %u")
        );
    }

    #[test]
    fn resolves_exec_lines() {
        assert_eq!(exec_path("sh -c 'x'").as_deref(), Some("/usr/bin/sh"));
        assert_eq!(exec_path("env FOO=1 sh %U").as_deref(), Some("/usr/bin/sh"));
        assert_eq!(exec_path("/no/such/binary %f"), None);
    }
}
