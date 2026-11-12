//! Per-app split tunneling. Processes of listed apps (and anything started
//! with `portal bypass`) are moved into one cgroup, `/sys/fs/cgroup/portal-split`,
//! which the nft table matches. Children inherit the cgroup, so a whole app
//! follows its main process.
//!
//! Apps are found by scanning `/proc` once a second, so the first
//! connection or two of a freshly started app may still use the other side.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use portal_core::SplitApp;
use tokio::task::JoinHandle;
use tracing::{debug, info};

pub const CGROUP: &str = "portal-split";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// How a listed app is recognized.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Matcher {
    path: PathBuf,
    /// Executable file names (as listed and after following symlinks);
    /// they also match snap and flatpak copies of the same program.
    names: Vec<String>,
}

/// Launchers and interpreters: matching these by name would split every
/// program that uses them.
const GENERIC: &[&str] = &[
    "snap", "flatpak", "bwrap", "env", "sh", "bash", "dash", "zsh", "python", "python3", "perl",
    "ruby", "node", "java", "mono", "dotnet", "electron", "wine", "wine64",
];

fn matcher(app: &SplitApp) -> Option<Matcher> {
    let listed = PathBuf::from(&app.path);
    let path = std::fs::canonicalize(&listed).unwrap_or_else(|_| listed.clone());
    let mut names: Vec<String> = [&listed, &path]
        .iter()
        .filter_map(|p| p.file_name()?.to_str().map(str::to_string))
        .filter(|n| !GENERIC.contains(&n.as_str()) && !n.starts_with("python"))
        .collect();
    names.dedup();
    Some(Matcher { path, names })
}

#[derive(Default)]
struct State {
    matchers: Vec<Matcher>,
    /// pid → cgroup it came from, for every process we moved.
    moved: HashMap<u32, String>,
    /// pids moved by `portal bypass`, kept regardless of the app list.
    manual: HashSet<u32>,
}

pub struct Tracker {
    root: PathBuf,
    state: Arc<Mutex<State>>,
    task: Option<JoinHandle<()>>,
}

fn proc_cgroup(pid: u32) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(|s| s.trim_matches('/').to_string())
}

fn exe(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

impl Tracker {
    /// Create the cgroup. Fails without root.
    pub fn new() -> Result<Tracker> {
        Self::with_root(Path::new(CGROUP_ROOT))
    }

    fn with_root(root: &Path) -> Result<Tracker> {
        let dir = root.join(CGROUP);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(Tracker {
            root: root.to_path_buf(),
            state: Arc::default(),
            task: None,
        })
    }

    fn move_to(&self, pid: u32, cgroup: &str) -> std::io::Result<()> {
        std::fs::write(self.root.join(cgroup).join("cgroup.procs"), pid.to_string())
    }

    /// Put `pid` in the split cgroup, remembering where it was.
    pub fn add(&self, pid: u32, manual: bool) -> Result<()> {
        let from = proc_cgroup(pid).context("no such process")?;
        if from == CGROUP {
            return Ok(());
        }
        self.move_to(pid, CGROUP)
            .with_context(|| format!("moving process {pid}"))?;
        let mut st = self.state.lock().unwrap();
        st.moved.insert(pid, from);
        if manual {
            st.manual.insert(pid);
        }
        Ok(())
    }

    fn release(&self, pid: u32, to: &str) {
        // The original cgroup may be gone (its unit stopped); then leave it.
        if self.root.join(to).is_dir() {
            let _ = self.move_to(pid, to);
        }
    }

    /// Start (or restart) watching for `apps`. Processes of apps that were
    /// removed from the list go back where they came from.
    pub fn set_apps(&mut self, apps: &[SplitApp]) {
        let matchers: Vec<Matcher> = apps.iter().filter_map(matcher).collect();
        let to_release: Vec<(u32, String)> = {
            let mut st = self.state.lock().unwrap();
            st.matchers = matchers;
            let keep: Vec<u32> = st
                .moved
                .keys()
                .copied()
                .filter(|pid| {
                    st.manual.contains(pid) || exe(*pid).is_some_and(|e| is_match(&st.matchers, &e))
                })
                .collect();
            let gone: Vec<(u32, String)> = st
                .moved
                .iter()
                .filter(|(p, _)| !keep.contains(p))
                .map(|(p, c)| (*p, c.clone()))
                .collect();
            for (p, _) in &gone {
                st.moved.remove(p);
            }
            gone
        };
        for (pid, cg) in to_release {
            self.release(pid, &cg);
        }
        if self.task.is_none() {
            let me = Tracker {
                root: self.root.clone(),
                state: self.state.clone(),
                task: None,
            };
            self.task = Some(tokio::spawn(async move {
                loop {
                    me.scan();
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }));
        }
    }

    fn scan(&self) {
        let matchers = self.state.lock().unwrap().matchers.clone();
        if matchers.is_empty() {
            return;
        }
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return;
        };
        for entry in dir.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            let Some(path) = exe(pid) else { continue };
            if !is_match(&matchers, &path) || proc_cgroup(pid).as_deref() == Some(CGROUP) {
                continue;
            }
            match self.add(pid, false) {
                Ok(()) => info!("split: {} ({pid})", path.display()),
                Err(e) => debug!("split: {pid}: {e:#}"),
            }
        }
        // Forget processes that have exited.
        self.state
            .lock()
            .unwrap()
            .moved
            .retain(|pid, _| Path::new(&format!("/proc/{pid}")).exists());
    }

    /// Stop watching and put every process back.
    pub fn stop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
        let moved: Vec<(u32, String)> = {
            let mut st = self.state.lock().unwrap();
            st.manual.clear();
            st.moved.drain().collect()
        };
        for (pid, cg) in moved {
            self.release(pid, &cg);
        }
    }

    pub fn count(&self) -> usize {
        self.state.lock().unwrap().moved.len()
    }
}

fn is_match(matchers: &[Matcher], exe: &Path) -> bool {
    let name = exe.file_name().and_then(|n| n.to_str()).unwrap_or("");
    // `/proc/pid/exe` shows " (deleted)" after an upgrade replaced the file.
    let name = name.trim_end_matches(" (deleted)");
    matchers
        .iter()
        .any(|m| m.path == exe || m.names.iter().any(|n| n == name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_by_path_or_name() {
        let m = vec![Matcher {
            path: "/usr/bin/telegram-desktop".into(),
            names: vec!["telegram-desktop".into()],
        }];
        assert!(is_match(&m, Path::new("/usr/bin/telegram-desktop")));
        assert!(is_match(
            &m,
            Path::new("/snap/telegram-desktop/6000/usr/bin/telegram-desktop")
        ));
        assert!(is_match(
            &m,
            Path::new("/usr/bin/telegram-desktop (deleted)")
        ));
        assert!(!is_match(&m, Path::new("/usr/bin/firefox")));
    }

    #[test]
    fn never_matches_interpreters_by_name() {
        let app = SplitApp {
            name: "Script".into(),
            path: "/usr/bin/python3".into(),
        };
        let m = vec![matcher(&app).unwrap()];
        assert!(m[0].names.is_empty());
        assert!(!is_match(&m, Path::new("/usr/local/bin/python3")));
    }

    #[test]
    fn moves_and_restores_processes() {
        // A fake cgroupfs: plain directories, so writes just land in files.
        let dir = tempfile::tempdir().unwrap();
        let t = Tracker::with_root(dir.path()).unwrap();
        let me = std::process::id();
        let from = proc_cgroup(me).unwrap();
        std::fs::create_dir_all(dir.path().join(&from)).unwrap();
        t.add(me, true).unwrap();
        let procs = std::fs::read_to_string(dir.path().join(CGROUP).join("cgroup.procs")).unwrap();
        assert_eq!(procs, me.to_string());
        assert_eq!(t.count(), 1);
        let mut t = t;
        t.stop();
        let back = std::fs::read_to_string(dir.path().join(&from).join("cgroup.procs")).unwrap();
        assert_eq!(back, me.to_string());
        assert_eq!(t.count(), 0);
    }
}
