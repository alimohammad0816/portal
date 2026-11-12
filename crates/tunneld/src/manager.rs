//! Connection state machine. Owns the profile store, the settings and the
//! current session; turns backend events into a [`Status`]; keeps the
//! firewall, DNS and split tunneling in line with the connection;
//! publishes changes.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use tokio::sync::{Mutex, mpsc};
use tracing::{info, warn};
use tunnel_core::names::TUNNEL_IFACE;
use tunnel_core::split::{DomainList, Rule};
use tunnel_core::{ConnState, DnsMode, FirewallMode, Profile, Settings, SplitMode, Status};

use crate::backend::{Backend, Credentials, Event, EventTx, SessionHandle};
use crate::dns::LinkDns;
use crate::firewall::{self, Firewall, Plan};
use crate::gateway::Gateway;
use crate::profiles::{ProfileStore, write_private};
use crate::split::{Link, Split, geoip};

const LOG_LINES: usize = 500;

/// Something clients should hear about.
#[derive(Debug, Clone)]
pub enum Notice {
    Status(Status),
    Log(String),
    Settings(Settings),
}

/// How the manager touches the system.
pub struct Platform {
    /// Load nftables rules, configure systemd-resolved and routing. Off in
    /// session (development) mode, where we aren't root.
    pub system: bool,
    pub settings_path: PathBuf,
    /// Where country IP lists are cached.
    pub geoip_dir: PathBuf,
}

pub struct Manager {
    store: ProfileStore,
    backend: Arc<dyn Backend>,
    status: Status,
    session: Option<SessionHandle>,
    seq: u64,
    user_stopped: bool,
    last_bytes: Option<(Instant, u64, u64)>,
    log: VecDeque<String>,
    events: EventTx,
    notices: mpsc::UnboundedSender<Notice>,

    settings: Settings,
    platform: Platform,
    firewall: Firewall,
    daemon_cgroup: Option<String>,
    resolver_cgroup: Option<String>,
    /// The tunnel dropped without the user asking; with the firewall on
    /// `Auto`, traffic stays blocked until they reconnect or disconnect.
    blocked_after_drop: bool,
    /// DNS servers and search domains the server pushed this session.
    pushed: (Vec<IpAddr>, Vec<String>),
    /// resolved now sends lookups through the tunnel.
    dns_ready: bool,

    split: Split,
    /// Whether this session's OpenVPN runs without its own routes (include
    /// mode). Fixed for the session.
    session_include: bool,
    /// Country ranges currently loaded, and for which countries.
    geo: (Vec<String>, Vec<String>),
    /// The physical network's resolvers, learned when DNS was applied.
    direct_dns: Vec<IpAddr>,
    gateway: Option<Gateway>,
}

pub type Shared = Arc<Mutex<Manager>>;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load_settings(path: &PathBuf) -> Settings {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            warn!("ignoring unreadable {}: {e}", path.display());
            Settings::default()
        }),
        Err(_) => Settings::default(),
    }
}

fn wants_include(s: &Settings) -> bool {
    s.split.enabled && s.split.mode == SplitMode::Include
}

impl Manager {
    /// Build the manager, apply the firewall for the saved settings, and
    /// start the task that feeds it backend events.
    pub fn spawn(
        store: ProfileStore,
        backend: Arc<dyn Backend>,
        notices: mpsc::UnboundedSender<Notice>,
        platform: Platform,
    ) -> Shared {
        let (events, mut rx) = mpsc::unbounded_channel();
        let settings = load_settings(&platform.settings_path);
        let (daemon_cgroup, resolver_cgroup) = if platform.system {
            (firewall::own_cgroup(), firewall::resolver_cgroup())
        } else {
            (None, None)
        };
        let mut mgr = Manager {
            store,
            backend,
            status: Status::default(),
            session: None,
            seq: 0,
            user_stopped: false,
            last_bytes: None,
            log: VecDeque::with_capacity(LOG_LINES),
            events,
            notices,
            settings,
            firewall: Firewall::new(platform.system),
            split: Split::new(platform.system, daemon_cgroup.clone()),
            platform,
            daemon_cgroup,
            resolver_cgroup,
            blocked_after_drop: false,
            pushed: (Vec::new(), Vec::new()),
            dns_ready: false,
            session_include: false,
            geo: (Vec::new(), Vec::new()),
            direct_dns: Vec::new(),
            gateway: None,
        };
        mgr.sync_firewall();
        mgr.load_geo();
        let mgr = Arc::new(Mutex::new(mgr));
        let weak = Arc::downgrade(&mgr);
        tokio::spawn(async move {
            while let Some((seq, event)) = rx.recv().await {
                let Some(mgr) = weak.upgrade() else { break };
                mgr.lock().await.on_event(seq, event);
            }
        });
        mgr
    }

    pub fn profiles(&self) -> &[Profile] {
        self.store.list()
    }

    pub fn status(&self) -> &Status {
        &self.status
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn log(&self) -> Vec<String> {
        self.log.iter().cloned().collect()
    }

    pub fn import(&mut self, file_name: &str, content: &str) -> Result<Profile> {
        let p = self.store.import(file_name, content)?;
        info!("imported profile {} ({})", p.name, p.id);
        Ok(p)
    }

    pub fn update(&mut self, id: &str, name: &str, group: &str, country: &str) -> Result<Profile> {
        self.store.update(id, name, group, country)
    }

    pub fn remove(&mut self, id: &str) -> Result<()> {
        if self.status.profile_id.as_deref() == Some(id) && self.session.is_some() {
            bail!("Disconnect before removing the profile in use.");
        }
        self.store.remove(id)
    }

    pub fn set_settings(&mut self, new: Settings) -> Result<Settings> {
        new.validate().map_err(|e| anyhow!(e))?;
        let old = std::mem::replace(&mut self.settings, new.clone());
        if let Err(e) = write_private(
            &self.platform.settings_path,
            &serde_json::to_vec_pretty(&new)?,
        )
        .context("saving settings")
        {
            self.settings = old;
            return Err(e);
        }
        info!("settings changed: {new:?}");
        if self.settings.firewall != FirewallMode::Auto {
            self.blocked_after_drop = false;
        }
        if old.split.countries != new.split.countries {
            self.load_geo();
        }
        if self.status.state == ConnState::Connected {
            self.apply_split_change(&old);
            if new.dns != old.dns || new.split.enabled != old.split.enabled {
                self.apply_dns();
            }
        }
        self.sync_firewall();
        self.publish();
        let _ = self.notices.send(Notice::Settings(self.settings.clone()));
        Ok(self.settings.clone())
    }

    /// Bring split tunneling on the running connection in line with the
    /// settings, as far as possible without reconnecting.
    fn apply_split_change(&mut self, old: &Settings) {
        let s = self.settings.split.clone();
        if wants_include(&self.settings) != self.session_include {
            // OpenVPN's routes were set up for the other mode.
            self.status.split_needs_reconnect = true;
            return;
        }
        self.status.split_needs_reconnect = false;
        let result = match (old.split.enabled, s.enabled, self.split.mode()) {
            (_, false, Some(_)) => {
                self.split.stop();
                Ok(())
            }
            (_, true, Some(mode)) if mode == s.mode => self.split.update(&s, &self.geo.1),
            (_, true, _) => self.start_split(),
            _ => Ok(()),
        };
        if let Err(e) = result {
            self.split_failed(e);
        }
        self.refresh_split_status();
    }

    fn start_split(&mut self) -> Result<()> {
        let link = Link {
            server_ip: self.status.server_ip.clone(),
            vpn_dns: self.vpn_dns(),
            direct_dns: self.direct_dns.clone(),
        };
        self.split.start(&self.settings.split, &self.geo.1, &link)
    }

    /// Run the proxy gateway while connected, if it's on.
    fn sync_gateway(&mut self) {
        let want = self.settings.proxy_gateway.enabled && self.status.state == ConnState::Connected;
        let port = self.settings.proxy_gateway.port;
        let running_port = self.gateway.as_ref().map(|g| g.addr.port());
        if want && running_port == Some(port) {
            return;
        }
        if let Some(g) = self.gateway.take() {
            g.stop();
        }
        self.status.proxy_address = None;
        if !want {
            return;
        }
        let Some(ip) = crate::gateway::lan_address(TUNNEL_IFACE) else {
            self.push_log("Proxy gateway: no LAN address to listen on.".into());
            return;
        };
        let mark = if self.split.mode() == Some(SplitMode::Include) {
            crate::split::net::MARK_TUNNEL
        } else {
            0
        };
        match Gateway::start(ip, port, mark) {
            Ok(g) => {
                self.status.proxy_address = Some(g.addr.to_string());
                self.gateway = Some(g);
            }
            Err(e) => {
                warn!("proxy gateway: {e:#}");
                self.push_log(format!("Proxy gateway couldn't start: {e:#}"));
            }
        }
    }

    fn split_failed(&mut self, e: anyhow::Error) {
        warn!("split tunneling: {e:#}");
        self.push_log(format!("Split tunneling couldn't start: {e:#}"));
        self.status.error = Some(format!("Split tunneling: {e:#}"));
    }

    fn refresh_split_status(&mut self) {
        self.status.split_active = self.split.mode().is_some();
        self.status.split_processes = self.split.apps_moved();
    }

    /// Load country lists in the background.
    fn load_geo(&mut self) {
        let countries = self.settings.split.countries.clone();
        if countries == self.geo.0 {
            return;
        }
        if countries.is_empty() {
            self.geo = (Vec::new(), Vec::new());
            return;
        }
        let (dir, events, seq) = (
            self.platform.geoip_dir.clone(),
            self.events.clone(),
            self.seq,
        );
        tokio::spawn(async move {
            let mut networks = Vec::new();
            for c in &countries {
                match geoip::networks(&dir, c).await {
                    Ok(n) => networks.extend(n),
                    Err(e) => warn!("country list {c}: {e:#}"),
                }
            }
            let _ = events.send((
                seq,
                Event::GeoLoaded {
                    countries,
                    networks,
                },
            ));
        });
    }

    /// Move the calling process into the split cgroup (`tunnel bypass`).
    pub fn bypass(&mut self, pid: u32) -> Result<()> {
        self.split.bypass(pid)?;
        self.refresh_split_status();
        self.publish();
        Ok(())
    }

    /// First half of connecting: validate, take the old session out so the
    /// caller can stop it without holding the lock, and show "connecting".
    /// The firewall keeps blocking across a location switch.
    pub fn begin_connect(
        &mut self,
        id: &str,
        creds: &Credentials,
    ) -> Result<Option<SessionHandle>> {
        if self.store.get(id).is_none() {
            bail!("No profile with id {id}.");
        }
        if self.store.needs_credentials(id) && creds.username.is_empty() {
            bail!("This profile needs a username and password.");
        }
        let old = self.session.take();
        self.split.stop();
        self.seq += 1;
        self.user_stopped = false;
        self.last_bytes = None;
        self.blocked_after_drop = false;
        self.pushed = (Vec::new(), Vec::new());
        self.dns_ready = false;
        self.session_include = wants_include(&self.settings);
        self.status = Status {
            state: ConnState::Connecting,
            profile_id: Some(id.to_string()),
            ..Status::default()
        };
        self.sync_firewall();
        self.publish();
        Ok(old)
    }

    /// Second half: start the new session (unless another connect or a
    /// disconnect happened while the old one was stopping).
    pub fn finish_connect(&mut self, id: &str, creds: Credentials) -> Result<()> {
        if self.status.profile_id.as_deref() != Some(id)
            || self.status.state != ConnState::Connecting
        {
            return Ok(());
        }
        let config = self
            .store
            .config_path(id)
            .ok_or_else(|| anyhow!("profile disappeared"))?;
        // Include mode: OpenVPN must not route anything itself; split rules
        // decide what enters the tunnel.
        let extra = if self.session_include {
            vec!["--route-noexec".to_string()]
        } else {
            Vec::new()
        };
        match self
            .backend
            .start(self.seq, config, creds, extra, self.events.clone())
        {
            Ok(handle) => {
                self.session = Some(handle);
                Ok(())
            }
            Err(e) => {
                self.status.state = ConnState::Disconnected;
                self.status.error = Some(format!("{e:#}"));
                self.sync_firewall();
                self.publish();
                Err(e)
            }
        }
    }

    /// Stop the session, if any, and lift a kill-switch block.
    pub fn begin_disconnect(&mut self) -> Option<SessionHandle> {
        if self.blocked_after_drop {
            self.blocked_after_drop = false;
            self.status.error = None;
            self.sync_firewall();
            self.publish();
        }
        let handle = self.session.take()?;
        self.user_stopped = true;
        self.split.stop();
        self.refresh_split_status();
        self.status.state = ConnState::Disconnecting;
        self.publish();
        Some(handle)
    }

    /// Remove our rules unless they're meant to outlive us.
    pub fn shutdown(&mut self) {
        if let Some(g) = self.gateway.take() {
            g.stop();
        }
        self.split.stop();
        if self.settings.firewall != FirewallMode::Always {
            self.firewall.clear();
        }
    }

    fn plan(&self) -> Plan {
        let active = self.session.is_some() || self.status.state != ConnState::Disconnected;
        let block = match self.settings.firewall {
            FirewallMode::Off => false,
            FirewallMode::Always => true,
            FirewallMode::Auto => active || self.blocked_after_drop,
        };
        let connected = self.status.state == ConnState::Connected;
        let split = self.split.mode();
        Plan {
            block,
            iface: TUNNEL_IFACE.into(),
            connected,
            allow_lan: self.settings.allow_lan,
            block_ipv6: self.settings.block_ipv6,
            // Only once resolved uses the tunnel, and never in include
            // mode, where most lookups are meant to stay outside.
            dns_guard: self.settings.dns_leak_protection
                && self.dns_ready
                && split != Some(SplitMode::Include),
            daemon_cgroup: self.daemon_cgroup.clone(),
            resolver_cgroup: self.resolver_cgroup.clone(),
            split,
        }
    }

    fn sync_firewall(&mut self) {
        self.sync_gateway();
        let plan = self.plan();
        if let Err(e) = self.firewall.apply(&plan) {
            warn!("{e:#}");
            self.status.error = Some(format!("Firewall: {e:#}"));
        }
        self.status.firewall_active = self.firewall.is_active();
        self.status.internet_blocked = plan.block && !plan.connected;
    }

    fn vpn_dns(&self) -> Vec<IpAddr> {
        match &self.settings.dns {
            DnsMode::Custom(list) => list.iter().filter_map(|s| s.parse().ok()).collect(),
            DnsMode::Vpn => self.pushed.0.clone(),
        }
    }

    /// Point DNS at the tunnel (or at the split DNS proxy). Runs in the
    /// background and reports back through the event channel.
    fn apply_dns(&mut self) {
        let servers = self.vpn_dns();
        let search = self.pushed.1.clone();
        let (seq, events, system) = (self.seq, self.events.clone(), self.platform.system);
        let proxy = self.split.dns_listen();
        let split_mode = self.split.mode();
        let split_domains: Vec<String> = DomainList::new(
            &self
                .settings
                .split
                .hosts
                .iter()
                .filter_map(|h| Rule::parse(h).ok())
                .collect::<Vec<_>>(),
        )
        .suffixes()
        .to_vec();
        if servers.is_empty() && proxy.is_none() {
            self.push_log("The server didn't push DNS servers; using the system's DNS.".into());
            self.dns_ready = false;
            self.status.dns_servers.clear();
            return;
        }
        tokio::spawn(async move {
            let shown: Vec<String> = servers.iter().map(ToString::to_string).collect();
            let mut direct = Vec::new();
            let result = if system {
                // Learn the physical resolvers before the tunnel takes over.
                direct = crate::dns::system_servers(TUNNEL_IFACE).await;
                let cfg = match (proxy, split_mode) {
                    (Some(p), Some(SplitMode::Include)) => LinkDns {
                        servers: vec![p],
                        routing: split_domains,
                        search: Vec::new(),
                        default_route: false,
                    },
                    (Some(p), _) => LinkDns {
                        servers: vec![p],
                        routing: vec![".".into()],
                        search,
                        default_route: true,
                    },
                    (None, _) => LinkDns {
                        servers,
                        routing: vec![".".into()],
                        search,
                        default_route: true,
                    },
                };
                crate::dns::configure(TUNNEL_IFACE, &cfg)
                    .await
                    .map_err(|e| format!("{e:#}"))
            } else {
                Ok(())
            };
            let _ = events.send((
                seq,
                Event::DnsApplied {
                    servers: shown,
                    direct,
                    result,
                },
            ));
        });
    }

    fn on_event(&mut self, seq: u64, event: Event) {
        if let Event::Log(line) = &event {
            self.push_log(line.clone());
        }
        // Country lists don't belong to a session.
        if let Event::GeoLoaded {
            countries,
            networks,
        } = event
        {
            if countries == self.settings.split.countries {
                self.geo = (countries, networks);
                if let Err(e) = self.split.update(&self.settings.split, &self.geo.1) {
                    self.split_failed(e);
                }
                self.publish();
            }
            return;
        }
        if seq != self.seq {
            return;
        }
        match event {
            Event::State {
                name,
                tunnel_ip,
                server_ip,
            } => {
                match name.as_str() {
                    "CONNECTED" => {
                        self.status.state = ConnState::Connected;
                        self.status.connected_since = Some(now());
                        self.status.tunnel_ip = tunnel_ip;
                        self.status.server_ip = server_ip;
                        self.status.error = None;
                        if let Some(id) = self.status.profile_id.clone() {
                            self.store.mark_connected(&id);
                        }
                        if self.settings.split.enabled
                            && let Err(e) = self.start_split()
                        {
                            self.split_failed(e);
                        }
                        self.refresh_split_status();
                        self.apply_dns();
                    }
                    "EXITING" => self.status.state = ConnState::Disconnecting,
                    _ if self.status.state != ConnState::Disconnecting => {
                        // Includes RECONNECTING: the old DNS route is gone,
                        // and routes are rebuilt when the tunnel is back.
                        self.status.state = ConnState::Connecting;
                        self.status.connected_since = None;
                        self.dns_ready = false;
                        self.split.stop();
                        self.refresh_split_status();
                    }
                    _ => {}
                }
                self.status.detail = Some(name);
                self.sync_firewall();
                self.publish();
            }
            Event::Bytes { rx, tx } => {
                let t = Instant::now();
                if let Some((t0, rx0, tx0)) = self.last_bytes {
                    let secs = t.duration_since(t0).as_secs_f64().max(0.25);
                    self.status.rate_in = (rx.saturating_sub(rx0) as f64 / secs) as u64;
                    self.status.rate_out = (tx.saturating_sub(tx0) as f64 / secs) as u64;
                }
                self.last_bytes = Some((t, rx, tx));
                self.status.bytes_in = rx;
                self.status.bytes_out = tx;
                self.status.split_processes = self.split.apps_moved();
                self.publish();
            }
            Event::Log(line) => {
                if let Some(pushed) = crate::dns::parse_push(&line) {
                    self.pushed = pushed;
                    // The log and the state come through different pipes;
                    // if the push shows up after CONNECTED, apply it now.
                    if self.status.state == ConnState::Connected
                        && !self.dns_ready
                        && self.settings.dns == DnsMode::Vpn
                    {
                        let (vpn, direct) = (self.vpn_dns(), self.direct_dns.clone());
                        self.split.set_dns(&vpn, &direct);
                        self.apply_dns();
                    }
                }
            }
            Event::DnsApplied {
                servers,
                direct,
                result,
            } => {
                match result {
                    Ok(()) => {
                        self.dns_ready = self.status.state == ConnState::Connected;
                        self.status.dns_servers = servers;
                        if !direct.is_empty() {
                            self.direct_dns = direct;
                        }
                        let vpn = self.vpn_dns();
                        self.split.set_dns(&vpn, &self.direct_dns);
                    }
                    Err(e) => {
                        warn!("DNS: {e}");
                        self.push_log(format!("Couldn't set the tunnel's DNS: {e}"));
                        self.dns_ready = false;
                    }
                }
                self.sync_firewall();
                self.publish();
            }
            Event::GeoLoaded { .. } => {}
            Event::Fatal(msg) => {
                self.status.error = Some(msg);
                self.publish();
            }
            Event::Exited => {
                self.session = None;
                self.split.stop();
                let dropped = !self.user_stopped;
                let error = self.status.error.take().or_else(|| {
                    dropped.then(|| {
                        "The connection ended unexpectedly. See the log for details.".into()
                    })
                });
                self.blocked_after_drop = dropped && self.settings.firewall == FirewallMode::Auto;
                self.dns_ready = false;
                self.status = Status {
                    state: ConnState::Disconnected,
                    profile_id: self.status.profile_id.take(),
                    error,
                    ..Status::default()
                };
                self.sync_firewall();
                self.publish();
            }
        }
    }

    fn push_log(&mut self, line: String) {
        if self.log.len() == LOG_LINES {
            self.log.pop_front();
        }
        self.log.push_back(line.clone());
        let _ = self.notices.send(Notice::Log(line));
    }

    fn publish(&self) {
        let _ = self.notices.send(Notice::Status(self.status.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Mock;
    use tunnel_core::SplitSettings;

    const CFG: &str = "client\nremote de-fra-02.example.net 1194\n";

    struct Fixture {
        mgr: Shared,
        rx: mpsc::UnboundedReceiver<Notice>,
        id: String,
        _dir: tempfile::TempDir,
    }

    async fn setup_with(cfg: &str, settings: Option<Settings>) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ProfileStore::open(dir.path().join("profiles")).unwrap();
        let id = store.import("de.ovpn", cfg).unwrap().id;
        let settings_path = dir.path().join("settings.json");
        if let Some(s) = settings {
            std::fs::write(&settings_path, serde_json::to_vec(&s).unwrap()).unwrap();
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let platform = Platform {
            system: false,
            settings_path,
            geoip_dir: dir.path().join("geoip"),
        };
        Fixture {
            mgr: Manager::spawn(store, Arc::new(Mock), tx, platform),
            rx,
            id,
            _dir: dir,
        }
    }

    async fn setup() -> Fixture {
        setup_with(CFG, None).await
    }

    async fn wait_for(
        rx: &mut mpsc::UnboundedReceiver<Notice>,
        f: impl Fn(&Status) -> bool,
    ) -> Status {
        loop {
            let n = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap();
            if let Notice::Status(s) = n
                && f(&s)
            {
                return s;
            }
        }
    }

    async fn connect(f: &mut Fixture) -> Status {
        let old = f
            .mgr
            .lock()
            .await
            .begin_connect(&f.id, &Credentials::default())
            .unwrap();
        assert!(old.is_none());
        f.mgr
            .lock()
            .await
            .finish_connect(&f.id, Credentials::default())
            .unwrap();
        wait_for(&mut f.rx, |s| {
            s.state == ConnState::Connected && !s.dns_servers.is_empty()
        })
        .await
    }

    #[tokio::test]
    async fn connects_and_disconnects() {
        let mut f = setup().await;
        let s = connect(&mut f).await;
        assert_eq!(s.tunnel_ip.as_deref(), Some("10.8.0.6"));
        assert_eq!(s.dns_servers, vec!["10.8.0.1"]);
        assert!(s.firewall_active, "Auto firewall is on while connected");
        assert!(!s.internet_blocked);
        assert!(!s.split_active);
        assert!(f.mgr.lock().await.profiles()[0].last_connected_at.is_some());

        let h = f.mgr.lock().await.begin_disconnect().unwrap();
        h.stop().await;
        let s = wait_for(&mut f.rx, |s| s.state == ConnState::Disconnected).await;
        assert_eq!(s.error, None);
        assert!(
            !s.firewall_active,
            "Auto firewall lifts after a normal disconnect"
        );
    }

    #[tokio::test]
    async fn kill_switch_holds_after_a_drop() {
        let mut f = setup().await;
        connect(&mut f).await;
        let mut m = f.mgr.lock().await;
        let seq = m.seq;
        m.session = None; // the backend went away on its own
        m.on_event(seq, Event::Exited);
        assert!(m.status().internet_blocked);
        assert!(m.status().error.is_some());
        assert!(m.begin_disconnect().is_none());
        assert!(!m.status().internet_blocked, "disconnect lifts the block");
    }

    #[tokio::test]
    async fn always_mode_blocks_while_disconnected() {
        let s = Settings {
            firewall: FirewallMode::Always,
            ..Settings::default()
        };
        let f = setup_with(CFG, Some(s)).await;
        let m = f.mgr.lock().await;
        assert!(m.status().internet_blocked);
        assert!(m.plan().block);
    }

    #[tokio::test]
    async fn custom_dns_and_settings_persist() {
        let mut f = setup().await;
        let new = Settings {
            dns: DnsMode::Custom(vec!["1.1.1.1".into()]),
            ..Settings::default()
        };
        f.mgr.lock().await.set_settings(new.clone()).unwrap();
        let s = connect(&mut f).await;
        assert_eq!(s.dns_servers, vec!["1.1.1.1"]);
        let path = f.mgr.lock().await.platform.settings_path.clone();
        assert_eq!(load_settings(&path), new);
        let bad = Settings {
            dns: DnsMode::Custom(vec!["nope".into()]),
            ..Settings::default()
        };
        assert!(f.mgr.lock().await.set_settings(bad).is_err());
        assert_eq!(
            f.mgr.lock().await.settings(),
            &new,
            "a rejected change leaves settings alone"
        );
    }

    #[tokio::test]
    async fn dns_guard_waits_for_tunnel_dns() {
        let mut f = setup().await;
        f.mgr
            .lock()
            .await
            .begin_connect(&f.id, &Credentials::default())
            .unwrap();
        assert!(!f.mgr.lock().await.plan().dns_guard);
        f.mgr
            .lock()
            .await
            .finish_connect(&f.id, Credentials::default())
            .unwrap();
        wait_for(&mut f.rx, |s| !s.dns_servers.is_empty()).await;
        assert!(f.mgr.lock().await.plan().dns_guard);
    }

    fn split(mode: SplitMode) -> Settings {
        Settings {
            split: SplitSettings {
                enabled: true,
                mode,
                hosts: vec!["*.ir".into()],
                ..SplitSettings::default()
            },
            ..Settings::default()
        }
    }

    #[tokio::test]
    async fn split_exclude_starts_with_the_tunnel_and_changes_live() {
        let mut f = setup_with(CFG, Some(split(SplitMode::Exclude))).await;
        let s = connect(&mut f).await;
        assert!(s.split_active);
        assert_eq!(f.mgr.lock().await.plan().split, Some(SplitMode::Exclude));

        // Turning it off and on again needs no reconnect in exclude mode.
        let off = Settings::default();
        let s = {
            f.mgr.lock().await.set_settings(off).unwrap();
            f.mgr.lock().await.status().clone()
        };
        assert!(!s.split_active && !s.split_needs_reconnect);
        f.mgr
            .lock()
            .await
            .set_settings(split(SplitMode::Exclude))
            .unwrap();
        assert!(f.mgr.lock().await.status().split_active);

        // Include mode needs OpenVPN without routes: reconnect.
        f.mgr
            .lock()
            .await
            .set_settings(split(SplitMode::Include))
            .unwrap();
        assert!(f.mgr.lock().await.status().split_needs_reconnect);
    }

    #[tokio::test]
    async fn split_include_disables_dns_guard() {
        let mut f = setup_with(CFG, Some(split(SplitMode::Include))).await;
        let s = connect(&mut f).await;
        assert!(s.split_active);
        let m = f.mgr.lock().await;
        assert!(m.session_include);
        assert!(!m.plan().dns_guard);
    }

    #[tokio::test]
    async fn requires_credentials_for_user_pass_profiles() {
        let f = setup_with("client\nremote a.example\nauth-user-pass\n", None).await;
        let Err(err) = f
            .mgr
            .lock()
            .await
            .begin_connect(&f.id, &Credentials::default())
        else {
            panic!("connect without credentials should fail");
        };
        assert!(err.to_string().contains("username"));
    }

    #[tokio::test]
    async fn ignores_events_from_replaced_sessions() {
        let f = setup().await;
        let mut m = f.mgr.lock().await;
        m.begin_connect(&f.id, &Credentials::default()).unwrap();
        let stale = m.seq - 1;
        m.on_event(stale, Event::Exited);
        assert_eq!(m.status().state, ConnState::Connecting);
    }
}
