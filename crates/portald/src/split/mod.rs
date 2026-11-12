//! Split tunneling: chosen apps, domains, networks and countries go around
//! the tunnel (exclude mode) or are the only things that use it (include
//! mode). See `net` for the kernel side, `dnsproxy` for domains and `apps`
//! for per-app rules. Rule changes apply to the running connection; only
//! switching to or from include mode needs a reconnect, because OpenVPN
//! must start without installing its routes. `flows` deals with
//! connections that were already open when the rules changed.

pub mod apps;
pub mod dnsmsg;
pub mod dnsproxy;
pub mod flows;
pub mod geoip;
pub mod net;

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

use anyhow::Result;
use portal_core::names::TUNNEL_IFACE;
use portal_core::split::{DomainList, Rule};
use portal_core::{SplitMode, SplitSettings};
use tracing::{info, warn};

use self::dnsproxy::{Proxy, ProxyConfig, Sink};

/// Facts about the running connection that split tunneling needs.
#[derive(Debug, Clone, Default)]
pub struct Link {
    pub server_ip: Option<String>,
    /// Resolvers on the VPN side.
    pub vpn_dns: Vec<IpAddr>,
    /// The physical network's resolvers.
    pub direct_dns: Vec<IpAddr>,
}

pub struct Split {
    /// Touch the kernel (root). Off in session/mock mode, where only the
    /// bookkeeping runs.
    system: bool,
    daemon_cgroup: Option<String>,
    mode: Option<SplitMode>,
    proxy: Option<Proxy>,
    tracker: Option<apps::Tracker>,
    server_ip: Option<IpAddr>,
    /// Rules in force, to tell what a change added or removed.
    nets: HashSet<String>,
    domains: Vec<Rule>,
    apps: Vec<String>,
    pending: Pending,
}

/// Changes since the last apply that open connections don't follow yet.
/// They keep working on their old side, so they're only closed on request.
#[derive(Debug, Default)]
struct Pending {
    /// Removed networks and the addresses of removed domains.
    targets: flows::Targets,
    /// Apps were added or removed.
    apps: bool,
}

impl Pending {
    fn is_empty(&self) -> bool {
        self.targets.is_empty() && !self.apps
    }
}

fn domain_rules(s: &SplitSettings) -> Vec<Rule> {
    rules(s)
        .into_iter()
        .filter(|r| matches!(r, Rule::Domain(_)))
        .collect()
}

fn nets_of<'a>(items: impl IntoIterator<Item = &'a String>) -> Vec<flows::Net> {
    items
        .into_iter()
        .filter_map(|n| flows::Net::parse(n))
        .collect()
}

fn rules(s: &SplitSettings) -> Vec<Rule> {
    s.hosts.iter().filter_map(|h| Rule::parse(h).ok()).collect()
}

/// Static set contents: listed networks plus country ranges.
fn static_sets(s: &SplitSettings, countries: &[String]) -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let listed = rules(s)
        .iter()
        .filter_map(Rule::nft_element)
        .collect::<Vec<_>>();
    for e in listed.into_iter().chain(countries.iter().cloned()) {
        if e.contains(':') {
            v6.push(e)
        } else {
            v4.push(e)
        }
    }
    (v4, v6)
}

impl Split {
    pub fn new(system: bool, daemon_cgroup: Option<String>) -> Self {
        Split {
            system,
            daemon_cgroup,
            mode: None,
            proxy: None,
            tracker: None,
            server_ip: None,
            nets: HashSet::new(),
            domains: Vec::new(),
            apps: Vec::new(),
            pending: Pending::default(),
        }
    }

    /// Open connections still follow rules that have since changed.
    pub fn pending(&self) -> bool {
        self.mode.is_some() && !self.pending.is_empty()
    }

    pub fn mode(&self) -> Option<SplitMode> {
        self.mode
    }

    /// Address resolved should send the tunnel's lookups to while split
    /// tunneling runs.
    pub fn dns_listen(&self) -> Option<IpAddr> {
        self.proxy.as_ref().map(|p| p.addr.ip())
    }

    pub fn apps_moved(&self) -> usize {
        self.tracker.as_ref().map_or(0, apps::Tracker::count)
    }

    fn tracker(&mut self) -> Result<&mut apps::Tracker> {
        if self.tracker.is_none() {
            self.tracker = Some(apps::Tracker::new()?);
        }
        Ok(self.tracker.as_mut().expect("just set"))
    }

    /// Set everything up for a fresh connection.
    pub fn start(&mut self, s: &SplitSettings, countries: &[String], link: &Link) -> Result<()> {
        self.stop();
        if !s.enabled {
            return Ok(());
        }
        let mode = s.mode;
        let (v4, v6) = static_sets(s, countries);
        if self.system {
            self.tracker()?;
            let spec = net::TableSpec {
                mode,
                iface: TUNNEL_IFACE.into(),
                app_cgroup: Some(apps::CGROUP.into()),
                daemon_cgroup: self.daemon_cgroup.clone(),
                static_v4: v4.clone(),
                static_v6: v6.clone(),
            };
            net::run_nft(&net::table_script(&spec))?;
            if let Err(e) = net::setup_routing(mode, TUNNEL_IFACE, link.server_ip.as_deref()) {
                self.stop();
                return Err(e);
            }
            let config = ProxyConfig {
                mode,
                domains: DomainList::new(&rules(s)),
                vpn: link.vpn_dns.clone(),
                direct: link.direct_dns.clone(),
                upstream_port: 53,
            };
            match Proxy::start(dnsproxy::LISTEN, config, Sink::Nft) {
                Ok(p) => self.proxy = Some(p),
                Err(e) => warn!("split DNS isn't available, domain rules won't apply: {e:#}"),
            }
            self.tracker()?.set_apps(&s.apps);
        }
        self.mode = Some(mode);
        self.server_ip = link.server_ip.as_deref().and_then(|ip| ip.parse().ok());
        self.nets = v4.iter().chain(&v6).cloned().collect();
        self.domains = domain_rules(s);
        self.apps = s.apps.iter().map(|a| a.path.clone()).collect();
        self.pending = Pending::default();
        if self.system {
            // Connections that were open before split tunneling started.
            let targets = flows::Targets {
                ips: self.seed_looked_up(&self.domains.clone()),
                nets: nets_of(&self.nets),
            };
            self.close_broken(&targets);
            if !self.domains.is_empty() {
                flows::flush_resolved();
            }
        }
        info!(
            "split tunneling on ({mode:?}): {} apps, {} hosts, {} country networks",
            s.apps.len(),
            s.hosts.len(),
            countries.len()
        );
        Ok(())
    }

    /// Apply changed rules to the running connection (same mode).
    pub fn update(&mut self, s: &SplitSettings, countries: &[String]) -> Result<()> {
        if self.mode.is_none() {
            return Ok(());
        }
        if self.system {
            let (v4, v6) = static_sets(s, countries);
            net::run_nft(&net::static_sets_script(&v4, &v6))?;
            let nets: HashSet<String> = v4.into_iter().chain(v6).collect();
            let added_nets = nets_of(nets.difference(&self.nets));
            self.pending
                .targets
                .nets
                .extend(nets_of(self.nets.difference(&nets)));
            self.nets = nets;

            let domains = domain_rules(s);
            let added: Vec<Rule> = domains
                .iter()
                .filter(|d| !self.domains.contains(d))
                .cloned()
                .collect();
            let removed = self.domains.iter().any(|d| !domains.contains(d));
            self.domains = domains;
            if let Some(p) = &self.proxy {
                let gone = p.set_domains(DomainList::new(&rules(s)));
                if !gone.is_empty() {
                    info!(
                        "split: dropping {} address(es) of removed domains",
                        gone.len()
                    );
                    net::forget_dynamic(&gone);
                    self.pending.targets.ips.extend(gone);
                }
            }

            // Connections to what was just added break if left alone (see
            // `flows`), so they're closed now.
            let targets = flows::Targets {
                ips: self.seed_looked_up(&added),
                nets: added_nets,
            };
            self.close_broken(&targets);
            if !added.is_empty() || removed {
                flows::flush_resolved();
            }

            let apps: Vec<String> = s.apps.iter().map(|a| a.path.clone()).collect();
            if apps != self.apps {
                self.pending.apps = true;
                self.apps = apps;
            }
            self.tracker()?.set_apps(&s.apps);
        }
        Ok(())
    }

    /// Split the addresses apps already looked up for `domains` (they keep
    /// using them without asking again), and return everything split for
    /// those domains.
    fn seed_looked_up(&self, domains: &[Rule]) -> HashSet<IpAddr> {
        let Some(p) = &self.proxy else {
            return HashSet::new();
        };
        if domains.is_empty() {
            return HashSet::new();
        }
        let list = DomainList::new(domains);
        let entries = p.seed(&list);
        if !entries.is_empty() {
            info!(
                "split: {} address(es) apps already looked up",
                entries.len()
            );
            if let Err(e) = net::run_nft(&net::dynamic_script(&entries)) {
                warn!("adding looked-up split addresses: {e:#}");
            }
        }
        p.learned_for(&list).into_iter().collect()
    }

    fn tunnel_addrs() -> HashSet<IpAddr> {
        net::iface_addrs(TUNNEL_IFACE).unwrap_or_default()
    }

    /// Close connections to `targets` that the change moved to the other
    /// side: in exclude mode those that went through the tunnel (they use
    /// its address), in include mode those that didn't.
    fn close_broken(&self, targets: &flows::Targets) {
        if targets.is_empty() {
            return;
        }
        let tunnel = Self::tunnel_addrs();
        let exclude = self.mode == Some(SplitMode::Exclude);
        self.close(|s| {
            let sel = flows::Selection {
                targets,
                apps: None,
                daemon_cgroup: self.daemon_cgroup.as_deref(),
                server_ip: self.server_ip,
            };
            flows::select(s, &sel)
                .into_iter()
                .filter(|x| tunnel.contains(&x.local.0) == exclude)
                .collect()
        });
    }

    fn close(&self, pick: impl FnOnce(&[flows::Sock]) -> Vec<flows::Sock>) -> usize {
        let socks = match flows::established() {
            Ok(s) => s,
            Err(e) => {
                warn!("listing connections: {e:#}");
                return 0;
            }
        };
        let victims = pick(&socks);
        if victims.is_empty() {
            return 0;
        }
        match flows::kill(&victims) {
            Ok(()) => {
                info!(
                    "split: closed {} connection(s) to apply rules",
                    victims.len()
                );
                victims.len()
            }
            Err(e) => {
                warn!("closing connections: {e:#}");
                0
            }
        }
    }

    /// Make open connections follow the current rules: close those still on
    /// the side an earlier rule set chose. Apps reconnect right away.
    pub fn apply_now(&mut self) -> Result<usize> {
        anyhow::ensure!(self.mode.is_some(), "Split tunneling is off.");
        if !self.system {
            self.pending = Pending::default();
            return Ok(0);
        }
        let domains = self.domains.clone();
        let current = flows::Targets {
            ips: self.seed_looked_up(&domains),
            nets: nets_of(&self.nets),
        };
        let tunnel = Self::tunnel_addrs();
        let exclude = self.mode == Some(SplitMode::Exclude);
        let owned = flows::cgroup_socket_inodes(Path::new(apps::CGROUP_ROOT), apps::CGROUP);
        let pending = std::mem::take(&mut self.pending);
        let n = self.close(|socks| {
            let base = |targets, apps| flows::Selection {
                targets,
                apps,
                daemon_cgroup: self.daemon_cgroup.as_deref(),
                server_ip: self.server_ip,
            };
            let mut out =
                flows::select(socks, &base(&pending.targets, Some((apps::CGROUP, &owned))));
            out.extend(
                flows::select(socks, &base(&current, None))
                    .into_iter()
                    .filter(|x| tunnel.contains(&x.local.0) == exclude),
            );
            out.sort_by_key(|s| s.inode);
            out.dedup_by_key(|s| s.inode);
            out
        });
        flows::flush_resolved();
        Ok(n)
    }

    /// Turn split tunneling off on a running connection. Connections that
    /// went around the tunnel can't move into it, so they're closed.
    pub fn turn_off(&mut self) {
        let targets = flows::Targets {
            ips: self
                .proxy
                .as_ref()
                .map(|p| p.learned_for(&DomainList::new(&self.domains)))
                .unwrap_or_default()
                .into_iter()
                .chain(self.pending.targets.ips.iter().copied())
                .collect(),
            nets: nets_of(&self.nets)
                .into_iter()
                .chain(self.pending.targets.nets.iter().copied())
                .collect(),
        };
        let was = self.mode;
        self.stop();
        if !self.system || was.is_none() {
            return;
        }
        let none = HashSet::new();
        self.close(|socks| {
            flows::select(
                socks,
                &flows::Selection {
                    targets: &targets,
                    apps: Some((apps::CGROUP, &none)),
                    daemon_cgroup: self.daemon_cgroup.as_deref(),
                    server_ip: self.server_ip,
                },
            )
        });
    }

    pub fn set_dns(&mut self, vpn: &[IpAddr], direct: &[IpAddr]) {
        if let Some(p) = &self.proxy {
            p.update(|c| {
                c.vpn = vpn.to_vec();
                c.direct = direct.to_vec();
            });
        }
    }

    /// Move a process (and its future children) into the split cgroup.
    pub fn bypass(&mut self, pid: u32) -> Result<()> {
        anyhow::ensure!(
            self.system,
            "per-app split tunneling needs the system service"
        );
        self.tracker()?.add(pid, true)
    }

    pub fn stop(&mut self) {
        if let Some(p) = self.proxy.take() {
            p.stop();
        }
        if let Some(t) = self.tracker.as_mut() {
            t.stop();
        }
        if self.mode.take().is_some() && self.system {
            if let Err(e) = net::run_nft(&net::delete_table_script()) {
                warn!("removing split rules: {e:#}");
            }
            net::clear_routing();
            info!("split tunneling off");
        }
        self.pending = Pending::default();
        self.nets.clear();
        self.domains.clear();
        self.apps.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_static_sets() {
        let s = SplitSettings {
            enabled: true,
            hosts: vec!["*.ir".into(), "10.1.0.0/16".into(), "2001:db8::/32".into()],
            ..SplitSettings::default()
        };
        let (v4, v6) = static_sets(&s, &["5.0.0.0/8".into(), "2a01::/16".into()]);
        assert_eq!(v4, vec!["10.1.0.0/16", "5.0.0.0/8"]);
        assert_eq!(v6, vec!["2001:db8::/32", "2a01::/16"]);
    }

    #[test]
    fn session_mode_only_tracks_state() {
        let mut sp = Split::new(false, None);
        let s = SplitSettings {
            enabled: true,
            ..SplitSettings::default()
        };
        sp.start(&s, &[], &Link::default()).unwrap();
        assert_eq!(sp.mode(), Some(SplitMode::Exclude));
        sp.stop();
        assert_eq!(sp.mode(), None);
    }
}
