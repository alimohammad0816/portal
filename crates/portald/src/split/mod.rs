//! Split tunneling: chosen apps, domains, networks and countries go around
//! the tunnel (exclude mode) or are the only things that use it (include
//! mode). See `net` for the kernel side, `dnsproxy` for domains and `apps`
//! for per-app rules. Rule changes apply to the running connection; only
//! switching to or from include mode needs a reconnect, because OpenVPN
//! must start without installing its routes.

pub mod apps;
pub mod dnsmsg;
pub mod dnsproxy;
pub mod geoip;
pub mod net;

use std::net::IpAddr;

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
        }
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
                static_v4: v4,
                static_v6: v6,
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
            if let Some(p) = &self.proxy {
                let domains = DomainList::new(&rules(s));
                p.update(|c| c.domains = domains);
            }
            self.tracker()?.set_apps(&s.apps);
        }
        Ok(())
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
