//! Kill switch, IPv6 and DNS leak rules, as one nftables table
//! (`inet portal`) that the daemon owns. Every change replaces the whole
//! table in a single `nft -f` transaction, so there is never a moment with
//! half the rules loaded. Other tables (ufw, Docker, ...) are left alone.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use portal_core::SplitMode;
use tracing::{debug, info, warn};

use crate::split::net::{MARK_DIRECT, MARK_TUNNEL};

const TABLE: &str = "portal";

/// Everything the rules depend on. Built by the manager from the settings
/// and the connection state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Kill switch: reject everything except the tunnel and the exceptions.
    pub block: bool,
    /// Tunnel interface name.
    pub iface: String,
    /// The tunnel is up (DNS and IPv6 rules only make sense then).
    pub connected: bool,
    pub allow_lan: bool,
    pub block_ipv6: bool,
    pub dns_guard: bool,
    /// cgroup of the daemon (and the OpenVPN it starts), which must reach
    /// the VPN server while everything else is blocked.
    pub daemon_cgroup: Option<String>,
    /// cgroup of systemd-resolved, allowed to resolve the server's name
    /// while connecting.
    pub resolver_cgroup: Option<String>,
    /// Address of the VPN server once connected. With DCO the kernel sends
    /// the encrypted packets itself, outside the daemon's cgroup, so the
    /// cgroup rule alone would block the tunnel.
    pub server: Option<std::net::IpAddr>,
    /// Split tunneling mode while it's running.
    pub split: Option<SplitMode>,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        !self.block && !(self.connected && (self.block_ipv6 || self.dns_guard))
    }
}

const LAN_V4: &str =
    "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255";
const LAN_V6: &str = "fe80::/10, fc00::/7, ff00::/8";

fn cgroup_rule(path: &str) -> String {
    let level = path.split('/').filter(|s| !s.is_empty()).count();
    format!("socket cgroupv2 level {level} \"{path}\"")
}

/// The nft script for a plan. Always starts by removing the old table.
pub fn ruleset(plan: &Plan) -> String {
    let s = format!("table inet {TABLE} {{}}\ndelete table inet {TABLE}\n");
    if plan.is_empty() {
        return s;
    }
    let iface = &plan.iface;
    let mut rules: Vec<String> = vec![
        "oifname \"lo\" accept".into(),
        format!("oifname \"{iface}\" accept"),
    ];
    // The daemon's own traffic: OpenVPN reaching the server, and the split
    // DNS proxy asking the physical network's resolvers.
    if let Some(cg) = &plan.daemon_cgroup {
        rules.push(format!("{} accept", cgroup_rule(cg)));
    }
    match plan.server {
        Some(std::net::IpAddr::V4(ip)) => rules.push(format!("ip daddr {ip} accept")),
        Some(std::net::IpAddr::V6(ip)) => rules.push(format!("ip6 daddr {ip} accept")),
        None => {}
    }

    if plan.connected && plan.dns_guard {
        // DNS (plain and DoT) may only leave through the tunnel.
        rules.push("meta l4proto { tcp, udp } th dport { 53, 853 } reject with icmpx type admin-prohibited".into());
    }

    match plan.split {
        // Split traffic is meant to go around the tunnel.
        Some(SplitMode::Exclude) if plan.connected => {
            rules.push(format!("meta mark {MARK_DIRECT:#x} accept"))
        }
        // Only split traffic uses the tunnel; the kill switch guards just that.
        Some(SplitMode::Include) if plan.connected && plan.block => {
            rules.push(format!(
                "meta mark {MARK_TUNNEL:#x} reject with icmpx type admin-prohibited"
            ));
            return finish(s, rules);
        }
        _ => {}
    }

    if plan.block {
        if !plan.connected
            && let Some(cg) = &plan.resolver_cgroup
        {
            rules.push(format!(
                "{} meta l4proto {{ tcp, udp }} th dport 53 accept",
                cgroup_rule(cg)
            ));
        }
        // Keep the link itself working: DHCP and IPv6 neighbor discovery.
        rules.push("udp sport 68 udp dport 67 accept".into());
        rules.push("udp dport 547 accept".into());
        rules.push(
            "icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, mld2-listener-report } accept"
                .into(),
        );
        if plan.allow_lan {
            rules.push(format!("ip daddr {{ {LAN_V4} }} accept"));
            rules.push(format!("ip6 daddr {{ {LAN_V6} }} accept"));
        }
        rules.push("reject with icmpx type admin-prohibited".into());
    } else if plan.connected && plan.block_ipv6 && plan.split != Some(SplitMode::Include) {
        if plan.allow_lan {
            rules.push(format!("ip6 daddr {{ {LAN_V6} }} accept"));
        }
        rules.push(
            "icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept"
                .into(),
        );
        rules.push("meta nfproto ipv6 reject with icmpx type admin-prohibited".into());
    }

    finish(s, rules)
}

fn finish(mut s: String, rules: Vec<String>) -> String {
    s.push_str(&format!("table inet {TABLE} {{\n  chain output {{\n    type filter hook output priority filter; policy accept;\n"));
    for r in rules {
        s.push_str("    ");
        s.push_str(&r);
        s.push('\n');
    }
    s.push_str("  }\n}\n");
    s
}

/// Loads plans with `nft`. In development (`--session`) it only logs.
pub struct Firewall {
    enabled: bool,
    current: Option<Plan>,
}

impl Firewall {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            current: None,
        }
    }

    /// Apply a plan if it differs from the loaded one.
    pub fn apply(&mut self, plan: &Plan) -> Result<()> {
        if self.current.as_ref() == Some(plan) {
            return Ok(());
        }
        let script = ruleset(plan);
        if self.enabled {
            run_nft(&script)?;
        } else {
            debug!("firewall (not applied in session mode):\n{script}");
        }
        if plan.is_empty() {
            info!("firewall rules removed");
        } else {
            info!(
                "firewall rules loaded (block={}, connected={}, lan={}, ipv6={}, dns_guard={})",
                plan.block, plan.connected, plan.allow_lan, plan.block_ipv6, plan.dns_guard
            );
        }
        self.current = Some(plan.clone());
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.current.as_ref().is_some_and(|p| p.block)
    }

    /// Remove our table, e.g. on shutdown.
    pub fn clear(&mut self) {
        if let Err(e) = self.apply(&Plan::default()) {
            warn!("removing firewall rules: {e:#}");
        }
    }
}

fn run_nft(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("running nft (is nftables installed?)")?;
    child
        .stdin
        .take()
        .context("nft stdin")?
        .write_all(script.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "nft rejected the firewall rules: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// cgroup v2 path of this process, e.g. `system.slice/portald.service`.
pub fn own_cgroup() -> Option<String> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = text
        .lines()
        .find_map(|l| l.strip_prefix("0::"))?
        .trim_matches('/');
    (!path.is_empty()).then(|| path.to_string())
}

/// cgroup of systemd-resolved, if it runs.
pub fn resolver_cgroup() -> Option<String> {
    let path = "system.slice/systemd-resolved.service";
    std::path::Path::new("/sys/fs/cgroup")
        .join(path)
        .is_dir()
        .then(|| path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Plan {
        Plan {
            iface: "portal0".into(),
            daemon_cgroup: Some("system.slice/portald.service".into()),
            resolver_cgroup: Some("system.slice/systemd-resolved.service".into()),
            allow_lan: true,
            block_ipv6: true,
            dns_guard: true,
            ..Plan::default()
        }
    }

    #[test]
    fn empty_plan_only_removes_the_table() {
        let s = ruleset(&Plan::default());
        assert_eq!(s, "table inet portal {}\ndelete table inet portal\n");
    }

    #[test]
    fn kill_switch_while_connecting() {
        let s = ruleset(&Plan {
            block: true,
            ..base()
        });
        assert!(s.contains("oifname \"portal0\" accept"));
        assert!(s.contains("socket cgroupv2 level 2 \"system.slice/portald.service\" accept"));
        assert!(
            s.contains("systemd-resolved.service\" meta l4proto { tcp, udp } th dport 53 accept")
        );
        assert!(s.contains("ip daddr { 10.0.0.0/8"));
        assert!(
            !s.contains("th dport { 53, 853 } reject"),
            "no DNS guard before the tunnel is up"
        );
        assert!(
            s.trim_end()
                .ends_with("reject with icmpx type admin-prohibited\n  }\n}")
        );
    }

    #[test]
    fn kill_switch_while_connected() {
        let s = ruleset(&Plan {
            block: true,
            connected: true,
            ..base()
        });
        assert!(
            !s.contains("systemd-resolved"),
            "the resolver must use the tunnel once it's up"
        );
        let guard = s.find("th dport { 53, 853 } reject").unwrap();
        let daemon = s.find("portald.service").unwrap();
        assert!(
            daemon < guard,
            "the daemon's split DNS proxy may reach physical resolvers"
        );
    }

    #[test]
    fn kill_switch_lets_the_kernel_reach_the_server() {
        let s = ruleset(&Plan {
            block: true,
            connected: true,
            server: Some("79.127.59.71".parse().unwrap()),
            ..base()
        });
        let server = s.find("ip daddr 79.127.59.71 accept").unwrap();
        assert!(server < s.rfind("reject").unwrap());
        let s = ruleset(&Plan {
            block: true,
            server: Some("2001:db8::1".parse().unwrap()),
            ..base()
        });
        assert!(s.contains("ip6 daddr 2001:db8::1 accept"));
    }

    #[test]
    fn no_lan_exception_when_disallowed() {
        let s = ruleset(&Plan {
            block: true,
            allow_lan: false,
            ..base()
        });
        assert!(!s.contains("192.168.0.0/16"));
    }

    #[test]
    fn leak_rules_without_kill_switch() {
        let s = ruleset(&Plan {
            connected: true,
            ..base()
        });
        assert!(s.contains("th dport { 53, 853 } reject"));
        assert!(s.contains("meta nfproto ipv6 reject"));
        let off = Plan {
            connected: true,
            block_ipv6: false,
            dns_guard: false,
            ..base()
        };
        assert!(off.is_empty());
    }

    /// Load every rule variant into a real nftables, inside a throwaway
    /// user + network namespace. Skipped where that isn't allowed.
    #[test]
    fn nft_accepts_the_rules() {
        let probe = Command::new("unshare")
            .args(["-rn", "nft", "list", "tables"])
            .output();
        if !matches!(&probe, Ok(o) if o.status.success()) {
            eprintln!("skipping: can't run nft in a user namespace here");
            return;
        }
        let real = Plan {
            daemon_cgroup: own_cgroup(),
            resolver_cgroup: resolver_cgroup(),
            ..base()
        };
        let plans = [
            Plan {
                block: true,
                ..real.clone()
            },
            Plan {
                block: true,
                connected: true,
                server: Some("203.0.113.24".parse().unwrap()),
                ..real.clone()
            },
            Plan {
                block: true,
                server: Some("2001:db8::1".parse().unwrap()),
                ..real.clone()
            },
            Plan {
                block: true,
                allow_lan: false,
                ..real.clone()
            },
            Plan {
                connected: true,
                ..real.clone()
            },
            Plan::default(),
        ];
        for plan in plans {
            let script = ruleset(&plan);
            let mut child = Command::new("unshare")
                .args([
                    "-rn",
                    "sh",
                    "-c",
                    "nft -f - && nft list table inet portal 2>/dev/null; true",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(script.as_bytes())
                .unwrap();
            let out = child.wait_with_output().unwrap();
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.trim().is_empty(),
                "nft rejected:\n{script}\n{stderr}"
            );
            if !plan.is_empty() {
                assert!(String::from_utf8_lossy(&out.stdout).contains("chain output"));
            }
        }
    }

    #[test]
    fn split_exclude_lets_marked_traffic_out() {
        let s = ruleset(&Plan {
            block: true,
            connected: true,
            split: Some(SplitMode::Exclude),
            ..base()
        });
        let mark = s.find("meta mark 0x5470 accept").unwrap();
        let reject = s.rfind("reject with icmpx").unwrap();
        assert!(mark < reject);
    }

    #[test]
    fn split_include_guards_only_marked_traffic() {
        let s = ruleset(&Plan {
            block: true,
            connected: true,
            split: Some(SplitMode::Include),
            ..base()
        });
        assert!(s.contains("meta mark 0x5471 reject"));
        assert_eq!(
            s.matches("reject").count(),
            2,
            "DNS guard + marked traffic only:\n{s}"
        );
    }
}
