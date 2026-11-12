//! Open connections and split rule changes.
//!
//! The nft rules decide a flow's side per packet, and a socket's source
//! address is fixed when it connects. So when a destination becomes split
//! while a connection to it runs through the tunnel, its packets start
//! leaving the other way with the tunnel's source address and the
//! connection hangs. The same goes the other way in include mode. Those
//! sockets are closed (`ss -K`, which the app sees as a reset) so the app
//! reconnects on the right side straight away.
//!
//! Changes that leave open connections working (a removed rule, an app
//! added or removed) wait for an explicit apply, since closing working
//! connections would interrupt downloads and calls.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use tracing::debug;

/// An address or network from the static sets, for matching peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Net {
    addr: IpAddr,
    prefix: u8,
}

impl Net {
    pub fn parse(s: &str) -> Option<Net> {
        let (a, p) = s.split_once('/').unwrap_or((s, ""));
        let addr: IpAddr = a.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = if p.is_empty() { max } else { p.parse().ok()? };
        (prefix <= max).then_some(Net { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

/// Destinations whose open connections should be closed.
#[derive(Debug, Default, Clone)]
pub struct Targets {
    pub ips: HashSet<IpAddr>,
    pub nets: Vec<Net>,
}

impl Targets {
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() && self.nets.is_empty()
    }

    fn matches(&self, ip: IpAddr) -> bool {
        self.ips.contains(&ip) || self.nets.iter().any(|n| n.contains(ip))
    }
}

/// One established TCP connection or connected UDP socket, from `ss`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sock {
    pub udp: bool,
    pub local: (IpAddr, u16),
    pub peer: (IpAddr, u16),
    pub inode: u64,
    /// cgroup the socket was created in, e.g. `/portal-split`.
    pub cgroup: String,
}

fn endpoint(s: &str) -> Option<(IpAddr, u16)> {
    let (addr, port) = s.rsplit_once(':')?;
    let addr = addr.trim_start_matches('[').trim_end_matches(']');
    // Link-local and bound addresses carry `%iface`.
    let addr = addr.split('%').next()?;
    Some((addr.parse().ok()?, port.parse().ok()?))
}

/// Parse `ss -tuneH state established` output.
pub fn parse_ss(text: &str) -> Vec<Sock> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let udp = match *f.first()? {
                "tcp" => false,
                "udp" => true,
                _ => return None,
            };
            let field = |k: &str| f.iter().find_map(|x| x.strip_prefix(k));
            Some(Sock {
                udp,
                local: endpoint(f.get(3)?)?,
                peer: endpoint(f.get(4)?)?,
                inode: field("ino:")?.parse().ok()?,
                cgroup: field("cgroup:").unwrap_or("").to_string(),
            })
        })
        .collect()
}

pub fn established() -> Result<Vec<Sock>> {
    let out = Command::new("ss")
        .args(["-tuneH", "state", "established"])
        .output()
        .context("running ss")?;
    if !out.status.success() {
        bail!("ss: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(parse_ss(&String::from_utf8_lossy(&out.stdout)))
}

/// Socket inodes held by the processes in `cgroup` (relative to the
/// cgroup root).
pub fn cgroup_socket_inodes(root: &Path, cgroup: &str) -> HashSet<u64> {
    let procs = std::fs::read_to_string(root.join(cgroup).join("cgroup.procs")).unwrap_or_default();
    let mut inodes = HashSet::new();
    for pid in procs.lines().filter_map(|l| l.trim().parse::<u32>().ok()) {
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(link) = std::fs::read_link(fd.path())
                && let Some(n) = link
                    .to_str()
                    .and_then(|l| l.strip_prefix("socket:["))
                    .and_then(|l| l.strip_suffix(']'))
                    .and_then(|n| n.parse().ok())
            {
                inodes.insert(n);
            }
        }
    }
    inodes
}

/// What decides which sockets to close.
pub struct Selection<'a> {
    pub targets: &'a Targets,
    /// Also close sockets whose split cgroup membership no longer matches
    /// their owner's (apps added or removed).
    pub apps: Option<(&'a str, &'a HashSet<u64>)>,
    /// The daemon's own cgroup: OpenVPN's connection is never touched.
    pub daemon_cgroup: Option<&'a str>,
    pub server_ip: Option<IpAddr>,
}

pub fn select(socks: &[Sock], sel: &Selection) -> Vec<Sock> {
    socks
        .iter()
        .filter(|s| {
            let peer = s.peer.0;
            if peer.is_loopback() || Some(peer) == sel.server_ip {
                return false;
            }
            let cg = s.cgroup.trim_matches('/');
            if sel
                .daemon_cgroup
                .is_some_and(|d| cg == d || cg.starts_with(&format!("{d}/")))
            {
                return false;
            }
            if sel.targets.matches(peer) {
                return true;
            }
            sel.apps.is_some_and(|(split_cg, owned)| {
                (cg == split_cg.trim_matches('/')) != owned.contains(&s.inode)
            })
        })
        .cloned()
        .collect()
}

fn host(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

/// `ss` filter matching exactly these sockets.
pub fn kill_filter(socks: &[Sock]) -> String {
    let parts: Vec<String> = socks
        .iter()
        .map(|s| {
            format!(
                "( src {} and sport = :{} and dst {} and dport = :{} )",
                host(s.local.0),
                s.local.1,
                host(s.peer.0),
                s.peer.1
            )
        })
        .collect();
    parts.join(" or ")
}

/// Close the sockets; their apps see a reset and reconnect.
pub fn kill(socks: &[Sock]) -> Result<()> {
    for chunk in socks.chunks(32) {
        let out = Command::new("ss")
            .args(["-K", "-tuH"])
            .arg(kill_filter(chunk))
            .output()
            .context("running ss -K")?;
        if !out.status.success() {
            bail!("ss -K: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
    }
    Ok(())
}

/// Make the next lookups go through the split DNS proxy again.
pub fn flush_resolved() {
    match Command::new("resolvectl").arg("flush-caches").output() {
        Ok(o) if o.status.success() => {}
        Ok(o) => debug!(
            "resolvectl flush-caches: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => debug!("resolvectl flush-caches: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SS: &str = "\
udp   0      0            172.16.100.100%enp6s0:68                172.16.100.201:67    ino:35093 sk:1 cgroup:/system.slice/NetworkManager.service <->
tcp   0      0                        10.16.0.2:55908             149.154.167.92:443   uid:1000 ino:2646896 sk:1001 cgroup:/user.slice/app.slice/telegram.scope <->
tcp   0      0                        10.16.0.2:40100               46.36.99.104:443   uid:1000 ino:777 sk:1002 cgroup:/portal-split <->
tcp   0      0              [2a02:6ea0::5]:50000           [2a00:1450::1]:443   uid:1000 ino:888 sk:1003 cgroup:/user.slice/firefox.scope <->
tcp   0      0                        10.16.0.2:41000              94.183.175.203:1194 ino:999 sk:1004 cgroup:/system.slice/portald.service <->
tcp   0      0                        127.0.0.1:27018                  127.0.0.1:40174 ino:51617 sk:1005 cgroup:/system.slice/docker.service <->
";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_ss() {
        let socks = parse_ss(SS);
        assert_eq!(socks.len(), 6);
        assert_eq!(socks[0].local, (ip("172.16.100.100"), 68));
        assert!(socks[0].udp);
        assert_eq!(socks[2].cgroup, "/portal-split");
        assert_eq!(socks[3].peer, (ip("2a00:1450::1"), 443));
        assert_eq!(socks[3].inode, 888);
    }

    #[test]
    fn nets_match() {
        assert!(
            Net::parse("46.36.0.0/16")
                .unwrap()
                .contains(ip("46.36.99.104"))
        );
        assert!(
            !Net::parse("46.36.0.0/16")
                .unwrap()
                .contains(ip("46.37.0.1"))
        );
        assert!(Net::parse("0.0.0.0/0").unwrap().contains(ip("1.2.3.4")));
        assert!(
            Net::parse("2a00::/12")
                .unwrap()
                .contains(ip("2a00:1450::1"))
        );
        assert!(!Net::parse("2a00::/12").unwrap().contains(ip("1.2.3.4")));
        assert!(Net::parse("1.2.3.4").unwrap().contains(ip("1.2.3.4")));
        assert!(Net::parse("1.2.3.4/33").is_none());
    }

    #[test]
    fn selects_affected_sockets() {
        let socks = parse_ss(SS);
        let targets = Targets {
            ips: [ip("149.154.167.92")].into(),
            // Covers the VPN relay too; its connection must survive.
            nets: vec![Net::parse("94.183.0.0/16").unwrap()],
        };
        let sel = Selection {
            targets: &targets,
            apps: None,
            daemon_cgroup: Some("system.slice/portald.service"),
            server_ip: None,
        };
        let picked: Vec<u64> = select(&socks, &sel).iter().map(|s| s.inode).collect();
        assert_eq!(picked, vec![2646896]);

        // Apps: 777 sits in the split cgroup but its owner left it; 888's
        // owner joined it.
        let owned: HashSet<u64> = [888].into();
        let sel = Selection {
            targets: &Targets::default(),
            apps: Some(("portal-split", &owned)),
            daemon_cgroup: Some("system.slice/portald.service"),
            server_ip: None,
        };
        let picked: Vec<u64> = select(&socks, &sel).iter().map(|s| s.inode).collect();
        assert_eq!(picked, vec![777, 888]);

        // Nothing changed for apps that stay put.
        let owned: HashSet<u64> = [777].into();
        let sel = Selection {
            apps: Some(("portal-split", &owned)),
            targets: &Targets::default(),
            daemon_cgroup: None,
            server_ip: None,
        };
        assert!(select(&socks, &sel).is_empty());
    }

    #[test]
    fn kill_filter_is_exact() {
        let socks = parse_ss(SS);
        assert_eq!(
            kill_filter(&socks[2..4]),
            "( src 10.16.0.2 and sport = :40100 and dst 46.36.99.104 and dport = :443 ) or \
             ( src [2a02:6ea0::5] and sport = :50000 and dst [2a00:1450::1] and dport = :443 )"
        );
    }
}
