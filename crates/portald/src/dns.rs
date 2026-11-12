//! DNS for the tunnel through systemd-resolved: the tunnel link gets the
//! VPN's (or the user's) servers and the `~.` routing domain, so every
//! lookup goes through the tunnel. resolved forgets the link's settings by
//! itself when the interface disappears.

use std::net::IpAddr;

use anyhow::{Context, Result};
use tracing::{info, warn};
use zbus::proxy;

#[proxy(
    interface = "org.freedesktop.resolve1.Manager",
    default_service = "org.freedesktop.resolve1",
    default_path = "/org/freedesktop/resolve1"
)]
trait Resolved {
    #[zbus(name = "SetLinkDNS")]
    fn set_link_dns(&self, ifindex: i32, addresses: &[(i32, Vec<u8>)]) -> zbus::Result<()>;
    fn set_link_domains(&self, ifindex: i32, domains: &[(&str, bool)]) -> zbus::Result<()>;
    fn set_link_default_route(&self, ifindex: i32, enable: bool) -> zbus::Result<()>;
    #[zbus(name = "SetLinkDNSOverTLS")]
    fn set_link_dns_over_tls(&self, ifindex: i32, mode: &str) -> zbus::Result<()>;
    #[zbus(property, name = "DNS")]
    fn dns(&self) -> zbus::Result<Vec<(i32, i32, Vec<u8>)>>;
}

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;

fn ifindex(iface: &str) -> Result<i32> {
    let text = std::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .with_context(|| format!("interface {iface} not found"))?;
    Ok(text.trim().parse()?)
}

fn encode(ip: &IpAddr) -> (i32, Vec<u8>) {
    match ip {
        IpAddr::V4(v4) => (AF_INET, v4.octets().to_vec()),
        IpAddr::V6(v6) => (AF_INET6, v6.octets().to_vec()),
    }
}

/// How the tunnel link should take part in DNS.
#[derive(Debug, Clone)]
pub struct LinkDns {
    pub servers: Vec<IpAddr>,
    /// Routing domains: `.` sends every lookup here; split include mode
    /// lists only the split domains.
    pub routing: Vec<String>,
    /// Extra search domains pushed by the server.
    pub search: Vec<String>,
    /// Use this link for names no routing domain matches.
    pub default_route: bool,
}

pub async fn configure(iface: &str, cfg: &LinkDns) -> Result<()> {
    let idx = ifindex(iface)?;
    let conn = zbus::Connection::system().await?;
    let r = ResolvedProxy::new(&conn)
        .await
        .context("systemd-resolved isn't available")?;
    let addrs: Vec<(i32, Vec<u8>)> = cfg.servers.iter().map(encode).collect();
    r.set_link_dns(idx, &addrs)
        .await
        .context("setting tunnel DNS servers")?;
    let mut domains: Vec<(&str, bool)> = cfg.routing.iter().map(|d| (d.as_str(), true)).collect();
    domains.extend(cfg.search.iter().map(|d| (d.as_str(), false)));
    r.set_link_domains(idx, &domains)
        .await
        .context("setting tunnel DNS domains")?;
    r.set_link_default_route(idx, cfg.default_route).await?;
    // Plain DNS inside the tunnel; most VPN resolvers don't speak DoT.
    if let Err(e) = r.set_link_dns_over_tls(idx, "no").await {
        warn!("resolved: {e}");
    }
    info!(
        "DNS for {iface}: {:?} (routing {:?})",
        cfg.servers, cfg.routing
    );
    Ok(())
}

/// The resolvers configured for every link except `iface`, plus the global
/// ones: what the physical network uses.
pub async fn system_servers(iface: &str) -> Vec<IpAddr> {
    let skip = ifindex(iface).unwrap_or(-1);
    let Ok(conn) = zbus::Connection::system().await else {
        return vec![];
    };
    let Ok(r) = ResolvedProxy::new(&conn).await else {
        return vec![];
    };
    let Ok(list) = r.dns().await else {
        return vec![];
    };
    let mut out: Vec<IpAddr> = list
        .into_iter()
        .filter(|(idx, _, _)| *idx != skip)
        .filter_map(|(_, family, bytes)| decode(family, &bytes))
        .filter(|ip| !ip.is_loopback())
        .collect();
    out.dedup();
    out
}

fn decode(family: i32, bytes: &[u8]) -> Option<IpAddr> {
    match (family, bytes.len()) {
        (AF_INET, 4) => Some(IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?)),
        (AF_INET6, 16) => Some(IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?)),
        _ => None,
    }
}

/// DNS servers and search domains from a `PUSH_REPLY` log line, e.g.
/// `PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.8.0.1,...'`.
/// Understands both `dhcp-option DNS/DNS6/DOMAIN/DOMAIN-SEARCH` and the
/// OpenVPN 2.6 `dns server N address A` / `dns search-domains` options.
pub fn parse_push(line: &str) -> Option<(Vec<IpAddr>, Vec<String>)> {
    let start = line.find("PUSH_REPLY,")? + "PUSH_REPLY,".len();
    let body = line[start..].trim_end_matches(['\'', '"']);
    let mut servers = Vec::new();
    let mut domains = Vec::new();
    for opt in body.split(',') {
        let w: Vec<&str> = opt.split_whitespace().collect();
        match w.as_slice() {
            ["dhcp-option", "DNS" | "DNS6", ip, ..] => {
                if let Ok(ip) = ip.parse() {
                    servers.push(ip);
                }
            }
            [
                "dhcp-option",
                "DOMAIN" | "DOMAIN-SEARCH" | "ADAPTER_DOMAIN_SUFFIX",
                d,
                ..,
            ] => domains.push(d.to_string()),
            ["dns", "server", _, "address", addrs @ ..] => {
                for a in addrs {
                    // `address` may carry `ip:port` or `[ip6]:port`.
                    let a = a.trim_start_matches('[');
                    let a = a.split(']').next().unwrap_or(a);
                    let a = if a.matches(':').count() == 1 {
                        a.split(':').next().unwrap_or(a)
                    } else {
                        a
                    };
                    if let Ok(ip) = a.parse() {
                        servers.push(ip);
                    }
                }
            }
            ["dns", "search-domains", ds @ ..] => domains.extend(ds.iter().map(|d| d.to_string())),
            _ => {}
        }
    }
    servers.dedup();
    domains.dedup();
    Some((servers, domains))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dhcp_options() {
        let line = "PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 10.8.0.1,dhcp-option DNS 1.1.1.1,dhcp-option DOMAIN corp.example,route-gateway 10.8.0.1,ifconfig 10.8.0.6 255.255.255.0'";
        let (s, d) = parse_push(line).unwrap();
        assert_eq!(
            s,
            vec![
                "10.8.0.1".parse::<IpAddr>().unwrap(),
                "1.1.1.1".parse().unwrap()
            ]
        );
        assert_eq!(d, vec!["corp.example"]);
    }

    #[test]
    fn parses_dns_options() {
        let line = "PUSH_REPLY,dns server 0 address 10.8.0.1 [fd00::1]:53,dns search-domains a.example b.example,peer-id 0";
        let (s, d) = parse_push(line).unwrap();
        assert_eq!(
            s,
            vec![
                "10.8.0.1".parse::<IpAddr>().unwrap(),
                "fd00::1".parse().unwrap()
            ]
        );
        assert_eq!(d, vec!["a.example", "b.example"]);
    }

    #[test]
    fn ignores_other_lines() {
        assert!(parse_push("Initialization Sequence Completed").is_none());
        assert!(
            parse_push("PUSH_REPLY,route 10.0.0.0")
                .unwrap()
                .0
                .is_empty()
        );
    }
}
