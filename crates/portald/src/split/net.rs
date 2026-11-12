//! Kernel side of split tunneling: an nftables table that marks split
//! traffic, NAT so marked packets carry the right source address, and
//! policy routing that sends marked packets around (exclude) or into
//! (include) the tunnel.
//!
//! Exclude mode: OpenVPN routes everything into the tunnel as usual.
//! Marked packets look up `main` with prefixes of length 0 and 1 hidden
//! (so OpenVPN's `0/1` + `128/1` and the default route don't apply, but LAN
//! routes do), then a table whose default route is the physical gateway.
//!
//! Include mode: OpenVPN installs no routes; marked packets look up `main`
//! without its default route, then a table whose default route is the
//! tunnel.

use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use portal_core::SplitMode;
use serde::Deserialize;

pub const TABLE: &str = "portalsplit";
/// Packet mark for "goes outside the tunnel" (exclude mode).
pub const MARK_DIRECT: u32 = 0x5470;
/// Packet mark for "goes through the tunnel" (include mode).
pub const MARK_TUNNEL: u32 = 0x5471;
const RT_TABLE_DIRECT: u32 = 5470;
const RT_TABLE_TUNNEL: u32 = 5471;
const RULE_PRIORITY: u32 = 5470;

pub fn mark(mode: SplitMode) -> u32 {
    match mode {
        SplitMode::Exclude => MARK_DIRECT,
        SplitMode::Include => MARK_TUNNEL,
    }
}

/// What the nft table needs to know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableSpec {
    pub mode: SplitMode,
    pub iface: String,
    /// cgroup (relative to /sys/fs/cgroup) whose processes are split.
    pub app_cgroup: Option<String>,
    /// The daemon's own cgroup, whose traffic (OpenVPN!) is never touched.
    pub daemon_cgroup: Option<String>,
    pub static_v4: Vec<String>,
    pub static_v6: Vec<String>,
}

fn cgroup_match(path: &str) -> String {
    let level = path.split('/').filter(|s| !s.is_empty()).count();
    format!("socket cgroupv2 level {level} \"{path}\"")
}

fn set_decl(name: &str, ty: &str, flags: &str, elements: &[String]) -> String {
    let mut s = format!("  set {name} {{\n    type {ty}\n    flags {flags}\n");
    if flags.contains("interval") {
        s.push_str("    auto-merge\n");
    }
    if !elements.is_empty() {
        s.push_str(&format!("    elements = {{ {} }}\n", elements.join(", ")));
    }
    s.push_str("  }\n");
    s
}

/// Full table, replacing any previous one.
pub fn table_script(spec: &TableSpec) -> String {
    let m = format!("{:#x}", mark(spec.mode));
    let iface = &spec.iface;
    let mut s =
        format!("table inet {TABLE} {{}}\ndelete table inet {TABLE}\ntable inet {TABLE} {{\n");
    s.push_str(&set_decl(
        "static4",
        "ipv4_addr",
        "interval",
        &spec.static_v4,
    ));
    s.push_str(&set_decl(
        "static6",
        "ipv6_addr",
        "interval",
        &spec.static_v6,
    ));
    s.push_str(&set_decl("dyn4", "ipv4_addr", "timeout", &[]));
    s.push_str(&set_decl("dyn6", "ipv6_addr", "timeout", &[]));

    let mut route = vec![
        // Sockets that chose a side themselves (our DNS proxy) keep it.
        "meta mark != 0 return".to_string(),
        "ip daddr 127.0.0.0/8 return".into(),
        "ip6 daddr ::1 return".into(),
    ];
    if let Some(cg) = &spec.daemon_cgroup {
        route.push(format!("{} return", cgroup_match(cg)));
    }
    // A flow stays on the side it started on, even after a DNS entry expires.
    route.push(format!("ct mark {m} meta mark set {m} return"));
    let set_mark = format!("meta mark set {m} ct mark set {m}");
    if let Some(cg) = &spec.app_cgroup {
        route.push(format!("{} {set_mark}", cgroup_match(cg)));
    }
    for (proto, set) in [
        ("ip", "static4"),
        ("ip", "dyn4"),
        ("ip6", "static6"),
        ("ip6", "dyn6"),
    ] {
        route.push(format!("{proto} daddr @{set} {set_mark}"));
    }

    s.push_str("  chain route_out {\n    type route hook output priority mangle; policy accept;\n");
    for r in route {
        s.push_str(&format!("    {r}\n"));
    }
    s.push_str("  }\n");

    // Sockets pick their source address before we mark them, so rewrite it
    // for the interface the packet really leaves on.
    let nat = match spec.mode {
        SplitMode::Exclude => format!("meta mark {m} oifname != \"{iface}\" masquerade"),
        SplitMode::Include => format!("meta mark {m} oifname \"{iface}\" masquerade"),
    };
    s.push_str(&format!(
        "  chain nat_out {{\n    type nat hook postrouting priority srcnat; policy accept;\n    {nat}\n  }}\n}}\n"
    ));
    s
}

/// Replace just the static sets (rules changed while connected). Dynamic
/// DNS entries stay; those of removed domains go through `forget_dynamic`.
pub fn static_sets_script(v4: &[String], v6: &[String]) -> String {
    let mut s = format!("flush set inet {TABLE} static4\nflush set inet {TABLE} static6\n");
    if !v4.is_empty() {
        s.push_str(&format!(
            "add element inet {TABLE} static4 {{ {} }}\n",
            v4.join(", ")
        ));
    }
    if !v6.is_empty() {
        s.push_str(&format!(
            "add element inet {TABLE} static6 {{ {} }}\n",
            v6.join(", ")
        ));
    }
    s
}

/// Add resolved addresses with a lifetime.
pub fn dynamic_script(entries: &[(IpAddr, u32)]) -> String {
    let fmt = |v6: bool| -> Vec<String> {
        entries
            .iter()
            .filter(|(ip, _)| ip.is_ipv6() == v6)
            .map(|(ip, secs)| format!("{ip} timeout {secs}s"))
            .collect()
    };
    let mut s = String::new();
    for (set, v6) in [("dyn4", false), ("dyn6", true)] {
        let els = fmt(v6);
        if !els.is_empty() {
            s.push_str(&format!(
                "add element inet {TABLE} {set} {{ {} }}\n",
                els.join(", ")
            ));
        }
    }
    s
}

/// Remove addresses learned for domains that are no longer split.
pub fn forget_script(ips: &[IpAddr]) -> String {
    let mut s = String::new();
    for (set, v6) in [("dyn4", false), ("dyn6", true)] {
        let els: Vec<String> = ips
            .iter()
            .filter(|ip| ip.is_ipv6() == v6)
            .map(IpAddr::to_string)
            .collect();
        if !els.is_empty() {
            s.push_str(&format!(
                "delete element inet {TABLE} {set} {{ {} }}\n",
                els.join(", ")
            ));
        }
    }
    s
}

/// `forget_script`, tolerating addresses whose timeout already ran out in
/// the kernel (deleting a missing element fails the whole batch).
pub fn forget_dynamic(ips: &[IpAddr]) {
    if ips.is_empty() || run_nft(&forget_script(ips)).is_ok() {
        return;
    }
    for ip in ips {
        let _ = run_nft(&forget_script(std::slice::from_ref(ip)));
    }
}

pub fn delete_table_script() -> String {
    format!("table inet {TABLE} {{}}\ndelete table inet {TABLE}\n")
}

pub fn run_nft(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("running nft")?;
    child
        .stdin
        .take()
        .context("nft stdin")?
        .write_all(script.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("nft: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

pub async fn run_nft_async(script: String) -> Result<()> {
    tokio::task::spawn_blocking(move || run_nft(&script)).await?
}

// ---------------------------------------------------------------- routing --

fn ip(args: &[&str]) -> Result<String> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .context("running ip")?;
    if !out.status.success() {
        bail!(
            "ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[derive(Deserialize)]
struct AddrJson {
    #[serde(default)]
    addr_info: Vec<AddrInfo>,
}

#[derive(Deserialize)]
struct AddrInfo {
    #[serde(default)]
    local: Option<String>,
}

/// Addresses assigned to an interface.
pub fn iface_addrs(iface: &str) -> Result<std::collections::HashSet<IpAddr>> {
    let links: Vec<AddrJson> = serde_json::from_str(&ip(&["-j", "addr", "show", "dev", iface])?)?;
    Ok(links
        .iter()
        .flat_map(|l| &l.addr_info)
        .filter_map(|a| a.local.as_deref()?.parse().ok())
        .collect())
}

#[derive(Deserialize)]
struct RouteJson {
    #[serde(default)]
    gateway: Option<String>,
    #[serde(default)]
    dev: Option<String>,
}

/// The physical path to `dest`, as the kernel sees it right now.
fn route_to(family: &str, dest: &str) -> Option<(Option<String>, String)> {
    let out = ip(&[family, "-j", "route", "get", dest]).ok()?;
    let routes: Vec<RouteJson> = serde_json::from_str(&out).ok()?;
    let r = routes.into_iter().next()?;
    Some((r.gateway, r.dev?))
}

/// The default route of `main` that doesn't use the tunnel, if any.
fn physical_default(family: &str, tunnel: &str) -> Option<(Option<String>, String)> {
    let out = ip(&[family, "-j", "route", "show", "default"]).ok()?;
    let routes: Vec<RouteJson> = serde_json::from_str(&out).ok()?;
    routes
        .into_iter()
        .filter_map(|r| Some((r.gateway, r.dev?)))
        .find(|(_, dev)| dev != tunnel)
}

fn set_default(family: &str, table: u32, via: &Option<String>, dev: &str) -> Result<()> {
    let t = table.to_string();
    let mut args = vec![family, "route", "replace", "default"];
    if let Some(gw) = via {
        args.extend(["via", gw.as_str()]);
    }
    args.extend(["dev", dev, "table", t.as_str()]);
    ip(&args).map(|_| ())
}

fn add_rules(family: &str, mark: u32, suppress: u8, table: u32) -> Result<()> {
    let m = format!("{mark:#x}");
    let p1 = RULE_PRIORITY.to_string();
    let p2 = (RULE_PRIORITY + 1).to_string();
    let sup = suppress.to_string();
    let t = table.to_string();
    ip(&[
        family,
        "rule",
        "add",
        "priority",
        &p1,
        "fwmark",
        &m,
        "lookup",
        "main",
        "suppress_prefixlength",
        &sup,
    ])?;
    ip(&[
        family, "rule", "add", "priority", &p2, "fwmark", &m, "lookup", &t,
    ])?;
    Ok(())
}

/// Remove our rules and tables (both modes, both families). Errors are
/// expected when something isn't there.
pub fn clear_routing() {
    for family in ["-4", "-6"] {
        for prio in [RULE_PRIORITY, RULE_PRIORITY + 1] {
            let p = prio.to_string();
            while ip(&[family, "rule", "del", "priority", &p]).is_ok() {}
        }
        for table in [RT_TABLE_DIRECT, RT_TABLE_TUNNEL] {
            let _ = ip(&[family, "route", "flush", "table", &table.to_string()]);
        }
    }
}

/// Install routing for `mode`. `server` is the VPN server's address, whose
/// route OpenVPN pins to the physical gateway.
pub fn setup_routing(mode: SplitMode, iface: &str, server: Option<&str>) -> Result<()> {
    clear_routing();
    // Let marked packets pass reverse-path checks with their real source.
    let _ = std::fs::write("/proc/sys/net/ipv4/conf/all/src_valid_mark", "1");
    match mode {
        SplitMode::Exclude => {
            let v4 = server
                .and_then(|s| route_to("-4", s))
                .filter(|(_, dev)| dev != iface)
                .or_else(|| physical_default("-4", iface))
                .context("couldn't find the physical network's gateway")?;
            set_default("-4", RT_TABLE_DIRECT, &v4.0, &v4.1)?;
            add_rules("-4", MARK_DIRECT, 1, RT_TABLE_DIRECT)?;
            if let Some(v6) = physical_default("-6", iface) {
                set_default("-6", RT_TABLE_DIRECT, &v6.0, &v6.1)?;
                add_rules("-6", MARK_DIRECT, 1, RT_TABLE_DIRECT)?;
            }
        }
        SplitMode::Include => {
            set_default("-4", RT_TABLE_TUNNEL, &None, iface)?;
            add_rules("-4", MARK_TUNNEL, 0, RT_TABLE_TUNNEL)?;
            if set_default("-6", RT_TABLE_TUNNEL, &None, iface).is_ok() {
                add_rules("-6", MARK_TUNNEL, 0, RT_TABLE_TUNNEL)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(mode: SplitMode) -> TableSpec {
        TableSpec {
            mode,
            iface: "portal0".into(),
            app_cgroup: Some("portal-split".into()),
            daemon_cgroup: Some("system.slice/portald.service".into()),
            static_v4: vec!["5.0.0.0/8".into(), "1.2.3.4".into()],
            static_v6: vec![],
        }
    }

    #[test]
    fn exclude_table() {
        let s = table_script(&spec(SplitMode::Exclude));
        assert!(s.contains("elements = { 5.0.0.0/8, 1.2.3.4 }"));
        assert!(s.contains(
            "socket cgroupv2 level 1 \"portal-split\" meta mark set 0x5470 ct mark set 0x5470"
        ));
        assert!(s.contains("socket cgroupv2 level 2 \"system.slice/portald.service\" return"));
        assert!(s.contains("ip daddr @dyn4 meta mark set 0x5470"));
        assert!(s.contains("meta mark 0x5470 oifname != \"portal0\" masquerade"));
        let daemon = s.find("portald.service").unwrap();
        let apps = s.find("portal-split\" meta mark").unwrap();
        assert!(daemon < apps, "the daemon (and OpenVPN) is never split");
    }

    #[test]
    fn include_table() {
        let s = table_script(&spec(SplitMode::Include));
        assert!(s.contains("meta mark 0x5471 oifname \"portal0\" masquerade"));
    }

    #[test]
    fn set_updates() {
        let s = static_sets_script(&["10.0.0.0/8".into()], &[]);
        assert_eq!(
            s,
            "flush set inet portalsplit static4\nflush set inet portalsplit static6\nadd element inet portalsplit static4 { 10.0.0.0/8 }\n"
        );
        let d = dynamic_script(&[
            ("1.2.3.4".parse().unwrap(), 300),
            ("::1".parse().unwrap(), 60),
        ]);
        assert!(d.contains("add element inet portalsplit dyn4 { 1.2.3.4 timeout 300s }"));
        assert!(d.contains("add element inet portalsplit dyn6 { ::1 timeout 60s }"));
    }

    #[test]
    fn forget_script_by_family() {
        let f = forget_script(&[
            "1.2.3.4".parse().unwrap(),
            "5.6.7.8".parse().unwrap(),
            "::1".parse().unwrap(),
        ]);
        assert!(f.contains("delete element inet portalsplit dyn4 { 1.2.3.4, 5.6.7.8 }"));
        assert!(f.contains("delete element inet portalsplit dyn6 { ::1 }"));
        assert!(forget_script(&[]).is_empty());
    }

    fn sh(cmd: &str) -> String {
        let out = Command::new("sh").args(["-c", cmd]).output().unwrap();
        assert!(
            out.status.success(),
            "{cmd}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn tx(dev: &str) -> u64 {
        let out = sh(&format!("ip -s -j link show dev {dev}"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        v[0]["stats64"]["tx"]["packets"].as_u64().unwrap()
    }

    /// Send a UDP packet and report which interface it left on.
    fn leaves_via(dest: &str) -> &'static str {
        let (e, t) = (tx("eth0"), tx("portal0"));
        let sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let _ = sock.send_to(b"x", (dest, 9));
        match (tx("eth0") > e, tx("portal0") > t) {
            (true, false) => "eth0",
            (false, true) => "portal0",
            other => panic!("{dest}: unexpected {other:?}"),
        }
    }

    /// Fake network: eth0 is the physical link with a LAN and a gateway,
    /// portal0 is the VPN.
    fn fake_network(def1: bool) {
        // Tests share the namespace when run one after another.
        let _ = Command::new("sh")
            .args(["-c", "ip link del eth0; ip link del portal0"])
            .output();
        clear_routing();
        let _ = run_nft(&delete_table_script());
        sh("ip link set lo up
            ip link add eth0 type dummy && ip addr add 192.168.1.50/24 dev eth0 && ip link set eth0 up
            ip route add default via 192.168.1.1 dev eth0
            ip link add portal0 type dummy && ip addr add 10.8.0.6/24 dev portal0 && ip link set portal0 up
            ip neigh add 192.168.1.1 lladdr 02:00:00:00:00:01 dev eth0");
        if def1 {
            sh(
                "ip route add 0.0.0.0/1 dev portal0 && ip route add 128.0.0.0/1 dev portal0
                ip route add 203.0.113.1/32 via 192.168.1.1 dev eth0",
            );
        }
    }

    /// Real routing and nftables in a throwaway network namespace. Needs
    /// root there: `unshare -rn cargo test -p portald -- --ignored --test-threads=1 netns`.
    #[test]
    #[ignore]
    fn netns_exclude_mode_routes_split_traffic_outside() {
        fake_network(true);
        let spec = TableSpec {
            daemon_cgroup: None,
            app_cgroup: None,
            ..spec(SplitMode::Exclude)
        };
        run_nft(&table_script(&spec)).unwrap();
        setup_routing(SplitMode::Exclude, "portal0", Some("203.0.113.1")).unwrap();

        assert_eq!(
            leaves_via("8.8.8.8"),
            "portal0",
            "normal traffic uses the VPN"
        );
        assert_eq!(
            leaves_via("5.1.2.3"),
            "eth0",
            "listed network goes around it"
        );
        assert_eq!(
            leaves_via("1.2.3.4"),
            "eth0",
            "listed address goes around it"
        );
        run_nft(&dynamic_script(&[("9.9.9.9".parse().unwrap(), 60)])).unwrap();
        assert_eq!(
            leaves_via("9.9.9.9"),
            "eth0",
            "addresses from split DNS go around it"
        );
        // 7.7.7.7 was never added: the batch fails and each is retried alone.
        forget_dynamic(&["9.9.9.9".parse().unwrap(), "7.7.7.7".parse().unwrap()]);
        assert_eq!(
            leaves_via("9.9.9.9"),
            "portal0",
            "addresses of removed domains go back into the tunnel"
        );
        run_nft(&static_sets_script(&[], &[])).unwrap();
        assert_eq!(leaves_via("5.1.2.3"), "portal0", "rule changes apply live");
        assert!(sh("nft list table inet portalsplit").contains("masquerade"));

        clear_routing();
        run_nft(&delete_table_script()).unwrap();
        assert_eq!(leaves_via("9.9.9.9"), "portal0");
    }

    #[test]
    #[ignore]
    fn netns_include_mode_routes_only_split_traffic_inside() {
        fake_network(false);
        let spec = TableSpec {
            daemon_cgroup: None,
            app_cgroup: None,
            ..spec(SplitMode::Include)
        };
        run_nft(&table_script(&spec)).unwrap();
        setup_routing(SplitMode::Include, "portal0", None).unwrap();

        assert_eq!(
            leaves_via("8.8.8.8"),
            "eth0",
            "normal traffic stays outside"
        );
        assert_eq!(
            leaves_via("5.1.2.3"),
            "portal0",
            "listed network uses the VPN"
        );
        assert_eq!(leaves_via("192.168.1.9"), "eth0", "the LAN stays local");
        clear_routing();
    }

    /// A lookup for a split domain through the DNS proxy puts its address
    /// in the nft set, so the very next packet goes around the tunnel.
    #[tokio::test]
    #[ignore]
    async fn netns_split_dns_routes_looked_up_names_outside() {
        use super::super::dnsmsg::tests::{answer, query};
        use super::super::dnsproxy::{Proxy, ProxyConfig, Sink};
        use portal_core::split::{DomainList, Rule};

        fake_network(true);
        let spec = TableSpec {
            daemon_cgroup: None,
            app_cgroup: None,
            static_v4: vec![],
            ..spec(SplitMode::Exclude)
        };
        run_nft(&table_script(&spec)).unwrap();
        setup_routing(SplitMode::Exclude, "portal0", Some("203.0.113.1")).unwrap();

        let up = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = up.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 512];
            loop {
                let (n, from) = up.recv_from(&mut buf).await.unwrap();
                let ip = if super::super::dnsmsg::question_name(&buf[..n])
                    .unwrap()
                    .ends_with(".ir")
                {
                    [2, 144, 1, 1]
                } else {
                    [8, 8, 4, 4]
                };
                up.send_to(&answer(&buf[..n], &[ip], 60), from)
                    .await
                    .unwrap();
            }
        });
        let cfg = ProxyConfig {
            mode: SplitMode::Exclude,
            domains: DomainList::new(&[Rule::parse("*.ir").unwrap()]),
            vpn: vec!["127.0.0.1".parse().unwrap()],
            direct: vec![],
            upstream_port: port,
        };
        let proxy = Proxy::start("127.0.0.153:0", cfg, Sink::Nft).unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(proxy.addr).await.unwrap();
        let mut buf = vec![0u8; 512];

        assert_eq!(leaves_via("2.144.1.1"), "portal0", "before the lookup");
        client.send(&query(1, "www.snapp.ir")).await.unwrap();
        client.recv(&mut buf).await.unwrap();
        assert_eq!(leaves_via("2.144.1.1"), "eth0", "right after the lookup");
        assert!(sh("nft list set inet portalsplit dyn4").contains("2.144.1.1"));

        client.send(&query(2, "www.google.com")).await.unwrap();
        client.recv(&mut buf).await.unwrap();
        assert_eq!(
            leaves_via("8.8.4.4"),
            "portal0",
            "other names stay in the tunnel"
        );
        proxy.stop();
        clear_routing();
    }
}
