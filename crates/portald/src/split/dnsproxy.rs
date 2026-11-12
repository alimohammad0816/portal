//! Small DNS forwarder for split tunneling. systemd-resolved sends the
//! tunnel's lookups here; queries for split domains go to the resolver on
//! the side the traffic will use (so CDNs answer with nearby addresses),
//! and the answers' addresses are added to the nft sets before the reply
//! goes back, so the first connection is already routed right.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use portal_core::SplitMode;
use portal_core::split::DomainList;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use super::dnsmsg;
use super::net::{self, MARK_DIRECT, MARK_TUNNEL};

/// Where resolved sends the tunnel's lookups.
pub const LISTEN: &str = "127.0.0.153:53";
const TIMEOUT: Duration = Duration::from_secs(3);
/// Keep split addresses at least this long, however short the TTL: apps
/// cache answers longer than they're told to.
const MIN_TTL: u32 = 300;
const MAX_TTL: u32 = 6 * 3600;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub mode: SplitMode,
    pub domains: DomainList,
    /// Resolvers on the VPN side (pushed or custom).
    pub vpn: Vec<IpAddr>,
    /// The physical network's resolvers.
    pub direct: Vec<IpAddr>,
    pub upstream_port: u16,
}

pub type SharedConfig = Arc<RwLock<ProxyConfig>>;

/// Where answers for split domains are recorded.
#[derive(Clone)]
pub enum Sink {
    Nft,
    #[cfg(test)]
    Test(tokio::sync::mpsc::UnboundedSender<Vec<(IpAddr, u32)>>),
}

impl Sink {
    async fn add(&self, entries: Vec<(IpAddr, u32)>) {
        match self {
            Sink::Nft => {
                if let Err(e) = net::run_nft_async(net::dynamic_script(&entries)).await {
                    warn!("adding split addresses: {e:#}");
                }
            }
            #[cfg(test)]
            Sink::Test(tx) => {
                let _ = tx.send(entries);
            }
        }
    }
}

/// How many recent answers to keep for names that aren't split (yet).
const RECENT_MAX: usize = 4096;

/// What the proxy remembers about answers.
#[derive(Debug, Default)]
pub struct Learned {
    /// Which split names each address in the nft sets was learned for, and
    /// until when, so a domain's addresses can leave the sets as soon as
    /// its rule is removed instead of when their timeout runs out.
    split: HashMap<IpAddr, HashMap<String, Instant>>,
    /// Recent answers for every name. Apps keep using addresses they looked
    /// up before a domain was listed; this is where those are found.
    /// (resolved doesn't cache answers from this proxy: it's on localhost.)
    recent: HashMap<String, (Vec<IpAddr>, Instant)>,
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

impl Learned {
    fn remember(&mut self, name: &str, entries: &[(IpAddr, u32)], now: Instant) {
        let secs = entries.iter().map(|(_, s)| *s).max().unwrap_or(MIN_TTL);
        let until = now + Duration::from_secs(u64::from(secs));
        if self.recent.len() >= RECENT_MAX {
            self.recent.retain(|_, (_, u)| *u > now);
            if self.recent.len() >= RECENT_MAX
                && let Some(oldest) = self
                    .recent
                    .iter()
                    .min_by_key(|(_, (_, u))| *u)
                    .map(|(n, _)| n.clone())
            {
                self.recent.remove(&oldest);
            }
        }
        let ips = entries.iter().map(|(ip, _)| *ip).collect();
        self.recent.insert(normalize(name), (ips, until));
    }

    /// Recently answered addresses of names `domains` matches, with the
    /// seconds they stay valid.
    fn recent_matching(&self, domains: &DomainList, now: Instant) -> Vec<(String, IpAddr, u32)> {
        self.recent
            .iter()
            .filter(|(n, (_, until))| *until > now && domains.matches(n))
            .flat_map(|(n, (ips, until))| {
                let left = u32::try_from((*until - now).as_secs()).unwrap_or(MAX_TTL);
                ips.iter()
                    .map(move |ip| (n.clone(), *ip, left.max(MIN_TTL)))
            })
            .collect()
    }

    fn add(&mut self, name: &str, entries: &[(IpAddr, u32)], now: Instant) {
        let name = normalize(name);
        for (ip, secs) in entries {
            let until = now + Duration::from_secs(u64::from(*secs));
            let slot = self
                .split
                .entry(*ip)
                .or_default()
                .entry(name.clone())
                .or_insert(until);
            *slot = (*slot).max(until);
        }
    }

    /// Live addresses learned for any name `domains` matches.
    fn matching(&self, domains: &DomainList, now: Instant) -> Vec<IpAddr> {
        self.split
            .iter()
            .filter(|(_, names)| {
                names
                    .iter()
                    .any(|(n, until)| *until > now && domains.matches(n))
            })
            .map(|(ip, _)| *ip)
            .collect()
    }

    /// Forget names that `domains` no longer lists and return the addresses
    /// that are left without any, which should leave the nft sets now.
    /// Addresses whose entries already timed out are dropped silently.
    fn prune(&mut self, domains: &DomainList, now: Instant) -> Vec<IpAddr> {
        let mut gone = Vec::new();
        self.split.retain(|ip, names| {
            names.retain(|_, until| *until > now);
            if names.is_empty() {
                return false;
            }
            names.retain(|name, _| domains.matches(name));
            if names.is_empty() {
                gone.push(*ip);
                return false;
            }
            true
        });
        gone
    }
}

struct Route {
    upstreams: Vec<IpAddr>,
    mark: u32,
    record: bool,
}

fn route_for(cfg: &ProxyConfig, name: Option<&str>) -> Route {
    let mut r = route_for_inner(cfg, name);
    if r.upstreams.is_empty() {
        // The server pushed no resolvers: fall back to the physical network's.
        r.upstreams = cfg.direct.clone();
        r.mark = if cfg.mode == SplitMode::Exclude {
            MARK_DIRECT
        } else {
            0
        };
    }
    r
}

fn route_for_inner(cfg: &ProxyConfig, name: Option<&str>) -> Route {
    let listed = name.is_some_and(|n| cfg.domains.matches(n));
    match (cfg.mode, listed) {
        (SplitMode::Exclude, true) if !cfg.direct.is_empty() => Route {
            upstreams: cfg.direct.clone(),
            mark: MARK_DIRECT,
            record: true,
        },
        (SplitMode::Exclude, true) => Route {
            upstreams: cfg.vpn.clone(),
            mark: 0,
            record: true,
        },
        (SplitMode::Exclude, false) => Route {
            upstreams: cfg.vpn.clone(),
            mark: 0,
            record: false,
        },
        (SplitMode::Include, true) => Route {
            upstreams: cfg.vpn.clone(),
            mark: MARK_TUNNEL,
            record: true,
        },
        (SplitMode::Include, false) if !cfg.direct.is_empty() => Route {
            upstreams: cfg.direct.clone(),
            mark: 0,
            record: false,
        },
        (SplitMode::Include, false) => Route {
            upstreams: cfg.vpn.clone(),
            mark: 0,
            record: false,
        },
    }
}

fn socket(kind: Type, proto: Protocol, target: &SocketAddr, mark: u32) -> Result<Socket> {
    let s = Socket::new(Domain::for_address(*target), kind, Some(proto))?;
    if mark != 0 {
        s.set_mark(mark).context("setting SO_MARK")?;
    }
    s.set_nonblocking(true)?;
    Ok(s)
}

async fn ask_udp(query: &[u8], target: SocketAddr, mark: u32) -> Result<Vec<u8>> {
    let s = socket(Type::DGRAM, Protocol::UDP, &target, mark)?;
    let sock = UdpSocket::from_std(s.into())?;
    sock.connect(target).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = tokio::time::timeout(TIMEOUT, sock.recv(&mut buf)).await??;
        if n >= 2 && buf[..2] == query[..2] {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

async fn ask_tcp(query: &[u8], target: SocketAddr, mark: u32) -> Result<Vec<u8>> {
    let s = socket(Type::STREAM, Protocol::TCP, &target, mark)?;
    match s.connect(&target.into()) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc_einprogress()) => {}
        Err(e) => return Err(e.into()),
    }
    let mut stream = TcpStream::from_std(std::net::TcpStream::from(s))?;
    tokio::time::timeout(TIMEOUT, stream.writable()).await??;
    if let Some(e) = stream.take_error()? {
        return Err(e.into());
    }
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(query).await?;
    let len = tokio::time::timeout(TIMEOUT, stream.read_u16()).await?? as usize;
    let mut buf = vec![0u8; len];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut buf)).await??;
    Ok(buf)
}

const fn libc_einprogress() -> i32 {
    115
}

/// Forward one query and record split answers. Always produces a reply.
async fn resolve(
    query: &[u8],
    tcp: bool,
    cfg: &SharedConfig,
    learned: &Mutex<Learned>,
    sink: &Sink,
) -> Option<Vec<u8>> {
    let name = dnsmsg::question_name(query);
    let (route, port) = {
        let c = cfg.read().ok()?;
        (route_for(&c, name.as_deref()), c.upstream_port)
    };
    for up in &route.upstreams {
        let target = SocketAddr::new(*up, port);
        let reply = if tcp {
            ask_tcp(query, target, route.mark).await
        } else {
            ask_udp(query, target, route.mark).await
        };
        match reply {
            Ok(r) => {
                let addrs: Vec<(IpAddr, u32)> = dnsmsg::answer_addresses(&r)
                    .into_iter()
                    .map(|(ip, ttl)| (ip, ttl.clamp(MIN_TTL, MAX_TTL)))
                    .collect();
                if let (Some(n), false) = (&name, addrs.is_empty())
                    && let Ok(mut l) = learned.lock()
                {
                    let now = Instant::now();
                    l.remember(n, &addrs, now);
                    if route.record {
                        l.add(n, &addrs, now);
                    }
                }
                if route.record && !addrs.is_empty() {
                    debug!("split {:?}: {addrs:?}", name);
                    sink.add(addrs).await;
                }
                return Some(r);
            }
            Err(e) => debug!("{target} for {name:?}: {e:#}"),
        }
    }
    dnsmsg::servfail(query)
}

pub struct Proxy {
    pub config: SharedConfig,
    learned: Arc<Mutex<Learned>>,
    tasks: Vec<JoinHandle<()>>,
    pub addr: SocketAddr,
}

impl Proxy {
    /// Bind and start serving. Must run inside the tokio runtime.
    pub fn start(listen: &str, config: ProxyConfig, sink: Sink) -> Result<Proxy> {
        let addr: SocketAddr = listen.parse()?;
        let std_udp =
            std::net::UdpSocket::bind(addr).with_context(|| format!("binding {addr}/udp"))?;
        std_udp.set_nonblocking(true)?;
        let addr = std_udp.local_addr()?;
        let std_tcp =
            std::net::TcpListener::bind(addr).with_context(|| format!("binding {addr}/tcp"))?;
        std_tcp.set_nonblocking(true)?;
        let udp = Arc::new(UdpSocket::from_std(std_udp)?);
        let tcp = TcpListener::from_std(std_tcp)?;
        let config = Arc::new(RwLock::new(config));
        let learned = Arc::new(Mutex::new(Learned::default()));

        let (cfg, l, s) = (config.clone(), learned.clone(), sink.clone());
        let udp_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                    continue;
                };
                if n < 12 {
                    continue;
                }
                let query = buf[..n].to_vec();
                let (udp, cfg, l, s) = (udp.clone(), cfg.clone(), l.clone(), s.clone());
                tokio::spawn(async move {
                    if let Some(r) = resolve(&query, false, &cfg, &l, &s).await {
                        let _ = udp.send_to(&r, from).await;
                    }
                });
            }
        });

        let (cfg, l, s) = (config.clone(), learned.clone(), sink);
        let tcp_task = tokio::spawn(async move {
            loop {
                let Ok((mut conn, _)) = tcp.accept().await else {
                    continue;
                };
                let (cfg, l, s) = (cfg.clone(), l.clone(), s.clone());
                tokio::spawn(async move {
                    while let Ok(Ok(len)) =
                        tokio::time::timeout(Duration::from_secs(10), conn.read_u16()).await
                    {
                        let mut q = vec![0u8; len as usize];
                        if conn.read_exact(&mut q).await.is_err() || q.len() < 12 {
                            break;
                        }
                        let Some(r) = resolve(&q, true, &cfg, &l, &s).await else {
                            break;
                        };
                        if conn
                            .write_all(&(r.len() as u16).to_be_bytes())
                            .await
                            .is_err()
                            || conn.write_all(&r).await.is_err()
                        {
                            break;
                        }
                    }
                });
            }
        });

        Ok(Proxy {
            config,
            learned,
            tasks: vec![udp_task, tcp_task],
            addr,
        })
    }

    pub fn update(&self, f: impl FnOnce(&mut ProxyConfig)) {
        if let Ok(mut c) = self.config.write() {
            f(&mut c);
        }
    }

    /// Change the split domains. Returns the addresses learned only for
    /// domains that are no longer listed; the caller removes them from the
    /// nft sets so those sites stop being split right away.
    pub fn set_domains(&self, domains: DomainList) -> Vec<IpAddr> {
        let gone = match self.learned.lock() {
            Ok(mut l) => l.prune(&domains, Instant::now()),
            Err(_) => Vec::new(),
        };
        self.update(|c| c.domains = domains);
        gone
    }

    /// Split the addresses apps already looked up for `domains` before they
    /// were listed, as if they had just been asked. Returns the entries for
    /// the nft sets.
    pub fn seed(&self, domains: &DomainList) -> Vec<(IpAddr, u32)> {
        let Ok(c) = self.config.read() else {
            return Vec::new();
        };
        let now = Instant::now();
        let mut out = Vec::new();
        if let Ok(mut l) = self.learned.lock() {
            for (name, ip, secs) in l.recent_matching(domains, now) {
                if c.domains.matches(&name) {
                    l.add(&name, &[(ip, secs)], now);
                    out.push((ip, secs));
                }
            }
        }
        out
    }

    /// Addresses currently split because of a name `domains` matches.
    pub fn learned_for(&self, domains: &DomainList) -> Vec<IpAddr> {
        self.learned
            .lock()
            .map(|l| l.matching(domains, Instant::now()))
            .unwrap_or_default()
    }

    pub fn stop(self) {
        for t in self.tasks {
            t.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::dnsmsg::tests::{answer, query};
    use super::*;
    use portal_core::split::Rule;
    use tokio::sync::mpsc;

    /// A fake upstream that answers every query with `addr`.
    async fn upstream(addr: [u8; 4]) -> (u16, JoinHandle<()>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        let t = tokio::spawn(async move {
            let mut buf = vec![0u8; 512];
            loop {
                let (n, from) = sock.recv_from(&mut buf).await.unwrap();
                let r = answer(&buf[..n], &[addr], 30);
                sock.send_to(&r, from).await.unwrap();
            }
        });
        (port, t)
    }

    #[tokio::test]
    async fn records_only_split_domains() {
        let (port, _up) = upstream([93, 184, 216, 34]).await;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let rules = [Rule::parse("*.ir").unwrap()];
        let cfg = ProxyConfig {
            mode: SplitMode::Exclude,
            domains: DomainList::new(&rules),
            // Both sides point at the fake upstream; marks need root, so
            // the direct side is left empty here.
            vpn: vec!["127.0.0.1".parse().unwrap()],
            direct: vec![],
            upstream_port: port,
        };
        let proxy = Proxy::start("127.0.0.1:0", cfg, Sink::Test(tx)).unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(proxy.addr).await.unwrap();

        let mut buf = vec![0u8; 512];
        client.send(&query(1, "www.snapp.ir")).await.unwrap();
        let n = client.recv(&mut buf).await.unwrap();
        assert_eq!(
            dnsmsg::answer_addresses(&buf[..n])[0].0,
            "93.184.216.34".parse::<IpAddr>().unwrap()
        );
        let recorded = rx.recv().await.unwrap();
        assert_eq!(recorded, vec![("93.184.216.34".parse().unwrap(), MIN_TTL)]);

        client.send(&query(2, "example.com")).await.unwrap();
        client.recv(&mut buf).await.unwrap();
        assert!(rx.try_recv().is_err(), "unlisted domains aren't recorded");
        // ...but remembered: listing example.com later splits what the app
        // already holds.
        proxy.set_domains(DomainList::new(&[
            Rule::parse("*.ir").unwrap(),
            Rule::parse("example.com").unwrap(),
        ]));
        assert_eq!(
            proxy.seed(&DomainList::new(&[Rule::parse("example.com").unwrap()])),
            vec![("93.184.216.34".parse().unwrap(), MIN_TTL)]
        );

        // Rules change live. The fake upstream gives every name the same
        // address, which example.com still claims, so it stays split...
        let gone = proxy.set_domains(DomainList::new(&[Rule::parse("example.com").unwrap()]));
        assert!(gone.is_empty());
        // ...until no listed name claims it.
        let gone = proxy.set_domains(DomainList::new(&[Rule::parse("other.org").unwrap()]));
        assert_eq!(gone, vec!["93.184.216.34".parse::<IpAddr>().unwrap()]);
        // A plain name is exact; its subdomains need the wildcard.
        proxy.set_domains(DomainList::new(&[Rule::parse("example.com").unwrap()]));
        client.send(&query(3, "a.example.com")).await.unwrap();
        client.recv(&mut buf).await.unwrap();
        assert!(rx.try_recv().is_err());
        proxy.set_domains(DomainList::new(&[Rule::parse("*.example.com").unwrap()]));
        client.send(&query(4, "a.example.com")).await.unwrap();
        client.recv(&mut buf).await.unwrap();
        assert!(rx.recv().await.is_some());
        proxy.stop();
    }

    #[tokio::test]
    async fn answers_servfail_when_upstreams_fail() {
        let cfg = ProxyConfig {
            mode: SplitMode::Exclude,
            domains: DomainList::default(),
            vpn: vec!["127.0.0.1".parse().unwrap()],
            direct: vec![],
            upstream_port: 9, // discard: nothing answers
        };
        let (tx, _rx) = mpsc::unbounded_channel();
        let proxy = Proxy::start("127.0.0.1:0", cfg, Sink::Test(tx)).unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(proxy.addr).await.unwrap();
        client.send(&query(5, "x.example")).await.unwrap();
        let mut buf = vec![0u8; 512];
        let n = tokio::time::timeout(Duration::from_secs(8), client.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(buf[3] & 0x0f, 2);
        assert_eq!(&buf[..2], &5u16.to_be_bytes());
        assert!(n > 12);
        proxy.stop();
    }

    #[test]
    fn prune_forgets_only_unlisted_names() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let list = |r: &[&str]| {
            DomainList::new(
                &r.iter()
                    .map(|r| Rule::parse(r).unwrap())
                    .collect::<Vec<_>>(),
            )
        };
        let now = Instant::now();
        let mut l = Learned::default();
        l.add("sabtira.ir.", &[(ip("46.36.99.104"), 300)], now);
        // A CDN address shared by a listed and an unlisted name.
        l.add("www.snapp.ir", &[(ip("2.144.1.1"), 300)], now);
        l.add("digikala.com", &[(ip("2.144.1.1"), 300)], now);
        // Already timed out in the kernel: nothing to delete.
        l.add("old.ir", &[(ip("5.5.5.5"), 60)], now);

        let later = now + Duration::from_secs(120);
        let mut gone = l.prune(&list(&["digikala.com"]), later);
        gone.sort();
        assert_eq!(gone, vec![ip("46.36.99.104")]);
        // digikala.com still holds the shared address.
        assert!(l.prune(&list(&["digikala.com"]), later).is_empty());
        assert_eq!(l.matching(&list(&["*.com"]), later), vec![ip("2.144.1.1")]);
        assert!(
            l.matching(&list(&["*.ir"]), later).is_empty(),
            "pruned names don't count"
        );
        assert_eq!(l.prune(&list(&[]), later), vec![ip("2.144.1.1")]);
        assert!(l.split.is_empty());
    }

    #[test]
    fn routes_by_mode() {
        let rules = [Rule::parse("*.ir").unwrap()];
        let mut cfg = ProxyConfig {
            mode: SplitMode::Exclude,
            domains: DomainList::new(&rules),
            vpn: vec!["10.8.0.1".parse().unwrap()],
            direct: vec!["192.168.1.1".parse().unwrap()],
            upstream_port: 53,
        };
        let r = route_for(&cfg, Some("snapp.ir"));
        assert_eq!(
            (r.upstreams[0].to_string(), r.mark, r.record),
            ("192.168.1.1".into(), MARK_DIRECT, true)
        );
        let r = route_for(&cfg, Some("google.com"));
        assert_eq!(
            (r.upstreams[0].to_string(), r.mark, r.record),
            ("10.8.0.1".into(), 0, false)
        );
        cfg.mode = SplitMode::Include;
        let r = route_for(&cfg, Some("snapp.ir"));
        assert_eq!(
            (r.upstreams[0].to_string(), r.mark, r.record),
            ("10.8.0.1".into(), MARK_TUNNEL, true)
        );
    }
}
