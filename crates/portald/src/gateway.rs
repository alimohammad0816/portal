//! Proxy gateway: lets other devices on your LAN (a phone, a TV, a game
//! console) use the VPN through a proxy on this computer. One port speaks
//! both SOCKS5 and HTTP (CONNECT and plain `http://` requests), since phones
//! usually only offer an HTTP proxy setting.
//!
//! It listens only on the LAN address (never on the tunnel) and only while
//! the VPN is connected. Its outgoing connections come from the daemon, so
//! they use the tunnel and pass the kill switch.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::task::JoinHandle;
use tracing::{debug, info};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HEAD: usize = 16 * 1024;

pub struct Gateway {
    pub addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Gateway {
    /// Listen on `ip:port`. `mark` is set on outgoing sockets (include
    /// mode, where only marked traffic uses the tunnel).
    pub fn start(ip: IpAddr, port: u16, mark: u32) -> Result<Gateway> {
        let std = std::net::TcpListener::bind((ip, port))
            .with_context(|| format!("binding {ip}:{port}"))?;
        std.set_nonblocking(true)?;
        let listener = TcpListener::from_std(std)?;
        let addr = listener.local_addr()?;
        info!("proxy gateway on {addr}");
        let task = tokio::spawn(async move {
            loop {
                let Ok((conn, peer)) = listener.accept().await else {
                    continue;
                };
                if !is_local(peer.ip()) {
                    debug!("gateway: refusing {peer}");
                    continue;
                }
                tokio::spawn(async move {
                    if let Err(e) = serve(conn, mark).await {
                        debug!("gateway {peer}: {e:#}");
                    }
                });
            }
        });
        Ok(Gateway { addr, task })
    }

    pub fn stop(self) {
        self.task.abort();
        info!("proxy gateway stopped");
    }
}

/// Clients we serve: the LAN and this machine.
pub fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let seg = v6.segments()[0];
            v6.is_loopback() || (seg & 0xfe00) == 0xfc00 || (seg & 0xffc0) == 0xfe80
        }
    }
}

/// This computer's address on the LAN: a private IPv4 on an interface
/// other than the tunnel.
pub fn lan_address(tunnel: &str) -> Option<IpAddr> {
    let out = std::process::Command::new("ip")
        .args(["-j", "-4", "addr", "show", "scope", "global"])
        .output()
        .ok()?;
    let ifaces: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).ok()?;
    ifaces
        .iter()
        .filter(|i| i["ifname"].as_str() != Some(tunnel))
        .flat_map(|i| i["addr_info"].as_array().cloned().unwrap_or_default())
        .filter_map(|a| a["local"].as_str()?.parse::<IpAddr>().ok())
        .find(|ip| is_local(*ip) && !ip.is_loopback())
}

/// Connect to `host`, trying each of its addresses in turn: the first one
/// may be unreachable (IPv6 blocked outside an IPv4-only tunnel, `localhost`
/// resolving to `::1` first).
async fn dial(host: &str, port: u16, mark: u32) -> Result<TcpStream> {
    let targets: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    if targets.is_empty() {
        bail!("no address for {host}");
    }
    tokio::time::timeout(CONNECT_TIMEOUT, dial_any(&targets, mark))
        .await
        .context("timed out connecting")?
}

/// The first of `targets` that accepts a connection.
async fn dial_any(targets: &[SocketAddr], mark: u32) -> Result<TcpStream> {
    let mut last = anyhow::anyhow!("no address to connect to");
    for target in targets {
        match dial_one(*target, mark).await {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

async fn dial_one(target: SocketAddr, mark: u32) -> Result<TcpStream> {
    let sock = if target.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if mark != 0 {
        socket2::SockRef::from(&sock).set_mark(mark)?;
    }
    Ok(sock.connect(target).await?)
}

async fn serve(conn: TcpStream, mark: u32) -> Result<()> {
    let mut first = [0u8; 1];
    conn.peek(&mut first).await?;
    if first[0] == 5 {
        socks5(conn, mark).await
    } else {
        http(conn, mark).await
    }
}

async fn socks5(mut c: TcpStream, mark: u32) -> Result<()> {
    let mut head = [0u8; 2];
    c.read_exact(&mut head).await?;
    let mut methods = vec![0u8; head[1] as usize];
    c.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        c.write_all(&[5, 0xff]).await?;
        bail!("client wants authentication");
    }
    c.write_all(&[5, 0]).await?;

    let mut req = [0u8; 4];
    c.read_exact(&mut req).await?;
    if req[1] != 1 {
        c.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        bail!("only CONNECT is supported");
    }
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            c.read_exact(&mut a).await?;
            IpAddr::from(a).to_string()
        }
        4 => {
            let mut a = [0u8; 16];
            c.read_exact(&mut a).await?;
            IpAddr::from(a).to_string()
        }
        3 => {
            let len = c.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            c.read_exact(&mut name).await?;
            String::from_utf8(name)?
        }
        _ => bail!("bad address type"),
    };
    let port = c.read_u16().await?;
    match dial(&host, port, mark).await {
        Ok(mut up) => {
            c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            copy_bidirectional(&mut c, &mut up).await?;
            Ok(())
        }
        Err(e) => {
            c.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            Err(e)
        }
    }
}

/// Split `host:port`, `[v6]:port` or a bare host.
fn host_port(s: &str, default: u16) -> Option<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once(']')?;
        let port = p
            .strip_prefix(':')
            .map_or(Some(default), |p| p.parse().ok())?;
        return Some((h.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Some((h.to_string(), p.parse().ok()?)),
        _ => Some((s.to_string(), default)),
    }
}

/// Request line and headers of an HTTP proxy request, rewritten for the
/// origin server. Returns (host, port, head to send, is CONNECT).
pub fn parse_http_head(head: &str) -> Option<(String, u16, String, bool)> {
    let mut lines = head.split("\r\n");
    let first = lines.next()?;
    let mut parts = first.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if method.eq_ignore_ascii_case("CONNECT") {
        let (h, p) = host_port(target, 443)?;
        return Some((h, p, String::new(), true));
    }
    let rest = target.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (h, p) = host_port(authority, 80)?;
    let mut out = format!("{method} {path} {version}\r\n");
    for l in lines {
        if l.is_empty() {
            continue;
        }
        let name = l
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if name == "proxy-connection" || name == "connection" || name == "proxy-authorization" {
            continue;
        }
        out.push_str(l);
        out.push_str("\r\n");
    }
    // One request per connection keeps every request going to its own host.
    out.push_str("Connection: close\r\n\r\n");
    Some((h, p, out, false))
}

async fn http(mut c: TcpStream, mark: u32) -> Result<()> {
    let mut buf = Vec::with_capacity(1024);
    let end = loop {
        let mut chunk = [0u8; 1024];
        let n = c.read(&mut chunk).await?;
        if n == 0 {
            bail!("closed before the request ended");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > MAX_HEAD {
            bail!("request head too large");
        }
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let Some((host, port, rewritten, connect)) = parse_http_head(&head) else {
        c.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            .await?;
        bail!("unsupported request");
    };
    let mut up = match dial(&host, port, mark).await {
        Ok(u) => u,
        Err(e) => {
            c.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await?;
            return Err(e);
        }
    };
    if connect {
        c.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    } else {
        up.write_all(rewritten.as_bytes()).await?;
    }
    // Anything the client already sent after the head (a request body).
    up.write_all(&buf[end..]).await?;
    copy_bidirectional(&mut c, &mut up).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_http_requests() {
        let (h, p, out, connect) = parse_http_head(
            "GET http://example.com:8080/a?b HTTP/1.1\r\nHost: example.com:8080\r\nProxy-Connection: keep-alive\r\nAccept: */*\r\n\r\n",
        )
        .unwrap();
        assert_eq!((h.as_str(), p, connect), ("example.com", 8080, false));
        assert_eq!(
            out,
            "GET /a?b HTTP/1.1\r\nHost: example.com:8080\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        let (h, p, _, connect) =
            parse_http_head("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!((h.as_str(), p, connect), ("2001:db8::1", 443, true));
        assert!(parse_http_head("GET /relative HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn serves_only_local_clients() {
        for ip in [
            "192.168.1.20",
            "10.0.0.5",
            "127.0.0.1",
            "fe80::1",
            "fd00::2",
        ] {
            assert!(is_local(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "2001:db8::1"] {
            assert!(!is_local(ip.parse().unwrap()), "{ip}");
        }
    }

    async fn echo_server() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut b = [0u8; 256];
                    let n = s.read(&mut b).await.unwrap();
                    s.write_all(&b[..n]).await.unwrap();
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn dial_falls_back_to_the_next_address() {
        let echo = echo_server().await;
        // `::1` first (nothing listens there), then `127.0.0.1`.
        let targets = [
            SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 1], echo.port())),
            echo,
        ];
        let mut s = dial_any(&targets, 0).await.unwrap();
        s.write_all(b"x").await.unwrap();
        let mut b = [0u8; 1];
        s.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"x");
        assert!(dial_any(&targets[..1], 0).await.is_err());
    }

    #[tokio::test]
    async fn proxies_socks5_and_http_connect() {
        let echo = echo_server().await;
        let gw = Gateway::start("127.0.0.1".parse().unwrap(), 0, 0).unwrap();

        // SOCKS5, domain name address.
        let mut c = TcpStream::connect(gw.addr).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut r = [0u8; 2];
        c.read_exact(&mut r).await.unwrap();
        assert_eq!(r, [5, 0]);
        let mut req = vec![5, 1, 0, 3, 9];
        req.extend_from_slice(b"localhost");
        req.extend_from_slice(&echo.port().to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0, "SOCKS reply OK");
        c.write_all(b"hello").await.unwrap();
        let mut b = [0u8; 5];
        c.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"hello");

        // HTTP CONNECT.
        let mut c = TcpStream::connect(gw.addr).await.unwrap();
        c.write_all(format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", echo.port()).as_bytes())
            .await
            .unwrap();
        let mut head = vec![0u8; 39];
        c.read_exact(&mut head).await.unwrap();
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
        c.write_all(b"ping!").await.unwrap();
        c.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"ping!");
        gw.stop();
    }
}
