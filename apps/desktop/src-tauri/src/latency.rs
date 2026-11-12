//! Rough round-trip time to a VPN server, for the location list.
//!
//! TCP servers: time a TCP handshake to the server's port. UDP servers don't
//! answer anything we can send without speaking OpenVPN, so use ICMP via the
//! system `ping`, which is setuid/cap-enabled on Ubuntu.

use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::process::Command;

const TIMEOUT: Duration = Duration::from_secs(2);

pub async fn probe(host: &str, port: u16, proto: &str) -> Option<u32> {
    if host.is_empty() || host.starts_with('-') || host.len() > 253 {
        return None;
    }
    if proto == "tcp" {
        tcp(host, port).await
    } else {
        icmp(host).await
    }
}

async fn tcp(host: &str, port: u16) -> Option<u32> {
    let start = Instant::now();
    let fut = TcpStream::connect((host, port));
    match tokio::time::timeout(TIMEOUT, fut).await {
        Ok(Ok(_)) => Some(start.elapsed().as_millis() as u32),
        _ => None,
    }
}

async fn icmp(host: &str) -> Option<u32> {
    let out = tokio::time::timeout(
        TIMEOUT + Duration::from_millis(500),
        Command::new("ping")
            .args(["-c", "1", "-n", "-W", "2", "--", host])
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_ping(&String::from_utf8_lossy(&out.stdout))
}

fn parse_ping(text: &str) -> Option<u32> {
    let at = text.find("time=")? + 5;
    let rest = &text[at..];
    let end = rest.find(|c: char| !(c.is_ascii_digit() || c == '.'))?;
    let ms: f64 = rest[..end].parse().ok()?;
    Some(ms.round() as u32)
}

#[cfg(test)]
mod tests {
    use super::parse_ping;

    #[test]
    fn parses_ping_output() {
        let out = "PING x (1.2.3.4) 56(84) bytes of data.\n64 bytes from 1.2.3.4: icmp_seq=1 ttl=55 time=48.3 ms\n";
        assert_eq!(parse_ping(out), Some(48));
        assert_eq!(parse_ping("no reply"), None);
    }
}
