//! Running one VPN session. [`OpenVpn`] drives a real `openvpn` process over
//! its management socket; [`Mock`] simulates one so the GUI can be developed
//! and tested without root.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

/// What a session reports back to the manager.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// OpenVPN state change (`>STATE:`).
    State { name: String, tunnel_ip: Option<String>, server_ip: Option<String> },
    /// Cumulative byte counters (`>BYTECOUNT:`).
    Bytes { rx: u64, tx: u64 },
    Log(String),
    /// Something went wrong; the session is about to end.
    Fatal(String),
    /// The session is over.
    Exited,
}

#[derive(Debug, Clone, Default)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    /// Static challenge response (OTP), if the profile has one.
    pub response: Option<String>,
}

pub struct SessionHandle {
    stop: Option<oneshot::Sender<()>>,
    done: oneshot::Receiver<()>,
}

impl SessionHandle {
    /// Ask the session to end and wait until it has, up to a few seconds.
    pub async fn stop(mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        let _ = tokio::time::timeout(Duration::from_secs(8), &mut self.done).await;
    }
}

pub type EventTx = mpsc::UnboundedSender<(u64, Event)>;

pub trait Backend: Send + Sync {
    fn start(&self, seq: u64, config: PathBuf, creds: Credentials, events: EventTx) -> Result<SessionHandle>;
}

// ---------------------------------------------------------------- OpenVPN --

pub struct OpenVpn {
    pub binary: PathBuf,
    pub runtime_dir: PathBuf,
}

impl Backend for OpenVpn {
    fn start(&self, seq: u64, config: PathBuf, creds: Credentials, events: EventTx) -> Result<SessionHandle> {
        std::fs::create_dir_all(&self.runtime_dir)
            .with_context(|| format!("creating {}", self.runtime_dir.display()))?;
        let socket = self.runtime_dir.join(format!("mgmt-{seq}.sock"));
        let _ = std::fs::remove_file(&socket);

        let mut child = Command::new(&self.binary)
            .arg("--config")
            .arg(&config)
            .arg("--management")
            .arg(&socket)
            .arg("unix")
            .args(["--management-hold", "--management-query-passwords"])
            .args(["--auth-retry", "none", "--auth-nocache"])
            .args(["--verb", "3", "--suppress-timestamps"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("starting {}", self.binary.display()))?;

        if let Some(stderr) = child.stderr.take() {
            let ev = events.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let _ = ev.send((seq, Event::Log(line)));
                }
            });
        }

        let (stop_tx, stop_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        tokio::spawn(async move {
            let result = run_management(seq, &socket, &creds, &events, stop_rx, &mut child).await;
            if let Err(e) = result {
                warn!("session {seq}: {e:#}");
                let _ = events.send((seq, Event::Fatal(format!("{e:#}"))));
            }
            // Give OpenVPN a moment to tear down routes, then make sure it's gone.
            match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
                Ok(Ok(status)) => debug!("session {seq}: openvpn exited with {status}"),
                _ => {
                    let _ = child.kill().await;
                }
            }
            let _ = std::fs::remove_file(&socket);
            let _ = events.send((seq, Event::Exited));
            let _ = done_tx.send(());
        });

        Ok(SessionHandle { stop: Some(stop_tx), done: done_rx })
    }
}

async fn connect_socket(path: &std::path::Path, child: &mut tokio::process::Child) -> Result<UnixStream> {
    for _ in 0..100 {
        if let Ok(s) = UnixStream::connect(path).await {
            return Ok(s);
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("OpenVPN exited before it was ready ({status}). Check the log for details.");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("OpenVPN did not open its management socket")
}

async fn run_management(
    seq: u64,
    socket: &std::path::Path,
    creds: &Credentials,
    events: &EventTx,
    mut stop: oneshot::Receiver<()>,
    child: &mut tokio::process::Child,
) -> Result<()> {
    let stream = connect_socket(socket, child).await?;
    let (rd, mut wr) = stream.into_split();
    let mut lines = BufReader::new(rd).lines();

    for cmd in ["state on", "bytecount 1", "log on", "hold release"] {
        wr.write_all(format!("{cmd}\n").as_bytes()).await?;
    }

    let mut stopping = false;
    loop {
        tokio::select! {
            _ = &mut stop, if !stopping => {
                stopping = true;
                wr.write_all(b"signal SIGTERM\n").await?;
            }
            line = lines.next_line() => {
                let Some(line) = line? else { return Ok(()) };
                for reply in handle_line(&line, creds, seq, events)? {
                    wr.write_all(reply.as_bytes()).await?;
                }
            }
        }
    }
}

/// React to one management-interface line; returns commands to send back.
fn handle_line(line: &str, creds: &Credentials, seq: u64, events: &EventTx) -> Result<Vec<String>> {
    let send = |e: Event| {
        let _ = events.send((seq, e));
    };
    let Some(rest) = line.strip_prefix('>') else {
        if let Some(err) = line.strip_prefix("ERROR:") {
            debug!("management error: {err}");
        }
        return Ok(vec![]);
    };
    let (kind, body) = rest.split_once(':').unwrap_or((rest, ""));
    match kind {
        "STATE" => {
            let f: Vec<&str> = body.split(',').collect();
            let opt = |i: usize| f.get(i).filter(|s| !s.is_empty()).map(|s| s.to_string());
            if let Some(name) = f.get(1) {
                send(Event::State { name: name.to_string(), tunnel_ip: opt(3), server_ip: opt(4) });
            }
        }
        "BYTECOUNT" => {
            let mut it = body.split(',').map(|s| s.trim().parse::<u64>().unwrap_or(0));
            send(Event::Bytes { rx: it.next().unwrap_or(0), tx: it.next().unwrap_or(0) });
        }
        "LOG" => {
            let msg = body.splitn(3, ',').nth(2).unwrap_or(body);
            send(Event::Log(msg.to_string()));
        }
        "FATAL" => send(Event::Fatal(body.to_string())),
        "HOLD" => return Ok(vec!["hold release\n".into()]),
        "PASSWORD" => return Ok(password_reply(body, creds, &send)),
        _ => {}
    }
    Ok(vec![])
}

fn password_reply(body: &str, creds: &Credentials, send: &dyn Fn(Event)) -> Vec<String> {
    if body.starts_with("Verification Failed") {
        send(Event::Fatal("Authentication failed. Check your username and password.".into()));
        return vec!["signal SIGTERM\n".into()];
    }
    let Some(kind) = body.split('\'').nth(1) else { return vec![] };
    if kind == "Auth" {
        let password = match &creds.response {
            Some(resp) if body.contains("SC:") => {
                format!("SCRV1:{}:{}", base64(creds.password.as_bytes()), base64(resp.as_bytes()))
            }
            _ => creds.password.clone(),
        };
        vec![
            format!("username \"Auth\" {}\n", quote(&creds.username)),
            format!("password \"Auth\" {}\n", quote(&password)),
        ]
    } else {
        send(Event::Fatal(format!("This profile needs a '{kind}' password, which isn't supported yet.")));
        vec!["signal SIGTERM\n".into()]
    }
}

/// Quote a value for the management interface.
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\n' | '\r' => {}
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

// ------------------------------------------------------------------- Mock --

/// Fake backend: walks through the usual states and reports traffic.
pub struct Mock;

impl Backend for Mock {
    fn start(&self, seq: u64, _config: PathBuf, _creds: Credentials, events: EventTx) -> Result<SessionHandle> {
        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
        let (done_tx, done_rx) = oneshot::channel();
        tokio::spawn(async move {
            let send = |e: Event| {
                let _ = events.send((seq, e));
            };
            let steps = ["RESOLVE", "WAIT", "AUTH", "GET_CONFIG", "ASSIGN_IP"];
            for name in steps {
                send(Event::State { name: name.into(), tunnel_ip: None, server_ip: None });
                send(Event::Log(format!("MOCK: {name}")));
                tokio::select! {
                    _ = &mut stop_rx => { send(Event::Exited); let _ = done_tx.send(()); return; }
                    _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                }
            }
            send(Event::State {
                name: "CONNECTED".into(),
                tunnel_ip: Some("10.8.0.6".into()),
                server_ip: Some("203.0.113.24".into()),
            });
            send(Event::Log("MOCK: Initialization Sequence Completed".into()));
            let (mut rx, mut tx) = (0u64, 0u64);
            let mut tick = 0u64;
            loop {
                tokio::select! {
                    _ = &mut stop_rx => break,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {
                        tick += 1;
                        rx += 6_000_000 + (tick * 7_919 % 5) * 1_000_000;
                        tx += 900_000 + (tick * 104_729 % 4) * 150_000;
                        send(Event::Bytes { rx, tx });
                    }
                }
            }
            send(Event::State { name: "EXITING".into(), tunnel_ip: None, server_ip: None });
            tokio::time::sleep(Duration::from_millis(200)).await;
            send(Event::Exited);
            let _ = done_tx.send(());
        });
        Ok(SessionHandle { stop: Some(stop_tx), done: done_rx })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(line: &str, creds: &Credentials) -> (Vec<String>, Vec<Event>) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let replies = handle_line(line, creds, 7, &tx).unwrap();
        drop(tx);
        let mut events = Vec::new();
        while let Ok((seq, e)) = rx.try_recv() {
            assert_eq!(seq, 7);
            events.push(e);
        }
        (replies, events)
    }

    #[test]
    fn parses_state_lines() {
        let (_, ev) = collect(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.6,203.0.113.1,1194,,", &Credentials::default());
        assert_eq!(
            ev,
            vec![Event::State {
                name: "CONNECTED".into(),
                tunnel_ip: Some("10.8.0.6".into()),
                server_ip: Some("203.0.113.1".into())
            }]
        );
    }

    #[test]
    fn parses_bytecount_and_log() {
        let (_, ev) = collect(">BYTECOUNT:1024,2048", &Credentials::default());
        assert_eq!(ev, vec![Event::Bytes { rx: 1024, tx: 2048 }]);
        let (_, ev) = collect(">LOG:1700000000,I,Peer Connection Initiated, with x", &Credentials::default());
        assert_eq!(ev, vec![Event::Log("Peer Connection Initiated, with x".into())]);
    }

    #[test]
    fn answers_password_prompts() {
        let creds = Credentials { username: "ali".into(), password: "p\"w\\d".into(), response: None };
        let (replies, _) = collect(">PASSWORD:Need 'Auth' username/password", &creds);
        assert_eq!(replies, vec!["username \"Auth\" \"ali\"\n", "password \"Auth\" \"p\\\"w\\\\d\"\n"]);
    }

    #[test]
    fn answers_static_challenge() {
        let creds = Credentials { username: "u".into(), password: "pass".into(), response: Some("123456".into()) };
        let (replies, _) = collect(">PASSWORD:Need 'Auth' username/password SC:1,Enter OTP", &creds);
        assert_eq!(replies[1], "password \"Auth\" \"SCRV1:cGFzcw==:MTIzNDU2\"\n");
    }

    #[test]
    fn reports_auth_failure() {
        let (replies, ev) = collect(">PASSWORD:Verification Failed: 'Auth'", &Credentials::default());
        assert_eq!(replies, vec!["signal SIGTERM\n"]);
        assert!(matches!(&ev[0], Event::Fatal(m) if m.contains("Authentication failed")));
    }

    #[test]
    fn releases_hold() {
        let (replies, _) = collect(">HOLD:Waiting for hold release:0", &Credentials::default());
        assert_eq!(replies, vec!["hold release\n"]);
    }

    #[test]
    fn base64_matches_reference() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }
}
