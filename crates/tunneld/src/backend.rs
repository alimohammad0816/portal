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
use tunnel_core::names::TUNNEL_IFACE;
use tunnel_core::{InputKind, InputRequest};

/// What a session reports back to the manager.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// OpenVPN state change (`>STATE:`).
    State {
        name: String,
        tunnel_ip: Option<String>,
        server_ip: Option<String>,
    },
    /// Cumulative byte counters (`>BYTECOUNT:`).
    Bytes {
        rx: u64,
        tx: u64,
    },
    Log(String),
    /// Something went wrong; the session is about to end.
    Fatal(String),
    /// The tunnel's DNS was configured (or failed to be). Sent by the
    /// manager's own DNS task, not by a backend.
    DnsApplied {
        servers: Vec<String>,
        /// The physical network's resolvers, for split DNS.
        direct: Vec<std::net::IpAddr>,
        result: Result<(), String>,
    },
    /// Country IP ranges were loaded (manager's own task).
    GeoLoaded {
        countries: Vec<String>,
        networks: Vec<String>,
    },
    /// OpenVPN wants something we weren't given. With `live` the session
    /// keeps waiting for [`SessionHandle::answer`]; otherwise it is ending
    /// and has to be started again with the answer. `crv1` carries a
    /// dynamic challenge's state id and username for that restart.
    NeedsInput {
        request: InputRequest,
        live: bool,
        crv1: Option<(String, String)>,
    },
    /// The server wants the user to sign in on this web page.
    AuthUrl(String),
    /// The session is over.
    Exited,
}

pub type Credentials = tunnel_core::Secrets;

/// What to run.
#[derive(Debug, Clone, Default)]
pub struct Launch {
    /// Full config text (sanitized profile plus the app's additions).
    pub config: String,
    /// Extra command-line options.
    pub args: Vec<String>,
    /// Turn off data channel offload, where OpenVPN has it.
    pub disable_dco: bool,
}

pub struct SessionHandle {
    stop: Option<oneshot::Sender<()>>,
    done: oneshot::Receiver<()>,
    input: Option<mpsc::UnboundedSender<String>>,
}

impl SessionHandle {
    /// Send the answer to a pending challenge (`>INFOMSG:CR_TEXT`).
    pub fn answer(&self, response: &str) -> bool {
        self.input.as_ref().is_some_and(|tx| {
            tx.send(format!("cr-response {}\n", base64(response.as_bytes())))
                .is_ok()
        })
    }

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
    fn start(
        &self,
        seq: u64,
        launch: Launch,
        creds: Credentials,
        events: EventTx,
    ) -> Result<SessionHandle>;
}

// ---------------------------------------------------------------- OpenVPN --

pub struct OpenVpn {
    pub binary: PathBuf,
    pub runtime_dir: PathBuf,
    /// OpenVPN 2.7+ runs its own DNS hook unless told not to; we configure
    /// DNS through systemd-resolved ourselves.
    pub disable_dns_updown: bool,
    /// OpenVPN 2.6+ knows `--disable-dco`.
    pub has_dco: bool,
}

impl OpenVpn {
    pub fn new(binary: PathBuf, runtime_dir: PathBuf) -> Self {
        let help = std::process::Command::new(&binary)
            .arg("--help")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        Self {
            binary,
            runtime_dir,
            disable_dns_updown: help.contains("--dns-updown"),
            has_dco: help.contains("--disable-dco"),
        }
    }
}

impl Backend for OpenVpn {
    fn start(
        &self,
        seq: u64,
        launch: Launch,
        creds: Credentials,
        events: EventTx,
    ) -> Result<SessionHandle> {
        std::fs::create_dir_all(&self.runtime_dir)
            .with_context(|| format!("creating {}", self.runtime_dir.display()))?;
        let socket = self.runtime_dir.join(format!("mgmt-{seq}.sock"));
        let _ = std::fs::remove_file(&socket);
        let dev_type = tunnel_core::ovpn::sanitize(&launch.config)
            .map(|p| p.dev_type)
            .unwrap_or_else(|_| "tun".into());
        let config: PathBuf = self.runtime_dir.join(format!("session-{seq}.ovpn"));
        crate::profiles::write_private(&config, launch.config.as_bytes())?;

        let mut cmd = Command::new(&self.binary);
        cmd.arg("--config").arg(&config);
        // Options after --config override the profile's: a fixed device
        // name lets the firewall and DNS find the tunnel.
        cmd.args(["--dev", TUNNEL_IFACE, "--dev-type", &dev_type]);
        if self.disable_dns_updown {
            cmd.args(["--dns-updown", "disable"]);
        }
        if launch.disable_dco {
            if self.has_dco {
                cmd.arg("--disable-dco");
            } else {
                let _ = events.send((
                    seq,
                    Event::Log("This OpenVPN has no DCO; nothing to turn off.".into()),
                ));
            }
        }
        cmd.args(&launch.args);
        let spawned = cmd
            .arg("--management")
            .arg(&socket)
            .arg("unix")
            .args(["--management-hold", "--management-query-passwords"])
            .args(["--auth-retry", "none", "--auth-nocache"])
            .args(["--verb", "3", "--suppress-timestamps"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("starting {}", self.binary.display()));
        let mut child = match spawned {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_file(&config);
                return Err(e);
            }
        };

        // OpenVPN logs to stdout; stderr carries the odd early error.
        if let Some(stderr) = child.stderr.take() {
            let ev = events.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let _ = ev.send((seq, Event::Log(line)));
                }
            });
        }
        if let Some(stdout) = child.stdout.take() {
            let ev = events.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let _ = ev.send((seq, Event::Log(line)));
                }
            });
        }

        let (stop_tx, stop_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let (input_tx, input_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let result =
                run_management(seq, &socket, &creds, &events, stop_rx, input_rx, &mut child).await;
            // OpenVPN has read its config long ago; it holds secrets-adjacent
            // material (keys), so don't leave it lying around.
            let _ = std::fs::remove_file(&config);
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

        Ok(SessionHandle {
            stop: Some(stop_tx),
            done: done_rx,
            input: Some(input_tx),
        })
    }
}

async fn connect_socket(
    path: &std::path::Path,
    child: &mut tokio::process::Child,
) -> Result<UnixStream> {
    for _ in 0..100 {
        if let Ok(s) = UnixStream::connect(path).await {
            return Ok(s);
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!(
                "OpenVPN exited before it was ready ({status}). Check the log for details."
            );
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
    mut input: mpsc::UnboundedReceiver<String>,
    child: &mut tokio::process::Child,
) -> Result<()> {
    let stream = connect_socket(socket, child).await?;
    let (rd, mut wr) = stream.into_split();
    let mut lines = BufReader::new(rd).lines();

    for cmd in ["state on", "bytecount 1", "hold release"] {
        wr.write_all(format!("{cmd}\n").as_bytes()).await?;
    }

    let mut stopping = false;
    loop {
        tokio::select! {
            _ = &mut stop, if !stopping => {
                stopping = true;
                wr.write_all(b"signal SIGTERM\n").await?;
            }
            Some(cmd) = input.recv() => {
                wr.write_all(cmd.as_bytes()).await?;
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
                send(Event::State {
                    name: name.to_string(),
                    tunnel_ip: opt(3),
                    server_ip: opt(4),
                });
            }
        }
        "BYTECOUNT" => {
            let mut it = body
                .split(',')
                .map(|s| s.trim().parse::<u64>().unwrap_or(0));
            send(Event::Bytes {
                rx: it.next().unwrap_or(0),
                tx: it.next().unwrap_or(0),
            });
        }
        "LOG" => {
            let msg = body.splitn(3, ',').nth(2).unwrap_or(body);
            send(Event::Log(msg.to_string()));
        }
        "FATAL" => send(Event::Fatal(body.to_string())),
        "HOLD" => return Ok(vec!["hold release\n".into()]),
        "PASSWORD" => return Ok(password_reply(body, creds, &send)),
        "INFOMSG" => info_message(body, &send),
        _ => {}
    }
    Ok(vec![])
}

/// `>INFOMSG:` carries web sign-in links and pending-auth challenges.
fn info_message(body: &str, send: &dyn Fn(Event)) {
    let (kind, rest) = body.split_once(':').unwrap_or((body, ""));
    match kind {
        // WEB_AUTH:flags:url, or the older OPEN_URL:url.
        "WEB_AUTH" | "OPEN_URL" => {
            let url = if kind == "WEB_AUTH" {
                rest.split_once(':').map_or(rest, |(_, u)| u)
            } else {
                rest
            };
            if url.starts_with("https://") || url.starts_with("http://") {
                send(Event::AuthUrl(url.to_string()));
            }
        }
        // CR_TEXT:flags:text, answered with `cr-response` on this session.
        "CR_TEXT" => {
            let (flags, text) = rest.split_once(':').unwrap_or(("", rest));
            send(Event::NeedsInput {
                request: InputRequest {
                    kind: InputKind::Challenge,
                    message: Some(text.to_string()),
                    echo: flags.split(',').any(|f| f == "E"),
                },
                live: true,
                crv1: None,
            });
        }
        _ => {}
    }
}

/// A dynamic challenge from a failed sign-in:
/// `... ['CRV1:R,E:state_id:base64(username):text']`.
fn parse_crv1(body: &str) -> Option<(InputRequest, String, String)> {
    let start = body.find("CRV1:")? + 5;
    let rest = body[start..].trim_end_matches(['\'', ']']);
    let mut parts = rest.splitn(4, ':');
    let flags = parts.next()?;
    let state = parts.next()?.to_string();
    let user = String::from_utf8(unbase64(parts.next()?)?).ok()?;
    let text = parts.next().unwrap_or("").to_string();
    Some((
        InputRequest {
            kind: InputKind::Challenge,
            message: Some(text),
            echo: flags.split(',').any(|f| f == "E"),
        },
        state,
        user,
    ))
}

fn needs(kind: InputKind, send: &dyn Fn(Event)) -> Vec<String> {
    send(Event::NeedsInput {
        request: InputRequest {
            kind,
            message: None,
            echo: false,
        },
        live: false,
        crv1: None,
    });
    vec!["signal SIGTERM\n".into()]
}

fn password_reply(body: &str, creds: &Credentials, send: &dyn Fn(Event)) -> Vec<String> {
    let kind = body.split('\'').nth(1).unwrap_or("");
    if body.starts_with("Verification Failed") {
        if let Some((request, state, user)) = parse_crv1(body) {
            send(Event::NeedsInput {
                request,
                live: false,
                crv1: Some((state, user)),
            });
        } else {
            send(Event::Fatal(
                match kind {
                    "Private Key" => "The private key passphrase is wrong.",
                    "HTTP Proxy" | "SOCKS Proxy" => "The proxy rejected its username or password.",
                    _ => "Authentication failed. Check your username and password.",
                }
                .into(),
            ));
        }
        return vec!["signal SIGTERM\n".into()];
    }
    match kind {
        "Auth" => {
            if creds.username.is_empty() && creds.password.is_empty() {
                return needs(InputKind::Login, send);
            }
            let password = match &creds.response {
                Some(resp) if body.contains("SC:") => {
                    format!(
                        "SCRV1:{}:{}",
                        base64(creds.password.as_bytes()),
                        base64(resp.as_bytes())
                    )
                }
                _ => creds.password.clone(),
            };
            vec![
                format!("username \"Auth\" {}\n", quote(&creds.username)),
                format!("password \"Auth\" {}\n", quote(&password)),
            ]
        }
        "Private Key" => match &creds.key_passphrase {
            Some(p) => vec![format!("password \"Private Key\" {}\n", quote(p))],
            None => needs(InputKind::KeyPassphrase, send),
        },
        "HTTP Proxy" | "SOCKS Proxy" => match (&creds.proxy_username, &creds.proxy_password) {
            (Some(u), Some(p)) => vec![
                format!("username \"{kind}\" {}\n", quote(u)),
                format!("password \"{kind}\" {}\n", quote(p)),
            ],
            _ => needs(InputKind::ProxyLogin, send),
        },
        "" => vec![],
        other => {
            send(Event::Fatal(format!(
                "OpenVPN asked for a '{other}' password, which Tunnel can't provide."
            )));
            vec!["signal SIGTERM\n".into()]
        }
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
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
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

fn unbase64(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        if chunk.len() == 1 {
            return None;
        }
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

// ------------------------------------------------------------------- Mock --

/// Fake backend: walks through the usual states and reports traffic.
///
/// A few usernames act out the less common sign-ins, for UI work:
/// `challenge` gets a dynamic challenge (answer `123456`), `pending` a
/// live one; a profile with an encrypted key wants the passphrase `secret`.
pub struct Mock;

impl Backend for Mock {
    fn start(
        &self,
        seq: u64,
        launch: Launch,
        creds: Credentials,
        events: EventTx,
    ) -> Result<SessionHandle> {
        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
        let (done_tx, done_rx) = oneshot::channel();
        let (input_tx, mut input_rx) = mpsc::unbounded_channel::<String>();
        let key_encrypted = tunnel_core::ovpn::sanitize(&launch.config)
            .map(|p| p.key_encrypted)
            .unwrap_or(false);
        tokio::spawn(async move {
            let send = |e: Event| {
                let _ = events.send((seq, e));
            };
            let end = |send: &dyn Fn(Event)| {
                send(Event::Exited);
            };
            if key_encrypted && creds.key_passphrase.as_deref() != Some("secret") {
                if creds.key_passphrase.is_some() {
                    send(Event::Fatal("The private key passphrase is wrong.".into()));
                } else {
                    needs(InputKind::KeyPassphrase, &send);
                }
                end(&send);
                let _ = done_tx.send(());
                return;
            }
            if creds.username == "challenge" && !creds.password.starts_with("CRV1::") {
                let msg = ">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:mockstate:Y2hhbGxlbmdl:Enter the code from your authenticator app']";
                password_reply(msg.strip_prefix(">PASSWORD:").unwrap_or(msg), &creds, &send);
                end(&send);
                let _ = done_tx.send(());
                return;
            }
            if creds.password.starts_with("CRV1::") && creds.password != "CRV1::mockstate::123456" {
                send(Event::Fatal(
                    "Authentication failed. Check your username and password.".into(),
                ));
                end(&send);
                let _ = done_tx.send(());
                return;
            }
            let steps = ["RESOLVE", "WAIT", "AUTH", "GET_CONFIG", "ASSIGN_IP"];
            for name in steps {
                send(Event::State {
                    name: name.into(),
                    tunnel_ip: None,
                    server_ip: None,
                });
                send(Event::Log(format!("MOCK: {name}")));
                tokio::select! {
                    _ = &mut stop_rx => { send(Event::Exited); let _ = done_tx.send(()); return; }
                    _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                }
                if name == "AUTH" && creds.username == "pending" {
                    info_message(
                        "CR_TEXT:R,E:Approve the sign-in on your phone, then enter the number shown",
                        &send,
                    );
                    tokio::select! {
                        _ = &mut stop_rx => { send(Event::Exited); let _ = done_tx.send(()); return; }
                        answer = input_rx.recv() => {
                            send(Event::Log(format!("MOCK: got {}", answer.unwrap_or_default().trim())));
                        }
                    }
                }
            }
            send(Event::Log(
                "PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 10.8.0.1,ifconfig 10.8.0.6 255.255.255.0'".into(),
            ));
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
            send(Event::State {
                name: "EXITING".into(),
                tunnel_ip: None,
                server_ip: None,
            });
            tokio::time::sleep(Duration::from_millis(200)).await;
            send(Event::Exited);
            let _ = done_tx.send(());
        });
        Ok(SessionHandle {
            stop: Some(stop_tx),
            done: done_rx,
            input: Some(input_tx),
        })
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
        let (_, ev) = collect(
            ">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.6,203.0.113.1,1194,,",
            &Credentials::default(),
        );
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
        let (_, ev) = collect(
            ">LOG:1700000000,I,Peer Connection Initiated, with x",
            &Credentials::default(),
        );
        assert_eq!(
            ev,
            vec![Event::Log("Peer Connection Initiated, with x".into())]
        );
    }

    #[test]
    fn answers_password_prompts() {
        let creds = Credentials {
            username: "ali".into(),
            password: "p\"w\\d".into(),
            ..Default::default()
        };
        let (replies, _) = collect(">PASSWORD:Need 'Auth' username/password", &creds);
        assert_eq!(
            replies,
            vec![
                "username \"Auth\" \"ali\"\n",
                "password \"Auth\" \"p\\\"w\\\\d\"\n"
            ]
        );
    }

    #[test]
    fn answers_static_challenge() {
        let creds = Credentials {
            username: "u".into(),
            password: "pass".into(),
            response: Some("123456".into()),
            ..Default::default()
        };
        let (replies, _) = collect(
            ">PASSWORD:Need 'Auth' username/password SC:1,Enter OTP",
            &creds,
        );
        assert_eq!(
            replies[1],
            "password \"Auth\" \"SCRV1:cGFzcw==:MTIzNDU2\"\n"
        );
    }

    #[test]
    fn reports_auth_failure() {
        let (replies, ev) = collect(
            ">PASSWORD:Verification Failed: 'Auth'",
            &Credentials::default(),
        );
        assert_eq!(replies, vec!["signal SIGTERM\n"]);
        assert!(matches!(&ev[0], Event::Fatal(m) if m.contains("Authentication failed")));
    }

    #[test]
    fn asks_for_what_it_lacks() {
        let none = Credentials::default();
        for (line, kind) in [
            (">PASSWORD:Need 'Auth' username/password", InputKind::Login),
            (
                ">PASSWORD:Need 'Private Key' password",
                InputKind::KeyPassphrase,
            ),
            (
                ">PASSWORD:Need 'HTTP Proxy' username/password",
                InputKind::ProxyLogin,
            ),
            (
                ">PASSWORD:Need 'SOCKS Proxy' username/password",
                InputKind::ProxyLogin,
            ),
        ] {
            let (replies, ev) = collect(line, &none);
            assert_eq!(replies, vec!["signal SIGTERM\n"], "{line}");
            assert!(
                matches!(&ev[0], Event::NeedsInput { request, live: false, crv1: None } if request.kind == kind),
                "{line}: {ev:?}"
            );
        }
    }

    #[test]
    fn answers_key_and_proxy_prompts() {
        let creds = Credentials {
            key_passphrase: Some("k".into()),
            proxy_username: Some("pu".into()),
            proxy_password: Some("pp".into()),
            ..Default::default()
        };
        let (r, _) = collect(">PASSWORD:Need 'Private Key' password", &creds);
        assert_eq!(r, vec!["password \"Private Key\" \"k\"\n"]);
        let (r, _) = collect(">PASSWORD:Need 'HTTP Proxy' username/password", &creds);
        assert_eq!(
            r,
            vec![
                "username \"HTTP Proxy\" \"pu\"\n",
                "password \"HTTP Proxy\" \"pp\"\n"
            ]
        );
        let (_, ev) = collect(">PASSWORD:Verification Failed: 'Private Key'", &creds);
        assert!(matches!(&ev[0], Event::Fatal(m) if m.contains("passphrase")));
    }

    #[test]
    fn parses_dynamic_challenge() {
        let (replies, ev) = collect(
            ">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l:Y3Ix:Please enter token PIN']",
            &Credentials::default(),
        );
        assert_eq!(replies, vec!["signal SIGTERM\n"]);
        match &ev[0] {
            Event::NeedsInput {
                request,
                live: false,
                crv1: Some((state, user)),
            } => {
                assert_eq!(request.kind, InputKind::Challenge);
                assert_eq!(request.message.as_deref(), Some("Please enter token PIN"));
                assert!(request.echo);
                assert_eq!(state, "Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l");
                assert_eq!(user, "cr1");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn handles_info_messages() {
        let (_, ev) = collect(
            ">INFOMSG:WEB_AUTH::https://sso.example/auth?x=1",
            &Credentials::default(),
        );
        assert_eq!(
            ev,
            vec![Event::AuthUrl("https://sso.example/auth?x=1".into())]
        );
        let (_, ev) = collect(
            ">INFOMSG:OPEN_URL:javascript:alert(1)",
            &Credentials::default(),
        );
        assert!(ev.is_empty());
        let (_, ev) = collect(">INFOMSG:CR_TEXT:R:Enter the code", &Credentials::default());
        assert!(matches!(
            &ev[0],
            Event::NeedsInput { request, live: true, .. }
                if request.message.as_deref() == Some("Enter the code") && !request.echo
        ));
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
        for s in [&b""[..], b"f", b"fo", b"foo", b"foobar", b"\xff\x00\x10"] {
            assert_eq!(unbase64(&base64(s)).unwrap(), s);
        }
        assert!(unbase64("a").is_none());
    }
}
