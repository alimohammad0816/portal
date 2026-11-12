//! OpenVPN client config handling.
//!
//! The daemon runs OpenVPN as root, so an imported config is a privilege
//! boundary: anything that runs commands, loads plugins, or reads and writes
//! arbitrary paths would let any local user who can import a profile run code
//! as root. [`sanitize`] rejects those directives and requires every key or
//! certificate to be inline. Clients turn file references into inline blocks
//! first, reading the files with the user's own permissions ([`inline_files`]).

use std::fmt;
use std::path::Path;

use thiserror::Error;

use crate::model::AuthKind;

/// Largest config we accept, inline material included.
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;

/// Directives that execute commands, load code, or make OpenVPN read or write
/// paths chosen by the config author. Never allowed in an imported profile.
const FORBIDDEN: &[&str] = &[
    "up",
    "down",
    "route-up",
    "route-pre-down",
    "ipchange",
    "client-connect",
    "client-disconnect",
    "learn-address",
    "auth-user-pass-verify",
    "tls-verify",
    "tls-export-cert",
    "plugin",
    "script-security",
    "iproute",
    "dev-node",
    "tmp-dir",
    "askpass",
    "replay-persist",
    "ifconfig-pool-persist",
    "log",
    "log-append",
    "status",
    "writepid",
    "cd",
    "chroot",
    "daemon",
    "config",
    "management",
    "management-client-user",
    "management-client-group",
    "management-hold",
    "management-query-passwords",
    "management-query-proxy",
    "management-query-remote",
    "management-external-key",
    "management-external-cert",
    "management-client-auth",
    "management-forget-disconnect",
    "management-up-down",
    "management-log-cache",
    "management-signal",
    "management-client",
    "machine-readable-output",
    "mode",
    "server",
    "server-bridge",
    "tls-server",
    "client-config-dir",
    "ccd-exclusive",
];

/// Directives whose first argument is a file. Allowed only as inline blocks.
const FILE_DIRECTIVES: &[&str] = &[
    "ca",
    "cert",
    "key",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
    "pkcs12",
    "extra-certs",
    "crl-verify",
    "secret",
    "dh",
    "http-proxy-user-pass",
];

/// Inline blocks we accept (`<ca>...</ca>` and friends).
const INLINE_BLOCKS: &[&str] = &[
    "ca",
    "cert",
    "key",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
    "pkcs12",
    "extra-certs",
    "crl-verify",
    "secret",
    "dh",
    "auth-user-pass",
    "http-proxy-user-pass",
    "connection",
];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("line {line}: `{directive}` is not allowed in imported profiles")]
    Forbidden { directive: String, line: usize },
    #[error("line {line}: `{directive}` points to a file; import it so the file is embedded")]
    ExternalFile { directive: String, line: usize },
    #[error("line {line}: unterminated <{tag}> block")]
    UnterminatedBlock { tag: String, line: usize },
    #[error("line {line}: unexpected </{tag}>")]
    UnexpectedClose { tag: String, line: usize },
    #[error("line {line}: unsupported inline block <{tag}>")]
    UnknownBlock { tag: String, line: usize },
    #[error("line {line}: unterminated quote")]
    UnterminatedQuote { line: usize },
    #[error("the config has no `remote` line")]
    NoRemote,
    #[error("line {line}: invalid port `{value}`")]
    BadPort { value: String, line: usize },
    #[error("the config is too large")]
    TooLarge,
    #[error("line {line}: `{directive}` can't be changed in extra options")]
    NotInExtra { directive: String, line: usize },
    #[error("line {line}: extra options can't contain <{tag}> blocks")]
    BlockInExtra { tag: String, line: usize },
    #[error("could not read {path}: {reason}")]
    Read { path: String, reason: String },
}

/// One `remote` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub host: String,
    pub port: u16,
    /// `udp` or `tcp`.
    pub proto: String,
}

/// What we learn from a config while sanitizing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedConfig {
    pub remotes: Vec<Remote>,
    pub auth: AuthKind,
    pub challenge: Option<String>,
    /// `tun` or `tap`, from the `dev` / `dev-type` directives.
    pub dev_type: String,
    /// The inline private key is encrypted and needs a passphrase.
    pub key_encrypted: bool,
    /// Config text safe to hand to OpenVPN.
    pub sanitized: String,
}

impl ParsedConfig {
    pub fn primary(&self) -> &Remote {
        &self.remotes[0]
    }
}

/// A logical line of a config: either a directive or an inline block.
enum Item<'a> {
    Directive {
        line: usize,
        raw: &'a str,
        words: Vec<String>,
    },
    Block {
        line: usize,
        tag: String,
        body: Vec<&'a str>,
    },
    Other(&'a str),
}

impl fmt::Debug for Item<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Item::Directive { words, .. } => write!(f, "Directive({words:?})"),
            Item::Block { tag, .. } => write!(f, "Block({tag})"),
            Item::Other(s) => write!(f, "Other({s:?})"),
        }
    }
}

fn split_items(text: &str) -> Result<Vec<Item<'_>>, ConfigError> {
    let mut items = Vec::new();
    let mut lines = text.lines().enumerate().peekable();
    while let Some((idx, raw)) = lines.next() {
        let line = idx + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            items.push(Item::Other(raw));
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("</") {
            let tag = rest.trim_end_matches('>').to_string();
            return Err(ConfigError::UnexpectedClose { tag, line });
        }
        if trimmed.starts_with('<') && trimmed.ends_with('>') {
            let tag = trimmed[1..trimmed.len() - 1].trim().to_ascii_lowercase();
            let close = format!("</{tag}>");
            let mut body = Vec::new();
            let mut closed = false;
            for (_, inner) in lines.by_ref() {
                if inner.trim().eq_ignore_ascii_case(&close) {
                    closed = true;
                    break;
                }
                body.push(inner);
            }
            if !closed {
                return Err(ConfigError::UnterminatedBlock { tag, line });
            }
            items.push(Item::Block { line, tag, body });
            continue;
        }
        let words = tokenize(trimmed).ok_or(ConfigError::UnterminatedQuote { line })?;
        items.push(Item::Directive { line, raw, words });
    }
    Ok(items)
}

/// Split a config line into words, honoring OpenVPN's quoting rules closely
/// enough for parsing: double quotes with backslash escapes, single quotes
/// literal, and a trailing `#`/`;` comment.
fn tokenize(line: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '"' => break,
                        '\\' => cur.push(chars.next()?),
                        other => cur.push(other),
                    }
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '\'' => break,
                        other => cur.push(other),
                    }
                }
            }
            '\\' => {
                in_word = true;
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            '#' | ';' if !in_word => break,
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    Some(words)
}

fn normalize_proto(p: &str) -> Option<&'static str> {
    let p = p.to_ascii_lowercase();
    if p.starts_with("udp") {
        Some("udp")
    } else if p.starts_with("tcp") {
        Some("tcp")
    } else {
        None
    }
}

fn parse_port(value: &str, line: usize) -> Result<u16, ConfigError> {
    value.parse::<u16>().map_err(|_| ConfigError::BadPort {
        value: value.to_string(),
        line,
    })
}

/// Checks every directive gets, wherever it appears. Returns the
/// lower-cased directive name.
fn check_safe(words: &[String], line: usize) -> Result<String, ConfigError> {
    let name = words[0].trim_start_matches("--").to_ascii_lowercase();
    if FORBIDDEN.contains(&name.as_str()) {
        return Err(ConfigError::Forbidden {
            directive: name,
            line,
        });
    }
    let arg = |i: usize| words.get(i).map(String::as_str);
    let external = match name.as_str() {
        n if FILE_DIRECTIVES.contains(&n) => arg(1).unwrap_or("") != "[inline]",
        // The third argument is a credentials file, unless OpenVPN is to
        // ask for them (over the management socket).
        "http-proxy" => arg(3).is_some_and(|a| !matches!(a, "auto" | "auto-nct" | "stdin")),
        "socks-proxy" => arg(3).is_some_and(|a| a != "stdin"),
        _ => false,
    };
    if external {
        return Err(ConfigError::ExternalFile {
            directive: name,
            line,
        });
    }
    Ok(name)
}

/// Validate a config and produce the text the daemon will run.
pub fn sanitize(text: &str) -> Result<ParsedConfig, ConfigError> {
    if text.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge);
    }
    let items = split_items(text)?;

    let mut default_proto = "udp".to_string();
    let mut default_port: u16 = 1194;
    // (host, explicit port, explicit proto)
    let mut raw_remotes: Vec<(String, Option<u16>, Option<String>)> = Vec::new();
    let mut auth_user_pass = false;
    let mut inline_creds = false;
    let mut challenge = None;
    let mut dev_type = "tun".to_string();
    let mut key_encrypted = false;
    let mut out = String::with_capacity(text.len());

    let mut check =
        |words: &[String], line: usize, out: &mut String, raw: &str| -> Result<(), ConfigError> {
            let name = check_safe(words, line)?;
            match name.as_str() {
                "remote" => {
                    let host = words.get(1).cloned().unwrap_or_default();
                    let port = words.get(2).map(|p| parse_port(p, line)).transpose()?;
                    let proto = words
                        .get(3)
                        .and_then(|p| normalize_proto(p))
                        .map(str::to_string);
                    if !host.is_empty() {
                        raw_remotes.push((host, port, proto));
                    }
                }
                "proto" => {
                    if let Some(p) = words.get(1).and_then(|p| normalize_proto(p)) {
                        default_proto = p.to_string();
                    }
                }
                "port" | "rport" => {
                    if let Some(p) = words.get(1) {
                        default_port = parse_port(p, line)?;
                    }
                }
                "auth-user-pass" => {
                    auth_user_pass = true;
                    // Credentials come from the user over the management socket,
                    // never from a file the config names.
                    out.push_str("auth-user-pass\n");
                    return Ok(());
                }
                "static-challenge" => {
                    challenge = words.get(1).cloned();
                }
                "dev" | "dev-type" => {
                    if let Some(d) = words.get(1) {
                        let d = d.to_ascii_lowercase();
                        if d.starts_with("tap") {
                            dev_type = "tap".into();
                        } else if d.starts_with("tun") {
                            dev_type = "tun".into();
                        }
                    }
                }
                _ => {}
            }
            out.push_str(raw.trim_end());
            out.push('\n');
            Ok(())
        };

    for item in &items {
        match item {
            Item::Other(raw) => {
                out.push_str(raw.trim_end());
                out.push('\n');
            }
            Item::Directive { line, raw, words } => check(words, *line, &mut out, raw)?,
            Item::Block { line, tag, body } => {
                if !INLINE_BLOCKS.contains(&tag.as_str()) {
                    return Err(ConfigError::UnknownBlock {
                        tag: tag.clone(),
                        line: *line,
                    });
                }
                if tag == "auth-user-pass" {
                    inline_creds = true;
                }
                // PKCS#8 (`BEGIN ENCRYPTED PRIVATE KEY`) and the older
                // `Proc-Type: 4,ENCRYPTED` PEM headers.
                if tag == "key" && body.iter().any(|l| l.contains("ENCRYPTED")) {
                    key_encrypted = true;
                }
                out.push_str(&format!("<{tag}>\n"));
                if tag == "connection" {
                    for (offset, inner) in body.iter().enumerate() {
                        let inner_line = line + offset + 1;
                        let trimmed = inner.trim();
                        if trimmed.is_empty()
                            || trimmed.starts_with('#')
                            || trimmed.starts_with(';')
                        {
                            out.push_str(inner.trim_end());
                            out.push('\n');
                            continue;
                        }
                        let words = tokenize(trimmed)
                            .ok_or(ConfigError::UnterminatedQuote { line: inner_line })?;
                        check(&words, inner_line, &mut out, inner)?;
                    }
                } else {
                    for inner in body {
                        out.push_str(inner.trim_end());
                        out.push('\n');
                    }
                }
                out.push_str(&format!("</{tag}>\n"));
            }
        }
    }

    if raw_remotes.is_empty() {
        return Err(ConfigError::NoRemote);
    }
    let remotes = raw_remotes
        .into_iter()
        .map(|(host, port, proto)| Remote {
            host,
            port: port.unwrap_or(default_port),
            proto: proto.unwrap_or_else(|| default_proto.clone()),
        })
        .collect();

    let auth = match (auth_user_pass && !inline_creds, challenge.is_some()) {
        (false, _) => AuthKind::Certificate,
        (true, false) => AuthKind::UserPass,
        (true, true) => AuthKind::UserPassChallenge,
    };

    Ok(ParsedConfig {
        remotes,
        auth,
        challenge,
        dev_type,
        key_encrypted,
        sanitized: out,
    })
}

/// Largest block of extra options we accept.
pub const MAX_EXTRA_BYTES: usize = 8 * 1024;

/// Directives that would change how the daemon talks to OpenVPN or
/// contradict what it learned from the profile.
const NOT_IN_EXTRA: &[&str] = &[
    "auth-user-pass",
    "static-challenge",
    "dev",
    "dev-type",
    "auth-retry",
    "auth-nocache",
    "route-noexec",
    "dns-updown",
];

/// Check user-supplied extra options (one directive per line, no inline
/// blocks) and return them normalized.
pub fn sanitize_extra(text: &str) -> Result<String, ConfigError> {
    if text.len() > MAX_EXTRA_BYTES {
        return Err(ConfigError::TooLarge);
    }
    let mut out = String::new();
    for item in split_items(text)? {
        match item {
            Item::Other(raw) => {
                if !raw.trim().is_empty() {
                    out.push_str(raw.trim());
                    out.push('\n');
                }
            }
            Item::Block { line, tag, .. } => return Err(ConfigError::BlockInExtra { tag, line }),
            Item::Directive { line, raw, words } => {
                let name = check_safe(&words, line)?;
                if NOT_IN_EXTRA.contains(&name.as_str()) {
                    return Err(ConfigError::NotInExtra {
                        directive: name,
                        line,
                    });
                }
                out.push_str(raw.trim());
                out.push('\n');
            }
        }
    }
    Ok(out)
}

const PROXY_DIRECTIVES: &[&str] = &[
    "http-proxy",
    "http-proxy-option",
    "http-proxy-user-pass",
    "http-proxy-retry",
    "http-proxy-timeout",
    "socks-proxy",
    "socks-proxy-retry",
];

/// Remove a (sanitized) config's own proxy settings, so a proxy chosen in
/// the app replaces them instead of clashing.
pub fn strip_proxies(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_creds = false;
    for raw in text.lines() {
        let t = raw.trim();
        if in_creds {
            in_creds = !t.eq_ignore_ascii_case("</http-proxy-user-pass>");
            continue;
        }
        if t.eq_ignore_ascii_case("<http-proxy-user-pass>") {
            in_creds = true;
            continue;
        }
        let first = t
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_start_matches("--")
            .to_ascii_lowercase();
        if PROXY_DIRECTIVES.contains(&first.as_str()) {
            continue;
        }
        out.push_str(raw);
        out.push('\n');
    }
    out
}

/// Host names in the top-level `remote` lines that OpenVPN would have to
/// resolve. Empty when the config should be left alone: a proxy resolves
/// names itself, and `<connection>` blocks hold one remote each.
pub fn remote_hosts(text: &str) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let first = words
            .first()
            .map(|w| w.trim_start_matches("--").to_ascii_lowercase())
            .unwrap_or_default();
        if first == "<connection>"
            || first == "remote-random-hostname"
            || PROXY_DIRECTIVES.contains(&first.as_str())
        {
            return Vec::new();
        }
        if first == "remote"
            && let Some(host) = words.get(1)
            && host.parse::<std::net::IpAddr>().is_err()
            && !hosts.iter().any(|h| h.eq_ignore_ascii_case(host))
        {
            hosts.push(host.to_string());
        }
    }
    hosts
}

/// Replace each `remote <host>` line with one line per address the host
/// resolved to (`None` = it didn't resolve, so the line is dropped).
/// Returns the text unchanged if that would leave no remote at all.
pub fn pin_remotes(text: &str, resolve: impl Fn(&str) -> Option<Vec<std::net::IpAddr>>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut remotes = 0;
    for raw in text.lines() {
        let words: Vec<&str> = raw.split_whitespace().collect();
        let is_remote = words
            .first()
            .is_some_and(|w| w.trim_start_matches("--").eq_ignore_ascii_case("remote"));
        let host = words.get(1).copied().unwrap_or("");
        if !is_remote || host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
            remotes += usize::from(is_remote);
            out.push_str(raw);
            out.push('\n');
            continue;
        }
        let rest = words[2..].join(" ");
        match resolve(host) {
            Some(addrs) if !addrs.is_empty() => {
                out.push_str(&format!("# Portal: {host} resolved in advance\n"));
                for ip in addrs {
                    remotes += 1;
                    out.push_str(format!("remote {ip} {rest}").trim_end());
                    out.push('\n');
                }
            }
            _ => out.push_str(&format!("# Portal: skipped {host}, it didn't resolve\n")),
        }
    }
    if remotes == 0 { text.to_string() } else { out }
}

/// Replace file references (`ca ca.crt`, `tls-auth ta.key 1`, ...) with inline
/// blocks, reading each file relative to `base_dir`. Run this on the client
/// side, as the user, before sending a config to the daemon.
pub fn inline_files(text: &str, base_dir: &Path) -> Result<String, ConfigError> {
    let mut out = String::with_capacity(text.len());
    let mut in_block = false;
    for (idx, raw) in text.lines().enumerate() {
        let trimmed = raw.trim();
        if trimmed.starts_with('<') && trimmed.ends_with('>') {
            in_block = !trimmed.starts_with("</");
            out.push_str(raw);
            out.push('\n');
            continue;
        }
        if in_block || trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            out.push_str(raw);
            out.push('\n');
            continue;
        }
        let Some(words) = tokenize(trimmed) else {
            return Err(ConfigError::UnterminatedQuote { line: idx + 1 });
        };
        let name = words[0].trim_start_matches("--").to_ascii_lowercase();
        let is_file = FILE_DIRECTIVES.contains(&name.as_str());
        match words.get(1) {
            Some(arg) if is_file && arg != "[inline]" => {
                let path = base_dir.join(arg);
                let body = read_small(&path)?;
                out.push_str(&format!("<{name}>\n{}\n</{name}>\n", body.trim_end()));
                if name == "tls-auth"
                    && let Some(dir) = words.get(2)
                {
                    out.push_str(&format!("key-direction {dir}\n"));
                }
            }
            _ => {
                out.push_str(raw);
                out.push('\n');
            }
        }
    }
    Ok(out)
}

fn read_small(path: &Path) -> Result<String, ConfigError> {
    let err = |reason: String| ConfigError::Read {
        path: path.display().to_string(),
        reason,
    };
    let meta = std::fs::metadata(path).map_err(|e| err(e.to_string()))?;
    if meta.len() as usize > MAX_CONFIG_BYTES {
        return Err(err("file is too large".into()));
    }
    std::fs::read_to_string(path).map_err(|e| err(e.to_string()))
}

const ISO_COUNTRIES: &str = "ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bl bm bn bo bq br bs bt bv bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg eh er es et fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mf mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sj sk sl sm sn so sr ss st sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug um us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw";

/// Guess a country code from host and file names such as `de-fra-02.example`,
/// `us1.vpn.example` or `nl.ovpn`. Returns an upper-case ISO code.
pub fn guess_country(candidates: &[&str]) -> Option<String> {
    for c in candidates {
        let lower = c.to_ascii_lowercase();
        let base = lower.rsplit('/').next().unwrap_or(&lower);
        let bytes = base.as_bytes();
        if bytes.len() < 2 || !bytes[0].is_ascii_alphabetic() || !bytes[1].is_ascii_alphabetic() {
            continue;
        }
        let boundary = bytes.get(2).is_none_or(|b| !b.is_ascii_alphabetic());
        if !boundary {
            continue;
        }
        let code = match &base[..2] {
            "uk" => "gb",
            other => other,
        };
        if ISO_COUNTRIES.split(' ').any(|c| c == code) {
            return Some(code.to_ascii_uppercase());
        }
    }
    None
}

#[cfg(test)]
mod tests {

    #[test]
    fn pins_remote_hosts_to_addresses() {
        let cfg = "client\nremote-random\nremote 198.51.100.1 443 udp\nremote vpn.example 1194 tcp\nremote dead.example 1194\n";
        assert_eq!(remote_hosts(cfg), vec!["vpn.example", "dead.example"]);
        let out = pin_remotes(cfg, |h| match h {
            "vpn.example" => Some(vec![
                "203.0.113.5".parse().unwrap(),
                "203.0.113.6".parse().unwrap(),
            ]),
            _ => None,
        });
        assert!(out.contains("remote 198.51.100.1 443 udp\n"));
        assert!(out.contains("remote 203.0.113.5 1194 tcp\nremote 203.0.113.6 1194 tcp\n"));
        assert!(!out.contains("remote dead.example"));
        assert!(out.contains("remote-random\n"));
    }

    #[test]
    fn keeps_the_config_when_nothing_would_be_left() {
        let cfg = "client\nremote dead.example 1194\n";
        assert_eq!(pin_remotes(cfg, |_| None), cfg);
        assert!(remote_hosts("remote a.example\nhttp-proxy p 8080\n").is_empty());
        assert!(remote_hosts("<connection>\nremote a.example\n</connection>\n").is_empty());
    }

    use super::*;

    const BASIC: &str = "client\ndev tun\nproto udp\nremote de-fra-02.example.net 1194\nremote-cert-tls server\nauth-user-pass\n<ca>\n-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n</ca>\n";

    #[test]
    fn parses_basic_profile() {
        let p = sanitize(BASIC).unwrap();
        assert_eq!(
            p.primary(),
            &Remote {
                host: "de-fra-02.example.net".into(),
                port: 1194,
                proto: "udp".into()
            }
        );
        assert_eq!(p.auth, AuthKind::UserPass);
        assert!(p.sanitized.contains("<ca>"));
    }

    #[test]
    fn remote_inherits_port_and_proto() {
        let p = sanitize(
            "client\nproto tcp-client\nport 443\nremote a.example\nremote b.example 8443 udp\n",
        )
        .unwrap();
        assert_eq!(
            p.remotes[0],
            Remote {
                host: "a.example".into(),
                port: 443,
                proto: "tcp".into()
            }
        );
        assert_eq!(
            p.remotes[1],
            Remote {
                host: "b.example".into(),
                port: 8443,
                proto: "udp".into()
            }
        );
        assert_eq!(p.auth, AuthKind::Certificate);
    }

    #[test]
    fn rejects_script_hooks() {
        for d in [
            "up /tmp/x.sh",
            "script-security 2",
            "plugin /lib/evil.so",
            "--down x",
            "management 0.0.0.0 7505",
        ] {
            let cfg = format!("client\nremote a.example\n{d}\n");
            assert!(
                matches!(sanitize(&cfg), Err(ConfigError::Forbidden { line: 3, .. })),
                "{d}"
            );
        }
    }

    #[test]
    fn rejects_hooks_inside_connection_blocks() {
        let cfg = "client\n<connection>\nremote a.example 1194 udp\nup /tmp/x\n</connection>\n";
        assert!(matches!(
            sanitize(cfg),
            Err(ConfigError::Forbidden { line: 4, .. })
        ));
    }

    #[test]
    fn rejects_external_files() {
        let err = sanitize("client\nremote a.example\nca /etc/shadow\n").unwrap_err();
        assert_eq!(
            err,
            ConfigError::ExternalFile {
                directive: "ca".into(),
                line: 3
            }
        );
    }

    #[test]
    fn strips_auth_file_argument() {
        let p = sanitize("client\nremote a.example\nauth-user-pass /root/creds.txt\n").unwrap();
        assert!(p.sanitized.contains("auth-user-pass\n"));
        assert!(!p.sanitized.contains("creds.txt"));
    }

    #[test]
    fn detects_static_challenge() {
        let p = sanitize(
            "client\nremote a.example\nauth-user-pass\nstatic-challenge \"Enter OTP\" 1\n",
        )
        .unwrap();
        assert_eq!(p.auth, AuthKind::UserPassChallenge);
        assert_eq!(p.challenge.as_deref(), Some("Enter OTP"));
    }

    #[test]
    fn detects_device_type() {
        assert_eq!(
            sanitize("client\nremote a\ndev tun0\n").unwrap().dev_type,
            "tun"
        );
        assert_eq!(
            sanitize("client\nremote a\ndev tap\n").unwrap().dev_type,
            "tap"
        );
        assert_eq!(
            sanitize("client\nremote a\ndev vpn\ndev-type tap\n")
                .unwrap()
                .dev_type,
            "tap"
        );
    }

    #[test]
    fn requires_a_remote() {
        assert_eq!(
            sanitize("client\ndev tun\n").unwrap_err(),
            ConfigError::NoRemote
        );
    }

    #[test]
    fn reports_unterminated_blocks() {
        assert!(matches!(
            sanitize("client\nremote a\n<ca>\nAAA\n"),
            Err(ConfigError::UnterminatedBlock { line: 3, .. })
        ));
    }

    #[test]
    fn ignores_comments_and_quotes() {
        let p = sanitize("# up /x\n; plugin y\nclient\nremote \"a b.example\" 1194 # trailing\n")
            .unwrap();
        assert_eq!(p.primary().host, "a b.example");
    }

    #[test]
    fn inlines_referenced_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ca.crt"), "CA-DATA\n").unwrap();
        std::fs::write(dir.path().join("ta.key"), "TA-DATA\n").unwrap();
        let out = inline_files(
            "client\nremote a.example\nca ca.crt\ntls-auth ta.key 1\n",
            dir.path(),
        )
        .unwrap();
        assert!(out.contains("<ca>\nCA-DATA\n</ca>"));
        assert!(out.contains("<tls-auth>\nTA-DATA\n</tls-auth>\nkey-direction 1"));
        assert!(sanitize(&out).is_ok());
    }

    #[test]
    fn detects_encrypted_keys() {
        let enc = "client\nremote a\n<key>\n-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAA\n-----END ENCRYPTED PRIVATE KEY-----\n</key>\n";
        assert!(sanitize(enc).unwrap().key_encrypted);
        let old = "client\nremote a\n<key>\n-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nAAA\n</key>\n";
        assert!(sanitize(old).unwrap().key_encrypted);
        let plain = "client\nremote a\n<key>\n-----BEGIN PRIVATE KEY-----\nAAA\n</key>\n";
        assert!(!sanitize(plain).unwrap().key_encrypted);
    }

    #[test]
    fn proxy_credentials_must_come_from_the_user() {
        assert!(sanitize("client\nremote a\nhttp-proxy p.example 8080\n").is_ok());
        assert!(sanitize("client\nremote a\nhttp-proxy p.example 8080 auto ntlm\n").is_ok());
        assert!(sanitize("client\nremote a\nsocks-proxy p.example 1080 stdin\n").is_ok());
        for d in [
            "http-proxy p.example 8080 /root/creds",
            "socks-proxy p.example 1080 /etc/shadow",
        ] {
            let cfg = format!("client\nremote a\n{d}\n");
            assert!(
                matches!(
                    sanitize(&cfg),
                    Err(ConfigError::ExternalFile { line: 3, .. })
                ),
                "{d}"
            );
        }
    }

    #[test]
    fn checks_extra_options() {
        assert_eq!(
            sanitize_extra("  mssfix 1400\n\n# note\ntun-mtu 1500  \n").unwrap(),
            "mssfix 1400\n# note\ntun-mtu 1500\n"
        );
        assert!(matches!(
            sanitize_extra("mssfix 1400\nup /bin/sh\n"),
            Err(ConfigError::Forbidden { line: 2, .. })
        ));
        assert!(matches!(
            sanitize_extra("ca /etc/ssl/ca.pem"),
            Err(ConfigError::ExternalFile { .. })
        ));
        assert!(matches!(
            sanitize_extra("<ca>\nAAA\n</ca>\n"),
            Err(ConfigError::BlockInExtra { .. })
        ));
        assert!(matches!(
            sanitize_extra("dev tap0"),
            Err(ConfigError::NotInExtra { .. })
        ));
    }

    #[test]
    fn strips_profile_proxies() {
        let cfg = "client\nremote a\nhttp-proxy p 8080 auto\nhttp-proxy-option VERSION 1.1\n<http-proxy-user-pass>\nu\np\n</http-proxy-user-pass>\n<connection>\nremote b\nsocks-proxy s 1080\n</connection>\n";
        let out = strip_proxies(cfg);
        assert_eq!(
            out,
            "client\nremote a\n<connection>\nremote b\n</connection>\n"
        );
    }

    #[test]
    fn guesses_countries() {
        assert_eq!(
            guess_country(&["de-fra-02.example.net"]).as_deref(),
            Some("DE")
        );
        assert_eq!(guess_country(&["us1.vpn.example"]).as_deref(), Some("US"));
        assert_eq!(guess_country(&["uk-lon.ovpn"]).as_deref(), Some("GB"));
        assert_eq!(guess_country(&["vpn.office.example", "office.ovpn"]), None);
    }
}
