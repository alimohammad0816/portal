//! Data sent between the daemon and its clients. Everything crosses D-Bus as
//! JSON strings, which keeps optional fields simple and lets the desktop app
//! hand the same payloads straight to the web frontend.

use serde::{Deserialize, Serialize};

/// How a profile authenticates, as far as the client has to care.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    /// Certificate/key only; nothing to ask the user.
    Certificate,
    /// `auth-user-pass`: the user must supply a username and password.
    UserPass,
    /// `auth-user-pass` plus `static-challenge` (OTP or similar).
    UserPassChallenge,
}

impl AuthKind {
    pub fn needs_credentials(self) -> bool {
        !matches!(self, AuthKind::Certificate)
    }
}

/// An imported OpenVPN profile, as shown to the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    /// Display name, editable by the user.
    pub name: String,
    /// Group shown as a section in the location list.
    pub group: String,
    /// ISO 3166-1 alpha-2 country code, if known or guessed.
    pub country: Option<String>,
    /// First `remote` of the config.
    pub remote_host: String,
    pub remote_port: u16,
    /// `udp` or `tcp`.
    pub proto: String,
    pub auth: AuthKind,
    /// Text of `static-challenge`, if any.
    pub challenge: Option<String>,
    /// Original file name at import time.
    pub source_file: String,
    /// Unix seconds.
    pub imported_at: u64,
    /// Unix seconds of the last successful connection.
    pub last_connected_at: Option<u64>,
    /// The private key is protected by a passphrase.
    #[serde(default)]
    pub key_encrypted: bool,
    /// Run without OpenVPN's kernel data channel offload (DCO).
    #[serde(default)]
    pub disable_dco: bool,
    /// Extra OpenVPN directives, one per line, added after the profile's
    /// own. Checked with [`crate::ovpn::sanitize_extra`].
    #[serde(default)]
    pub extra_directives: String,
}

/// Changes to a profile; `None` leaves a field as it is.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProfileEdit {
    pub name: Option<String>,
    pub group: Option<String>,
    /// Two-letter code, or `-` to clear it.
    pub country: Option<String>,
    pub disable_dco: Option<bool>,
    pub extra_directives: Option<String>,
}

/// Everything a connection may need from the user. Empty fields mean
/// "not given"; OpenVPN asks for what it needs, and the daemon reports a
/// [`InputRequest`] when something is missing.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Secrets {
    pub username: String,
    pub password: String,
    /// Static challenge response (OTP), if the profile has one.
    pub response: Option<String>,
    /// Passphrase of the profile's private key.
    pub key_passphrase: Option<String>,
    /// Sign-in for the proxy the connection goes through.
    pub proxy_username: Option<String>,
    pub proxy_password: Option<String>,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let set = |o: &Option<String>| o.as_ref().map(|_| "<set>");
        f.debug_struct("Secrets")
            .field("username", &self.username)
            .field("password", &(!self.password.is_empty()).then_some("<set>"))
            .field("response", &set(&self.response))
            .field("key_passphrase", &set(&self.key_passphrase))
            .field("proxy_username", &self.proxy_username)
            .field("proxy_password", &set(&self.proxy_password))
            .finish()
    }
}

/// What the connection is waiting for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    /// Username and password.
    Login,
    /// The private key's passphrase.
    KeyPassphrase,
    /// Username and password for the proxy.
    ProxyLogin,
    /// An answer to a question from the server (`message`), sent with
    /// `AnswerChallenge`.
    Challenge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputRequest {
    pub kind: InputKind,
    /// Text from the server, for challenges.
    pub message: Option<String>,
    /// The answer may be shown while typing (not a secret).
    pub echo: bool,
}

/// Connection state machine as reported to clients.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnState {
    #[default]
    Disconnected,
    Connecting,
    /// Waiting for the client to answer a credentials request.
    NeedsCredentials,
    Connected,
    Disconnecting,
}

/// Snapshot of the daemon's connection status.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Status {
    pub state: ConnState,
    /// Profile in use (or last used, when disconnected with an error).
    pub profile_id: Option<String>,
    /// Raw OpenVPN state name (`WAIT`, `AUTH`, `GET_CONFIG`, ...).
    pub detail: Option<String>,
    /// Unix seconds when the tunnel came up.
    pub connected_since: Option<u64>,
    /// Address assigned on the tunnel interface.
    pub tunnel_ip: Option<String>,
    /// Address of the VPN server we are talking to.
    pub server_ip: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Bytes per second, averaged over the last report interval.
    pub rate_in: u64,
    pub rate_out: u64,
    /// Why the last attempt failed, if it did.
    pub error: Option<String>,
    /// The kill switch rules are loaded right now.
    #[serde(default)]
    pub firewall_active: bool,
    /// Traffic outside the tunnel is blocked and there is no tunnel: the
    /// kill switch is holding after a drop, or the firewall is always on.
    #[serde(default)]
    pub internet_blocked: bool,
    /// DNS servers in use for the tunnel, once connected.
    #[serde(default)]
    pub dns_servers: Vec<String>,
    /// Split tunneling rules are applied to the running connection.
    #[serde(default)]
    pub split_active: bool,
    /// Split settings changed in a way that needs a reconnect (switching
    /// to or from include mode).
    #[serde(default)]
    pub split_needs_reconnect: bool,
    /// Split rules changed in a way open connections don't follow yet
    /// (removed rules, apps); `ApplySplit` closes them so they reconnect.
    #[serde(default)]
    pub split_pending: bool,
    /// Processes currently split by app rules or `portal bypass`.
    #[serde(default)]
    pub split_processes: usize,
    /// Where the proxy gateway listens (`192.168.1.50:1080`) while it runs.
    #[serde(default)]
    pub proxy_address: Option<String>,
    /// With `state` = `needs_credentials`: what to ask the user for.
    #[serde(default)]
    pub request: Option<InputRequest>,
    /// The server wants you to sign in on a web page (SSO).
    #[serde(default)]
    pub auth_url: Option<String>,
}

/// How OpenVPN reaches the server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyKind {
    /// Directly, or through whatever proxy the profile names.
    #[default]
    Profile,
    Http,
    Socks,
}

/// Connect to VPN servers through a proxy (e.g. on networks that only
/// allow web traffic). The proxy's password, if any, comes with each
/// connect and is never stored by the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectionProxy {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    /// The proxy asks for a username and password.
    pub auth: bool,
}

impl Default for ConnectionProxy {
    fn default() -> Self {
        Self {
            kind: ProxyKind::Profile,
            host: String::new(),
            port: 8080,
            auth: false,
        }
    }
}

impl ConnectionProxy {
    pub fn active(&self) -> bool {
        self.kind != ProxyKind::Profile
    }

    /// Directives that send the connection through this proxy.
    pub fn directives(&self) -> Option<String> {
        let (host, port) = (&self.host, self.port);
        match self.kind {
            ProxyKind::Profile => None,
            // `auto` asks for a password (over the management socket) only
            // if the proxy wants one, and picks Basic, Digest or NTLM.
            ProxyKind::Http if self.auth => Some(format!("http-proxy {host} {port} auto\n")),
            ProxyKind::Http => Some(format!("http-proxy {host} {port}\n")),
            ProxyKind::Socks if self.auth => Some(format!("socks-proxy {host} {port} stdin\n")),
            ProxyKind::Socks => Some(format!("socks-proxy {host} {port}\n")),
        }
    }
}

/// Share the VPN with other devices on the LAN through a proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyGateway {
    pub enabled: bool,
    /// One port for both SOCKS5 and HTTP.
    pub port: u16,
}

impl Default for ProxyGateway {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 1080,
        }
    }
}

/// When the kill switch blocks traffic outside the tunnel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallMode {
    /// Never.
    Off,
    /// While connecting or connected, and after the tunnel drops until you
    /// disconnect.
    #[default]
    Auto,
    /// Always, even when disconnected. Only the tunnel (and the LAN, if
    /// allowed) can be reached.
    Always,
}

/// Which DNS servers to use while connected.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode", content = "servers")]
pub enum DnsMode {
    /// Servers pushed by the VPN server.
    #[default]
    Vpn,
    /// These servers, reached through the tunnel.
    Custom(Vec<String>),
}

/// Daemon-wide settings, stored by `portald`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub firewall: FirewallMode,
    /// Let traffic to private and link-local networks bypass the firewall.
    pub allow_lan: bool,
    /// Block IPv6 outside the tunnel while connected, so dual-stack sites
    /// can't leak around an IPv4-only VPN.
    pub block_ipv6: bool,
    pub dns: DnsMode,
    /// While connected, send all DNS through the tunnel and block port 53
    /// and 853 everywhere else.
    pub dns_leak_protection: bool,
    pub split: SplitSettings,
    pub proxy_gateway: ProxyGateway,
    pub connection_proxy: ConnectionProxy,
}

/// Which side of the tunnel the listed traffic goes to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitMode {
    /// Everything uses the VPN except the listed apps and hosts.
    #[default]
    Exclude,
    /// Only the listed apps and hosts use the VPN.
    Include,
}

/// An app whose traffic is split, matched by executable name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitApp {
    pub name: String,
    /// Executable path as installed, e.g. `/usr/bin/telegram-desktop`.
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SplitSettings {
    pub enabled: bool,
    pub mode: SplitMode,
    pub apps: Vec<SplitApp>,
    /// Domains (`example.com` is just that name, `*.example.com` its
    /// subdomains, `*.ir` a whole TLD), IP addresses and CIDR blocks.
    pub hosts: Vec<String>,
    /// ISO country codes whose IP ranges are split, e.g. `IR`.
    pub countries: Vec<String>,
    /// Meaning of `hosts`; see `migrate`. Missing (older files and
    /// clients) means 0, while new settings start at the current version.
    #[serde(default)]
    pub rules_version: u32,
}

impl Default for SplitSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: SplitMode::default(),
            apps: Vec::new(),
            hosts: Vec::new(),
            countries: Vec::new(),
            rules_version: Self::RULES_VERSION,
        }
    }
}

impl SplitSettings {
    pub const RULES_VERSION: u32 = 1;

    /// Bring hosts saved (or sent by an older client) under an earlier
    /// meaning up to date. Version 0: a domain also covered its subdomains.
    pub fn migrate(&mut self) {
        if self.rules_version < 1 {
            self.hosts = crate::split::migrate_hosts_v1(&self.hosts);
        }
        self.rules_version = Self::RULES_VERSION;
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            firewall: FirewallMode::Auto,
            allow_lan: true,
            block_ipv6: true,
            dns: DnsMode::Vpn,
            dns_leak_protection: true,
            split: SplitSettings::default(),
            proxy_gateway: ProxyGateway::default(),
            connection_proxy: ConnectionProxy::default(),
        }
    }
}

impl Settings {
    /// Check values that came from a client.
    pub fn validate(&self) -> Result<(), String> {
        if self.proxy_gateway.port < 1024 {
            return Err("Use a proxy port from 1024 up.".into());
        }
        let cp = &self.connection_proxy;
        if cp.active() {
            let host_ok = !cp.host.is_empty()
                && cp.host.len() <= 253
                && cp
                    .host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'));
            if !host_ok {
                return Err("Enter the proxy's host name or IP address.".into());
            }
            if cp.port == 0 {
                return Err("Enter the proxy's port.".into());
            }
        }
        if self.split.apps.len() > 200
            || self.split.hosts.len() > 2000
            || self.split.countries.len() > 20
        {
            return Err("That's too many split tunneling rules.".into());
        }
        for h in &self.split.hosts {
            crate::split::Rule::parse(h)?;
        }
        for c in &self.split.countries {
            if c.len() != 2 || !c.chars().all(|ch| ch.is_ascii_uppercase()) {
                return Err(format!("`{c}` isn't a two-letter country code."));
            }
        }
        for a in &self.split.apps {
            if !a.path.starts_with('/') || a.path.contains('\n') {
                return Err(format!("`{}` isn't an absolute path.", a.path));
            }
        }
        if let DnsMode::Custom(servers) = &self.dns {
            if servers.is_empty() {
                return Err("Add at least one DNS server.".into());
            }
            if servers.len() > 4 {
                return Err("Use at most four DNS servers.".into());
            }
            for s in servers {
                if s.parse::<std::net::IpAddr>().is_err() {
                    return Err(format!("`{s}` isn't an IP address."));
                }
            }
        }
        Ok(())
    }
}
