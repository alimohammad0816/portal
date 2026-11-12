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

/// Daemon-wide settings, stored by `tunneld`.
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
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            firewall: FirewallMode::Auto,
            allow_lan: true,
            block_ipv6: true,
            dns: DnsMode::Vpn,
            dns_leak_protection: true,
        }
    }
}

impl Settings {
    /// Check values that came from a client.
    pub fn validate(&self) -> Result<(), String> {
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
