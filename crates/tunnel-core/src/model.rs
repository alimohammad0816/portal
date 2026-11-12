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
}
