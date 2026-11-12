//! Shared pieces used by the daemon (`tunneld`), the CLI (`tunnel`) and the
//! desktop app: the D-Bus contract, the data model sent over it, and the
//! OpenVPN config parser/sanitizer.

pub mod model;
pub mod names;
pub mod ovpn;
pub mod proxy;
pub mod split;

pub use model::{
    AuthKind, ConnState, ConnectionProxy, DnsMode, FirewallMode, InputKind, InputRequest, Profile,
    ProfileEdit, ProxyGateway, ProxyKind, Secrets, Settings, SplitApp, SplitMode, SplitSettings,
    Status,
};
pub use proxy::DaemonProxy;
