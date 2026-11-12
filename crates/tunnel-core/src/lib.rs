//! Shared pieces used by the daemon (`tunneld`), the CLI (`tunnel`) and the
//! desktop app: the D-Bus contract, the data model sent over it, and the
//! OpenVPN config parser/sanitizer.

pub mod model;
pub mod names;
pub mod ovpn;
pub mod proxy;

pub use model::{AuthKind, ConnState, Profile, Status};
pub use proxy::DaemonProxy;
