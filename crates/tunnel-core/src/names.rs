//! Well-known names. Kept in one place so the product name can change
//! without hunting through three binaries and the packaging files.

/// Bus name the daemon owns on the system bus (or session bus in dev mode).
pub const BUS_NAME: &str = "org.tunnelvpn.Daemon1";
/// Object path of the single daemon object.
pub const OBJECT_PATH: &str = "/org/tunnelvpn/Daemon1";
/// D-Bus interface name.
pub const INTERFACE: &str = "org.tunnelvpn.Daemon1";

/// polkit action for connecting and disconnecting.
pub const ACTION_CONNECT: &str = "org.tunnelvpn.connect";
/// polkit action for importing, editing and removing profiles.
pub const ACTION_MANAGE_PROFILES: &str = "org.tunnelvpn.manage-profiles";
