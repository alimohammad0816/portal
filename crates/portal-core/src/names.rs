//! Well-known names. Kept in one place so the product name can change
//! without hunting through three binaries and the packaging files.

/// Bus name the daemon owns on the system bus (or session bus in dev mode).
pub const BUS_NAME: &str = "io.github.alimohammad0816.Portal.Daemon1";
/// Object path of the single daemon object.
pub const OBJECT_PATH: &str = "/io/github/alimohammad0816/Portal/Daemon1";
/// D-Bus interface name.
pub const INTERFACE: &str = "io.github.alimohammad0816.Portal.Daemon1";

/// polkit action for connecting and disconnecting.
pub const ACTION_CONNECT: &str = "io.github.alimohammad0816.Portal.connect";
/// polkit action for importing, editing and removing profiles.
pub const ACTION_MANAGE_PROFILES: &str = "io.github.alimohammad0816.Portal.manage-profiles";
/// polkit action for changing firewall and DNS settings.
pub const ACTION_SETTINGS: &str = "io.github.alimohammad0816.Portal.change-settings";
/// Name of the tunnel interface the daemon creates.
pub const TUNNEL_IFACE: &str = "portal0";
/// polkit action for installing a signed app update.
pub const ACTION_UPDATE: &str = "io.github.alimohammad0816.Portal.update";

/// GitHub `owner/repo` that publishes releases, baked in at build time by
/// the release workflow. `None` in local builds: update checks are off.
pub const UPDATE_REPO: Option<&str> = option_env!("PORTAL_UPDATE_REPO");
