//! Client-side proxy for the daemon's D-Bus interface.

use zbus::proxy;

/// Typed client for `org.tunnelvpn.Daemon1`.
///
/// Payloads are JSON: `list_profiles` returns `[Profile]`, `import_profile`
/// returns `Profile`, `get_status` and the `status_changed` signal carry a
/// `Status`.
#[proxy(
    interface = "org.tunnelvpn.Daemon1",
    default_service = "org.tunnelvpn.Daemon1",
    default_path = "/org/tunnelvpn/Daemon1"
)]
pub trait Daemon {
    fn list_profiles(&self) -> zbus::Result<String>;

    /// `file_name` is only used for display and country guessing; `content`
    /// must already have its file references inlined.
    fn import_profile(&self, file_name: &str, content: &str) -> zbus::Result<String>;

    fn update_profile(
        &self,
        id: &str,
        name: &str,
        group: &str,
        country: &str,
    ) -> zbus::Result<String>;

    fn remove_profile(&self, id: &str) -> zbus::Result<()>;

    /// Credentials may be empty for certificate-only profiles. `response` is
    /// the answer to a static challenge (OTP), empty if none.
    fn connect(&self, id: &str, username: &str, password: &str, response: &str)
    -> zbus::Result<()>;

    fn disconnect(&self) -> zbus::Result<()>;

    fn get_status(&self) -> zbus::Result<String>;

    /// Recent OpenVPN log lines, oldest first.
    fn get_log(&self) -> zbus::Result<Vec<String>>;

    /// Version of the running daemon (the installed package version).
    fn version(&self) -> zbus::Result<String>;

    /// Install a release `.deb`, passed as an open file, with its minisign
    /// signature. Returns the version being installed. The daemon restarts
    /// when the install finishes.
    fn install_update(
        &self,
        package: zbus::zvariant::Fd<'_>,
        signature: &str,
    ) -> zbus::Result<String>;

    #[zbus(signal)]
    fn status_changed(&self, status: String) -> zbus::Result<()>;

    #[zbus(signal)]
    fn log_line(&self, line: String) -> zbus::Result<()>;
}
