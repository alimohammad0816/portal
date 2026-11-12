//! Client-side proxy for the daemon's D-Bus interface.

use zbus::proxy;

/// Typed client for `io.github.alimohammad0816.Portal.Daemon1`.
///
/// Payloads are JSON: `list_profiles` returns `[Profile]`, `import_profile`
/// returns `Profile`, `get_status` and the `status_changed` signal carry a
/// `Status`.
#[proxy(
    interface = "io.github.alimohammad0816.Portal.Daemon1",
    default_service = "io.github.alimohammad0816.Portal.Daemon1",
    default_path = "/io/github/alimohammad0816/Portal/Daemon1"
)]
pub trait Daemon {
    fn list_profiles(&self) -> zbus::Result<String>;

    /// `file_name` is only used for display and country guessing; `content`
    /// must already have its file references inlined.
    fn import_profile(&self, file_name: &str, content: &str) -> zbus::Result<String>;

    /// `edit` is a JSON `ProfileEdit`; returns the updated `Profile`.
    fn update_profile(&self, id: &str, edit: &str) -> zbus::Result<String>;

    fn remove_profile(&self, id: &str) -> zbus::Result<()>;

    /// `secrets` is a JSON `Secrets`; `{}` for certificate-only profiles.
    /// If something is missing, the status turns `needs_credentials` with a
    /// `request` saying what.
    fn connect(&self, id: &str, secrets: &str) -> zbus::Result<()>;

    /// Answer the server's challenge (`request.kind` = `challenge`).
    fn answer_challenge(&self, response: &str) -> zbus::Result<()>;

    fn disconnect(&self) -> zbus::Result<()>;

    fn get_status(&self) -> zbus::Result<String>;

    /// Recent OpenVPN log lines, oldest first.
    fn get_log(&self) -> zbus::Result<Vec<String>>;

    /// Move the calling process (and its future children) into split
    /// tunneling.
    fn split_self(&self) -> zbus::Result<()>;
    fn apply_split(&self) -> zbus::Result<u32>;

    /// Current `Settings` as JSON.
    fn get_settings(&self) -> zbus::Result<String>;

    /// Replace the settings (JSON `Settings`); returns what was stored.
    /// Firewall and DNS changes apply immediately.
    fn set_settings(&self, settings: &str) -> zbus::Result<String>;

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

    #[zbus(signal)]
    fn settings_changed(&self, settings: String) -> zbus::Result<()>;
}
