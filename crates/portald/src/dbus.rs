//! The `io.github.alimohammad0816.Portal.Daemon1` D-Bus object and polkit authorization.

use std::collections::HashMap;

use portal_core::names::{ACTION_CONNECT, ACTION_MANAGE_PROFILES, ACTION_SETTINGS, ACTION_UPDATE};
use portal_core::{ProfileEdit, Settings};
use zbus::message::Header;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::Value;
use zbus::{Connection, fdo, interface, proxy};

use crate::backend::Credentials;
use crate::manager::Shared;

#[proxy(
    interface = "org.freedesktop.PolicyKit1.Authority",
    default_service = "org.freedesktop.PolicyKit1",
    default_path = "/org/freedesktop/PolicyKit1/Authority"
)]
trait Authority {
    fn check_authorization(
        &self,
        subject: &(&str, HashMap<&str, Value<'_>>),
        action_id: &str,
        details: &HashMap<&str, &str>,
        flags: u32,
        cancellation_id: &str,
    ) -> zbus::Result<(bool, bool, HashMap<String, String>)>;
}

pub struct DaemonIface {
    pub mgr: Shared,
    /// Check polkit before privileged calls. Off on the session bus, where
    /// only the user's own processes can reach us anyway.
    pub use_polkit: bool,
    /// Where verified update packages are staged.
    pub cache_dir: std::path::PathBuf,
}

fn failed(e: anyhow::Error) -> fdo::Error {
    fdo::Error::Failed(format!("{e:#}"))
}

fn to_json<T: serde::Serialize>(v: &T) -> fdo::Result<String> {
    serde_json::to_string(v).map_err(|e| fdo::Error::Failed(e.to_string()))
}

impl DaemonIface {
    /// Stop the old session (without holding the lock) and start the new one.
    async fn connect_with(&self, id: &str, creds: Credentials) -> fdo::Result<()> {
        let old = self
            .mgr
            .lock()
            .await
            .begin_connect(id, &creds)
            .map_err(failed)?;
        if let Some(old) = old {
            old.stop().await;
        }
        self.mgr
            .lock()
            .await
            .finish_connect(id, creds)
            .map_err(failed)
    }

    async fn authorize(
        &self,
        conn: &Connection,
        hdr: &Header<'_>,
        action: &str,
    ) -> fdo::Result<()> {
        if !self.use_polkit {
            return Ok(());
        }
        let sender = hdr
            .sender()
            .ok_or_else(|| fdo::Error::AccessDenied("no sender".into()))?;
        let authority = AuthorityProxy::new(conn).await?;
        let subject = (
            "system-bus-name",
            HashMap::from([("name", Value::from(sender.as_str()))]),
        );
        // 1 = AllowUserInteraction: polkit may show a password prompt.
        let (ok, _, _) = authority
            .check_authorization(&subject, action, &HashMap::new(), 1, "")
            .await
            .map_err(|e| fdo::Error::AccessDenied(format!("polkit: {e}")))?;
        if ok {
            Ok(())
        } else {
            Err(fdo::Error::AccessDenied("Not authorized.".into()))
        }
    }
}

#[interface(name = "io.github.alimohammad0816.Portal.Daemon1")]
impl DaemonIface {
    async fn list_profiles(&self) -> fdo::Result<String> {
        to_json(&self.mgr.lock().await.profiles())
    }

    async fn import_profile(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
        file_name: String,
        content: String,
    ) -> fdo::Result<String> {
        self.authorize(conn, &hdr, ACTION_MANAGE_PROFILES).await?;
        let p = self
            .mgr
            .lock()
            .await
            .import(&file_name, &content)
            .map_err(failed)?;
        to_json(&p)
    }

    async fn update_profile(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
        id: String,
        edit: String,
    ) -> fdo::Result<String> {
        self.authorize(conn, &hdr, ACTION_MANAGE_PROFILES).await?;
        let edit: ProfileEdit =
            serde_json::from_str(&edit).map_err(|e| fdo::Error::InvalidArgs(e.to_string()))?;
        let p = self.mgr.lock().await.update(&id, &edit).map_err(failed)?;
        to_json(&p)
    }

    async fn remove_profile(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
        id: String,
    ) -> fdo::Result<()> {
        self.authorize(conn, &hdr, ACTION_MANAGE_PROFILES).await?;
        self.mgr.lock().await.remove(&id).map_err(failed)
    }

    async fn connect(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
        id: String,
        secrets: String,
    ) -> fdo::Result<()> {
        self.authorize(conn, &hdr, ACTION_CONNECT).await?;
        let mut creds: Credentials =
            serde_json::from_str(&secrets).map_err(|e| fdo::Error::InvalidArgs(e.to_string()))?;
        // Empty strings from simple clients mean "not given".
        for field in [
            &mut creds.response,
            &mut creds.key_passphrase,
            &mut creds.proxy_username,
            &mut creds.proxy_password,
        ] {
            if field.as_deref() == Some("") {
                *field = None;
            }
        }
        self.connect_with(&id, creds).await
    }

    async fn answer_challenge(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
        response: String,
    ) -> fdo::Result<()> {
        self.authorize(conn, &hdr, ACTION_CONNECT).await?;
        let restart = self.mgr.lock().await.answer(&response).map_err(failed)?;
        match restart {
            Some((id, creds)) => self.connect_with(&id, creds).await,
            None => Ok(()),
        }
    }

    async fn disconnect(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<()> {
        self.authorize(conn, &hdr, ACTION_CONNECT).await?;
        let handle = self.mgr.lock().await.begin_disconnect();
        if let Some(h) = handle {
            h.stop().await;
        }
        Ok(())
    }

    async fn get_status(&self) -> fdo::Result<String> {
        to_json(self.mgr.lock().await.status())
    }

    async fn get_log(&self) -> Vec<String> {
        self.mgr.lock().await.log()
    }

    /// Move the calling process into split tunneling (`portal bypass`).
    /// Children started afterwards inherit it.
    async fn split_self(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<()> {
        self.authorize(conn, &hdr, ACTION_CONNECT).await?;
        let sender = hdr
            .sender()
            .ok_or_else(|| fdo::Error::AccessDenied("no sender".into()))?
            .to_owned();
        let bus = fdo::DBusProxy::new(conn).await?;
        let pid = bus.get_connection_unix_process_id(sender.into()).await?;
        self.mgr.lock().await.bypass(pid).map_err(failed)
    }

    /// Close open connections that don't follow the current split rules
    /// yet, so their apps reconnect on the right side. Returns the count.
    async fn apply_split(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<u32> {
        self.authorize(conn, &hdr, ACTION_SETTINGS).await?;
        let n = self.mgr.lock().await.apply_split().map_err(failed)?;
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }

    async fn get_settings(&self) -> fdo::Result<String> {
        to_json(self.mgr.lock().await.settings())
    }

    async fn set_settings(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
        settings: String,
    ) -> fdo::Result<String> {
        self.authorize(conn, &hdr, ACTION_SETTINGS).await?;
        let new: Settings =
            serde_json::from_str(&settings).map_err(|e| fdo::Error::InvalidArgs(e.to_string()))?;
        let stored = self.mgr.lock().await.set_settings(new).map_err(failed)?;
        to_json(&stored)
    }

    async fn version(&self) -> String {
        crate::update::current_version().to_string()
    }

    async fn install_update(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
        package: zbus::zvariant::OwnedFd,
        signature: String,
    ) -> fdo::Result<String> {
        self.authorize(conn, &hdr, ACTION_UPDATE).await?;
        let file = std::fs::File::from(std::os::fd::OwnedFd::from(package));
        let cache = self.cache_dir.clone();
        tokio::task::spawn_blocking(move || crate::update::install(file, &signature, &cache))
            .await
            .map_err(|e| fdo::Error::Failed(e.to_string()))?
            .map_err(failed)
    }

    #[zbus(signal)]
    pub async fn status_changed(emitter: &SignalEmitter<'_>, status: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn settings_changed(emitter: &SignalEmitter<'_>, settings: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn log_line(emitter: &SignalEmitter<'_>, line: &str) -> zbus::Result<()>;
}
