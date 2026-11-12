//! Connection state machine. Owns the profile store and the current session,
//! turns backend events into a [`Status`], and publishes changes.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Result, anyhow, bail};
use tokio::sync::{Mutex, mpsc};
use tracing::info;
use tunnel_core::{ConnState, Profile, Status};

use crate::backend::{Backend, Credentials, Event, EventTx, SessionHandle};
use crate::profiles::ProfileStore;

const LOG_LINES: usize = 500;

/// Something clients should hear about.
#[derive(Debug, Clone)]
pub enum Notice {
    Status(Status),
    Log(String),
}

pub struct Manager {
    store: ProfileStore,
    backend: Arc<dyn Backend>,
    status: Status,
    session: Option<SessionHandle>,
    seq: u64,
    user_stopped: bool,
    last_bytes: Option<(Instant, u64, u64)>,
    log: VecDeque<String>,
    events: EventTx,
    notices: mpsc::UnboundedSender<Notice>,
}

pub type Shared = Arc<Mutex<Manager>>;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Manager {
    /// Build the manager and start the task that feeds it backend events.
    pub fn spawn(
        store: ProfileStore,
        backend: Arc<dyn Backend>,
        notices: mpsc::UnboundedSender<Notice>,
    ) -> Shared {
        let (events, mut rx) = mpsc::unbounded_channel();
        let mgr = Arc::new(Mutex::new(Manager {
            store,
            backend,
            status: Status::default(),
            session: None,
            seq: 0,
            user_stopped: false,
            last_bytes: None,
            log: VecDeque::with_capacity(LOG_LINES),
            events,
            notices,
        }));
        let weak = Arc::downgrade(&mgr);
        tokio::spawn(async move {
            while let Some((seq, event)) = rx.recv().await {
                let Some(mgr) = weak.upgrade() else { break };
                mgr.lock().await.on_event(seq, event);
            }
        });
        mgr
    }

    pub fn profiles(&self) -> &[Profile] {
        self.store.list()
    }

    pub fn status(&self) -> &Status {
        &self.status
    }

    pub fn log(&self) -> Vec<String> {
        self.log.iter().cloned().collect()
    }

    pub fn import(&mut self, file_name: &str, content: &str) -> Result<Profile> {
        let p = self.store.import(file_name, content)?;
        info!("imported profile {} ({})", p.name, p.id);
        Ok(p)
    }

    pub fn update(&mut self, id: &str, name: &str, group: &str, country: &str) -> Result<Profile> {
        self.store.update(id, name, group, country)
    }

    pub fn remove(&mut self, id: &str) -> Result<()> {
        if self.status.profile_id.as_deref() == Some(id) && self.session.is_some() {
            bail!("Disconnect before removing the profile in use.");
        }
        self.store.remove(id)
    }

    /// First half of connecting: validate, take the old session out so the
    /// caller can stop it without holding the lock, and show "connecting".
    pub fn begin_connect(
        &mut self,
        id: &str,
        creds: &Credentials,
    ) -> Result<Option<SessionHandle>> {
        if self.store.get(id).is_none() {
            bail!("No profile with id {id}.");
        }
        if self.store.needs_credentials(id) && creds.username.is_empty() {
            bail!("This profile needs a username and password.");
        }
        let old = self.session.take();
        self.seq += 1;
        self.user_stopped = false;
        self.last_bytes = None;
        self.status = Status {
            state: ConnState::Connecting,
            profile_id: Some(id.to_string()),
            ..Status::default()
        };
        self.publish();
        Ok(old)
    }

    /// Second half: start the new session (unless another connect or a
    /// disconnect happened while the old one was stopping).
    pub fn finish_connect(&mut self, id: &str, creds: Credentials) -> Result<()> {
        if self.status.profile_id.as_deref() != Some(id)
            || self.status.state != ConnState::Connecting
        {
            return Ok(());
        }
        let config = self
            .store
            .config_path(id)
            .ok_or_else(|| anyhow!("profile disappeared"))?;
        match self
            .backend
            .start(self.seq, config, creds, self.events.clone())
        {
            Ok(handle) => {
                self.session = Some(handle);
                Ok(())
            }
            Err(e) => {
                self.status.state = ConnState::Disconnected;
                self.status.error = Some(format!("{e:#}"));
                self.publish();
                Err(e)
            }
        }
    }

    pub fn begin_disconnect(&mut self) -> Option<SessionHandle> {
        let handle = self.session.take()?;
        self.user_stopped = true;
        self.status.state = ConnState::Disconnecting;
        self.publish();
        Some(handle)
    }

    fn on_event(&mut self, seq: u64, event: Event) {
        if let Event::Log(line) = &event {
            self.push_log(line.clone());
        }
        if seq != self.seq {
            return;
        }
        match event {
            Event::State {
                name,
                tunnel_ip,
                server_ip,
            } => {
                match name.as_str() {
                    "CONNECTED" => {
                        self.status.state = ConnState::Connected;
                        self.status.connected_since = Some(now());
                        self.status.tunnel_ip = tunnel_ip;
                        self.status.server_ip = server_ip;
                        self.status.error = None;
                        if let Some(id) = self.status.profile_id.clone() {
                            self.store.mark_connected(&id);
                        }
                    }
                    "EXITING" => self.status.state = ConnState::Disconnecting,
                    _ if self.status.state != ConnState::Disconnecting => {
                        self.status.state = ConnState::Connecting;
                        self.status.connected_since = None;
                    }
                    _ => {}
                }
                self.status.detail = Some(name);
                self.publish();
            }
            Event::Bytes { rx, tx } => {
                let t = Instant::now();
                if let Some((t0, rx0, tx0)) = self.last_bytes {
                    let secs = t.duration_since(t0).as_secs_f64().max(0.25);
                    self.status.rate_in = (rx.saturating_sub(rx0) as f64 / secs) as u64;
                    self.status.rate_out = (tx.saturating_sub(tx0) as f64 / secs) as u64;
                }
                self.last_bytes = Some((t, rx, tx));
                self.status.bytes_in = rx;
                self.status.bytes_out = tx;
                self.publish();
            }
            Event::Fatal(msg) => {
                self.status.error = Some(msg);
                self.publish();
            }
            Event::Exited => {
                self.session = None;
                let error = self.status.error.take().or_else(|| {
                    (!self.user_stopped).then(|| {
                        "The connection ended unexpectedly. See the log for details.".into()
                    })
                });
                self.status = Status {
                    state: ConnState::Disconnected,
                    profile_id: self.status.profile_id.take(),
                    error,
                    ..Status::default()
                };
                self.publish();
            }
            Event::Log(_) => {}
        }
    }

    fn push_log(&mut self, line: String) {
        if self.log.len() == LOG_LINES {
            self.log.pop_front();
        }
        self.log.push_back(line.clone());
        let _ = self.notices.send(Notice::Log(line));
    }

    fn publish(&self) {
        let _ = self.notices.send(Notice::Status(self.status.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Mock;

    const CFG: &str = "client\nremote de-fra-02.example.net 1194\n";

    async fn setup() -> (
        Shared,
        mpsc::UnboundedReceiver<Notice>,
        String,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ProfileStore::open(dir.path().to_path_buf()).unwrap();
        let id = store.import("de.ovpn", CFG).unwrap().id;
        let (tx, rx) = mpsc::unbounded_channel();
        (Manager::spawn(store, Arc::new(Mock), tx), rx, id, dir)
    }

    async fn wait_for(rx: &mut mpsc::UnboundedReceiver<Notice>, state: ConnState) -> Status {
        loop {
            let n = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap();
            if let Notice::Status(s) = n
                && s.state == state
            {
                return s;
            }
        }
    }

    #[tokio::test]
    async fn connects_and_disconnects() {
        let (mgr, mut rx, id, _dir) = setup().await;
        let old = mgr
            .lock()
            .await
            .begin_connect(&id, &Credentials::default())
            .unwrap();
        assert!(old.is_none());
        mgr.lock()
            .await
            .finish_connect(&id, Credentials::default())
            .unwrap();
        let s = wait_for(&mut rx, ConnState::Connected).await;
        assert_eq!(s.tunnel_ip.as_deref(), Some("10.8.0.6"));
        assert!(mgr.lock().await.profiles()[0].last_connected_at.is_some());

        let h = mgr.lock().await.begin_disconnect().unwrap();
        h.stop().await;
        let s = wait_for(&mut rx, ConnState::Disconnected).await;
        assert_eq!(s.error, None);
    }

    #[tokio::test]
    async fn requires_credentials_for_user_pass_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ProfileStore::open(dir.path().to_path_buf()).unwrap();
        let id = store
            .import("x.ovpn", "client\nremote a.example\nauth-user-pass\n")
            .unwrap()
            .id;
        let (tx, _rx) = mpsc::unbounded_channel();
        let mgr = Manager::spawn(store, Arc::new(Mock), tx);
        let Err(err) = mgr.lock().await.begin_connect(&id, &Credentials::default()) else {
            panic!("connect without credentials should fail");
        };
        assert!(err.to_string().contains("username"));
    }

    #[tokio::test]
    async fn ignores_events_from_replaced_sessions() {
        let (mgr, _rx, id, _dir) = setup().await;
        {
            let mut m = mgr.lock().await;
            m.begin_connect(&id, &Credentials::default()).unwrap();
            let stale = m.seq - 1;
            m.on_event(stale, Event::Exited);
            assert_eq!(m.status().state, ConnState::Connecting);
        }
    }
}
