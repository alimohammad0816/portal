//! `tunneld`: owns the VPN connection. Runs as root under systemd on the
//! system bus; `--session --mock` runs it as a normal user for UI work.

mod backend;
mod dbus;
mod dns;
mod firewall;
mod gateway;
mod manager;
mod profiles;
mod split;
mod update;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::mpsc;
use tracing::{info, warn};
use tunnel_core::names::{BUS_NAME, OBJECT_PATH};
use zbus::object_server::SignalEmitter;

use crate::backend::{Backend, Mock, OpenVpn};
use crate::dbus::DaemonIface;
use crate::manager::{Manager, Notice, Platform};
use crate::profiles::ProfileStore;

#[derive(Parser, Debug)]
#[command(version, about = "Tunnel VPN daemon")]
struct Args {
    /// Use the session bus instead of the system bus (development).
    #[arg(long)]
    session: bool,
    /// Simulate connections instead of running OpenVPN (development).
    #[arg(long)]
    mock: bool,
    /// Where profiles are stored.
    #[arg(long, env = "STATE_DIRECTORY")]
    state_dir: Option<PathBuf>,
    /// Where management sockets live.
    #[arg(long, env = "RUNTIME_DIRECTORY")]
    runtime_dir: Option<PathBuf>,
    /// Where verified update packages are staged.
    #[arg(long, env = "CACHE_DIRECTORY")]
    cache_dir: Option<PathBuf>,
    /// OpenVPN binary.
    #[arg(long, default_value = "/usr/sbin/openvpn")]
    openvpn: PathBuf,
}

fn user_dir(env: &str, fallback: &str) -> PathBuf {
    std::env::var_os(env)
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(fallback)))
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tunneld=info".into()),
        )
        .with_target(false)
        .init();

    let args = Args::parse();
    let (state_dir, runtime_dir, cache_dir) = if args.session {
        (
            args.state_dir
                .unwrap_or_else(|| user_dir("XDG_DATA_HOME", ".local/share").join("tunneld")),
            args.runtime_dir
                .unwrap_or_else(|| user_dir("XDG_RUNTIME_DIR", ".cache").join("tunneld")),
            args.cache_dir
                .unwrap_or_else(|| user_dir("XDG_CACHE_HOME", ".cache").join("tunneld")),
        )
    } else {
        (
            args.state_dir.unwrap_or_else(|| "/var/lib/tunneld".into()),
            args.runtime_dir.unwrap_or_else(|| "/run/tunneld".into()),
            args.cache_dir
                .unwrap_or_else(|| "/var/cache/tunneld".into()),
        )
    };
    info!("tunneld {}", update::current_version());

    let store = ProfileStore::open(state_dir.join("profiles"))?;
    let backend: Arc<dyn Backend> = if args.mock {
        warn!("mock backend: connections are simulated");
        Arc::new(Mock)
    } else {
        Arc::new(OpenVpn::new(args.openvpn, runtime_dir))
    };

    let (notice_tx, mut notice_rx) = mpsc::unbounded_channel();
    let platform = Platform {
        system: !args.session,
        settings_path: state_dir.join("settings.json"),
        geoip_dir: cache_dir.join("geoip"),
    };
    let mgr = Manager::spawn(store, backend, notice_tx, platform);
    let iface = DaemonIface {
        mgr: mgr.clone(),
        use_polkit: !args.session,
        cache_dir,
    };

    let builder = if args.session {
        zbus::connection::Builder::session()?
    } else {
        zbus::connection::Builder::system()?
    };
    let conn = builder
        .name(BUS_NAME)?
        .serve_at(OBJECT_PATH, iface)?
        .build()
        .await
        .context("connecting to D-Bus (is the bus policy installed?)")?;
    info!(
        "listening on the {} bus as {BUS_NAME}",
        if args.session { "session" } else { "system" }
    );

    let emitter_conn = conn.clone();
    tokio::spawn(async move {
        let Ok(emitter) = SignalEmitter::new(&emitter_conn, OBJECT_PATH) else {
            return;
        };
        while let Some(n) = notice_rx.recv().await {
            let r = match n {
                Notice::Status(s) => {
                    let json = serde_json::to_string(&s).unwrap_or_default();
                    DaemonIface::status_changed(&emitter, &json).await
                }
                Notice::Log(line) => DaemonIface::log_line(&emitter, &line).await,
                Notice::Settings(st) => {
                    let json = serde_json::to_string(&st).unwrap_or_default();
                    DaemonIface::settings_changed(&emitter, &json).await
                }
            };
            if let Err(e) = r {
                warn!("emitting signal: {e}");
            }
        }
    });

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    info!("shutting down");
    let handle = mgr.lock().await.begin_disconnect();
    if let Some(h) = handle {
        h.stop().await;
    }
    mgr.lock().await.shutdown();
    Ok(())
}
