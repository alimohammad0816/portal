//! Desktop shell: bridges the web UI to `tunneld` over D-Bus, owns the tray
//! icon, and keeps running in the tray when the window is closed.

mod latency;
mod updater;

use std::path::PathBuf;
use std::time::Duration;

use futures_util::StreamExt;
use serde::Serialize;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent, Wry};
use tokio::sync::Mutex;
use tunnel_core::ovpn;
use tunnel_core::{ConnState, DaemonProxy, Profile, Status};

/// Which bus the daemon lives on. `TUNNEL_SESSION_BUS=1` selects the
/// session bus, for running against `tunneld --session --mock`.
fn use_session_bus() -> bool {
    std::env::var("TUNNEL_SESSION_BUS").is_ok_and(|v| !v.is_empty() && v != "0")
}

#[derive(Default)]
struct Daemon {
    proxy: Mutex<Option<DaemonProxy<'static>>>,
}

impl Daemon {
    async fn get(&self) -> Result<DaemonProxy<'static>, String> {
        let mut guard = self.proxy.lock().await;
        if let Some(p) = guard.as_ref() {
            return Ok(p.clone());
        }
        let conn = if use_session_bus() {
            zbus::Connection::session().await
        } else {
            zbus::Connection::system().await
        }
        .map_err(|e| format!("Couldn't connect to D-Bus: {e}"))?;
        let proxy = DaemonProxy::new(&conn).await.map_err(err)?;
        *guard = Some(proxy.clone());
        Ok(proxy)
    }
}

/// Turn a D-Bus error into the message the daemon meant to show.
fn err(e: zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(name, msg, _) => match (name.as_str(), msg) {
            ("org.freedesktop.DBus.Error.ServiceUnknown", _) => {
                "The Tunnel service isn't running.".into()
            }
            ("org.freedesktop.DBus.Error.AccessDenied", Some(m)) => format!("Not allowed: {m}"),
            (_, Some(m)) => m,
            (n, None) => n.to_string(),
        },
        zbus::Error::FDO(e) => match *e {
            zbus::fdo::Error::ServiceUnknown(_) => "The Tunnel service isn't running.".into(),
            zbus::fdo::Error::Failed(m) => m,
            other => other.to_string(),
        },
        other => other.to_string(),
    }
}

fn parse<T: serde::de::DeserializeOwned>(json: String) -> Result<T, String> {
    serde_json::from_str(&json).map_err(|e| format!("Unexpected reply from the service: {e}"))
}

#[derive(Serialize, Clone)]
struct DaemonInfo {
    bus: &'static str,
    reachable: bool,
    error: Option<String>,
}

#[derive(Serialize)]
struct ImportError {
    file: String,
    message: String,
}

#[derive(Serialize)]
struct ImportResult {
    imported: Vec<Profile>,
    errors: Vec<ImportError>,
}

#[tauri::command]
async fn daemon_info(daemon: State<'_, Daemon>) -> Result<DaemonInfo, String> {
    let bus = if use_session_bus() {
        "session"
    } else {
        "system"
    };
    let probe = async { daemon.get().await?.get_status().await.map_err(err) };
    Ok(match probe.await {
        Ok(_) => DaemonInfo {
            bus,
            reachable: true,
            error: None,
        },
        Err(e) => DaemonInfo {
            bus,
            reachable: false,
            error: Some(e),
        },
    })
}

#[tauri::command]
async fn list_profiles(daemon: State<'_, Daemon>) -> Result<Vec<Profile>, String> {
    parse(daemon.get().await?.list_profiles().await.map_err(err)?)
}

#[tauri::command]
async fn import_profiles(
    daemon: State<'_, Daemon>,
    paths: Vec<String>,
) -> Result<ImportResult, String> {
    let d = daemon.get().await?;
    let mut out = ImportResult {
        imported: Vec::new(),
        errors: Vec::new(),
    };
    for raw in paths {
        let path = PathBuf::from(&raw);
        let file = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&raw)
            .to_string();
        // Files are read here, as the user, and embedded before the daemon
        // (running as root) ever sees them.
        let result = async {
            let text = tokio::fs::read_to_string(&path)
                .await
                .map_err(|e| e.to_string())?;
            let base = path.parent().map(PathBuf::from).unwrap_or_default();
            let inlined = ovpn::inline_files(&text, &base).map_err(|e| e.to_string())?;
            parse::<Profile>(d.import_profile(&file, &inlined).await.map_err(err)?)
        }
        .await;
        match result {
            Ok(p) => out.imported.push(p),
            Err(message) => out.errors.push(ImportError { file, message }),
        }
    }
    Ok(out)
}

#[tauri::command]
async fn update_profile(
    daemon: State<'_, Daemon>,
    id: String,
    name: String,
    group: String,
    country: String,
) -> Result<Profile, String> {
    parse(
        daemon
            .get()
            .await?
            .update_profile(&id, &name, &group, &country)
            .await
            .map_err(err)?,
    )
}

#[tauri::command]
async fn remove_profile(daemon: State<'_, Daemon>, id: String) -> Result<(), String> {
    daemon.get().await?.remove_profile(&id).await.map_err(err)
}

#[tauri::command]
async fn connect(
    daemon: State<'_, Daemon>,
    id: String,
    username: String,
    password: String,
    response: String,
) -> Result<(), String> {
    daemon
        .get()
        .await?
        .connect(&id, &username, &password, &response)
        .await
        .map_err(err)
}

#[tauri::command]
async fn disconnect(daemon: State<'_, Daemon>) -> Result<(), String> {
    daemon.get().await?.disconnect().await.map_err(err)
}

#[tauri::command]
async fn get_status(daemon: State<'_, Daemon>) -> Result<Status, String> {
    parse(daemon.get().await?.get_status().await.map_err(err)?)
}

#[tauri::command]
async fn get_log(daemon: State<'_, Daemon>) -> Result<Vec<String>, String> {
    daemon.get().await?.get_log().await.map_err(err)
}

#[tauri::command]
async fn probe_latency(host: String, port: u16, proto: String) -> Result<Option<u32>, String> {
    Ok(latency::probe(&host, port, &proto).await)
}

// --------------------------------------------------------------- updates --

/// The last release found by `check_update`. Installs only ever use URLs
/// that came from GitHub here, never ones passed in from the web view.
#[derive(Default)]
struct Updates {
    latest: Mutex<Option<updater::Release>>,
}

#[derive(Serialize)]
struct Versions {
    app: String,
    daemon: Option<String>,
}

#[tauri::command]
async fn versions(daemon: State<'_, Daemon>) -> Result<Versions, String> {
    let daemon_version = match daemon.get().await {
        Ok(d) => d.version().await.ok(),
        Err(_) => None,
    };
    Ok(Versions {
        app: env!("CARGO_PKG_VERSION").to_string(),
        daemon: daemon_version,
    })
}

#[tauri::command]
async fn check_update(updates: State<'_, Updates>) -> Result<updater::UpdateInfo, String> {
    let info = updater::check().await?;
    *updates.latest.lock().await = info.available.clone();
    Ok(info)
}

#[tauri::command]
async fn install_update(
    daemon: State<'_, Daemon>,
    updates: State<'_, Updates>,
) -> Result<String, String> {
    use std::os::fd::AsFd;
    let rel = updates
        .latest
        .lock()
        .await
        .clone()
        .ok_or("There's no update to install.")?;
    let (path, signature) = updater::download(&rel).await?;
    let file = std::fs::File::open(&path).map_err(|e| e.to_string())?;
    let d = daemon.get().await?;
    let version = d
        .install_update(zbus::zvariant::Fd::from(file.as_fd()), &signature)
        .await
        .map_err(err)?;
    let _ = std::fs::remove_file(&path);
    Ok(version)
}

#[tauri::command]
fn restart_app(app: AppHandle) {
    app.restart();
}

// ------------------------------------------------------------------ tray --

struct Tray {
    status: MenuItem<Wry>,
    toggle: MenuItem<Wry>,
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn build_tray(app: &AppHandle) -> tauri::Result<Tray> {
    let status = MenuItem::with_id(app, "status", "Not connected", false, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", "Connect", true, None::<&str>)?;
    let show = MenuItem::with_id(app, "show", "Show Tunnel", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &status,
            &PredefinedMenuItem::separator(app)?,
            &toggle,
            &show,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )?;
    let mut builder = TrayIconBuilder::with_id("main")
        .tooltip("Tunnel")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main(app),
            "quit" => app.exit(0),
            "toggle" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let daemon = app.state::<Daemon>();
                    let Ok(d) = daemon.get().await else { return };
                    let status: Option<Status> = d
                        .get_status()
                        .await
                        .ok()
                        .and_then(|s| serde_json::from_str(&s).ok());
                    match status {
                        Some(s) if s.state != ConnState::Disconnected => {
                            let _ = d.disconnect().await;
                        }
                        // Connecting may need credentials; the window handles that.
                        _ => show_main(&app),
                    }
                });
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(Tray { status, toggle })
}

fn update_tray(app: &AppHandle, s: &Status, profile_name: Option<&str>) {
    let Some(tray) = app.try_state::<Tray>() else {
        return;
    };
    let name = profile_name.unwrap_or("VPN");
    let (text, action) = match s.state {
        ConnState::Connected => (format!("Connected · {name}"), "Disconnect"),
        ConnState::Connecting | ConnState::NeedsCredentials => {
            (format!("Connecting · {name}"), "Cancel")
        }
        ConnState::Disconnecting => ("Disconnecting…".to_string(), "Disconnect"),
        ConnState::Disconnected => ("Not connected".to_string(), "Connect…"),
    };
    let _ = tray.status.set_text(&text);
    let _ = tray.toggle.set_text(action);
    if let Some(icon) = app.tray_by_id("main") {
        let _ = icon.set_tooltip(Some(format!("Tunnel · {text}")));
    }
}

// ---------------------------------------------------------- daemon events --

/// Forward daemon signals to the UI and the tray, reconnecting if the bus
/// connection or the daemon goes away.
async fn pump_events(app: AppHandle) {
    let mut last_reachable = None;
    loop {
        let daemon = app.state::<Daemon>();
        let result: Result<(), String> = async {
            let d = daemon.get().await?;
            let mut status = d.receive_status_changed().await.map_err(err)?;
            let mut log = d.receive_log_line().await.map_err(err)?;
            let mut owner = d.inner().receive_owner_changed().await.map_err(err)?;

            let initial: Status = parse(d.get_status().await.map_err(err)?)?;
            if last_reachable != Some(true) {
                last_reachable = Some(true);
                let _ = app.emit("tunnel://daemon", DaemonInfo { bus: bus_name(), reachable: true, error: None });
            }
            let mut names = profile_names(&d).await;
            update_tray(&app, &initial, initial.profile_id.as_ref().and_then(|id| names.get(id)).map(String::as_str));

            loop {
                tokio::select! {
                    Some(sig) = status.next() => {
                        let Ok(args) = sig.args() else { continue };
                        let Ok(s) = serde_json::from_str::<Status>(args.status()) else { continue };
                        if s.profile_id.as_ref().is_some_and(|id| !names.contains_key(id)) {
                            names = profile_names(&d).await;
                        }
                        update_tray(&app, &s, s.profile_id.as_ref().and_then(|id| names.get(id)).map(String::as_str));
                        let _ = app.emit("tunnel://status", s);
                    }
                    Some(sig) = log.next() => {
                        if let Ok(args) = sig.args() {
                            let _ = app.emit("tunnel://log", args.line().to_string());
                        }
                    }
                    Some(new_owner) = owner.next() => {
                        if new_owner.is_none() {
                            return Err("The Tunnel service stopped.".to_string());
                        }
                        let _ = app.emit("tunnel://daemon", DaemonInfo { bus: bus_name(), reachable: true, error: None });
                    }
                    else => return Err("Lost the D-Bus connection.".to_string()),
                }
            }
        }
        .await;

        if let Err(e) = result {
            if last_reachable != Some(false) {
                last_reachable = Some(false);
                let _ = app.emit(
                    "tunnel://daemon",
                    DaemonInfo {
                        bus: bus_name(),
                        reachable: false,
                        error: Some(e),
                    },
                );
                update_tray(&app, &Status::default(), None);
            }
            // A dropped bus connection needs a fresh proxy.
            *daemon.proxy.lock().await = None;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn bus_name() -> &'static str {
    if use_session_bus() {
        "session"
    } else {
        "system"
    }
}

async fn profile_names(d: &DaemonProxy<'_>) -> std::collections::HashMap<String, String> {
    let list: Vec<Profile> = match d.list_profiles().await {
        Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    list.into_iter().map(|p| (p.id, p.name)).collect()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main(app)
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(Daemon::default())
        .manage(Updates::default())
        .invoke_handler(tauri::generate_handler![
            versions,
            check_update,
            install_update,
            restart_app,
            daemon_info,
            list_profiles,
            import_profiles,
            update_profile,
            remove_profile,
            connect,
            disconnect,
            get_status,
            get_log,
            probe_latency,
        ])
        .setup(|app| {
            let tray = build_tray(app.handle())?;
            app.manage(tray);
            tauri::async_runtime::spawn(pump_events(app.handle().clone()));
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window keeps the VPN app in the tray.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running Tunnel");
}
