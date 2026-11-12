//! Desktop shell: bridges the web UI to `tunneld` over D-Bus, owns the tray
//! icon, and keeps running in the tray when the window is closed.

mod apps;
mod keyring;
mod latency;
mod network;
mod prefs;
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
use tunnel_core::{ConnState, DaemonProxy, Profile, ProfileEdit, Secrets, Settings, Status};

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
    let mut files = Vec::new();
    for raw in paths {
        let path = PathBuf::from(&raw);
        if path.is_dir() {
            let found = profiles_in(&path);
            if found.is_empty() {
                out.errors.push(ImportError {
                    file: raw.clone(),
                    message: "No OpenVPN profiles in this folder.".into(),
                });
            }
            files.extend(found.into_iter().map(|p| p.display().to_string()));
        } else {
            files.push(raw);
        }
    }
    for raw in files {
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

/// OpenVPN profiles in a folder (and one level of subfolders, as provider
/// downloads often have), sorted by name. `.conf` files count only if they
/// look like client configs.
fn profiles_in(dir: &std::path::Path) -> Vec<PathBuf> {
    fn scan(dir: &std::path::Path, depth: usize, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = entries.flatten().map(|e| e.path()).collect();
        entries.sort();
        for p in entries {
            if out.len() >= 500 {
                return;
            }
            if p.is_dir() {
                if depth > 0 {
                    scan(&p, depth - 1, out);
                }
                continue;
            }
            let ext = p
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase);
            let wanted = match ext.as_deref() {
                Some("ovpn") => true,
                Some("conf") => std::fs::read_to_string(&p)
                    .is_ok_and(|t| t.lines().any(|l| l.trim_start().starts_with("remote "))),
                _ => false,
            };
            if wanted {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    scan(dir, 1, &mut out);
    out
}

#[tauri::command]
async fn update_profile(
    daemon: State<'_, Daemon>,
    id: String,
    edit: ProfileEdit,
) -> Result<Profile, String> {
    let edit = serde_json::to_string(&edit).map_err(|e| e.to_string())?;
    parse(
        daemon
            .get()
            .await?
            .update_profile(&id, &edit)
            .await
            .map_err(err)?,
    )
}

#[tauri::command]
async fn remove_profile(daemon: State<'_, Daemon>, id: String) -> Result<(), String> {
    daemon.get().await?.remove_profile(&id).await.map_err(err)
}

/// What the window collected; empty fields come from the keyring.
#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct ConnectInput {
    username: String,
    password: String,
    response: String,
    key_passphrase: String,
    proxy_username: String,
    proxy_password: String,
}

/// Fill in what wasn't typed from the keyring, and save what was (if asked
/// to). Secrets go from the keyring straight to the service, never through
/// the web view.
async fn secrets_for(id: &str, name: &str, input: ConnectInput, remember: Option<bool>) -> Secrets {
    let opt = |s: String| (!s.is_empty()).then_some(s);
    let mut out = Secrets {
        response: opt(input.response),
        ..Default::default()
    };

    if input.username.is_empty() {
        if let Ok(Some(s)) = keyring::load(&keyring::login_slot(id)).await {
            out.username = s.username;
            out.password = s.password;
        }
    } else {
        out.username = input.username;
        out.password = input.password;
        let saved = keyring::Saved {
            username: out.username.clone(),
            password: out.password.clone(),
        };
        keep(&keyring::login_slot(id), name, &saved, remember).await;
    }

    if input.key_passphrase.is_empty() {
        if let Ok(Some(s)) = keyring::load(&keyring::key_slot(id)).await {
            out.key_passphrase = Some(s.password);
        }
    } else {
        let saved = keyring::Saved {
            username: String::new(),
            password: input.key_passphrase.clone(),
        };
        keep(
            &keyring::key_slot(id),
            &format!("{name} (key)"),
            &saved,
            remember,
        )
        .await;
        out.key_passphrase = Some(input.key_passphrase);
    }

    if input.proxy_username.is_empty() {
        if let Ok(Some(s)) = keyring::load(keyring::PROXY_SLOT).await {
            out.proxy_username = Some(s.username);
            out.proxy_password = Some(s.password);
        }
    } else {
        let saved = keyring::Saved {
            username: input.proxy_username.clone(),
            password: input.proxy_password.clone(),
        };
        keep(keyring::PROXY_SLOT, "proxy", &saved, remember).await;
        out.proxy_username = Some(input.proxy_username);
        out.proxy_password = Some(input.proxy_password);
    }
    out
}

async fn keep(slot: &str, name: &str, saved: &keyring::Saved, remember: Option<bool>) {
    match remember {
        Some(true) => {
            if let Err(e) = keyring::save(slot, name, saved).await {
                eprintln!("keyring: {e}");
            }
        }
        Some(false) => {
            let _ = keyring::forget(slot).await;
        }
        None => {}
    }
}

#[tauri::command]
async fn connect(
    daemon: State<'_, Daemon>,
    id: String,
    input: Option<ConnectInput>,
    remember: Option<bool>,
    name: Option<String>,
) -> Result<(), String> {
    let name = name.unwrap_or_else(|| id.clone());
    let secrets = secrets_for(&id, &name, input.unwrap_or_default(), remember).await;
    let json = serde_json::to_string(&secrets).map_err(|e| e.to_string())?;
    daemon.get().await?.connect(&id, &json).await.map_err(err)
}

#[tauri::command]
async fn answer_challenge(daemon: State<'_, Daemon>, response: String) -> Result<(), String> {
    daemon
        .get()
        .await?
        .answer_challenge(&response)
        .await
        .map_err(err)
}

#[derive(Serialize)]
struct SavedCredentials {
    login: bool,
    key: bool,
    proxy: bool,
}

#[tauri::command]
async fn saved_credentials(id: String) -> SavedCredentials {
    SavedCredentials {
        login: keyring::has(&keyring::login_slot(&id)).await,
        key: keyring::has(&keyring::key_slot(&id)).await,
        proxy: keyring::has(keyring::PROXY_SLOT).await,
    }
}

/// Forget saved secrets: `login`, `key`, `proxy`, or (no kind) everything
/// saved for the profile.
#[tauri::command]
async fn forget_credentials(id: String, kind: Option<String>) -> Result<(), String> {
    let slots = match kind.as_deref() {
        Some("login") => vec![keyring::login_slot(&id)],
        Some("key") => vec![keyring::key_slot(&id)],
        Some("proxy") => vec![keyring::PROXY_SLOT.to_string()],
        _ => vec![keyring::login_slot(&id), keyring::key_slot(&id)],
    };
    for slot in slots {
        keyring::forget(&slot).await.map_err(|e| e.to_string())?;
    }
    Ok(())
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
async fn list_apps() -> Result<Vec<apps::InstalledApp>, String> {
    tauri::async_runtime::spawn_blocking(apps::installed)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_settings(daemon: State<'_, Daemon>) -> Result<Settings, String> {
    parse(daemon.get().await?.get_settings().await.map_err(err)?)
}

#[tauri::command]
async fn set_settings(daemon: State<'_, Daemon>, settings: Settings) -> Result<Settings, String> {
    let json = serde_json::to_string(&settings).map_err(|e| e.to_string())?;
    parse(daemon.get().await?.set_settings(&json).await.map_err(err)?)
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

// ------------------------------------------------- automatic connections --

#[derive(Serialize, Clone)]
struct NeedsCredentials {
    profile_id: String,
}

/// Connect without asking, if we can: certificate profiles, and password
/// profiles with a saved password. Otherwise bring up the window and let it
/// ask. Does nothing when already connected or connecting.
async fn auto_connect(app: &AppHandle, profile: Option<String>, why: &str) {
    let daemon = app.state::<Daemon>();
    let Ok(d) = daemon.get().await else { return };
    let Ok(status) = d.get_status().await.map_err(err).and_then(parse::<Status>) else {
        return;
    };
    if status.state != ConnState::Disconnected {
        return;
    }
    let Ok(profiles) = d
        .list_profiles()
        .await
        .map_err(err)
        .and_then(parse::<Vec<Profile>>)
    else {
        return;
    };
    let chosen = profile
        .or_else(|| prefs::load().auto_profile)
        .and_then(|id| profiles.iter().find(|p| p.id == id))
        .or_else(|| {
            profiles
                .iter()
                .filter(|p| p.last_connected_at.is_some())
                .max_by_key(|p| p.last_connected_at)
        })
        .or_else(|| profiles.first());
    let Some(p) = chosen else { return };
    eprintln!("auto-connect to {} ({why})", p.name);
    let settings: Settings = d
        .get_settings()
        .await
        .map_err(err)
        .and_then(parse)
        .unwrap_or_default();
    let secrets = secrets_for(&p.id, &p.name, ConnectInput::default(), None).await;
    let complete = match p.auth {
        tunnel_core::AuthKind::Certificate => true,
        tunnel_core::AuthKind::UserPass => !secrets.username.is_empty(),
        // A one-time code can't be automated.
        tunnel_core::AuthKind::UserPassChallenge => false,
    } && (!p.key_encrypted || secrets.key_passphrase.is_some())
        && (!(settings.connection_proxy.active() && settings.connection_proxy.auth)
            || secrets.proxy_username.is_some());
    let result = if complete {
        let json = serde_json::to_string(&secrets).unwrap_or_default();
        d.connect(&p.id, &json).await.map_err(err)
    } else {
        Err("needs credentials".to_string())
    };
    if result.is_err() {
        show_main(app);
        let _ = app.emit(
            "tunnel://needs-credentials",
            NeedsCredentials {
                profile_id: p.id.clone(),
            },
        );
    }
}

/// Wait until the service answers (it may start after us at login).
async fn wait_for_daemon(app: &AppHandle) -> bool {
    for _ in 0..30 {
        if let Ok(d) = app.state::<Daemon>().get().await
            && d.get_status().await.is_ok()
        {
            return true;
        }
        *app.state::<Daemon>().proxy.lock().await = None;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    false
}

async fn watch_networks(app: AppHandle) {
    network::watch(|net| {
        let app = app.clone();
        async move {
            let _ = app.emit("tunnel://network", net.clone());
            let p = prefs::load();
            if let Some(n) = net
                && p.auto_connect_untrusted
                && !p.trusted_networks.contains(&n.name)
            {
                auto_connect(&app, None, &format!("untrusted network {}", n.name)).await;
            }
        }
    })
    .await;
}

#[tauri::command]
fn get_prefs() -> prefs::Prefs {
    prefs::load()
}

#[tauri::command]
fn set_prefs(prefs: prefs::Prefs) -> Result<prefs::Prefs, String> {
    prefs::save(&prefs)?;
    Ok(prefs)
}

#[tauri::command]
async fn current_network() -> Option<network::Network> {
    network::current().await
}

#[derive(Serialize, serde::Deserialize, Clone)]
struct ExitInfo {
    ip: String,
    country_code: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
}

#[derive(serde::Deserialize)]
struct ExitResp {
    #[serde(default = "yes")]
    success: bool,
    #[serde(flatten)]
    info: ExitInfo,
}

fn yes() -> bool {
    true
}

/// Where the VPN exits to the internet, from a geolocation service. Runs
/// through the tunnel like any other request.
#[tauri::command]
async fn exit_info() -> Result<ExitInfo, String> {
    let r: ExitResp = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .user_agent(concat!("Tunnel/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?
        .get("https://ipwho.is/?fields=success,ip,country_code,city,latitude,longitude")
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    if !r.success {
        return Err("the location service didn't answer".into());
    }
    Ok(r.info)
}

/// `--connect` → `Some(None)` (last profile), `--connect ID` → `Some(Some(ID))`.
fn connect_arg(args: impl IntoIterator<Item = String>) -> Option<Option<String>> {
    let mut it = args.into_iter().skip_while(|a| a != "--connect");
    it.next()?;
    Some(it.next().filter(|a| !a.starts_with("--")))
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
                        Some(s) if s.state != ConnState::Disconnected || s.internet_blocked => {
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
        ConnState::Disconnected if s.internet_blocked => {
            ("Internet blocked by the firewall".to_string(), "Unblock")
        }
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
            let mut settings = d.receive_settings_changed().await.map_err(err)?;
            let mut owner = d.inner().receive_owner_changed().await.map_err(err)?;

            let initial: Status = parse(d.get_status().await.map_err(err)?)?;
            if last_reachable != Some(true) {
                last_reachable = Some(true);
                let _ = app.emit("tunnel://daemon", DaemonInfo { bus: bus_name(), reachable: true, error: None });
            }
            let mut names = profile_names(&d).await;
            update_tray(&app, &initial, initial.profile_id.as_ref().and_then(|id| names.get(id)).map(String::as_str));
            let mut opened_url: Option<String> = None;
            let mut asked = false;

            loop {
                tokio::select! {
                    Some(sig) = status.next() => {
                        let Ok(args) = sig.args() else { continue };
                        let Ok(s) = serde_json::from_str::<Status>(args.status()) else { continue };
                        if s.profile_id.as_ref().is_some_and(|id| !names.contains_key(id)) {
                            names = profile_names(&d).await;
                        }
                        update_tray(&app, &s, s.profile_id.as_ref().and_then(|id| names.get(id)).map(String::as_str));
                        // The server wants a web sign-in: open it once.
                        if let Some(url) = &s.auth_url
                            && opened_url.as_ref() != Some(url)
                            && (url.starts_with("https://") || url.starts_with("http://"))
                        {
                            use tauri_plugin_opener::OpenerExt;
                            if let Err(e) = app.opener().open_url(url, None::<&str>) {
                                eprintln!("opening sign-in page: {e}");
                            }
                            opened_url = Some(url.clone());
                        }
                        // Something to ask: bring the window up, even if
                        // the connection started from the tray or at login.
                        let asking = s.state == ConnState::NeedsCredentials && s.request.is_some();
                        if asking && !asked {
                            show_main(&app);
                        }
                        asked = asking;
                        let _ = app.emit("tunnel://status", s);
                    }
                    Some(sig) = settings.next() => {
                        if let Ok(args) = sig.args()
                            && let Ok(st) = serde_json::from_str::<Settings>(args.settings())
                        {
                            let _ = app.emit("tunnel://settings", st);
                        }
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
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            // A second launch: `--connect [id]` (the GNOME panel, scripts)
            // connects; `--hidden` (login) does nothing; anything else
            // shows the window.
            if let Some(profile) = connect_arg(args.iter().cloned()) {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    auto_connect(&app, profile, "command line").await;
                });
            } else if !args.iter().any(|a| a == "--hidden") {
                show_main(app);
            }
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
            get_settings,
            set_settings,
            list_apps,
            get_prefs,
            set_prefs,
            current_network,
            exit_info,
            saved_credentials,
            forget_credentials,
            answer_challenge,
            probe_latency,
        ])
        .setup(|app| {
            let tray = build_tray(app.handle())?;
            app.manage(tray);
            tauri::async_runtime::spawn(pump_events(app.handle().clone()));
            let handle = app.handle().clone();
            let hidden = std::env::args().any(|a| a == "--hidden");
            if hidden && let Some(w) = app.get_webview_window("main") {
                let _ = w.hide();
            }
            let connect_arg = connect_arg(std::env::args());
            tauri::async_runtime::spawn(async move {
                if wait_for_daemon(&handle).await {
                    if connect_arg.is_some() || prefs::load().connect_on_launch {
                        auto_connect(&handle, connect_arg.flatten(), "startup").await;
                    }
                    watch_networks(handle).await;
                }
            });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exit_info() {
        let r: ExitResp = serde_json::from_str(
            r#"{"success":true,"ip":"185.107.56.12","country_code":"DE","city":"Frankfurt am Main","latitude":50.11,"longitude":8.68}"#,
        )
        .unwrap();
        assert!(r.success);
        assert_eq!(r.info.city.as_deref(), Some("Frankfurt am Main"));
        let r: ExitResp = serde_json::from_str(r#"{"success":false,"ip":""}"#).unwrap();
        assert!(!r.success);
    }

    #[test]
    fn finds_profiles_in_folders() {
        let dir = std::env::temp_dir().join(format!("tunnel-scan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mk = |rel: &str, text: &str| {
            let p = dir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        };
        mk("b.ovpn", "remote b\n");
        mk("a.OVPN", "remote a\n");
        mk("sub/c.ovpn", "remote c\n");
        mk("client.conf", "client\nremote d 1194\n");
        mk("nginx.conf", "server {}\n");
        mk("notes.txt", "remote x\n");
        mk("too/deep/e.ovpn", "remote e\n");
        let names: Vec<String> = profiles_in(&dir)
            .iter()
            .map(|p| p.strip_prefix(&dir).unwrap().display().to_string())
            .collect();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(names, ["a.OVPN", "b.ovpn", "client.conf", "sub/c.ovpn"]);
    }

    #[test]
    fn parses_connect_args() {
        let a = |v: &[&str]| connect_arg(v.iter().map(|s| s.to_string()));
        assert_eq!(a(&["tunnel-desktop"]), None);
        assert_eq!(a(&["tunnel-desktop", "--connect"]), Some(None));
        assert_eq!(
            a(&["tunnel-desktop", "--connect", "abc"]),
            Some(Some("abc".into()))
        );
        assert_eq!(a(&["tunnel-desktop", "--connect", "--hidden"]), Some(None));
    }
}
