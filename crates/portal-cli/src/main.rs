//! `portal`: command-line client for `portald`.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use portal_core::ovpn;
use portal_core::{
    AuthKind, ConnState, DaemonProxy, DnsMode, FirewallMode, InputKind, Profile, ProfileEdit,
    ProxyKind, Secrets, Settings, SplitApp, SplitMode, SplitSettings, Status,
};

#[derive(Parser)]
#[command(name = "portal", version, about = "Control the Portal VPN daemon")]
struct Cli {
    /// Talk to a daemon on the session bus (development).
    #[arg(long, global = true, env = "PORTAL_SESSION_BUS")]
    session: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Import one or more .ovpn files.
    Import { files: Vec<PathBuf> },
    /// List imported profiles.
    List,
    /// Connect to a profile (name, id or id prefix).
    Connect {
        profile: String,
        #[arg(short, long)]
        username: Option<String>,
    },
    /// Disconnect.
    Disconnect,
    /// Show the connection status.
    Status {
        /// Keep printing updates.
        #[arg(short, long)]
        watch: bool,
    },
    /// Change a profile: name, group, country, DCO and extra options.
    Edit {
        profile: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        group: Option<String>,
        /// Two-letter country code, or `-` to clear it.
        #[arg(long)]
        country: Option<String>,
        /// Data channel offload: `on` (OpenVPN's default) or `off`.
        #[arg(long)]
        dco: Option<String>,
        /// Extra OpenVPN directive, e.g. `--extra 'mssfix 1400'`. Repeat for
        /// more; replaces the profile's current extra options.
        #[arg(long)]
        extra: Vec<String>,
        /// Remove all extra options.
        #[arg(long, conflicts_with = "extra")]
        clear_extra: bool,
    },
    /// Remove a profile.
    Remove { profile: String },
    /// Show or change settings, e.g.
    /// `portal settings firewall=always lan=off ipv6=on dns=1.1.1.1,9.9.9.9 dns-guard=on`.
    /// `firewall` is off, auto or always; `dns` is `vpn` or a list of servers;
    /// `proxy` is `off`, `http://host:port` or `socks://host:port`.
    Settings { changes: Vec<String> },
    /// Split tunneling. With no arguments, shows the rules. Examples:
    /// `portal split on`, `portal split mode include`,
    /// `portal split add '*.ir' 10.0.0.0/8 country:IR /usr/bin/telegram-desktop`,
    /// `portal split remove '*.ir'`.
    Split {
        #[command(subcommand)]
        action: Option<SplitCmd>,
    },
    /// Run a program with split tunneling applied to it (and its children),
    /// e.g. `portal bypass -- firefox -P local`.
    Bypass {
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Print the OpenVPN log.
    Log {
        /// Keep printing new lines.
        #[arg(short, long)]
        follow: bool,
    },
}

#[derive(Subcommand)]
enum SplitCmd {
    On,
    Off,
    /// `exclude` (listed things skip the VPN) or `include` (only they use it).
    Mode {
        mode: String,
    },
    /// Add domains, IPs, networks, `country:XX` or app paths.
    Add {
        items: Vec<String>,
    },
    /// Remove entries added with `add`.
    Remove {
        items: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // `{:#}` joins the context chain; drop D-Bus error names, which
            // mean nothing to a person reading the message.
            let msg = format!("{e:#}")
                .replace("org.freedesktop.DBus.Error.Failed: ", "")
                .replace("org.freedesktop.DBus.Error.ServiceUnknown: ", "");
            eprintln!("portal: {msg}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let conn = if cli.session {
        zbus::Connection::session().await?
    } else {
        zbus::Connection::system().await?
    };
    let d = DaemonProxy::new(&conn)
        .await
        .context("connecting to portald")?;

    match cli.cmd {
        Cmd::Import { files } => {
            if files.is_empty() {
                bail!("give at least one .ovpn file");
            }
            for f in files {
                let p = import(&d, &f)
                    .await
                    .with_context(|| format!("importing {}", f.display()))?;
                println!(
                    "imported {}  {}  {}:{}/{}",
                    short(&p.id),
                    p.name,
                    p.remote_host,
                    p.remote_port,
                    p.proto
                );
            }
        }
        Cmd::List => {
            let profiles = profiles(&d).await?;
            if profiles.is_empty() {
                println!("No profiles yet. Import one with `portal import file.ovpn`.");
            }
            for p in profiles {
                println!(
                    "{}  {:<24} {:<12} {:<3} {}:{}/{}",
                    short(&p.id),
                    p.name,
                    p.group,
                    p.country.as_deref().unwrap_or("--"),
                    p.remote_host,
                    p.remote_port,
                    p.proto
                );
            }
        }
        Cmd::Connect { profile, username } => {
            let p = find(&d, &profile).await?;
            let st: Settings = serde_json::from_str(&d.get_settings().await?)?;
            let mut secrets = credentials(&p, username, &st)?;
            let mut stream = d.receive_status_changed().await?;
            d.connect(&p.id, &serde_json::to_string(&secrets)?).await?;
            println!("connecting to {}…", p.name);
            let mut shown_url = None;
            // The waiting state can be published more than once; answer once.
            let mut answered = false;
            while let Some(sig) = stream.next().await {
                let s: Status = serde_json::from_str(sig.args()?.status())?;
                if let Some(url) = &s.auth_url
                    && shown_url.as_ref() != Some(url)
                {
                    println!("Sign in to continue: {url}");
                    let _ = std::process::Command::new("xdg-open")
                        .arg(url)
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn();
                    shown_url = Some(url.clone());
                }
                match s.state {
                    ConnState::Connected => {
                        println!("connected  {}", s.tunnel_ip.unwrap_or_default());
                        break;
                    }
                    ConnState::Disconnected => {
                        bail!(s.error.unwrap_or_else(|| "disconnected".into()))
                    }
                    ConnState::NeedsCredentials if answered => {}
                    ConnState::NeedsCredentials => {
                        let Some(req) = s.request else { continue };
                        answered = true;
                        match req.kind {
                            InputKind::Challenge => {
                                let text = req.message.as_deref().unwrap_or("Response");
                                let answer = if req.echo {
                                    ask(&format!("{text}: "))?
                                } else {
                                    rpassword::prompt_password(format!("{text}: "))?
                                };
                                d.answer_challenge(&answer).await?;
                                continue;
                            }
                            InputKind::Login => {
                                secrets.username = ask("Username: ")?;
                                secrets.password = rpassword::prompt_password("Password: ")?;
                            }
                            InputKind::KeyPassphrase => {
                                secrets.key_passphrase =
                                    Some(rpassword::prompt_password("Private key passphrase: ")?);
                            }
                            InputKind::ProxyLogin => {
                                secrets.proxy_username = Some(ask("Proxy username: ")?);
                                secrets.proxy_password =
                                    Some(rpassword::prompt_password("Proxy password: ")?);
                            }
                        }
                        d.connect(&p.id, &serde_json::to_string(&secrets)?).await?;
                    }
                    _ => answered = false,
                }
            }
        }
        Cmd::Disconnect => d.disconnect().await?,
        Cmd::Status { watch } => {
            print_status(&d, &serde_json::from_str(&d.get_status().await?)?).await?;
            if watch {
                let mut stream = d.receive_status_changed().await?;
                while let Some(sig) = stream.next().await {
                    print_status(&d, &serde_json::from_str(sig.args()?.status())?).await?;
                }
            }
        }
        Cmd::Edit {
            profile,
            name,
            group,
            country,
            dco,
            extra,
            clear_extra,
        } => {
            let p = find(&d, &profile).await?;
            let edit = ProfileEdit {
                name,
                group,
                country,
                disable_dco: dco.as_deref().map(on_off).transpose()?.map(|on| !on),
                extra_directives: if clear_extra {
                    Some(String::new())
                } else if extra.is_empty() {
                    None
                } else {
                    Some(extra.join("\n"))
                },
            };
            let u: Profile = serde_json::from_str(
                &d.update_profile(&p.id, &serde_json::to_string(&edit)?)
                    .await?,
            )?;
            println!("{}  {}  {}", short(&u.id), u.name, u.group);
            println!("dco        {}", if u.disable_dco { "off" } else { "on" });
            for line in u.extra_directives.lines() {
                println!("extra      {line}");
            }
        }
        Cmd::Remove { profile } => {
            let p = find(&d, &profile).await?;
            d.remove_profile(&p.id).await?;
            println!("removed {}", p.name);
        }
        Cmd::Settings { changes } => {
            let mut st: Settings = serde_json::from_str(&d.get_settings().await?)?;
            if !changes.is_empty() {
                for c in &changes {
                    apply_change(&mut st, c)?;
                }
                st = serde_json::from_str(&d.set_settings(&serde_json::to_string(&st)?).await?)?;
            }
            print_settings(&st);
        }
        Cmd::Split { action } => {
            let mut st: Settings = serde_json::from_str(&d.get_settings().await?)?;
            if let Some(a) = action {
                apply_split(&mut st.split, a)?;
                st = serde_json::from_str(&d.set_settings(&serde_json::to_string(&st)?).await?)?;
                let s: Status = serde_json::from_str(&d.get_status().await?)?;
                if s.split_needs_reconnect {
                    println!("Reconnect to switch modes.");
                }
            }
            print_split(&st.split);
        }
        Cmd::Bypass { command } => {
            use std::os::unix::process::CommandExt;
            d.split_self().await?;
            // Replace this process; the program keeps our cgroup.
            let err = std::process::Command::new(&command[0])
                .args(&command[1..])
                .exec();
            bail!("running {}: {err}", command[0]);
        }
        Cmd::Log { follow } => {
            let mut stream = if follow {
                Some(d.receive_log_line().await?)
            } else {
                None
            };
            for line in d.get_log().await? {
                println!("{line}");
            }
            if let Some(stream) = stream.as_mut() {
                while let Some(sig) = stream.next().await {
                    println!("{}", sig.args()?.line());
                }
            }
        }
    }
    Ok(())
}

fn short(id: &str) -> &str {
    &id[..id.len().min(8)]
}

async fn import(d: &DaemonProxy<'_>, path: &PathBuf) -> Result<Profile> {
    let text = std::fs::read_to_string(path)?;
    let base = path.parent().map(PathBuf::from).unwrap_or_default();
    let inlined = ovpn::inline_files(&text, &base)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("profile.ovpn");
    Ok(serde_json::from_str(
        &d.import_profile(name, &inlined).await?,
    )?)
}

async fn profiles(d: &DaemonProxy<'_>) -> Result<Vec<Profile>> {
    Ok(serde_json::from_str(&d.list_profiles().await?)?)
}

async fn find(d: &DaemonProxy<'_>, query: &str) -> Result<Profile> {
    let all = profiles(d).await?;
    let q = query.to_lowercase();
    // Exact name or id prefix first, then names that start with the query,
    // then names that contain it.
    let tiers: [&dyn Fn(&Profile) -> bool; 3] = [
        &|p| p.id.starts_with(&q) || p.name.to_lowercase() == q,
        &|p| p.name.to_lowercase().starts_with(&q),
        &|p| p.name.to_lowercase().contains(&q),
    ];
    let mut hits: Vec<Profile> = Vec::new();
    for tier in tiers {
        hits = all.iter().filter(|p| tier(p)).cloned().collect();
        if !hits.is_empty() {
            break;
        }
    }
    match hits.len() {
        0 => bail!("no profile matches `{query}`"),
        1 => Ok(hits.remove(0)),
        _ => bail!(
            "`{query}` matches {} profiles; use more of the id",
            hits.len()
        ),
    }
}

fn ask(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

/// Ask up front for what the profile and settings say we'll need.
fn credentials(p: &Profile, username: Option<String>, st: &Settings) -> Result<Secrets> {
    let mut out = Secrets::default();
    if p.auth != AuthKind::Certificate {
        out.username = match username {
            Some(u) => u,
            None => ask("Username: ")?,
        };
        out.password = rpassword::prompt_password("Password: ")?;
        if p.auth == AuthKind::UserPassChallenge {
            out.response = Some(rpassword::prompt_password(format!(
                "{}: ",
                p.challenge.as_deref().unwrap_or("Response")
            ))?);
        }
    }
    if p.key_encrypted {
        out.key_passphrase = Some(rpassword::prompt_password("Private key passphrase: ")?);
    }
    if st.connection_proxy.active() && st.connection_proxy.auth {
        out.proxy_username = Some(ask("Proxy username: ")?);
        out.proxy_password = Some(rpassword::prompt_password("Proxy password: ")?);
    }
    Ok(out)
}

fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1000.0 && i < UNITS.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

async fn print_status(d: &DaemonProxy<'_>, s: &Status) -> Result<()> {
    let name = match &s.profile_id {
        Some(id) => profiles(d)
            .await?
            .into_iter()
            .find(|p| &p.id == id)
            .map(|p| p.name),
        None => None,
    };
    let state = format!("{:?}", s.state).to_lowercase();
    match s.state {
        ConnState::Connected => println!(
            "{state}  {}  ip {}  ↓ {}/s  ↑ {}/s  total ↓ {} ↑ {}",
            name.unwrap_or_default(),
            s.tunnel_ip.as_deref().unwrap_or("-"),
            human(s.rate_in),
            human(s.rate_out),
            human(s.bytes_in),
            human(s.bytes_out)
        ),
        _ => {
            let detail = s
                .detail
                .as_deref()
                .map(|d| format!(" ({d})"))
                .unwrap_or_default();
            println!("{state}{detail}  {}", name.unwrap_or_default());
            if let Some(e) = &s.error {
                println!("error: {e}");
            }
            if s.internet_blocked {
                println!("firewall: internet is blocked outside the VPN");
            }
            if let Some(r) = &s.request {
                println!(
                    "waiting for: {}",
                    match r.kind {
                        InputKind::Login => "username and password",
                        InputKind::KeyPassphrase => "private key passphrase",
                        InputKind::ProxyLogin => "proxy username and password",
                        InputKind::Challenge => r.message.as_deref().unwrap_or("an answer"),
                    }
                );
            }
        }
    }
    if let Some(p) = &s.proxy_address {
        println!("proxy gateway: {p}");
    }
    Ok(())
}

fn on_off(v: &str) -> Result<bool> {
    match v {
        "on" | "yes" | "true" | "1" => Ok(true),
        "off" | "no" | "false" | "0" => Ok(false),
        _ => bail!("expected on or off, got `{v}`"),
    }
}

fn apply_change(st: &mut Settings, change: &str) -> Result<()> {
    let (key, value) = change
        .split_once('=')
        .with_context(|| format!("`{change}` should look like key=value"))?;
    match key {
        "firewall" => {
            st.firewall = match value {
                "off" => FirewallMode::Off,
                "auto" => FirewallMode::Auto,
                "always" => FirewallMode::Always,
                _ => bail!("firewall is off, auto or always"),
            }
        }
        "lan" => st.allow_lan = on_off(value)?,
        "ipv6" => st.block_ipv6 = on_off(value)?,
        "dns-guard" => st.dns_leak_protection = on_off(value)?,
        "gateway" => st.proxy_gateway.enabled = on_off(value)?,
        "gateway-port" => {
            st.proxy_gateway.port = value.parse().context("gateway-port is a number")?
        }
        "proxy" => {
            let cp = &mut st.connection_proxy;
            if value == "off" {
                cp.kind = ProxyKind::Profile;
            } else {
                let (kind, rest) = value
                    .split_once("://")
                    .context("proxy is off, http://host:port or socks://host:port")?;
                cp.kind = match kind {
                    "http" => ProxyKind::Http,
                    "socks" | "socks5" => ProxyKind::Socks,
                    _ => bail!("proxy is off, http://host:port or socks://host:port"),
                };
                let (host, port) = rest
                    .trim_end_matches('/')
                    .rsplit_once(':')
                    .context("give the proxy's port, e.g. http://proxy.lan:3128")?;
                cp.host = host.trim_matches(['[', ']']).to_string();
                cp.port = port.parse().context("the proxy port is a number")?;
            }
        }
        "proxy-auth" => st.connection_proxy.auth = on_off(value)?,
        "dns" => {
            st.dns = if value == "vpn" {
                DnsMode::Vpn
            } else {
                DnsMode::Custom(value.split(',').map(|s| s.trim().to_string()).collect())
            }
        }
        _ => bail!(
            "unknown setting `{key}` (firewall, lan, ipv6, dns, dns-guard, gateway, gateway-port, proxy, proxy-auth)"
        ),
    }
    Ok(())
}

fn print_settings(st: &Settings) {
    let yn = |b: bool| if b { "on" } else { "off" };
    let fw = match st.firewall {
        FirewallMode::Off => "off",
        FirewallMode::Auto => "auto",
        FirewallMode::Always => "always",
    };
    let dns = match &st.dns {
        DnsMode::Vpn => "vpn".to_string(),
        DnsMode::Custom(list) => list.join(","),
    };
    println!("firewall   {fw}");
    println!(
        "lan        {}  (allowed through the firewall)",
        yn(st.allow_lan)
    );
    println!(
        "ipv6       {}  (blocked outside the tunnel)",
        yn(st.block_ipv6)
    );
    println!("dns        {dns}");
    println!("dns-guard  {}", yn(st.dns_leak_protection));
    println!(
        "gateway    {}  (port {}, SOCKS5 and HTTP for the LAN)",
        yn(st.proxy_gateway.enabled),
        st.proxy_gateway.port
    );
    let cp = &st.connection_proxy;
    match cp.kind {
        ProxyKind::Profile => println!("proxy      off  (the profile's own, if any)"),
        ProxyKind::Http | ProxyKind::Socks => println!(
            "proxy      {}://{}:{}{}",
            if cp.kind == ProxyKind::Http {
                "http"
            } else {
                "socks"
            },
            cp.host,
            cp.port,
            if cp.auth { "  (with sign-in)" } else { "" }
        ),
    }
}

fn apply_split(sp: &mut SplitSettings, action: SplitCmd) -> Result<()> {
    match action {
        SplitCmd::On => sp.enabled = true,
        SplitCmd::Off => sp.enabled = false,
        SplitCmd::Mode { mode } => {
            sp.mode = match mode.as_str() {
                "exclude" => SplitMode::Exclude,
                "include" | "only" => SplitMode::Include,
                _ => bail!("mode is exclude or include"),
            }
        }
        SplitCmd::Add { items } => {
            for it in items {
                if let Some(c) = it.strip_prefix("country:") {
                    let c = c.to_ascii_uppercase();
                    if !sp.countries.contains(&c) {
                        sp.countries.push(c);
                    }
                } else if it.starts_with('/') {
                    let name = std::path::Path::new(&it)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(&it)
                        .to_string();
                    if !sp.apps.iter().any(|a| a.path == it) {
                        sp.apps.push(SplitApp { name, path: it });
                    }
                } else {
                    portal_core::split::Rule::parse(&it).map_err(|e| anyhow::anyhow!(e))?;
                    if !sp.hosts.contains(&it) {
                        sp.hosts.push(it);
                    }
                }
            }
        }
        SplitCmd::Remove { items } => {
            for it in items {
                let c = it.strip_prefix("country:").map(str::to_ascii_uppercase);
                sp.countries.retain(|x| Some(x) != c.as_ref());
                sp.apps.retain(|a| a.path != it);
                sp.hosts.retain(|h| *h != it);
            }
        }
    }
    Ok(())
}

fn print_split(sp: &SplitSettings) {
    let mode = match sp.mode {
        SplitMode::Exclude => "exclude (listed things skip the VPN)",
        SplitMode::Include => "include (only listed things use the VPN)",
    };
    println!("split      {}", if sp.enabled { "on" } else { "off" });
    println!("mode       {mode}");
    for a in &sp.apps {
        println!("app        {}  {}", a.name, a.path);
    }
    for h in &sp.hosts {
        println!("host       {h}");
    }
    for c in &sp.countries {
        println!("country    {c}");
    }
}
