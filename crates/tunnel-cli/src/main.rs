//! `tunnel`: command-line client for `tunneld`.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use tunnel_core::ovpn;
use tunnel_core::{
    AuthKind, ConnState, DaemonProxy, DnsMode, FirewallMode, Profile, Settings, Status,
};

#[derive(Parser)]
#[command(name = "tunnel", version, about = "Control the Tunnel VPN daemon")]
struct Cli {
    /// Talk to a daemon on the session bus (development).
    #[arg(long, global = true, env = "TUNNEL_SESSION_BUS")]
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
    /// Rename a profile or move it to another group.
    Edit {
        profile: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        group: Option<String>,
        /// Two-letter country code, or `-` to clear it.
        #[arg(long)]
        country: Option<String>,
    },
    /// Remove a profile.
    Remove { profile: String },
    /// Show or change settings, e.g.
    /// `tunnel settings firewall=always lan=off ipv6=on dns=1.1.1.1,9.9.9.9 dns-guard=on`.
    /// `firewall` is off, auto or always; `dns` is `vpn` or a list of servers.
    Settings { changes: Vec<String> },
    /// Print the OpenVPN log.
    Log {
        /// Keep printing new lines.
        #[arg(short, long)]
        follow: bool,
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
            eprintln!("tunnel: {msg}");
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
        .context("connecting to tunneld")?;

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
                println!("No profiles yet. Import one with `tunnel import file.ovpn`.");
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
            let (user, pass, resp) = credentials(&p, username)?;
            let mut stream = d.receive_status_changed().await?;
            d.connect(&p.id, &user, &pass, &resp).await?;
            println!("connecting to {}…", p.name);
            while let Some(sig) = stream.next().await {
                let s: Status = serde_json::from_str(sig.args()?.status())?;
                match s.state {
                    ConnState::Connected => {
                        println!("connected  {}", s.tunnel_ip.unwrap_or_default());
                        break;
                    }
                    ConnState::Disconnected => {
                        bail!(s.error.unwrap_or_else(|| "disconnected".into()))
                    }
                    _ => {}
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
        } => {
            let p = find(&d, &profile).await?;
            let u: Profile = serde_json::from_str(
                &d.update_profile(
                    &p.id,
                    name.as_deref().unwrap_or(""),
                    group.as_deref().unwrap_or(""),
                    country.as_deref().unwrap_or(""),
                )
                .await?,
            )?;
            println!("{}  {}  {}", short(&u.id), u.name, u.group);
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

fn credentials(p: &Profile, username: Option<String>) -> Result<(String, String, String)> {
    if p.auth == AuthKind::Certificate {
        return Ok(Default::default());
    }
    let user = match username {
        Some(u) => u,
        None => {
            print!("Username: ");
            std::io::stdout().flush()?;
            let mut s = String::new();
            std::io::stdin().read_line(&mut s)?;
            s.trim().to_string()
        }
    };
    let pass = rpassword::prompt_password("Password: ")?;
    let resp = if p.auth == AuthKind::UserPassChallenge {
        rpassword::prompt_password(format!(
            "{}: ",
            p.challenge.as_deref().unwrap_or("Response")
        ))?
    } else {
        String::new()
    };
    Ok((user, pass, resp))
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
        }
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
        "dns" => {
            st.dns = if value == "vpn" {
                DnsMode::Vpn
            } else {
                DnsMode::Custom(value.split(',').map(|s| s.trim().to_string()).collect())
            }
        }
        _ => bail!("unknown setting `{key}` (firewall, lan, ipv6, dns, dns-guard)"),
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
}
