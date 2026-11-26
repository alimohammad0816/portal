//! Blocklists for the DNS proxy: download and cache the public lists
//! behind each category, and decide whether a name is blocked.
//!
//! Lists are kept as sorted 64-bit hashes of their domains (8 bytes per
//! domain, about 5 MB with every category on) and matched against each
//! suffix of a looked-up name, so an entry also blocks its subdomains.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use portal_core::BlockingSettings;
use portal_core::blocking::Blocklist;
use portal_core::split::{DomainList, Rule};
use tracing::{info, warn};

/// Lists are downloaded again when they're older than this.
pub const MAX_AGE: Duration = Duration::from_secs(24 * 3600);
const MAX_SIZE: usize = 64 << 20;
const USER_AGENT: &str = concat!("portald/", env!("CARGO_PKG_VERSION"));

/// FNV-1a: stable across runs and builds, which a cache of hashes needs.
pub fn hash(name: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// The domain a list line names, if any. Takes plain domains, hosts file
/// lines (`0.0.0.0 example.com`) and adblock rules (`||example.com^`).
fn line_domain(line: &str) -> Option<String> {
    let line = line.split('#').next()?.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
        return None;
    }
    let candidate = if let Some(rest) = line.strip_prefix("||") {
        let end = rest.find(['^', '$', '/']).unwrap_or(rest.len());
        // Only whole-domain rules; anything with options or paths is a
        // browser filter, not a DNS one.
        if rest[end..].trim_start_matches('^').is_empty() {
            &rest[..end]
        } else {
            return None;
        }
    } else {
        let mut words = line.split_whitespace();
        let first = words.next()?;
        match words.next() {
            Some(second) if first.parse::<std::net::IpAddr>().is_ok() => second,
            Some(_) => return None,
            None => first,
        }
    };
    let candidate = candidate.trim_start_matches("*.");
    if matches!(
        candidate,
        "localhost"
            | "localhost.localdomain"
            | "local"
            | "broadcasthost"
            | "0.0.0.0"
            | "ip6-localhost"
    ) {
        return None;
    }
    match Rule::parse(candidate).ok()? {
        Rule::Domain(d) if d.contains('.') => Some(d),
        _ => None,
    }
}

/// Hashes of the domains in a list, sorted, without duplicates.
pub fn parse(text: &str) -> Vec<u64> {
    let mut v: Vec<u64> = text
        .lines()
        .filter_map(line_domain)
        .map(|d| hash(&d))
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// A list ready to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaded {
    pub hashes: Vec<u64>,
    /// Unix seconds the list was downloaded.
    pub updated_at: u64,
    /// The download failed and an older copy is in use.
    pub stale: Option<String>,
}

fn path_for(dir: &Path, list: &Blocklist) -> PathBuf {
    dir.join(format!("{}.txt", list.id))
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn download(url: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(60))
        .build()?;
    let resp = client
        .get(url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .with_context(|| format!("downloading {url}"))?;
    if resp.content_length().is_some_and(|n| n as usize > MAX_SIZE) {
        bail!("the list is too big");
    }
    let bytes = resp.bytes().await?;
    if bytes.len() > MAX_SIZE {
        bail!("the list is too big");
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

async fn parse_file(path: PathBuf) -> Result<Vec<u64>> {
    tokio::task::spawn_blocking(move || -> Result<Vec<u64>> {
        Ok(parse(&std::fs::read_to_string(&path)?))
    })
    .await?
}

/// The list from the cache when it's fresh (unless `force`), otherwise
/// from the network. Falls back to an older cached copy when the download
/// fails.
pub async fn load(dir: &Path, list: &Blocklist, force: bool) -> Result<Loaded> {
    let path = path_for(dir, list);
    let age = modified(&path).and_then(|t| SystemTime::now().duration_since(t).ok());
    if !force && age.is_some_and(|a| a < MAX_AGE) {
        let hashes = parse_file(path.clone()).await?;
        if !hashes.is_empty() {
            return Ok(Loaded {
                hashes,
                updated_at: modified(&path).map(unix).unwrap_or(0),
                stale: None,
            });
        }
    }
    let err = match download(list.url).await {
        Ok(text) => {
            let hashes = tokio::task::spawn_blocking(move || (parse(&text), text)).await?;
            let (hashes, text) = hashes;
            if hashes.is_empty() {
                anyhow::anyhow!("the list was empty")
            } else {
                std::fs::create_dir_all(dir)?;
                let tmp = path.with_extension("tmp");
                std::fs::write(&tmp, text)?;
                std::fs::rename(&tmp, &path)?;
                info!("blocklist {}: {} domains", list.id, hashes.len());
                return Ok(Loaded {
                    hashes,
                    updated_at: unix(SystemTime::now()),
                    stale: None,
                });
            }
        }
        Err(e) => e,
    };
    warn!("blocklist {}: {err:#}", list.id);
    if path.exists() {
        let hashes = parse_file(path.clone()).await?;
        if !hashes.is_empty() {
            return Ok(Loaded {
                hashes,
                updated_at: modified(&path).map(unix).unwrap_or(0),
                stale: Some(format!("{err:#}")),
            });
        }
    }
    Err(err)
}

fn domains(rules: &[String]) -> DomainList {
    DomainList::new(
        &rules
            .iter()
            .filter_map(|r| Rule::parse(r).ok())
            .collect::<Vec<_>>(),
    )
}

/// What the DNS proxy blocks.
#[derive(Default)]
pub struct Filter {
    lists: Vec<u64>,
    allow: DomainList,
    block: DomainList,
    /// Never blocked: the VPN server's names, so OpenVPN can always find
    /// it again (the VPN category lists many providers).
    keep: Vec<String>,
}

impl std::fmt::Debug for Filter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Filter")
            .field("domains", &self.lists.len())
            .field("keep", &self.keep)
            .finish()
    }
}

impl Filter {
    pub fn new<'a>(
        lists: impl IntoIterator<Item = &'a [u64]>,
        settings: &BlockingSettings,
        keep: Vec<String>,
    ) -> Self {
        let mut all: Vec<u64> = lists.into_iter().flatten().copied().collect();
        all.sort_unstable();
        all.dedup();
        Filter {
            lists: all,
            allow: domains(&settings.allow),
            block: domains(&settings.block),
            keep: keep
                .into_iter()
                .map(|k| k.trim_end_matches('.').to_ascii_lowercase())
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.lists.is_empty() && self.block.is_empty()
    }

    pub fn blocks(&self, name: &str) -> bool {
        if self.is_empty() {
            return false;
        }
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if name.is_empty() || self.keep.contains(&name) || self.allow.matches(&name) {
            return false;
        }
        if self.block.matches(&name) {
            return true;
        }
        let mut s = name.as_str();
        loop {
            if self.lists.binary_search(&hash(s)).is_ok() {
                return true;
            }
            match s.find('.') {
                Some(i) => s = &s[i + 1..],
                None => return false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_list_formats() {
        let text = "# Title: test\n\
            ads.example.com\n\
            0.0.0.0 tracker.example # inline\n\
            127.0.0.1 localhost\n\
            ||adblock.example^\n\
            ||path.example/ads^\n\
            ||opt.example^$third-party\n\
            *.wild.example\n\
            ! comment\n\
            not a domain line\n\
            com\n";
        let got = parse(text);
        let mut want: Vec<u64> = [
            "ads.example.com",
            "tracker.example",
            "adblock.example",
            "wild.example",
        ]
        .iter()
        .map(|d| hash(d))
        .collect();
        want.sort_unstable();
        assert_eq!(got, want);
    }

    #[test]
    fn blocks_listed_domains_and_subdomains() {
        let list = parse("doubleclick.net\nfacebook.com\nexpressvpn.com\n");
        let settings = BlockingSettings {
            lists: vec!["ads".into()],
            allow: vec!["*.facebook.com".into()],
            block: vec!["extra.example".into()],
        };
        let f = Filter::new(
            [list.as_slice()],
            &settings,
            vec!["US1.ExpressVPN.com.".into()],
        );
        assert!(f.blocks("doubleclick.net"));
        assert!(f.blocks("Stats.G.DoubleClick.net."));
        assert!(!f.blocks("notdoubleclick.net"));
        assert!(!f.blocks("example.org"));
        assert!(
            f.blocks("facebook.com"),
            "the allow rule covers only subdomains"
        );
        assert!(!f.blocks("www.facebook.com"));
        assert!(f.blocks("extra.example"));
        assert!(!f.blocks("a.extra.example"));
        assert!(f.blocks("expressvpn.com"));
        assert!(
            !f.blocks("us1.expressvpn.com"),
            "the VPN server stays reachable"
        );
        assert!(!Filter::default().blocks("doubleclick.net"));
    }

    #[tokio::test]
    async fn uses_a_fresh_cache() {
        let dir = tempfile::tempdir().unwrap();
        let list = portal_core::blocking::blocklist("ads").unwrap();
        std::fs::write(dir.path().join("ads.txt"), "ads.example\n").unwrap();
        let l = load(dir.path(), list, false).await.unwrap();
        assert_eq!(l.hashes, vec![hash("ads.example")]);
        assert!(l.stale.is_none());
        assert!(l.updated_at > 0);
    }
}
