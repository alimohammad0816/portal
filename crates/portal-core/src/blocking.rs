//! Blocking: categories of domains the daemon's DNS proxy answers with
//! nothing while connected (like an ad-blocking resolver), plus the user's
//! own allow and block rules.

use serde::{Deserialize, Serialize};

use crate::split::Rule;

/// A category the user can turn on, and the public list behind it. Every
/// entry blocks the domain and all its subdomains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blocklist {
    pub id: &'static str,
    pub url: &'static str,
}

macro_rules! hagezi {
    ($name:literal) => {
        concat!(
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/",
            $name,
            "-onlydomains.txt"
        )
    };
}

/// The categories, in the order the app shows them.
pub const BLOCKLISTS: &[Blocklist] = &[
    Blocklist {
        id: "malware",
        url: hagezi!("tif.mini"),
    },
    Blocklist {
        id: "ads",
        url: hagezi!("pro"),
    },
    Blocklist {
        id: "social",
        url: hagezi!("social"),
    },
    Blocklist {
        id: "adult",
        url: hagezi!("nsfw"),
    },
    Blocklist {
        id: "gambling",
        url: hagezi!("gambling.mini"),
    },
    Blocklist {
        id: "scams",
        url: hagezi!("fake"),
    },
    Blocklist {
        id: "vpn",
        url: hagezi!("doh-vpn-proxy-bypass"),
    },
    Blocklist {
        id: "crypto",
        url: "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt",
    },
];

pub fn blocklist(id: &str) -> Option<&'static Blocklist> {
    BLOCKLISTS.iter().find(|b| b.id == id)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BlockingSettings {
    /// Ids of the categories that are on.
    pub lists: Vec<String>,
    /// Domains that are never blocked, in split rule syntax:
    /// `example.com` is that name, `*.example.com` its subdomains.
    pub allow: Vec<String>,
    /// More domains to block, same syntax.
    pub block: Vec<String>,
}

impl BlockingSettings {
    /// Whether anything is blocked at all.
    pub fn active(&self) -> bool {
        !self.lists.is_empty() || !self.block.is_empty()
    }

    pub fn validate(&self) -> Result<(), String> {
        for id in &self.lists {
            if blocklist(id).is_none() {
                return Err(format!("`{id}` isn't a blocklist."));
            }
        }
        if self.allow.len() > 2000 || self.block.len() > 2000 {
            return Err("That's too many blocking rules.".into());
        }
        for d in self.allow.iter().chain(&self.block) {
            match Rule::parse(d)? {
                Rule::Domain(_) | Rule::Subdomains(_) => {}
                Rule::Net { .. } => return Err(format!("`{d}` isn't a domain.")),
            }
        }
        Ok(())
    }
}

/// How a category is doing, for the app.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BlocklistStatus {
    pub id: String,
    /// Domains in the list; 0 until it's loaded.
    pub domains: usize,
    /// Unix seconds the list was downloaded.
    pub updated_at: Option<u64>,
    /// Being downloaded or read right now.
    pub loading: bool,
    /// Why the last download failed.
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_consistent() {
        let mut ids: Vec<_> = BLOCKLISTS.iter().map(|b| b.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), BLOCKLISTS.len());
        assert!(BLOCKLISTS.iter().all(|b| b.url.starts_with("https://")));
        assert!(
            blocklist("ads")
                .unwrap()
                .url
                .ends_with("/wildcard/pro-onlydomains.txt")
        );
    }

    #[test]
    fn validates() {
        let mut s = BlockingSettings {
            lists: vec!["ads".into()],
            allow: vec!["*.example.com".into()],
            block: vec!["tracker.example".into()],
        };
        assert!(s.validate().is_ok());
        assert!(s.active());
        s.lists.push("nope".into());
        assert!(s.validate().is_err());
        s.lists.pop();
        s.block.push("10.0.0.0/8".into());
        assert!(s.validate().is_err());
        assert!(!BlockingSettings::default().active());
    }
}
