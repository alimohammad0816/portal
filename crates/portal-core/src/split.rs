//! Split tunneling rules: what a user-entered host string means, and
//! matching domain names against the list.

use std::net::IpAddr;

/// One entry of the hosts list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// Exactly this name, lower case, no trailing dot: `example.com`.
    Domain(String),
    /// Every subdomain of this name, but not the name itself:
    /// `*.example.com`, or `*.ir` for a whole TLD.
    Subdomains(String),
    /// An address or a network.
    Net { addr: IpAddr, prefix: u8 },
}

impl Rule {
    pub fn parse(input: &str) -> Result<Rule, String> {
        let s = input.trim();
        if s.is_empty() {
            return Err("Empty host.".into());
        }
        if let Some((a, p)) = s.split_once('/') {
            let addr: IpAddr = a
                .parse()
                .map_err(|_| format!("`{s}` isn't a valid network."))?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            let prefix: u8 = p
                .parse()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("`{s}` has an invalid prefix length."))?;
            return Ok(Rule::Net {
                addr: network(addr, prefix),
                prefix,
            });
        }
        if let Ok(addr) = s.parse::<IpAddr>() {
            let prefix = if addr.is_ipv4() { 32 } else { 128 };
            return Ok(Rule::Net { addr, prefix });
        }
        let wildcard = s.starts_with("*.");
        let d = s
            .trim_start_matches("*.")
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let valid = !d.is_empty()
            && d.len() <= 253
            && d.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            });
        if !valid {
            return Err(format!("`{s}` isn't a domain, IP address or network."));
        }
        Ok(if wildcard {
            Rule::Subdomains(d)
        } else {
            Rule::Domain(d)
        })
    }

    /// nft set element, e.g. `10.0.0.0/8` or `1.2.3.4`.
    pub fn nft_element(&self) -> Option<String> {
        match self {
            Rule::Net { addr, prefix } if (addr.is_ipv4() && *prefix == 32) || *prefix == 128 => {
                Some(addr.to_string())
            }
            Rule::Net { addr, prefix } => Some(format!("{addr}/{prefix}")),
            Rule::Domain(_) | Rule::Subdomains(_) => None,
        }
    }
}

/// Zero the host bits so `10.1.2.3/8` becomes `10.0.0.0/8`, which nft
/// requires for interval sets.
pub fn network(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            IpAddr::V4((bits & mask).into())
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            IpAddr::V6((bits & mask).into())
        }
    }
}

/// Domain rules to match lookups against.
#[derive(Debug, Clone, Default)]
pub struct DomainList {
    /// Names matched exactly.
    exact: Vec<String>,
    /// Names whose subdomains match.
    parents: Vec<String>,
}

impl DomainList {
    pub fn new<'a>(rules: impl IntoIterator<Item = &'a Rule>) -> Self {
        let mut list = Self::default();
        for r in rules {
            match r {
                Rule::Domain(d) => list.exact.push(d.clone()),
                Rule::Subdomains(d) => list.parents.push(d.clone()),
                Rule::Net { .. } => {}
            }
        }
        for v in [&mut list.exact, &mut list.parents] {
            v.sort();
            v.dedup();
        }
        list
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.parents.is_empty()
    }

    /// Domains to hand resolved as routing domains (each also routes its
    /// subdomains there, which is fine: the proxy decides what's split).
    pub fn routing_domains(&self) -> Vec<String> {
        let mut all: Vec<String> = self.exact.iter().chain(&self.parents).cloned().collect();
        all.sort();
        all.dedup();
        all
    }

    /// `example.com` matches only `example.com`; `*.example.com` matches
    /// `www.example.com` and deeper names but not `example.com` or
    /// `notexample.com`. Case and a trailing dot don't matter.
    pub fn matches(&self, name: &str) -> bool {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        self.exact.contains(&name)
            || self.parents.iter().any(|p| {
                name.len() > p.len()
                    && name.ends_with(p.as_str())
                    && name.as_bytes()[name.len() - p.len() - 1] == b'.'
            })
    }
}

/// Rewrite hosts saved before version 1, when `example.com` and
/// `*.example.com` both meant the name and all its subdomains, so they
/// keep matching the same names: `example.com` + `*.example.com`. A bare
/// TLD (`*.ir`) only needs the wildcard.
pub fn migrate_hosts_v1(hosts: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |h: String| {
        if !out.contains(&h) {
            out.push(h);
        }
    };
    for h in hosts {
        match Rule::parse(h) {
            Ok(Rule::Domain(d) | Rule::Subdomains(d)) => {
                if d.contains('.') {
                    push(d.clone());
                }
                push(format!("*.{d}"));
            }
            _ => push(h.clone()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hosts() {
        assert_eq!(Rule::parse("*.IR").unwrap(), Rule::Subdomains("ir".into()));
        assert!(Rule::parse(".ir").is_err());
        assert!(Rule::parse("a.*.ir").is_err());
        assert_eq!(
            Rule::parse("digikala.com.").unwrap(),
            Rule::Domain("digikala.com".into())
        );
        assert_eq!(
            Rule::parse("185.143.233.120/22").unwrap(),
            Rule::Net {
                addr: "185.143.232.0".parse().unwrap(),
                prefix: 22
            }
        );
        assert_eq!(
            Rule::parse("192.168.1.10").unwrap().nft_element().unwrap(),
            "192.168.1.10"
        );
        assert_eq!(
            Rule::parse("2001:db8::1/32")
                .unwrap()
                .nft_element()
                .unwrap(),
            "2001:db8::/32"
        );
        assert!(Rule::parse("10.0.0.0/33").is_err());
        assert!(Rule::parse("bad host!").is_err());
        assert!(Rule::parse("").is_err());
    }

    #[test]
    fn matches_exact_names_and_subdomains() {
        let rules = [
            "*.ir",
            "digikala.com",
            "api.sabtira.ir",
            "*.example.org",
            "1.2.3.4",
        ]
        .map(|h| Rule::parse(h).unwrap());
        let list = DomainList::new(&rules);
        assert!(list.matches("DIGIKALA.com."));
        assert!(!list.matches("www.digikala.com"), "a plain name is exact");
        assert!(list.matches("snapp.ir"));
        assert!(list.matches("a.b.snapp.ir"));
        assert!(
            !list.matches("ir"),
            "a wildcard doesn't cover the name itself"
        );
        assert!(list.matches("www.example.org"));
        assert!(!list.matches("example.org"));
        assert!(!list.matches("notexample.org"));
        assert!(!list.matches("example.com"));
        assert_eq!(
            list.routing_domains(),
            ["api.sabtira.ir", "digikala.com", "example.org", "ir"]
        );
    }

    #[test]
    fn migrates_old_hosts() {
        let old = [
            "sabtira.ir",
            "*.sabtira.ir",
            "*.ir",
            "10.0.0.0/8",
            "digikala.com.",
        ]
        .map(String::from);
        assert_eq!(
            migrate_hosts_v1(&old),
            [
                "sabtira.ir",
                "*.sabtira.ir",
                "*.ir",
                "10.0.0.0/8",
                "digikala.com",
                "*.digikala.com"
            ]
        );
    }
}
