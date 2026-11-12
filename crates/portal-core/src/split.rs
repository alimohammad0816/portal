//! Split tunneling rules: what a user-entered host string means, and
//! matching domain names against the list.

use std::net::IpAddr;

/// One entry of the hosts list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// A domain and all of its subdomains, lower case, no trailing dot.
    /// `*.ir` and `ir` both become `Domain("ir")`.
    Domain(String),
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
        let d = s
            .trim_start_matches("*.")
            .trim_start_matches('.')
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
        Ok(Rule::Domain(d))
    }

    /// nft set element, e.g. `10.0.0.0/8` or `1.2.3.4`.
    pub fn nft_element(&self) -> Option<String> {
        match self {
            Rule::Net { addr, prefix } if (addr.is_ipv4() && *prefix == 32) || *prefix == 128 => {
                Some(addr.to_string())
            }
            Rule::Net { addr, prefix } => Some(format!("{addr}/{prefix}")),
            Rule::Domain(_) => None,
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

/// Domain suffixes to match lookups against.
#[derive(Debug, Clone, Default)]
pub struct DomainList {
    suffixes: Vec<String>,
}

impl DomainList {
    pub fn new<'a>(rules: impl IntoIterator<Item = &'a Rule>) -> Self {
        let mut suffixes: Vec<String> = rules
            .into_iter()
            .filter_map(|r| match r {
                Rule::Domain(d) => Some(d.clone()),
                Rule::Net { .. } => None,
            })
            .collect();
        suffixes.sort();
        suffixes.dedup();
        Self { suffixes }
    }

    pub fn is_empty(&self) -> bool {
        self.suffixes.is_empty()
    }

    pub fn suffixes(&self) -> &[String] {
        &self.suffixes
    }

    /// `www.Example.com.` matches `example.com`; `notexample.com` doesn't.
    pub fn matches(&self, name: &str) -> bool {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        self.suffixes.iter().any(|s| {
            name == *s
                || (name.len() > s.len()
                    && name.ends_with(s.as_str())
                    && name.as_bytes()[name.len() - s.len() - 1] == b'.')
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hosts() {
        assert_eq!(Rule::parse("*.IR").unwrap(), Rule::Domain("ir".into()));
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
    fn matches_suffixes_on_label_boundaries() {
        let rules = ["*.ir", "digikala.com", "1.2.3.4"].map(|h| Rule::parse(h).unwrap());
        let list = DomainList::new(&rules);
        assert!(list.matches("www.digikala.com."));
        assert!(list.matches("DIGIKALA.com"));
        assert!(list.matches("snapp.ir"));
        assert!(list.matches("ir"));
        assert!(!list.matches("notdigikala.com"));
        assert!(!list.matches("example.com"));
        assert_eq!(list.suffixes(), ["digikala.com", "ir"]);
    }
}
