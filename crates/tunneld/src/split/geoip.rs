//! Country IP ranges for split tunneling, from the regional internet
//! registries' delegation data as aggregated by ipverse (with ipdeny as a
//! fallback). Lists are cached on disk and refreshed weekly.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use tracing::{info, warn};
use tunnel_core::split::Rule;

const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);
const USER_AGENT: &str = concat!("tunneld/", env!("CARGO_PKG_VERSION"));

fn sources(cc: &str) -> [[String; 2]; 2] {
    let lc = cc.to_ascii_lowercase();
    [
        [
            format!(
                "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/{lc}/ipv4-aggregated.txt"
            ),
            format!(
                "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/{lc}/ipv6-aggregated.txt"
            ),
        ],
        [
            format!("https://www.ipdeny.com/ipblocks/data/aggregated/{lc}-aggregated.zone"),
            format!("https://www.ipdeny.com/ipv6/ipaddresses/aggregated/{lc}-aggregated.zone"),
        ],
    ]
}

/// Parse a list: one network per line, `#` comments. Bad lines are skipped.
pub fn parse(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| Rule::parse(l).ok())
        .filter_map(|r| r.nft_element())
        .collect()
}

async fn download(client: &reqwest::Client, urls: &[String; 2]) -> Result<String> {
    let mut text = String::new();
    for url in urls {
        let body = client
            .get(url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .with_context(|| format!("downloading {url}"))?
            .text()
            .await?;
        text.push_str(&body);
        text.push('\n');
    }
    if parse(&text).is_empty() {
        bail!("the list was empty");
    }
    Ok(text)
}

fn fresh(path: &Path) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|age| age < MAX_AGE)
}

/// Networks for `country` (ISO code), from the cache or the network. Falls
/// back to a stale cache when the download fails.
pub async fn networks(cache_dir: &Path, country: &str) -> Result<Vec<String>> {
    let path: PathBuf = cache_dir.join(format!("{}.txt", country.to_ascii_lowercase()));
    if fresh(&path) {
        return Ok(parse(&std::fs::read_to_string(&path)?));
    }
    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut last_err = None;
    for urls in sources(country) {
        match download(&client, &urls).await {
            Ok(text) => {
                std::fs::create_dir_all(cache_dir)?;
                std::fs::write(&path, &text)?;
                let nets = parse(&text);
                info!("{country}: {} networks", nets.len());
                return Ok(nets);
            }
            Err(e) => {
                warn!("{country}: {e:#}");
                last_err = Some(e);
            }
        }
    }
    if let Ok(text) = std::fs::read_to_string(&path) {
        warn!("{country}: using an older list");
        return Ok(parse(&text));
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no source for {country}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lists() {
        let text =
            "# Country: Iran (IR)\n2.144.0.0/14\n\n5.22.0.0/17\nnot a network\n2a01:5ec0::/29\n";
        assert_eq!(
            parse(text),
            vec!["2.144.0.0/14", "5.22.0.0/17", "2a01:5ec0::/29"]
        );
    }

    #[tokio::test]
    async fn uses_a_fresh_cache() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ir.txt"), "1.0.0.0/8\n").unwrap();
        assert_eq!(networks(dir.path(), "IR").await.unwrap(), vec!["1.0.0.0/8"]);
    }
}
