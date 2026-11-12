//! How Portal was installed, which decides which release file an update
//! uses and how the daemon installs it. Each package ships a one-word
//! marker file naming its own format.

use std::path::Path;

/// Written by the package: `deb`, `rpm` or `arch`.
pub const FORMAT_FILE: &str = "/usr/lib/portal/package-format";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageFormat {
    Deb,
    Rpm,
    Arch,
}

impl PackageFormat {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "deb" => Some(Self::Deb),
            "rpm" => Some(Self::Rpm),
            "arch" => Some(Self::Arch),
            _ => None,
        }
    }

    /// The format this copy was installed as. Packages before 0.1.2 had
    /// no marker and were all .deb.
    pub fn installed() -> Self {
        Self::read(Path::new(FORMAT_FILE)).unwrap_or(Self::Deb)
    }

    fn read(path: &Path) -> Option<Self> {
        Self::parse(&std::fs::read_to_string(path).ok()?)
    }

    /// End of the release file name for this format on `arch` (Rust's
    /// `std::env::consts::ARCH`); `None` where no package is built.
    pub fn asset_suffix(self, arch: &str) -> Option<&'static str> {
        Some(match (self, arch) {
            (Self::Deb, "x86_64") => "_amd64.deb",
            (Self::Deb, "aarch64") => "_arm64.deb",
            (Self::Rpm, "x86_64") => ".x86_64.rpm",
            (Self::Rpm, "aarch64") => ".aarch64.rpm",
            (Self::Arch, "x86_64") => "-x86_64.pkg.tar.zst",
            _ => return None,
        })
    }

    /// File extension the package tools expect.
    pub fn extension(self) -> &'static str {
        match self {
            Self::Deb => "deb",
            Self::Rpm => "rpm",
            Self::Arch => "pkg.tar.zst",
        }
    }
}

/// `1.2.10` > `1.2.9`. A leading `v`, pre-release suffixes and package
/// revisions (`0.2.0-1`) are ignored.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    let parse = |v: &str| -> Vec<u64> {
        v.trim_start_matches('v')
            .split(['-', '+'])
            .next()
            .unwrap_or("")
            .split('.')
            .map(|p| p.parse().unwrap_or(0))
            .collect()
    };
    let (a, b) = (parse(candidate), parse(current));
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (
            a.get(i).copied().unwrap_or(0),
            b.get(i).copied().unwrap_or(0),
        );
        if x != y {
            return x > y;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_versions() {
        assert!(is_newer("v0.2.0", "0.1.9"));
        assert!(is_newer("0.10.0", "0.9.3"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(is_newer("0.1.2-1", "0.1.1"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("v0.1.0-rc1", "0.1.0"));
        assert!(!is_newer("0.0.9", "0.1.0"));
    }

    #[test]
    fn picks_release_files() {
        assert_eq!(
            PackageFormat::Deb.asset_suffix("x86_64"),
            Some("_amd64.deb")
        );
        assert_eq!(
            PackageFormat::Rpm.asset_suffix("aarch64"),
            Some(".aarch64.rpm")
        );
        assert_eq!(PackageFormat::Arch.asset_suffix("aarch64"), None);
        assert_eq!(PackageFormat::parse("rpm\n"), Some(PackageFormat::Rpm));
        assert_eq!(PackageFormat::parse("snap"), None);
    }
}
