#!/usr/bin/env bash
# Bump the version everywhere, commit, tag and push. GitHub Actions then
# builds, signs and publishes the .deb, and installed apps offer the update.
#
#   scripts/release.sh 0.2.0
set -euo pipefail

cd "$(dirname "$0")/.."

new="${1:-}"
if [[ ! "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 X.Y.Z" >&2
  exit 2
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Commit or stash your changes first." >&2
  exit 1
fi
if git rev-parse "v$new" >/dev/null 2>&1; then
  echo "Tag v$new already exists." >&2
  exit 1
fi

old=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
echo "Releasing $old -> $new"

sed -i "0,/^version = \"$old\"/s//version = \"$new\"/" Cargo.toml
sed -i "s/\"version\": \"$old\"/\"version\": \"$new\"/" apps/desktop/package.json
cargo update --workspace --quiet

cargo test --workspace --quiet

git add Cargo.toml Cargo.lock apps/desktop/package.json
git commit -m "Release v$new"
git tag -a "v$new" -m "Tunnel $new"
git push origin HEAD "v$new"

echo "Pushed v$new. Follow the build under the repository's Actions tab."
