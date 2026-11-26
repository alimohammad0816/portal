#!/usr/bin/env bash
# Release notes from the commit titles since the previous tag, as Markdown.
# The app shows them in its update dialog, so they say what changed for
# users: version bumps and commits that only touch CI are left out.
#
#   scripts/release-notes.sh v0.2.0 [owner/repo] > notes.md
set -euo pipefail

cd "$(dirname "$0")/.."

tag="${1:?usage: $0 TAG [owner/repo]}"
repo="${2:-${GITHUB_REPOSITORY:-}}"
prev=$(git describe --tags --abbrev=0 --match 'v*' "$tag^" 2>/dev/null || true)
range="${prev:+$prev..}$tag"

# Only CI and its test helpers; anything else may matter to users.
ci_only() {
  local files
  files=$(git diff-tree --no-commit-id --name-only -r "$1")
  [[ -n "$files" ]] && ! grep -qvE '^(\.github/|packaging/ci/)' <<<"$files"
}

lines=()
while IFS=' ' read -r sha subject; do
  [[ "$subject" =~ ^Release\ v[0-9] ]] && continue
  ci_only "$sha" && continue
  lines+=("- $subject")
done < <(git log --reverse --no-merges --format='%H %s' "$range")

if ((${#lines[@]} == 0)); then
  echo "- Maintenance release."
else
  printf '%s\n' "${lines[@]}"
fi
if [[ -n "$prev" && -n "$repo" ]]; then
  printf '\n**Full changelog**: [%s...%s](https://github.com/%s/compare/%s...%s)\n' \
    "$prev" "$tag" "$repo" "$prev" "$tag"
fi
