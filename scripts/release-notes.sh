#!/usr/bin/env bash
#
# Print one version's section of CHANGELOG.md, without its heading, for the
# GitHub Release notes. The release workflow runs it twice: once before the
# build, so a tag with no changelog section fails in seconds rather than after
# the arm64 emulation, and once to write the notes.
#
# Usage: scripts/release-notes.sh 1.0.0

set -euo pipefail

version="${1:?usage: $0 <version>}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

notes="$(awk -v heading="## [$version]" '
    index($0, heading) == 1 { found = 1; next }
    found && /^## \[/        { exit }
    found                    { print }
' "$root/CHANGELOG.md")"

# Trim the blank lines either side, and refuse an empty section.
notes="$(printf '%s\n' "$notes" | sed -e '/./,$!d')"
if ! printf '%s' "$notes" | grep -q '[^[:space:]]'; then
    echo "error: CHANGELOG.md has no section for [$version]" >&2
    exit 1
fi

printf '%s\n' "$notes"
