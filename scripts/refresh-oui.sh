#!/usr/bin/env bash
#
# Regenerates data/oui.tsv from the IEEE registries.
#
# The file is checked in, so a build never needs network access. Run this when
# the vendor lookups start missing new hardware, and commit the result.
#
# Output format: PREFIX<TAB>ORGANISATION, one per line, sorted and deduplicated.
# Prefixes are 6 hex digits (MA-L, 24-bit), 7 (MA-M, 28-bit) or 9 (MA-S,
# 36-bit); the lookup tries the longest first, because the 24-bit blocks IEEE
# has subdivided are registered to "IEEE Registration Authority" itself.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$here/data/oui.tsv"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for spec in "oui/oui:MA-L" "oui28/mam:MA-M" "oui36/oui36:MA-S"; do
    path="${spec%%:*}"
    label="${spec##*:}"
    name="$(basename "$path")"
    echo "fetching $label..."
    curl -sSL --fail --max-time 300 \
        -o "$work/$name.csv" \
        "https://standards-oui.ieee.org/$path.csv"
done

# The CSV has quoted fields containing commas, so it needs a real parser rather
# than cut or awk. Perl's Text::ParseWords is in every core install.
cat "$work"/*.csv | perl -MText::ParseWords -ne '
    next if /^Registry,/;
    chomp; s/\r$//;
    my @f = parse_line(",", 0, $_);
    next unless defined $f[1] && defined $f[2];
    my ($assignment, $org) = (uc($f[1]), $f[2]);
    next unless $assignment =~ /^[0-9A-F]{6,9}$/;
    $org =~ s/\t/ /g;
    $org =~ s/^\s+|\s+$//g;
    $org =~ s/\s+/ /g;
    next if $org eq "";
    print "$assignment\t$org\n";
' | sort -u > "$work/oui.tsv"

count="$(wc -l < "$work/oui.tsv" | tr -d ' ')"
if [ "$count" -lt 40000 ]; then
    echo "refusing to install a suspiciously small registry ($count entries)" >&2
    exit 1
fi

mv "$work/oui.tsv" "$out"
echo "wrote $out ($count entries)"
echo "run 'cargo test --lib identity::oui' to confirm the lookups still work"
