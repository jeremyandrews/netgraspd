//! Vendor lookup against the IEEE MAC address registries, embedded at build
//! time.
//!
//! `data/oui.tsv` is a compaction of the three IEEE registries into
//! `PREFIX<TAB>ORGANISATION` lines: MA-L (24-bit, six hex digits), MA-M
//! (28-bit, seven) and MA-S (36-bit, nine). Regenerate it with
//! `scripts/refresh-oui.sh`.
//!
//! Lookups try the longest prefix first, because the 24-bit blocks that IEEE
//! has subdivided are registered to "IEEE Registration Authority" itself and
//! carry no useful vendor. Such a hit is treated as no hit.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::types::MacAddr;

/// The compacted registry, embedded in the binary.
const OUI_TSV: &str = include_str!("../../data/oui.tsv");

/// Placeholder organisation on 24-bit blocks that IEEE has subdivided into
/// MA-M or MA-S assignments. Never a real vendor.
const REGISTRY_PLACEHOLDER: &str = "IEEE Registration Authority";

/// Prefix widths, in hex digits, longest first.
const PREFIX_WIDTHS: [usize; 3] = [9, 7, 6];

/// Parsed registry, built once on first lookup.
fn table() -> &'static HashMap<&'static str, &'static str> {
    static TABLE: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut map = HashMap::with_capacity(64 * 1024);
        for line in OUI_TSV.lines() {
            let Some((prefix, org)) = line.split_once('\t') else {
                continue;
            };
            if prefix.is_empty() || org.is_empty() {
                continue;
            }
            map.insert(prefix, org);
        }
        map
    })
}

/// Number of registry entries embedded in this build.
#[must_use]
pub fn entry_count() -> usize {
    table().len()
}

/// Returns the registered organisation for a MAC address, if there is one.
///
/// Returns `None` for a locally-administered (randomised) address, because a
/// vendor guess from one is meaningless, and for a prefix that resolves only to
/// the IEEE placeholder organisation.
#[must_use]
pub fn lookup(mac: MacAddr) -> Option<&'static str> {
    if mac.is_locally_administered() || mac.is_group() || mac.is_zero() {
        return None;
    }
    let t = table();
    for width in PREFIX_WIDTHS {
        if let Some(org) = t.get(mac.hex_prefix(width).as_str())
            && *org != REGISTRY_PLACEHOLDER
        {
            return Some(org);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(s: &str) -> MacAddr {
        s.parse().expect("test mac parses")
    }

    #[test]
    fn registry_is_embedded_and_substantial() {
        // A truncated or missing data file would silently disable every vendor
        // signal, so assert the order of magnitude rather than an exact count.
        assert!(
            entry_count() > 40_000,
            "expected the full IEEE registry, got {} entries",
            entry_count()
        );
    }

    #[test]
    fn resolves_well_known_24_bit_blocks() {
        assert_eq!(lookup(mac("3c:22:fb:11:22:33")), Some("Apple, Inc."));
        assert_eq!(
            lookup(mac("b8:27:eb:aa:bb:cc")),
            Some("Raspberry Pi Foundation")
        );
    }

    #[test]
    fn prefers_the_longest_matching_prefix() {
        // 8C1F64 is an IEEE-subdivided block; 8C1F64AFA is a real MA-S
        // assignment inside it. The long match must win.
        assert_eq!(
            lookup(mac("8c:1f:64:af:a1:23")),
            Some("DATA ELECTRONIC DEVICES, INC")
        );
    }

    #[test]
    fn subdivided_block_with_no_long_match_is_not_a_vendor() {
        // ...FF F is very unlikely to be an assigned MA-S, so the only hit is
        // the placeholder, which must be suppressed.
        assert_eq!(lookup(mac("8c:1f:64:ff:ff:ff")), None);
    }

    #[test]
    fn randomised_and_group_addresses_have_no_vendor() {
        assert_eq!(
            lookup(mac("02:11:22:33:44:55")),
            None,
            "locally administered"
        );
        assert_eq!(lookup(mac("ff:ff:ff:ff:ff:ff")), None, "broadcast");
        assert_eq!(lookup(mac("01:00:5e:00:00:fb")), None, "multicast");
        assert_eq!(lookup(mac("00:00:00:00:00:00")), None, "all zero");
    }

    #[test]
    fn unassigned_prefix_returns_none() {
        // The 0x?E first octet range used here is universally administered but
        // the block is unassigned in the registry.
        assert_eq!(lookup(mac("fc:ff:ff:00:00:01")), None);
    }
}
