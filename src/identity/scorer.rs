//! The weighted scorer that turns a pile of raw signals into one display
//! identity.
//!
//! Every signal a capture source produces is stored in `ng_device_signals` and
//! kept forever, so a later signal *refines* the identity instead of
//! overwriting it: a device first seen as `Apple, Inc. device` becomes
//! `Living Room Apple TV` when mDNS finally announces, and stays there even if
//! a weaker reverse-DNS answer arrives afterwards.
//!
//! A name typed by a human in the Trovato UI is an absolute override and is not
//! scored against anything.

use crate::types::{MacAddr, Signal, SignalKind};

/// Everything the scorer needs to know about one device.
#[derive(Debug, Clone)]
pub struct IdentityInput<'a> {
    /// The device's hardware address, the identity of last resort.
    pub mac: MacAddr,
    /// Every stored signal for the device.
    ///
    /// Where two signals share a kind, the one appearing **earlier** in the
    /// slice wins. Callers reading from `ng_device_signals` order by
    /// `last_seen_at DESC`, so that means "the most recently confirmed value".
    pub signals: &'a [Signal],
    /// Classified device type, when one is known. Milestone 1 never sets this;
    /// it exists so that the vendor signal can render as `Brother printer`
    /// once classification lands.
    pub device_type: Option<&'a str>,
}

/// The chosen display identity for a device.
#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    /// The name to show.
    pub display_name: String,
    /// Which signal kind produced it.
    pub source: SignalKind,
    /// The weight of that kind, carried through so the UI can show how much to
    /// trust the name.
    pub confidence: f64,
}

/// Chooses a display identity.
///
/// Order of decision:
///
/// 1. A `UserAssigned` signal wins outright.
/// 2. Otherwise the highest-weighted kind present wins.
/// 3. Ties between two different kinds cannot happen, because every kind has a
///    distinct weight; ties within a kind are broken by slice order.
/// 4. A device with no usable signal at all falls back to its bare MAC.
#[must_use]
pub fn resolve(input: &IdentityInput<'_>) -> Identity {
    if let Some(sig) = first_usable(input.signals, SignalKind::UserAssigned) {
        return Identity {
            display_name: sig.to_string(),
            source: SignalKind::UserAssigned,
            confidence: SignalKind::UserAssigned.weight(),
        };
    }

    // Every naming kind, strongest first. Vendor is handled separately because
    // it composes with the device type rather than standing alone.
    const NAMING: [SignalKind; 5] = [
        SignalKind::MdnsName,
        SignalKind::DhcpHostname,
        SignalKind::ReverseDns,
        SignalKind::NetbiosName,
        SignalKind::SsdpFriendlyName,
    ];
    for kind in NAMING {
        if let Some(value) = first_usable(input.signals, kind) {
            return Identity {
                display_name: value.to_string(),
                source: kind,
                confidence: kind.weight(),
            };
        }
    }

    if let Some(vendor) = first_usable(input.signals, SignalKind::Vendor) {
        return Identity {
            display_name: match input.device_type {
                Some(t) if !t.trim().is_empty() => format!("{vendor} {}", t.trim()),
                _ => format!("{vendor} device"),
            },
            source: SignalKind::Vendor,
            confidence: SignalKind::Vendor.weight(),
        };
    }

    Identity {
        display_name: input.mac.to_string(),
        source: SignalKind::Mac,
        confidence: SignalKind::Mac.weight(),
    }
}

/// First signal of the given kind whose value is not blank.
///
/// Blank values are skipped rather than trusted: an empty mDNS instance name
/// would otherwise beat a perfectly good vendor string.
fn first_usable(signals: &[Signal], kind: SignalKind) -> Option<&str> {
    signals
        .iter()
        .filter(|s| s.kind == kind)
        .map(|s| s.value.trim())
        .find(|v| !v.is_empty())
}

/// How a candidate identity compares with the one a device already has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing changed.
    Same,
    /// The candidate wins on rank, so it is adopted at once.
    Better,
    /// The candidate is a different name of exactly the same rank.
    ///
    /// **This is the flapping case and it is not adopted at once.** Two mDNS
    /// names of equal weight take turns winning the same-kind tie-break as
    /// consecutive frames reorder the signal list, and adopting each turn
    /// produced 385 `name_updated` events in thirty minutes on a real network.
    /// See [`settled`].
    Rival,
    /// The candidate is worse and is ignored.
    Worse,
}

/// Compares a candidate identity with the current one.
///
/// Rank is the whole of the comparison, and rank alone can promote a name
/// immediately: a device that was `Apple, Inc. device` and has just announced
/// over mDNS should be renamed on the spot. An equal-rank rival is a different
/// question, answered by [`settled`] rather than here.
#[must_use]
pub fn compare(candidate: &Identity, current: &Identity) -> Verdict {
    if candidate.confidence > current.confidence {
        Verdict::Better
    } else if candidate.confidence < current.confidence {
        Verdict::Worse
    } else if candidate.display_name == current.display_name {
        Verdict::Same
    } else {
        Verdict::Rival
    }
}

/// How long an equal-rank rival must stay the winner before it is adopted.
///
/// Five minutes. The number is a compromise between the two ways of being
/// wrong. Shorter, and a pair of alternating mDNS names still gets through:
/// responders re-announce on the order of a minute, so a window under a couple
/// of announcement intervals does not prove anything settled. Longer, and a
/// person who genuinely renames their laptop waits too long to see it. Nothing
/// is lost by waiting either way, because the name itself is already stored as a
/// signal the moment it arrives; only the display identity and its event are
/// held back.
///
/// A rival that wins on *rank* is never delayed by this.
pub const SETTLE_WINDOW: std::time::Duration = std::time::Duration::from_secs(300);

/// Whether an equal-rank rival has been the winner for long enough to adopt.
///
/// `since` is when this same rival first won. A rival that loses even once
/// resets it, so alternating candidates never settle and never produce an event.
#[must_use]
pub fn settled(since: chrono::DateTime<chrono::Utc>, now: chrono::DateTime<chrono::Utc>) -> bool {
    now.signed_duration_since(since)
        .to_std()
        .is_ok_and(|elapsed| elapsed >= SETTLE_WINDOW)
}

/// True when `candidate` is a strictly better identity than `current`.
///
/// Kept as the rank-only question, which is what callers outside the device
/// manager mean when they ask. The manager itself uses [`compare`] and
/// [`settled`], because it is the only caller that can hold a rival pending.
#[must_use]
pub fn improves_on(candidate: &Identity, current: &Identity) -> bool {
    matches!(
        compare(candidate, current),
        Verdict::Better | Verdict::Rival
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac() -> MacAddr {
        "3c:22:fb:01:02:03".parse().expect("test mac")
    }

    fn resolve_with(signals: &[Signal]) -> Identity {
        resolve(&IdentityInput {
            mac: mac(),
            signals,
            device_type: None,
        })
    }

    #[test]
    fn bare_mac_is_the_floor() {
        let id = resolve_with(&[]);
        assert_eq!(id.display_name, "3c:22:fb:01:02:03");
        assert_eq!(id.source, SignalKind::Mac);
        assert_eq!(id.confidence, 0.1);
    }

    #[test]
    fn vendor_alone_renders_as_a_generic_device() {
        let id = resolve_with(&[Signal::new(SignalKind::Vendor, "Apple, Inc.")]);
        assert_eq!(id.display_name, "Apple, Inc. device");
        assert_eq!(id.source, SignalKind::Vendor);
    }

    #[test]
    fn vendor_composes_with_a_known_device_type() {
        let signals = [Signal::new(SignalKind::Vendor, "Brother Industries, LTD.")];
        let id = resolve(&IdentityInput {
            mac: mac(),
            signals: &signals,
            device_type: Some("printer"),
        });
        assert_eq!(id.display_name, "Brother Industries, LTD. printer");
    }

    #[test]
    fn mdns_beats_every_weaker_signal() {
        let id = resolve_with(&[
            Signal::new(SignalKind::Vendor, "Apple, Inc."),
            Signal::new(SignalKind::ReverseDns, "apple-tv.lan"),
            Signal::new(SignalKind::MdnsName, "Living Room Apple TV"),
            Signal::new(SignalKind::NetbiosName, "APPLETV"),
        ]);
        assert_eq!(id.display_name, "Living Room Apple TV");
        assert_eq!(id.source, SignalKind::MdnsName);
        assert_eq!(id.confidence, 0.9);
    }

    #[test]
    fn the_full_weight_ladder_is_respected_in_order() {
        // Peel the strongest signal off one at a time and check that the next
        // rung of the ladder takes over.
        let mut signals = vec![
            Signal::new(SignalKind::MdnsName, "mdns"),
            Signal::new(SignalKind::DhcpHostname, "dhcp"),
            Signal::new(SignalKind::ReverseDns, "rdns"),
            Signal::new(SignalKind::NetbiosName, "netbios"),
            Signal::new(SignalKind::SsdpFriendlyName, "ssdp"),
            Signal::new(SignalKind::Vendor, "Vendor"),
        ];
        let expected = [
            ("mdns", SignalKind::MdnsName),
            ("dhcp", SignalKind::DhcpHostname),
            ("rdns", SignalKind::ReverseDns),
            ("netbios", SignalKind::NetbiosName),
            ("ssdp", SignalKind::SsdpFriendlyName),
            ("Vendor device", SignalKind::Vendor),
        ];
        for (name, kind) in expected {
            let id = resolve_with(&signals);
            assert_eq!(id.display_name, name, "expected {kind:?} to win");
            assert_eq!(id.source, kind);
            signals.remove(0);
        }
        assert_eq!(resolve_with(&signals).source, SignalKind::Mac);
    }

    #[test]
    fn user_assigned_overrides_everything_including_mdns() {
        let id = resolve_with(&[
            Signal::new(SignalKind::MdnsName, "Living Room Apple TV"),
            Signal::new(SignalKind::UserAssigned, "Jamie's telly"),
        ]);
        assert_eq!(id.display_name, "Jamie's telly");
        assert_eq!(id.source, SignalKind::UserAssigned);
        assert_eq!(id.confidence, 1.0);
    }

    #[test]
    fn a_weaker_later_signal_does_not_overwrite_a_stronger_one() {
        // This is the refinement rule stated as a test: adding reverse DNS to a
        // device that already has mDNS changes nothing.
        let before = resolve_with(&[Signal::new(SignalKind::MdnsName, "Office Printer")]);
        let after = resolve_with(&[
            Signal::new(SignalKind::MdnsName, "Office Printer"),
            Signal::new(SignalKind::ReverseDns, "hp1234.lan"),
            Signal::new(SignalKind::Vendor, "Hewlett Packard"),
        ]);
        assert_eq!(before, after);
    }

    #[test]
    fn a_stronger_later_signal_refines_upward() {
        let before = resolve_with(&[Signal::new(SignalKind::Vendor, "Apple, Inc.")]);
        let after = resolve_with(&[
            Signal::new(SignalKind::Vendor, "Apple, Inc."),
            Signal::new(SignalKind::MdnsName, "Aurora's iPad"),
        ]);
        assert!(improves_on(&after, &before));
        assert_eq!(after.display_name, "Aurora's iPad");
    }

    #[test]
    fn duplicate_kinds_break_the_tie_by_slice_order() {
        let id = resolve_with(&[
            Signal::new(SignalKind::MdnsName, "newest"),
            Signal::new(SignalKind::MdnsName, "older"),
        ]);
        assert_eq!(id.display_name, "newest");
    }

    #[test]
    fn blank_values_are_skipped_not_trusted() {
        let id = resolve_with(&[
            Signal::new(SignalKind::MdnsName, "   "),
            Signal::new(SignalKind::MdnsName, ""),
            Signal::new(SignalKind::Vendor, "Apple, Inc."),
        ]);
        assert_eq!(id.display_name, "Apple, Inc. device");
        assert_eq!(id.source, SignalKind::Vendor);
    }

    #[test]
    fn values_are_trimmed() {
        let id = resolve_with(&[Signal::new(SignalKind::MdnsName, "  Kitchen Speaker  ")]);
        assert_eq!(id.display_name, "Kitchen Speaker");
    }

    #[test]
    fn improves_on_compares_confidence_then_text() {
        let strong = Identity {
            display_name: "a".into(),
            source: SignalKind::MdnsName,
            confidence: 0.9,
        };
        let weak = Identity {
            display_name: "b".into(),
            source: SignalKind::Vendor,
            confidence: 0.3,
        };
        assert!(improves_on(&strong, &weak));
        assert!(!improves_on(&weak, &strong));
        assert!(!improves_on(&strong, &strong));

        let renamed = Identity {
            display_name: "c".into(),
            ..strong.clone()
        };
        assert!(
            improves_on(&renamed, &strong),
            "a same-confidence rename is still a change worth an event"
        );
    }
}
