//! What the daemon can and cannot see, per interface: the visibility report.
//!
//! On a network somebody else runs, the first question is not "which devices
//! are here" but "can I see anything at all". A guest network with client
//! isolation delivers the gateway's broadcasts and nothing else, and before
//! this report that looked exactly like broken capture: an empty device table
//! either way. The numbers here tell the two apart: frames seen, distinct
//! senders, and how long the interface has been listening, per interface and
//! per source, plus the gateway the daemon believes in and why. [`verdict`]
//! turns them into one plain line per interface.
//!
//! The counts are kept by the capture threads themselves, in a [`Tally`] they
//! share with the daemon, and count **frames the BPF filter delivered**, before
//! any parser has looked at them. That is the honest measure of what reached
//! this machine: a frame a parser rejects was still seen.
//!
//! # Bounded memory
//!
//! Distinct senders are counted by remembering each source MAC, in a set per
//! interface and one per interface and source. Each set stops growing at
//! [`MAX_TRACKED_SENDERS`] (4096 addresses, about 100 KiB with hashing
//! overhead); past that the count is reported as "at least" that many and
//! frames are still counted. A network with more distinct senders than that on
//! one interface is not one where isolation is in question.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::types::MacAddr;

/// How many distinct source MACs each set remembers before it stops growing.
pub const MAX_TRACKED_SENDERS: usize = 4096;

/// How long an interface must have been listening, with nothing received,
/// before the verdict calls capture into question.
///
/// Two minutes. Any network with a router on it carries ARP and usually mDNS
/// well inside that; an interface that has heard nothing at all for that long
/// is not being delivered frames.
pub const SILENCE_BEFORE_FAULT: TimeDelta = TimeDelta::minutes(2);

/// One source's view of one interface.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceVisibility {
    /// Frames the source's filter delivered on this interface.
    pub frames: u64,
    /// Distinct source MACs among them.
    pub senders: u64,
    /// True when `senders` stopped at [`MAX_TRACKED_SENDERS`], so the real
    /// number is at least that.
    #[serde(default)]
    pub senders_capped: bool,
}

/// What one interface has seen, across every source capturing on it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceVisibility {
    /// When the first capture thread on this interface started listening.
    /// `None` when none ever did.
    #[serde(default)]
    pub listening_since: Option<DateTime<Utc>>,
    /// Frames delivered, every source together.
    #[serde(default)]
    pub frames: u64,
    /// Distinct source MACs, every source together, this host included.
    #[serde(default)]
    pub senders: u64,
    /// True when `senders` stopped at [`MAX_TRACKED_SENDERS`].
    #[serde(default)]
    pub senders_capped: bool,
    /// True when one of the senders is this host itself. libpcap delivers a
    /// host's own outgoing broadcasts, so this is usually true and is not
    /// evidence that anything else is reachable.
    #[serde(default)]
    pub this_host_seen: bool,
    /// True when one of the senders is the gateway the daemon believes in.
    #[serde(default)]
    pub gateway_seen: bool,
    /// When the most recent frame arrived.
    #[serde(default)]
    pub last_frame_at: Option<DateTime<Utc>>,
    /// The same counts, per capture source.
    #[serde(default)]
    pub sources: BTreeMap<String, SourceVisibility>,
}

impl InterfaceVisibility {
    /// Senders other than this host.
    #[must_use]
    pub fn other_senders(&self) -> u64 {
        self.senders.saturating_sub(u64::from(self.this_host_seen))
    }
}

/// The gateway the daemon believes in, and where the belief came from.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayBelief {
    /// Its IPv4 address, when known.
    pub ip: Option<String>,
    /// Its hardware address, when known.
    pub mac: Option<String>,
    /// Where the address belief came from: `route`, `dhcp`, `configured`,
    /// `inferred` or `unknown`.
    pub ip_source: String,
    /// Where the hardware address belief came from, in the same terms.
    pub mac_source: String,
}

impl GatewayBelief {
    /// One line for `netgraspd stats` and the export.
    #[must_use]
    pub fn line(&self) -> String {
        match (&self.ip, &self.mac) {
            (None, None) => "gateway not known yet".to_string(),
            (Some(ip), None) => format!(
                "gateway {ip} (from {}), hardware address not seen yet",
                self.ip_source
            ),
            (None, Some(mac)) => format!(
                "gateway at {mac} (from {}), address not known yet",
                self.mac_source
            ),
            (Some(ip), Some(mac)) => format!(
                "gateway {ip} (from {}) at {mac} (from {})",
                self.ip_source, self.mac_source
            ),
        }
    }
}

/// What the numbers say about one interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictKind {
    /// Every capture thread on the interface failed, or none ever started.
    CaptureFailed,
    /// Nothing yet, but it has not been listening long enough to say.
    TooEarly,
    /// Listening for a while and nothing at all received.
    PossibleFault,
    /// Frames arrive, but only this host's own.
    OnlyThisHost,
    /// One other sender: what client isolation looks like.
    Isolated,
    /// Several senders: an ordinary shared segment.
    Working,
}

/// A verdict and the line that states it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    /// Which case this is.
    pub kind: VerdictKind,
    /// The plain sentence for a human.
    pub line: String,
}

/// Says what one interface's numbers mean.
///
/// Pure: the same counts always give the same line, which is what lets the
/// report be tested without a network. `failures` is how many capture threads
/// on this interface ended in failure; `as_of` is when the counts were taken.
///
/// The cases, in the order they are decided:
///
/// - never listened → capture failed;
/// - nothing received → too early under [`SILENCE_BEFORE_FAULT`], otherwise a
///   possible capture fault;
/// - only this host's own frames → capture works and nothing else reaches it;
/// - exactly one other sender → consistent with client isolation, the gateway
///   named when it is the gateway;
/// - more → capture is working, with the count.
#[must_use]
pub fn verdict(
    interface: &str,
    v: &InterfaceVisibility,
    failures: usize,
    as_of: DateTime<Utc>,
) -> Verdict {
    let listened = v
        .listening_since
        .map(|since| (as_of - since).max(TimeDelta::zero()));
    let Some(listened) = listened else {
        let why = if failures == 0 {
            "no capture thread started".to_string()
        } else {
            format!(
                "{failures} capture thread{} failed",
                if failures == 1 { "" } else { "s" }
            )
        };
        return Verdict {
            kind: VerdictKind::CaptureFailed,
            line: format!("capture failed on {interface}: {why}, so nothing here was seen"),
        };
    };
    let duration = super::human_duration(listened);

    if v.frames == 0 {
        return if listened < SILENCE_BEFORE_FAULT {
            Verdict {
                kind: VerdictKind::TooEarly,
                line: format!(
                    "nothing received on {interface} yet, after {duration}: too early to say"
                ),
            }
        } else {
            Verdict {
                kind: VerdictKind::PossibleFault,
                line: format!(
                    "nothing received on {interface} in {duration}: capture may be broken"
                ),
            }
        };
    }

    let others = v.other_senders();
    let at_least = if v.senders_capped { "at least " } else { "" };
    match others {
        0 => Verdict {
            kind: VerdictKind::OnlyThisHost,
            line: "capture is working, but only this host's own frames arrive: no other sender \
                   seen, consistent with client isolation that hides even the gateway"
                .to_string(),
        },
        1 => Verdict {
            kind: VerdictKind::Isolated,
            line: format!(
                "capture is working: 1 sender seen{}, consistent with client isolation",
                if v.gateway_seen { " (the gateway)" } else { "" }
            ),
        },
        n => Verdict {
            kind: VerdictKind::Working,
            line: format!("capture is working: {at_least}{n} senders seen besides this host"),
        },
    }
}

/// One bounded set of senders.
#[derive(Debug, Default)]
struct Senders {
    seen: HashSet<MacAddr>,
    capped: bool,
}

impl Senders {
    /// Remembers a sender, unless the set is full.
    fn insert(&mut self, mac: MacAddr) {
        if self.seen.contains(&mac) {
            return;
        }
        if self.seen.len() >= MAX_TRACKED_SENDERS {
            self.capped = true;
        } else {
            self.seen.insert(mac);
        }
    }

    fn count(&self) -> u64 {
        self.seen.len() as u64
    }
}

/// Live counts for one interface.
#[derive(Debug, Default)]
struct InterfaceTally {
    listening_since: Option<DateTime<Utc>>,
    frames: u64,
    senders: Senders,
    last_frame_at: Option<DateTime<Utc>>,
    sources: BTreeMap<&'static str, (u64, Senders)>,
}

/// The live counts, shared between the capture threads and the daemon.
///
/// One short lock per frame. Broadcast and multicast traffic is a few hundred
/// frames a second on a busy network, which a mutex handles without notice.
#[derive(Debug, Default)]
pub struct Tally {
    interfaces: Mutex<HashMap<String, InterfaceTally>>,
}

impl Tally {
    /// Records that a capture thread on `interface` has started listening.
    pub fn listening(&self, interface: &str, at: DateTime<Utc>) {
        let mut interfaces = self.lock();
        let entry = interfaces.entry(interface.to_string()).or_default();
        // The earliest start: a second source starting later does not reset it.
        entry.listening_since = Some(entry.listening_since.map_or(at, |since| since.min(at)));
    }

    /// Records one frame the filter delivered.
    pub fn frame(
        &self,
        interface: &str,
        source: &'static str,
        sender: Option<MacAddr>,
        at: DateTime<Utc>,
    ) {
        let mut interfaces = self.lock();
        let entry = interfaces.entry(interface.to_string()).or_default();
        entry.frames += 1;
        entry.last_frame_at = Some(entry.last_frame_at.map_or(at, |last| last.max(at)));
        let (frames, senders) = entry.sources.entry(source).or_default();
        *frames += 1;
        if let Some(sender) = sender {
            senders.insert(sender);
            entry.senders.insert(sender);
        }
    }

    /// Locks the counts. A capture thread that panicked holding the lock left
    /// nothing half-written that matters, so a poisoned lock is used as is.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, InterfaceTally>> {
        self.interfaces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The counts as they stand, for the status file.
    ///
    /// `this_host` is every MAC the capture host owns, and `gateway` the
    /// gateway's MAC when it is known; they set `this_host_seen` and
    /// `gateway_seen`.
    #[must_use]
    pub fn snapshot(
        &self,
        this_host: &[MacAddr],
        gateway: Option<MacAddr>,
    ) -> BTreeMap<String, InterfaceVisibility> {
        self.lock()
            .iter()
            .map(|(name, t)| {
                let sources = t
                    .sources
                    .iter()
                    .map(|(source, (frames, senders))| {
                        (
                            (*source).to_string(),
                            SourceVisibility {
                                frames: *frames,
                                senders: senders.count(),
                                senders_capped: senders.capped,
                            },
                        )
                    })
                    .collect();
                let visibility = InterfaceVisibility {
                    listening_since: t.listening_since,
                    frames: t.frames,
                    senders: t.senders.count(),
                    senders_capped: t.senders.capped,
                    this_host_seen: this_host.iter().any(|m| t.senders.seen.contains(m)),
                    gateway_seen: gateway.is_some_and(|m| t.senders.seen.contains(&m)),
                    last_frame_at: t.last_frame_at,
                    sources,
                };
                (name.clone(), visibility)
            })
            .collect()
    }
}

/// The source MAC of an Ethernet frame, when it has one worth counting.
#[must_use]
///
/// Bytes six to twelve. Group addresses and the all-zero address identify no
/// device, so they are not senders.
pub fn ethernet_source(frame: &[u8]) -> Option<MacAddr> {
    let bytes: [u8; 6] = frame.get(6..12)?.try_into().ok()?;
    let mac = MacAddr(bytes);
    (!mac.is_group() && !mac.is_zero()).then_some(mac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(minutes: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 14, 9, 0, 0)
            .single()
            .expect("valid time")
            + TimeDelta::minutes(minutes)
    }

    fn mac(last: u8) -> MacAddr {
        MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, last])
    }

    /// Ten minutes of listening, with the given counts.
    fn listened(frames: u64, senders: u64, this_host: bool, gateway: bool) -> InterfaceVisibility {
        InterfaceVisibility {
            listening_since: Some(at(0)),
            frames,
            senders,
            senders_capped: false,
            this_host_seen: this_host,
            gateway_seen: gateway,
            last_frame_at: (frames > 0).then(|| at(9)),
            sources: BTreeMap::new(),
        }
    }

    #[test]
    fn only_the_gateway_reads_as_client_isolation_not_as_an_error() {
        let v = listened(42, 1, false, true);
        let verdict = verdict("en0", &v, 0, at(10));
        assert_eq!(verdict.kind, VerdictKind::Isolated, "{verdict:?}");
        assert!(
            verdict.line.contains("capture is working"),
            "{}",
            verdict.line
        );
        assert!(verdict.line.contains("1 sender seen"), "{}", verdict.line);
        assert!(
            verdict.line.contains("consistent with client isolation"),
            "{}",
            verdict.line
        );
        assert!(verdict.line.contains("the gateway"), "{}", verdict.line);
        assert!(!verdict.line.contains("broken"), "{}", verdict.line);
    }

    #[test]
    fn the_gateway_and_this_host_alone_is_still_isolation() {
        // libpcap hands a host its own broadcasts back, so on a Mac the
        // isolated case is two senders, one of them itself.
        let v = listened(80, 2, true, true);
        let verdict = verdict("en0", &v, 0, at(10));
        assert_eq!(verdict.kind, VerdictKind::Isolated, "{verdict:?}");
        assert!(verdict.line.contains("1 sender seen"), "{}", verdict.line);
    }

    #[test]
    fn nothing_received_for_ten_minutes_reads_as_a_possible_capture_fault() {
        let v = listened(0, 0, false, false);
        let verdict = verdict("en0", &v, 0, at(10));
        assert_eq!(verdict.kind, VerdictKind::PossibleFault, "{verdict:?}");
        assert_eq!(
            verdict.line,
            "nothing received on en0 in 10m 0s: capture may be broken"
        );
    }

    #[test]
    fn nothing_received_yet_is_too_early_to_call() {
        let v = listened(0, 0, false, false);
        let verdict = verdict("en0", &v, 0, at(0) + TimeDelta::seconds(30));
        assert_eq!(verdict.kind, VerdictKind::TooEarly, "{verdict:?}");
        assert!(verdict.line.contains("too early"), "{}", verdict.line);
    }

    #[test]
    fn only_this_hosts_own_frames_is_not_a_capture_fault() {
        let v = listened(12, 1, true, false);
        let verdict = verdict("en0", &v, 0, at(10));
        assert_eq!(verdict.kind, VerdictKind::OnlyThisHost, "{verdict:?}");
        assert!(verdict.line.contains("no other sender"), "{}", verdict.line);
    }

    #[test]
    fn many_senders_is_an_ordinary_working_segment() {
        let v = listened(5000, 37, true, true);
        let verdict = verdict("en0", &v, 0, at(10));
        assert_eq!(verdict.kind, VerdictKind::Working, "{verdict:?}");
        assert_eq!(
            verdict.line,
            "capture is working: 36 senders seen besides this host"
        );
    }

    #[test]
    fn an_interface_that_never_listened_reports_the_failure() {
        let v = InterfaceVisibility::default();
        let verdict = verdict("utun3", &v, 2, at(10));
        assert_eq!(verdict.kind, VerdictKind::CaptureFailed, "{verdict:?}");
        assert!(verdict.line.contains("utun3"), "{}", verdict.line);
    }

    #[test]
    fn the_tally_counts_frames_and_distinct_senders_per_interface_and_source() {
        let tally = Tally::default();
        tally.listening("en0", at(0));
        tally.frame("en0", "arp", Some(mac(1)), at(1));
        tally.frame("en0", "arp", Some(mac(1)), at(2));
        tally.frame("en0", "arp", Some(mac(2)), at(3));
        tally.frame("en0", "mdns", Some(mac(2)), at(4));
        tally.frame("en0", "mdns", None, at(5));

        let snap = tally.snapshot(&[mac(2)], Some(mac(1)));
        let en0 = snap.get("en0").expect("en0 reported");
        assert_eq!(en0.listening_since, Some(at(0)));
        assert_eq!(en0.frames, 5);
        assert_eq!(en0.senders, 2);
        assert!(en0.this_host_seen);
        assert!(en0.gateway_seen);
        assert_eq!(en0.other_senders(), 1);
        assert_eq!(en0.last_frame_at, Some(at(5)));
        assert_eq!(
            en0.sources.get("arp"),
            Some(&SourceVisibility {
                frames: 3,
                senders: 2,
                senders_capped: false
            })
        );
        assert_eq!(en0.sources["mdns"].frames, 2);
        assert_eq!(en0.sources["mdns"].senders, 1);
    }

    #[test]
    fn the_distinct_sender_count_is_bounded() {
        let tally = Tally::default();
        tally.listening("en0", at(0));
        for i in 0..(MAX_TRACKED_SENDERS as u32 + 50) {
            let b = i.to_be_bytes();
            tally.frame(
                "en0",
                "arp",
                Some(MacAddr([0x02, 0, b[0], b[1], b[2], b[3]])),
                at(1),
            );
        }
        let snap = tally.snapshot(&[], None);
        let en0 = &snap["en0"];
        assert_eq!(en0.senders, MAX_TRACKED_SENDERS as u64);
        assert!(en0.senders_capped);
        assert!(en0.sources["arp"].senders_capped);
        assert_eq!(
            en0.frames,
            MAX_TRACKED_SENDERS as u64 + 50,
            "frames keep counting"
        );
    }

    #[test]
    fn an_ethernet_source_is_read_from_bytes_six_to_twelve() {
        let frame = crate::capture::fixtures::arp_request();
        let src = ethernet_source(&frame).expect("a source MAC");
        assert_eq!(
            src.0,
            <[u8; 6]>::try_from(&frame[6..12]).expect("six bytes")
        );
        assert_eq!(ethernet_source(&frame[..10]), None, "a runt has none");
    }
}
