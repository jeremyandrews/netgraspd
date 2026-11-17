//! Detects one MAC sweeping the address space.
//!
//! A host mapping a network ARPs for address after address. A host going about
//! its business ARPs for its gateway, its DNS server and whatever it is actually
//! talking to, which is a handful of addresses that repeat.
//!
//! So the signal is **distinct target addresses inside a sliding window**, not
//! ARP packets. A device retrying one unanswered request two hundred times is
//! not scanning anything, and counting packets would call it a scanner every
//! time its printer was switched off.
//!
//! The gateway gets a much looser threshold rather than an exemption. A router
//! legitimately ARPs for everything it forwards to, so it will always cross the
//! ordinary threshold; but a compromised router sweeping the whole subnet is
//! exactly the thing worth knowing about, so silencing it entirely would be
//! wrong.
//!
//! **The gateway is not the only router.** The gateway tracker names one, and a
//! LAN routed across several segments has others: on the home LAN of issue #11
//! a second router ARPed from 10.20.0.2, 10.30.0.1 and 10.40.0.1 for hosts on
//! each, and as an ordinary host it was 19,857 `arp_scan` alerts in a week,
//! 93% of every security event. What marks a router out on the wire is that it
//! **asks from more than one address of its own**: it has a leg on each segment
//! it routes, and asks for that segment's hosts from its address there. A host
//! asks from the one address it has. So a MAC that has asked from two or more
//! addresses within ten minutes gets the gateway's threshold too, and the same
//! rule: looser, never exempt. A scanner that forges a second sender address
//! buys the router threshold and no more, and a sweep past it alerts.

use std::time::Duration;

use crate::clock::Timestamp;
use serde_json::json;

use crate::analyze::window::{BoundedMap, DistinctWindow};
use crate::analyze::{Analyzer, Context, SecurityAlert, Stimulus, cooled_down};
use crate::config::ArpScanConfig;
use crate::types::{ArpOp, EventType, MacAddr};

/// How many distinct targets one MAC's window holds before it stops growing.
///
/// Any value far above the threshold works; this only bounds memory, because by
/// the time a window holds this many the alert has long since fired.
const WINDOW_CAPACITY: usize = 512;

/// How long an address a MAC asked from counts toward it being a router.
///
/// Longer than the scan window, because a router asks from its quieter legs
/// less often than once every thirty seconds, and short enough that a host that
/// changed address once is not a router for the rest of the day.
const ROUTER_MEMORY: Duration = Duration::from_secs(10 * 60);

/// How many of its own addresses one MAC's sender window holds. Two is all the
/// rule needs; a few more keep the count honest for reporting.
const SENDER_CAPACITY: usize = 8;

/// Per-MAC scan state.
#[derive(Debug)]
struct Tracked {
    targets: DistinctWindow<std::net::Ipv4Addr>,
    /// The addresses this MAC has asked *from*, which is what tells a router
    /// from a host; see the module documentation.
    senders: DistinctWindow<std::net::Ipv4Addr>,
    last_alert: Option<Timestamp>,
}

/// The `arp_scan` analyzer.
pub struct ArpScan {
    window: Duration,
    threshold: usize,
    gateway_threshold: usize,
    tracked: BoundedMap<MacAddr, Tracked>,
}

impl ArpScan {
    /// Builds the analyzer.
    #[must_use]
    pub fn new(config: &ArpScanConfig, max_tracked: usize) -> Self {
        ArpScan {
            window: config.window.get(),
            threshold: config.threshold.max(1),
            gateway_threshold: config.gateway_threshold.max(config.threshold.max(1)),
            tracked: BoundedMap::new(max_tracked),
        }
    }
}

impl Analyzer for ArpScan {
    fn name(&self) -> &'static str {
        "arp_scan"
    }

    fn analyze(&mut self, stimulus: &Stimulus<'_>, context: &Context) -> Vec<SecurityAlert> {
        let Stimulus::Observed(observation) = stimulus else {
            return Vec::new();
        };
        let Some(arp) = observation.arp() else {
            return Vec::new();
        };
        // Only a request asks about somebody else. A reply and a gratuitous
        // announcement both name the sender's own address.
        if arp.op != ArpOp::Request || arp.gratuitous {
            return Vec::new();
        }
        if arp.target_ip.is_unspecified()
            || arp.target_ip.is_broadcast()
            || arp.target_ip.is_multicast()
        {
            return Vec::new();
        }

        let mac = observation.mac;
        let now = observation.observed_at;
        let window = self.window;

        let tracked = self.tracked.entry_or_insert_with(mac, now, || Tracked {
            targets: DistinctWindow::new(WINDOW_CAPACITY),
            senders: DistinctWindow::new(SENDER_CAPACITY),
            last_alert: None,
        });
        // An ARP probe asks from 0.0.0.0 and a link-local address is
        // self-assigned; neither is a leg on a routed segment.
        let own_addresses = match arp.sender_ip {
            Some(sender) if !sender.is_link_local() => {
                tracked.senders.record(sender, now, ROUTER_MEMORY)
            }
            _ => tracked.senders.len(),
        };
        let is_gateway = context.gateway.is_gateway(mac);
        let multi_homed = own_addresses >= 2;
        let threshold = if is_gateway || multi_homed {
            self.gateway_threshold
        } else {
            self.threshold
        };
        let distinct = tracked.targets.record(arp.target_ip, now, window);
        if distinct < threshold {
            return Vec::new();
        }
        // The cooldown is the window: a sweep that lasts ten minutes produces
        // one alert per window rather than one per packet after the threshold.
        if !cooled_down(tracked.last_alert, now, window) {
            return Vec::new();
        }
        tracked.last_alert = Some(now);
        // Start fresh so the next alert needs a new burst, rather than firing
        // again the instant the cooldown expires on the same evidence.
        tracked.targets.clear();

        vec![
            SecurityAlert::new(
                EventType::ArpScan,
                mac,
                now,
                context.priority,
                json!({
                    "analyzer": "arp_scan",
                    "distinct_targets": distinct,
                    "threshold": threshold,
                    "window_secs": window.as_secs(),
                    "latest_target": arp.target_ip.to_string(),
                    "is_gateway": is_gateway,
                    "multi_homed": multi_homed,
                }),
            )
            .with_interface(observation.interface.clone()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::GatewayTracker;
    use crate::capture::{arp, fixtures};
    use crate::config::HumanDuration;
    use crate::types::{EventPriority, Observation};

    fn at(secs: i64) -> Timestamp {
        Timestamp::from_unix(1_770_000_000 + secs, 0).expect("valid timestamp")
    }

    fn mac(s: &str) -> MacAddr {
        s.parse().expect("test mac")
    }

    fn context() -> Context {
        Context {
            gateway: GatewayTracker::new(None, None),
            exempt: Vec::new(),
            priority: EventPriority::Urgent,
            max_tracked: 1024,
        }
    }

    /// An ARP request from `from` asking about `target`.
    fn request(from: &str, target: [u8; 4], when: Timestamp) -> Observation {
        let mut frame = fixtures::arp_request();
        let source = mac(from).octets();
        frame[6..12].copy_from_slice(&source);
        frame[22..28].copy_from_slice(&source);
        frame[38..42].copy_from_slice(&target);
        arp::parse_frame(&frame, "eth0", when).expect("parsed")
    }

    fn config() -> ArpScanConfig {
        ArpScanConfig {
            enabled: true,
            window: HumanDuration::from_secs(30),
            threshold: 10,
            gateway_threshold: 100,
        }
    }

    #[test]
    fn a_burst_of_distinct_targets_fires() {
        let mut analyzer = ArpScan::new(&config(), 1024);
        let context = context();
        let mut alerts = Vec::new();
        for n in 1..=12u8 {
            alerts.extend(analyzer.analyze(
                &Stimulus::Observed(&request("3c:22:fb:00:00:01", [192, 168, 1, n], at(0))),
                &context,
            ));
        }
        assert_eq!(alerts.len(), 1, "one sweep is one alert");
        let alert = &alerts[0];
        assert_eq!(alert.event_type, EventType::ArpScan);
        assert_eq!(alert.mac, mac("3c:22:fb:00:00:01"));
        assert_eq!(alert.details["distinct_targets"], 10);
        assert_eq!(alert.details["threshold"], 10);
        assert_eq!(alert.details["is_gateway"], false);
        assert_eq!(alert.interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn ordinary_traffic_never_fires() {
        // A device talking to its gateway, its DNS server and a NAS, over and
        // over. Three distinct targets is not a scan however many packets it is.
        let mut analyzer = ArpScan::new(&config(), 1024);
        let context = context();
        for round in 0..100i64 {
            for target in [[192, 168, 1, 1], [192, 168, 1, 2], [192, 168, 1, 77]] {
                assert!(
                    analyzer
                        .analyze(
                            &Stimulus::Observed(&request("3c:22:fb:00:00:01", target, at(round))),
                            &context
                        )
                        .is_empty(),
                    "round {round}"
                );
            }
        }
    }

    #[test]
    fn one_target_retried_forever_is_not_a_scan() {
        let mut analyzer = ArpScan::new(&config(), 1024);
        let context = context();
        for n in 0..500 {
            assert!(
                analyzer
                    .analyze(
                        &Stimulus::Observed(&request(
                            "3c:22:fb:00:00:01",
                            [192, 168, 1, 99],
                            at(n)
                        )),
                        &context
                    )
                    .is_empty()
            );
        }
    }

    #[test]
    fn targets_that_fall_out_of_the_window_stop_counting() {
        let mut analyzer = ArpScan::new(&config(), 1024);
        let context = context();
        // Nine targets a minute apart: never more than one inside a 30s window.
        for n in 1..=9u8 {
            assert!(
                analyzer
                    .analyze(
                        &Stimulus::Observed(&request(
                            "3c:22:fb:00:00:01",
                            [192, 168, 1, n],
                            at(i64::from(n) * 60)
                        )),
                        &context
                    )
                    .is_empty(),
                "target {n}"
            );
        }
    }

    #[test]
    fn the_gateway_is_held_to_a_looser_threshold_not_exempted() {
        let mut analyzer = ArpScan::new(&config(), 1024);
        let context = Context {
            gateway: GatewayTracker::new(None, Some(mac("b8:27:eb:44:55:66"))),
            ..context()
        };
        // Twenty targets: over the ordinary threshold, under the gateway's.
        let mut alerts = Vec::new();
        for n in 1..=20u8 {
            alerts.extend(analyzer.analyze(
                &Stimulus::Observed(&request("b8:27:eb:44:55:66", [192, 168, 1, n], at(0))),
                &context,
            ));
        }
        assert!(alerts.is_empty(), "a router forwards, that is its job");

        // A hundred and one: even the gateway is sweeping now.
        for n in 21..=200u8 {
            alerts.extend(analyzer.analyze(
                &Stimulus::Observed(&request("b8:27:eb:44:55:66", [192, 168, 1, n], at(0))),
                &context,
            ));
        }
        assert_eq!(
            alerts.len(),
            1,
            "a compromised router is still worth an alert"
        );
        assert_eq!(alerts[0].details["is_gateway"], true);
        assert_eq!(alerts[0].details["threshold"], 100);
    }

    #[test]
    fn a_second_router_arping_from_several_of_its_own_addresses_gets_the_router_threshold() {
        // Issue #11. The gateway is known and is somebody else; this router
        // routes three segments on the same wire and ARPs for hosts on each
        // from its address there. Sixty distinct targets in one window is the
        // most the live database recorded for it in a week.
        use crate::capture::fixtures::lan;
        let mut analyzer = ArpScan::new(&config(), 1024);
        let context = Context {
            gateway: GatewayTracker::new(Some(lan::GATEWAY_IP), Some(MacAddr(lan::GATEWAY))),
            ..context()
        };
        let frame = |n: usize, second: i64| {
            let sender = lan::ROUTER_IPS[n % 3];
            let [a, b, c, _] = sender.octets();
            let target = std::net::Ipv4Addr::new(a, b, c, u8::try_from(10 + n).expect("small"));
            arp::parse_frame(
                &lan::arp_request(lan::ROUTER, sender, target),
                "eth0",
                at(second),
            )
            .expect("parsed")
        };
        let mut alerts = Vec::new();
        for n in 0..60 {
            alerts.extend(analyzer.analyze(&Stimulus::Observed(&frame(n, 0)), &context));
        }
        assert!(
            alerts.is_empty(),
            "a router forwarding for three segments is not sweeping one: {alerts:?}"
        );

        // Not an exemption: past the router threshold it is a sweep.
        for n in 60..240 {
            alerts.extend(analyzer.analyze(&Stimulus::Observed(&frame(n, 1)), &context));
        }
        assert_eq!(alerts.len(), 1, "a router sweeping is still worth an alert");
        assert_eq!(alerts[0].details["threshold"], 100);
        assert_eq!(alerts[0].details["is_gateway"], false);
    }

    #[test]
    fn a_host_on_one_address_still_gets_the_ordinary_threshold_beside_a_second_router() {
        use crate::capture::fixtures::lan;
        let mut analyzer = ArpScan::new(&config(), 1024);
        let context = Context {
            gateway: GatewayTracker::new(Some(lan::GATEWAY_IP), Some(MacAddr(lan::GATEWAY))),
            ..context()
        };
        let mut alerts = Vec::new();
        for n in 1..=12u8 {
            let obs = arp::parse_frame(
                &lan::arp_request(
                    lan::MACBOOK,
                    lan::MACBOOK_IP,
                    std::net::Ipv4Addr::new(10, 20, 228, n),
                ),
                "eth0",
                at(0),
            )
            .expect("parsed");
            alerts.extend(analyzer.analyze(&Stimulus::Observed(&obs), &context));
        }
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].details["threshold"], 10);
    }

    #[test]
    fn probes_and_link_local_senders_do_not_make_a_host_a_router() {
        use crate::capture::fixtures::lan;
        let mut analyzer = ArpScan::new(&config(), 1024);
        let context = context();
        let probe = std::net::Ipv4Addr::UNSPECIFIED;
        let link_local = std::net::Ipv4Addr::new(169, 254, 7, 7);
        let mut alerts = Vec::new();
        for n in 1..=12u8 {
            let sender = match n % 3 {
                0 => probe,
                1 => link_local,
                _ => lan::MACBOOK_IP,
            };
            let obs = arp::parse_frame(
                &lan::arp_request(
                    lan::MACBOOK,
                    sender,
                    std::net::Ipv4Addr::new(10, 20, 228, n),
                ),
                "eth0",
                at(0),
            )
            .expect("parsed");
            alerts.extend(analyzer.analyze(&Stimulus::Observed(&obs), &context));
        }
        assert_eq!(alerts.len(), 1, "{alerts:?}");
        assert_eq!(alerts[0].details["threshold"], 10);
        assert_eq!(alerts[0].details["multi_homed"], false);
    }

    #[test]
    fn a_sustained_sweep_alerts_once_per_window_not_once_per_packet() {
        let mut analyzer = ArpScan::new(&config(), 1024);
        let context = context();
        let mut alerts = Vec::new();
        // Five minutes of continuous scanning at two targets a second.
        for second in 0..300i64 {
            for half in 0..2u8 {
                #[allow(clippy::cast_possible_truncation)] // Deliberate wrap:
                // the point is a stream of distinct-looking targets.
                let target = [
                    10,
                    0,
                    (second >> 7) as u8,
                    (second * 2 + i64::from(half)) as u8,
                ];
                alerts.extend(analyzer.analyze(
                    &Stimulus::Observed(&request("3c:22:fb:00:00:01", target, at(second))),
                    &context,
                ));
            }
        }
        // 300 seconds at a 30-second window and cooldown: ten alerts, not six
        // hundred.
        assert!(
            (5..=11).contains(&alerts.len()),
            "expected roughly one alert per window, got {}",
            alerts.len()
        );
    }

    #[test]
    fn replies_and_announcements_are_not_questions() {
        let mut analyzer = ArpScan::new(&config(), 1024);
        let context = context();
        for _ in 0..100 {
            let reply = arp::parse_frame(&fixtures::arp_reply(), "eth0", at(0)).expect("parsed");
            assert!(
                analyzer
                    .analyze(&Stimulus::Observed(&reply), &context)
                    .is_empty()
            );
            let gratuitous =
                arp::parse_frame(&fixtures::arp_gratuitous(), "eth0", at(0)).expect("parsed");
            assert!(
                analyzer
                    .analyze(&Stimulus::Observed(&gratuitous), &context)
                    .is_empty()
            );
        }
    }

    #[test]
    fn a_reclassification_is_not_this_analyzers_business() {
        let mut analyzer = ArpScan::new(&config(), 1024);
        let change = crate::device::Reclassification {
            mac: mac("3c:22:fb:00:00:01"),
            display_name: "x".into(),
            previous: crate::identity::Classification::default(),
            current: crate::identity::Classification::default(),
            interface: None,
            at: at(0),
        };
        assert!(
            analyzer
                .analyze(&Stimulus::Reclassified(&change), &context())
                .is_empty()
        );
    }

    #[test]
    fn a_forged_source_mac_per_packet_cannot_grow_the_tracker() {
        let mut analyzer = ArpScan::new(&config(), 64);
        let context = context();
        for n in 0..5000u32 {
            let source = format!(
                "02:00:{:02x}:{:02x}:{:02x}:{:02x}",
                n >> 24,
                (n >> 16) & 0xff,
                (n >> 8) & 0xff,
                n & 0xff
            );
            let _ = analyzer.analyze(
                &Stimulus::Observed(&request(&source, [192, 168, 1, 1], at(0))),
                &context,
            );
        }
        assert!(analyzer.tracked.len() <= 64);
        assert!(analyzer.tracked.evictions() > 4000);
    }
}
