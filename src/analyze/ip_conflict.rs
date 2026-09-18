//! Detects two active devices using one address.
//!
//! ## Why this is not `arp_spoof`
//!
//! They overlap and that is deliberate. A poisoning attack trips both, and an
//! operator who wants to page on one and log the other needs them to be separate
//! events with separate priorities.
//!
//! What they actually measure differs. `arp_spoof` watches the **transition**:
//! an address changing hands while its holder is still talking. This watches
//! **co-presence**: two MACs both using an address inside a short window,
//! however they got there. The common cause is not an attack at all, it is
//! somebody typing a static address that the DHCP pool also hands out, and the
//! symptom is an address that oscillates between two owners rather than moving
//! once.
//!
//! Any observation carrying an address counts, not just ARP. A device using an
//! address in mDNS or DHCP is using it just as much as one that ARPs for it.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::json;

use crate::analyze::window::BoundedMap;
use crate::analyze::{Analyzer, Context, SecurityAlert, Stimulus, cooled_down};
use crate::config::IpConflictConfig;
use crate::types::{EventType, MacAddr};

/// How long after alerting about one address before alerting about it again.
///
/// A genuine static-address collision persists until somebody fixes it, and it
/// should not produce an alert per packet in the meantime.
const COOLDOWN: Duration = Duration::from_secs(600);

/// Who has recently used an address.
#[derive(Debug)]
struct Users {
    /// The most recent user, and when.
    latest: (MacAddr, DateTime<Utc>),
    /// The previous distinct user, and when.
    previous: Option<(MacAddr, DateTime<Utc>)>,
    last_alert: Option<DateTime<Utc>>,
}

/// The `ip_conflict` analyzer.
pub struct IpConflict {
    active_within: Duration,
    addresses: BoundedMap<Ipv4Addr, Users>,
}

impl IpConflict {
    /// Builds the analyzer.
    #[must_use]
    pub fn new(config: &IpConflictConfig, max_tracked: usize) -> Self {
        IpConflict {
            active_within: config.active_within.get(),
            addresses: BoundedMap::new(max_tracked),
        }
    }
}

impl Analyzer for IpConflict {
    fn name(&self) -> &'static str {
        "ip_conflict"
    }

    fn analyze(&mut self, stimulus: &Stimulus<'_>, context: &Context) -> Vec<SecurityAlert> {
        let Stimulus::Observed(observation) = stimulus else {
            return Vec::new();
        };
        // IPv4 only. Two devices sharing an IPv6 address is prevented by
        // Duplicate Address Detection at the protocol level, so the equivalent
        // failure does not exist there.
        let Some(IpAddr::V4(address)) = observation.ip else {
            return Vec::new();
        };
        if address.is_unspecified() || address.is_broadcast() || address.is_multicast() {
            return Vec::new();
        }
        // The gateway answering for somebody else's address is proxy ARP, not a
        // second device using the address. Returning before the address map is
        // touched is the point: if the gateway were recorded as a user of the
        // address, the real owner's next packet would be read as displacing it
        // and would alert on the way past.
        if context.gateway.proxy_arp_for(observation).is_some() {
            return Vec::new();
        }

        let mac = observation.mac;
        let now = observation.observed_at;
        let active_within = self.active_within;

        let users = self.addresses.entry_or_insert_with(address, now, || Users {
            latest: (mac, now),
            previous: None,
            last_alert: None,
        });

        if users.latest.0 == mac {
            users.latest.1 = now;
            return Vec::new();
        }

        // A different MAC. The one it displaces becomes the previous user.
        let displaced = users.latest;
        users.previous = Some(displaced);
        users.latest = (mac, now);

        let gap = now.signed_duration_since(displaced.1);
        let simultaneous = gap.to_std().is_ok_and(|elapsed| elapsed <= active_within);
        if !simultaneous {
            return Vec::new();
        }
        if !cooled_down(users.last_alert, now, COOLDOWN) {
            return Vec::new();
        }
        users.last_alert = Some(now);

        vec![
            SecurityAlert::new(
                EventType::IpConflict,
                mac,
                now,
                context.priority,
                json!({
                    "analyzer": "ip_conflict",
                    "address": address.to_string(),
                    "other_mac": displaced.0.to_string(),
                    "seconds_apart": gap.num_seconds().max(0),
                    "active_within_secs": active_within.as_secs(),
                    "source": observation.source,
                }),
            )
            .with_ip(address.to_string())
            .with_interface(observation.interface.clone()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::GatewayTracker;
    use crate::config::HumanDuration;
    use crate::types::{EventPriority, Observation, ObservationKind};
    use chrono::TimeZone;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_770_000_000 + secs, 0)
            .single()
            .expect("valid timestamp")
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

    fn using(who: &str, address: &str, when: DateTime<Utc>) -> Observation {
        Observation::new(
            mac(who),
            Some(address.parse().expect("test address")),
            "eth0",
            "arp",
            ObservationKind::Reply,
            when,
        )
    }

    fn config() -> IpConflictConfig {
        IpConflictConfig {
            enabled: true,
            active_within: HumanDuration::from_secs(60),
        }
    }

    #[test]
    fn two_macs_using_one_address_at_once_fires() {
        let mut analyzer = IpConflict::new(&config(), 1024);
        let context = context();
        assert!(
            analyzer
                .analyze(
                    &Stimulus::Observed(&using("3c:22:fb:00:00:01", "192.168.1.40", at(0))),
                    &context
                )
                .is_empty()
        );
        let alerts = analyzer.analyze(
            &Stimulus::Observed(&using("00:11:32:aa:bb:cc", "192.168.1.40", at(5))),
            &context,
        );
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].event_type, EventType::IpConflict);
        assert_eq!(alerts[0].mac, mac("00:11:32:aa:bb:cc"));
        assert_eq!(alerts[0].details["other_mac"], "3c:22:fb:00:00:01");
        assert_eq!(alerts[0].details["seconds_apart"], 5);
    }

    /// A context whose gateway is the Routerboard from the 2026-09-17 run.
    fn proxying_context() -> Context {
        Context {
            gateway: GatewayTracker::new(
                Some("192.168.1.1".parse().expect("gateway ip")),
                Some(mac("18:fd:74:39:e5:23")),
            ),
            ..context()
        }
    }

    /// An ARP reply from `from` claiming `claimed`.
    fn claim(from: &str, claimed: &str, when: DateTime<Utc>) -> Observation {
        let mut frame = crate::capture::fixtures::arp_reply();
        let source = mac(from).octets();
        let address: std::net::Ipv4Addr = claimed.parse().expect("test address");
        frame[6..12].copy_from_slice(&source);
        frame[22..28].copy_from_slice(&source);
        frame[28..32].copy_from_slice(&address.octets());
        crate::capture::arp::parse_frame(&frame, "eth0", when).expect("parsed")
    }

    #[test]
    fn the_gateway_proxy_arping_across_vlans_is_not_a_conflict() {
        // The 2026-09-17 pattern. Hosts on two other segments talk; the router
        // answers ARP for both with its own MAC; the hosts talk again. Before
        // the fix every one of those handovers was an address conflict.
        let mut analyzer = IpConflict::new(&config(), 1024);
        let context = proxying_context();
        let mut alerts = Vec::new();
        for second in 0..600i64 {
            for host in ["192.168.20.55", "192.168.30.12"] {
                alerts.extend(analyzer.analyze(
                    &Stimulus::Observed(&using("00:11:32:aa:bb:cc", host, at(second))),
                    &context,
                ));
                alerts.extend(analyzer.analyze(
                    &Stimulus::Observed(&claim("18:fd:74:39:e5:23", host, at(second))),
                    &context,
                ));
            }
        }
        assert!(alerts.is_empty(), "proxy ARP is not a conflict: {alerts:?}");
    }

    #[test]
    fn a_real_conflict_on_an_address_the_gateway_did_not_proxy_still_fires() {
        // The attack the analyzer exists for must survive the exemption.
        let mut analyzer = IpConflict::new(&config(), 1024);
        let context = proxying_context();
        let _ = analyzer.analyze(
            &Stimulus::Observed(&using("3c:22:fb:00:00:01", "192.168.1.40", at(0))),
            &context,
        );
        let alerts = analyzer.analyze(
            &Stimulus::Observed(&using("00:11:32:aa:bb:cc", "192.168.1.40", at(5))),
            &context,
        );
        assert_eq!(alerts.len(), 1, "two ordinary devices, one address");
    }

    #[test]
    fn a_proxied_address_still_conflicts_when_a_third_device_takes_it() {
        // Proxy ARP must not make an address permanently safe. The gateway's own
        // answers are ignored, so the real owner stays the recorded holder and a
        // stranger claiming it is still a conflict.
        let mut analyzer = IpConflict::new(&config(), 1024);
        let context = proxying_context();
        let _ = analyzer.analyze(
            &Stimulus::Observed(&using("00:11:32:aa:bb:cc", "192.168.20.55", at(0))),
            &context,
        );
        let _ = analyzer.analyze(
            &Stimulus::Observed(&claim("18:fd:74:39:e5:23", "192.168.20.55", at(1))),
            &context,
        );
        let alerts = analyzer.analyze(
            &Stimulus::Observed(&using("02:de:ad:be:ef:01", "192.168.20.55", at(2))),
            &context,
        );
        assert_eq!(
            alerts.len(),
            1,
            "a stranger on a proxied address still alerts"
        );
        assert_eq!(
            alerts[0].details["other_mac"], "00:11:32:aa:bb:cc",
            "and it is compared against the real owner, not the router"
        );
    }

    #[test]
    fn turning_the_rule_off_restores_the_alert() {
        let mut analyzer = IpConflict::new(&config(), 1024);
        let context = Context {
            gateway: GatewayTracker::new(
                Some("192.168.1.1".parse().expect("gateway ip")),
                Some(mac("18:fd:74:39:e5:23")),
            )
            .with_proxy_arp(false),
            ..context()
        };
        let _ = analyzer.analyze(
            &Stimulus::Observed(&using("00:11:32:aa:bb:cc", "192.168.20.55", at(0))),
            &context,
        );
        let alerts = analyzer.analyze(
            &Stimulus::Observed(&claim("18:fd:74:39:e5:23", "192.168.20.55", at(1))),
            &context,
        );
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn a_handover_after_the_window_is_a_reassignment_not_a_conflict() {
        let mut analyzer = IpConflict::new(&config(), 1024);
        let context = context();
        let _ = analyzer.analyze(
            &Stimulus::Observed(&using("3c:22:fb:00:00:01", "192.168.1.40", at(0))),
            &context,
        );
        assert!(
            analyzer
                .analyze(
                    &Stimulus::Observed(&using("00:11:32:aa:bb:cc", "192.168.1.40", at(3600))),
                    &context
                )
                .is_empty()
        );
    }

    #[test]
    fn one_device_using_its_own_address_forever_never_fires() {
        let mut analyzer = IpConflict::new(&config(), 1024);
        let context = context();
        for n in 0..1000 {
            assert!(
                analyzer
                    .analyze(
                        &Stimulus::Observed(&using("3c:22:fb:00:00:01", "192.168.1.40", at(n))),
                        &context
                    )
                    .is_empty()
            );
        }
    }

    #[test]
    fn a_persistent_collision_alerts_at_a_bounded_rate() {
        // The real-world shape: a static address inside the DHCP pool, both
        // machines talking all day.
        let mut analyzer = IpConflict::new(&config(), 1024);
        let context = context();
        let mut alerts = Vec::new();
        for second in 0..3600i64 {
            alerts.extend(analyzer.analyze(
                &Stimulus::Observed(&using("3c:22:fb:00:00:01", "192.168.1.40", at(second))),
                &context,
            ));
            alerts.extend(analyzer.analyze(
                &Stimulus::Observed(&using("00:11:32:aa:bb:cc", "192.168.1.40", at(second))),
                &context,
            ));
        }
        assert!(
            (5..=15).contains(&alerts.len()),
            "one hour at a 600s cooldown, got {}",
            alerts.len()
        );
    }

    #[test]
    fn any_protocol_that_reveals_an_address_counts() {
        let mut analyzer = IpConflict::new(&config(), 1024);
        let context = context();
        let mut first = using("3c:22:fb:00:00:01", "192.168.1.40", at(0));
        first.source = "mdns";
        let mut second = using("00:11:32:aa:bb:cc", "192.168.1.40", at(1));
        second.source = "dhcp";
        let _ = analyzer.analyze(&Stimulus::Observed(&first), &context);
        let alerts = analyzer.analyze(&Stimulus::Observed(&second), &context);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].details["source"], "dhcp");
    }

    #[test]
    fn ipv6_is_left_to_duplicate_address_detection() {
        let mut analyzer = IpConflict::new(&config(), 1024);
        let context = context();
        let _ = analyzer.analyze(
            &Stimulus::Observed(&using("3c:22:fb:00:00:01", "2001:db8::1", at(0))),
            &context,
        );
        assert!(
            analyzer
                .analyze(
                    &Stimulus::Observed(&using("00:11:32:aa:bb:cc", "2001:db8::1", at(1))),
                    &context
                )
                .is_empty()
        );
    }

    #[test]
    fn an_observation_with_no_address_is_not_a_conflict() {
        let mut analyzer = IpConflict::new(&config(), 1024);
        let context = context();
        let observation = Observation::new(
            mac("3c:22:fb:00:00:01"),
            None,
            "eth0",
            "arp",
            ObservationKind::Request,
            at(0),
        );
        assert!(
            analyzer
                .analyze(&Stimulus::Observed(&observation), &context)
                .is_empty()
        );
    }

    #[test]
    fn the_address_tracker_is_bounded() {
        let mut analyzer = IpConflict::new(&config(), 64);
        let context = context();
        for n in 0..5000u32 {
            let address = format!("10.{}.{}.{}", (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
            let _ = analyzer.analyze(
                &Stimulus::Observed(&using("3c:22:fb:00:00:01", &address, at(0))),
                &context,
            );
        }
        assert!(analyzer.addresses.len() <= 64);
    }
}
