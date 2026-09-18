//! Detects a MAC claiming an address that a different, still-active MAC holds.
//!
//! ## The grace period is the entire design
//!
//! Addresses change hands legitimately all day. A laptop leaves, its lease
//! expires, the router hands the address to a tablet, and the tablet ARPs for
//! it. An analyzer that alerted on every address changing MAC would fire several
//! times a day on a healthy network, which is the same as never firing at all.
//!
//! So the question is not "did this address change hands" but "did it change
//! hands **while its current holder was still talking**". A claim on an address
//! whose holder was last heard from within the grace period is a spoof; a claim
//! on an address that has been quiet for longer is a reassignment.
//!
//! ## Except for the gateway
//!
//! Impersonating the gateway is what an ARP poisoning attack is *for*: it puts
//! the attacker between every device and the internet. A non-gateway MAC
//! claiming the gateway's address fires immediately, with no grace period, and
//! **without needing to have seen the real gateway claim it first**. The gateway
//! is known from DHCP option 3 or from configuration, and on a settled network
//! the real gateway may never ARP at all because everybody already has it
//! cached. Requiring a prior claim would mean the one attack this analyzer most
//! needs to catch is the one it would miss.

use std::net::Ipv4Addr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::json;

use crate::analyze::window::BoundedMap;
use crate::analyze::{Analyzer, Context, SecurityAlert, Stimulus, cooled_down};
use crate::config::ArpSpoofConfig;
use crate::types::{EventType, MacAddr};

/// How long after an alert about one address before another can fire for it.
///
/// A poisoning attack sends gratuitous replies continuously; without this it
/// would produce an alert per packet.
const COOLDOWN: Duration = Duration::from_secs(300);

/// Who holds an address, and when they were last heard claiming it.
#[derive(Debug)]
struct Holder {
    mac: MacAddr,
    last_claim: DateTime<Utc>,
    last_alert: Option<DateTime<Utc>>,
}

/// The `arp_spoof` analyzer.
pub struct ArpSpoof {
    grace_period: Duration,
    holders: BoundedMap<Ipv4Addr, Holder>,
}

impl ArpSpoof {
    /// Builds the analyzer.
    #[must_use]
    pub fn new(config: &ArpSpoofConfig, max_tracked: usize) -> Self {
        ArpSpoof {
            grace_period: config.grace_period.get(),
            holders: BoundedMap::new(max_tracked),
        }
    }
}

impl Analyzer for ArpSpoof {
    fn name(&self) -> &'static str {
        "arp_spoof"
    }

    fn analyze(&mut self, stimulus: &Stimulus<'_>, context: &Context) -> Vec<SecurityAlert> {
        let Stimulus::Observed(observation) = stimulus else {
            return Vec::new();
        };
        let Some(arp) = observation.arp() else {
            return Vec::new();
        };
        // Only a claim matters. A request with a sender address is a claim on
        // that address just as much as a reply is; a probe claims nothing.
        let Some(claimed) = arp.sender_ip else {
            return Vec::new();
        };
        if claimed.is_unspecified() || claimed.is_broadcast() || claimed.is_multicast() {
            return Vec::new();
        }
        // Proxy ARP by the gateway is an answer on somebody's behalf, not a
        // claim on their address. It returns before the holder table is written,
        // so the real owner stays the recorded holder and a genuine spoof of
        // that address is still caught. The predicate requires the *gateway's*
        // MAC and a non-gateway address, so neither attack this analyzer exists
        // for can reach this line: a stranger claiming the gateway's address is
        // not the gateway, and the gateway claiming its own address is not
        // proxying. See `GatewayTracker::proxy_arp_for`.
        if context.gateway.proxy_arp_for(observation).is_some() {
            return Vec::new();
        }

        let mac = observation.mac;
        let now = observation.observed_at;
        let gateway_impersonation =
            context.gateway.is_gateway_ip(claimed) && !context.gateway.is_gateway(mac);

        // The sender field disagreeing with the Ethernet source is itself a
        // spoofing shape, and it is recorded either way so an operator can see
        // it in the evidence.
        let forged_sender = arp.sender_mac != mac;

        let previous = self.holders.get(&claimed).map(|h| (h.mac, h.last_claim));
        let held_by_someone_else = previous.filter(|(holder, _)| *holder != mac);

        // How long the current holder has been quiet, when there is one. A
        // gateway impersonation does not need one: the gateway's address is
        // known from DHCP or from configuration, and a stranger claiming it is
        // an attack whether or not the real gateway has happened to ARP since
        // the daemon started. Requiring a prior claim here was a real hole,
        // because the common case is that everybody already has the gateway
        // cached and it never has to answer.
        let silence = held_by_someone_else.map(|(_, last)| now.signed_duration_since(last));
        let still_active = silence.is_some_and(|gap| {
            gap.to_std()
                .is_ok_and(|elapsed| elapsed < self.grace_period)
        });

        let mut alerts = Vec::new();
        if gateway_impersonation || still_active {
            let last_alert = self.holders.get(&claimed).and_then(|h| h.last_alert);
            if cooled_down(last_alert, now, COOLDOWN) {
                alerts.push(
                    SecurityAlert::new(
                        EventType::ArpSpoof,
                        mac,
                        now,
                        context.priority,
                        json!({
                            "analyzer": "arp_spoof",
                            "claimed_ip": claimed.to_string(),
                            "previous_holder": held_by_someone_else.map(|(h, _)| h.to_string()),
                            "previous_holder_silent_secs":
                                silence.map(|gap| gap.num_seconds().max(0)),
                            "grace_period_secs": self.grace_period.as_secs(),
                            "gateway_impersonation": gateway_impersonation,
                            "forged_sender": forged_sender,
                            "arp_sender_mac": arp.sender_mac.to_string(),
                        }),
                    )
                    .with_ip(claimed.to_string())
                    .with_interface(observation.interface.clone()),
                );
            }
        }

        // The claim is recorded whether or not it alerted. An attacker who wins
        // the address does now hold it, and the next legitimate claim by the
        // real owner is the interesting one.
        let alerted_at = alerts.first().map(|_| now);
        let existing_alert = self.holders.get(&claimed).and_then(|h| h.last_alert);
        self.holders.insert(
            claimed,
            Holder {
                mac,
                last_claim: now,
                last_alert: alerted_at.or(existing_alert),
            },
            now,
        );
        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::GatewayTracker;
    use crate::capture::{arp, fixtures};
    use crate::config::HumanDuration;
    use crate::types::{EventPriority, Observation};
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

    fn gateway_context() -> Context {
        Context {
            gateway: GatewayTracker::new(
                Some(Ipv4Addr::new(192, 168, 1, 1)),
                Some(mac("b8:27:eb:44:55:66")),
            ),
            ..context()
        }
    }

    /// An ARP reply from `from` claiming `claimed`.
    fn claim(from: &str, claimed: [u8; 4], when: DateTime<Utc>) -> Observation {
        let mut frame = fixtures::arp_reply();
        let source = mac(from).octets();
        frame[6..12].copy_from_slice(&source);
        frame[22..28].copy_from_slice(&source);
        frame[28..32].copy_from_slice(&claimed);
        arp::parse_frame(&frame, "eth0", when).expect("parsed")
    }

    fn config() -> ArpSpoofConfig {
        ArpSpoofConfig {
            enabled: true,
            grace_period: HumanDuration::from_secs(60),
        }
    }

    /// A context whose gateway is the Routerboard from the 2026-09-17 run.
    fn proxying_context() -> Context {
        Context {
            gateway: GatewayTracker::new(
                Some(Ipv4Addr::new(192, 168, 1, 1)),
                Some(mac("18:fd:74:39:e5:23")),
            ),
            ..context()
        }
    }

    #[test]
    fn the_gateway_proxy_arping_across_vlans_never_fires() {
        // The 2026-09-17 pattern: the router answers for hosts on two other
        // segments while those hosts are plainly still talking, which is exactly
        // the shape the grace period reads as a spoof.
        let mut analyzer = ArpSpoof::new(&config(), 1024);
        let context = proxying_context();
        let mut alerts = Vec::new();
        for second in 0..600i64 {
            for host in [[192, 168, 20, 55], [192, 168, 30, 12]] {
                alerts.extend(analyzer.analyze(
                    &Stimulus::Observed(&claim("00:11:32:aa:bb:cc", host, at(second))),
                    &context,
                ));
                alerts.extend(analyzer.analyze(
                    &Stimulus::Observed(&claim("18:fd:74:39:e5:23", host, at(second))),
                    &context,
                ));
            }
        }
        assert!(alerts.is_empty(), "proxy ARP is not a spoof: {alerts:?}");
    }

    #[test]
    fn a_stranger_claiming_the_gateway_address_still_fires() {
        // The first of the two attacks this analyzer exists for. The exemption
        // requires the gateway's own MAC, so an impersonator cannot reach it.
        let mut analyzer = ArpSpoof::new(&config(), 1024);
        let alerts = analyzer.analyze(
            &Stimulus::Observed(&claim("02:de:ad:be:ef:01", [192, 168, 1, 1], at(0))),
            &proxying_context(),
        );
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].details["gateway_impersonation"], true);
    }

    #[test]
    fn a_second_mac_taking_an_address_the_gateway_did_not_proxy_still_fires() {
        // The second attack. An ordinary address, an ordinary still-active
        // holder, a stranger taking it.
        let mut analyzer = ArpSpoof::new(&config(), 1024);
        let context = proxying_context();
        let _ = analyzer.analyze(
            &Stimulus::Observed(&claim("3c:22:fb:00:00:01", [192, 168, 1, 40], at(0))),
            &context,
        );
        let alerts = analyzer.analyze(
            &Stimulus::Observed(&claim("02:de:ad:be:ef:01", [192, 168, 1, 40], at(5))),
            &context,
        );
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].details["previous_holder"], "3c:22:fb:00:00:01");
    }

    #[test]
    fn proxying_an_address_does_not_hand_it_to_the_router() {
        // The holder table is the load-bearing part: if the router's answer were
        // recorded as a claim, the real owner's next packet would look like it
        // was taking the address back and would alert on the way past.
        let mut analyzer = ArpSpoof::new(&config(), 1024);
        let context = proxying_context();
        let _ = analyzer.analyze(
            &Stimulus::Observed(&claim("00:11:32:aa:bb:cc", [192, 168, 20, 55], at(0))),
            &context,
        );
        let _ = analyzer.analyze(
            &Stimulus::Observed(&claim("18:fd:74:39:e5:23", [192, 168, 20, 55], at(1))),
            &context,
        );
        assert!(
            analyzer
                .analyze(
                    &Stimulus::Observed(&claim("00:11:32:aa:bb:cc", [192, 168, 20, 55], at(2))),
                    &context
                )
                .is_empty(),
            "the real owner never lost the address"
        );
        // And a stranger taking it is still caught.
        let alerts = analyzer.analyze(
            &Stimulus::Observed(&claim("02:de:ad:be:ef:01", [192, 168, 20, 55], at(3))),
            &context,
        );
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn taking_an_address_from_a_device_that_is_still_talking_fires() {
        let mut analyzer = ArpSpoof::new(&config(), 1024);
        let context = context();
        assert!(
            analyzer
                .analyze(
                    &Stimulus::Observed(&claim("3c:22:fb:00:00:01", [192, 168, 1, 40], at(0))),
                    &context
                )
                .is_empty(),
            "the first claim establishes the holder"
        );
        let alerts = analyzer.analyze(
            &Stimulus::Observed(&claim("00:11:32:aa:bb:cc", [192, 168, 1, 40], at(30))),
            &context,
        );
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].event_type, EventType::ArpSpoof);
        assert_eq!(alerts[0].mac, mac("00:11:32:aa:bb:cc"));
        assert_eq!(alerts[0].ip.as_deref(), Some("192.168.1.40"));
        assert_eq!(alerts[0].details["previous_holder"], "3c:22:fb:00:00:01");
        assert_eq!(alerts[0].details["gateway_impersonation"], false);
    }

    #[test]
    fn a_dhcp_reassignment_after_the_grace_period_is_not_a_spoof() {
        // The false positive this analyzer exists to avoid. A laptop leaves,
        // the lease expires, a tablet gets the address.
        let mut analyzer = ArpSpoof::new(&config(), 1024);
        let context = context();
        let _ = analyzer.analyze(
            &Stimulus::Observed(&claim("3c:22:fb:00:00:01", [192, 168, 1, 40], at(0))),
            &context,
        );
        let alerts = analyzer.analyze(
            &Stimulus::Observed(&claim("00:11:32:aa:bb:cc", [192, 168, 1, 40], at(120))),
            &context,
        );
        assert!(
            alerts.is_empty(),
            "the previous holder had been quiet for two minutes: {alerts:?}"
        );
    }

    #[test]
    fn the_grace_period_boundary_is_exact() {
        for (offset, expect_alert) in [(59, true), (60, false), (61, false)] {
            let mut analyzer = ArpSpoof::new(&config(), 1024);
            let context = context();
            let _ = analyzer.analyze(
                &Stimulus::Observed(&claim("3c:22:fb:00:00:01", [192, 168, 1, 40], at(0))),
                &context,
            );
            let alerts = analyzer.analyze(
                &Stimulus::Observed(&claim("00:11:32:aa:bb:cc", [192, 168, 1, 40], at(offset))),
                &context,
            );
            assert_eq!(
                !alerts.is_empty(),
                expect_alert,
                "at {offset}s past the last claim"
            );
        }
    }

    #[test]
    fn claiming_the_gateway_address_fires_immediately_however_quiet_it_has_been() {
        let mut analyzer = ArpSpoof::new(&config(), 1024);
        let context = gateway_context();
        let _ = analyzer.analyze(
            &Stimulus::Observed(&claim("b8:27:eb:44:55:66", [192, 168, 1, 1], at(0))),
            &context,
        );
        // An hour later, well past any grace period.
        let alerts = analyzer.analyze(
            &Stimulus::Observed(&claim("00:11:32:aa:bb:cc", [192, 168, 1, 1], at(3600))),
            &context,
        );
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].details["gateway_impersonation"], true);
    }

    #[test]
    fn claiming_the_gateway_address_fires_even_if_the_gateway_never_arped() {
        // The hole this closes. On a settled network everybody already has the
        // gateway cached, so it may never answer an ARP; the gateway is known
        // from DHCP option 3 instead. An analyzer that needed a prior claim
        // would miss the attack it exists for.
        let mut analyzer = ArpSpoof::new(&config(), 1024);
        let context = gateway_context();
        let alerts = analyzer.analyze(
            &Stimulus::Observed(&claim("00:11:32:aa:bb:cc", [192, 168, 1, 1], at(0))),
            &context,
        );
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].details["gateway_impersonation"], true);
        assert!(
            alerts[0].details["previous_holder"].is_null(),
            "nobody had claimed it, and that is the point"
        );
    }

    #[test]
    fn an_ordinary_address_nobody_has_claimed_is_not_a_spoof() {
        // The other half of the same rule: without a prior holder and without
        // the gateway address, a first claim is just a device introducing
        // itself.
        let mut analyzer = ArpSpoof::new(&config(), 1024);
        let context = gateway_context();
        assert!(
            analyzer
                .analyze(
                    &Stimulus::Observed(&claim("00:11:32:aa:bb:cc", [192, 168, 1, 55], at(0))),
                    &context
                )
                .is_empty()
        );
    }

    #[test]
    fn the_real_gateway_reclaiming_its_own_address_is_not_an_attack() {
        let mut analyzer = ArpSpoof::new(&config(), 1024);
        let context = gateway_context();
        for n in 0..10 {
            assert!(
                analyzer
                    .analyze(
                        &Stimulus::Observed(&claim(
                            "b8:27:eb:44:55:66",
                            [192, 168, 1, 1],
                            at(n * 600)
                        )),
                        &context
                    )
                    .is_empty(),
                "round {n}"
            );
        }
    }

    #[test]
    fn a_device_reclaiming_its_own_address_is_never_an_alert() {
        let mut analyzer = ArpSpoof::new(&config(), 1024);
        let context = context();
        for n in 0..1000 {
            assert!(
                analyzer
                    .analyze(
                        &Stimulus::Observed(&claim("3c:22:fb:00:00:01", [192, 168, 1, 40], at(n))),
                        &context
                    )
                    .is_empty()
            );
        }
    }

    #[test]
    fn a_sustained_poisoning_attack_alerts_at_a_bounded_rate() {
        let mut analyzer = ArpSpoof::new(&config(), 1024);
        let context = context();
        let mut alerts = Vec::new();
        // The victim keeps claiming, the attacker keeps overriding, once a
        // second for an hour.
        for second in 0..3600i64 {
            alerts.extend(analyzer.analyze(
                &Stimulus::Observed(&claim("3c:22:fb:00:00:01", [192, 168, 1, 40], at(second))),
                &context,
            ));
            alerts.extend(analyzer.analyze(
                &Stimulus::Observed(&claim("00:11:32:aa:bb:cc", [192, 168, 1, 40], at(second))),
                &context,
            ));
        }
        // Two claimants alternating, a 300-second cooldown, one hour: a couple
        // of dozen at most, not seven thousand.
        assert!(
            (2..=30).contains(&alerts.len()),
            "expected a bounded alert rate, got {}",
            alerts.len()
        );
    }

    #[test]
    fn a_forged_sender_field_is_recorded_in_the_evidence() {
        let mut analyzer = ArpSpoof::new(&config(), 1024);
        let context = context();
        let _ = analyzer.analyze(
            &Stimulus::Observed(&claim("3c:22:fb:00:00:01", [192, 168, 1, 40], at(0))),
            &context,
        );
        // The Ethernet source and the ARP sender disagree.
        let mut frame = fixtures::arp_reply();
        frame[6..12].copy_from_slice(&mac("00:11:32:aa:bb:cc").octets());
        frame[22..28].copy_from_slice(&mac("3c:22:fb:99:99:99").octets());
        frame[28..32].copy_from_slice(&[192, 168, 1, 40]);
        let observation = arp::parse_frame(&frame, "eth0", at(10)).expect("parsed");

        let alerts = analyzer.analyze(&Stimulus::Observed(&observation), &context);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].details["forged_sender"], true);
        assert_eq!(alerts[0].details["arp_sender_mac"], "3c:22:fb:99:99:99");
    }

    #[test]
    fn an_arp_probe_claims_nothing_and_alerts_on_nothing() {
        let mut analyzer = ArpSpoof::new(&config(), 1024);
        let context = context();
        let probe = arp::parse_frame(&fixtures::arp_probe(), "eth0", at(0)).expect("parsed");
        assert!(
            analyzer
                .analyze(&Stimulus::Observed(&probe), &context)
                .is_empty()
        );
    }

    #[test]
    fn a_scanner_forging_addresses_cannot_grow_the_tracker() {
        let mut analyzer = ArpSpoof::new(&config(), 64);
        let context = context();
        for n in 0..5000u32 {
            #[allow(clippy::cast_possible_truncation)] // Deliberate: many
            // distinct claimed addresses is the hostile case.
            let claimed = [10, (n >> 16) as u8, (n >> 8) as u8, n as u8];
            let _ = analyzer.analyze(
                &Stimulus::Observed(&claim("3c:22:fb:00:00:01", claimed, at(0))),
                &context,
            );
        }
        assert!(analyzer.holders.len() <= 64);
    }
}
