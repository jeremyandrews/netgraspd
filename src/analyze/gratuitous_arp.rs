//! Detects a flood of gratuitous ARP announcements from one MAC.
//!
//! A gratuitous ARP is a device saying "this address is mine" without being
//! asked. A device sending them continuously against somebody else's address
//! is trying to keep a poisoned entry alive in everybody's ARP cache, because a
//! poisoned cache entry expires and has to be refreshed.
//!
//! That is why this is separate from `arp_spoof` rather than folded into it.
//! `arp_spoof` catches the moment an address changes hands; this catches the
//! sustained hammering that keeps it changed.
//!
//! ## Not every announcement is evidence
//!
//! Until issue #28 every announcement counted, and on a home LAN with no
//! attacker on it that was about fifty `gratuitous_arp` events a day, every one
//! at the threshold: Macs announcing their own address in a burst on every
//! wake and every Wi-Fi roam, and Apple TVs acting as Bonjour Sleep Proxy
//! announcing the address of a Mac that had just gone to sleep. Neither is
//! anybody claiming anything that is not theirs.
//!
//! So the analyzer keeps a **binding** per address: the MAC the daemon last
//! saw holding it, learned from ordinary ARP requests and replies, from RFC
//! 5227 probes (a device probing an address is about to take it), and from DHCP
//! Acks. A binding never moves away from a holder that is still live (heard on
//! any protocol within `live_within`), except to or from a known sleep proxy.
//! Each announcement is then one of:
//!
//! | Announcement | Counts toward `threshold` |
//! |---|---|
//! | of the address the sender already holds (wake, roam) | no |
//! | by a known sleep proxy for a sleeping holder, or by the holder taking it back | no |
//! | of an address whose holder has been quiet past `live_within` (a reassignment) | no |
//! | of an address a different, live MAC holds | **yes** |
//! | of the gateway's address by a MAC that is not the gateway | **yes**, however quiet the gateway |
//! | of an address the daemon holds no binding for | **yes**, as before |
//!
//! A probe (sender 0.0.0.0) is never an announcement at all.
//!
//! A **known sleep proxy** is a MAC that has sent an mDNS response advertising
//! `_sleep-proxy._udp` in the last day. It is not a licence: once the holder is
//! heard between two of the proxy's announcements for its address, the holder
//! was never asleep and the proxy's announcements count like anybody else's.
//!
//! The last row is what keeps a device flooding an address nobody has been
//! seen using caught, and is the one place a device waking can still alert: a
//! device that announces a fresh address with no probe, no DHCP Ack and no
//! ordinary ARP traffic the daemon saw first. On the network of issue #28 that
//! was four events in four days.

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::clock::Timestamp;
use serde_json::json;

use crate::analyze::window::{BoundedMap, RateWindow};
use crate::analyze::{Analyzer, Context, SecurityAlert, Stimulus, cooled_down};
use crate::config::GratuitousArpConfig;
use crate::types::{
    ArpDetail, DhcpMessageType, EventType, MacAddr, Observation, ObservationKind, ProtocolDetail,
    SignalKind,
};

/// How many timestamps one MAC's window holds. Any value above the threshold
/// works; this only bounds memory.
const WINDOW_CAPACITY: usize = 256;

/// The mDNS service a Bonjour Sleep Proxy advertises.
const SLEEP_PROXY_SERVICE: &str = "_sleep-proxy._udp";

/// How long a MAC stays a known sleep proxy after its last advertisement.
const SLEEP_PROXY_MEMORY: Duration = Duration::from_secs(24 * 3600);

/// Per-MAC flood state.
#[derive(Debug)]
struct Tracked {
    announcements: RateWindow,
    last_alert: Option<Timestamp>,
}

/// The last announcement seen for one address.
#[derive(Debug, Clone, Copy)]
struct Announced {
    by: MacAddr,
    at: Timestamp,
}

/// What one announcement is, against what the daemon knows about its address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Standing {
    /// The sender already holds the address.
    Own,
    /// A known sleep proxy answering for a sleeping holder, or the holder
    /// taking its address back from one.
    SleepProxy,
    /// The holder has gone quiet; the address is changing hands.
    Reassigned,
    /// A different, live MAC holds the address.
    Conflict(MacAddr),
    /// A MAC that is not the gateway announcing the gateway's address.
    GatewayImpersonation,
    /// Nobody is known to hold the address.
    Unbound,
}

impl Standing {
    /// Whether the announcement is evidence toward a flood.
    const fn counts(self) -> bool {
        matches!(
            self,
            Standing::Conflict(_) | Standing::GatewayImpersonation | Standing::Unbound
        )
    }
}

/// The gratuitous ARP flood analyzer.
pub struct GratuitousArp {
    window: Duration,
    threshold: usize,
    live_within: Duration,
    tracked: BoundedMap<MacAddr, Tracked>,
    /// Who holds each address; see the module documentation.
    bindings: BoundedMap<Ipv4Addr, MacAddr>,
    /// When each MAC was last heard on any protocol.
    heard: BoundedMap<MacAddr, Timestamp>,
    /// When each known sleep proxy last advertised.
    sleep_proxies: BoundedMap<MacAddr, Timestamp>,
    /// The last announcement of each address.
    announced: BoundedMap<Ipv4Addr, Announced>,
}

impl GratuitousArp {
    /// Builds the analyzer.
    #[must_use]
    pub fn new(config: &GratuitousArpConfig, max_tracked: usize) -> Self {
        GratuitousArp {
            window: config.window.get(),
            threshold: config.threshold.max(1),
            live_within: config.live_within.get(),
            tracked: BoundedMap::new(max_tracked),
            bindings: BoundedMap::new(max_tracked),
            heard: BoundedMap::new(max_tracked),
            sleep_proxies: BoundedMap::new(max_tracked),
            announced: BoundedMap::new(max_tracked),
        }
    }

    /// True when `then` is no more than `limit` before `now`.
    fn within(then: Timestamp, now: Timestamp, limit: Duration) -> bool {
        Duration::try_from(now.since(then)).is_ok_and(|elapsed| elapsed <= limit)
    }

    /// Whether a MAC has been heard from recently enough to still hold an
    /// address.
    fn is_live(&self, mac: MacAddr, now: Timestamp) -> bool {
        self.heard
            .get(&mac)
            .is_some_and(|last| Self::within(*last, now, self.live_within))
    }

    /// Whether a MAC has advertised itself as a Bonjour Sleep Proxy lately.
    fn is_sleep_proxy(&self, mac: MacAddr, now: Timestamp) -> bool {
        self.sleep_proxies
            .get(&mac)
            .is_some_and(|last| Self::within(*last, now, SLEEP_PROXY_MEMORY))
    }

    /// Records that `mac` holds `address`, unless a different MAC that is still
    /// live holds it. A sleep proxy never keeps an address from anybody: it
    /// holds it only while its owner sleeps.
    fn bind(&mut self, address: Ipv4Addr, mac: MacAddr, now: Timestamp) {
        if !usable(address) {
            return;
        }
        let keep = self.bindings.get(&address).is_some_and(|holder| {
            *holder != mac && self.is_live(*holder, now) && !self.is_sleep_proxy(*holder, now)
        });
        if !keep {
            self.bindings.insert(address, mac, now);
        }
    }

    /// Learns from everything that is not a gratuitous announcement.
    fn learn(&mut self, observation: &Observation, context: &Context) {
        let mac = observation.mac;
        let now = observation.observed_at;
        self.heard.insert(mac, now, now);
        if observation.source == crate::capture::mdns::SOURCE
            && observation.kind == ObservationKind::Announcement
            && observation.claims.iter().any(|claim| {
                claim.signal.kind == SignalKind::MdnsService
                    && claim.signal.value == SLEEP_PROXY_SERVICE
            })
        {
            self.sleep_proxies.insert(mac, now, now);
        }
        match &observation.detail {
            Some(ProtocolDetail::Dhcp(dhcp)) if dhcp.message_type == DhcpMessageType::Ack => {
                if let (Some(client), Some(address)) = (dhcp.client_mac, dhcp.assigned_ip) {
                    self.bind(address, client, now);
                }
            }
            Some(ProtocolDetail::Arp(arp)) if !arp.gratuitous => match arp.sender_ip {
                // An RFC 5227 probe: the sender is about to take the target.
                None => self.bind(arp.target_ip, mac, now),
                // The gateway answering for somebody else is not a claim; see
                // `GatewayTracker::proxy_arp_for`.
                Some(_) if context.gateway.proxy_arp_for(observation).is_some() => {}
                Some(sender) => self.bind(sender, mac, now),
            },
            _ => {}
        }
    }

    /// Classifies one announcement, and moves the binding when the address is
    /// legitimately changing hands.
    fn stand(
        &mut self,
        arp: &ArpDetail,
        mac: MacAddr,
        now: Timestamp,
        context: &Context,
    ) -> Standing {
        let address = arp.target_ip;
        let previous = self.announced.get(&address).copied();
        self.announced
            .insert(address, Announced { by: mac, at: now }, now);

        if context.gateway.is_gateway_ip(address) && !context.gateway.is_gateway(mac) {
            return Standing::GatewayImpersonation;
        }
        let Some(holder) = self.bindings.get(&address).copied() else {
            return Standing::Unbound;
        };
        if holder == mac {
            return Standing::Own;
        }
        if self.is_sleep_proxy(holder, now) {
            // The owner waking and taking its address back.
            self.bindings.insert(address, mac, now);
            return Standing::SleepProxy;
        }
        if self.is_sleep_proxy(mac, now) {
            // Answering for a sleeping holder, unless the holder has been heard
            // since this proxy's previous announcement of the address, in which
            // case it is awake and the two are fighting.
            let holder_spoke_since = previous
                .filter(|before| before.by == mac)
                .zip(self.heard.get(&holder).copied())
                .is_some_and(|(before, heard)| heard > before.at);
            return if holder_spoke_since {
                Standing::Conflict(holder)
            } else {
                Standing::SleepProxy
            };
        }
        if self.is_live(holder, now) {
            return Standing::Conflict(holder);
        }
        self.bindings.insert(address, mac, now);
        Standing::Reassigned
    }
}

/// Whether an address can be held by a device at all.
fn usable(address: Ipv4Addr) -> bool {
    !(address.is_unspecified() || address.is_broadcast() || address.is_multicast())
}

impl Analyzer for GratuitousArp {
    fn name(&self) -> &'static str {
        "gratuitous_arp"
    }

    fn analyze(&mut self, stimulus: &Stimulus<'_>, context: &Context) -> Vec<SecurityAlert> {
        let Stimulus::Observed(observation) = stimulus else {
            return Vec::new();
        };
        let Some(arp) = observation.arp().filter(|arp| arp.gratuitous) else {
            self.learn(observation, context);
            return Vec::new();
        };

        let mac = observation.mac;
        let now = observation.observed_at;
        let standing = self.stand(arp, mac, now, context);
        self.heard.insert(mac, now, now);
        if !standing.counts() {
            return Vec::new();
        }

        let window = self.window;
        let threshold = self.threshold;
        let tracked = self.tracked.entry_or_insert_with(mac, now, || Tracked {
            announcements: RateWindow::new(WINDOW_CAPACITY),
            last_alert: None,
        });
        let count = tracked.announcements.record(now, window);
        if count < threshold {
            return Vec::new();
        }
        // The cooldown is ten windows rather than one. A device stuck
        // announcing is stuck for hours, and a ten-second window would otherwise
        // mean an alert every ten seconds for as long as it lasts.
        let cooldown = window.saturating_mul(10);
        if !cooled_down(tracked.last_alert, now, cooldown) {
            return Vec::new();
        }
        tracked.last_alert = Some(now);
        tracked.announcements.clear();

        let live_holder = match standing {
            Standing::Conflict(holder) => Some(holder.to_string()),
            _ => None,
        };
        let mut alert = SecurityAlert::new(
            EventType::GratuitousArp,
            mac,
            now,
            context.priority,
            json!({
                "analyzer": "gratuitous_arp",
                "announcements": count,
                "threshold": threshold,
                "window_secs": window.as_secs(),
                "announced_ip": arp.target_ip.to_string(),
                "live_holder": live_holder,
                "gateway_impersonation": standing == Standing::GatewayImpersonation,
            }),
        )
        .with_interface(observation.interface.clone());
        if let Some(sender_ip) = arp.sender_ip {
            alert = alert.with_ip(sender_ip.to_string());
        }
        vec![alert]
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

    /// A gratuitous ARP from `from`.
    fn announcement(from: &str, when: Timestamp) -> Observation {
        let mut frame = fixtures::arp_gratuitous();
        let source = mac(from).octets();
        frame[6..12].copy_from_slice(&source);
        frame[22..28].copy_from_slice(&source);
        arp::parse_frame(&frame, "eth0", when).expect("parsed")
    }

    fn config() -> GratuitousArpConfig {
        GratuitousArpConfig {
            enabled: true,
            window: HumanDuration::from_secs(10),
            threshold: 5,
            ..GratuitousArpConfig::default()
        }
    }

    #[test]
    fn a_flood_fires() {
        let mut analyzer = GratuitousArp::new(&config(), 1024);
        let context = context();
        let mut alerts = Vec::new();
        for _ in 0..6 {
            alerts.extend(analyzer.analyze(
                &Stimulus::Observed(&announcement("00:11:32:aa:bb:cc", at(0))),
                &context,
            ));
        }
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].event_type, EventType::GratuitousArp);
        assert_eq!(alerts[0].mac, mac("00:11:32:aa:bb:cc"));
        assert_eq!(alerts[0].details["announcements"], 5);
        assert_eq!(alerts[0].details["threshold"], 5);
        assert_eq!(alerts[0].ip.as_deref(), Some("192.168.1.77"));
    }

    #[test]
    fn the_handful_a_device_sends_on_boot_never_fires() {
        let mut analyzer = GratuitousArp::new(&config(), 1024);
        let context = context();
        // Four announcements, which is what a device sends when it comes up.
        for n in 0..4 {
            assert!(
                analyzer
                    .analyze(
                        &Stimulus::Observed(&announcement("00:11:32:aa:bb:cc", at(n))),
                        &context
                    )
                    .is_empty()
            );
        }
    }

    #[test]
    fn announcements_spread_out_never_accumulate() {
        let mut analyzer = GratuitousArp::new(&config(), 1024);
        let context = context();
        // One a minute forever: never more than one inside a ten-second window.
        for n in 0..100 {
            assert!(
                analyzer
                    .analyze(
                        &Stimulus::Observed(&announcement("00:11:32:aa:bb:cc", at(n * 60))),
                        &context
                    )
                    .is_empty(),
                "minute {n}"
            );
        }
    }

    #[test]
    fn a_device_stuck_announcing_alerts_at_a_bounded_rate() {
        let mut analyzer = GratuitousArp::new(&config(), 1024);
        let context = context();
        let mut alerts = Vec::new();
        // Two announcements a second for an hour.
        for second in 0..3600i64 {
            for _ in 0..2 {
                alerts.extend(analyzer.analyze(
                    &Stimulus::Observed(&announcement("00:11:32:aa:bb:cc", at(second))),
                    &context,
                ));
            }
        }
        // A 100-second cooldown over an hour: 36ish, not 7200.
        assert!(
            (30..=40).contains(&alerts.len()),
            "expected a bounded alert rate, got {}",
            alerts.len()
        );
    }

    #[test]
    fn an_ordinary_request_or_reply_is_not_an_announcement() {
        let mut analyzer = GratuitousArp::new(&config(), 1024);
        let context = context();
        for _ in 0..100 {
            for frame in [fixtures::arp_request(), fixtures::arp_reply()] {
                let observation = arp::parse_frame(&frame, "eth0", at(0)).expect("parsed");
                assert!(
                    analyzer
                        .analyze(&Stimulus::Observed(&observation), &context)
                        .is_empty()
                );
            }
        }
    }

    #[test]
    fn the_count_is_per_mac_not_global() {
        let mut analyzer = GratuitousArp::new(&config(), 1024);
        let context = context();
        let mut alerts = Vec::new();
        // Five devices announcing once each is not one device announcing five
        // times.
        for n in 1..=5u8 {
            let who = format!("00:11:32:aa:bb:{n:02x}");
            alerts.extend(
                analyzer.analyze(&Stimulus::Observed(&announcement(&who, at(0))), &context),
            );
        }
        assert!(alerts.is_empty());
    }

    // ---- Issue #28: wake, roam and sleep proxy traffic ------------------

    const MAC_A: &str = "02:00:5e:28:00:0a";
    const MAC_B: &str = "02:00:5e:28:00:0b";
    const PROXY: &str = "02:00:5e:28:00:5b";
    const STRANGER: &str = "02:00:5e:28:de:ad";
    const ADDRESS_A: [u8; 4] = [192, 168, 1, 40];

    /// An ARP frame as the capture layer would hand it over: `sender` of
    /// `None` is a probe from 0.0.0.0.
    fn arp_frame(
        op: crate::types::ArpOp,
        from: &str,
        sender: Option<[u8; 4]>,
        target: [u8; 4],
        when: Timestamp,
    ) -> Observation {
        use crate::types::{ArpDetail, ObservationKind, ProtocolDetail};
        let sender = sender.map(std::net::Ipv4Addr::from);
        let target = std::net::Ipv4Addr::from(target);
        let gratuitous = sender == Some(target);
        let kind = match (op, gratuitous) {
            (_, true) => ObservationKind::Announcement,
            (crate::types::ArpOp::Request, false) => ObservationKind::Request,
            (crate::types::ArpOp::Reply, false) => ObservationKind::Reply,
        };
        Observation::new(
            mac(from),
            sender.map(std::net::IpAddr::V4),
            "eth0",
            "arp",
            kind,
            when,
        )
        .with_detail(ProtocolDetail::Arp(ArpDetail {
            op,
            sender_mac: mac(from),
            sender_ip: sender,
            target_ip: target,
            gratuitous,
        }))
    }

    fn announce(from: &str, address: [u8; 4], when: Timestamp) -> Observation {
        arp_frame(
            crate::types::ArpOp::Request,
            from,
            Some(address),
            address,
            when,
        )
    }

    fn probe(from: &str, address: [u8; 4], when: Timestamp) -> Observation {
        arp_frame(crate::types::ArpOp::Request, from, None, address, when)
    }

    /// An ordinary ARP request: `from` at `address` asking for the gateway.
    fn talk(from: &str, address: [u8; 4], when: Timestamp) -> Observation {
        arp_frame(
            crate::types::ArpOp::Request,
            from,
            Some(address),
            [192, 168, 1, 1],
            when,
        )
    }

    /// An mDNS response advertising the Bonjour Sleep Proxy service.
    fn sleep_proxy_advert(from: &str, when: Timestamp) -> Observation {
        use crate::types::{NameClaim, ObservationKind, Signal, SignalKind};
        let mut observation = Observation::new(
            mac(from),
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                192, 168, 1, 9,
            ))),
            "eth0",
            "mdns",
            ObservationKind::Announcement,
            when,
        );
        observation.claims.push(NameClaim::unaddressed(Signal::new(
            SignalKind::MdnsService,
            "_sleep-proxy._udp",
        )));
        observation
    }

    fn run(analyzer: &mut GratuitousArp, frames: &[Observation]) -> Vec<SecurityAlert> {
        let context = context();
        frames
            .iter()
            .flat_map(|frame| analyzer.analyze(&Stimulus::Observed(frame), &context))
            .collect()
    }

    #[test]
    fn a_mac_waking_probes_then_announces_its_own_address_and_raises_nothing() {
        // The RFC 5227 sequence a Mac sends on wake and on roam: a probe from
        // 0.0.0.0, then a burst of announcements of the address it probed.
        // Five in ten seconds is exactly the old threshold.
        let mut analyzer = GratuitousArp::new(&config(), 1024);
        let mut frames = vec![probe(MAC_A, ADDRESS_A, at(0))];
        frames.extend((1..=5).map(|n| announce(MAC_A, ADDRESS_A, at(n * 2))));
        let alerts = run(&mut analyzer, &frames);
        assert!(
            alerts.is_empty(),
            "a device waking is not spoofing: {alerts:?}"
        );
    }

    #[test]
    fn a_device_announcing_the_address_it_already_holds_raises_nothing() {
        // No probe this time: a roam between access points. The daemon already
        // holds the binding from the device's ordinary traffic.
        let mut analyzer = GratuitousArp::new(&config(), 1024);
        let mut frames = vec![talk(MAC_A, ADDRESS_A, at(0))];
        for burst in 0..10i64 {
            frames.extend((0..8).map(|n| announce(MAC_A, ADDRESS_A, at(600 * burst + n))));
        }
        let alerts = run(&mut analyzer, &frames);
        assert!(alerts.is_empty(), "{alerts:?}");
    }

    #[test]
    fn a_sleep_proxy_announcing_for_a_sleeping_peer_raises_nothing() {
        // The peer talks, registers with the proxy and sleeps; the proxy takes
        // its address seconds later, while the peer still looks live. Then the
        // peer wakes and takes the address back.
        let mut analyzer = GratuitousArp::new(&config(), 1024);
        let mut frames = vec![
            sleep_proxy_advert(PROXY, at(0)),
            talk(MAC_A, ADDRESS_A, at(1)),
        ];
        frames.extend((0..6).map(|n| announce(PROXY, ADDRESS_A, at(3 + n))));
        frames.push(probe(MAC_A, ADDRESS_A, at(3600)));
        frames.extend((0..6).map(|n| announce(MAC_A, ADDRESS_A, at(3601 + n))));
        let alerts = run(&mut analyzer, &frames);
        assert!(
            alerts.is_empty(),
            "a sleep proxy is not a spoofer: {alerts:?}"
        );
    }

    #[test]
    fn a_device_claiming_a_live_peers_address_raises_gratuitous_arp() {
        let mut analyzer = GratuitousArp::new(&config(), 1024);
        let mut frames = Vec::new();
        for n in 0..10i64 {
            // The real holder keeps talking throughout.
            frames.push(talk(MAC_A, ADDRESS_A, at(n)));
            if (2..7).contains(&n) {
                frames.push(announce(STRANGER, ADDRESS_A, at(n)));
            }
        }
        let alerts = run(&mut analyzer, &frames);
        assert_eq!(alerts.len(), 1, "{alerts:?}");
        assert_eq!(alerts[0].event_type, EventType::GratuitousArp);
        assert_eq!(alerts[0].mac, mac(STRANGER));
        assert_eq!(alerts[0].ip.as_deref(), Some("192.168.1.40"));
    }

    #[test]
    fn a_sleep_proxy_fighting_a_peer_that_is_still_talking_raises_gratuitous_arp() {
        // Being a known sleep proxy is not a licence: once the holder is heard
        // between the proxy's announcements, it was never asleep.
        let mut analyzer = GratuitousArp::new(&config(), 1024);
        let mut frames = vec![sleep_proxy_advert(PROXY, at(0))];
        for n in 1..=8i64 {
            frames.push(talk(MAC_A, ADDRESS_A, at(n)));
            frames.push(announce(PROXY, ADDRESS_A, at(n)));
        }
        let alerts = run(&mut analyzer, &frames);
        assert_eq!(alerts.len(), 1, "{alerts:?}");
        assert_eq!(alerts[0].mac, mac(PROXY));
    }

    #[test]
    fn a_stranger_flooding_the_gateway_address_raises_gratuitous_arp_however_quiet_the_gateway() {
        let mut analyzer = GratuitousArp::new(&config(), 1024);
        let context = Context {
            gateway: GatewayTracker::new(
                Some(std::net::Ipv4Addr::new(192, 168, 1, 1)),
                Some(mac(MAC_B)),
            ),
            ..context()
        };
        let mut alerts = Vec::new();
        let mut frames = vec![announce(MAC_B, [192, 168, 1, 1], at(0))];
        frames.extend((0..5).map(|n| announce(STRANGER, [192, 168, 1, 1], at(3600 + n))));
        for frame in &frames {
            alerts.extend(analyzer.analyze(&Stimulus::Observed(frame), &context));
        }
        assert_eq!(alerts.len(), 1, "{alerts:?}");
        assert_eq!(alerts[0].mac, mac(STRANGER));
    }

    #[test]
    fn taking_over_an_address_whose_holder_went_quiet_raises_nothing() {
        // A lease reassigned: the old holder has been silent for an hour.
        let mut analyzer = GratuitousArp::new(&config(), 1024);
        let mut frames = vec![talk(MAC_A, ADDRESS_A, at(0))];
        frames.extend((0..6).map(|n| announce(MAC_B, ADDRESS_A, at(3600 + n))));
        let alerts = run(&mut analyzer, &frames);
        assert!(alerts.is_empty(), "{alerts:?}");
    }

    #[test]
    fn the_tracker_is_bounded() {
        let mut analyzer = GratuitousArp::new(&config(), 64);
        let context = context();
        for n in 0..5000u32 {
            let who = format!(
                "02:00:{:02x}:{:02x}:{:02x}:{:02x}",
                n >> 24,
                (n >> 16) & 0xff,
                (n >> 8) & 0xff,
                n & 0xff
            );
            let _ = analyzer.analyze(&Stimulus::Observed(&announcement(&who, at(0))), &context);
        }
        assert!(analyzer.tracked.len() <= 64);
    }
}
