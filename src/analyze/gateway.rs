//! Working out which device is the gateway, without asking.
//!
//! Several analyzers need this. `arp_spoof` treats a claim on the gateway's
//! address as an immediate alert rather than a grace-period question, because
//! impersonating the gateway is the whole point of an ARP poisoning attack.
//! `arp_scan` holds the gateway to a looser threshold, because a router
//! legitimately ARPs for everything it forwards to.
//!
//! Three sources, in descending order of how much they can be trusted:
//!
//! 1. **Configuration.** An operator who typed it in is right.
//! 2. **DHCP option 3.** The server handing out leases states the default
//!    gateway. This is authoritative, it is on the wire already, and it costs
//!    nothing to read. A rogue DHCP server could lie, which is why `rogue_dhcp`
//!    exists and why a learned value never overrides a configured one.
//! 3. **ARP request popularity.** Every device on a LAN ARPs for the gateway,
//!    and almost nothing else is asked about by everybody. The address that the
//!    most *distinct* MACs have asked about is the gateway. Distinct askers
//!    rather than total requests, because one chatty device retrying one address
//!    would otherwise elect it.
//!
//! The MAC then follows from the address: whoever answers an ARP for the gateway
//! address, or sources traffic from it, is the gateway.
//!
//! None of this transmits anything.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};

use crate::types::{ArpOp, MacAddr, Observation};

/// How many distinct MACs must ask about an address before it is inferred to be
/// the gateway.
///
/// Three is enough to beat coincidence on a household network and low enough to
/// converge within seconds of startup.
const INFERENCE_QUORUM: usize = 3;

/// How many candidate addresses the inference tracks. Bounded so that a scanner
/// asking about the whole subnet cannot grow it.
const MAX_CANDIDATES: usize = 512;

/// Where the current belief came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewaySource {
    /// Nothing is known yet.
    Unknown,
    /// An operator configured it.
    Configured,
    /// A DHCP server said so, in option 3.
    Dhcp,
    /// Inferred from who everybody ARPs for.
    Inferred,
}

impl GatewaySource {
    /// Stable name, used in alert details.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            GatewaySource::Unknown => "unknown",
            GatewaySource::Configured => "configured",
            GatewaySource::Dhcp => "dhcp",
            GatewaySource::Inferred => "inferred",
        }
    }

    /// How much this source can be trusted, so a weaker one never overrides a
    /// stronger one.
    const fn rank(&self) -> u8 {
        match self {
            GatewaySource::Unknown => 0,
            GatewaySource::Inferred => 1,
            GatewaySource::Dhcp => 2,
            GatewaySource::Configured => 3,
        }
    }
}

/// How many proxied addresses are remembered for reporting.
///
/// Reporting only: the suppression decision is made from the packet in hand and
/// never from this set, so a full set costs visibility and nothing else. A
/// router proxying for two or three VLANs is well inside it.
const MAX_PROXIED: usize = 256;

/// What is currently believed about the gateway.
#[derive(Debug)]
pub struct GatewayTracker {
    ip: Option<Ipv4Addr>,
    ip_source: GatewaySource,
    mac: Option<MacAddr>,
    mac_source: GatewaySource,
    /// Distinct MACs that have asked about each candidate address.
    askers: HashMap<Ipv4Addr, Vec<MacAddr>>,
    /// Whether proxy ARP by the gateway is treated as ordinary.
    proxy_arp: bool,
    /// Addresses the gateway has been seen answering for on somebody's behalf.
    /// Kept for `netgraspd stats` and for the logs; see [`MAX_PROXIED`].
    proxied: BTreeSet<Ipv4Addr>,
}

impl GatewayTracker {
    /// Builds a tracker, seeded with whatever the operator configured.
    #[must_use]
    pub fn new(ip: Option<Ipv4Addr>, mac: Option<MacAddr>) -> Self {
        GatewayTracker {
            ip,
            ip_source: if ip.is_some() {
                GatewaySource::Configured
            } else {
                GatewaySource::Unknown
            },
            mac,
            mac_source: if mac.is_some() {
                GatewaySource::Configured
            } else {
                GatewaySource::Unknown
            },
            askers: HashMap::new(),
            proxy_arp: true,
            proxied: BTreeSet::new(),
        }
    }

    /// Sets whether proxy ARP by the gateway is treated as ordinary, builder
    /// style. Defaults to true; `security.proxy_arp_gateway` is the switch.
    #[must_use]
    pub const fn with_proxy_arp(mut self, proxy_arp: bool) -> Self {
        self.proxy_arp = proxy_arp;
        self
    }

    /// Addresses the gateway has been seen proxy-ARPing for.
    #[must_use]
    pub fn proxied(&self) -> &BTreeSet<Ipv4Addr> {
        &self.proxied
    }

    /// The address a frame is the gateway proxy-ARPing for, when it is one.
    ///
    /// **A router that proxy-ARPs answers for addresses that are not its own,
    /// with its own hardware address.** On a segment routed across VLANs that is
    /// how a host on one segment reaches a host on another, and it means the
    /// same address is legitimately seen at the router's MAC and at its real
    /// owner's. Reading that as two devices fighting over an address produced
    /// every one of the 34 `ip_conflict` and `arp_spoof` alerts on a real
    /// network on 2026-09-17.
    ///
    /// The three conditions are all necessary and none of them is negotiable:
    ///
    /// 1. **A reply.** A request carries the sender's own address and is a claim
    ///    on it, not an answer on anybody's behalf.
    /// 2. **From the learned gateway MAC.** Not from the ARP sender field, which
    ///    an attacker writes; from the Ethernet source, which is who actually
    ///    transmitted. A MAC that is not the gateway gets no exemption at all.
    /// 3. **For an address that is not the gateway's own.** The gateway
    ///    answering for the gateway address is the gateway, and an impersonation
    ///    of it is exactly what `arp_spoof` must still catch.
    ///
    /// The decision is made from the packet every time rather than from
    /// [`proxied`](Self::proxied), so nothing an attacker sends can widen it
    /// later.
    #[must_use]
    pub fn proxy_arp_for(&self, observation: &Observation) -> Option<Ipv4Addr> {
        if !self.proxy_arp {
            return None;
        }
        let arp = observation.arp()?;
        if arp.op != ArpOp::Reply {
            return None;
        }
        if !self.is_gateway(observation.mac) {
            return None;
        }
        let claimed = arp.sender_ip?;
        (!self.is_gateway_ip(claimed)).then_some(claimed)
    }

    /// The gateway's address, when one is known.
    #[must_use]
    pub const fn ip(&self) -> Option<Ipv4Addr> {
        self.ip
    }

    /// The gateway's hardware address, when one is known.
    #[must_use]
    pub const fn mac(&self) -> Option<MacAddr> {
        self.mac
    }

    /// Where the current address belief came from.
    #[must_use]
    pub const fn ip_source(&self) -> GatewaySource {
        self.ip_source
    }

    /// Where the current hardware address belief came from.
    #[must_use]
    pub const fn mac_source(&self) -> GatewaySource {
        self.mac_source
    }

    /// True when this MAC is believed to be the gateway.
    ///
    /// False when nothing is known, which is the safe reading: an analyzer that
    /// treated every MAC as the gateway while it was still learning would
    /// exempt the whole network.
    #[must_use]
    pub fn is_gateway(&self, mac: MacAddr) -> bool {
        self.mac == Some(mac)
    }

    /// True when this address is believed to be the gateway's.
    #[must_use]
    pub fn is_gateway_ip(&self, ip: Ipv4Addr) -> bool {
        self.ip == Some(ip)
    }

    /// Folds one observation into the belief.
    pub fn observe(&mut self, observation: &Observation) {
        if let Some(dhcp) = observation.dhcp()
            && let Some(router) = dhcp.router
        {
            self.set_ip(router, GatewaySource::Dhcp);
        }
        if let Some(arp) = observation.arp() {
            match arp.op {
                // Whoever answers for the gateway address is the gateway.
                ArpOp::Reply => {
                    if let Some(sender_ip) = arp.sender_ip
                        && self.ip == Some(sender_ip)
                    {
                        self.set_mac(observation.mac, self.ip_source);
                    }
                }
                ArpOp::Request => {
                    if !arp.gratuitous {
                        self.record_asker(arp.target_ip, observation.mac);
                    }
                }
            }
        }
        // Any traffic sourced from the gateway address identifies its MAC, which
        // covers a network where the gateway never has to answer an ARP because
        // everybody already has it cached.
        if let Some(IpAddr::V4(v4)) = observation.ip
            && self.ip == Some(v4)
        {
            self.set_mac(observation.mac, self.ip_source);
        }

        // Record proxy ARP, which the analyzers then decline to alert on. This
        // runs after the two `set_mac` branches above, so a frame that is itself
        // what identified the gateway is judged against that knowledge.
        if let Some(proxied) = self.proxy_arp_for(observation) {
            self.note_proxy_arp(proxied);
        }
    }

    /// Remembers an address the gateway answered for on somebody else's behalf.
    ///
    /// Logged the first time each address is seen and never again: a router
    /// proxying for a VLAN answers constantly, and a line per packet would be
    /// its own kind of alert fatigue.
    fn note_proxy_arp(&mut self, address: Ipv4Addr) {
        if self.proxied.contains(&address) {
            return;
        }
        if self.proxied.len() >= MAX_PROXIED {
            return;
        }
        self.proxied.insert(address);
        tracing::info!(
            %address,
            gateway = ?self.mac.map(|m| m.to_string()),
            "the gateway is proxy-ARPing for this address; it is not an address conflict"
        );
    }

    /// Records that a MAC asked about an address, promoting the address to
    /// gateway once enough distinct MACs have asked.
    fn record_asker(&mut self, target: Ipv4Addr, asker: MacAddr) {
        if target.is_unspecified() || target.is_broadcast() || target.is_multicast() {
            return;
        }
        if self.ip_source.rank() > GatewaySource::Inferred.rank() {
            // Something authoritative already answered this; counting would only
            // burn memory.
            return;
        }
        if !self.askers.contains_key(&target) && self.askers.len() >= MAX_CANDIDATES {
            // A scanner asking about the whole subnet must not be able to grow
            // this. Dropping new candidates is right: the gateway is already
            // being asked about by everybody and is already in the map.
            return;
        }
        let askers = self.askers.entry(target).or_default();
        if !askers.contains(&asker) {
            askers.push(asker);
        }
        if askers.len() >= INFERENCE_QUORUM {
            self.set_ip(target, GatewaySource::Inferred);
        }
    }

    /// Sets the address if the new source is at least as trustworthy.
    fn set_ip(&mut self, ip: Ipv4Addr, source: GatewaySource) {
        if source.rank() < self.ip_source.rank() {
            return;
        }
        if self.ip != Some(ip) {
            tracing::info!(%ip, source = source.as_str(), "gateway address learned");
            // The MAC belonged to the old address, so it is no longer known.
            if self.mac_source != GatewaySource::Configured {
                self.mac = None;
                self.mac_source = GatewaySource::Unknown;
            }
        }
        self.ip = Some(ip);
        self.ip_source = source;
        self.askers.clear();
    }

    /// Sets the hardware address, refusing to be talked out of one it already
    /// holds by evidence that is no stronger.
    ///
    /// **This is the load-bearing rule of the whole tracker.** The MAC is
    /// learned from ARP replies and from traffic sourced at the gateway address,
    /// and both of those are channels an attacker controls completely. An
    /// attacker who could replace the known gateway MAC by sending one forged
    /// reply would make `arp_spoof` treat itself as the gateway and stop
    /// alerting, which turns the detector into an accessory.
    ///
    /// So: **learning** a MAC needs only equal rank, because nothing is being
    /// contradicted. **Replacing** one needs strictly greater rank. A genuinely
    /// replaced router is handled by configuring `security.gateway_mac` or by
    /// restarting, which is a fair price for the attack this closes.
    fn set_mac(&mut self, mac: MacAddr, source: GatewaySource) {
        if source == GatewaySource::Unknown {
            return;
        }
        match self.mac {
            Some(known) if known == mac => {
                // Same answer; keep the stronger of the two sources.
                if source.rank() > self.mac_source.rank() {
                    self.mac_source = source;
                }
            }
            Some(known) => {
                if source.rank() > self.mac_source.rank() {
                    tracing::info!(
                        previous = %known,
                        %mac,
                        source = source.as_str(),
                        "gateway hardware address replaced by stronger evidence"
                    );
                    self.mac = Some(mac);
                    self.mac_source = source;
                } else {
                    // Not necessarily an attack: proxy ARP and a failover pair
                    // both look like this. But it is never something to act on
                    // silently, and arp_spoof will have its own opinion.
                    tracing::warn!(
                        known = %known,
                        claimant = %mac,
                        source = source.as_str(),
                        "a second MAC answered for the gateway address; keeping the known one"
                    );
                }
            }
            None => {
                if source.rank() >= self.mac_source.rank() {
                    tracing::info!(
                        %mac,
                        source = source.as_str(),
                        "gateway hardware address learned"
                    );
                    self.mac = Some(mac);
                    self.mac_source = source;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{arp, dhcp, fixtures};
    use chrono::{DateTime, TimeZone, Utc};

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_770_000_000 + secs, 0)
            .single()
            .expect("valid timestamp")
    }

    fn mac(s: &str) -> MacAddr {
        s.parse().expect("test mac")
    }

    /// An ARP request from `from` asking about `target`.
    fn request(from: &str, target: [u8; 4], when: DateTime<Utc>) -> Observation {
        let mut frame = fixtures::arp_request();
        let source = mac(from).octets();
        frame[6..12].copy_from_slice(&source);
        frame[22..28].copy_from_slice(&source);
        frame[38..42].copy_from_slice(&target);
        arp::parse_frame(&frame, "eth0", when).expect("parsed")
    }

    /// An ARP reply from `from` claiming `claimed`.
    fn reply(from: &str, claimed: [u8; 4], when: DateTime<Utc>) -> Observation {
        let mut frame = fixtures::arp_reply();
        let source = mac(from).octets();
        frame[6..12].copy_from_slice(&source);
        frame[22..28].copy_from_slice(&source);
        frame[28..32].copy_from_slice(&claimed);
        arp::parse_frame(&frame, "eth0", when).expect("parsed")
    }

    /// A tracker that already knows both halves of the gateway.
    fn known() -> GatewayTracker {
        GatewayTracker::new(
            Some(Ipv4Addr::new(192, 168, 1, 1)),
            Some(mac("18:fd:74:39:e5:23")),
        )
    }

    #[test]
    fn the_gateway_answering_for_another_segment_is_proxy_arp() {
        // The 2026-09-17 shape: a Routerboard proxy-ARPing across VLANs. Two
        // segments, two addresses that are not the gateway's own.
        let mut tracker = known();
        for claimed in [[192, 168, 20, 55], [192, 168, 30, 12]] {
            let observation = reply("18:fd:74:39:e5:23", claimed, at(0));
            assert!(
                tracker.proxy_arp_for(&observation).is_some(),
                "{claimed:?} is the gateway answering on somebody's behalf"
            );
            tracker.observe(&observation);
        }
        assert_eq!(
            tracker.proxied().len(),
            2,
            "both proxied addresses are recorded for the operator to see"
        );
    }

    #[test]
    fn the_gateway_answering_for_itself_is_not_proxy_arp() {
        // Otherwise the exemption would swallow the gateway's own address, and
        // an impersonation of it is the attack arp_spoof exists for.
        let tracker = known();
        let observation = reply("18:fd:74:39:e5:23", [192, 168, 1, 1], at(0));
        assert_eq!(tracker.proxy_arp_for(&observation), None);
    }

    #[test]
    fn a_stranger_answering_for_anything_is_not_proxy_arp() {
        let tracker = known();
        for claimed in [[192, 168, 1, 1], [192, 168, 20, 55]] {
            let observation = reply("02:de:ad:be:ef:01", claimed, at(0));
            assert_eq!(
                tracker.proxy_arp_for(&observation),
                None,
                "only the gateway's own MAC earns the exemption"
            );
        }
    }

    #[test]
    fn a_request_is_never_proxy_arp() {
        // A request carries the sender's own address and is a claim on it.
        let tracker = known();
        let observation = request("18:fd:74:39:e5:23", [192, 168, 20, 55], at(0));
        assert_eq!(tracker.proxy_arp_for(&observation), None);
    }

    #[test]
    fn an_unknown_gateway_exempts_nothing() {
        let tracker = GatewayTracker::new(None, None);
        let observation = reply("18:fd:74:39:e5:23", [192, 168, 20, 55], at(0));
        assert_eq!(tracker.proxy_arp_for(&observation), None);
    }

    #[test]
    fn the_switch_turns_the_whole_rule_off() {
        let tracker = known().with_proxy_arp(false);
        let observation = reply("18:fd:74:39:e5:23", [192, 168, 20, 55], at(0));
        assert_eq!(tracker.proxy_arp_for(&observation), None);
    }

    #[test]
    fn the_proxied_set_is_bounded() {
        // A router proxying for a whole /16 must not be able to grow this.
        let mut tracker = known();
        for n in 0..5000u32 {
            let claimed = [
                10,
                u8::try_from((n >> 8) & 0xff).expect("byte"),
                u8::try_from(n & 0xff).expect("byte"),
                7,
            ];
            tracker.observe(&reply("18:fd:74:39:e5:23", claimed, at(0)));
        }
        assert!(tracker.proxied().len() <= MAX_PROXIED);
    }

    #[test]
    fn nothing_is_known_until_something_says_so() {
        let tracker = GatewayTracker::new(None, None);
        assert_eq!(tracker.ip(), None);
        assert_eq!(tracker.mac(), None);
        assert_eq!(tracker.ip_source(), GatewaySource::Unknown);
        assert!(
            !tracker.is_gateway(mac("3c:22:fb:00:00:01")),
            "an unknown gateway must not match everything"
        );
    }

    #[test]
    fn configuration_is_taken_at_its_word() {
        let tracker = GatewayTracker::new(
            Some(Ipv4Addr::new(10, 0, 0, 1)),
            Some(mac("b8:27:eb:44:55:66")),
        );
        assert_eq!(tracker.ip(), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(tracker.is_gateway(mac("b8:27:eb:44:55:66")));
        assert_eq!(tracker.ip_source(), GatewaySource::Configured);
    }

    #[test]
    fn a_dhcp_offer_states_the_gateway_authoritatively() {
        let mut tracker = GatewayTracker::new(None, None);
        let offer = dhcp::parse_frame(&fixtures::dhcp_offer(), "eth0", at(0)).expect("parsed");
        tracker.observe(&offer);
        assert_eq!(tracker.ip(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(tracker.ip_source(), GatewaySource::Dhcp);
        // The Offer is sourced from 192.168.1.1, so the same packet names the MAC.
        assert_eq!(tracker.mac(), Some(mac("b8:27:eb:44:55:66")));
    }

    #[test]
    fn dhcp_does_not_override_configuration() {
        // A rogue DHCP server saying otherwise must not move a configured value.
        let mut tracker = GatewayTracker::new(Some(Ipv4Addr::new(10, 0, 0, 1)), None);
        let offer = dhcp::parse_frame(&fixtures::dhcp_offer(), "eth0", at(0)).expect("parsed");
        tracker.observe(&offer);
        assert_eq!(tracker.ip(), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(tracker.ip_source(), GatewaySource::Configured);
    }

    #[test]
    fn the_address_everybody_asks_about_is_the_gateway() {
        let mut tracker = GatewayTracker::new(None, None);
        for (n, who) in [
            "3c:22:fb:00:00:01",
            "3c:22:fb:00:00:02",
            "3c:22:fb:00:00:03",
        ]
        .into_iter()
        .enumerate()
        {
            tracker.observe(&request(
                who,
                [192, 168, 1, 1],
                at(i64::try_from(n).expect("small")),
            ));
        }
        assert_eq!(tracker.ip(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(tracker.ip_source(), GatewaySource::Inferred);
    }

    #[test]
    fn one_device_asking_repeatedly_elects_nothing() {
        // The false inference this prevents: a device retrying one unanswered
        // ARP two hundred times.
        let mut tracker = GatewayTracker::new(None, None);
        for n in 0..200 {
            tracker.observe(&request("3c:22:fb:00:00:01", [192, 168, 1, 99], at(n)));
        }
        assert_eq!(
            tracker.ip(),
            None,
            "distinct askers is the quorum, not packets"
        );
    }

    #[test]
    fn a_scanner_asking_about_the_whole_subnet_cannot_grow_the_candidate_map() {
        let mut tracker = GatewayTracker::new(None, None);
        for n in 0..5000u32 {
            #[allow(clippy::cast_possible_truncation)] // Deliberate: the point
            // is to produce many distinct target addresses.
            let target = [10, (n >> 16) as u8, (n >> 8) as u8, n as u8];
            tracker.observe(&request("3c:22:fb:00:00:01", target, at(0)));
        }
        assert!(tracker.askers.len() <= MAX_CANDIDATES);
    }

    #[test]
    fn whoever_answers_for_the_gateway_address_is_the_gateway() {
        let mut tracker = GatewayTracker::new(Some(Ipv4Addr::new(192, 168, 1, 1)), None);
        let reply = arp::parse_frame(&fixtures::arp_reply(), "eth0", at(0)).expect("parsed");
        tracker.observe(&reply);
        assert_eq!(tracker.mac(), Some(mac("b8:27:eb:44:55:66")));
        assert!(tracker.is_gateway(mac("b8:27:eb:44:55:66")));
    }

    #[test]
    fn a_reply_for_a_different_address_names_nobody() {
        let mut tracker = GatewayTracker::new(Some(Ipv4Addr::new(10, 0, 0, 1)), None);
        let reply = arp::parse_frame(&fixtures::arp_reply(), "eth0", at(0)).expect("parsed");
        tracker.observe(&reply);
        assert_eq!(tracker.mac(), None);
    }

    #[test]
    fn a_gratuitous_request_does_not_vote_for_its_own_address() {
        // A device announcing itself asks about its own address, and counting
        // that would let three announcements elect a printer as the gateway.
        let mut tracker = GatewayTracker::new(None, None);
        for _ in 0..10 {
            let observation =
                arp::parse_frame(&fixtures::arp_gratuitous(), "eth0", at(0)).expect("parsed");
            tracker.observe(&observation);
        }
        assert_eq!(tracker.ip(), None);
    }

    #[test]
    fn learning_a_new_address_forgets_the_old_hardware_address() {
        let mut tracker = GatewayTracker::new(None, None);
        let offer = dhcp::parse_frame(&fixtures::dhcp_offer(), "eth0", at(0)).expect("parsed");
        tracker.observe(&offer);
        assert!(tracker.mac().is_some());
        // The network is renumbered and a new server says so.
        tracker.set_ip(Ipv4Addr::new(10, 0, 0, 1), GatewaySource::Dhcp);
        assert_eq!(
            tracker.mac(),
            None,
            "the old MAC answered for an address that is no longer the gateway"
        );
    }

    #[test]
    fn a_forged_reply_cannot_talk_the_tracker_out_of_the_gateway_it_knows() {
        // The attack this closes. The MAC is learned from ARP replies, which is
        // a channel an attacker controls; if one forged reply could replace it,
        // arp_spoof would treat the attacker as the gateway and go quiet.
        let mut tracker = GatewayTracker::new(None, None);
        let offer = dhcp::parse_frame(&fixtures::dhcp_offer(), "eth0", at(0)).expect("parsed");
        tracker.observe(&offer);
        assert_eq!(tracker.mac(), Some(mac("b8:27:eb:44:55:66")));

        // The attacker answers for the gateway address, repeatedly.
        let mut frame = fixtures::arp_reply();
        frame[6..12].copy_from_slice(&mac("02:de:ad:be:ef:01").octets());
        frame[22..28].copy_from_slice(&mac("02:de:ad:be:ef:01").octets());
        frame[28..32].copy_from_slice(&[192, 168, 1, 1]);
        for n in 0..100 {
            let observation = arp::parse_frame(&frame, "eth0", at(n)).expect("parsed");
            tracker.observe(&observation);
        }
        assert_eq!(
            tracker.mac(),
            Some(mac("b8:27:eb:44:55:66")),
            "the known gateway must survive any amount of forged agreement"
        );
        assert!(!tracker.is_gateway(mac("02:de:ad:be:ef:01")));
    }

    #[test]
    fn stronger_evidence_may_still_replace_a_learned_hardware_address() {
        let mut tracker = GatewayTracker::new(None, None);
        tracker.set_mac(mac("00:11:32:aa:bb:cc"), GatewaySource::Inferred);
        assert_eq!(tracker.mac(), Some(mac("00:11:32:aa:bb:cc")));
        tracker.set_mac(mac("b8:27:eb:44:55:66"), GatewaySource::Configured);
        assert_eq!(tracker.mac(), Some(mac("b8:27:eb:44:55:66")));
        assert_eq!(tracker.mac_source(), GatewaySource::Configured);
    }

    #[test]
    fn the_same_answer_from_stronger_evidence_upgrades_the_source() {
        let mut tracker = GatewayTracker::new(None, None);
        tracker.set_mac(mac("b8:27:eb:44:55:66"), GatewaySource::Inferred);
        assert_eq!(tracker.mac_source(), GatewaySource::Inferred);
        tracker.set_mac(mac("b8:27:eb:44:55:66"), GatewaySource::Dhcp);
        assert_eq!(tracker.mac_source(), GatewaySource::Dhcp);
    }

    #[test]
    fn a_configured_hardware_address_survives_a_renumbering() {
        let mut tracker = GatewayTracker::new(None, Some(mac("b8:27:eb:44:55:66")));
        tracker.set_ip(Ipv4Addr::new(10, 0, 0, 1), GatewaySource::Dhcp);
        assert_eq!(tracker.mac(), Some(mac("b8:27:eb:44:55:66")));
    }
}
