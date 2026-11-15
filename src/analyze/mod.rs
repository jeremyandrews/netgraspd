//! The security analyzer chain.
//!
//! Analyzers sit between the capture layer and the device state machine. They
//! consume the same [`Observation`] stream, keep their own small in-memory
//! state, and emit [`SecurityAlert`]s that the state machine turns into events
//! on the existing bus. No schema change was needed for any of it:
//! `ng_events.details` is jsonb.
//!
//! ## Three properties the design turns on
//!
//! **Analyzers see every observation, including the deduplicated ones.** The
//! cross-interface dedup collapses observations keyed on `(MAC, kind, second)`,
//! which is exactly the shape of a scan burst: two hundred ARP requests from one
//! MAC in one second are one observation to the state machine and are the entire
//! signal to `arp_scan`. The daemon therefore feeds the chain before dedup
//! decides anything.
//!
//! **Analyzers are stateless across restarts.** Nothing here is persisted. A
//! restart rebuilds every window from live traffic within a window's length,
//! and a security detector that trusted state written before a crash would be
//! trusting state written by whatever caused it. The one place this costs
//! something is `rogue_dhcp`, whose first-seen-server heuristic re-learns after
//! a restart; `security.rogue_dhcp.known_servers` is how an operator closes
//! that window, and the analyzer says so in its own documentation.
//!
//! **Analyzers know nothing about devices.** They deal in MAC addresses and
//! nothing else, so they need no lock on the device table and no database. The
//! state machine attaches names, vendors and row ids afterwards, in
//! [`crate::device::Manager::security_event`].
//!
//! ## Every analyzer holds itself back
//!
//! Each one has a cooldown, so a condition that persists for an hour produces
//! alerts at a bounded rate rather than one per packet. That is not the
//! notification dispatcher's debounce, which security events deliberately
//! bypass; it is the detector declining to say the same thing twice.

pub mod arp_scan;
pub mod arp_spoof;
pub mod gateway;
pub mod gratuitous_arp;
pub mod identity_change;
pub mod ip_conflict;
pub mod rogue_dhcp;
pub mod window;

use chrono::{DateTime, Utc};
use serde_json::Value as Json;

use crate::config::SecurityConfig;
use crate::device::Reclassification;
use crate::types::{EventPriority, EventType, MacAddr, Observation};

pub use gateway::GatewayTracker;

/// Something an analyzer decided is worth telling somebody about.
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityAlert {
    /// Which kind of finding this is.
    pub event_type: EventType,
    /// The MAC the alert is *about*, which for every analyzer here is the actor
    /// rather than the victim.
    pub mac: MacAddr,
    /// The address involved, when the finding is about one.
    pub ip: Option<String>,
    /// The interface it was seen on.
    pub interface: Option<String>,
    /// When it was decided.
    pub at: DateTime<Utc>,
    /// How loudly to deliver it.
    pub priority: EventPriority,
    /// The evidence, as it will land in `ng_events.details`.
    pub details: Json,
}

impl SecurityAlert {
    /// Builds an alert with no address and no interface.
    #[must_use]
    pub fn new(
        event_type: EventType,
        mac: MacAddr,
        at: DateTime<Utc>,
        priority: EventPriority,
        details: Json,
    ) -> Self {
        SecurityAlert {
            event_type,
            mac,
            ip: None,
            interface: None,
            at,
            priority,
            details,
        }
    }

    /// Attaches an address, builder style.
    #[must_use]
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip = Some(ip.into());
        self
    }

    /// Attaches an interface, builder style.
    #[must_use]
    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = Some(interface.into());
        self
    }
}

/// What an analyzer is being shown.
///
/// Two shapes rather than one, because `identity_change` watches the classifier
/// rather than the wire while every other analyzer watches the wire. Giving them
/// one trait and one chain keeps the enable flags, the cooldowns and the
/// alert-emitting path identical for all six.
#[derive(Debug)]
pub enum Stimulus<'a> {
    /// A packet-derived observation, before deduplication.
    Observed(&'a Observation),
    /// A device the classifier reassessed.
    Reclassified(&'a Reclassification),
}

/// Shared context every analyzer can read.
#[derive(Debug)]
pub struct Context {
    /// What is known about the gateway, which several analyzers treat
    /// differently from everything else.
    pub gateway: GatewayTracker,
    /// MAC addresses no analyzer alerts on.
    pub exempt: Vec<MacAddr>,
    /// How loudly security alerts are delivered.
    pub priority: EventPriority,
    /// Per-analyzer tracking cap.
    pub max_tracked: usize,
}

impl Context {
    /// True when a MAC is exempt from alerting entirely.
    #[must_use]
    pub fn is_exempt(&self, mac: MacAddr) -> bool {
        self.exempt.contains(&mac)
    }
}

/// One detector.
pub trait Analyzer: Send {
    /// Short stable name, used in logs and in alert details.
    fn name(&self) -> &'static str;

    /// Examines one stimulus and returns whatever it found.
    ///
    /// Returning a `Vec` rather than an `Option` because a single packet can
    /// legitimately trip two conditions: an ARP reply claiming the gateway's
    /// address is both a spoof and, if the real gateway is still talking, a
    /// conflict.
    fn analyze(&mut self, stimulus: &Stimulus<'_>, context: &Context) -> Vec<SecurityAlert>;
}

/// The configured chain.
pub struct Chain {
    analyzers: Vec<Box<dyn Analyzer>>,
    context: Context,
    enabled: bool,
}

impl Chain {
    /// Builds the chain the configuration asks for.
    ///
    /// A disabled analyzer is not built at all rather than built and skipped, so
    /// that switching one off also stops it allocating.
    #[must_use]
    pub fn new(config: &SecurityConfig) -> Self {
        let mut analyzers: Vec<Box<dyn Analyzer>> = Vec::with_capacity(6);
        if config.arp_scan.enabled {
            analyzers.push(Box::new(arp_scan::ArpScan::new(
                &config.arp_scan,
                config.max_tracked,
            )));
        }
        if config.arp_spoof.enabled {
            analyzers.push(Box::new(arp_spoof::ArpSpoof::new(
                &config.arp_spoof,
                config.max_tracked,
            )));
        }
        if config.rogue_dhcp.enabled {
            analyzers.push(Box::new(rogue_dhcp::RogueDhcp::new(&config.rogue_dhcp)));
        }
        if config.ip_conflict.enabled {
            analyzers.push(Box::new(ip_conflict::IpConflict::new(
                &config.ip_conflict,
                config.max_tracked,
            )));
        }
        if config.gratuitous_arp.enabled {
            analyzers.push(Box::new(gratuitous_arp::GratuitousArp::new(
                &config.gratuitous_arp,
                config.max_tracked,
            )));
        }
        if config.identity_change.enabled {
            analyzers.push(Box::new(identity_change::IdentityChange::new(
                &config.identity_change,
            )));
        }

        Chain {
            analyzers,
            context: Context {
                gateway: GatewayTracker::new(config.gateway_ip(), config.gateway_mac())
                    .with_proxy_arp(config.proxy_arp_gateway),
                exempt: config.exempt_macs(),
                priority: config.notifications.priority,
                max_tracked: config.max_tracked,
            },
            enabled: config.enabled,
        }
    }

    /// Seeds the gateway belief from the capture host's own default route,
    /// builder style; see [`GatewayTracker::with_default_route`].
    #[must_use]
    pub fn with_default_route(
        mut self,
        route: Option<&gateway::DefaultRoute>,
        captured: &[String],
    ) -> Self {
        self.context.gateway.apply_default_route(route, captured);
        self
    }

    /// Names of the analyzers that are running.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.analyzers.iter().map(|a| a.name()).collect()
    }

    /// True when the chain will do anything at all.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.enabled && !self.analyzers.is_empty()
    }

    /// What the chain currently believes about the gateway.
    #[must_use]
    pub const fn gateway(&self) -> &GatewayTracker {
        &self.context.gateway
    }

    /// Feeds one observation to every analyzer.
    #[must_use]
    pub fn observe(&mut self, observation: &Observation) -> Vec<SecurityAlert> {
        if !self.enabled {
            return Vec::new();
        }
        // The gateway tracker learns before the analyzers run, so a packet that
        // reveals the gateway is already usable by the analyzer reading it.
        self.context.gateway.observe(observation);
        self.run(&Stimulus::Observed(observation))
    }

    /// Feeds one classification change to every analyzer.
    #[must_use]
    pub fn reclassified(&mut self, change: &Reclassification) -> Vec<SecurityAlert> {
        if !self.enabled {
            return Vec::new();
        }
        self.run(&Stimulus::Reclassified(change))
    }

    /// Runs the chain, dropping alerts about exempt MACs.
    fn run(&mut self, stimulus: &Stimulus<'_>) -> Vec<SecurityAlert> {
        let mut alerts = Vec::new();
        for analyzer in &mut self.analyzers {
            alerts.extend(analyzer.analyze(stimulus, &self.context));
        }
        // The exemption is applied here rather than in each analyzer, so that no
        // analyzer can forget it and adding one cannot reintroduce the bug.
        alerts.retain(|alert| {
            let exempt = self.context.is_exempt(alert.mac);
            if exempt {
                tracing::debug!(mac = %alert.mac, event = %alert.event_type, "alert suppressed: exempt MAC");
            }
            !exempt
        });
        alerts
    }
}

/// Whether an alert should be held back because one just fired.
///
/// Every analyzer needs this and every analyzer would otherwise implement it
/// slightly differently. A cooldown of zero always allows.
#[must_use]
pub fn cooled_down(
    last: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    cooldown: std::time::Duration,
) -> bool {
    let Some(last) = last else {
        return true;
    };
    now.signed_duration_since(last)
        .to_std()
        .is_ok_and(|elapsed| elapsed >= cooldown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecurityConfig;
    use chrono::TimeZone;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_770_000_000 + secs, 0)
            .single()
            .expect("valid timestamp")
    }

    #[test]
    fn the_default_configuration_runs_all_six_analyzers() {
        let chain = Chain::new(&SecurityConfig::default());
        let mut names = chain.names();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "arp_scan",
                "arp_spoof",
                "gratuitous_arp",
                "identity_change",
                "ip_conflict",
                "rogue_dhcp"
            ]
        );
        assert!(chain.is_active());
    }

    #[test]
    fn a_disabled_analyzer_is_not_built() {
        let config = SecurityConfig {
            arp_scan: crate::config::ArpScanConfig {
                enabled: false,
                ..crate::config::ArpScanConfig::default()
            },
            ..SecurityConfig::default()
        };
        let chain = Chain::new(&config);
        assert!(!chain.names().contains(&"arp_scan"));
        assert_eq!(chain.names().len(), 5);
    }

    #[test]
    fn the_master_switch_stops_the_whole_chain() {
        let config = SecurityConfig {
            enabled: false,
            ..SecurityConfig::default()
        };
        let mut chain = Chain::new(&config);
        assert!(!chain.is_active());
        let observation = crate::capture::arp::parse_frame(
            &crate::capture::fixtures::arp_request(),
            "eth0",
            at(0),
        )
        .expect("parsed");
        assert!(chain.observe(&observation).is_empty());
    }

    #[test]
    fn every_analyzer_disabled_is_an_inactive_chain() {
        let config = SecurityConfig {
            arp_scan: crate::config::ArpScanConfig {
                enabled: false,
                ..Default::default()
            },
            arp_spoof: crate::config::ArpSpoofConfig {
                enabled: false,
                ..Default::default()
            },
            rogue_dhcp: crate::config::RogueDhcpConfig {
                enabled: false,
                ..Default::default()
            },
            identity_change: crate::config::IdentityChangeConfig {
                enabled: false,
                ..Default::default()
            },
            ip_conflict: crate::config::IpConflictConfig {
                enabled: false,
                ..Default::default()
            },
            gratuitous_arp: crate::config::GratuitousArpConfig {
                enabled: false,
                ..Default::default()
            },
            ..SecurityConfig::default()
        };
        let chain = Chain::new(&config);
        assert!(!chain.is_active());
        assert!(chain.names().is_empty());
    }

    #[test]
    fn a_cooldown_of_zero_never_holds_anything_back() {
        assert!(cooled_down(None, at(0), std::time::Duration::ZERO));
        assert!(cooled_down(
            Some(at(0)),
            at(0),
            std::time::Duration::from_secs(0)
        ));
    }

    #[test]
    fn a_cooldown_holds_until_it_elapses_and_not_after() {
        let cooldown = std::time::Duration::from_secs(30);
        assert!(cooled_down(None, at(0), cooldown), "nothing fired yet");
        assert!(!cooled_down(Some(at(0)), at(29), cooldown));
        assert!(cooled_down(Some(at(0)), at(30), cooldown));
    }

    #[test]
    fn a_clock_that_went_backwards_holds_the_alert_rather_than_releasing_it() {
        // to_std() fails on a negative duration. Treating that as "cooled down"
        // would make a clock step release every held alert at once.
        assert!(!cooled_down(
            Some(at(100)),
            at(0),
            std::time::Duration::from_secs(30)
        ));
    }

    /// The C1 network, as the chain saw it on 2026-11-14: a Routerboard at
    /// 10.20.0.1 that proxy-ARPs, the capture host at 10.20.229.200, and the
    /// ordinary hosts around them.
    mod c1 {
        use super::*;
        use crate::analyze::gateway::DefaultRoute;
        use crate::types::{
            ArpDetail, ArpOp, DhcpDetail, DhcpMessageType, EventType, ObservationKind,
            ProtocolDetail,
        };
        use std::net::{IpAddr, Ipv4Addr};

        pub const ROUTER: &str = "4c:5e:0c:10:20:01";
        pub const STUDIO: &str = "9a:3b:5c:7d:20:c8";
        pub const ROUTER_IP: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 1);
        pub const STUDIO_IP: Ipv4Addr = Ipv4Addr::new(10, 20, 229, 200);
        /// Three ordinary hosts, each with an address of its own.
        pub const HOSTS: [(&str, Ipv4Addr); 3] = [
            ("3c:22:fb:00:00:01", Ipv4Addr::new(10, 20, 1, 10)),
            ("3c:22:fb:00:00:02", Ipv4Addr::new(10, 20, 1, 11)),
            ("3c:22:fb:00:00:03", Ipv4Addr::new(10, 20, 1, 12)),
        ];

        fn mac(s: &str) -> MacAddr {
            s.parse().expect("test mac")
        }

        fn arp(
            op: ArpOp,
            from: &str,
            sender: Ipv4Addr,
            target: Ipv4Addr,
            secs: i64,
        ) -> Observation {
            Observation::new(
                mac(from),
                Some(IpAddr::V4(sender)),
                "en1",
                "arp",
                if op == ArpOp::Request {
                    ObservationKind::Request
                } else {
                    ObservationKind::Reply
                },
                at(secs),
            )
            .with_detail(ProtocolDetail::Arp(ArpDetail {
                op,
                sender_mac: mac(from),
                sender_ip: Some(sender),
                target_ip: target,
                gratuitous: false,
            }))
        }

        /// The sequence, ending with the DHCP Ack that corrected the belief at
        /// minute 8.5.
        pub fn sequence() -> Vec<Observation> {
            let mut out = Vec::new();
            // One host asks for the gateway and the router answers: on a
            // settled network that is about as much as the gateway is asked.
            out.push(arp(ArpOp::Request, HOSTS[0].0, HOSTS[0].1, ROUTER_IP, 0));
            out.push(arp(ArpOp::Reply, ROUTER, ROUTER_IP, HOSTS[0].1, 0));
            // Three hosts ask for the capture host within a second, and it
            // answers for itself.
            for (who, address) in HOSTS {
                out.push(arp(ArpOp::Request, who, address, STUDIO_IP, 1));
            }
            out.push(arp(ArpOp::Reply, STUDIO, STUDIO_IP, HOSTS[0].1, 1));
            // The router proxy-ARPs for the capture host and for two hosts.
            out.push(arp(ArpOp::Reply, ROUTER, STUDIO_IP, HOSTS[2].1, 2));
            out.push(arp(ArpOp::Reply, ROUTER, HOSTS[0].1, HOSTS[2].1, 2));
            out.push(arp(ArpOp::Reply, ROUTER, HOSTS[1].1, HOSTS[2].1, 2));
            // Everybody carries on using their own address.
            out.push(arp(ArpOp::Reply, STUDIO, STUDIO_IP, HOSTS[1].1, 3));
            out.push(arp(ArpOp::Request, HOSTS[0].0, HOSTS[0].1, HOSTS[1].1, 3));
            out.push(arp(ArpOp::Request, HOSTS[1].0, HOSTS[1].1, HOSTS[0].1, 3));
            // A DHCP Ack from the router, carrying option 3.
            out.push(
                Observation::new(
                    mac(ROUTER),
                    Some(IpAddr::V4(ROUTER_IP)),
                    "en1",
                    "dhcp",
                    ObservationKind::Reply,
                    at(510),
                )
                .with_detail(ProtocolDetail::Dhcp(DhcpDetail {
                    message_type: DhcpMessageType::Ack,
                    client_mac: Some(mac(HOSTS[2].0)),
                    assigned_ip: Some(HOSTS[2].1),
                    router: Some(ROUTER_IP),
                })),
            );
            out
        }

        pub fn route() -> DefaultRoute {
            DefaultRoute {
                gateway: ROUTER_IP,
                interface: "en1".to_string(),
            }
        }

        pub fn captured() -> Vec<String> {
            ["en1", "bridge100", "bridge101"]
                .into_iter()
                .map(String::from)
                .collect()
        }

        /// Every `ip_conflict` and `arp_spoof` alert, as (type, MAC, address).
        pub fn address_alerts(chain: &mut Chain) -> Vec<(EventType, String, Option<String>)> {
            let mut alerts = Vec::new();
            for observation in sequence() {
                for alert in chain.observe(&observation) {
                    if matches!(
                        alert.event_type,
                        EventType::IpConflict | EventType::ArpSpoof
                    ) {
                        alerts.push((alert.event_type, alert.mac.to_string(), alert.ip));
                    }
                }
            }
            alerts
        }
    }

    #[test]
    fn with_the_host_route_the_c1_sequence_raises_no_address_alerts() {
        let mut chain = Chain::new(&SecurityConfig::default())
            .with_default_route(Some(&c1::route()), &c1::captured());
        let alerts = c1::address_alerts(&mut chain);
        assert_eq!(alerts, Vec::new(), "no ip_conflict and no arp_spoof");
        assert_eq!(chain.gateway().ip(), Some(c1::ROUTER_IP));
        assert_eq!(
            chain.gateway().mac(),
            Some(c1::ROUTER.parse().expect("mac"))
        );
    }

    /// Characterization, not a goal: with no host route to read, the
    /// popularity fallback still elects the capture host on this sequence, and
    /// the router's proxy replies then read as an impersonation and as
    /// conflicts until something stronger says otherwise. This is what main did
    /// in C1, and it is the path a daemon on an isolated segment still takes.
    #[test]
    fn without_a_host_route_the_c1_sequence_is_what_main_did() {
        let mut chain = Chain::new(&SecurityConfig::default());
        let alerts = c1::address_alerts(&mut chain);
        let router = c1::ROUTER.to_string();
        assert!(
            alerts.contains(&(
                EventType::ArpSpoof,
                router.clone(),
                Some(c1::STUDIO_IP.to_string())
            )),
            "{alerts:?}"
        );
        assert!(
            alerts
                .iter()
                .any(|(kind, mac, _)| *kind == EventType::IpConflict && *mac == router),
            "{alerts:?}"
        );
        // The DHCP Ack at the end corrects the belief, as it did at minute 8.5.
        assert_eq!(chain.gateway().ip(), Some(c1::ROUTER_IP));
    }
}
