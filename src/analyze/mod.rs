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
                gateway: GatewayTracker::new(config.gateway_ip(), config.gateway_mac()),
                exempt: config.exempt_macs(),
                priority: config.notifications.priority,
                max_tracked: config.max_tracked,
            },
            enabled: config.enabled,
        }
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
}
