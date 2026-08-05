//! Detects a DHCP server that should not be there.
//!
//! Only a server sends an Offer, an Ack or a Nak. A client that sends one is not
//! a client, and on a home network there is exactly one machine allowed to do
//! it. A second is either somebody's router plugged into the wrong port, which
//! breaks the network, or somebody's laptop handing out a poisoned default
//! gateway, which is worse.
//!
//! ## The restart window, stated plainly
//!
//! With `known_servers` empty the analyzer trusts the first server it hears
//! after startup. That is right on a healthy network and wrong on one where a
//! rogue is already answering when the daemon starts: whichever server answers
//! the next Discover becomes the legitimate one, and it might be the rogue.
//!
//! This is a deliberate trade, not an oversight. The alternative is persisting
//! the learned server, and a security detector that trusts state written before
//! a crash is trusting state written by whatever caused it. Listing the real
//! server in `security.rogue_dhcp.known_servers` closes the window completely,
//! and the analyzer says so in its own log line the first time it learns one.

use chrono::{DateTime, Utc};
use serde_json::json;

use crate::analyze::{Analyzer, Context, SecurityAlert, Stimulus, cooled_down};
use crate::config::RogueDhcpConfig;
use crate::types::{EventType, MacAddr};

/// How long after alerting about one rogue server before alerting about it
/// again. A rogue answering every Discover would otherwise alert per packet.
const COOLDOWN: std::time::Duration = std::time::Duration::from_secs(300);

/// How many rogue servers are tracked for cooldown purposes. More than a
/// handful means something very unusual is happening and the alerts have
/// already fired.
const MAX_ROGUES: usize = 32;

/// The `rogue_dhcp` analyzer.
pub struct RogueDhcp {
    /// Servers the operator declared legitimate. When non-empty, nothing is
    /// learned: the list is the whole truth.
    configured: Vec<MacAddr>,
    /// The server learned from traffic, when nothing was configured.
    learned: Option<MacAddr>,
    /// When each rogue was last alerted about.
    alerted: Vec<(MacAddr, DateTime<Utc>)>,
}

impl RogueDhcp {
    /// Builds the analyzer.
    #[must_use]
    pub fn new(config: &RogueDhcpConfig) -> Self {
        RogueDhcp {
            configured: config
                .known_servers
                .iter()
                .filter_map(|m| m.trim().parse().ok())
                .collect(),
            learned: None,
            alerted: Vec::new(),
        }
    }

    /// True when this MAC is allowed to answer DHCP.
    fn is_legitimate(&self, mac: MacAddr) -> bool {
        if self.configured.is_empty() {
            self.learned == Some(mac)
        } else {
            self.configured.contains(&mac)
        }
    }

    /// When this rogue was last alerted about.
    fn last_alert(&self, mac: MacAddr) -> Option<DateTime<Utc>> {
        self.alerted
            .iter()
            .find(|(m, _)| *m == mac)
            .map(|(_, at)| *at)
    }

    /// Records that a rogue was alerted about.
    fn record_alert(&mut self, mac: MacAddr, at: DateTime<Utc>) {
        if let Some(slot) = self.alerted.iter_mut().find(|(m, _)| *m == mac) {
            slot.1 = at;
            return;
        }
        if self.alerted.len() >= MAX_ROGUES {
            self.alerted.remove(0);
        }
        self.alerted.push((mac, at));
    }
}

impl Analyzer for RogueDhcp {
    fn name(&self) -> &'static str {
        "rogue_dhcp"
    }

    fn analyze(&mut self, stimulus: &Stimulus<'_>, context: &Context) -> Vec<SecurityAlert> {
        let Stimulus::Observed(observation) = stimulus else {
            return Vec::new();
        };
        let Some(dhcp) = observation.dhcp() else {
            return Vec::new();
        };
        if !dhcp.message_type.is_server_message() {
            return Vec::new();
        }

        let mac = observation.mac;
        let now = observation.observed_at;

        if self.is_legitimate(mac) {
            return Vec::new();
        }

        // Nothing configured and nothing learned: this is the first server
        // heard, and it becomes the reference point.
        if self.configured.is_empty() && self.learned.is_none() {
            tracing::info!(
                %mac,
                "learned the DHCP server from traffic; set security.rogue_dhcp.known_servers \
                 to close the window where a rogue running before startup is trusted instead"
            );
            self.learned = Some(mac);
            return Vec::new();
        }

        if !cooled_down(self.last_alert(mac), now, COOLDOWN) {
            return Vec::new();
        }
        self.record_alert(mac, now);

        let expected = if self.configured.is_empty() {
            self.learned.map(|m| m.to_string()).unwrap_or_default()
        } else {
            self.configured
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };

        let mut alert = SecurityAlert::new(
            EventType::RogueDhcp,
            mac,
            now,
            context.priority,
            json!({
                "analyzer": "rogue_dhcp",
                "message_type": dhcp.message_type.as_str(),
                "expected_server": expected,
                "server_source": if self.configured.is_empty() { "learned" } else { "configured" },
                "offered_ip": dhcp.assigned_ip.map(|ip| ip.to_string()),
                "offered_router": dhcp.router.map(|ip| ip.to_string()),
                "client_mac": dhcp.client_mac.map(|m| m.to_string()),
            }),
        )
        .with_interface(observation.interface.clone());
        if let Some(ip) = observation.ip {
            alert = alert.with_ip(ip.to_string());
        }
        vec![alert]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::GatewayTracker;
    use crate::capture::{dhcp, fixtures};
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

    /// A DHCP Offer sent by `from`.
    fn offer(from: &str, when: DateTime<Utc>) -> Observation {
        let mut frame = fixtures::dhcp_offer();
        frame[6..12].copy_from_slice(&mac(from).octets());
        dhcp::parse_frame(&frame, "eth0", when).expect("parsed")
    }

    /// A DHCP Discover, which a client sends and which is never a rogue.
    fn discover(when: DateTime<Utc>) -> Observation {
        dhcp::parse_frame(&fixtures::dhcp_discover(), "eth0", when).expect("parsed")
    }

    fn config() -> RogueDhcpConfig {
        RogueDhcpConfig {
            enabled: true,
            known_servers: Vec::new(),
        }
    }

    #[test]
    fn the_first_server_heard_becomes_the_reference() {
        let mut analyzer = RogueDhcp::new(&config());
        let context = context();
        assert!(
            analyzer
                .analyze(
                    &Stimulus::Observed(&offer("b8:27:eb:44:55:66", at(0))),
                    &context
                )
                .is_empty()
        );
        assert_eq!(analyzer.learned, Some(mac("b8:27:eb:44:55:66")));
    }

    #[test]
    fn the_real_server_answering_forever_never_alerts() {
        let mut analyzer = RogueDhcp::new(&config());
        let context = context();
        for n in 0..1000 {
            assert!(
                analyzer
                    .analyze(
                        &Stimulus::Observed(&offer("b8:27:eb:44:55:66", at(n))),
                        &context
                    )
                    .is_empty()
            );
        }
    }

    #[test]
    fn a_second_server_fires() {
        let mut analyzer = RogueDhcp::new(&config());
        let context = context();
        let _ = analyzer.analyze(
            &Stimulus::Observed(&offer("b8:27:eb:44:55:66", at(0))),
            &context,
        );
        let alerts = analyzer.analyze(
            &Stimulus::Observed(&offer("00:11:32:aa:bb:cc", at(10))),
            &context,
        );
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].event_type, EventType::RogueDhcp);
        assert_eq!(alerts[0].mac, mac("00:11:32:aa:bb:cc"));
        assert_eq!(alerts[0].details["message_type"], "offer");
        assert_eq!(alerts[0].details["expected_server"], "b8:27:eb:44:55:66");
        assert_eq!(alerts[0].details["server_source"], "learned");
        assert_eq!(alerts[0].details["offered_router"], "192.168.1.1");
    }

    #[test]
    fn a_configured_list_needs_no_learning_and_closes_the_restart_window() {
        let mut analyzer = RogueDhcp::new(&RogueDhcpConfig {
            enabled: true,
            known_servers: vec!["b8:27:eb:44:55:66".into()],
        });
        let context = context();
        // The rogue speaks first. With nothing configured it would be trusted.
        let alerts = analyzer.analyze(
            &Stimulus::Observed(&offer("00:11:32:aa:bb:cc", at(0))),
            &context,
        );
        assert_eq!(alerts.len(), 1, "a configured list is the whole truth");
        assert_eq!(alerts[0].details["server_source"], "configured");
        // And the real one still passes.
        assert!(
            analyzer
                .analyze(
                    &Stimulus::Observed(&offer("b8:27:eb:44:55:66", at(10))),
                    &context
                )
                .is_empty()
        );
    }

    #[test]
    fn a_client_message_is_never_a_rogue_server() {
        let mut analyzer = RogueDhcp::new(&config());
        let context = context();
        for n in 0..100 {
            assert!(
                analyzer
                    .analyze(&Stimulus::Observed(&discover(at(n))), &context)
                    .is_empty()
            );
        }
        assert_eq!(analyzer.learned, None, "a Discover is not a server");
    }

    #[test]
    fn a_rogue_answering_every_discover_alerts_at_a_bounded_rate() {
        let mut analyzer = RogueDhcp::new(&config());
        let context = context();
        let _ = analyzer.analyze(
            &Stimulus::Observed(&offer("b8:27:eb:44:55:66", at(0))),
            &context,
        );
        let mut alerts = Vec::new();
        for second in 1..3600i64 {
            alerts.extend(analyzer.analyze(
                &Stimulus::Observed(&offer("00:11:32:aa:bb:cc", at(second))),
                &context,
            ));
        }
        assert!(
            (10..=15).contains(&alerts.len()),
            "one hour at a 300s cooldown, got {}",
            alerts.len()
        );
    }

    #[test]
    fn two_different_rogues_are_two_different_alerts() {
        let mut analyzer = RogueDhcp::new(&config());
        let context = context();
        let _ = analyzer.analyze(
            &Stimulus::Observed(&offer("b8:27:eb:44:55:66", at(0))),
            &context,
        );
        let mut alerts = Vec::new();
        alerts.extend(analyzer.analyze(
            &Stimulus::Observed(&offer("00:11:32:aa:bb:cc", at(1))),
            &context,
        ));
        alerts.extend(analyzer.analyze(
            &Stimulus::Observed(&offer("3c:2a:f4:11:22:33", at(2))),
            &context,
        ));
        assert_eq!(alerts.len(), 2, "the cooldown is per rogue, not global");
    }

    #[test]
    fn the_rogue_cooldown_list_is_bounded() {
        let mut analyzer = RogueDhcp::new(&RogueDhcpConfig {
            enabled: true,
            known_servers: vec!["b8:27:eb:44:55:66".into()],
        });
        let context = context();
        for n in 0..500u32 {
            let source = format!(
                "02:00:{:02x}:{:02x}:{:02x}:{:02x}",
                n >> 24,
                (n >> 16) & 0xff,
                (n >> 8) & 0xff,
                n & 0xff
            );
            let _ = analyzer.analyze(&Stimulus::Observed(&offer(&source, at(0))), &context);
        }
        assert!(analyzer.alerted.len() <= MAX_ROGUES);
    }

    #[test]
    fn an_unparseable_configured_server_is_dropped_rather_than_trusted() {
        // config.validate() rejects these before startup; this is the second
        // line of defence, and it must not turn a typo into an allow-all.
        let analyzer = RogueDhcp::new(&RogueDhcpConfig {
            enabled: true,
            known_servers: vec!["not-a-mac".into(), "b8:27:eb:44:55:66".into()],
        });
        assert_eq!(analyzer.configured, vec![mac("b8:27:eb:44:55:66")]);
    }
}
