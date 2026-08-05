//! Detects a flood of gratuitous ARP announcements from one MAC.
//!
//! A gratuitous ARP is a device saying "this address is mine" without being
//! asked. Devices legitimately send a few: on boot, on waking, after a failover.
//! A device sending them continuously is either broken or is trying to keep a
//! poisoned entry alive in everybody's ARP cache, because a poisoned cache entry
//! expires and has to be refreshed.
//!
//! That is why this is separate from `arp_spoof` rather than folded into it.
//! `arp_spoof` catches the moment an address changes hands; this catches the
//! sustained hammering that keeps it changed, and it fires even when the flooder
//! is announcing an address that is genuinely its own, which is the signature of
//! a failing NIC or a misconfigured failover pair.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::json;

use crate::analyze::window::{BoundedMap, RateWindow};
use crate::analyze::{Analyzer, Context, SecurityAlert, Stimulus, cooled_down};
use crate::config::GratuitousArpConfig;
use crate::types::{EventType, MacAddr};

/// How many timestamps one MAC's window holds. Any value above the threshold
/// works; this only bounds memory.
const WINDOW_CAPACITY: usize = 256;

/// Per-MAC flood state.
#[derive(Debug)]
struct Tracked {
    announcements: RateWindow,
    last_alert: Option<DateTime<Utc>>,
}

/// The gratuitous ARP flood analyzer.
pub struct GratuitousArp {
    window: Duration,
    threshold: usize,
    tracked: BoundedMap<MacAddr, Tracked>,
}

impl GratuitousArp {
    /// Builds the analyzer.
    #[must_use]
    pub fn new(config: &GratuitousArpConfig, max_tracked: usize) -> Self {
        GratuitousArp {
            window: config.window.get(),
            threshold: config.threshold.max(1),
            tracked: BoundedMap::new(max_tracked),
        }
    }
}

impl Analyzer for GratuitousArp {
    fn name(&self) -> &'static str {
        "gratuitous_arp"
    }

    fn analyze(&mut self, stimulus: &Stimulus<'_>, context: &Context) -> Vec<SecurityAlert> {
        let Stimulus::Observed(observation) = stimulus else {
            return Vec::new();
        };
        let Some(arp) = observation.arp() else {
            return Vec::new();
        };
        if !arp.gratuitous {
            return Vec::new();
        }

        let mac = observation.mac;
        let now = observation.observed_at;
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

    /// A gratuitous ARP from `from`.
    fn announcement(from: &str, when: DateTime<Utc>) -> Observation {
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
