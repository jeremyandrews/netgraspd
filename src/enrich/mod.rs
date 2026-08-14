//! Enrichment: facts about a device that passive capture cannot see.
//!
//! Everything else in this daemon works from frames that arrived on their own.
//! An enricher is the one place that asks somebody a question, and what it asks
//! is a controller the operator already runs, never a monitored device. The
//! standing fence holds: `netgraspd` still never sends a packet to anything it
//! is watching.
//!
//! **Why this lives in the daemon and not in the Trovato plugin.** The
//! controller sits on a private address, and the kernel's HTTP host function
//! refuses private addresses under its SSRF policy. A plugin therefore cannot
//! reach it at all, and the daemon can.
//!
//! An enricher that fails does not take the daemon with it. A controller that is
//! rebooting, unreachable, or answering with nonsense produces a logged warning
//! and no enrichments; every device keeps the location it already had, and the
//! next successful poll corrects whatever moved in the meantime.

pub mod unifi;

use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value as Json;
use tokio::time::Instant;

use crate::config::EnrichmentConfig;
use crate::device::DeviceSnapshot;
use crate::types::MacAddr;

/// What an enricher learned about one device.
///
/// Every field but the MAC is optional, because a source that knows the access
/// point and nothing else is still useful and should not have to invent the
/// rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrichment {
    /// Which device this is about.
    pub mac: MacAddr,
    /// The access point it is associated with.
    pub ap_name: Option<String>,
    /// The place, when the source itself knows one. Usually `None`: the
    /// operator's AP-to-room map in [`crate::location`] is what resolves this,
    /// and a source that overrides it had better have a reason.
    pub ap_location: Option<String>,
    /// The VLAN it is on.
    pub vlan: Option<i64>,
    /// Bytes received, as the controller counts them.
    pub bandwidth_rx: Option<i64>,
    /// Bytes transmitted, as the controller counts them.
    pub bandwidth_tx: Option<i64>,
    /// Anything else the source wants to record.
    ///
    /// This rides into `ng_events.details` on a location change rather than into
    /// a column of its own. Adding a `vlan` or `bandwidth_rx` column to
    /// `ng_devices` would be a schema change the Trovato plugin has not seen,
    /// and none of it is worth one: it is per-poll telemetry, not device
    /// identity.
    pub extra: Json,
}

impl Enrichment {
    /// An enrichment about one device with nothing filled in yet.
    #[must_use]
    pub fn new(mac: MacAddr) -> Self {
        Enrichment {
            mac,
            ap_name: None,
            ap_location: None,
            vlan: None,
            bandwidth_rx: None,
            bandwidth_tx: None,
            extra: Json::Null,
        }
    }

    /// True when this carries nothing worth applying.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ap_name.is_none()
            && self.ap_location.is_none()
            && self.vlan.is_none()
            && self.bandwidth_rx.is_none()
            && self.bandwidth_tx.is_none()
            && self.extra.is_null()
    }

    /// The telemetry fields, as they land in a location-change event's details.
    ///
    /// Returns `None` when there is nothing to say, so an event does not carry
    /// an object full of nulls.
    #[must_use]
    pub fn telemetry(&self) -> Option<Json> {
        let mut map = serde_json::Map::new();
        if let Some(vlan) = self.vlan {
            map.insert("vlan".into(), Json::from(vlan));
        }
        if let Some(rx) = self.bandwidth_rx {
            map.insert("bandwidth_rx".into(), Json::from(rx));
        }
        if let Some(tx) = self.bandwidth_tx {
            map.insert("bandwidth_tx".into(), Json::from(tx));
        }
        if !self.extra.is_null() {
            map.insert("extra".into(), self.extra.clone());
        }
        (!map.is_empty()).then_some(Json::Object(map))
    }
}

/// A source of facts that passive capture cannot produce.
#[async_trait]
pub trait Enricher: Send + Sync {
    /// Short stable name, used in logs and in `netgraspd stats`.
    fn name(&self) -> &str;

    /// How often this source should be polled, or `None` for an event-driven
    /// source that pushes instead of being asked.
    fn poll_interval(&self) -> Option<Duration>;

    /// Reads whatever the source knows about the devices given.
    ///
    /// # Errors
    ///
    /// Returns an error when the source is unreachable or answers with something
    /// unusable. The orchestrator logs it and keeps every device's last known
    /// values rather than clearing them.
    async fn enrich(&self, devices: &[DeviceSnapshot]) -> Result<Vec<Enrichment>>;
}

/// One enricher plus when it is next due.
struct Scheduled {
    enricher: Box<dyn Enricher>,
    interval: Duration,
    next_due: Instant,
    polls: u64,
    failures: u64,
}

/// Runs every enabled enricher on its own cadence.
pub struct Orchestrator {
    enrichers: Vec<Scheduled>,
    enabled: bool,
}

/// How often the daemon asks the orchestrator whether anything is due.
///
/// Independent of any enricher's own interval: the orchestrator holds the
/// per-source deadlines and this is only the resolution at which they are
/// noticed.
pub const TICK: Duration = Duration::from_secs(1);

impl Orchestrator {
    /// Builds the orchestrator the configuration asks for.
    ///
    /// A disabled enricher is not built at all rather than built and skipped, so
    /// that switching one off also stops it holding an HTTP client open.
    ///
    /// # Errors
    ///
    /// Returns an error when an enabled enricher cannot be constructed, which
    /// for the UniFi one means a TLS or client-builder failure rather than an
    /// unreachable controller.
    pub fn from_config(cfg: &EnrichmentConfig) -> Result<Self> {
        let mut enrichers: Vec<Box<dyn Enricher>> = Vec::new();
        if cfg.unifi.enabled {
            enrichers.push(Box::new(unifi::UnifiEnricher::new(&cfg.unifi)?));
        }
        Ok(Orchestrator::with_enrichers(cfg.enabled, enrichers))
    }

    /// Builds an orchestrator over an explicit set of enrichers, for tests and
    /// for any caller that builds its own.
    #[must_use]
    pub fn with_enrichers(enabled: bool, enrichers: Vec<Box<dyn Enricher>>) -> Self {
        let now = Instant::now();
        let enrichers = enrichers
            .into_iter()
            .map(|enricher| {
                let interval = enricher
                    .poll_interval()
                    // A source with no interval is event driven and is not
                    // polled at all; parking it a long way out costs nothing and
                    // keeps the schedule uniform.
                    .unwrap_or(Duration::from_secs(u64::from(u32::MAX)));
                Scheduled {
                    enricher,
                    interval,
                    // Due immediately, so a fresh start places every device
                    // rather than waiting out a poll interval first.
                    next_due: now,
                    polls: 0,
                    failures: 0,
                }
            })
            .collect();
        Orchestrator { enrichers, enabled }
    }

    /// True when the orchestrator will do anything at all.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.enabled && !self.enrichers.is_empty()
    }

    /// Names of the enrichers that are running.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.enrichers.iter().map(|s| s.enricher.name()).collect()
    }

    /// How many polls each enricher has made, and how many of those failed.
    #[must_use]
    pub fn counters(&self) -> Vec<(&str, u64, u64)> {
        self.enrichers
            .iter()
            .map(|s| (s.enricher.name(), s.polls, s.failures))
            .collect()
    }

    /// Polls every enricher whose interval has elapsed.
    ///
    /// Enrichers run one after another rather than concurrently. There are one
    /// or two of them, each talking to a controller on the same LAN, and running
    /// them in sequence keeps a slow one from being masked by a fast one in the
    /// logs.
    pub async fn poll_due(&mut self, now: Instant, devices: &[DeviceSnapshot]) -> Vec<Enrichment> {
        if !self.enabled {
            return Vec::new();
        }
        let mut out = Vec::new();
        for scheduled in &mut self.enrichers {
            if now < scheduled.next_due {
                continue;
            }
            scheduled.polls += 1;
            let started = Instant::now();
            let result = scheduled.enricher.enrich(devices).await;
            // Scheduled from when the poll *finished*, not from when it started.
            // An unreachable controller takes the full request timeout twice
            // over while the client works out which API shape it is talking to,
            // which is comfortably longer than the poll interval; measuring from
            // the start would leave the next attempt already overdue and run
            // failing polls back to back forever.
            //
            // The elapsed time is measured against the real clock and added to
            // the caller's, so the caller's clock stays the authority on when
            // "now" is and a test can still drive this with a synthetic one.
            scheduled.next_due = now + started.elapsed() + scheduled.interval;
            match result {
                Ok(enrichments) => {
                    tracing::debug!(
                        enricher = scheduled.enricher.name(),
                        found = enrichments.len(),
                        "enrichment poll succeeded"
                    );
                    out.extend(enrichments.into_iter().filter(|e| !e.is_empty()));
                }
                Err(err) => {
                    scheduled.failures += 1;
                    // Deliberately not fatal, and deliberately not a reason to
                    // clear anything: a controller that is rebooting must not
                    // make every device's location vanish.
                    tracing::warn!(
                        enricher = scheduled.enricher.name(),
                        failures = scheduled.failures,
                        %err,
                        "enrichment poll failed; keeping the last known values"
                    );
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UnifiConfig;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn mac(s: &str) -> MacAddr {
        s.parse().expect("test mac")
    }

    /// An enricher that answers from a script and counts its calls.
    struct Scripted {
        name: &'static str,
        interval: Option<Duration>,
        calls: AtomicUsize,
        answers: Mutex<Vec<Result<Vec<Enrichment>, String>>>,
    }

    impl Scripted {
        fn new(name: &'static str, interval: Option<Duration>) -> Self {
            Scripted {
                name,
                interval,
                calls: AtomicUsize::new(0),
                answers: Mutex::new(Vec::new()),
            }
        }

        fn from_script(
            name: &'static str,
            interval: Option<Duration>,
            answers: Vec<Result<Vec<Enrichment>, String>>,
        ) -> Self {
            let s = Scripted::new(name, interval);
            *s.answers.lock().expect("answers") = answers;
            s
        }
    }

    #[async_trait]
    impl Enricher for Scripted {
        fn name(&self) -> &str {
            self.name
        }

        fn poll_interval(&self) -> Option<Duration> {
            self.interval
        }

        async fn enrich(&self, _devices: &[DeviceSnapshot]) -> Result<Vec<Enrichment>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut answers = self.answers.lock().expect("answers");
            if answers.is_empty() {
                return Ok(Vec::new());
            }
            match answers.remove(0) {
                Ok(v) => Ok(v),
                Err(message) => anyhow::bail!(message),
            }
        }
    }

    fn placed(m: &str, ap: &str) -> Enrichment {
        Enrichment {
            ap_name: Some(ap.into()),
            ..Enrichment::new(mac(m))
        }
    }

    #[tokio::test]
    async fn a_due_enricher_is_polled_and_its_results_come_back() {
        let scripted = Scripted::from_script(
            "scripted",
            Some(Duration::from_secs(30)),
            vec![Ok(vec![placed("3c:22:fb:00:00:01", "Kitchen AP")])],
        );
        let mut o = Orchestrator::with_enrichers(true, vec![Box::new(scripted)]);
        assert!(o.is_active());
        let out = o.poll_due(Instant::now(), &[]).await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ap_name.as_deref(), Some("Kitchen AP"));
    }

    #[tokio::test]
    async fn an_enricher_is_not_polled_again_until_its_interval_elapses() {
        let scripted =
            std::sync::Arc::new(Scripted::new("scripted", Some(Duration::from_secs(30))));
        struct Shared(std::sync::Arc<Scripted>);
        #[async_trait]
        impl Enricher for Shared {
            fn name(&self) -> &str {
                self.0.name()
            }
            fn poll_interval(&self) -> Option<Duration> {
                self.0.poll_interval()
            }
            async fn enrich(&self, devices: &[DeviceSnapshot]) -> Result<Vec<Enrichment>> {
                self.0.enrich(devices).await
            }
        }

        let mut o = Orchestrator::with_enrichers(true, vec![Box::new(Shared(scripted.clone()))]);
        let start = Instant::now();
        let _ = o.poll_due(start, &[]).await;
        assert_eq!(scripted.calls.load(Ordering::SeqCst), 1);

        let _ = o.poll_due(start + Duration::from_secs(29), &[]).await;
        assert_eq!(scripted.calls.load(Ordering::SeqCst), 1, "not due yet");

        // A second past the interval rather than exactly on it: the next
        // deadline is the interval plus however long the poll itself took, and
        // asserting to the microsecond would be asserting the speed of the test
        // machine.
        let _ = o.poll_due(start + Duration::from_secs(31), &[]).await;
        assert_eq!(scripted.calls.load(Ordering::SeqCst), 2, "due now");
    }

    #[tokio::test]
    async fn a_failing_enricher_yields_nothing_and_does_not_stop_the_others() {
        // The whole point: a controller that is rebooting must not take the
        // daemon with it, and must not clear anything either.
        let failing = Scripted::from_script(
            "failing",
            Some(Duration::from_secs(30)),
            vec![Err("controller unreachable".into())],
        );
        let working = Scripted::from_script(
            "working",
            Some(Duration::from_secs(30)),
            vec![Ok(vec![placed("3c:22:fb:00:00:02", "Garage AP")])],
        );
        let mut o = Orchestrator::with_enrichers(true, vec![Box::new(failing), Box::new(working)]);
        let out = o.poll_due(Instant::now(), &[]).await;
        assert_eq!(out.len(), 1, "the working enricher still reported");
        assert_eq!(out[0].ap_name.as_deref(), Some("Garage AP"));

        let counters = o.counters();
        assert_eq!(counters[0], ("failing", 1, 1));
        assert_eq!(counters[1], ("working", 1, 0));
    }

    #[tokio::test]
    async fn a_failure_does_not_stop_the_next_poll_from_happening() {
        let scripted = Scripted::from_script(
            "flaky",
            Some(Duration::from_secs(30)),
            vec![
                Err("down".into()),
                Ok(vec![placed("3c:22:fb:00:00:03", "Kitchen AP")]),
            ],
        );
        let mut o = Orchestrator::with_enrichers(true, vec![Box::new(scripted)]);
        let start = Instant::now();
        assert!(o.poll_due(start, &[]).await.is_empty());
        let out = o.poll_due(start + Duration::from_secs(31), &[]).await;
        assert_eq!(out.len(), 1, "it recovers on the next interval");
    }

    #[tokio::test]
    async fn a_poll_that_takes_longer_than_the_interval_does_not_run_back_to_back() {
        // Regression, found by running the daemon against an unreachable
        // controller. A poll that outlasts its own interval left the next
        // attempt already overdue, so failing polls ran continuously; combined
        // with a biased select loop that starved the arms after it, the
        // maintenance and status ticks stopped firing entirely.
        struct Slow;
        #[async_trait]
        impl Enricher for Slow {
            fn name(&self) -> &str {
                "slow"
            }
            fn poll_interval(&self) -> Option<Duration> {
                Some(Duration::from_secs(5))
            }
            async fn enrich(&self, _devices: &[DeviceSnapshot]) -> Result<Vec<Enrichment>> {
                tokio::time::sleep(Duration::from_millis(120)).await;
                Ok(Vec::new())
            }
        }

        let mut o = Orchestrator::with_enrichers(true, vec![Box::new(Slow)]);
        let start = Instant::now();
        let _ = o.poll_due(start, &[]).await;
        assert_eq!(o.counters()[0].1, 1);

        // The poll took 120ms, so the next one is due 5s after it finished and
        // not 5s after it started.
        let _ = o.poll_due(start + Duration::from_millis(5_100), &[]).await;
        assert_eq!(o.counters()[0].1, 1, "still inside the interval");

        let _ = o.poll_due(start + Duration::from_millis(5_300), &[]).await;
        assert_eq!(o.counters()[0].1, 2);
    }

    #[tokio::test]
    async fn the_master_switch_stops_every_enricher() {
        let scripted = Scripted::from_script(
            "scripted",
            Some(Duration::from_secs(30)),
            vec![Ok(vec![placed("3c:22:fb:00:00:01", "Kitchen AP")])],
        );
        let mut o = Orchestrator::with_enrichers(false, vec![Box::new(scripted)]);
        assert!(!o.is_active());
        assert!(o.poll_due(Instant::now(), &[]).await.is_empty());
    }

    #[tokio::test]
    async fn an_empty_enrichment_is_dropped_rather_than_applied() {
        let scripted = Scripted::from_script(
            "scripted",
            Some(Duration::from_secs(30)),
            vec![Ok(vec![Enrichment::new(mac("3c:22:fb:00:00:01"))])],
        );
        let mut o = Orchestrator::with_enrichers(true, vec![Box::new(scripted)]);
        assert!(o.poll_due(Instant::now(), &[]).await.is_empty());
    }

    #[test]
    fn no_enrichers_configured_is_an_inactive_orchestrator() {
        let o = Orchestrator::with_enrichers(true, Vec::new());
        assert!(!o.is_active());
        assert!(o.names().is_empty());
    }

    #[test]
    fn the_default_configuration_builds_nothing() {
        let o = Orchestrator::from_config(&EnrichmentConfig::default()).expect("builds");
        assert!(!o.is_active(), "nothing reaches the network out of the box");
    }

    #[test]
    fn an_enabled_unifi_enricher_is_built() {
        let cfg = EnrichmentConfig {
            enabled: true,
            unifi: UnifiConfig {
                enabled: true,
                controller_url: "https://192.168.1.1".into(),
                api_key: "secret".into(),
                ..UnifiConfig::default()
            },
        };
        let o = Orchestrator::from_config(&cfg).expect("builds");
        assert_eq!(o.names(), vec!["unifi"]);
        assert!(o.is_active());
    }

    #[test]
    fn telemetry_is_absent_when_there_is_nothing_to_say() {
        assert!(
            Enrichment::new(mac("3c:22:fb:00:00:01"))
                .telemetry()
                .is_none()
        );
        assert!(
            placed("3c:22:fb:00:00:01", "Kitchen AP")
                .telemetry()
                .is_none()
        );
    }

    #[test]
    fn telemetry_carries_exactly_the_fields_that_were_set() {
        let e = Enrichment {
            vlan: Some(20),
            bandwidth_rx: Some(4096),
            ..placed("3c:22:fb:00:00:01", "Kitchen AP")
        };
        let telemetry = e.telemetry().expect("some telemetry");
        assert_eq!(telemetry["vlan"], 20);
        assert_eq!(telemetry["bandwidth_rx"], 4096);
        assert!(telemetry.get("bandwidth_tx").is_none());
    }

    #[test]
    fn an_enrichment_with_only_an_ap_is_not_empty() {
        assert!(Enrichment::new(mac("3c:22:fb:00:00:01")).is_empty());
        assert!(!placed("3c:22:fb:00:00:01", "Kitchen AP").is_empty());
    }
}
