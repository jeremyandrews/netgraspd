//! Notification delivery.
//!
//! **All rate limiting lives in [`Dispatcher`], never in a [`Notifier`].** A
//! notifier's only job is to put one message somewhere; deciding whether a
//! message should exist at all is policy, and policy that lives in each
//! transport gets implemented three different ways.
//!
//! The dispatcher applies, in order:
//!
//! 1. The master switch, the per-device `notify` toggle, and learning-window
//!    suppression (via [`DeviceEvent::deliverable`]).
//! 2. The configured event-type allowlist.
//! 3. Quiet hours.
//! 4. Per-device debounce.
//! 5. Batching: events are held for `batch_window`, and a window that
//!    accumulated at least `batch_threshold` of them collapses into one summary
//!    instead of a storm. This is what makes a network restart one notification.
//!
//! The batch window costs up to `batch_window` of latency on every
//! notification. That is the deliberate trade: it is still far faster than the
//! plugin's cron cadence, and a user who wants instant alerts sets
//! `batch_window` low or sets `batch_threshold` to zero to disable batching
//! entirely.

pub mod ntfy;

use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, FixedOffset, Timelike, Utc};

use crate::config::NotifyConfig;
use crate::device::DeviceEvent;
use crate::device::persist::RecordedEvent;
use crate::types::MacAddr;

/// Somewhere a notification can be sent.
#[async_trait]
pub trait Notifier: Send + Sync {
    /// Short stable name, used in logs.
    fn name(&self) -> &str;

    /// Sends one event.
    ///
    /// # Errors
    ///
    /// Returns an error when delivery fails. The dispatcher logs and continues:
    /// a notifier being down must never stall the observation pipeline.
    async fn send(&self, event: &DeviceEvent) -> Result<()>;

    /// Sends a collapsed summary of several events.
    ///
    /// The default implementation sends each event separately, which is correct
    /// but defeats the point of batching; a transport that can express a summary
    /// should override it.
    ///
    /// # Errors
    ///
    /// Returns an error when delivery fails.
    async fn send_batch(&self, events: &[DeviceEvent]) -> Result<()> {
        for event in events {
            self.send(event).await?;
        }
        Ok(())
    }

    /// Whether this transport understands priority levels.
    fn supports_priority(&self) -> bool {
        false
    }
}

/// What the dispatcher decided to deliver.
#[derive(Debug, Clone, PartialEq)]
pub enum Delivery {
    /// One event, sent on its own.
    Single(Box<RecordedEvent>),
    /// Several events collapsed into one summary message.
    Summary(Vec<RecordedEvent>),
}

impl Delivery {
    /// The events this delivery covers, so the caller can mark them notified.
    #[must_use]
    pub fn events(&self) -> Vec<&RecordedEvent> {
        match self {
            Delivery::Single(e) => vec![e],
            Delivery::Summary(events) => events.iter().collect(),
        }
    }
}

/// Why an event was not delivered. Counted so that "why did I not get an alert"
/// has an answer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SuppressionCounts {
    /// Notifications are switched off entirely.
    pub disabled: usize,
    /// The device's `notify` flag is off, or a learning window was in progress.
    pub not_deliverable: usize,
    /// The event type is not in the configured allowlist.
    pub wrong_type: usize,
    /// Quiet hours were in effect.
    pub quiet_hours: usize,
    /// Another notification about the same device was too recent.
    pub debounced: usize,
}

impl SuppressionCounts {
    /// Total suppressed.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.disabled + self.not_deliverable + self.wrong_type + self.quiet_hours + self.debounced
    }
}

/// Decides what gets delivered and when.
///
/// Pure and synchronous: it takes events and a clock reading and returns
/// deliveries. Every rule above is therefore a plain test.
pub struct Dispatcher {
    config: NotifyConfig,
    offset: FixedOffset,
    last_accepted: HashMap<MacAddr, DateTime<Utc>>,
    pending: Vec<RecordedEvent>,
    window_opened_at: Option<DateTime<Utc>>,
    suppressed: SuppressionCounts,
}

impl Dispatcher {
    /// Builds a dispatcher.
    ///
    /// `offset` is the local UTC offset used to evaluate quiet hours; taking it
    /// as a parameter rather than reading the system clock is what makes quiet
    /// hours testable.
    #[must_use]
    pub fn new(config: NotifyConfig, offset: FixedOffset) -> Self {
        Dispatcher {
            config,
            offset,
            last_accepted: HashMap::new(),
            pending: Vec::new(),
            window_opened_at: None,
            suppressed: SuppressionCounts::default(),
        }
    }

    /// Builds a dispatcher using the machine's current UTC offset.
    #[must_use]
    pub fn with_local_offset(config: NotifyConfig) -> Self {
        let offset = *chrono::Local::now().offset();
        Dispatcher::new(config, offset)
    }

    /// Counts of everything suppressed so far.
    #[must_use]
    pub const fn suppressed(&self) -> SuppressionCounts {
        self.suppressed
    }

    /// How many events are waiting for the batch window to close.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Offers an event for delivery.
    ///
    /// Returns any deliveries that became due as a result, which is usually none
    /// because the batch window has to close first.
    #[must_use]
    pub fn offer(&mut self, event: RecordedEvent, now: DateTime<Utc>) -> Vec<Delivery> {
        if !self.config.enabled {
            self.suppressed.disabled += 1;
            return self.tick(now);
        }
        if !event.event.deliverable() {
            self.suppressed.not_deliverable += 1;
            return self.tick(now);
        }
        if !self
            .config
            .event_types
            .iter()
            .any(|t| t == event.event.event_type.as_str())
        {
            self.suppressed.wrong_type += 1;
            return self.tick(now);
        }
        if self.in_quiet_hours(now) {
            self.suppressed.quiet_hours += 1;
            return self.tick(now);
        }
        if let Some(previous) = self.last_accepted.get(&event.event.mac)
            && now
                .signed_duration_since(*previous)
                .to_std()
                .unwrap_or_default()
                < self.config.debounce.get()
        {
            self.suppressed.debounced += 1;
            return self.tick(now);
        }

        self.last_accepted.insert(event.event.mac, now);
        self.pending.push(event);
        self.window_opened_at.get_or_insert(now);
        self.tick(now)
    }

    /// Closes the batch window if it has elapsed, returning what is due.
    ///
    /// Call this on a timer as well as after every offer, otherwise a single
    /// event arriving on a quiet network would wait for the next one.
    #[must_use]
    pub fn tick(&mut self, now: DateTime<Utc>) -> Vec<Delivery> {
        let Some(opened) = self.window_opened_at else {
            return Vec::new();
        };
        let elapsed = now
            .signed_duration_since(opened)
            .to_std()
            .unwrap_or_default();
        if elapsed < self.config.batch_window.get() {
            return Vec::new();
        }
        self.drain()
    }

    /// Delivers everything pending immediately, regardless of the window. Used
    /// at shutdown so that a held notification is not simply lost.
    #[must_use]
    pub fn drain(&mut self) -> Vec<Delivery> {
        self.window_opened_at = None;
        let pending = std::mem::take(&mut self.pending);
        if pending.is_empty() {
            return Vec::new();
        }
        if self.config.batch_threshold > 0 && pending.len() >= self.config.batch_threshold {
            vec![Delivery::Summary(pending)]
        } else {
            pending
                .into_iter()
                .map(|e| Delivery::Single(Box::new(e)))
                .collect()
        }
    }

    /// Whether the given instant falls inside the configured quiet period.
    #[must_use]
    pub fn in_quiet_hours(&self, now: DateTime<Utc>) -> bool {
        let Some(quiet) = self.config.quiet_hours else {
            return false;
        };
        let local = now.with_timezone(&self.offset);
        quiet.contains(local.hour() * 60 + local.minute())
    }
}

/// Sends a delivery through a notifier, logging rather than propagating a
/// transport failure.
///
/// Returns true when delivery succeeded. A notifier being unreachable is an
/// operational problem, not a reason to stop watching the network.
pub async fn deliver(notifier: &dyn Notifier, delivery: &Delivery) -> bool {
    let result = match delivery {
        Delivery::Single(event) => notifier.send(&event.event).await,
        Delivery::Summary(events) => {
            let payload: Vec<DeviceEvent> = events.iter().map(|e| e.event.clone()).collect();
            notifier.send_batch(&payload).await
        }
    };
    match result {
        Ok(()) => true,
        Err(err) => {
            tracing::warn!(notifier = notifier.name(), %err, "notification delivery failed");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClockTime, HumanDuration, QuietHours};
    use crate::types::EventType;
    use chrono::TimeZone;
    use std::sync::Mutex;

    fn utc() -> FixedOffset {
        FixedOffset::east_opt(0).expect("utc offset")
    }

    fn base() -> DateTime<Utc> {
        // 2026-02-02T12:00:00Z, a time comfortably outside any quiet window used
        // in these tests.
        Utc.with_ymd_and_hms(2026, 2, 2, 12, 0, 0)
            .single()
            .expect("valid time")
    }

    fn at(secs: i64) -> DateTime<Utc> {
        base() + chrono::Duration::seconds(secs)
    }

    fn config() -> NotifyConfig {
        NotifyConfig {
            enabled: true,
            debounce: HumanDuration::from_secs(300),
            batch_threshold: 10,
            batch_window: HumanDuration::from_secs(60),
            event_types: vec!["new_device".into(), "returned".into()],
            quiet_hours: None,
            ntfy: None,
        }
    }

    fn event(id: i64, mac: &str, kind: EventType) -> RecordedEvent {
        RecordedEvent {
            id,
            event: DeviceEvent {
                event_type: kind,
                mac: mac.parse().expect("mac"),
                display_name: format!("device {id}"),
                vendor: Some("Apple, Inc.".into()),
                ip: Some("192.168.1.40".into()),
                interface: Some("eth0".into()),
                at: base(),
                baseline: false,
                during_learning: false,
                notify: true,
                details: serde_json::Value::Null,
            },
        }
    }

    fn mac_of(n: u8) -> String {
        format!("3c:22:fb:00:00:{n:02x}")
    }

    #[test]
    fn one_event_is_delivered_when_its_window_closes() {
        let mut d = Dispatcher::new(config(), utc());
        assert!(
            d.offer(event(1, &mac_of(1), EventType::NewDevice), base())
                .is_empty()
        );
        assert_eq!(d.pending(), 1);
        assert!(d.tick(at(59)).is_empty(), "the window has not closed");
        let out = d.tick(at(60));
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Delivery::Single(_)));
        assert_eq!(d.pending(), 0);
    }

    #[test]
    fn nine_devices_arrive_individually_and_ten_collapse_to_a_summary() {
        let mut d = Dispatcher::new(config(), utc());
        for n in 1..=9 {
            let _ = d.offer(event(n.into(), &mac_of(n), EventType::NewDevice), base());
        }
        let out = d.tick(at(60));
        assert_eq!(out.len(), 9, "below the threshold, each is its own message");

        let mut d = Dispatcher::new(config(), utc());
        for n in 1..=10 {
            let _ = d.offer(event(n.into(), &mac_of(n), EventType::NewDevice), base());
        }
        let out = d.tick(at(60));
        assert_eq!(out.len(), 1);
        match &out[0] {
            Delivery::Summary(events) => assert_eq!(events.len(), 10),
            other => panic!("expected a summary, got {other:?}"),
        }
    }

    #[test]
    fn a_summary_still_names_every_event_so_they_can_be_marked_notified() {
        let mut d = Dispatcher::new(config(), utc());
        for n in 1..=10 {
            let _ = d.offer(event(n.into(), &mac_of(n), EventType::NewDevice), base());
        }
        let out = d.tick(at(60));
        let ids: Vec<i64> = out[0].events().iter().map(|e| e.id).collect();
        assert_eq!(ids, (1..=10).collect::<Vec<i64>>());
    }

    #[test]
    fn a_zero_threshold_disables_batching_entirely() {
        let mut d = Dispatcher::new(
            NotifyConfig {
                batch_threshold: 0,
                ..config()
            },
            utc(),
        );
        for n in 1..=20 {
            let _ = d.offer(event(n.into(), &mac_of(n), EventType::NewDevice), base());
        }
        assert_eq!(d.tick(at(60)).len(), 20);
    }

    #[test]
    fn the_same_device_twice_inside_the_debounce_is_one_notification() {
        let mut d = Dispatcher::new(config(), utc());
        let _ = d.offer(event(1, &mac_of(1), EventType::NewDevice), base());
        let _ = d.offer(event(2, &mac_of(1), EventType::Returned), at(10));
        assert_eq!(d.pending(), 1);
        assert_eq!(d.suppressed().debounced, 1);
    }

    #[test]
    fn the_debounce_boundary_is_exclusive_at_the_edge() {
        let mut d = Dispatcher::new(config(), utc());
        let _ = d.offer(event(1, &mac_of(1), EventType::NewDevice), base());
        let _ = d.tick(at(60));
        // 299 seconds later: still debounced.
        let _ = d.offer(event(2, &mac_of(1), EventType::Returned), at(299));
        assert_eq!(d.suppressed().debounced, 1);
        assert_eq!(d.pending(), 0);
        // 300 seconds later: through.
        let _ = d.offer(event(3, &mac_of(1), EventType::Returned), at(300));
        assert_eq!(d.suppressed().debounced, 1);
        assert_eq!(d.pending(), 1);
    }

    #[test]
    fn the_debounce_is_per_device_not_global() {
        let mut d = Dispatcher::new(config(), utc());
        let _ = d.offer(event(1, &mac_of(1), EventType::NewDevice), base());
        let _ = d.offer(event(2, &mac_of(2), EventType::NewDevice), at(1));
        assert_eq!(d.pending(), 2);
        assert_eq!(d.suppressed().debounced, 0);
    }

    #[test]
    fn quiet_hours_suppress_and_release_on_the_boundary() {
        let cfg = NotifyConfig {
            quiet_hours: Some(QuietHours {
                start: ClockTime {
                    hour: 22,
                    minute: 0,
                },
                end: ClockTime { hour: 7, minute: 0 },
            }),
            ..config()
        };
        let mut d = Dispatcher::new(cfg, utc());
        let night = Utc
            .with_ymd_and_hms(2026, 2, 2, 23, 30, 0)
            .single()
            .expect("valid time");
        let _ = d.offer(event(1, &mac_of(1), EventType::NewDevice), night);
        assert_eq!(d.suppressed().quiet_hours, 1);
        assert_eq!(d.pending(), 0);

        let morning = Utc
            .with_ymd_and_hms(2026, 2, 3, 7, 0, 0)
            .single()
            .expect("valid time");
        let _ = d.offer(event(2, &mac_of(2), EventType::NewDevice), morning);
        assert_eq!(d.suppressed().quiet_hours, 1, "07:00 is no longer quiet");
        assert_eq!(d.pending(), 1);
    }

    #[test]
    fn quiet_hours_are_evaluated_in_local_time_not_utc() {
        let cfg = NotifyConfig {
            quiet_hours: Some(QuietHours {
                start: ClockTime {
                    hour: 22,
                    minute: 0,
                },
                end: ClockTime { hour: 7, minute: 0 },
            }),
            ..config()
        };
        // Rome in winter: UTC+1. 21:30 UTC is 22:30 local, which is quiet.
        let rome = FixedOffset::east_opt(3600).expect("offset");
        let mut d = Dispatcher::new(cfg.clone(), rome);
        let evening = Utc
            .with_ymd_and_hms(2026, 2, 2, 21, 30, 0)
            .single()
            .expect("valid time");
        let _ = d.offer(event(1, &mac_of(1), EventType::NewDevice), evening);
        assert_eq!(d.suppressed().quiet_hours, 1);

        // The same instant in UTC is 21:30, which is not quiet.
        let mut d = Dispatcher::new(cfg, utc());
        let _ = d.offer(event(1, &mac_of(1), EventType::NewDevice), evening);
        assert_eq!(d.suppressed().quiet_hours, 0);
    }

    #[test]
    fn events_outside_the_configured_types_are_dropped() {
        let mut d = Dispatcher::new(config(), utc());
        let _ = d.offer(event(1, &mac_of(1), EventType::IpChanged), base());
        assert_eq!(d.suppressed().wrong_type, 1);
        assert_eq!(d.pending(), 0);
    }

    #[test]
    fn a_learning_window_suppresses_delivery_but_the_event_still_arrived() {
        let mut d = Dispatcher::new(config(), utc());
        let mut e = event(1, &mac_of(1), EventType::NewDevice);
        e.event.during_learning = true;
        let _ = d.offer(e, base());
        assert_eq!(d.suppressed().not_deliverable, 1);
        assert_eq!(d.pending(), 0);
    }

    #[test]
    fn a_device_with_notifications_turned_off_is_silent() {
        let mut d = Dispatcher::new(config(), utc());
        let mut e = event(1, &mac_of(1), EventType::NewDevice);
        e.event.notify = false;
        let _ = d.offer(e, base());
        assert_eq!(d.suppressed().not_deliverable, 1);
    }

    #[test]
    fn the_master_switch_stops_everything() {
        let mut d = Dispatcher::new(
            NotifyConfig {
                enabled: false,
                ..config()
            },
            utc(),
        );
        let _ = d.offer(event(1, &mac_of(1), EventType::NewDevice), base());
        assert_eq!(d.suppressed().disabled, 1);
        assert_eq!(d.suppressed().total(), 1);
    }

    #[test]
    fn draining_at_shutdown_does_not_lose_a_held_notification() {
        let mut d = Dispatcher::new(config(), utc());
        let _ = d.offer(event(1, &mac_of(1), EventType::NewDevice), base());
        assert_eq!(d.pending(), 1);
        let out = d.drain();
        assert_eq!(out.len(), 1);
        assert!(d.drain().is_empty(), "draining twice sends nothing twice");
    }

    #[test]
    fn a_suppressed_event_still_lets_a_due_window_close() {
        let mut d = Dispatcher::new(config(), utc());
        let _ = d.offer(event(1, &mac_of(1), EventType::NewDevice), base());
        // A second event that is filtered out, arriving after the window is due,
        // must still flush the first one rather than stranding it.
        let out = d.offer(event(2, &mac_of(2), EventType::IpChanged), at(61));
        assert_eq!(out.len(), 1);
    }

    /// A notifier that records what it was asked to send and can be told to
    /// fail.
    struct SpyNotifier {
        sent: Mutex<Vec<String>>,
        fail: bool,
    }

    #[async_trait]
    impl Notifier for SpyNotifier {
        fn name(&self) -> &str {
            "spy"
        }

        async fn send(&self, event: &DeviceEvent) -> Result<()> {
            if self.fail {
                anyhow::bail!("transport is down");
            }
            self.sent
                .lock()
                .expect("spy lock")
                .push(event.display_name.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn the_default_batch_implementation_sends_each_event() {
        let spy = SpyNotifier {
            sent: Mutex::new(Vec::new()),
            fail: false,
        };
        let events: Vec<RecordedEvent> = (1..=3)
            .map(|n| {
                event(
                    n,
                    &mac_of(u8::try_from(n).expect("fits")),
                    EventType::NewDevice,
                )
            })
            .collect();
        assert!(deliver(&spy, &Delivery::Summary(events)).await);
        assert_eq!(spy.sent.lock().expect("spy lock").len(), 3);
    }

    #[tokio::test]
    async fn a_failing_notifier_is_logged_not_propagated() {
        let spy = SpyNotifier {
            sent: Mutex::new(Vec::new()),
            fail: true,
        };
        let delivered = deliver(
            &spy,
            &Delivery::Single(Box::new(event(1, &mac_of(1), EventType::NewDevice))),
        )
        .await;
        assert!(!delivered, "failure is reported, not raised");
    }
}
