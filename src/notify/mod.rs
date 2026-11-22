//! Notification delivery.
//!
//! **All rate limiting lives in [`Dispatcher`], never in a [`Notifier`].** A
//! notifier's only job is to put one message somewhere; deciding whether a
//! message should exist at all is policy, and policy that lives in each
//! transport gets implemented three different ways.
//!
//! The dispatcher applies, in order:
//!
//! 1. The master switch and `[security.notifications].enabled`, then the
//!    per-event rule in [`DeviceEvent::deliverable`]: a learning window
//!    suppresses everything but security events; after it, `new_device` always
//!    delivers, `returned` and `went_offline` only for a device whose `notify`
//!    a person turned on, and `ip_changed`, `name_updated` and
//!    `device_location_changed` never.
//! 2. Approved devices: a type in `notify.approved_quiet_types` from a device
//!    a person has vouched for ([`DeviceEvent::approved`]) goes no further.
//! 3. The configured event-type allowlist, for device lifecycle events.
//! 4. The event's **class** (`notify.classes`). `off` stops here; `digest`
//!    counts it for the daily digest at `notify.digest_time`; `push` goes on.
//! 5. Quiet hours, unless the class has `respect_quiet_hours = false`.
//! 6. Per-device debounce for lifecycle and person events, kept apart for
//!    person events (see below).
//! 7. Pooling per source, keyed by (class, event type, MAC): the first
//!    `instant_count` events go out as they happen, the last of them saying so,
//!    then one summary per `pool_period`, slowing to one per `backoff_period`
//!    once the source has repeated for `backoff_after` without a gap of
//!    `quiet_reset`. A gap of `quiet_reset` starts over.
//! 8. Batching: instant alerts are held for `batch_window`, and a window that
//!    accumulated at least `batch_threshold` of them collapses into one summary
//!    instead of a storm. This is what makes a network restart one notification.
//!
//! The batch window costs up to `batch_window` of latency on every
//! notification. That is the deliberate trade: it is still far faster than the
//! plugin's cron cadence, and a user who wants instant alerts sets
//! `batch_window` low or sets `batch_threshold` to zero to disable batching
//! entirely.
//!
//! Pooling state lives in memory. A restart forgets it, so a source that was
//! pooled gets at most `instant_count` instant alerts again afterwards, and
//! the events held for a summary or the digest stay in `ng_events` unsent.
//!
//! ## Security events follow their class
//!
//! Security events used to skip quiet hours, the debounce and the batch window
//! outright. That made "security always alerts" true and also made one chatty
//! router twenty thousand alerts a week. Now each security type is in a class
//! like every other type, and the class decides: by default `arp_spoof` and
//! `rogue_dhcp` push and ignore quiet hours, `arp_scan` and `ip_conflict` push
//! and respect them, and `identity_change` and `gratuitous_arp` go in the
//! digest. A security type left out of every class falls back to the `anomaly`
//! class, never to `off`.
//!
//! They are not debounced: their repeats are pooled instead, which limits them
//! as hard and still counts every one. They still skip the event-type
//! allowlist, because they are governed by their class rather than by
//! `notify.event_types`, and they still ignore the learning window and the
//! device's `notify`.
//!
//! The one thing security events do **not** bypass is `notify.enabled`. That
//! switch and `--no-notify` mean "deliver nothing", and a master switch with an
//! exception is not a master switch. `[security.notifications].enabled` is the
//! finer control.
//!
//! ## Person events skip the allowlist and nothing else
//!
//! `person_arrived` and `person_departed` are gated by `notify_arrive` and
//! `notify_depart` in `ng_people`, which is where somebody sets them in the
//! admin UI. Making them *also* appear in `notify.event_types` would be the same
//! trap: an operator turns the flag on, nothing arrives, and there is nothing in
//! the logs to say why. So they skip the allowlist and obey everything else,
//! because somebody coming home is a lifecycle event and quiet hours mean quiet.
//!
//! Their debounce is their own. A phone coming back is `returned` and then
//! `person_arrived` for the same MAC in the same instant, and a debounce shared
//! with device events would always let the first through and drop the second.
//!
//! `person_location_changed` has no flag of its own, and adding one would need a
//! column the plugin has not seen. It is recorded with `notify` false, so it is
//! in the event log and never on a phone.

pub mod ntfy;

use std::collections::{BTreeMap, HashMap};

use crate::clock::Timestamp;
use anyhow::Result;
use async_trait::async_trait;
use jiff::SignedDuration;
use jiff::tz::Offset;

use crate::config::{AlertClass, ClassDelivery, ClockTime, NotifyConfig, SecurityNotifyConfig};
use crate::db::Db;
use crate::db::queries;
use crate::device::DeviceEvent;
use crate::device::persist::RecordedEvent;
use crate::types::{EventPriority, EventType, MacAddr};

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

    /// Sends one event with a line of its own added: the note that says the
    /// alerts after it from the same source will be pooled.
    ///
    /// The default sends the event without the note, which is correct but
    /// leaves the reader to wonder where the next alerts went.
    ///
    /// # Errors
    ///
    /// Returns an error when delivery fails.
    async fn send_noted(&self, event: &DeviceEvent, note: &str) -> Result<()> {
        let _ = note;
        self.send(event).await
    }

    /// Sends a message the dispatcher wrote: a pooled summary or the daily
    /// digest.
    ///
    /// # Errors
    ///
    /// Returns an error when delivery fails, or when the transport has no way
    /// to send free text.
    async fn send_report(&self, title: &str, body: &str, priority: EventPriority) -> Result<()> {
        let _ = (body, priority);
        anyhow::bail!("{} cannot send a summary: {title}", self.name())
    }

    /// Whether this transport understands priority levels.
    fn supports_priority(&self) -> bool {
        false
    }

    /// Sends a test alert, so that somebody can see delivery work without
    /// waiting for a device to come home.
    ///
    /// # Errors
    ///
    /// Returns an error when delivery fails, or when the transport has no way
    /// to send one.
    async fn send_test(&self, at: Timestamp) -> Result<()> {
        let _ = at;
        anyhow::bail!("{} cannot send a test alert", self.name())
    }
}

/// What became of a test alert somebody asked for.
///
/// Stored in `ng_notify_requests.outcome` as [`TestOutcome::as_str`]. A word,
/// never an error message: a transport error names the URL, and the URL
/// contains the topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestOutcome {
    /// At least one notifier accepted it.
    Sent,
    /// Every notifier refused it or could not be reached.
    Failed,
    /// There is nowhere to send it.
    NotConfigured,
}

impl TestOutcome {
    /// The word stored in `ng_notify_requests.outcome`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            TestOutcome::Sent => "sent",
            TestOutcome::Failed => "failed",
            TestOutcome::NotConfigured => "not_configured",
        }
    }
}

/// Whether anything will actually be delivered.
fn configured(notifiers: &[Box<dyn Notifier>], enabled: bool) -> bool {
    enabled && !notifiers.is_empty()
}

/// Writes `ng_notify_status`: whether delivery is configured, and by what.
///
/// Names the transport and nothing else. The topic, the server and the token
/// stay in the daemon's configuration.
///
/// # Errors
///
/// Returns an error when there is no database connection or the write fails.
pub async fn publish_status(
    db: &Db,
    notifiers: &[Box<dyn Notifier>],
    enabled: bool,
    now: Timestamp,
) -> Result<()> {
    let is_configured = configured(notifiers, enabled);
    let backend = if is_configured {
        Some(
            notifiers
                .iter()
                .map(|n| n.name())
                .collect::<Vec<_>>()
                .join(", "),
        )
    } else {
        None
    };
    let client = db.client().await?;
    queries::publish_notify_status(&client, is_configured, backend.as_deref(), now).await
}

/// Records the outcome of one delivery attempt in `ng_notify_status`.
///
/// # Errors
///
/// Returns an error when there is no database connection or the write fails.
pub async fn record_delivery(db: &Db, ok: bool, at: Timestamp) -> Result<()> {
    let client = db.client().await?;
    queries::record_notify_delivery(&client, ok, at).await
}

/// Answers every test request waiting in `ng_notify_requests` with one test
/// alert.
///
/// Several presses of the button before the tick comes round are one test, not
/// several: the person asked whether alerts work, and one alert answers that.
///
/// Returns `None` when nothing was waiting.
///
/// # Errors
///
/// Returns an error when there is no database connection or a query fails. A
/// transport failure is an outcome, not an error.
pub async fn handle_test_requests(
    db: &Db,
    notifiers: &[Box<dyn Notifier>],
    enabled: bool,
    now: Timestamp,
) -> Result<Option<TestOutcome>> {
    let client = db.client().await?;
    let pending = queries::pending_notify_requests(&client).await?;
    if pending.is_empty() {
        return Ok(None);
    }
    let outcome = if configured(notifiers, enabled) {
        let mut sent = false;
        for notifier in notifiers {
            match notifier.send_test(now).await {
                Ok(()) => sent = true,
                Err(err) => {
                    tracing::warn!(notifier = notifier.name(), %err, "test alert failed");
                }
            }
        }
        queries::record_notify_delivery(&client, sent, now).await?;
        if sent {
            TestOutcome::Sent
        } else {
            TestOutcome::Failed
        }
    } else {
        TestOutcome::NotConfigured
    };
    queries::complete_notify_requests(&client, &pending, outcome.as_str(), now).await?;
    tracing::info!(
        requests = pending.len(),
        outcome = outcome.as_str(),
        "answered a test alert request"
    );
    Ok(Some(outcome))
}

/// What the dispatcher decided to deliver.
#[derive(Debug, Clone, PartialEq)]
pub enum Delivery {
    /// One event, sent on its own.
    Single(Box<RecordedEvent>),
    /// Several events from one batch window collapsed into one summary message.
    Summary(Vec<RecordedEvent>),
    /// The last instant alert from a source before its alerts are pooled: the
    /// event, and the line that says what happens next.
    Noted {
        /// The event.
        event: Box<RecordedEvent>,
        /// "More alerts like this from ... will be pooled: one summary every
        /// hour."
        note: String,
    },
    /// Text the dispatcher wrote itself: a pooled summary for one source, or
    /// the daily digest.
    Report(Box<Report>),
}

/// A pooled summary or a daily digest, ready to send.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// Which of the two this is.
    pub kind: ReportKind,
    /// The notification title.
    pub title: String,
    /// The notification body.
    pub body: String,
    /// How loudly to deliver it.
    pub priority: EventPriority,
    /// Every event it covers, so the caller can mark them notified.
    pub events: Vec<RecordedEvent>,
}

/// What a [`Report`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportKind {
    /// One summary for one pooled source.
    Pooled,
    /// The daily digest of every `digest` class.
    Digest,
}

impl Delivery {
    /// The events this delivery covers, so the caller can mark them notified.
    #[must_use]
    pub fn events(&self) -> Vec<&RecordedEvent> {
        match self {
            Delivery::Single(e) | Delivery::Noted { event: e, .. } => vec![e],
            Delivery::Summary(events) => events.iter().collect(),
            Delivery::Report(report) => report.events.iter().collect(),
        }
    }
}

/// Why an event was not delivered. Counted so that "why did I not get an alert"
/// has an answer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SuppressionCounts {
    /// Notifications are switched off entirely.
    pub disabled: usize,
    /// The per-event rule said no: a learning window, a device nobody turned
    /// `notify` on for, or a type that is never delivered.
    pub not_deliverable: usize,
    /// The event type is not in the configured allowlist.
    pub wrong_type: usize,
    /// Quiet hours were in effect.
    pub quiet_hours: usize,
    /// Another notification about the same device was too recent.
    pub debounced: usize,
    /// Security notifications are switched off. The event was still recorded.
    pub security_disabled: usize,
    /// The device is approved and the type is in `notify.approved_quiet_types`.
    pub approved_quiet: usize,
    /// The event's class is `off`, or it is in no class.
    pub class_off: usize,
}

impl SuppressionCounts {
    /// Total suppressed.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.disabled
            + self.not_deliverable
            + self.wrong_type
            + self.quiet_hours
            + self.debounced
            + self.security_disabled
            + self.approved_quiet
            + self.class_off
    }
}

/// One instant alert waiting for its batch window to close.
#[derive(Debug, Clone)]
struct Waiting {
    event: RecordedEvent,
    note: Option<String>,
}

/// Which pool an event belongs to: its class, its type and its source.
type PoolKey = (String, EventType, MacAddr);

/// What the dispatcher remembers about one repeating source.
#[derive(Debug, Clone)]
struct Pool {
    /// When this run of repeats began; reset by a gap of `quiet_reset`.
    streak_started: Timestamp,
    /// The latest event, which is what `quiet_reset` is measured from.
    last_event: Timestamp,
    /// How many events of this run were delivered one by one.
    instants: u32,
    /// Events waiting for the next summary.
    held: Vec<RecordedEvent>,
    /// When the next summary is due, if anything is or may be held.
    next_summary: Option<Timestamp>,
    /// True once summaries have slowed to `backoff_period`.
    backed_off: bool,
}

impl Pool {
    fn new(now: Timestamp) -> Self {
        Pool {
            streak_started: now,
            last_event: now,
            instants: 0,
            held: Vec::new(),
            next_summary: None,
            backed_off: false,
        }
    }

    fn period(&self, class: &AlertClass) -> std::time::Duration {
        if self.backed_off {
            class.backoff_period.get()
        } else {
            class.pool_period.get()
        }
    }
}

/// Decides what gets delivered and when.
///
/// Pure and synchronous: it takes events and a clock reading and returns
/// deliveries. Every rule above is therefore a plain test.
pub struct Dispatcher {
    config: NotifyConfig,
    security: SecurityNotifyConfig,
    offset: Offset,
    /// Each event type's class, worked out once.
    classes: HashMap<EventType, (String, AlertClass)>,
    /// When an alert was last accepted, per device and per audience: a person
    /// event and a device event about the same MAC are debounced separately,
    /// because the one about the device always comes first and would otherwise
    /// swallow the one about the person.
    last_accepted: HashMap<(MacAddr, bool), Timestamp>,
    pending: Vec<Waiting>,
    window_opened_at: Option<Timestamp>,
    pools: BTreeMap<PoolKey, Pool>,
    /// Events for the next digest, with their class.
    digest: Vec<(String, RecordedEvent)>,
    next_digest: Option<Timestamp>,
    suppressed: SuppressionCounts,
}

impl Dispatcher {
    /// Builds a dispatcher.
    ///
    /// `offset` is the local UTC offset used to evaluate quiet hours and the
    /// digest time; taking it as a parameter rather than reading the system
    /// clock is what makes both testable.
    #[must_use]
    pub fn new(config: NotifyConfig, security: SecurityNotifyConfig, offset: Offset) -> Self {
        let classes = EventType::ALL
            .into_iter()
            .filter_map(|kind| config.class_of(kind).map(|class| (kind, class)))
            .collect();
        Dispatcher {
            config,
            security,
            offset,
            classes,
            last_accepted: HashMap::new(),
            pending: Vec::new(),
            window_opened_at: None,
            pools: BTreeMap::new(),
            digest: Vec::new(),
            next_digest: None,
            suppressed: SuppressionCounts::default(),
        }
    }

    /// Builds a dispatcher using the machine's current UTC offset.
    #[must_use]
    pub fn with_local_offset(config: NotifyConfig, security: SecurityNotifyConfig) -> Self {
        let offset = crate::clock::local_offset_now();
        Dispatcher::new(config, security, offset)
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

    /// How many events are held for a pooled summary.
    #[must_use]
    pub fn pooled(&self) -> usize {
        self.pools.values().map(|p| p.held.len()).sum()
    }

    /// How many events are waiting for the next digest.
    #[must_use]
    pub fn digest_waiting(&self) -> usize {
        self.digest.len()
    }

    /// Offers an event for delivery.
    ///
    /// Returns any deliveries that became due as a result, which is usually none
    /// because the batch window has to close first.
    #[must_use]
    pub fn offer(&mut self, event: RecordedEvent, now: Timestamp) -> Vec<Delivery> {
        // Whatever fell due before this event arrived goes first, which is also
        // what lets a source that went quiet start over with this event.
        let mut out = self.tick(now);
        self.accept(event, now);
        out.extend(self.tick(now));
        out
    }

    /// Runs one event through the rules, leaving it waiting, pooled, in the
    /// digest, or counted as suppressed.
    fn accept(&mut self, event: RecordedEvent, now: Timestamp) {
        let kind = event.event.event_type;
        let security = kind.is_security();

        // The master switch has no exception; see the module documentation.
        if !self.config.enabled {
            self.suppressed.disabled += 1;
            return;
        }
        if security && !self.security.enabled {
            self.suppressed.security_disabled += 1;
            return;
        }
        if !event.event.deliverable() {
            self.suppressed.not_deliverable += 1;
            return;
        }
        if event.event.approved && self.config.approved_quiet(kind) {
            self.suppressed.approved_quiet += 1;
            return;
        }
        // The allowlist governs device lifecycle events. Security and person
        // events are governed by their class, and person events also by the
        // per-person notify_arrive and notify_depart flags in ng_people.
        let person = kind.is_person();
        if !security && !person && !self.config.event_types.iter().any(|t| t == kind.as_str()) {
            self.suppressed.wrong_type += 1;
            return;
        }
        let Some((class_name, class)) = self.classes.get(&kind).cloned() else {
            self.suppressed.class_off += 1;
            return;
        };
        match class.delivery {
            ClassDelivery::Off => {
                self.suppressed.class_off += 1;
            }
            // Quiet hours decide when the digest goes out, not what it counts.
            ClassDelivery::Digest => self.digest.push((class_name, event)),
            ClassDelivery::Push => {
                if class.respect_quiet_hours && self.in_quiet_hours(now) {
                    self.suppressed.quiet_hours += 1;
                    return;
                }
                // The debounce is for devices coming and going. A security
                // event's repeats are limited by its pool instead, which counts
                // every one of them rather than dropping them.
                if !security {
                    if let Some(previous) = self.last_accepted.get(&(event.event.mac, person))
                        && std::time::Duration::try_from(now.since(*previous)).unwrap_or_default()
                            < self.config.debounce.get()
                    {
                        self.suppressed.debounced += 1;
                        return;
                    }
                    self.last_accepted.insert((event.event.mac, person), now);
                }
                self.pool(class_name, &class, event, now);
            }
        }
    }

    /// Counts a pushed event against its source, and either sends it now or
    /// holds it for the source's next summary.
    fn pool(
        &mut self,
        class_name: String,
        class: &AlertClass,
        event: RecordedEvent,
        now: Timestamp,
    ) {
        let key = (class_name, event.event.event_type, event.event.mac);
        let pool = self.pools.entry(key).or_insert_with(|| Pool::new(now));
        pool.last_event = now;
        if pool.instants < class.instant_count {
            pool.instants += 1;
            let note = (pool.instants == class.instant_count).then(|| {
                pool.next_summary = Some(now + signed(class.pool_period.get()));
                format!(
                    "More alerts like this from {} will be pooled: one summary every {}.",
                    event.event.mac,
                    unit(class.pool_period.get())
                )
            });
            self.pending.push(Waiting { event, note });
            self.window_opened_at.get_or_insert(now);
            return;
        }
        if pool.next_summary.is_none() {
            pool.next_summary = Some(now + signed(pool.period(class)));
        }
        pool.held.push(event);
    }

    /// Closes the batch window if it has elapsed, sends any pooled summary that
    /// is due, starts over for any source that has gone quiet, and sends the
    /// digest when its time comes. Returns what is due.
    ///
    /// Call this on a timer as well as after every offer, otherwise a single
    /// event arriving on a quiet network would wait for the next one.
    #[must_use]
    pub fn tick(&mut self, now: Timestamp) -> Vec<Delivery> {
        let mut out = self.tick_batch(now);
        out.extend(self.tick_pools(now));
        out.extend(self.tick_digest(now));
        out
    }

    fn tick_batch(&mut self, now: Timestamp) -> Vec<Delivery> {
        let Some(opened) = self.window_opened_at else {
            return Vec::new();
        };
        let elapsed = std::time::Duration::try_from(now.since(opened)).unwrap_or_default();
        if elapsed < self.config.batch_window.get() {
            return Vec::new();
        }
        self.drain()
    }

    fn tick_pools(&mut self, now: Timestamp) -> Vec<Delivery> {
        let quiet = self.in_quiet_hours(now);
        let mut out = Vec::new();
        let mut finished = Vec::new();
        for (key, pool) in &mut self.pools {
            let Some((_, class)) = self.classes.get(&key.1) else {
                finished.push(key.clone());
                continue;
            };
            // A summary due inside quiet hours waits for them to end.
            let held_back = class.respect_quiet_hours && quiet;
            let gone_quiet = std::time::Duration::try_from(now.since(pool.last_event))
                .unwrap_or_default()
                >= class.quiet_reset.get();
            if gone_quiet {
                if pool.held.is_empty() {
                    finished.push(key.clone());
                } else if !held_back {
                    out.push(pooled_summary(pool, class, now, None, self.offset));
                    finished.push(key.clone());
                }
                continue;
            }
            let Some(due) = pool.next_summary else {
                continue;
            };
            if now < due || held_back {
                continue;
            }
            if pool.held.is_empty() {
                pool.next_summary = None;
                continue;
            }
            let switched = !pool.backed_off
                && std::time::Duration::try_from(now.since(pool.streak_started))
                    .unwrap_or_default()
                    >= class.backoff_after.get();
            if switched {
                pool.backed_off = true;
            }
            let next = now + signed(pool.period(class));
            pool.next_summary = Some(next);
            let mut summary = pooled_summary(pool, class, now, Some(next), self.offset);
            if switched && let Delivery::Report(report) = &mut summary {
                report.body.push_str(&format!(
                    "\nIt has repeated for {} without a break of {}, so summaries now come \
                     once every {}.",
                    amount(class.backoff_after.get()),
                    amount(class.quiet_reset.get()),
                    unit(class.backoff_period.get())
                ));
            }
            out.push(summary);
        }
        for key in finished {
            self.pools.remove(&key);
        }
        out
    }

    fn tick_digest(&mut self, now: Timestamp) -> Vec<Delivery> {
        let due = *self
            .next_digest
            .get_or_insert_with(|| next_clock_time(now, self.config.digest_time, self.offset));
        if now < due {
            return Vec::new();
        }
        let held_back = self.in_quiet_hours(now)
            && self.digest.iter().any(|(name, _)| {
                self.config
                    .effective_classes()
                    .get(name)
                    .is_none_or(|c| c.respect_quiet_hours)
            });
        if held_back {
            return Vec::new();
        }
        self.next_digest = Some(next_clock_time(now, self.config.digest_time, self.offset));
        if self.digest.is_empty() {
            return Vec::new();
        }
        let entries = std::mem::take(&mut self.digest);
        vec![digest_report(entries)]
    }

    /// Delivers everything waiting for the batch window immediately. Used at
    /// shutdown so that a held notification is not simply lost.
    ///
    /// Pooled summaries and the digest are not sent early: their events stay in
    /// `ng_events`, and pooling state does not survive a restart.
    #[must_use]
    pub fn drain(&mut self) -> Vec<Delivery> {
        self.window_opened_at = None;
        let pending = std::mem::take(&mut self.pending);
        if pending.is_empty() {
            return Vec::new();
        }
        // A collapsed window says how many alerts there were, which is the
        // point of collapsing it; a pooling note inside it is dropped with the
        // rest of each alert's text, and the pooled summary still follows.
        if self.config.batch_threshold > 0 && pending.len() >= self.config.batch_threshold {
            vec![Delivery::Summary(
                pending.into_iter().map(|w| w.event).collect(),
            )]
        } else {
            pending
                .into_iter()
                .map(|w| match w.note {
                    Some(note) => Delivery::Noted {
                        event: Box::new(w.event),
                        note,
                    },
                    None => Delivery::Single(Box::new(w.event)),
                })
                .collect()
        }
    }

    /// Whether the given instant falls inside the configured quiet period.
    #[must_use]
    pub fn in_quiet_hours(&self, now: Timestamp) -> bool {
        let Some(quiet) = self.config.quiet_hours else {
            return false;
        };
        quiet.contains(now.minute_of_day_at(self.offset))
    }
}

/// A [`std::time::Duration`] as a jiff duration, saturating.
fn signed(d: std::time::Duration) -> SignedDuration {
    SignedDuration::try_from(d).unwrap_or(SignedDuration::MAX)
}

/// "hour", "24 hours", "30 minutes": what follows "every".
fn unit(d: std::time::Duration) -> String {
    let (n, word) = magnitude(d);
    if n == 1 {
        word.to_string()
    } else {
        format!("{n} {word}s")
    }
}

/// "an hour", "24 hours", "a minute": an amount of time on its own.
fn amount(d: std::time::Duration) -> String {
    let (n, word) = magnitude(d);
    match (n, word) {
        (1, "hour") => "an hour".to_string(),
        (1, w) => format!("a {w}"),
        (n, w) => format!("{n} {w}s"),
    }
}

fn magnitude(d: std::time::Duration) -> (u64, &'static str) {
    let s = d.as_secs();
    if s >= 3600 && s.is_multiple_of(3600) {
        (s / 3600, "hour")
    } else if s >= 60 && s.is_multiple_of(60) {
        (s / 60, "minute")
    } else {
        (s, "second")
    }
}

/// "09:03" when `at` is on the same local day as `now`, "2026-11-18 09:03"
/// otherwise.
fn local_time(at: Timestamp, now: Timestamp, offset: Offset) -> String {
    let pattern = if at.date_at(offset) == now.date_at(offset) {
        "%H:%M"
    } else {
        "%Y-%m-%d %H:%M"
    };
    at.at_offset(offset).strftime(pattern).to_string()
}

/// The first instant after `now` whose local time is `time`.
fn next_clock_time(now: Timestamp, time: ClockTime, offset: Offset) -> Timestamp {
    let local = now.unix_seconds() + i64::from(offset.seconds());
    let into_day = local.rem_euclid(86_400);
    let target = i64::from(time.minutes()) * 60;
    let mut wait = (target - into_day).rem_euclid(86_400);
    if wait == 0 {
        wait = 86_400;
    }
    now + SignedDuration::from_secs(wait)
}

/// One pooled source's summary, taking everything it held.
///
/// `next` is when the following summary is due, or `None` when the source has
/// gone quiet and this one closes it.
fn pooled_summary(
    pool: &mut Pool,
    class: &AlertClass,
    now: Timestamp,
    next: Option<Timestamp>,
    offset: Offset,
) -> Delivery {
    let events = std::mem::take(&mut pool.held);
    let first = events.first().map_or(now, |e| e.event.at);
    let last = events.last().map_or(now, |e| e.event.at);
    let sample = events.last().map(|e| &e.event);
    let count = events.len();
    let alerts = if count == 1 { "alert" } else { "alerts" };
    let source = sample.map_or_else(String::new, |e| e.mac.to_string());
    let title = sample.map_or_else(String::new, |e| {
        format!("{} ({count} more)", ntfy::title_for(e))
    });
    let mut body = format!(
        "{count} more {alerts} like this from {source} between {} and {}.",
        local_time(first, now, offset),
        local_time(last, now, offset)
    );
    match next {
        Some(next) => body.push_str(&format!(
            "\nNext summary at {} if it continues.",
            local_time(next, now, offset)
        )),
        None => body.push_str(&format!(
            "\nIt has been quiet for {}, so the next one alerts at once.",
            amount(class.quiet_reset.get())
        )),
    }
    let priority = events
        .iter()
        .map(|e| e.event.priority)
        .max()
        .unwrap_or(EventPriority::Normal);
    Delivery::Report(Box::new(Report {
        kind: ReportKind::Pooled,
        title,
        body,
        priority,
        events,
    }))
}

/// Digest counts: class, then type, then source, with the count and the
/// latest name for each source.
type DigestTree<'a> = BTreeMap<&'a str, BTreeMap<&'a str, BTreeMap<MacAddr, (usize, &'a str)>>>;

/// The daily digest: counts by class, then type, then source.
///
/// A source is a MAC, named by the latest event from it.
fn digest_report(entries: Vec<(String, RecordedEvent)>) -> Delivery {
    let mut tree: DigestTree = BTreeMap::new();
    for (class, recorded) in &entries {
        let e = &recorded.event;
        let source = tree
            .entry(class.as_str())
            .or_default()
            .entry(e.event_type.as_str())
            .or_default()
            .entry(e.mac)
            .or_default();
        source.0 += 1;
        source.1 = e.display_name.as_str();
    }
    let mut lines = Vec::new();
    for (class, types) in &tree {
        let total: usize = types.values().flat_map(BTreeMap::values).map(|s| s.0).sum();
        lines.push(format!("{class}: {total}"));
        for (kind, sources) in types {
            let count: usize = sources.values().map(|s| s.0).sum();
            lines.push(format!("  {kind}: {count}"));
            let mut by_count: Vec<_> = sources.iter().collect();
            by_count.sort_by(|a, b| b.1.0.cmp(&a.1.0).then(a.0.cmp(b.0)));
            for (mac, (n, name)) in by_count {
                if name.is_empty() || *name == mac.to_string() {
                    lines.push(format!("    {n} from {mac}"));
                } else {
                    lines.push(format!("    {n} from {name} ({mac})"));
                }
            }
        }
    }
    let count = entries.len();
    let alerts = if count == 1 { "alert" } else { "alerts" };
    Delivery::Report(Box::new(Report {
        kind: ReportKind::Digest,
        title: format!("Netgrasp daily digest: {count} {alerts}"),
        body: lines.join("\n"),
        priority: EventPriority::Normal,
        events: entries.into_iter().map(|(_, e)| e).collect(),
    }))
}

/// Sends a delivery through a notifier, logging rather than propagating a
/// transport failure.
///
/// Returns true when delivery succeeded. A notifier being unreachable is an
/// operational problem, not a reason to stop watching the network.
pub async fn deliver(notifier: &dyn Notifier, delivery: &Delivery) -> bool {
    let result = match delivery {
        Delivery::Single(event) => notifier.send(&event.event).await,
        Delivery::Noted { event, note } => notifier.send_noted(&event.event, note).await,
        Delivery::Summary(events) => {
            let payload: Vec<DeviceEvent> = events.iter().map(|e| e.event.clone()).collect();
            notifier.send_batch(&payload).await
        }
        Delivery::Report(report) => {
            notifier
                .send_report(&report.title, &report.body, report.priority)
                .await
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
    use crate::config::{ClockTime, HumanDuration, QuietHours, default_classes};
    use crate::types::EventType;
    use jiff::SignedDuration;

    use std::sync::Mutex;

    fn utc() -> Offset {
        Offset::from_seconds(0).expect("utc offset")
    }

    fn base() -> Timestamp {
        // 2026-02-02T12:00:00Z, a time comfortably outside any quiet window used
        // in these tests.
        Timestamp::from_utc(2026, 2, 2, 12, 0, 0).expect("valid time")
    }

    fn at(secs: i64) -> Timestamp {
        base() + SignedDuration::from_secs(secs)
    }

    fn security() -> SecurityNotifyConfig {
        SecurityNotifyConfig::default()
    }

    fn config() -> NotifyConfig {
        NotifyConfig {
            enabled: true,
            debounce: HumanDuration::from_secs(300),
            batch_threshold: 10,
            batch_window: HumanDuration::from_secs(60),
            event_types: vec!["new_device".into(), "returned".into()],
            quiet_hours: None,
            ..NotifyConfig::default()
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
                approved: false,
                priority: crate::types::EventPriority::Normal,
                details: serde_json::Value::Null,
            },
        }
    }

    fn mac_of(n: u8) -> String {
        format!("3c:22:fb:00:00:{n:02x}")
    }

    #[test]
    fn one_event_is_delivered_when_its_window_closes() {
        let mut d = Dispatcher::new(config(), security(), utc());
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
        let mut d = Dispatcher::new(config(), security(), utc());
        for n in 1..=9 {
            let _ = d.offer(event(n.into(), &mac_of(n), EventType::NewDevice), base());
        }
        let out = d.tick(at(60));
        assert_eq!(out.len(), 9, "below the threshold, each is its own message");

        let mut d = Dispatcher::new(config(), security(), utc());
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
        let mut d = Dispatcher::new(config(), security(), utc());
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
            security(),
            utc(),
        );
        for n in 1..=20 {
            let _ = d.offer(event(n.into(), &mac_of(n), EventType::NewDevice), base());
        }
        assert_eq!(d.tick(at(60)).len(), 20);
    }

    #[test]
    fn the_same_device_twice_inside_the_debounce_is_one_notification() {
        let mut d = Dispatcher::new(config(), security(), utc());
        let _ = d.offer(event(1, &mac_of(1), EventType::NewDevice), base());
        let _ = d.offer(event(2, &mac_of(1), EventType::Returned), at(10));
        assert_eq!(d.pending(), 1);
        assert_eq!(d.suppressed().debounced, 1);
    }

    #[test]
    fn the_debounce_boundary_is_exclusive_at_the_edge() {
        let mut d = Dispatcher::new(config(), security(), utc());
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
        let mut d = Dispatcher::new(config(), security(), utc());
        let _ = d.offer(event(1, &mac_of(1), EventType::NewDevice), base());
        let _ = d.offer(event(2, &mac_of(2), EventType::NewDevice), at(1));
        assert_eq!(d.pending(), 2);
        assert_eq!(d.suppressed().debounced, 0);
    }

    // Jamie's phone coming back is two events for one MAC in the same instant:
    // `returned`, then `person_arrived`. With a debounce keyed by MAC alone the
    // arrival was always swallowed by the device alert in front of it, so on the
    // default config nobody was ever told that Jamie was home.
    #[test]
    fn a_device_coming_back_does_not_debounce_its_owners_arrival() {
        let mut d = Dispatcher::new(config(), security(), utc());
        let _ = d.offer(event(1, &mac_of(1), EventType::Returned), base());
        let _ = d.offer(event(2, &mac_of(1), EventType::PersonArrived), base());
        assert_eq!(d.suppressed().debounced, 0);
        assert_eq!(d.pending(), 2);
        let ids: Vec<i64> = d
            .tick(at(60))
            .iter()
            .flat_map(|delivery| delivery.events().iter().map(|e| e.id).collect::<Vec<_>>())
            .collect();
        assert_eq!(ids, [1, 2]);
    }

    #[test]
    fn a_person_event_is_still_debounced_against_the_last_person_event() {
        let mut d = Dispatcher::new(config(), security(), utc());
        let _ = d.offer(event(1, &mac_of(1), EventType::PersonArrived), base());
        let _ = d.offer(event(2, &mac_of(1), EventType::PersonDeparted), at(10));
        assert_eq!(d.suppressed().debounced, 1);
        assert_eq!(d.pending(), 1);
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
        let mut d = Dispatcher::new(cfg, security(), utc());
        let night = Timestamp::from_utc(2026, 2, 2, 23, 30, 0).expect("valid time");
        let _ = d.offer(event(1, &mac_of(1), EventType::NewDevice), night);
        assert_eq!(d.suppressed().quiet_hours, 1);
        assert_eq!(d.pending(), 0);

        let morning = Timestamp::from_utc(2026, 2, 3, 7, 0, 0).expect("valid time");
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
        let rome = Offset::from_seconds(3600).expect("offset");
        let mut d = Dispatcher::new(cfg.clone(), security(), rome);
        let evening = Timestamp::from_utc(2026, 2, 2, 21, 30, 0).expect("valid time");
        let _ = d.offer(event(1, &mac_of(1), EventType::NewDevice), evening);
        assert_eq!(d.suppressed().quiet_hours, 1);

        // The same instant in UTC is 21:30, which is not quiet.
        let mut d = Dispatcher::new(cfg, security(), utc());
        let _ = d.offer(event(1, &mac_of(1), EventType::NewDevice), evening);
        assert_eq!(d.suppressed().quiet_hours, 0);
    }

    #[test]
    fn events_outside_the_configured_types_are_dropped() {
        let mut d = Dispatcher::new(config(), security(), utc());
        // Deliverable (notify is on) but not in this allowlist.
        let _ = d.offer(event(1, &mac_of(1), EventType::WentOffline), base());
        assert_eq!(d.suppressed().wrong_type, 1);
        assert_eq!(d.pending(), 0);
    }

    #[test]
    fn a_learning_window_suppresses_delivery_but_the_event_still_arrived() {
        let mut d = Dispatcher::new(config(), security(), utc());
        let mut e = event(1, &mac_of(1), EventType::NewDevice);
        e.event.during_learning = true;
        let _ = d.offer(e, base());
        assert_eq!(d.suppressed().not_deliverable, 1);
        assert_eq!(d.pending(), 0);
    }

    #[test]
    fn a_device_with_notifications_turned_off_is_silent() {
        let mut d = Dispatcher::new(config(), security(), utc());
        let mut e = event(1, &mac_of(1), EventType::Returned);
        e.event.notify = false;
        let _ = d.offer(e, base());
        assert_eq!(d.suppressed().not_deliverable, 1);
    }

    #[test]
    fn a_new_device_is_delivered_even_when_its_notify_is_off() {
        let mut d = Dispatcher::new(config(), security(), utc());
        let mut e = event(1, &mac_of(1), EventType::NewDevice);
        e.event.notify = false;
        let _ = d.offer(e, base());
        assert_eq!(d.suppressed().not_deliverable, 0);
        assert_eq!(d.tick(at(60)).len(), 1);
    }

    #[test]
    fn an_informational_event_is_never_delivered_even_when_listed() {
        let mut d = Dispatcher::new(
            NotifyConfig {
                event_types: [
                    "ip_changed",
                    "name_updated",
                    "device_location_changed",
                    "went_offline",
                ]
                .map(String::from)
                .to_vec(),
                ..config()
            },
            security(),
            utc(),
        );
        for (n, kind) in [
            EventType::IpChanged,
            EventType::NameUpdated,
            EventType::DeviceLocationChanged,
        ]
        .into_iter()
        .enumerate()
        {
            let id = i64::try_from(n).expect("small");
            let mac = mac_of(u8::try_from(n).expect("small"));
            let _ = d.offer(event(id, &mac, kind), base());
        }
        assert_eq!(d.suppressed().not_deliverable, 3);
        assert!(d.drain().is_empty());
    }

    #[test]
    fn the_default_allowlist_carries_a_chosen_device_coming_and_going() {
        let mut d = Dispatcher::new(NotifyConfig::default(), security(), utc());
        let _ = d.offer(event(1, &mac_of(1), EventType::WentOffline), base());
        let _ = d.offer(event(2, &mac_of(2), EventType::Returned), base());
        assert_eq!(d.suppressed(), SuppressionCounts::default());
        assert_eq!(d.drain().len(), 2);
    }

    #[test]
    fn the_master_switch_stops_everything() {
        let mut d = Dispatcher::new(
            NotifyConfig {
                enabled: false,
                ..config()
            },
            security(),
            utc(),
        );
        let _ = d.offer(event(1, &mac_of(1), EventType::NewDevice), base());
        assert_eq!(d.suppressed().disabled, 1);
        assert_eq!(d.suppressed().total(), 1);
    }

    #[test]
    fn draining_at_shutdown_does_not_lose_a_held_notification() {
        let mut d = Dispatcher::new(config(), security(), utc());
        let _ = d.offer(event(1, &mac_of(1), EventType::NewDevice), base());
        assert_eq!(d.pending(), 1);
        let out = d.drain();
        assert_eq!(out.len(), 1);
        assert!(d.drain().is_empty(), "draining twice sends nothing twice");
    }

    #[test]
    fn a_suppressed_event_still_lets_a_due_window_close() {
        let mut d = Dispatcher::new(config(), security(), utc());
        let _ = d.offer(event(1, &mac_of(1), EventType::NewDevice), base());
        // A second event that is filtered out, arriving after the window is due,
        // must still flush the first one rather than stranding it.
        let out = d.offer(event(2, &mac_of(2), EventType::IpChanged), at(61));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn a_security_event_needs_no_place_in_the_event_type_allowlist() {
        // notify.event_types governs device lifecycle events. Requiring an
        // operator to list arp_spoof there as well would make a silent
        // misconfiguration look like a working setup.
        let mut d = Dispatcher::new(config(), security(), utc());
        let _ = d.offer(event(1, &mac_of(1), EventType::ArpSpoof), base());
        assert_eq!(d.suppressed().wrong_type, 0);
        assert_eq!(d.tick(at(60)).len(), 1);
    }

    #[test]
    fn a_security_event_is_not_debounced_but_pooled() {
        // The failure the old bypass prevented: an attack producing one alert
        // and then silence for five minutes. Pooling keeps every event: three
        // alerts, then the rest counted for a summary.
        let mut d = Dispatcher::new(config(), security(), utc());
        for id in 1..=5 {
            let _ = d.offer(event(id, &mac_of(1), EventType::ArpSpoof), at(id));
        }
        assert_eq!(d.suppressed().debounced, 0);
        assert_eq!(d.pending(), 3);
        assert_eq!(d.pooled(), 2);
    }

    #[test]
    fn security_notifications_can_be_switched_off_on_their_own() {
        let off = SecurityNotifyConfig {
            enabled: false,
            ..SecurityNotifyConfig::default()
        };
        let mut d = Dispatcher::new(config(), off, utc());
        assert!(
            d.offer(event(1, &mac_of(1), EventType::ArpSpoof), base())
                .is_empty()
        );
        assert_eq!(d.suppressed().security_disabled, 1);
        // Device events still work.
        let _ = d.offer(event(2, &mac_of(2), EventType::NewDevice), base());
        assert_eq!(d.pending(), 1);
    }

    #[test]
    fn the_master_switch_has_no_security_exception() {
        // A switch with an exception is not a master switch, and --no-notify
        // has to mean what it says.
        let mut d = Dispatcher::new(
            NotifyConfig {
                enabled: false,
                ..config()
            },
            security(),
            utc(),
        );
        assert!(
            d.offer(event(1, &mac_of(1), EventType::ArpSpoof), base())
                .is_empty()
        );
        assert_eq!(d.suppressed().disabled, 1);
    }

    #[test]
    fn a_learning_window_never_silences_a_security_event() {
        // The security-relevant half: Netgrasp deciding which devices are normal
        // is not a reason to stay quiet while one of them attacks the network.
        let mut d = Dispatcher::new(config(), security(), utc());
        let mut e = event(1, &mac_of(1), EventType::ArpSpoof);
        e.event.during_learning = true;
        e.event.notify = false;
        let _ = d.offer(e, base());
        assert_eq!(d.pending(), 1);
        assert_eq!(d.suppressed().not_deliverable, 0);
    }

    // Pooling and classes. Every test drives the dispatcher's own clock: `at`
    // is the fake clock, and `run` ticks it once a minute the way the daemon's
    // one-second timer would, only coarser.

    const ROUTER: &str = "d0:21:f9:dc:a1:19";

    /// Offers `kind` from `mac` at each of `times` (seconds from `base`),
    /// ticking every minute in between and up to `until`, and returns every
    /// delivery with the second it came out at.
    fn run(
        d: &mut Dispatcher,
        mac: &str,
        kind: EventType,
        times: &[i64],
        until: i64,
    ) -> Vec<(i64, Delivery)> {
        let mut out = Vec::new();
        let mut next = times.iter().peekable();
        let mut id = 0;
        let mut now = 0;
        while now <= until {
            while let Some(&&t) = next.peek()
                && t <= now
            {
                id += 1;
                let mut e = event(id, mac, kind);
                e.event.at = at(t);
                out.extend(d.offer(e, at(t)).into_iter().map(|x| (t, x)));
                next.next();
            }
            out.extend(d.tick(at(now)).into_iter().map(|x| (now, x)));
            now += 60;
        }
        out
    }

    fn reports(out: &[(i64, Delivery)]) -> Vec<(i64, Report)> {
        out.iter()
            .filter_map(|(t, d)| match d {
                Delivery::Report(r) => Some((*t, (**r).clone())),
                _ => None,
            })
            .collect()
    }

    fn instants(out: &[(i64, Delivery)]) -> Vec<&Delivery> {
        out.iter()
            .map(|(_, d)| d)
            .filter(|d| matches!(d, Delivery::Single(_) | Delivery::Noted { .. }))
            .collect()
    }

    fn every(step: i64, from: i64, to: i64) -> Vec<i64> {
        (0..)
            .map(|n| from + n * step)
            .take_while(|t| *t <= to)
            .collect()
    }

    #[test]
    fn three_alerts_go_out_at_once_and_the_third_says_pooling_starts() {
        let mut d = Dispatcher::new(config(), security(), utc());
        // An ARP scan every 30 seconds for ten minutes.
        let out = run(&mut d, ROUTER, EventType::ArpScan, &every(30, 0, 600), 600);
        let sent = instants(&out);
        assert_eq!(sent.len(), 3, "{out:#?}");
        assert!(matches!(sent[0], Delivery::Single(_)));
        assert!(matches!(sent[1], Delivery::Single(_)));
        match sent[2] {
            Delivery::Noted { note, .. } => assert_eq!(
                note,
                "More alerts like this from d0:21:f9:dc:a1:19 will be pooled: \
                 one summary every hour."
            ),
            other => panic!("the third alert carries the note, got {other:?}"),
        }
        assert!(reports(&out).is_empty(), "no summary inside the first hour");
        assert_eq!(d.pooled(), 18, "the other 18 are held for the summary");
    }

    #[test]
    fn a_pooled_source_gets_one_summary_per_period_with_the_right_count() {
        let mut d = Dispatcher::new(config(), security(), utc());
        // Every 5 minutes for 3 hours: 37 events. The third, at 10 minutes,
        // starts pooling; summaries are due at 1h10 and 2h10, and the 3h10
        // one is not due yet.
        let out = run(
            &mut d,
            ROUTER,
            EventType::ArpScan,
            &every(300, 0, 10_800),
            10_800,
        );
        let summaries = reports(&out);
        assert_eq!(summaries.len(), 2, "{summaries:#?}");
        let (t1, first) = &summaries[0];
        let (t2, second) = &summaries[1];
        assert_eq!((*t1, *t2), (4200, 7800));
        // Held for the first: 15m to 65m. An event at the very second a
        // summary is due waits for the next one, so the second holds 70m to
        // 125m.
        assert_eq!(first.events.len(), 11);
        assert_eq!(second.events.len(), 12);
        assert_eq!(first.kind, ReportKind::Pooled);
        assert_eq!(
            first.body,
            "11 more alerts like this from d0:21:f9:dc:a1:19 between 12:15 and 13:05.\n\
             Next summary at 14:10 if it continues."
        );
        assert!(first.title.starts_with("ARP scan from"), "{}", first.title);
        assert!(first.title.ends_with("(11 more)"), "{}", first.title);
        // Nothing lost: 3 instants, 23 summarised, 11 still held.
        assert_eq!(instants(&out).len(), 3);
        assert_eq!(d.pooled(), 11);
    }

    #[test]
    fn a_source_repeating_for_a_day_backs_off_and_the_summary_says_so() {
        let mut d = Dispatcher::new(config(), security(), utc());
        let day = 24 * 3600;
        // Every 10 minutes for 50 hours, never a gap of an hour.
        let out = run(
            &mut d,
            ROUTER,
            EventType::ArpScan,
            &every(600, 0, 50 * 3600),
            50 * 3600,
        );
        let summaries = reports(&out);
        // Hourly from 1h20 (the third alert was at 20 minutes) up to the first
        // summary at or past 24 hours, then one 24 hours after that.
        let times: Vec<i64> = summaries.iter().map(|(t, _)| *t).collect();
        let hourly: Vec<i64> = every(3600, 4800, day + 1200);
        let mut expected = hourly.clone();
        expected.push(day + 1200 + day);
        assert_eq!(times, expected);
        let switching = &summaries[hourly.len() - 1].1;
        assert!(
            switching.body.ends_with(
                "It has repeated for 24 hours without a break of an hour, so summaries now \
                 come once every 24 hours."
            ),
            "{}",
            switching.body
        );
        for (_, earlier) in &summaries[..hourly.len() - 1] {
            assert!(!earlier.body.contains("repeated for"), "{}", earlier.body);
        }
        assert!(
            !summaries
                .last()
                .expect("one")
                .1
                .body
                .contains("repeated for")
        );
        assert_eq!(instants(&out).len(), 3, "no instant alert in 50 hours");
    }

    #[test]
    fn an_hour_of_quiet_closes_the_pool_and_the_next_event_alerts_at_once() {
        let mut d = Dispatcher::new(config(), security(), utc());
        // Four events a minute apart: three alerts and one held. Then silence
        // for an hour, then one more.
        let out = run(
            &mut d,
            ROUTER,
            EventType::ArpScan,
            &[0, 60, 120, 180, 180 + 3600 + 60],
            180 + 3600 + 120,
        );
        let summaries = reports(&out);
        assert_eq!(summaries.len(), 1, "{summaries:#?}");
        let (t, closing) = &summaries[0];
        assert_eq!(
            *t,
            120 + 3600,
            "the summary due at the hour carries the held one"
        );
        assert_eq!(closing.events.len(), 1);
        let sent = instants(&out);
        assert_eq!(
            sent.len(),
            4,
            "the event after the quiet hour alerts at once"
        );
        assert!(matches!(sent[3], Delivery::Single(_)), "{:?}", sent[3]);
    }

    #[test]
    fn a_pool_that_goes_quiet_before_its_summary_is_due_sends_what_it_held() {
        let mut class = default_classes().remove("anomaly").expect("anomaly");
        class.pool_period = HumanDuration::from_secs(4 * 3600);
        let cfg = NotifyConfig {
            classes: BTreeMap::from([("anomaly".to_string(), class)]),
            ..config()
        };
        let mut d = Dispatcher::new(cfg, security(), utc());
        let out = run(
            &mut d,
            ROUTER,
            EventType::ArpScan,
            &[0, 60, 120, 180, 240],
            4 * 3600,
        );
        let summaries = reports(&out);
        assert_eq!(summaries.len(), 1, "{summaries:#?}");
        assert_eq!(summaries[0].0, 240 + 3600, "closed after an hour of quiet");
        assert_eq!(summaries[0].1.events.len(), 2);
        assert!(
            summaries[0]
                .1
                .body
                .ends_with("It has been quiet for an hour, so the next one alerts at once."),
            "{}",
            summaries[0].1.body
        );
        assert_eq!(d.pooled(), 0);
    }

    #[test]
    fn each_source_and_each_type_is_pooled_on_its_own() {
        let mut d = Dispatcher::new(config(), security(), utc());
        let mut sent = 0;
        for id in 1..=3 {
            let _ = d.offer(event(id, &mac_of(1), EventType::ArpScan), at(id));
        }
        // The same router again: pooled.
        let _ = d.offer(event(4, &mac_of(1), EventType::ArpScan), at(4));
        // A different source, and a different type from the same source: each
        // gets its own first alert.
        let _ = d.offer(event(5, &mac_of(2), EventType::ArpScan), at(5));
        let _ = d.offer(event(6, &mac_of(1), EventType::IpConflict), at(6));
        for delivery in d.tick(at(70)) {
            sent += delivery.events().len();
        }
        assert_eq!(sent, 5);
        assert_eq!(d.pooled(), 1);
    }

    #[test]
    fn a_zero_instant_count_pools_from_the_first_event() {
        let mut class = default_classes().remove("anomaly").expect("anomaly");
        class.instant_count = 0;
        let cfg = NotifyConfig {
            classes: BTreeMap::from([("anomaly".to_string(), class)]),
            ..config()
        };
        let mut d = Dispatcher::new(cfg, security(), utc());
        let out = run(
            &mut d,
            ROUTER,
            EventType::ArpScan,
            &every(600, 0, 3000),
            3600,
        );
        assert!(instants(&out).is_empty(), "{out:#?}");
        let summaries = reports(&out);
        assert_eq!(summaries.len(), 1);
        assert_eq!(
            summaries[0].0, 3600,
            "at the end of the first event's period"
        );
        assert_eq!(summaries[0].1.events.len(), 6);
    }

    #[test]
    fn a_digest_class_sends_nothing_until_the_digest_time() {
        // base() is 12:00 UTC; with a UTC clock the digest is due at 08:00
        // the next morning.
        let mut d = Dispatcher::new(config(), security(), utc());
        let mut out = Vec::new();
        for (id, (mac, kind)) in [
            (1, EventType::GratuitousArp),
            (1, EventType::GratuitousArp),
            (2, EventType::GratuitousArp),
            (2, EventType::IdentityChange),
        ]
        .into_iter()
        .enumerate()
        {
            let id = i64::try_from(id).expect("small");
            out.extend(d.offer(event(id, &mac_of(mac), kind), at(id * 60)));
        }
        let until = 20 * 3600 - 60;
        for minute in 0..=until / 60 {
            out.extend(d.tick(at(minute * 60)));
        }
        assert!(out.is_empty(), "nothing before 08:00: {out:#?}");
        assert_eq!(d.digest_waiting(), 4);
        let digest = d.tick(at(20 * 3600));
        assert_eq!(digest.len(), 1);
        let Delivery::Report(report) = &digest[0] else {
            panic!("expected the digest, got {digest:?}");
        };
        assert_eq!(report.kind, ReportKind::Digest);
        assert_eq!(report.title, "Netgrasp daily digest: 4 alerts");
        assert_eq!(
            report.body,
            "identity: 4\n  \
               gratuitous_arp: 3\n    \
                 2 from device 1 (3c:22:fb:00:00:01)\n    \
                 1 from device 2 (3c:22:fb:00:00:02)\n  \
               identity_change: 1\n    \
                 1 from device 3 (3c:22:fb:00:00:02)"
        );
        assert_eq!(report.events.len(), 4);
        assert!(d.tick(at(20 * 3600 + 60)).is_empty(), "once a day");
    }

    #[test]
    fn only_a_class_that_ignores_quiet_hours_delivers_inside_them() {
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
        let mut d = Dispatcher::new(cfg, security(), utc());
        let night = Timestamp::from_utc(2026, 2, 2, 23, 30, 0).expect("valid time");
        // intrusion ignores quiet hours.
        let _ = d.offer(event(1, &mac_of(1), EventType::ArpSpoof), night);
        assert_eq!(d.pending(), 1);
        // anomaly and presence respect them.
        let _ = d.offer(event(2, &mac_of(2), EventType::ArpScan), night);
        let _ = d.offer(event(3, &mac_of(3), EventType::NewDevice), night);
        assert_eq!(d.suppressed().quiet_hours, 2);
        let out = d.tick(night + SignedDuration::from_secs(60));
        let ids: Vec<i64> = out.iter().flat_map(|x| x.events()).map(|e| e.id).collect();
        assert_eq!(ids, [1]);
    }

    #[test]
    fn an_off_class_records_and_never_delivers() {
        let mut anomaly = default_classes().remove("anomaly").expect("anomaly");
        anomaly.delivery = ClassDelivery::Off;
        let cfg = NotifyConfig {
            classes: BTreeMap::from([("anomaly".to_string(), anomaly)]),
            ..config()
        };
        let mut d = Dispatcher::new(cfg, security(), utc());
        let _ = d.offer(event(1, &mac_of(1), EventType::ArpScan), base());
        assert_eq!(d.suppressed().class_off, 1);
    }

    #[test]
    fn an_unclassified_security_type_is_pooled_as_an_anomaly() {
        // Only arp_scan is classified; arp_spoof falls back to anomaly rather
        // than going silent.
        let anomaly = AlertClass {
            event_types: vec!["arp_scan".into()],
            ..AlertClass::default()
        };
        let cfg = NotifyConfig {
            classes: BTreeMap::from([("anomaly".to_string(), anomaly)]),
            ..config()
        };
        let mut d = Dispatcher::new(cfg, security(), utc());
        for id in 1..=4 {
            let _ = d.offer(event(id, &mac_of(1), EventType::ArpSpoof), at(id));
        }
        assert_eq!(d.pending(), 3);
        assert_eq!(d.pooled(), 1);
        // A lifecycle type in no class is off.
        let _ = d.offer(event(9, &mac_of(9), EventType::NewDevice), at(9));
        assert_eq!(d.suppressed().class_off, 1);
    }

    #[test]
    fn an_approved_device_is_quiet_about_its_routine_types_and_nothing_else() {
        let mut d = Dispatcher::new(config(), security(), utc());
        for (id, kind) in [
            EventType::IdentityChange,
            EventType::GratuitousArp,
            EventType::IpConflict,
            EventType::ArpSpoof,
            EventType::RogueDhcp,
        ]
        .into_iter()
        .enumerate()
        {
            let mut e = event(i64::try_from(id).expect("small"), &mac_of(1), kind);
            e.event.approved = true;
            let _ = d.offer(e, base());
        }
        assert_eq!(d.suppressed().approved_quiet, 3);
        assert_eq!(d.digest_waiting(), 0, "not even in the digest");
        assert_eq!(d.pending(), 2, "arp_spoof and rogue_dhcp alert whatever");
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
