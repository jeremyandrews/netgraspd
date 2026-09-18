//! The device state machine.
//!
//! [`Manager`] is deliberately pure: it holds the MAC-keyed in-memory table,
//! decides what changed, and returns a list of [`Effect`]s. It never touches
//! Postgres and never awaits anything, which is what makes every transition and
//! every edge case a plain synchronous test.
//!
//! [`persist`] applies effects to the database. That split is also what keeps
//! the "state changes are stored, raw observations are not" rule enforceable by
//! inspection: the effect list has no variant that could write a row per packet.
//!
//! Effects are keyed by MAC rather than by database id, so the manager needs no
//! knowledge of primary keys and a device can be created and observed in the
//! same batch.

pub mod persist;

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::json;

use crate::analyze::SecurityAlert;
use crate::config::StateConfig;
use crate::db::queries::{DeviceRecord, UserSettings};
use crate::identity::classify::{ALWAYS_ON_HOURS, Classification, ClassifyInput};
use crate::identity::{self, Identity};
use crate::types::{
    DeviceState, EventPriority, EventType, MacAddr, Observation, Signal, SignalKind,
};

/// Something the state machine decided, for the persistence layer to apply.
#[derive(Debug, Clone, PartialEq)]
pub enum Effect {
    /// A MAC never seen before. Create the row.
    Discovered(Box<DeviceSnapshot>),
    /// A state change worth recording and possibly announcing.
    Event(Box<DeviceEvent>),
    /// Identity evidence to store, so later signals refine rather than
    /// overwrite.
    Signal {
        /// Which device.
        mac: MacAddr,
        /// The evidence.
        signal: Signal,
        /// When it was seen.
        at: DateTime<Utc>,
    },
    /// An address the device is holding.
    Address {
        /// Which device.
        mac: MacAddr,
        /// The address, rendered.
        ip: String,
        /// Interface it was seen on.
        interface: String,
        /// When it was seen.
        at: DateTime<Utc>,
    },
    /// A presence session started.
    PresenceOpened {
        /// Which device.
        mac: MacAddr,
        /// Interface the session is on.
        interface: String,
        /// Address at the time the session opened.
        ip: Option<String>,
        /// When it opened.
        at: DateTime<Utc>,
    },
    /// A presence session ended.
    PresenceClosed {
        /// Which device.
        mac: MacAddr,
        /// When it ended.
        at: DateTime<Utc>,
    },
    /// A device is somewhere new. Closes the open location stay and opens
    /// another, which is one effect rather than two so that the "at most one
    /// open stay per device" invariant cannot be broken by applying half of it.
    LocationChanged {
        /// Which device.
        mac: MacAddr,
        /// The access point it is now on.
        ap_name: Option<String>,
        /// The place that access point is in.
        location: String,
        /// When it moved.
        at: DateTime<Utc>,
    },
    /// A device is no longer anywhere: it went offline, so its stay ends and no
    /// new one opens until an enricher places it again.
    LocationClosed {
        /// Which device.
        mac: MacAddr,
        /// When the stay ended.
        at: DateTime<Utc>,
    },
}

/// A state change worth recording.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceEvent {
    /// What happened.
    pub event_type: EventType,
    /// Which device.
    pub mac: MacAddr,
    /// Name to show in the notification.
    pub display_name: String,
    /// Vendor, when known.
    pub vendor: Option<String>,
    /// Address at the time, when known.
    pub ip: Option<String>,
    /// Interface, when known.
    pub interface: Option<String>,
    /// When it happened.
    pub at: DateTime<Utc>,
    /// True when the device belongs to the learned baseline, which suppresses
    /// the notification but never the record.
    pub baseline: bool,
    /// True when the daemon was inside a learning window, likewise.
    pub during_learning: bool,
    /// The user's per-device notification toggle.
    pub notify: bool,
    /// How loudly to deliver this, when the transport understands priority.
    pub priority: EventPriority,
    /// Structured detail for `ng_events.details`.
    pub details: serde_json::Value,
}

impl DeviceEvent {
    /// Whether this event should reach a notifier at all.
    ///
    /// Learning-window suppression happens here and nowhere else, so that the
    /// record in `ng_events` is written either way. A security tool that forgets
    /// events during its own warm-up is worse than one that stays quiet.
    ///
    /// Security events are never suppressed. A learning window is Netgrasp
    /// deciding which devices are normal; it is not a reason to stay quiet while
    /// one of them poisons the ARP table. The per-device `notify` toggle is
    /// likewise ignored for them: it means "stop telling me when this device
    /// comes and goes", not "let this device attack the network in silence".
    #[must_use]
    pub const fn deliverable(&self) -> bool {
        if self.event_type.is_security() {
            return true;
        }
        self.notify && !self.during_learning
    }
}

/// A device whose classification changed.
///
/// Produced by the state machine and consumed by the `identity_change`
/// analyzer, which decides whether the change is worth an event. The state
/// machine deliberately does not make that call itself: whether a first
/// classification counts as a change is policy, and policy belongs with the
/// analyzers and their config.
#[derive(Debug, Clone, PartialEq)]
pub struct Reclassification {
    /// Which device.
    pub mac: MacAddr,
    /// Name to show in an alert about it.
    pub display_name: String,
    /// What it was classified as before.
    pub previous: Classification,
    /// What it is classified as now.
    pub current: Classification,
    /// Interface it was last seen on.
    pub interface: Option<String>,
    /// When the change happened.
    pub at: DateTime<Utc>,
}

/// The daemon-owned view of a device, used for flushes and for the CLI table.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceSnapshot {
    /// Hardware address.
    pub mac: MacAddr,
    /// Lifecycle state.
    pub state: DeviceState,
    /// Most recent IPv4 address.
    pub last_ip: Option<String>,
    /// Most recent IPv6 address, global preferred over link-local.
    pub last_ipv6: Option<String>,
    /// Interface last seen on.
    pub last_interface: Option<String>,
    /// First sighting.
    pub first_seen_at: DateTime<Utc>,
    /// Most recent sighting.
    pub last_seen_at: DateTime<Utc>,
    /// Learned during a baseline window.
    pub baseline: bool,
    /// Name the scorer picked.
    pub identity: Identity,
    /// User-assigned name, read back from Trovato. The daemon never writes it.
    pub display_name: Option<String>,
    /// Best host name signal.
    pub hostname: Option<String>,
    /// Best mDNS instance name signal.
    pub mdns_name: Option<String>,
    /// Vendor.
    pub vendor: Option<String>,
    /// Classified device type.
    pub device_type: Option<String>,
    /// How much to trust the device type.
    pub device_type_confidence: Option<f32>,
    /// Classified operating system family.
    pub os_family: Option<String>,
    /// The access point it is associated with, when an enricher has said.
    ///
    /// Cleared when the device goes offline: where an offline device is, is
    /// nowhere, and the history of where it has been lives in
    /// `ng_location_history`.
    pub current_ap: Option<String>,
    /// The place that access point is in.
    pub current_location: Option<String>,
    /// Observations counted since the last flush, added to the open presence
    /// session's counter. This is the only number that summarises packet volume,
    /// and it is a counter rather than a row per packet on purpose.
    pub observations_since_flush: i64,
}

impl DeviceSnapshot {
    /// The name to show a human.
    #[must_use]
    pub fn display(&self) -> String {
        self.display_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map_or_else(|| self.identity.display_name.clone(), str::to_string)
    }
}

/// One device's in-memory state.
#[derive(Debug, Clone)]
struct Entry {
    mac: MacAddr,
    state: DeviceState,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    last_ip: Option<String>,
    last_ipv6: Option<String>,
    last_interface: Option<String>,
    /// Every stored signal, most recently confirmed first, which is the order
    /// the scorer breaks ties in.
    signals: Vec<Signal>,
    identity: Identity,
    classification: Classification,
    display_name: Option<String>,
    current_ap: Option<String>,
    current_location: Option<String>,
    baseline: bool,
    notify: bool,
    /// How many times this device has been seen to go offline **since the
    /// daemon started**. The behavioural classifier reads it, and it is not
    /// persisted: a restart resets it to zero, which makes the weakest
    /// classification signal briefly optimistic and nothing else.
    offline_transitions: u32,
    observations_since_flush: i64,
    dirty: bool,
}

impl Entry {
    fn snapshot(&self) -> DeviceSnapshot {
        DeviceSnapshot {
            mac: self.mac,
            state: self.state,
            last_ip: self.last_ip.clone(),
            last_ipv6: self.last_ipv6.clone(),
            last_interface: self.last_interface.clone(),
            first_seen_at: self.first_seen_at,
            last_seen_at: self.last_seen_at,
            baseline: self.baseline,
            identity: self.identity.clone(),
            display_name: self.display_name.clone(),
            hostname: self.best(SignalKind::ReverseDns),
            mdns_name: self.best(SignalKind::MdnsName),
            vendor: self.best(SignalKind::Vendor),
            device_type: self.classification.device_type.clone(),
            #[allow(clippy::cast_possible_truncation)] // Confidence is in
            // [0.0, 1.0] and stored as REAL; f64 to f32 loses nothing here.
            device_type_confidence: self
                .classification
                .device_type
                .is_some()
                .then_some(self.classification.confidence as f32),
            os_family: self.classification.os_family.clone(),
            current_ap: self.current_ap.clone(),
            current_location: self.current_location.clone(),
            observations_since_flush: self.observations_since_flush,
        }
    }

    /// Records an IPv6 address as the device's current one.
    ///
    /// A global address always wins over a link-local one. Every IPv6 device has
    /// a link-local address derived from its MAC, so it carries no information
    /// the MAC does not already carry; showing it in place of the global address
    /// would be showing the least useful of the two.
    fn record_ipv6(&mut self, addr: std::net::Ipv6Addr) {
        let incoming_is_link_local = crate::capture::ndp::is_link_local(addr);
        let keep_existing = incoming_is_link_local
            && self
                .last_ipv6
                .as_deref()
                .and_then(|existing| existing.parse::<std::net::Ipv6Addr>().ok())
                .is_some_and(|existing| !crate::capture::ndp::is_link_local(existing));
        if !keep_existing {
            self.last_ipv6 = Some(addr.to_string());
        }
    }

    /// True when the device has been continuously present long enough for that
    /// to mean something.
    fn always_on(&self, now: DateTime<Utc>) -> bool {
        self.offline_transitions == 0
            && self.state != DeviceState::Offline
            && (now - self.first_seen_at).num_hours() >= ALWAYS_ON_HOURS
    }

    /// Recomputes the device type and OS family, returning the previous
    /// classification when anything changed.
    fn reclassify(&mut self, now: DateTime<Utc>) -> Option<Classification> {
        let vendor = self.best(SignalKind::Vendor);
        let candidate = identity::classify(&ClassifyInput {
            mac: self.mac,
            signals: &self.signals,
            vendor: vendor.as_deref(),
            always_on: self.always_on(now),
        });
        if candidate.changed_at_all(&self.classification) {
            Some(std::mem::replace(&mut self.classification, candidate))
        } else {
            // The reason string can shift without the conclusion changing, for
            // instance when a stronger signal arrives that agrees. Keep the
            // newer reason so the stored explanation stays current.
            self.classification = candidate;
            None
        }
    }

    /// Most recently confirmed value of one signal kind.
    fn best(&self, kind: SignalKind) -> Option<String> {
        self.signals
            .iter()
            .find(|s| s.kind == kind && !s.value.trim().is_empty())
            .map(|s| s.value.clone())
    }

    /// Records a batch of signals from one source, most recently confirmed
    /// first.
    ///
    /// The batch is inserted at the front **as a block**, preserving the order
    /// the source offered it. That ordering is meaningful: an mDNS packet lists
    /// the instance name (which a human chose) before the host name (which a
    /// vendor chose), and both are `MdnsName` signals, so the scorer's
    /// same-kind tie-break is the only thing that keeps `Living Room Apple TV`
    /// from losing to `living-room-apple-tv`. Inserting them one at a time
    /// would silently reverse the batch.
    ///
    /// Returns true when any of them was new evidence rather than a repeat.
    fn record_signals(&mut self, incoming: &[Signal]) -> bool {
        let mut any_new = false;
        let mut batch: Vec<Signal> = Vec::with_capacity(incoming.len());
        for signal in incoming {
            if batch
                .iter()
                .any(|s| s.kind == signal.kind && s.value == signal.value)
            {
                continue;
            }
            match self
                .signals
                .iter()
                .position(|s| s.kind == signal.kind && s.value == signal.value)
            {
                Some(pos) => {
                    self.signals.remove(pos);
                }
                None => any_new = true,
            }
            batch.push(signal.clone());
        }
        for signal in batch.into_iter().rev() {
            self.signals.insert(0, signal);
        }
        any_new
    }

    fn rescore(&mut self) -> Option<Identity> {
        let candidate = identity::resolve(&identity::IdentityInput {
            mac: self.mac,
            signals: &self.signals,
            device_type: self.classification.device_type.as_deref(),
        });
        if identity::improves_on(&candidate, &self.identity) {
            let previous = std::mem::replace(&mut self.identity, candidate);
            Some(previous)
        } else {
            None
        }
    }
}

/// One user-owned column the daemon keeps a copy of in memory, and how to fold
/// the stored value into an entry.
///
/// A list rather than a hand-written block of assignments, for the same reason
/// the plugin keeps a `USER_OWNED` list on its side: the merge then names every
/// column it touches, and a column that is not on the list cannot be reached by
/// accident. `apply` returns the old and new value when it changed something and
/// `None` when it did not, which is what makes the tick quiet on the usual pass
/// where nobody has edited anything.
struct UserOwnedColumn {
    /// The column's name in `ng_devices`.
    name: &'static str,
    /// Folds one column in, reporting a change as `(from, to)`.
    apply: fn(&mut Entry, &UserSettings) -> Option<(String, String)>,
}

/// The user-owned columns the in-memory table holds.
///
/// The other three are elsewhere by design: `owner_item_id` belongs to the
/// people registry, and `hidden` and `notes` have no daemon-side consumer at all
/// (see [`UserSettings`]). `USER_OWNED_COLUMNS_NOT_STORED` below names those
/// three so a test can assert the two lists together still account for every
/// user-owned column.
const USER_OWNED_COLUMNS: &[UserOwnedColumn] = &[
    UserOwnedColumn {
        name: "display_name",
        apply: |entry, settings| {
            if entry.display_name == settings.display_name {
                return None;
            }
            let from = entry.display_name.clone().unwrap_or_default();
            entry.display_name.clone_from(&settings.display_name);
            Some((from, settings.display_name.clone().unwrap_or_default()))
        },
    },
    UserOwnedColumn {
        name: "notify",
        apply: |entry, settings| {
            if entry.notify == settings.notify {
                return None;
            }
            let from = entry.notify;
            entry.notify = settings.notify;
            Some((from.to_string(), settings.notify.to_string()))
        },
    },
];

/// The user-owned columns the in-memory device table does not hold.
///
/// Only the drift guard reads it: its whole job is to fail when somebody adds a
/// user-owned column and puts it in neither list.
#[cfg(test)]
const USER_OWNED_COLUMNS_NOT_STORED: [&str; 3] = ["notes", "hidden", "owner_item_id"];

/// One user-owned value a reconcile changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserChange {
    /// Which device.
    pub mac: MacAddr,
    /// Which column, named as `ng_devices` names it.
    pub column: &'static str,
    /// What the daemon held.
    pub from: String,
    /// What the database says.
    pub to: String,
}

/// The MAC-keyed device table and the transitions over it.
pub struct Manager {
    devices: HashMap<MacAddr, Entry>,
    config: StateConfig,
    learning: bool,
    /// Classification changes waiting to be handed to the analyzer chain.
    reclassifications: Vec<Reclassification>,
}

impl Manager {
    /// Builds an empty manager.
    #[must_use]
    pub fn new(config: StateConfig, learning: bool) -> Self {
        Manager {
            devices: HashMap::new(),
            config,
            learning,
            reclassifications: Vec::new(),
        }
    }

    /// Takes every classification change since the last call.
    ///
    /// The caller feeds these to the analyzer chain, which decides whether a
    /// change is worth an event. Draining rather than returning a reference so
    /// that a caller which never asks cannot grow the list without bound.
    #[must_use]
    pub fn take_reclassifications(&mut self) -> Vec<Reclassification> {
        std::mem::take(&mut self.reclassifications)
    }

    /// Whether a learning window is in progress.
    #[must_use]
    pub const fn is_learning(&self) -> bool {
        self.learning
    }

    /// Ends the learning window. Devices keep their baseline flag; new devices
    /// discovered from now on do not get one.
    pub const fn end_learning(&mut self) {
        self.learning = false;
    }

    /// How many devices are known.
    #[must_use]
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// True when nothing is known yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// How many devices are in each state.
    #[must_use]
    pub fn state_counts(&self) -> (usize, usize, usize) {
        let mut counts = (0, 0, 0);
        for entry in self.devices.values() {
            match entry.state {
                DeviceState::Online => counts.0 += 1,
                DeviceState::Idle => counts.1 += 1,
                DeviceState::Offline => counts.2 += 1,
            }
        }
        counts
    }

    /// Rehydrates the table from Postgres at startup.
    ///
    /// Restored devices do not re-emit `new_device`: that is the whole point of
    /// persisting them, and the alternative is a notification storm on every
    /// restart.
    ///
    /// The stored classification is trusted as the starting point rather than
    /// being recomputed from scratch, so that a device does not appear to change
    /// identity every time the daemon restarts. It is recomputed on the next
    /// signal like any other.
    pub fn restore(&mut self, records: Vec<DeviceRecord>, mut signals: HashMap<i64, Vec<Signal>>) {
        for record in records {
            let stored = signals.remove(&record.id).unwrap_or_default();
            let identity = identity::resolve(&identity::IdentityInput {
                mac: record.mac,
                signals: &stored,
                device_type: record.device_type.as_deref(),
            });
            let classification = Classification {
                device_type: record.device_type,
                os_family: record.os_family,
                confidence: record.device_type_confidence.map_or(0.0, f64::from),
                reason: None,
            };
            // An offline device is nowhere, so its stored place is dropped
            // rather than restored. Keeping it would leave a device that went
            // offline weeks ago still apparently sitting in the kitchen, and
            // would stop the next enrichment poll from opening a fresh stay
            // because the access point would compare equal.
            let placed = record.state != DeviceState::Offline;
            self.devices.insert(
                record.mac,
                Entry {
                    mac: record.mac,
                    state: record.state,
                    first_seen_at: record.first_seen_at,
                    last_seen_at: record.last_seen_at,
                    last_ip: record.last_ip,
                    last_ipv6: record.last_ipv6,
                    last_interface: record.last_interface,
                    signals: stored,
                    identity,
                    classification,
                    display_name: record.display_name,
                    current_ap: record.current_ap.filter(|_| placed),
                    current_location: record.current_location.filter(|_| placed),
                    baseline: record.baseline,
                    notify: record.notify,
                    offline_transitions: 0,
                    observations_since_flush: 0,
                    dirty: false,
                },
            );
        }
    }

    /// Folds the user-owned columns back in, without disturbing anything else.
    ///
    /// [`restore`](Self::restore) reads them once at startup; this is how a
    /// change made from the web or by the assistant reaches a running daemon.
    /// Only the columns in `USER_OWNED_COLUMNS` are touched, and only in the
    /// direction database to memory: state, timestamps, signals, identity and
    /// location are the daemon's and the in-memory copy of them is newer than
    /// the database's between flushes.
    ///
    /// A changed device is deliberately **not** marked dirty. Dirty means "the
    /// daemon has something to write", and it has not: these columns are absent
    /// from its update statement by design, so flushing them back would be a
    /// round trip that writes nothing and a `sync_state = 'dirty'` the plugin's
    /// cron sweep then has to pick up for no reason.
    ///
    /// A MAC in the database that the table has never seen is skipped rather
    /// than inserted: discovery is the capture path's job, and a row the plugin
    /// created for a device that has not been on the network yet has no state
    /// machine to join.
    #[must_use]
    pub fn apply_user_settings(&mut self, settings: &[UserSettings]) -> Vec<UserChange> {
        let mut changes = Vec::new();
        for setting in settings {
            let Some(entry) = self.devices.get_mut(&setting.mac) else {
                continue;
            };
            for column in USER_OWNED_COLUMNS {
                if let Some((from, to)) = (column.apply)(entry, setting) {
                    changes.push(UserChange {
                        mac: setting.mac,
                        column: column.name,
                        from,
                        to,
                    });
                }
            }
        }
        changes
    }

    /// One device's lifecycle state and last sighting, when it is known.
    ///
    /// Enough to seed the people registry for a device that has just acquired an
    /// owner, and deliberately not a whole snapshot: the caller needs to know
    /// whether the device is online and when it was last heard from, and
    /// handing it anything more invites a second source of truth.
    #[must_use]
    pub fn state_of(&self, mac: MacAddr) -> Option<(DeviceState, DateTime<Utc>)> {
        self.devices
            .get(&mac)
            .map(|entry| (entry.state, entry.last_seen_at))
    }

    /// Folds one observation into the table.
    #[must_use]
    pub fn observe(&mut self, obs: &Observation) -> Vec<Effect> {
        // Group and all-zero addresses never identify a device. The parsers
        // already reject them, so reaching here means a new source got it wrong.
        if obs.mac.is_group() || obs.mac.is_zero() {
            tracing::debug!(mac = %obs.mac, source = obs.source, "ignoring a non-device MAC");
            return Vec::new();
        }

        let mut effects = Vec::new();
        let at = obs.observed_at;
        let known = self.devices.contains_key(&obs.mac);

        if !known {
            effects.extend(self.discover(obs));
        }

        let learning = self.learning;
        let config = self.config.clone();
        let Some(entry) = self.devices.get_mut(&obs.mac) else {
            return effects;
        };

        // Clock skew between capture sources, or a replayed capture, must not
        // drag last_seen_at backwards.
        if at > entry.last_seen_at {
            entry.last_seen_at = at;
        }
        entry.observations_since_flush += 1;
        entry.dirty = true;

        // A device that had gone offline is back.
        if entry.state == DeviceState::Offline {
            entry.state = DeviceState::Online;
            effects.push(Effect::PresenceOpened {
                mac: entry.mac,
                interface: obs.interface.clone(),
                ip: ipv4_string(obs.ip),
                at,
            });
            effects.push(Effect::Event(Box::new(DeviceEvent {
                event_type: EventType::Returned,
                mac: entry.mac,
                display_name: entry.snapshot().display(),
                vendor: entry.best(SignalKind::Vendor),
                ip: ipv4_string(obs.ip),
                interface: Some(obs.interface.clone()),
                at,
                baseline: entry.baseline,
                during_learning: learning,
                notify: entry.notify,
                priority: EventPriority::Normal,
                details: json!({ "source": obs.source, "interface": obs.interface }),
            })));
        } else if entry.state == DeviceState::Idle {
            // Idle to online is not an event: the device never left, it just
            // stopped talking for a while.
            entry.state = DeviceState::Online;
        }

        // Addresses. Only IPv4 moves last_ip and can raise ip_changed; an IPv6
        // sighting updates last_ipv6 and ng_ip_history but raises nothing,
        // because RFC 4941 privacy addresses rotate and a dual-stack device
        // would otherwise emit meaningless ip_changed events forever. See the
        // note in capture/ndp.rs, where this decision was reviewed once NDP
        // landed and kept.
        if let Some(ip) = obs.ip
            && is_recordable(ip)
        {
            effects.push(Effect::Address {
                mac: entry.mac,
                ip: ip.to_string(),
                interface: obs.interface.clone(),
                at,
            });
            if let Some(v4) = ipv4_string(Some(ip)) {
                let changed = entry.last_ip.as_deref().is_some_and(|old| old != v4);
                let previous = entry.last_ip.clone();
                entry.last_ip = Some(v4.clone());
                if changed {
                    effects.push(Effect::Event(Box::new(DeviceEvent {
                        event_type: EventType::IpChanged,
                        mac: entry.mac,
                        display_name: entry.snapshot().display(),
                        vendor: entry.best(SignalKind::Vendor),
                        ip: Some(v4.clone()),
                        interface: Some(obs.interface.clone()),
                        at,
                        baseline: entry.baseline,
                        during_learning: learning,
                        notify: entry.notify,
                        priority: EventPriority::Normal,
                        details: json!({
                            "previous_ip": previous,
                            "new_ip": v4,
                            "interface": obs.interface,
                        }),
                    })));
                }
            }
            if let IpAddr::V6(v6) = ip {
                entry.record_ipv6(v6);
            }
        }
        entry.last_interface = Some(obs.interface.clone());

        // Identity evidence. Recorded as one batch so that the order the source
        // listed them in survives; see `record_signals`.
        let usable: Vec<Signal> = obs
            .signals
            .iter()
            .filter(|s| !s.value.trim().is_empty())
            .cloned()
            .collect();
        entry.record_signals(&usable);
        for signal in usable {
            effects.push(Effect::Signal {
                mac: entry.mac,
                signal,
                at,
            });
        }
        if let Some(previous) = entry.rescore()
            && !matches!(effects.first(), Some(Effect::Discovered(_)))
        {
            effects.push(Effect::Event(Box::new(DeviceEvent {
                event_type: EventType::NameUpdated,
                mac: entry.mac,
                display_name: entry.snapshot().display(),
                vendor: entry.best(SignalKind::Vendor),
                ip: entry.last_ip.clone(),
                interface: Some(obs.interface.clone()),
                at,
                baseline: entry.baseline,
                during_learning: learning,
                notify: entry.notify,
                priority: EventPriority::Normal,
                details: json!({
                    "previous_name": previous.display_name,
                    "previous_source": previous.source.as_str(),
                    "new_source": entry.identity.source.as_str(),
                    "confidence": entry.identity.confidence,
                }),
            })));
        }

        // Classification is recomputed after the signals land, so a packet that
        // carries both a name and a fingerprint is one pass rather than two.
        let reclassified = entry.reclassify(at).map(|previous| Reclassification {
            mac: entry.mac,
            display_name: entry.snapshot().display(),
            previous,
            current: entry.classification.clone(),
            interface: Some(obs.interface.clone()),
            at,
        });
        drop(config);
        self.reclassifications.extend(reclassified);
        effects
    }

    /// Creates an entry for a MAC never seen before.
    fn discover(&mut self, obs: &Observation) -> Vec<Effect> {
        let at = obs.observed_at;
        let mut signals = Vec::new();
        if let Some(vendor) = identity::vendor_signal(obs.mac) {
            signals.push(vendor);
        }
        let identity = identity::resolve(&identity::IdentityInput {
            mac: obs.mac,
            signals: &signals,
            device_type: None,
        });
        let entry = Entry {
            mac: obs.mac,
            state: DeviceState::Online,
            first_seen_at: at,
            last_seen_at: at,
            last_ip: None,
            last_ipv6: None,
            last_interface: Some(obs.interface.clone()),
            signals,
            identity,
            classification: Classification::default(),
            display_name: None,
            current_ap: None,
            current_location: None,
            baseline: self.learning,
            notify: true,
            offline_transitions: 0,
            observations_since_flush: 0,
            dirty: true,
        };
        let vendor = entry.best(SignalKind::Vendor);
        let snapshot = entry.snapshot();
        let learning = self.learning;
        self.devices.insert(obs.mac, entry);

        let mut effects = vec![Effect::Discovered(Box::new(snapshot.clone()))];
        if let Some(vendor) = vendor.clone() {
            effects.push(Effect::Signal {
                mac: obs.mac,
                signal: Signal::new(SignalKind::Vendor, vendor),
                at,
            });
        }
        effects.push(Effect::PresenceOpened {
            mac: obs.mac,
            interface: obs.interface.clone(),
            ip: ipv4_string(obs.ip),
            at,
        });
        effects.push(Effect::Event(Box::new(DeviceEvent {
            event_type: EventType::NewDevice,
            mac: obs.mac,
            display_name: snapshot.display(),
            vendor,
            ip: ipv4_string(obs.ip),
            interface: Some(obs.interface.clone()),
            at,
            baseline: learning,
            during_learning: learning,
            notify: true,
            priority: EventPriority::Normal,
            details: json!({
                "source": obs.source,
                "interface": obs.interface,
                "learning": learning,
            }),
        })));
        effects
    }

    /// Adds identity evidence that did not come from a packet, such as a reverse
    /// DNS answer.
    ///
    /// Returns nothing for an unknown MAC: a signal about a device the state
    /// machine has never seen is a bug elsewhere, not a device.
    #[must_use]
    pub fn add_signal(&mut self, mac: MacAddr, signal: &Signal, at: DateTime<Utc>) -> Vec<Effect> {
        if signal.value.trim().is_empty() {
            return Vec::new();
        }
        let learning = self.learning;
        let Some(entry) = self.devices.get_mut(&mac) else {
            return Vec::new();
        };
        let is_new = entry.record_signals(std::slice::from_ref(signal));
        entry.dirty = true;
        let mut effects = vec![Effect::Signal {
            mac,
            signal: signal.clone(),
            at,
        }];
        if is_new && let Some(previous) = entry.rescore() {
            effects.push(Effect::Event(Box::new(DeviceEvent {
                event_type: EventType::NameUpdated,
                mac,
                display_name: entry.snapshot().display(),
                vendor: entry.best(SignalKind::Vendor),
                ip: entry.last_ip.clone(),
                interface: entry.last_interface.clone(),
                at,
                baseline: entry.baseline,
                during_learning: learning,
                notify: entry.notify,
                priority: EventPriority::Normal,
                details: json!({
                    "previous_name": previous.display_name,
                    "previous_source": previous.source.as_str(),
                    "new_source": entry.identity.source.as_str(),
                }),
            })));
        }
        let reclassified = entry.reclassify(at).map(|previous| Reclassification {
            mac,
            display_name: entry.snapshot().display(),
            previous,
            current: entry.classification.clone(),
            interface: entry.last_interface.clone(),
            at,
        });
        self.reclassifications.extend(reclassified);
        effects
    }

    /// The access point a device is currently on, so the caller can work out
    /// what the next one means.
    ///
    /// The state machine deliberately does not classify the crossing itself:
    /// which access points are edges is the operator's map, and the map belongs
    /// with [`crate::location`] rather than in here.
    #[must_use]
    pub fn current_ap(&self, mac: MacAddr) -> Option<String> {
        self.devices.get(&mac).and_then(|e| e.current_ap.clone())
    }

    /// Places a device at an access point.
    ///
    /// Returns nothing when the device is unknown, or when it is already on that
    /// access point: an enricher polling every thirty seconds reports the same
    /// association over and over, and turning each one into a location stay
    /// would reproduce exactly the row-per-observation failure this daemon
    /// exists to avoid.
    ///
    /// `movement` and `telemetry` only ride into the event's details. The state
    /// machine does not act on either, because what a crossing *means* is the
    /// people registry's business.
    #[must_use]
    pub fn set_location(
        &mut self,
        mac: MacAddr,
        place: &crate::location::Place,
        movement: crate::location::Movement,
        telemetry: Option<serde_json::Value>,
        at: DateTime<Utc>,
    ) -> Vec<Effect> {
        let learning = self.learning;
        let Some(entry) = self.devices.get_mut(&mac) else {
            return Vec::new();
        };
        if entry.current_ap.as_deref() == Some(place.ap_name.as_str()) {
            return Vec::new();
        }
        let previous_ap = entry.current_ap.replace(place.ap_name.clone());
        let previous_location = entry.current_location.replace(place.location.clone());
        entry.dirty = true;

        let mut details = json!({
            "ap": place.ap_name,
            "location": place.location,
            "previous_ap": previous_ap,
            "previous_location": previous_location,
            "movement": movement.as_str(),
            "edge": place.edge,
        });
        // Per-poll telemetry rides in the event rather than in a column: it is
        // not device identity, and a vlan or bandwidth column would be a schema
        // change the Trovato plugin has not seen.
        if let (Some(telemetry), Some(object)) = (telemetry, details.as_object_mut()) {
            object.insert("telemetry".to_string(), telemetry);
        }

        vec![
            Effect::LocationChanged {
                mac,
                ap_name: Some(place.ap_name.clone()),
                location: place.location.clone(),
                at,
            },
            Effect::Event(Box::new(DeviceEvent {
                event_type: EventType::DeviceLocationChanged,
                mac,
                display_name: entry.snapshot().display(),
                vendor: entry.best(SignalKind::Vendor),
                ip: entry.last_ip.clone(),
                interface: entry.last_interface.clone(),
                at,
                baseline: entry.baseline,
                during_learning: learning,
                notify: entry.notify,
                priority: EventPriority::Normal,
                details,
            })),
        ]
    }

    /// Records an event about a person, keyed to the device that revealed it.
    ///
    /// People are not devices, but a person event still wants a row in
    /// `ng_events`, a `device_id`, and the same notification path as everything
    /// else. Rather than a second event pipeline, the triggering device carries
    /// it: the display name becomes the person's, and the notification flag
    /// becomes the person's.
    ///
    /// Returns nothing for a MAC the state machine has never seen, which cannot
    /// happen through the ordinary path because the registry only learns about a
    /// device from its presence transitions.
    #[must_use]
    pub fn person_event(&self, event: &crate::people::PersonEvent) -> Vec<Effect> {
        let entry = self.devices.get(&event.mac);
        vec![Effect::Event(Box::new(DeviceEvent {
            event_type: event.event_type,
            mac: event.mac,
            display_name: event.name.clone(),
            vendor: entry.and_then(|e| e.best(SignalKind::Vendor)),
            ip: entry.and_then(|e| e.last_ip.clone()),
            interface: entry.and_then(|e| e.last_interface.clone()),
            at: event.at,
            baseline: entry.is_some_and(|e| e.baseline),
            // A person arriving during a learning window is still worth
            // knowing; the window is about which *devices* are normal.
            during_learning: false,
            notify: event.notify,
            priority: EventPriority::Normal,
            details: event.details.clone(),
        }))]
    }

    /// Turns an analyzer's finding into recordable effects.
    ///
    /// The analyzers know what happened but not who it happened to: they hold no
    /// device table, deliberately, so that they stay pure and restartable. This
    /// is where a MAC becomes a name, a vendor and a database row.
    ///
    /// An alert about a MAC the state machine has never seen still produces an
    /// event. `ng_events.device_id` is nullable precisely for this: the first
    /// thing a scanner does is scan, and refusing to record it because it has
    /// not introduced itself first would be exactly backwards.
    #[must_use]
    pub fn security_event(&self, alert: &SecurityAlert) -> Vec<Effect> {
        let entry = self.devices.get(&alert.mac);
        let display_name = entry.map_or_else(
            || {
                identity::vendor_signal(alert.mac).map_or_else(
                    || alert.mac.to_string(),
                    |vendor| format!("{} device", vendor.value),
                )
            },
            |e| e.snapshot().display(),
        );
        let mut details = alert.details.clone();
        if let Some(object) = details.as_object_mut() {
            // The flag the plugin and the CLI key on to render these
            // differently. Set here rather than in each analyzer so that no
            // analyzer can forget it.
            object.insert("security".to_string(), json!(true));
            object.insert("priority".to_string(), json!(alert.priority.as_str()));
        }
        vec![Effect::Event(Box::new(DeviceEvent {
            event_type: alert.event_type,
            mac: alert.mac,
            display_name,
            vendor: entry.and_then(|e| e.best(SignalKind::Vendor)),
            ip: alert.ip.clone(),
            interface: alert.interface.clone(),
            at: alert.at,
            baseline: entry.is_some_and(|e| e.baseline),
            // Never suppressed by a learning window; see DeviceEvent::deliverable.
            during_learning: false,
            notify: true,
            priority: alert.priority,
            details,
        }))]
    }

    /// Applies timeouts, moving quiet devices to idle and silent ones offline.
    #[must_use]
    pub fn sweep(&mut self, now: DateTime<Utc>) -> Vec<Effect> {
        let mut effects = Vec::new();
        for entry in self.devices.values_mut() {
            if entry.state == DeviceState::Offline {
                continue;
            }
            let silence = (now - entry.last_seen_at)
                .to_std()
                .unwrap_or(Duration::ZERO);
            let device_type = entry.classification.device_type.as_deref();
            let offline_after = self.config.offline_timeout_for(device_type);
            let idle_after = self.config.idle_timeout_for(device_type);

            // Offline is checked first so that a sweep delayed past both
            // thresholds lands on the right state in one pass rather than
            // parking the device in idle for another cycle.
            if silence >= offline_after {
                entry.state = DeviceState::Offline;
                entry.dirty = true;
                entry.offline_transitions = entry.offline_transitions.saturating_add(1);
                effects.push(Effect::PresenceClosed {
                    mac: entry.mac,
                    at: now,
                });
                // Where an offline device is, is nowhere. Its stay ends here and
                // the next enrichment poll opens another; leaving it open would
                // mean a device that left the house last March still counts as
                // being in the kitchen.
                if entry.current_ap.take().is_some() {
                    entry.current_location = None;
                    effects.push(Effect::LocationClosed {
                        mac: entry.mac,
                        at: now,
                    });
                }
                effects.push(Effect::Event(Box::new(DeviceEvent {
                    event_type: EventType::WentOffline,
                    mac: entry.mac,
                    display_name: entry.snapshot().display(),
                    vendor: entry.best(SignalKind::Vendor),
                    ip: entry.last_ip.clone(),
                    interface: entry.last_interface.clone(),
                    at: now,
                    baseline: entry.baseline,
                    during_learning: self.learning,
                    notify: entry.notify,
                    priority: EventPriority::Normal,
                    details: json!({
                        "last_seen_at": entry.last_seen_at,
                        "silent_for_secs": silence.as_secs(),
                    }),
                })));
            } else if silence >= idle_after && entry.state == DeviceState::Online {
                entry.state = DeviceState::Idle;
                entry.dirty = true;
            }
        }
        effects
    }

    /// Takes the snapshots of every device changed since the last call, and
    /// clears their pending observation counters.
    #[must_use]
    pub fn take_dirty(&mut self) -> Vec<DeviceSnapshot> {
        let mut out = Vec::new();
        for entry in self.devices.values_mut() {
            if entry.dirty {
                out.push(entry.snapshot());
                entry.dirty = false;
                entry.observations_since_flush = 0;
            }
        }
        out
    }

    /// Snapshots every device, most recently seen first, for the CLI table.
    #[must_use]
    pub fn snapshot(&self) -> Vec<DeviceSnapshot> {
        let mut out: Vec<DeviceSnapshot> = self.devices.values().map(Entry::snapshot).collect();
        out.sort_by(|a, b| {
            b.last_seen_at
                .cmp(&a.last_seen_at)
                .then_with(|| a.mac.cmp(&b.mac))
        });
        out
    }
}

/// Renders an IPv4 address, or `None` for anything else.
///
/// Milestone 1 tracks IPv4 for `last_ip` and for `ip_changed`. See the note in
/// `capture/ndp.rs` for why, and for when to revisit.
fn ipv4_string(ip: Option<IpAddr>) -> Option<String> {
    match ip {
        Some(IpAddr::V4(v4)) if !v4.is_unspecified() && !v4.is_multicast() => Some(v4.to_string()),
        _ => None,
    }
}

/// Whether an address is worth writing to `ng_ip_history`.
fn is_recordable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_multicast() && !v4.is_broadcast(),
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_multicast(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HumanDuration, StateConfig};
    use crate::types::ObservationKind;
    use chrono::TimeZone;

    fn base() -> DateTime<Utc> {
        Utc.timestamp_opt(1_770_000_000, 0)
            .single()
            .expect("valid timestamp")
    }

    fn at(offset_secs: i64) -> DateTime<Utc> {
        base() + chrono::Duration::seconds(offset_secs)
    }

    fn config() -> StateConfig {
        StateConfig {
            idle_timeout: HumanDuration::from_secs(1800),
            offline_timeout: HumanDuration::from_secs(10_800),
            ..StateConfig::default()
        }
    }

    fn mac(s: &str) -> MacAddr {
        s.parse().expect("test mac")
    }

    fn obs_at(m: &str, ip: Option<&str>, when: DateTime<Utc>) -> Observation {
        Observation::new(
            mac(m),
            ip.map(|s| s.parse().expect("test ip")),
            "eth0",
            "arp",
            ObservationKind::Request,
            when,
        )
    }

    fn events(effects: &[Effect]) -> Vec<EventType> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::Event(ev) => Some(ev.event_type),
                _ => None,
            })
            .collect()
    }

    fn event(effects: &[Effect], kind: EventType) -> DeviceEvent {
        effects
            .iter()
            .find_map(|e| match e {
                Effect::Event(ev) if ev.event_type == kind => Some((**ev).clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("expected a {kind} event in {effects:?}"))
    }

    #[test]
    fn a_first_sighting_creates_a_device_and_opens_a_session() {
        let mut m = Manager::new(config(), false);
        let effects = m.observe(&obs_at("3c:22:fb:00:00:01", Some("192.168.1.40"), base()));
        assert_eq!(events(&effects), vec![EventType::NewDevice]);
        assert!(effects.iter().any(|e| matches!(e, Effect::Discovered(_))));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::PresenceOpened { .. }))
        );
        assert_eq!(m.len(), 1);
        assert_eq!(m.state_counts(), (1, 0, 0));
    }

    #[test]
    fn a_new_device_gets_its_vendor_from_the_mac_prefix() {
        let mut m = Manager::new(config(), false);
        let effects = m.observe(&obs_at("b8:27:eb:00:00:01", Some("192.168.1.9"), base()));
        let ev = event(&effects, EventType::NewDevice);
        assert_eq!(ev.vendor.as_deref(), Some("Raspberry Pi Foundation"));
        assert_eq!(ev.display_name, "Raspberry Pi Foundation device");
    }

    #[test]
    fn a_second_sighting_is_not_a_new_device() {
        let mut m = Manager::new(config(), false);
        let _ = m.observe(&obs_at("3c:22:fb:00:00:01", Some("192.168.1.40"), base()));
        let effects = m.observe(&obs_at("3c:22:fb:00:00:01", Some("192.168.1.40"), at(60)));
        assert!(events(&effects).is_empty(), "{effects:?}");
    }

    #[test]
    fn silence_moves_a_device_to_idle_without_an_event() {
        let mut m = Manager::new(config(), false);
        let _ = m.observe(&obs_at("3c:22:fb:00:00:01", None, base()));
        let effects = m.sweep(at(1801));
        assert!(events(&effects).is_empty(), "idle is not eventful");
        assert_eq!(m.state_counts(), (0, 1, 0));
    }

    #[test]
    fn longer_silence_moves_a_device_offline_and_closes_the_session() {
        let mut m = Manager::new(config(), false);
        let _ = m.observe(&obs_at("3c:22:fb:00:00:01", None, base()));
        let _ = m.sweep(at(1801));
        let effects = m.sweep(at(10_801));
        assert_eq!(events(&effects), vec![EventType::WentOffline]);
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::PresenceClosed { .. }))
        );
        assert_eq!(m.state_counts(), (0, 0, 1));
    }

    #[test]
    fn a_sweep_delayed_past_both_thresholds_lands_offline_in_one_pass() {
        let mut m = Manager::new(config(), false);
        let _ = m.observe(&obs_at("3c:22:fb:00:00:01", None, base()));
        let effects = m.sweep(at(20_000));
        assert_eq!(events(&effects), vec![EventType::WentOffline]);
        assert_eq!(m.state_counts(), (0, 0, 1));
    }

    #[test]
    fn the_idle_boundary_is_inclusive_and_the_second_before_is_not() {
        let mut m = Manager::new(config(), false);
        let _ = m.observe(&obs_at("3c:22:fb:00:00:01", None, base()));
        let _ = m.sweep(at(1799));
        assert_eq!(m.state_counts(), (1, 0, 0), "one second early");
        let _ = m.sweep(at(1800));
        assert_eq!(m.state_counts(), (0, 1, 0), "exactly at the threshold");
    }

    #[test]
    fn an_observation_of_an_offline_device_is_a_return_not_a_discovery() {
        let mut m = Manager::new(config(), false);
        let _ = m.observe(&obs_at("3c:22:fb:00:00:01", Some("192.168.1.40"), base()));
        let _ = m.sweep(at(20_000));
        let effects = m.observe(&obs_at(
            "3c:22:fb:00:00:01",
            Some("192.168.1.40"),
            at(20_100),
        ));
        assert_eq!(events(&effects), vec![EventType::Returned]);
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::PresenceOpened { .. }))
        );
        assert_eq!(m.state_counts(), (1, 0, 0));
    }

    #[test]
    fn an_observation_of_an_idle_device_is_silent() {
        let mut m = Manager::new(config(), false);
        let _ = m.observe(&obs_at("3c:22:fb:00:00:01", None, base()));
        let _ = m.sweep(at(1801));
        let effects = m.observe(&obs_at("3c:22:fb:00:00:01", None, at(1802)));
        assert!(events(&effects).is_empty(), "{effects:?}");
        assert_eq!(m.state_counts(), (1, 0, 0));
    }

    #[test]
    fn rapid_flapping_produces_one_event_per_real_transition() {
        let mut m = Manager::new(config(), false);
        let mut seen = Vec::new();
        let mut t = 0i64;
        let _ = m.observe(&obs_at("3c:22:fb:00:00:01", None, at(t)));
        for _ in 0..5 {
            t += 20_000;
            seen.extend(events(&m.sweep(at(t))));
            t += 1;
            seen.extend(events(&m.observe(&obs_at(
                "3c:22:fb:00:00:01",
                None,
                at(t),
            ))));
        }
        assert_eq!(
            seen,
            [EventType::WentOffline, EventType::Returned].repeat(5),
            "each cycle is exactly one offline and one return"
        );
    }

    #[test]
    fn repeated_sweeps_do_not_re_announce_an_offline_device() {
        let mut m = Manager::new(config(), false);
        let _ = m.observe(&obs_at("3c:22:fb:00:00:01", None, base()));
        assert_eq!(events(&m.sweep(at(20_000))), vec![EventType::WentOffline]);
        for extra in [20_001, 30_000, 100_000] {
            assert!(events(&m.sweep(at(extra))).is_empty(), "sweep at {extra}");
        }
    }

    #[test]
    fn a_changed_address_raises_ip_changed_with_both_addresses() {
        let mut m = Manager::new(config(), false);
        let _ = m.observe(&obs_at("3c:22:fb:00:00:01", Some("192.168.1.40"), base()));
        let effects = m.observe(&obs_at("3c:22:fb:00:00:01", Some("192.168.1.41"), at(60)));
        let ev = event(&effects, EventType::IpChanged);
        assert_eq!(ev.details["previous_ip"], "192.168.1.40");
        assert_eq!(ev.details["new_ip"], "192.168.1.41");
    }

    #[test]
    fn the_first_address_a_device_shows_is_not_a_change() {
        let mut m = Manager::new(config(), false);
        // ARP probe first: presence with no address at all.
        let _ = m.observe(&obs_at("3c:22:fb:00:00:01", None, base()));
        let effects = m.observe(&obs_at("3c:22:fb:00:00:01", Some("192.168.1.40"), at(10)));
        assert!(
            !events(&effects).contains(&EventType::IpChanged),
            "{effects:?}"
        );
    }

    #[test]
    fn an_ipv6_sighting_is_recorded_but_does_not_disturb_the_ipv4_address() {
        let mut m = Manager::new(config(), false);
        let _ = m.observe(&obs_at("3c:22:fb:00:00:01", Some("192.168.1.40"), base()));
        let effects = m.observe(&obs_at("3c:22:fb:00:00:01", Some("fe80::1"), at(10)));
        assert!(
            !events(&effects).contains(&EventType::IpChanged),
            "dual stack must not flap: {effects:?}"
        );
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::Address { ip, .. } if ip == "fe80::1")),
            "the v6 address is still recorded in history"
        );
        assert_eq!(m.snapshot()[0].last_ip.as_deref(), Some("192.168.1.40"));
    }

    #[test]
    fn a_stronger_signal_refines_the_name_and_raises_name_updated() {
        let mut m = Manager::new(config(), false);
        let _ = m.observe(&obs_at("3c:22:fb:00:00:01", Some("192.168.1.40"), base()));
        let obs = obs_at("3c:22:fb:00:00:01", Some("192.168.1.40"), at(30))
            .with_signal(Signal::new(SignalKind::MdnsName, "Aurora's iPad"));
        let effects = m.observe(&obs);
        let ev = event(&effects, EventType::NameUpdated);
        assert_eq!(ev.display_name, "Aurora's iPad");
        assert_eq!(ev.details["previous_source"], "vendor");
        assert_eq!(ev.details["new_source"], "mdns_name");
    }

    #[test]
    fn a_weaker_later_signal_changes_nothing() {
        let mut m = Manager::new(config(), false);
        let strong = obs_at("3c:22:fb:00:00:01", Some("192.168.1.40"), base())
            .with_signal(Signal::new(SignalKind::MdnsName, "Aurora's iPad"));
        let _ = m.observe(&strong);
        let effects = m.add_signal(
            mac("3c:22:fb:00:00:01"),
            &Signal::new(SignalKind::ReverseDns, "ipad.lan"),
            at(60),
        );
        assert!(
            !events(&effects).contains(&EventType::NameUpdated),
            "{effects:?}"
        );
        assert_eq!(m.snapshot()[0].display(), "Aurora's iPad");
        assert_eq!(
            m.snapshot()[0].hostname.as_deref(),
            Some("ipad.lan"),
            "the weaker signal is still stored"
        );
    }

    #[test]
    fn a_batch_of_same_kind_signals_keeps_the_order_the_source_offered() {
        // Regression: signals used to be front-inserted one at a time, which
        // reversed each packet's batch. An mDNS packet lists the instance name
        // (human-chosen) before the host name (vendor-chosen), and both are
        // MdnsName, so reversing silently promoted `living-room-apple-tv` over
        // `Living Room Apple TV`.
        let mut m = Manager::new(config(), false);
        let obs = obs_at("b8:27:eb:00:00:01", Some("192.168.1.55"), base())
            .with_signal(Signal::new(SignalKind::MdnsName, "Living Room Apple TV"))
            .with_signal(Signal::new(SignalKind::MdnsName, "living-room-apple-tv"));
        let _ = m.observe(&obs);
        assert_eq!(m.snapshot()[0].display(), "Living Room Apple TV");
    }

    #[test]
    fn re_seeing_the_same_batch_does_not_reorder_it_or_raise_an_event() {
        let mut m = Manager::new(config(), false);
        let obs = obs_at("b8:27:eb:00:00:01", Some("192.168.1.55"), base())
            .with_signal(Signal::new(SignalKind::MdnsName, "Living Room Apple TV"))
            .with_signal(Signal::new(SignalKind::MdnsName, "living-room-apple-tv"));
        let _ = m.observe(&obs);
        for i in 1..5 {
            let repeat = obs_at("b8:27:eb:00:00:01", Some("192.168.1.55"), at(i * 10))
                .with_signal(Signal::new(SignalKind::MdnsName, "Living Room Apple TV"))
                .with_signal(Signal::new(SignalKind::MdnsName, "living-room-apple-tv"));
            let effects = m.observe(&repeat);
            assert!(events(&effects).is_empty(), "repeat {i}: {effects:?}");
        }
        assert_eq!(m.snapshot()[0].display(), "Living Room Apple TV");
    }

    #[test]
    fn a_duplicate_inside_one_batch_is_stored_once() {
        let mut m = Manager::new(config(), false);
        let obs = obs_at("b8:27:eb:00:00:01", None, base())
            .with_signal(Signal::new(SignalKind::MdnsName, "Kitchen Speaker"))
            .with_signal(Signal::new(SignalKind::MdnsName, "Kitchen Speaker"));
        let _ = m.observe(&obs);
        assert_eq!(m.snapshot()[0].display(), "Kitchen Speaker");
    }

    #[test]
    fn a_new_device_does_not_also_emit_name_updated() {
        let mut m = Manager::new(config(), false);
        let obs = obs_at("3c:22:fb:00:00:01", Some("192.168.1.40"), base())
            .with_signal(Signal::new(SignalKind::MdnsName, "Aurora's iPad"));
        let kinds = events(&m.observe(&obs));
        assert_eq!(kinds, vec![EventType::NewDevice], "{kinds:?}");
    }

    #[test]
    fn a_signal_about_an_unknown_device_is_ignored() {
        let mut m = Manager::new(config(), false);
        let effects = m.add_signal(
            mac("3c:22:fb:99:99:99"),
            &Signal::new(SignalKind::ReverseDns, "ghost.lan"),
            base(),
        );
        assert!(effects.is_empty());
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn learning_mode_records_the_event_and_only_suppresses_delivery() {
        let mut m = Manager::new(config(), true);
        let effects = m.observe(&obs_at("3c:22:fb:00:00:01", Some("192.168.1.40"), base()));
        let ev = event(&effects, EventType::NewDevice);
        assert!(ev.baseline, "the device joins the baseline");
        assert!(ev.during_learning);
        assert!(
            !ev.deliverable(),
            "no notification is sent during a learning window"
        );
        // The record still exists, which is the security-relevant half.
        assert_eq!(events(&effects), vec![EventType::NewDevice]);
    }

    #[test]
    fn devices_found_after_learning_ends_are_not_baseline_and_do_notify() {
        let mut m = Manager::new(config(), true);
        let _ = m.observe(&obs_at("3c:22:fb:00:00:01", None, base()));
        m.end_learning();
        assert!(!m.is_learning());
        let effects = m.observe(&obs_at("3c:22:fb:00:00:02", None, at(10)));
        let ev = event(&effects, EventType::NewDevice);
        assert!(!ev.baseline);
        assert!(ev.deliverable());
    }

    #[test]
    fn ending_learning_leaves_existing_devices_on_the_baseline() {
        let mut m = Manager::new(config(), true);
        let _ = m.observe(&obs_at("3c:22:fb:00:00:01", None, base()));
        m.end_learning();
        assert!(m.snapshot()[0].baseline);
    }

    #[test]
    fn a_users_notify_toggle_suppresses_delivery_without_suppressing_the_record() {
        let mut m = Manager::new(config(), false);
        let mut record = restored_record("3c:22:fb:00:00:01", DeviceState::Offline);
        record.notify = false;
        m.restore(vec![record], HashMap::new());
        let effects = m.observe(&obs_at("3c:22:fb:00:00:01", None, at(100)));
        let ev = event(&effects, EventType::Returned);
        assert!(!ev.deliverable());
    }

    #[test]
    fn restored_devices_do_not_re_announce_themselves() {
        let mut m = Manager::new(config(), false);
        m.restore(
            vec![restored_record("3c:22:fb:00:00:01", DeviceState::Online)],
            HashMap::new(),
        );
        let effects = m.observe(&obs_at("3c:22:fb:00:00:01", Some("192.168.1.40"), at(10)));
        assert!(
            !events(&effects).contains(&EventType::NewDevice),
            "a restart must not re-announce the whole network: {effects:?}"
        );
    }

    #[test]
    fn restored_signals_rebuild_the_identity() {
        let mut m = Manager::new(config(), false);
        let record = restored_record("3c:22:fb:00:00:01", DeviceState::Online);
        let mut signals = HashMap::new();
        signals.insert(
            record.id,
            vec![
                Signal::new(SignalKind::MdnsName, "Aurora's iPad"),
                Signal::new(SignalKind::Vendor, "Apple, Inc."),
            ],
        );
        m.restore(vec![record], signals);
        assert_eq!(m.snapshot()[0].display(), "Aurora's iPad");
    }

    #[test]
    fn a_user_assigned_name_beats_the_scorer_in_snapshots_and_events() {
        let mut m = Manager::new(config(), false);
        let mut record = restored_record("3c:22:fb:00:00:01", DeviceState::Offline);
        record.display_name = Some("Jamie's telly".into());
        let mut signals = HashMap::new();
        signals.insert(
            record.id,
            vec![Signal::new(SignalKind::MdnsName, "Living Room Apple TV")],
        );
        m.restore(vec![record], signals);
        let effects = m.observe(&obs_at("3c:22:fb:00:00:01", None, at(100)));
        assert_eq!(
            event(&effects, EventType::Returned).display_name,
            "Jamie's telly"
        );
        assert_eq!(m.snapshot()[0].display(), "Jamie's telly");
    }

    #[test]
    fn per_device_type_timeouts_are_honoured() {
        let mut config = config();
        config.device_type_overrides.insert(
            "router".into(),
            crate::config::TimeoutOverride {
                idle_timeout: Some(HumanDuration::from_secs(86_400)),
                offline_timeout: Some(HumanDuration::from_secs(86_400)),
            },
        );
        let mut m = Manager::new(config, false);
        m.restore(
            vec![
                DeviceRecord {
                    device_type: Some("router".into()),
                    ..restored_record("b8:27:eb:00:00:01", DeviceState::Online)
                },
                restored_record("3c:22:fb:00:00:02", DeviceState::Online),
            ],
            HashMap::new(),
        );
        // Well past the global timeouts but inside the router override.
        let effects = m.sweep(at(20_000));
        assert_eq!(
            events(&effects),
            vec![EventType::WentOffline],
            "only the ordinary device times out"
        );
        assert_eq!(m.state_counts(), (1, 0, 1));
    }

    #[test]
    fn dirty_snapshots_are_taken_once_and_reset_the_counter() {
        let mut m = Manager::new(config(), false);
        for i in 0..5 {
            let _ = m.observe(&obs_at("3c:22:fb:00:00:01", None, at(i)));
        }
        let dirty = m.take_dirty();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].observations_since_flush, 5);
        assert!(m.take_dirty().is_empty(), "nothing changed since the flush");

        let _ = m.observe(&obs_at("3c:22:fb:00:00:01", None, at(10)));
        assert_eq!(m.take_dirty()[0].observations_since_flush, 1);
    }

    #[test]
    fn a_clock_that_goes_backwards_does_not_drag_last_seen_with_it() {
        let mut m = Manager::new(config(), false);
        let _ = m.observe(&obs_at("3c:22:fb:00:00:01", None, at(1000)));
        let _ = m.observe(&obs_at("3c:22:fb:00:00:01", None, at(10)));
        assert_eq!(m.snapshot()[0].last_seen_at, at(1000));
    }

    #[test]
    fn group_and_zero_addresses_never_become_devices() {
        let mut m = Manager::new(config(), false);
        for bad in [
            "ff:ff:ff:ff:ff:ff",
            "01:00:5e:00:00:fb",
            "00:00:00:00:00:00",
        ] {
            assert!(m.observe(&obs_at(bad, None, base())).is_empty(), "{bad}");
        }
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn snapshots_are_ordered_by_recency() {
        let mut m = Manager::new(config(), false);
        let _ = m.observe(&obs_at("3c:22:fb:00:00:01", None, at(10)));
        let _ = m.observe(&obs_at("3c:22:fb:00:00:02", None, at(30)));
        let _ = m.observe(&obs_at("3c:22:fb:00:00:03", None, at(20)));
        let order: Vec<String> = m.snapshot().iter().map(|s| s.mac.to_string()).collect();
        assert_eq!(
            order,
            vec![
                "3c:22:fb:00:00:02",
                "3c:22:fb:00:00:03",
                "3c:22:fb:00:00:01"
            ]
        );
    }

    /// A device row as it would come back from Postgres.
    fn settings(m: &str) -> UserSettings {
        UserSettings {
            mac: mac(m),
            display_name: None,
            notes: None,
            hidden: false,
            notify: true,
            owner_item_id: None,
        }
    }

    #[test]
    fn the_two_column_lists_together_account_for_every_user_owned_column() {
        // The drift guard. A new user-owned column added to ng_devices has to be
        // either merged or consciously not merged, and this fails until it is
        // one or the other.
        let mut named: Vec<&str> = USER_OWNED_COLUMNS
            .iter()
            .map(|column| column.name)
            .chain(USER_OWNED_COLUMNS_NOT_STORED)
            .collect();
        named.sort_unstable();
        let mut expected: Vec<&str> = crate::db::queries::USER_OWNED_DEVICE_COLUMNS.to_vec();
        expected.sort_unstable();
        assert_eq!(named, expected);
    }

    #[test]
    fn a_reconcile_merges_the_user_owned_columns_and_touches_nothing_else() {
        let mut m = Manager::new(config(), false);
        m.restore(
            vec![restored_record("3c:22:fb:00:00:01", DeviceState::Online)],
            HashMap::new(),
        );
        // Give the device some daemon-owned state worth protecting.
        let _ = m.observe(&obs_at("3c:22:fb:00:00:01", Some("192.168.1.40"), at(10)));
        let before = m.snapshot()[0].clone();

        let mut incoming = settings("3c:22:fb:00:00:01");
        incoming.display_name = Some("Jamie's telly".into());
        incoming.notify = false;
        // Set by the plugin and merged elsewhere or nowhere; neither may leak
        // into the device table.
        incoming.hidden = true;
        incoming.notes = Some("in the loft".into());
        incoming.owner_item_id = Some("person-1".into());

        let changes = m.apply_user_settings(&[incoming]);
        let columns: Vec<&str> = changes.iter().map(|c| c.column).collect();
        assert_eq!(columns, vec!["display_name", "notify"], "{changes:?}");

        let after = m.snapshot()[0].clone();
        assert_eq!(after.display_name.as_deref(), Some("Jamie's telly"));
        assert_eq!(after.display(), "Jamie's telly");
        // Everything the daemon owns is byte for byte what it was.
        assert_eq!(after.state, before.state);
        assert_eq!(after.last_ip, before.last_ip);
        assert_eq!(after.last_seen_at, before.last_seen_at);
        assert_eq!(after.first_seen_at, before.first_seen_at);
        assert_eq!(after.identity, before.identity);
        assert_eq!(after.device_type, before.device_type);
        assert_eq!(after.current_ap, before.current_ap);
        assert_eq!(after.baseline, before.baseline);
        assert_eq!(
            after.observations_since_flush,
            before.observations_since_flush
        );
    }

    #[test]
    fn a_reconcile_that_changes_nothing_reports_nothing_and_leaves_the_row_clean() {
        let mut m = Manager::new(config(), false);
        m.restore(
            vec![restored_record("3c:22:fb:00:00:01", DeviceState::Online)],
            HashMap::new(),
        );
        // Drain the discovery flush so `take_dirty` below starts from nothing.
        let _ = m.take_dirty();
        assert!(
            m.apply_user_settings(&[settings("3c:22:fb:00:00:01")])
                .is_empty()
        );
        // A merge is not a reason to write: these columns are absent from the
        // daemon's update statement, so a dirty row here would be a round trip
        // that writes nothing and work for the plugin's cron sweep.
        assert!(
            m.take_dirty().is_empty(),
            "a reconcile must not dirty a row"
        );
    }

    #[test]
    fn a_reconcile_ignores_a_mac_the_daemon_has_never_seen() {
        let mut m = Manager::new(config(), false);
        assert!(
            m.apply_user_settings(&[settings("3c:22:fb:99:99:99")])
                .is_empty()
        );
        assert_eq!(m.len(), 0, "discovery is the capture path's job");
    }

    #[test]
    fn muting_a_device_while_running_silences_the_next_alert_without_a_restart() {
        // The regression this whole change exists to prevent: 33 of 35 presence
        // deliveries ignored a notify toggle set from the web because nothing
        // re-read the column between restarts.
        let mut m = Manager::new(config(), false);
        m.restore(
            vec![restored_record("3c:22:fb:00:00:01", DeviceState::Offline)],
            HashMap::new(),
        );
        let mut muted = settings("3c:22:fb:00:00:01");
        muted.notify = false;
        assert_eq!(m.apply_user_settings(&[muted]).len(), 1);

        let effects = m.observe(&obs_at("3c:22:fb:00:00:01", None, at(100)));
        let ev = event(&effects, EventType::Returned);
        assert!(!ev.deliverable(), "the mute must apply to the next event");
        // And the record survives, which is the security-relevant half.
        assert!(events(&effects).contains(&EventType::Returned));
    }

    #[test]
    fn unmuting_a_device_while_running_lets_the_next_alert_through() {
        let mut m = Manager::new(config(), false);
        let mut record = restored_record("3c:22:fb:00:00:01", DeviceState::Offline);
        record.notify = false;
        m.restore(vec![record], HashMap::new());
        let changes = m.apply_user_settings(&[settings("3c:22:fb:00:00:01")]);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].from, "false");
        assert_eq!(changes[0].to, "true");
        let effects = m.observe(&obs_at("3c:22:fb:00:00:01", None, at(100)));
        assert!(event(&effects, EventType::Returned).deliverable());
    }

    fn restored_record(m: &str, state: DeviceState) -> DeviceRecord {
        DeviceRecord {
            id: i64::from(mac(m).octets()[5]),
            mac: mac(m),
            display_name: None,
            resolved_name: None,
            identity_source: None,
            identity_confidence: None,
            hostname: None,
            mdns_name: None,
            vendor: None,
            device_type: None,
            device_type_confidence: None,
            os_family: None,
            state,
            last_ip: None,
            last_ipv6: None,
            last_interface: None,
            first_seen_at: base(),
            last_seen_at: base(),
            baseline: false,
            hidden: false,
            notify: true,
            notes: None,
            current_ap: None,
            current_location: None,
            owner_item_id: None,
        }
    }
}
