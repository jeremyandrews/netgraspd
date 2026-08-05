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
use crate::db::queries::DeviceRecord;
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
                    baseline: record.baseline,
                    notify: record.notify,
                    offline_transitions: 0,
                    observations_since_flush: 0,
                    dirty: false,
                },
            );
        }
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
        }
    }
}
