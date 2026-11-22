//! Who is home, inferred from which of their devices are online.
//!
//! The rule is deliberately simple, because every elaboration of it that anybody
//! has tried produces a system that announces you have left the house while you
//! are sitting in it:
//!
//! - A person is **home** when any device they own *that counts* is online.
//! - The first counting device to come online after all of them were offline is
//!   an arrival.
//! - The last counting device to go offline is a departure.
//!
//! ## Which devices count, and who is tracked at all
//!
//! Only a device a person carries says whether they are in. A laptop, a desktop
//! or a tablet left on the kitchen table is online all day while its owner is at
//! work, and when every owned device counted alike it kept them home all day and
//! dragged their location to the kitchen. [`counts_for_presence`] is the one
//! place that decides: by device type unless a person overrode it for that
//! device.
//!
//! Tracking where household members are is something people choose. A person
//! is [`PersonState::Untracked`] unless the install's `presence_tracking`
//! switch is on, their own `track_presence` is on, and they own at least one
//! device that counts. An untracked person has no location, is neither home nor
//! away, and produces no person events.
//!
//! A change to any of those settings re-evaluates the person at once, from the
//! devices that count now, and records the result without an event: switching
//! a laptop off as a presence device is not somebody leaving the house. See
//! [`Registry::settle`].
//!
//! Edge access points do not change that rule. They supply the *evidence* for
//! it: a device that crossed the driveway on its way in makes the arrival read
//! "arrived through the Driveway", and a device that crossed the driveway
//! shortly before falling silent makes the departure read "left through the
//! Driveway". A device wandering from the kitchen to the living room supplies no
//! such evidence and must never look like either, which is what
//! [`crate::location::Movement`] is for.
//!
//! A person's **location** is that of their most recently active device. Not the
//! first, not an average: the phone in somebody's pocket is talking, and the
//! tablet left in the bedroom is not.
//!
//! ## Ownership comes from two places
//!
//! When the Trovato plugin is installed it fills `ng_devices.owner_item_id` and
//! mirrors person rows into `ng_people`. When it is not, `[[people]]` in
//! `netgrasp.toml` names people and the MACs they own. The two are merged rather
//! than chosen between, so an install can migrate from one to the other without
//! a flag day. Configuration is applied first and the database wins on conflict,
//! because the database is what a human edited most recently through a UI.
//!
//! This registry is pure and synchronous: devices and clock readings in, person
//! events and rows-to-write out. Every rule above is therefore a plain test.

use jiff::SignedDuration;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::clock::Timestamp;
use serde_json::json;

use crate::location::{Movement, Place};
use crate::types::{EventType, MacAddr};

/// How close an edge crossing must be to the moment it is meant to explain.
///
/// Fifteen minutes is long enough to cover a device that associates with the
/// driveway AP, is carried indoors, and settles; and short enough that this
/// morning's departure is never offered as the reason for tonight's arrival.
///
/// **What the window is measured against differs by direction**, and getting
/// that wrong makes departures never carry evidence at all.
///
/// An *arrival* is decided the moment a device is heard from, so the crossing is
/// minutes old and the window is measured against the arrival itself.
///
/// A *departure* is decided `offline_timeout` after the device fell silent,
/// which is three hours by default. Measuring against the departure would put
/// every crossing outside a fifteen-minute window forever. The question worth
/// asking is not "did they cross an edge recently" but "did they cross an edge
/// shortly before they stopped talking", so a departure measures the crossing
/// against the device's own last activity instead.
pub const EDGE_EVIDENCE_WINDOW: SignedDuration = SignedDuration::from_mins(15);

/// The device types that decide, unless a person says otherwise, whether their
/// owner is home: the ones that leave the house in a pocket or on a wrist.
///
/// Tablets are deliberately absent. In a household a tablet lives on the sofa
/// far more often than it travels, and one that does travel can be switched on
/// per device. This list is not the device manager's list of carried types,
/// which answers a different question (whose long silences are absences).
pub const PRESENCE_DEVICE_TYPES: [&str; 2] = ["phone", "wearable"];

/// Whether a device decides if its owner is home.
///
/// `counts_override` is `ng_devices.counts_for_presence`, which a person sets:
/// `Some(true)` and `Some(false)` are their explicit choice and win outright.
/// `None` means "decide by type": the device counts when its classified
/// `device_type` is one of [`PRESENCE_DEVICE_TYPES`] (`phone` or `wearable`),
/// and does not count for any other type or when the type is unknown.
///
/// This is the only place the rule lives. Everything in the registry that asks
/// whether a device is a presence device asks this.
#[must_use]
pub fn counts_for_presence(counts_override: Option<bool>, device_type: Option<&str>) -> bool {
    counts_override
        .unwrap_or_else(|| device_type.is_some_and(|t| PRESENCE_DEVICE_TYPES.contains(&t)))
}

/// Whether a person is in the house, or whether anybody is asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PersonState {
    /// At least one owned device that counts is online.
    Home,
    /// Every owned device that counts is offline.
    Away,
    /// Presence is not tracked for this person: the install's switch is off,
    /// their own switch is off, or they own no device that counts. Never home
    /// and never away; no location and no person events.
    Untracked,
}

impl PersonState {
    /// Stable string used as the `ng_people.state` value.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            PersonState::Home => "home",
            PersonState::Away => "away",
            PersonState::Untracked => "untracked",
        }
    }

    /// Inverse of [`PersonState::as_str`]. Anything unrecognised reads as
    /// `Away`, the safe default: the next device sighting corrects it, and
    /// announcing an arrival that did happen is better than suppressing one.
    /// The daemon re-evaluates every person at startup in any case, so a stored
    /// value only ever survives when it agrees with the devices.
    #[must_use]
    pub fn from_db(s: &str) -> Self {
        match s {
            "home" => PersonState::Home,
            "untracked" => PersonState::Untracked,
            _ => PersonState::Away,
        }
    }
}

impl std::fmt::Display for PersonState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A person, as the registry holds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    /// The person Item's UUID, rendered as text. Plugin owned.
    pub item_id: String,
    /// Display name. Plugin owned.
    pub name: String,
    /// Notify when they arrive. Plugin owned.
    pub notify_arrive: bool,
    /// Notify when they leave. Plugin owned.
    pub notify_depart: bool,
    /// Whether anybody is to keep track of whether they are home. Plugin owned,
    /// off unless somebody switches it on.
    pub track_presence: bool,
    /// Whether they are home. Daemon owned.
    pub state: PersonState,
    /// Where they are, when they are home. Daemon owned.
    pub current_location: Option<String>,
    /// When they last arrived. Daemon owned, and the column the plugin orders
    /// its person listing by, so it is written on every arrival without fail.
    pub last_arrived_at: Option<Timestamp>,
    /// When they last left. Daemon owned.
    pub last_departed_at: Option<Timestamp>,
}

/// The daemon-owned columns of one person, for writing back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonUpdate {
    /// Which person.
    pub item_id: String,
    /// Whether they are home.
    pub state: PersonState,
    /// Where they are.
    pub current_location: Option<String>,
    /// When they last arrived.
    pub last_arrived_at: Option<Timestamp>,
    /// When they last left.
    pub last_departed_at: Option<Timestamp>,
}

/// Something worth telling somebody about a person.
#[derive(Debug, Clone, PartialEq)]
pub struct PersonEvent {
    /// What happened.
    pub event_type: EventType,
    /// Which person.
    pub item_id: String,
    /// Their name, which is what a notification says.
    pub name: String,
    /// The device that caused it. Person events carry one so that the row in
    /// `ng_events` has a `device_id` and the notification dispatcher's
    /// per-device debounce has something to key on.
    pub mac: MacAddr,
    /// When it happened.
    pub at: Timestamp,
    /// Whether the person's notification flags allow delivery.
    pub notify: bool,
    /// Structured detail for `ng_events.details`.
    pub details: serde_json::Value,
}

/// What a change to the registry produced.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Outcome {
    /// Events to record and possibly deliver.
    pub events: Vec<PersonEvent>,
    /// People whose daemon-owned columns changed.
    pub updates: Vec<PersonUpdate>,
}

impl Outcome {
    /// True when nothing happened.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty() && self.updates.is_empty()
    }
}

/// What the registry knows about one device.
#[derive(Debug, Clone, Default)]
struct DeviceView {
    online: bool,
    ap_name: Option<String>,
    location: Option<String>,
    /// When this device was last heard from, which is what decides whose
    /// location a person takes.
    last_active: Option<Timestamp>,
    /// The last edge access point this device crossed, and when.
    last_edge: Option<(String, Timestamp)>,
    /// `ng_devices.counts_for_presence`: a person's explicit choice, or `None`
    /// to decide by type.
    counts_override: Option<bool>,
    /// The classified device type, which decides when nobody chose.
    device_type: Option<String>,
}

/// One thing a reconcile changed about people or ownership.
///
/// Returned rather than logged in place so that the caller does the logging and
/// the registry stays a pure state machine, which is what makes every transition
/// in this module testable without a subscriber installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryChange {
    /// A person the daemon had not seen before.
    PersonAdded {
        /// Their item id.
        item_id: String,
        /// Their name.
        name: String,
    },
    /// A person's plugin-owned fields changed.
    PersonEdited {
        /// Their item id.
        item_id: String,
        /// Their name, after the edit.
        name: String,
        /// What changed, as `column=value` pairs.
        fields: Vec<String>,
    },
    /// A person who is no longer in `ng_people`.
    PersonRemoved {
        /// Their item id.
        item_id: String,
        /// The name they had.
        name: String,
    },
    /// Something that decides whether a device counts for presence changed:
    /// its `counts_for_presence` override or its classified type.
    PresenceSettingChanged {
        /// Which device.
        mac: MacAddr,
        /// Which setting, as `ng_devices` names it.
        column: &'static str,
        /// What the registry held.
        from: String,
        /// What it holds now.
        to: String,
    },
    /// A device's owner changed, was set, or was cleared.
    OwnerChanged {
        /// Which device.
        mac: MacAddr,
        /// Who owned it, if anybody.
        from: Option<String>,
        /// Who owns it now, if anybody.
        to: Option<String>,
    },
}

/// People, the devices they own, and the state machine over both.
#[derive(Debug, Default)]
pub struct Registry {
    people: BTreeMap<String, Person>,
    owner: HashMap<MacAddr, String>,
    /// Ownership that came from `netgrasp.toml` rather than from the database.
    ///
    /// Held separately because a reconcile reads `ng_devices.owner_item_id`, and
    /// a device owned only by configuration has that column null. Without this,
    /// the first reconcile after startup would read the null as "nobody owns it"
    /// and quietly undo an install that has no Trovato plugin at all.
    config_owner: HashMap<MacAddr, String>,
    devices: HashMap<MacAddr, DeviceView>,
    /// The install's `presence_tracking` switch. Off unless configured on.
    tracking: bool,
    /// People whose `[[people]]` entry in `netgrasp.toml` sets
    /// `track_presence`. Either that or the database column turns tracking on
    /// for a person, so an install with no plugin can switch somebody on.
    config_tracked: HashSet<String>,
    /// People whose presence inputs changed since the last
    /// [`Registry::settle`]: who owns what, which devices count, whether they
    /// are tracked.
    unsettled: BTreeSet<String>,
}

impl Registry {
    /// Builds an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Registry::default()
    }

    /// Adds a person the registry did not have.
    ///
    /// Replaces an existing entry with the same `item_id`, keeping the incoming
    /// row's daemon-owned state, which is what makes reloading from Postgres at
    /// startup a plain overwrite.
    ///
    /// The person is left unsettled: the next [`Registry::settle`] checks the
    /// stored state against the devices, silently.
    pub fn insert_person(&mut self, person: Person) {
        self.unsettled.insert(person.item_id.clone());
        self.people.insert(person.item_id.clone(), person);
    }

    /// Records that a device belongs to a person.
    ///
    /// An owner whose person row is not present is remembered anyway. The plugin
    /// fills `owner_item_id` and mirrors `ng_people` on separate cron passes, so
    /// a device can legitimately point at a person that has not arrived yet; the
    /// mapping simply does nothing until it does.
    pub fn set_owner(&mut self, mac: MacAddr, item_id: impl Into<String>) {
        self.owner.insert(mac, item_id.into());
    }

    /// Every device somebody owns, from the database or from configuration.
    pub fn owned_macs(&self) -> impl Iterator<Item = MacAddr> + '_ {
        self.owner.keys().copied()
    }

    /// Records that configuration, rather than the database, says a device
    /// belongs to a person.
    ///
    /// Sets the ownership as well as remembering where it came from, so a caller
    /// never has to do both.
    pub fn set_config_owner(&mut self, mac: MacAddr, item_id: impl Into<String>) {
        let item_id = item_id.into();
        self.config_owner.insert(mac, item_id.clone());
        self.owner.insert(mac, item_id);
    }

    /// Sets the install's `presence_tracking` switch.
    ///
    /// Turning it either way leaves every person unsettled, so the next
    /// [`Registry::settle`] re-evaluates them all.
    pub fn set_tracking(&mut self, on: bool) {
        if self.tracking != on {
            self.tracking = on;
            self.unsettled.extend(self.people.keys().cloned());
        }
    }

    /// Whether the install's `presence_tracking` switch is on.
    #[must_use]
    pub fn tracking(&self) -> bool {
        self.tracking
    }

    /// Records that `netgrasp.toml` switches tracking on for a person.
    pub fn set_config_tracked(&mut self, item_id: impl Into<String>) {
        let item_id = item_id.into();
        self.unsettled.insert(item_id.clone());
        self.config_tracked.insert(item_id);
    }

    /// Records what decides whether a device counts for presence, without
    /// re-evaluating anybody. For seeding at startup; a reconcile uses
    /// [`Registry::reconcile_presence`], which reports what changed.
    pub fn set_presence_settings(
        &mut self,
        mac: MacAddr,
        counts_override: Option<bool>,
        device_type: Option<String>,
    ) {
        let view = self.devices.entry(mac).or_default();
        view.counts_override = counts_override;
        view.device_type = device_type;
    }

    /// Whether this device decides if its owner is home. See
    /// [`counts_for_presence`].
    #[must_use]
    pub fn counts(&self, mac: MacAddr) -> bool {
        self.devices.get(&mac).is_some_and(|view| {
            counts_for_presence(view.counts_override, view.device_type.as_deref())
        })
    }

    /// Whether anybody is keeping track of whether this person is home: the
    /// install's switch is on, theirs is on, and they own a device that counts.
    #[must_use]
    pub fn is_tracked(&self, item_id: &str) -> bool {
        let Some(person) = self.people.get(item_id) else {
            return false;
        };
        self.tracking
            && (person.track_presence || self.config_tracked.contains(item_id))
            && self
                .owner
                .iter()
                .any(|(mac, owner)| owner.as_str() == item_id && self.counts(*mac))
    }

    /// Folds the plugin's half of `ng_people` and `ng_devices.owner_item_id`
    /// back in, without disturbing the daemon's half.
    ///
    /// `people` is the whole mirror and `owners` the whole ownership column, one
    /// entry per device row, `None` where nobody owns it. Both are complete
    /// rather than deltas, because the daemon has no way to know what the plugin
    /// changed and a row that vanished is as much a change as one that appeared.
    ///
    /// What moves and what does not:
    ///
    /// - For somebody already known, only `name`, `notify_arrive`,
    ///   `notify_depart` and `track_presence` are taken. `state`, `current_location`,
    ///   `last_arrived_at` and `last_departed_at` are the daemon's, and the copy
    ///   in memory is ahead of the database's.
    /// - Somebody new is taken whole: their stored state is all there is.
    /// - Somebody no longer in the mirror is dropped. Devices that named them
    ///   keep the mapping, which then does nothing, exactly as a mapping that
    ///   points at a person the plugin has not mirrored yet does nothing.
    /// - An owner set to null falls back to configuration if `netgrasp.toml`
    ///   named one, and is otherwise cleared.
    ///
    /// Newly owned devices carry no presence here. The caller seeds that from
    /// the device table with [`Registry::restore_device`], which is the same
    /// silent seeding a restart does: a person is not announced as arriving
    /// because somebody ticked a box next to a phone that was already online.
    #[must_use]
    pub fn reconcile(
        &mut self,
        people: Vec<Person>,
        owners: &[(MacAddr, Option<String>)],
    ) -> Vec<RegistryChange> {
        let mut changes = Vec::new();
        let mut present: HashSet<String> = HashSet::with_capacity(people.len());

        for person in people {
            present.insert(person.item_id.clone());
            match self.people.get_mut(&person.item_id) {
                Some(known) => {
                    let mut fields = Vec::new();
                    if known.name != person.name {
                        fields.push(format!("name={:?}", person.name));
                        known.name.clone_from(&person.name);
                    }
                    if known.notify_arrive != person.notify_arrive {
                        fields.push(format!("notify_arrive={}", person.notify_arrive));
                        known.notify_arrive = person.notify_arrive;
                    }
                    if known.notify_depart != person.notify_depart {
                        fields.push(format!("notify_depart={}", person.notify_depart));
                        known.notify_depart = person.notify_depart;
                    }
                    if known.track_presence != person.track_presence {
                        fields.push(format!("track_presence={}", person.track_presence));
                        known.track_presence = person.track_presence;
                        self.unsettled.insert(person.item_id.clone());
                    }
                    if !fields.is_empty() {
                        changes.push(RegistryChange::PersonEdited {
                            item_id: person.item_id.clone(),
                            name: person.name.clone(),
                            fields,
                        });
                    }
                }
                None => {
                    changes.push(RegistryChange::PersonAdded {
                        item_id: person.item_id.clone(),
                        name: person.name.clone(),
                    });
                    // Taken whole, and then settled: the stored state is
                    // whatever the plugin or an older daemon left there.
                    self.unsettled.insert(person.item_id.clone());
                    self.people.insert(person.item_id.clone(), person);
                }
            }
        }

        self.people.retain(|item_id, person| {
            let kept = present.contains(item_id);
            if !kept {
                changes.push(RegistryChange::PersonRemoved {
                    item_id: item_id.clone(),
                    name: person.name.clone(),
                });
            }
            kept
        });

        for (mac, stored) in owners {
            // The database wins where it says anything, configuration is the
            // fallback where it says nothing. That is the precedence the startup
            // roster already applies, and a reconcile that used a different one
            // would change who owns a device the first time it ran.
            let wanted = stored
                .clone()
                .or_else(|| self.config_owner.get(mac).cloned());
            let current = self.owner.get(mac).cloned();
            if current == wanted {
                continue;
            }
            match &wanted {
                Some(item_id) => {
                    self.owner.insert(*mac, item_id.clone());
                }
                None => {
                    self.owner.remove(mac);
                }
            }
            // Both sides: the old owner may have just lost the device that kept
            // them home, and the new one may have just gained it.
            self.unsettled.extend(current.iter().cloned());
            self.unsettled.extend(wanted.iter().cloned());
            changes.push(RegistryChange::OwnerChanged {
                mac: *mac,
                from: current,
                to: wanted,
            });
        }

        changes
    }

    /// Folds in what decides whether each device counts for presence: the
    /// user-owned `counts_for_presence` override and the classified
    /// `device_type`, one entry per device row.
    ///
    /// The owner of a device whose answer may have changed is left unsettled,
    /// so the caller's [`Registry::settle`] re-evaluates them on the same tick.
    #[must_use]
    pub fn reconcile_presence(
        &mut self,
        devices: &[(MacAddr, Option<bool>, Option<String>)],
    ) -> Vec<RegistryChange> {
        let mut changes = Vec::new();
        for (mac, counts_override, device_type) in devices {
            let view = self.devices.entry(*mac).or_default();
            let mut changed = false;
            if view.counts_override != *counts_override {
                changes.push(RegistryChange::PresenceSettingChanged {
                    mac: *mac,
                    column: "counts_for_presence",
                    from: describe_override(view.counts_override),
                    to: describe_override(*counts_override),
                });
                view.counts_override = *counts_override;
                changed = true;
            }
            if view.device_type != *device_type {
                changes.push(RegistryChange::PresenceSettingChanged {
                    mac: *mac,
                    column: "device_type",
                    from: view.device_type.clone().unwrap_or_default(),
                    to: device_type.clone().unwrap_or_default(),
                });
                view.device_type.clone_from(device_type);
                changed = true;
            }
            if changed && let Some(owner) = self.owner.get(mac) {
                self.unsettled.insert(owner.clone());
            }
        }
        changes
    }

    /// The devices of every unsettled person, so the caller can reseed them
    /// from the device table before [`Registry::settle`] reads them.
    #[must_use]
    pub fn unsettled_devices(&self) -> Vec<MacAddr> {
        let mut macs: Vec<MacAddr> = self
            .owner
            .iter()
            .filter(|(_, owner)| self.unsettled.contains(owner.as_str()))
            .map(|(mac, _)| *mac)
            .collect();
        macs.sort_unstable();
        macs
    }

    /// Re-evaluates every person whose presence inputs changed since the last
    /// call, from the devices that count now.
    ///
    /// The result is recorded, never announced: the outcome carries updates
    /// and no events. A person becoming untracked, or going from home to away
    /// because a laptop stopped counting, is a change of settings and not
    /// somebody walking through the door. The arrival and departure timestamps
    /// are left alone for the same reason; they keep meaning "an arrival" and
    /// "a departure".
    #[must_use]
    pub fn settle(&mut self) -> Outcome {
        let unsettled = std::mem::take(&mut self.unsettled);
        let mut outcome = Outcome::default();
        for item_id in unsettled {
            outcome.merge(self.reevaluate(&item_id));
        }
        outcome
    }

    /// Re-evaluates every person, silently. What the daemon does at startup,
    /// where the global switch and everybody's stored state are read fresh.
    #[must_use]
    pub fn settle_all(&mut self) -> Outcome {
        self.unsettled.extend(self.people.keys().cloned());
        self.settle()
    }

    /// One person's state as the devices that count say it should be, written
    /// into the registry without an event.
    fn reevaluate(&mut self, item_id: &str) -> Outcome {
        if !self.people.contains_key(item_id) {
            return Outcome::default();
        }
        let (state, location) = if !self.is_tracked(item_id) {
            (PersonState::Untracked, None)
        } else if self.any_online(item_id) {
            (PersonState::Home, self.location_of_person(item_id))
        } else {
            (PersonState::Away, None)
        };
        let person = self
            .people
            .get_mut(item_id)
            .expect("the person was just checked");
        if person.state == state && person.current_location == location {
            return Outcome::default();
        }
        person.state = state;
        person.current_location = location;
        Outcome {
            events: Vec::new(),
            updates: vec![update_of(person)],
        }
    }

    /// How many people are known.
    #[must_use]
    pub fn len(&self) -> usize {
        self.people.len()
    }

    /// True when nobody is known.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.people.is_empty()
    }

    /// True when the registry can say anything at all: somebody is known and
    /// owns at least one device.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.people.is_empty()
            && self
                .owner
                .values()
                .any(|item_id| self.people.contains_key(item_id))
    }

    /// One person, by item id.
    #[must_use]
    pub fn person(&self, item_id: &str) -> Option<&Person> {
        self.people.get(item_id)
    }

    /// Every person, ordered by item id.
    #[must_use]
    pub fn people(&self) -> Vec<&Person> {
        self.people.values().collect()
    }

    /// Every person by name, for the CLI and for tests.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&Person> {
        self.people
            .values()
            .find(|p| p.name.eq_ignore_ascii_case(name.trim()))
    }

    /// The MACs one person owns.
    #[must_use]
    pub fn devices_of(&self, item_id: &str) -> Vec<MacAddr> {
        let mut macs: Vec<MacAddr> = self
            .owner
            .iter()
            .filter(|(_, owner)| owner.as_str() == item_id)
            .map(|(mac, _)| *mac)
            .collect();
        macs.sort_unstable();
        macs
    }

    /// Seeds a device's state without producing events.
    ///
    /// Used at startup, when every device's state is read back from Postgres.
    /// A restart must not announce that the whole household just arrived.
    pub fn restore_device(&mut self, mac: MacAddr, online: bool, at: Timestamp) {
        let view = self.devices.entry(mac).or_default();
        view.online = online;
        view.last_active = Some(at);
    }

    /// Seeds where a device is without producing events, for the same reason
    /// as [`Registry::restore_device`]: a person whose tracking was just
    /// switched on is somewhere already, and that is not a move.
    pub fn restore_location(
        &mut self,
        mac: MacAddr,
        ap_name: Option<String>,
        location: Option<String>,
    ) {
        let view = self.devices.entry(mac).or_default();
        if view.online {
            view.ap_name = ap_name;
            view.location = location;
        } else {
            view.ap_name = None;
            view.location = None;
        }
    }

    /// Records that a device was heard from, which is what decides whose
    /// location a person takes.
    ///
    /// Produces no events on its own. Coming online is [`Registry::device_online`].
    pub fn device_seen(&mut self, mac: MacAddr, at: Timestamp) {
        if !self.owner.contains_key(&mac) {
            return;
        }
        let view = self.devices.entry(mac).or_default();
        if view.last_active.is_none_or(|previous| at > previous) {
            view.last_active = Some(at);
        }
    }

    /// A device came online.
    #[must_use]
    pub fn device_online(&mut self, mac: MacAddr, at: Timestamp) -> Outcome {
        let Some(item_id) = self.owner.get(&mac).cloned() else {
            return Outcome::default();
        };
        {
            let view = self.devices.entry(mac).or_default();
            view.online = true;
            view.last_active = Some(at);
        }
        // A laptop coming online says nothing about whether its owner walked
        // in, and nobody asked about a person who is not tracked.
        if !self.counts(mac) || !self.is_tracked(&item_id) {
            return Outcome::default();
        }
        let Some(person) = self.people.get(&item_id) else {
            return Outcome::default();
        };

        let mut outcome = Outcome::default();
        if person.state == PersonState::Untracked {
            // Tracked, but not settled since the settings changed. Settling is
            // silent, and so is this.
            return self.reevaluate(&item_id);
        }
        if person.state == PersonState::Away {
            let via = self.edge_evidence(mac, at);
            let location = self.location_of_person(&item_id);
            let person = self
                .people
                .get_mut(&item_id)
                .expect("the person was just read");
            person.state = PersonState::Home;
            person.last_arrived_at = Some(at);
            person.current_location.clone_from(&location);
            outcome.events.push(PersonEvent {
                event_type: EventType::PersonArrived,
                item_id: item_id.clone(),
                name: person.name.clone(),
                mac,
                at,
                notify: person.notify_arrive,
                details: json!({
                    "person": person.name,
                    "person_item_id": item_id,
                    "device": mac.to_string(),
                    "location": location,
                    "via": via,
                }),
            });
            outcome.updates.push(update_of(person));
        } else {
            outcome.merge(self.refresh_location(&item_id, mac, at));
        }
        outcome
    }

    /// A device went offline.
    #[must_use]
    pub fn device_offline(&mut self, mac: MacAddr, at: Timestamp) -> Outcome {
        let Some(item_id) = self.owner.get(&mac).cloned() else {
            return Outcome::default();
        };
        {
            let view = self.devices.entry(mac).or_default();
            view.online = false;
            // Where an offline device is, is nowhere. Its history is in
            // ng_location_history; keeping a stale place here would make a
            // person's location follow a tablet in a drawer.
            view.ap_name = None;
            view.location = None;
        }
        if !self.people.contains_key(&item_id) || !self.counts(mac) || !self.is_tracked(&item_id) {
            return Outcome::default();
        }

        let mut outcome = Outcome::default();
        if self.any_online(&item_id) {
            outcome.merge(self.refresh_location(&item_id, mac, at));
            return outcome;
        }
        let via = self.edge_evidence_for_person(&item_id);
        let person = self
            .people
            .get_mut(&item_id)
            .expect("the person was just checked");
        if person.state != PersonState::Home {
            return outcome;
        }
        person.state = PersonState::Away;
        person.last_departed_at = Some(at);
        person.current_location = None;
        outcome.events.push(PersonEvent {
            event_type: EventType::PersonDeparted,
            item_id: item_id.clone(),
            name: person.name.clone(),
            mac,
            at,
            notify: person.notify_depart,
            details: json!({
                "person": person.name,
                "person_item_id": item_id,
                "device": mac.to_string(),
                "via": via,
            }),
        });
        outcome.updates.push(update_of(person));
        outcome
    }

    /// A device moved to a different access point.
    ///
    /// `movement` is what [`crate::location::LocationMap::movement`] made of the crossing. It is
    /// passed in rather than recomputed so that the device event and the person
    /// event can never disagree about what happened.
    #[must_use]
    pub fn device_moved(
        &mut self,
        mac: MacAddr,
        place: &Place,
        movement: Movement,
        at: Timestamp,
    ) -> Outcome {
        let Some(item_id) = self.owner.get(&mac).cloned() else {
            return Outcome::default();
        };
        {
            let view = self.devices.entry(mac).or_default();
            view.ap_name = Some(place.ap_name.clone());
            view.location = Some(place.location.clone());
            view.last_active = Some(at);
            // The evidence is "this device was at an edge, at this time",
            // recorded whenever it is on one. That covers both directions with
            // one rule: on the way in the crossing is read afterwards, when the
            // device comes online indoors; on the way out it is read afterwards
            // too, when the device falls silent. Roaming between interior rooms
            // touches nothing, so wandering to the kitchen cannot erase the
            // record of somebody having come in through the driveway.
            if place.edge {
                view.last_edge = Some((place.ap_name.clone(), at));
            }
            tracing::debug!(
                %mac,
                ap = %place.ap_name,
                location = %place.location,
                %movement,
                "a device changed place"
            );
        }
        if !self.people.contains_key(&item_id) || !self.counts(mac) || !self.is_tracked(&item_id) {
            return Outcome::default();
        }
        self.refresh_location(&item_id, mac, at)
    }

    /// Recomputes a person's location and reports it if it changed.
    ///
    /// `trigger` is only used to attribute the event to a device; the location
    /// itself always comes from whichever owned device was heard from most
    /// recently.
    fn refresh_location(&mut self, item_id: &str, trigger: MacAddr, at: Timestamp) -> Outcome {
        let location = self.location_of_person(item_id);
        let Some(person) = self.people.get_mut(item_id) else {
            return Outcome::default();
        };
        if person.state != PersonState::Home || person.current_location == location {
            return Outcome::default();
        }
        let previous = person.current_location.clone();
        person.current_location.clone_from(&location);
        let mut outcome = Outcome::default();
        // A location the daemon cannot determine is not a move to nowhere: it is
        // an enricher that has not answered yet. Recording it would fill the
        // event log with round trips through null.
        if location.is_some() {
            outcome.events.push(PersonEvent {
                event_type: EventType::PersonLocationChanged,
                item_id: item_id.to_string(),
                name: person.name.clone(),
                mac: trigger,
                at,
                // There is no per-person flag for this in ng_people, and one
                // would need a column the plugin has not seen. It is recorded
                // and never delivered: somebody walking between rooms is not
                // worth a phone buzzing.
                notify: false,
                details: json!({
                    "person": person.name,
                    "person_item_id": item_id,
                    "device": trigger.to_string(),
                    "previous_location": previous,
                    "location": location,
                }),
            });
        }
        outcome.updates.push(update_of(person));
        outcome
    }

    /// The devices this person owns that count for presence.
    fn counting_devices<'a>(&'a self, item_id: &'a str) -> impl Iterator<Item = MacAddr> + 'a {
        self.owner
            .iter()
            .filter(move |(mac, owner)| owner.as_str() == item_id && self.counts(**mac))
            .map(|(mac, _)| *mac)
    }

    /// Whether any device this person owns that counts is online.
    fn any_online(&self, item_id: &str) -> bool {
        self.counting_devices(item_id)
            .any(|mac| self.devices.get(&mac).is_some_and(|v| v.online))
    }

    /// The location of the person's most recently active online device that
    /// counts. A laptop in the study is not where its owner is.
    fn location_of_person(&self, item_id: &str) -> Option<String> {
        self.counting_devices(item_id)
            .filter_map(|mac| self.devices.get(&mac))
            .filter(|view| view.online && view.location.is_some())
            .max_by(|a, b| {
                a.last_active
                    .cmp(&b.last_active)
                    // Two devices heard from in the same instant is a tie a
                    // clock cannot break, so break it on the location string.
                    // Arbitrary, but stable, which is what stops the person's
                    // location flapping between two rooms forever.
                    .then_with(|| a.location.cmp(&b.location))
            })
            .and_then(|view| view.location.clone())
    }

    /// The edge access point one device crossed recently, if any.
    fn edge_evidence(&self, mac: MacAddr, at: Timestamp) -> Option<String> {
        self.devices
            .get(&mac)
            .and_then(|view| view.last_edge.clone())
            .filter(|(_, when)| at >= *when && at - *when <= EDGE_EVIDENCE_WINDOW)
            .map(|(ap, _)| ap)
    }

    /// The edge access point a person's devices crossed on the way out.
    ///
    /// Measured against each device's own last activity rather than against the
    /// departure, because a departure is declared a whole offline timeout after
    /// the device fell silent. See [`EDGE_EVIDENCE_WINDOW`].
    fn edge_evidence_for_person(&self, item_id: &str) -> Option<String> {
        self.counting_devices(item_id)
            .filter_map(|mac| self.devices.get(&mac))
            .filter_map(|view| {
                let (ap, crossed) = view.last_edge.clone()?;
                let last_active = view.last_active?;
                (last_active >= crossed && last_active - crossed <= EDGE_EVIDENCE_WINDOW)
                    .then_some((ap, crossed))
            })
            .max_by_key(|(_, crossed)| *crossed)
            .map(|(ap, _)| ap)
    }
}

impl Outcome {
    /// Folds another outcome into this one, keeping one update per person.
    ///
    /// Every event is kept, because each is a separate thing that happened; only
    /// the write-back collapses, because two updates for one person are two
    /// snapshots of the same row and only the later one is true.
    pub fn merge(&mut self, other: Outcome) {
        self.events.extend(other.events);
        for update in other.updates {
            if let Some(existing) = self
                .updates
                .iter_mut()
                .find(|u| u.item_id == update.item_id)
            {
                *existing = update;
            } else {
                self.updates.push(update);
            }
        }
    }
}

/// An override as a log line reads it.
fn describe_override(value: Option<bool>) -> String {
    match value {
        None => "by type".to_string(),
        Some(true) => "counts".to_string(),
        Some(false) => "does not count".to_string(),
    }
}

/// The daemon-owned columns of a person, as a write-back.
fn update_of(person: &Person) -> PersonUpdate {
    PersonUpdate {
        item_id: person.item_id.clone(),
        state: person.state,
        current_location: person.current_location.clone(),
        last_arrived_at: person.last_arrived_at,
        last_departed_at: person.last_departed_at,
    }
}

/// Builds the ownership map and the people the daemon knows about.
///
/// Kept separate from [`Registry`] so that the merge rule between configuration
/// and database is one readable function rather than scattered through the state
/// machine.
#[derive(Debug, Default)]
pub struct Roster {
    /// People, keyed by item id.
    pub people: Vec<Person>,
    /// Which person owns which device, lowest precedence first: the registry
    /// keeps the last owner recorded for a MAC.
    pub owners: Vec<(MacAddr, String)>,
    /// The subset of `owners` that came from `netgrasp.toml` rather than from
    /// `ng_devices.owner_item_id`.
    ///
    /// Carried separately so a later reconcile can tell a device nobody owns
    /// from one the database has nothing to say about. See
    /// [`Registry::set_config_owner`].
    pub config_owners: Vec<(MacAddr, String)>,
}

impl Roster {
    /// Loads a registry from a roster.
    #[must_use]
    pub fn into_registry(self) -> Registry {
        let mut registry = Registry::new();
        let known: HashSet<String> = self.people.iter().map(|p| p.item_id.clone()).collect();
        for person in self.people {
            registry.insert_person(person);
        }
        // Recorded before the effective list, so an owner configuration supplies
        // is remembered as a fallback even when the database overrides it.
        for (mac, item_id) in self.config_owners {
            if known.contains(&item_id) {
                registry.set_config_owner(mac, item_id);
            }
        }
        for (mac, item_id) in self.owners {
            if known.contains(&item_id) {
                registry.set_owner(mac, item_id);
            } else {
                // The plugin fills owner_item_id and mirrors ng_people on
                // separate passes, so this is a normal intermediate state and
                // not a broken database.
                tracing::debug!(
                    %mac,
                    item_id,
                    "a device names an owner with no ng_people row yet; ignoring it for now"
                );
            }
        }
        registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UnifiConfig;
    use crate::location::LocationMap;

    fn base() -> Timestamp {
        Timestamp::from_utc(2026, 8, 14, 17, 0, 0).expect("valid time")
    }

    fn at(secs: i64) -> Timestamp {
        base() + SignedDuration::from_secs(secs)
    }

    fn mac(s: &str) -> MacAddr {
        s.parse().expect("test mac")
    }

    const PHONE: &str = "3c:22:fb:00:00:01";
    const LAPTOP: &str = "3c:22:fb:00:00:02";
    const WATCH: &str = "3c:22:fb:00:00:03";

    fn map() -> LocationMap {
        let mut cfg = UnifiConfig::default();
        cfg.locations
            .insert("Driveway AP".into(), "Driveway".into());
        cfg.locations.insert("Garage AP".into(), "Garage".into());
        cfg.locations
            .insert("Living Room AP".into(), "Living Room".into());
        cfg.locations.insert("Kitchen AP".into(), "Kitchen".into());
        cfg.locations
            .insert("Backyard AP".into(), "Backyard".into());
        cfg.edge_aps = vec!["Driveway AP".into(), "Garage AP".into()];
        LocationMap::from_unifi(&cfg)
    }

    fn person(item_id: &str, name: &str) -> Person {
        Person {
            item_id: item_id.into(),
            name: name.into(),
            notify_arrive: true,
            notify_depart: true,
            track_presence: true,
            state: PersonState::Away,
            current_location: None,
            last_arrived_at: None,
            last_departed_at: None,
        }
    }

    /// Gives a device its classified type, with no override.
    fn typed(r: &mut Registry, m: &str, device_type: &str) {
        r.set_presence_settings(mac(m), None, Some(device_type.into()));
    }

    /// One person owning a phone and a laptop, both offline, with tracking on
    /// for the install and for them. The phone counts by type; the laptop does
    /// not.
    fn registry() -> Registry {
        let mut r = Registry::new();
        r.set_tracking(true);
        r.insert_person(person("person-1", "Jeremy"));
        r.set_owner(mac(PHONE), "person-1");
        r.set_owner(mac(LAPTOP), "person-1");
        typed(&mut r, PHONE, "phone");
        typed(&mut r, LAPTOP, "computer");
        typed(&mut r, WATCH, "wearable");
        let _ = r.settle();
        r
    }

    /// The same, with the laptop switched on as a presence device by choice,
    /// for the rules about a person with two devices that both count.
    fn registry_with_counting_laptop() -> Registry {
        let mut r = registry();
        r.set_presence_settings(mac(LAPTOP), Some(true), Some("computer".into()));
        r
    }

    /// Walks a device through a sequence of access points, as the daemon does.
    fn walk(r: &mut Registry, m: MacAddr, aps: &[(&str, i64)]) -> Outcome {
        let map = map();
        let mut previous: Option<String> = None;
        let mut outcome = Outcome::default();
        for (ap, secs) in aps {
            let place = map.place(ap);
            let movement = map.movement(previous.as_deref(), ap);
            outcome.merge(r.device_moved(m, &place, movement, at(*secs)));
            previous = Some((*ap).to_string());
        }
        outcome
    }

    fn kinds(outcome: &Outcome) -> Vec<EventType> {
        outcome.events.iter().map(|e| e.event_type).collect()
    }

    #[test]
    fn the_first_owned_device_online_is_an_arrival() {
        let mut r = registry();
        let outcome = r.device_online(mac(PHONE), base());
        assert_eq!(kinds(&outcome), vec![EventType::PersonArrived]);
        assert_eq!(
            r.by_name("Jeremy").expect("person").state,
            PersonState::Home
        );
        assert_eq!(
            r.by_name("Jeremy").expect("person").last_arrived_at,
            Some(base())
        );
    }

    #[test]
    fn a_second_device_coming_online_is_not_a_second_arrival() {
        let mut r = registry();
        let _ = r.device_online(mac(PHONE), base());
        let outcome = r.device_online(mac(LAPTOP), at(60));
        assert!(
            !kinds(&outcome).contains(&EventType::PersonArrived),
            "{outcome:?}"
        );
    }

    #[test]
    fn a_person_is_still_home_while_any_counting_device_is_online() {
        let mut r = registry_with_counting_laptop();
        let _ = r.device_online(mac(PHONE), base());
        let _ = r.device_online(mac(LAPTOP), at(10));
        let outcome = r.device_offline(mac(PHONE), at(600));
        assert!(
            !kinds(&outcome).contains(&EventType::PersonDeparted),
            "the laptop is still online: {outcome:?}"
        );
        assert_eq!(
            r.by_name("Jeremy").expect("person").state,
            PersonState::Home
        );
    }

    #[test]
    fn the_last_counting_device_going_offline_is_a_departure() {
        let mut r = registry_with_counting_laptop();
        let _ = r.device_online(mac(PHONE), base());
        let _ = r.device_online(mac(LAPTOP), at(10));
        let _ = r.device_offline(mac(PHONE), at(600));
        let outcome = r.device_offline(mac(LAPTOP), at(700));
        assert_eq!(kinds(&outcome), vec![EventType::PersonDeparted]);
        let p = r.by_name("Jeremy").expect("person");
        assert_eq!(p.state, PersonState::Away);
        assert_eq!(p.last_departed_at, Some(at(700)));
        assert_eq!(p.current_location, None);
    }

    #[test]
    fn a_departure_is_not_announced_twice() {
        let mut r = registry();
        let _ = r.device_online(mac(PHONE), base());
        let _ = r.device_offline(mac(PHONE), at(600));
        let outcome = r.device_offline(mac(PHONE), at(700));
        assert!(outcome.events.is_empty(), "{outcome:?}");
    }

    #[test]
    fn arriving_through_the_driveway_names_the_driveway() {
        // The demo case: a device associates at the driveway AP, comes indoors,
        // and settles in the backyard.
        let mut r = registry();
        let _ = walk(
            &mut r,
            mac(PHONE),
            &[("Driveway AP", 0), ("Living Room AP", 30)],
        );
        let outcome = r.device_online(mac(PHONE), at(31));
        let arrival = outcome
            .events
            .iter()
            .find(|e| e.event_type == EventType::PersonArrived)
            .expect("an arrival");
        assert_eq!(arrival.details["via"], "Driveway AP");
    }

    #[test]
    fn leaving_through_the_garage_names_the_garage() {
        let mut r = registry();
        let _ = r.device_online(mac(PHONE), base());
        let _ = walk(
            &mut r,
            mac(PHONE),
            &[("Living Room AP", 10), ("Garage AP", 60)],
        );
        let outcome = r.device_offline(mac(PHONE), at(120));
        let departure = outcome
            .events
            .iter()
            .find(|e| e.event_type == EventType::PersonDeparted)
            .expect("a departure");
        assert_eq!(departure.details["via"], "Garage AP");
    }

    #[test]
    fn roaming_between_rooms_never_produces_an_arrival_or_a_departure() {
        // The case that must not fire.
        let mut r = registry();
        let _ = r.device_online(mac(PHONE), base());
        let outcome = walk(
            &mut r,
            mac(PHONE),
            &[
                ("Kitchen AP", 10),
                ("Living Room AP", 20),
                ("Kitchen AP", 30),
            ],
        );
        for kind in kinds(&outcome) {
            assert_eq!(
                kind,
                EventType::PersonLocationChanged,
                "roaming produced {kind}"
            );
        }
        assert_eq!(
            r.by_name("Jeremy").expect("person").state,
            PersonState::Home
        );
    }

    #[test]
    fn roaming_does_not_overwrite_the_evidence_of_how_somebody_got_in() {
        let mut r = registry();
        let _ = walk(
            &mut r,
            mac(PHONE),
            &[
                ("Driveway AP", 0),
                ("Living Room AP", 30),
                ("Kitchen AP", 60),
            ],
        );
        let outcome = r.device_online(mac(PHONE), at(61));
        let arrival = outcome
            .events
            .iter()
            .find(|e| e.event_type == EventType::PersonArrived)
            .expect("an arrival");
        assert_eq!(
            arrival.details["via"], "Driveway AP",
            "wandering to the kitchen must not erase the driveway"
        );
    }

    #[test]
    fn a_departure_hours_after_the_last_packet_still_names_the_edge_crossed() {
        // Regression. A departure is declared a whole offline timeout after the
        // device fell silent, three hours by default. Measuring the evidence
        // window against the departure rather than against the device's last
        // activity put every crossing outside a fifteen-minute window forever,
        // so no departure ever carried a `via` at all.
        let mut r = registry();
        let _ = r.device_online(mac(PHONE), base());
        let _ = walk(
            &mut r,
            mac(PHONE),
            &[("Living Room AP", 10), ("Garage AP", 60)],
        );
        // Three hours of silence, then the sweep declares them gone.
        let outcome = r.device_offline(mac(PHONE), at(60 + 3 * 3600));
        let departure = outcome
            .events
            .iter()
            .find(|e| e.event_type == EventType::PersonDeparted)
            .expect("a departure");
        assert_eq!(departure.details["via"], "Garage AP");
    }

    #[test]
    fn an_edge_crossed_long_before_the_last_packet_is_not_how_they_left() {
        // They came in through the driveway at breakfast and left through a door
        // with no access point on it. The driveway is not the answer.
        let mut r = registry();
        let _ = walk(&mut r, mac(PHONE), &[("Driveway AP", 0)]);
        let _ = r.device_online(mac(PHONE), at(10));
        let _ = walk(&mut r, mac(PHONE), &[("Living Room AP", 60)]);
        // Hours of ordinary indoor activity, then silence.
        r.device_seen(mac(PHONE), at(8 * 3600));
        let outcome = r.device_offline(mac(PHONE), at(11 * 3600));
        let departure = outcome
            .events
            .iter()
            .find(|e| e.event_type == EventType::PersonDeparted)
            .expect("a departure");
        assert!(
            departure.details["via"].is_null(),
            "{:?}",
            departure.details
        );
    }

    #[test]
    fn a_stale_edge_crossing_is_not_offered_as_evidence() {
        let mut r = registry();
        let _ = walk(&mut r, mac(PHONE), &[("Driveway AP", 0)]);
        // Well past the evidence window: this morning's arrival is not the
        // reason for tonight's.
        let outcome = r.device_online(mac(PHONE), at(60 * 60 * 9));
        let arrival = outcome
            .events
            .iter()
            .find(|e| e.event_type == EventType::PersonArrived)
            .expect("an arrival");
        assert!(arrival.details["via"].is_null(), "{:?}", arrival.details);
    }

    #[test]
    fn a_persons_location_follows_their_most_recently_active_device() {
        let mut r = registry_with_counting_laptop();
        let _ = r.device_online(mac(PHONE), base());
        let _ = r.device_online(mac(LAPTOP), at(1));
        let _ = walk(&mut r, mac(LAPTOP), &[("Kitchen AP", 10)]);
        let outcome = walk(&mut r, mac(PHONE), &[("Backyard AP", 20)]);
        assert_eq!(
            r.by_name("Jeremy")
                .expect("person")
                .current_location
                .as_deref(),
            Some("Backyard"),
            "the phone spoke last"
        );
        assert!(kinds(&outcome).contains(&EventType::PersonLocationChanged));

        // The laptop speaks again and the person is at the laptop.
        let _ = walk(&mut r, mac(LAPTOP), &[("Kitchen AP", 30)]);
        r.device_seen(mac(LAPTOP), at(30));
        assert_eq!(
            r.by_name("Jeremy")
                .expect("person")
                .current_location
                .as_deref(),
            Some("Kitchen")
        );
    }

    #[test]
    fn a_device_going_offline_hands_the_location_to_the_one_still_online() {
        let mut r = registry_with_counting_laptop();
        let _ = r.device_online(mac(PHONE), base());
        let _ = r.device_online(mac(LAPTOP), at(1));
        let _ = walk(&mut r, mac(LAPTOP), &[("Kitchen AP", 10)]);
        let _ = walk(&mut r, mac(PHONE), &[("Backyard AP", 20)]);
        assert_eq!(
            r.by_name("Jeremy")
                .expect("person")
                .current_location
                .as_deref(),
            Some("Backyard")
        );

        let outcome = r.device_offline(mac(PHONE), at(30));
        assert_eq!(
            r.by_name("Jeremy")
                .expect("person")
                .current_location
                .as_deref(),
            Some("Kitchen"),
            "the phone left, so the laptop's room is where they are"
        );
        assert!(kinds(&outcome).contains(&EventType::PersonLocationChanged));
    }

    #[test]
    fn the_same_location_twice_is_not_a_change() {
        let mut r = registry();
        let _ = r.device_online(mac(PHONE), base());
        let _ = walk(&mut r, mac(PHONE), &[("Kitchen AP", 10)]);
        let outcome = walk(&mut r, mac(PHONE), &[("Kitchen AP", 20)]);
        assert!(
            !kinds(&outcome).contains(&EventType::PersonLocationChanged),
            "{outcome:?}"
        );
    }

    #[test]
    fn a_location_that_is_not_yet_known_is_not_a_move_to_nowhere() {
        // Before the first enrichment poll answers, nobody has a location. That
        // must not fill the event log with round trips through null.
        let mut r = registry();
        let outcome = r.device_online(mac(PHONE), base());
        assert_eq!(kinds(&outcome), vec![EventType::PersonArrived]);
        let outcome = r.device_offline(mac(PHONE), at(60));
        assert_eq!(kinds(&outcome), vec![EventType::PersonDeparted]);
    }

    #[test]
    fn a_device_nobody_owns_produces_nothing() {
        let mut r = registry();
        assert!(r.device_online(mac(WATCH), base()).is_empty());
        assert!(r.device_offline(mac(WATCH), at(10)).is_empty());
        assert!(walk(&mut r, mac(WATCH), &[("Kitchen AP", 20)]).is_empty());
    }

    #[test]
    fn a_device_owned_by_a_person_the_registry_has_not_mirrored_yet_is_harmless() {
        // The plugin fills owner_item_id and mirrors ng_people on separate cron
        // passes, so this is a normal intermediate state.
        let mut r = Registry::new();
        r.set_owner(mac(PHONE), "person-not-mirrored-yet");
        assert!(r.device_online(mac(PHONE), base()).is_empty());
        assert!(!r.is_active());
    }

    #[test]
    fn restoring_devices_at_startup_announces_nothing() {
        // The whole household being home is not news every time the daemon
        // restarts.
        let mut r = registry();
        r.restore_device(mac(PHONE), true, base());
        r.restore_device(mac(LAPTOP), false, base());
        assert_eq!(
            r.by_name("Jeremy").expect("person").state,
            PersonState::Away,
            "restore seeds devices, not people"
        );
        // ...and the next real transition still works.
        let outcome = r.device_online(mac(PHONE), at(10));
        assert_eq!(kinds(&outcome), vec![EventType::PersonArrived]);
    }

    #[test]
    fn person_events_carry_the_notification_flags_from_the_person_row() {
        let mut r = Registry::new();
        r.set_tracking(true);
        r.insert_person(Person {
            notify_arrive: true,
            notify_depart: false,
            ..person("person-1", "Jamie")
        });
        r.set_owner(mac(PHONE), "person-1");
        typed(&mut r, PHONE, "phone");

        let arrival = r.device_online(mac(PHONE), base());
        assert!(arrival.events[0].notify, "notify_arrive is on");
        let departure = r.device_offline(mac(PHONE), at(60));
        assert!(!departure.events[0].notify, "notify_depart is off");
    }

    #[test]
    fn a_location_change_is_recorded_but_never_delivered() {
        let mut r = registry();
        let _ = r.device_online(mac(PHONE), base());
        let outcome = walk(&mut r, mac(PHONE), &[("Kitchen AP", 10)]);
        let moved = outcome
            .events
            .iter()
            .find(|e| e.event_type == EventType::PersonLocationChanged)
            .expect("a location change");
        assert!(
            !moved.notify,
            "somebody walking between rooms is not worth a phone buzzing"
        );
    }

    #[test]
    fn an_update_is_produced_for_every_state_change_so_ng_people_stays_current() {
        let mut r = registry();
        let arrival = r.device_online(mac(PHONE), base());
        let update = &arrival.updates[0];
        assert_eq!(update.item_id, "person-1");
        assert_eq!(update.state, PersonState::Home);
        assert_eq!(update.last_arrived_at, Some(base()));

        let departure = r.device_offline(mac(PHONE), at(60));
        assert_eq!(departure.updates[0].state, PersonState::Away);
        assert_eq!(departure.updates[0].last_departed_at, Some(at(60)));
        assert_eq!(
            departure.updates[0].last_arrived_at,
            Some(base()),
            "the arrival timestamp survives the departure"
        );
    }

    #[test]
    fn merging_outcomes_keeps_one_update_per_person() {
        let mut a = Outcome::default();
        a.merge(Outcome {
            events: Vec::new(),
            updates: vec![PersonUpdate {
                item_id: "person-1".into(),
                state: PersonState::Home,
                current_location: Some("Kitchen".into()),
                last_arrived_at: None,
                last_departed_at: None,
            }],
        });
        a.merge(Outcome {
            events: Vec::new(),
            updates: vec![PersonUpdate {
                item_id: "person-1".into(),
                state: PersonState::Home,
                current_location: Some("Backyard".into()),
                last_arrived_at: None,
                last_departed_at: None,
            }],
        });
        assert_eq!(a.updates.len(), 1);
        assert_eq!(a.updates[0].current_location.as_deref(), Some("Backyard"));
    }

    #[test]
    fn a_reconcile_takes_the_plugin_s_fields_and_leaves_the_daemon_s_alone() {
        let mut r = registry();
        // Jeremy is home, which is the daemon's finding and not the plugin's.
        let _ = r.device_online(mac(PHONE), base());
        assert_eq!(
            r.by_name("Jeremy").expect("Jeremy").state,
            PersonState::Home
        );

        // The mirror still has him away, with an edited name and flags.
        let mut stored = person("person-1", "Jeremy Andrews");
        stored.notify_depart = false;
        let changes = r.reconcile(vec![stored], &[(mac(PHONE), Some("person-1".into()))]);

        let jeremy = r.person("person-1").expect("still there");
        assert_eq!(jeremy.name, "Jeremy Andrews");
        assert!(!jeremy.notify_depart);
        assert!(jeremy.notify_arrive);
        // Daemon-owned, and the in-memory copy is the newer one.
        assert_eq!(jeremy.state, PersonState::Home);
        assert_eq!(jeremy.last_arrived_at, Some(base()));
        assert_eq!(changes.len(), 1, "{changes:?}");
        assert!(matches!(
            &changes[0],
            RegistryChange::PersonEdited { fields, .. } if fields.len() == 2
        ));
    }

    #[test]
    fn a_reconcile_adds_a_new_person_and_drops_one_the_mirror_no_longer_has() {
        let mut r = registry();
        let changes = r.reconcile(vec![person("person-2", "Jamie")], &[]);
        assert!(r.person("person-1").is_none(), "removed with the mirror");
        assert_eq!(r.by_name("Jamie").expect("Jamie").item_id, "person-2");
        assert_eq!(changes.len(), 2, "{changes:?}");
        assert!(changes.iter().any(|c| matches!(
            c,
            RegistryChange::PersonAdded { name, .. } if name == "Jamie"
        )));
        assert!(changes.iter().any(|c| matches!(
            c,
            RegistryChange::PersonRemoved { name, .. } if name == "Jeremy"
        )));
    }

    #[test]
    fn a_reconcile_moves_a_device_to_its_new_owner() {
        let mut r = registry();
        r.insert_person(person("person-2", "Jamie"));
        let changes = r.reconcile(
            vec![person("person-1", "Jeremy"), person("person-2", "Jamie")],
            &[
                (mac(PHONE), Some("person-2".into())),
                (mac(LAPTOP), Some("person-1".into())),
            ],
        );
        assert_eq!(r.devices_of("person-2"), vec![mac(PHONE)]);
        assert_eq!(r.devices_of("person-1"), vec![mac(LAPTOP)]);
        assert_eq!(changes.len(), 1, "only the phone moved: {changes:?}");
    }

    #[test]
    fn a_reconcile_clears_an_owner_the_database_has_taken_away() {
        let mut r = registry();
        let changes = r.reconcile(vec![person("person-1", "Jeremy")], &[(mac(PHONE), None)]);
        assert_eq!(r.devices_of("person-1"), vec![mac(LAPTOP)]);
        assert!(matches!(
            changes.as_slice(),
            [RegistryChange::OwnerChanged { to: None, .. }]
        ));
        // And an unowned device's presence says nothing about anybody.
        assert!(r.device_online(mac(PHONE), base()).is_empty());
    }

    #[test]
    fn a_reconcile_does_not_undo_ownership_that_came_from_configuration() {
        // An install with no Trovato plugin has owner_item_id null on every row
        // and netgrasp.toml as the only source of ownership. Reading the null as
        // "nobody owns it" would disable people tracking ten seconds after
        // start, which is the worst kind of regression: it looks like it works.
        let mut r = Registry::new();
        r.insert_person(person("person-1", "Jeremy"));
        r.set_config_owner(mac(PHONE), "person-1");
        let changes = r.reconcile(vec![person("person-1", "Jeremy")], &[(mac(PHONE), None)]);
        assert!(changes.is_empty(), "{changes:?}");
        assert_eq!(r.devices_of("person-1"), vec![mac(PHONE)]);
    }

    #[test]
    fn the_database_still_overrides_configuration_on_a_reconcile() {
        let mut r = Registry::new();
        r.insert_person(person("person-1", "Jeremy"));
        r.insert_person(person("person-2", "Jamie"));
        r.set_config_owner(mac(PHONE), "person-1");
        let _ = r.reconcile(
            vec![person("person-1", "Jeremy"), person("person-2", "Jamie")],
            &[(mac(PHONE), Some("person-2".into()))],
        );
        assert_eq!(r.devices_of("person-2"), vec![mac(PHONE)]);
        // ...and giving it back to nobody falls back to configuration again.
        let _ = r.reconcile(
            vec![person("person-1", "Jeremy"), person("person-2", "Jamie")],
            &[(mac(PHONE), None)],
        );
        assert_eq!(r.devices_of("person-1"), vec![mac(PHONE)]);
    }

    #[test]
    fn the_roster_drops_owners_whose_person_is_missing_and_keeps_the_rest() {
        let roster = Roster {
            people: vec![person("person-1", "Jeremy")],
            owners: vec![
                (mac(PHONE), "person-1".into()),
                (mac(LAPTOP), "person-not-mirrored-yet".into()),
            ],
            config_owners: Vec::new(),
        };
        let r = roster.into_registry();
        assert_eq!(r.devices_of("person-1"), vec![mac(PHONE)]);
        assert!(r.is_active());
    }

    #[test]
    fn person_state_round_trips_and_defaults_away() {
        for s in [PersonState::Home, PersonState::Away, PersonState::Untracked] {
            assert_eq!(PersonState::from_db(s.as_str()), s);
        }
        assert_eq!(PersonState::from_db("nonsense"), PersonState::Away);
    }

    #[test]
    fn two_people_do_not_affect_each_other() {
        let mut r = registry();
        r.insert_person(person("person-2", "Jamie"));
        r.set_owner(mac(WATCH), "person-2");

        let _ = r.device_online(mac(PHONE), base());
        assert_eq!(
            r.by_name("Jamie").expect("jamie").state,
            PersonState::Away,
            "Jeremy arriving does not bring Jamie home"
        );
        let outcome = r.device_online(mac(WATCH), at(10));
        assert_eq!(kinds(&outcome), vec![EventType::PersonArrived]);
        assert_eq!(outcome.events[0].name, "Jamie");
    }

    // ---------------------------------------------------------------------
    // Presence is opt in, and only carried devices decide who is home.
    // ---------------------------------------------------------------------

    /// Somebody with a phone and a laptop, as the issue describes them.
    const PERSON: &str = "person-a";

    fn carried_registry() -> Registry {
        let mut r = Registry::new();
        r.set_tracking(true);
        r.insert_person(person(PERSON, "Alex"));
        r.set_owner(mac(PHONE), PERSON);
        r.set_owner(mac(LAPTOP), PERSON);
        typed(&mut r, PHONE, "phone");
        typed(&mut r, LAPTOP, "computer");
        let _ = r.settle();
        r
    }

    fn state(r: &Registry) -> PersonState {
        r.person(PERSON).expect("the person").state
    }

    #[test]
    fn only_phones_and_wearables_count_by_type_and_an_override_wins() {
        for t in ["phone", "wearable"] {
            assert!(counts_for_presence(None, Some(t)), "{t}");
            assert!(
                !counts_for_presence(Some(false), Some(t)),
                "{t} switched off"
            );
        }
        for t in ["computer", "tablet", "tv", "printer", "unknown"] {
            assert!(!counts_for_presence(None, Some(t)), "{t}");
            assert!(counts_for_presence(Some(true), Some(t)), "{t} switched on");
        }
        assert!(
            !counts_for_presence(None, None),
            "an unknown type does not count"
        );
        assert!(counts_for_presence(Some(true), None));
    }

    #[test]
    fn the_phone_leaving_is_a_departure_though_the_laptop_stays_online() {
        let mut r = carried_registry();
        let _ = r.device_online(mac(PHONE), base());
        let laptop = r.device_online(mac(LAPTOP), at(10));
        assert!(
            laptop.is_empty(),
            "a laptop coming online is nothing: {laptop:?}"
        );
        let outcome = r.device_offline(mac(PHONE), at(600));
        assert_eq!(kinds(&outcome), vec![EventType::PersonDeparted]);
        assert_eq!(state(&r), PersonState::Away);
    }

    #[test]
    fn a_laptop_switched_on_as_a_presence_device_keeps_them_home() {
        let mut r = carried_registry();
        r.set_presence_settings(mac(LAPTOP), Some(true), Some("computer".into()));
        let _ = r.device_online(mac(PHONE), base());
        let _ = r.device_online(mac(LAPTOP), at(10));
        let outcome = r.device_offline(mac(PHONE), at(600));
        assert!(outcome.events.is_empty(), "{outcome:?}");
        assert_eq!(state(&r), PersonState::Home);
    }

    #[test]
    fn a_laptop_alone_never_makes_an_arrival_or_a_departure() {
        let mut r = carried_registry();
        assert!(r.device_online(mac(LAPTOP), base()).is_empty());
        assert_eq!(state(&r), PersonState::Away);
        let _ = r.device_online(mac(PHONE), at(10));
        assert!(r.device_offline(mac(LAPTOP), at(20)).is_empty());
        assert_eq!(state(&r), PersonState::Home);
    }

    #[test]
    fn a_phone_coming_online_for_a_person_not_tracked_is_nothing() {
        let mut r = Registry::new();
        r.set_tracking(true);
        r.insert_person(Person {
            track_presence: false,
            ..person(PERSON, "Alex")
        });
        r.set_owner(mac(PHONE), PERSON);
        typed(&mut r, PHONE, "phone");
        let settled = r.settle();
        assert!(settled.events.is_empty());
        assert_eq!(state(&r), PersonState::Untracked);

        let online = r.device_online(mac(PHONE), base());
        assert!(online.is_empty(), "{online:?}");
        let moved = walk(&mut r, mac(PHONE), &[("Kitchen AP", 10)]);
        assert!(moved.is_empty(), "{moved:?}");
        let offline = r.device_offline(mac(PHONE), at(60));
        assert!(offline.is_empty(), "{offline:?}");
        let p = r.person(PERSON).expect("the person");
        assert_eq!(p.state, PersonState::Untracked);
        assert_eq!(p.current_location, None);
    }

    #[test]
    fn with_the_global_switch_off_everybody_is_untracked_and_nothing_is_said() {
        let mut r = carried_registry();
        r.insert_person(person("person-b", "Sam"));
        r.set_owner(mac(WATCH), "person-b");
        typed(&mut r, WATCH, "wearable");
        let _ = r.device_online(mac(PHONE), base());
        let _ = r.settle();

        r.set_tracking(false);
        let settled = r.settle();
        assert!(settled.events.is_empty(), "{settled:?}");
        for p in r.people() {
            assert_eq!(p.state, PersonState::Untracked, "{}", p.name);
            assert_eq!(p.current_location, None);
        }
        let mut outcome = r.device_online(mac(WATCH), at(10));
        outcome.merge(r.device_offline(mac(PHONE), at(20)));
        outcome.merge(walk(&mut r, mac(WATCH), &[("Kitchen AP", 30)]));
        assert!(outcome.is_empty(), "{outcome:?}");
    }

    #[test]
    fn switching_the_laptop_off_while_the_phone_is_away_settles_away_silently() {
        let mut r = carried_registry();
        r.set_presence_settings(mac(LAPTOP), Some(true), Some("computer".into()));
        let _ = r.device_online(mac(PHONE), base());
        let _ = r.device_online(mac(LAPTOP), at(10));
        let _ = r.device_offline(mac(PHONE), at(600));
        assert_eq!(state(&r), PersonState::Home, "the laptop still counts");
        let before = r.person(PERSON).expect("the person").clone();

        // The reconcile tick reads the override flipped to FALSE.
        let changes = r.reconcile_presence(&[
            (mac(PHONE), None, Some("phone".into())),
            (mac(LAPTOP), Some(false), Some("computer".into())),
        ]);
        assert_eq!(changes.len(), 1, "{changes:?}");
        let settled = r.settle();
        assert!(
            settled.events.is_empty(),
            "a settings change is nobody leaving"
        );
        assert_eq!(settled.updates.len(), 1);
        assert_eq!(settled.updates[0].state, PersonState::Away);
        let after = r.person(PERSON).expect("the person");
        assert_eq!(after.state, PersonState::Away);
        assert_eq!(after.last_departed_at, before.last_departed_at);
        assert_eq!(after.last_arrived_at, before.last_arrived_at);

        // And the phone coming back is an ordinary, announced arrival.
        let back = r.device_online(mac(PHONE), at(900));
        assert_eq!(kinds(&back), vec![EventType::PersonArrived]);
    }

    #[test]
    fn a_reconcile_that_changes_nothing_settles_nobody() {
        let mut r = carried_registry();
        let _ = r.device_online(mac(PHONE), base());
        let changes = r.reconcile_presence(&[
            (mac(PHONE), None, Some("phone".into())),
            (mac(LAPTOP), None, Some("computer".into())),
        ]);
        assert!(changes.is_empty(), "{changes:?}");
        assert!(r.settle().is_empty());
    }

    #[test]
    fn a_device_reclassified_as_a_phone_starts_counting_on_the_next_tick() {
        let mut r = Registry::new();
        r.set_tracking(true);
        r.insert_person(person(PERSON, "Alex"));
        r.set_owner(mac(PHONE), PERSON);
        r.set_presence_settings(mac(PHONE), None, None);
        r.restore_device(mac(PHONE), true, base());
        assert!(r.settle_all().events.is_empty());
        assert_eq!(
            state(&r),
            PersonState::Untracked,
            "an unknown type does not count"
        );

        let _ = r.reconcile_presence(&[(mac(PHONE), None, Some("phone".into()))]);
        let settled = r.settle();
        assert!(settled.events.is_empty());
        assert_eq!(state(&r), PersonState::Home);
    }

    #[test]
    fn a_person_whose_only_device_is_a_tablet_is_untracked() {
        let mut r = Registry::new();
        r.set_tracking(true);
        r.insert_person(person(PERSON, "Alex"));
        r.set_owner(mac(LAPTOP), PERSON);
        typed(&mut r, LAPTOP, "tablet");
        let _ = r.settle_all();
        assert_eq!(state(&r), PersonState::Untracked);
        assert!(!r.is_tracked(PERSON));
        assert!(r.device_online(mac(LAPTOP), base()).is_empty());
        assert_eq!(state(&r), PersonState::Untracked);
    }

    #[test]
    fn location_follows_the_phone_and_not_the_laptop() {
        let mut r = carried_registry();
        let _ = r.device_online(mac(PHONE), base());
        let _ = r.device_online(mac(LAPTOP), at(1));
        let _ = walk(&mut r, mac(PHONE), &[("Backyard AP", 10)]);
        // The laptop is heard from last, in another room.
        let laptop = walk(&mut r, mac(LAPTOP), &[("Kitchen AP", 20)]);
        r.device_seen(mac(LAPTOP), at(30));
        assert!(laptop.is_empty(), "{laptop:?}");
        assert_eq!(
            r.person(PERSON)
                .expect("the person")
                .current_location
                .as_deref(),
            Some("Backyard"),
            "the laptop in the kitchen is not where they are"
        );
    }

    #[test]
    fn switching_tracking_on_for_somebody_at_home_is_not_an_arrival() {
        let mut r = Registry::new();
        r.set_tracking(true);
        r.insert_person(Person {
            track_presence: false,
            ..person(PERSON, "Alex")
        });
        r.set_owner(mac(PHONE), PERSON);
        typed(&mut r, PHONE, "phone");
        let _ = r.device_online(mac(PHONE), base());
        let _ = r.settle_all();
        assert_eq!(state(&r), PersonState::Untracked);

        let changes = r.reconcile(
            vec![person(PERSON, "Alex")],
            &[(mac(PHONE), Some(PERSON.into()))],
        );
        assert!(matches!(
            changes.as_slice(),
            [RegistryChange::PersonEdited { fields, .. }] if fields == &["track_presence=true"]
        ));
        let settled = r.settle();
        assert!(settled.events.is_empty(), "{settled:?}");
        assert_eq!(state(&r), PersonState::Home);
        // ...and the next real departure is announced.
        let gone = r.device_offline(mac(PHONE), at(60));
        assert_eq!(kinds(&gone), vec![EventType::PersonDeparted]);
    }

    #[test]
    fn a_restart_settles_everybody_without_announcing_anybody() {
        let mut r = Registry::new();
        r.set_tracking(true);
        r.insert_person(person(PERSON, "Alex"));
        r.set_owner(mac(PHONE), PERSON);
        typed(&mut r, PHONE, "phone");
        r.restore_device(mac(PHONE), true, base());
        let settled = r.settle_all();
        assert!(settled.events.is_empty());
        assert_eq!(state(&r), PersonState::Home, "silently home, not arrived");
    }

    #[test]
    fn configuration_can_switch_tracking_on_for_a_person() {
        let mut r = Registry::new();
        r.set_tracking(true);
        r.insert_person(Person {
            track_presence: false,
            ..person(PERSON, "Alex")
        });
        r.set_config_owner(mac(PHONE), PERSON);
        r.set_config_tracked(PERSON);
        typed(&mut r, PHONE, "phone");
        let _ = r.settle_all();
        assert_eq!(state(&r), PersonState::Away);
        let outcome = r.device_online(mac(PHONE), base());
        assert_eq!(kinds(&outcome), vec![EventType::PersonArrived]);
    }
}
