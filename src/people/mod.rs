//! Who is home, inferred from which of their devices are online.
//!
//! The rule is deliberately simple, because every elaboration of it that anybody
//! has tried produces a system that announces you have left the house while you
//! are sitting in it:
//!
//! - A person is **home** when any device they own is online.
//! - The first owned device to come online after all of them were offline is an
//!   arrival.
//! - The last owned device to go offline is a departure.
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

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Utc};
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
pub const EDGE_EVIDENCE_WINDOW: chrono::TimeDelta = chrono::TimeDelta::minutes(15);

/// Whether a person is in the house.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PersonState {
    /// At least one owned device is online.
    Home,
    /// Every owned device is offline.
    Away,
}

impl PersonState {
    /// Stable string used as the `ng_people.state` value.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            PersonState::Home => "home",
            PersonState::Away => "away",
        }
    }

    /// Inverse of [`PersonState::as_str`]. Anything unrecognised reads as
    /// `Away`, the safe default: the next device sighting corrects it, and
    /// announcing an arrival that did happen is better than suppressing one.
    #[must_use]
    pub fn from_db(s: &str) -> Self {
        match s {
            "home" => PersonState::Home,
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
    /// Whether they are home. Daemon owned.
    pub state: PersonState,
    /// Where they are, when they are home. Daemon owned.
    pub current_location: Option<String>,
    /// When they last arrived. Daemon owned, and the column the plugin orders
    /// its person listing by, so it is written on every arrival without fail.
    pub last_arrived_at: Option<DateTime<Utc>>,
    /// When they last left. Daemon owned.
    pub last_departed_at: Option<DateTime<Utc>>,
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
    pub last_arrived_at: Option<DateTime<Utc>>,
    /// When they last left.
    pub last_departed_at: Option<DateTime<Utc>>,
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
    pub at: DateTime<Utc>,
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
    last_active: Option<DateTime<Utc>>,
    /// The last edge access point this device crossed, and when.
    last_edge: Option<(String, DateTime<Utc>)>,
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
    pub fn insert_person(&mut self, person: Person) {
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
    /// - For somebody already known, only `name`, `notify_arrive` and
    ///   `notify_depart` are taken. `state`, `current_location`,
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
            changes.push(RegistryChange::OwnerChanged {
                mac: *mac,
                from: current,
                to: wanted,
            });
        }

        changes
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
    pub fn restore_device(&mut self, mac: MacAddr, online: bool, at: DateTime<Utc>) {
        let view = self.devices.entry(mac).or_default();
        view.online = online;
        view.last_active = Some(at);
    }

    /// Records that a device was heard from, which is what decides whose
    /// location a person takes.
    ///
    /// Produces no events on its own. Coming online is [`Registry::device_online`].
    pub fn device_seen(&mut self, mac: MacAddr, at: DateTime<Utc>) {
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
    pub fn device_online(&mut self, mac: MacAddr, at: DateTime<Utc>) -> Outcome {
        let Some(item_id) = self.owner.get(&mac).cloned() else {
            return Outcome::default();
        };
        {
            let view = self.devices.entry(mac).or_default();
            view.online = true;
            view.last_active = Some(at);
        }
        let Some(person) = self.people.get(&item_id) else {
            return Outcome::default();
        };

        let mut outcome = Outcome::default();
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
    pub fn device_offline(&mut self, mac: MacAddr, at: DateTime<Utc>) -> Outcome {
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
        if !self.people.contains_key(&item_id) {
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
        if person.state == PersonState::Away {
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
    /// `movement` is what [`LocationMap::movement`] made of the crossing. It is
    /// passed in rather than recomputed so that the device event and the person
    /// event can never disagree about what happened.
    #[must_use]
    pub fn device_moved(
        &mut self,
        mac: MacAddr,
        place: &Place,
        movement: Movement,
        at: DateTime<Utc>,
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
        if !self.people.contains_key(&item_id) {
            return Outcome::default();
        }
        self.refresh_location(&item_id, mac, at)
    }

    /// Recomputes a person's location and reports it if it changed.
    ///
    /// `trigger` is only used to attribute the event to a device; the location
    /// itself always comes from whichever owned device was heard from most
    /// recently.
    fn refresh_location(&mut self, item_id: &str, trigger: MacAddr, at: DateTime<Utc>) -> Outcome {
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

    /// Whether any device this person owns is online.
    fn any_online(&self, item_id: &str) -> bool {
        self.owner
            .iter()
            .filter(|(_, owner)| owner.as_str() == item_id)
            .any(|(mac, _)| self.devices.get(mac).is_some_and(|v| v.online))
    }

    /// The location of the person's most recently active online device.
    fn location_of_person(&self, item_id: &str) -> Option<String> {
        self.owner
            .iter()
            .filter(|(_, owner)| owner.as_str() == item_id)
            .filter_map(|(mac, _)| self.devices.get(mac))
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
    fn edge_evidence(&self, mac: MacAddr, at: DateTime<Utc>) -> Option<String> {
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
        self.owner
            .iter()
            .filter(|(_, owner)| owner.as_str() == item_id)
            .filter_map(|(mac, _)| self.devices.get(mac))
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
    use chrono::TimeZone;

    fn base() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 17, 0, 0)
            .single()
            .expect("valid time")
    }

    fn at(secs: i64) -> DateTime<Utc> {
        base() + chrono::Duration::seconds(secs)
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
            state: PersonState::Away,
            current_location: None,
            last_arrived_at: None,
            last_departed_at: None,
        }
    }

    /// One person owning a phone and a laptop, both offline.
    fn registry() -> Registry {
        let mut r = Registry::new();
        r.insert_person(person("person-1", "Jeremy"));
        r.set_owner(mac(PHONE), "person-1");
        r.set_owner(mac(LAPTOP), "person-1");
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
    fn a_person_is_still_home_while_any_owned_device_is_online() {
        let mut r = registry();
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
    fn the_last_owned_device_going_offline_is_a_departure() {
        let mut r = registry();
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
        let mut r = registry();
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
        let mut r = registry();
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
        r.insert_person(Person {
            notify_arrive: true,
            notify_depart: false,
            ..person("person-1", "Jamie")
        });
        r.set_owner(mac(PHONE), "person-1");

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
        for s in [PersonState::Home, PersonState::Away] {
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
}
