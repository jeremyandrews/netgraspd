//! Location stays and people, end to end against a real Postgres.
//!
//! The unit tests in `src/location` and `src/people` prove the rules. These
//! prove that the rules survive contact with the schema: that a stay opens and
//! closes where it should, that the "at most one open stay" invariant holds
//! through the real statements rather than only through a hand-written INSERT,
//! and that `ng_people` ends up with the timestamps the Trovato plugin orders
//! its person listing by.
//!
//! [`a_person_arrives_through_the_driveway_and_settles_in_the_backyard`] is the
//! demo: it prints what it produced, because a feature whose output nobody has
//! read is a feature nobody can tell is working.

mod common;

use chrono::{DateTime, Duration, TimeZone, Utc};
use netgraspd::config::{HumanDuration, StateConfig, UnifiConfig};
use netgraspd::db::queries;
use netgraspd::device::persist::Persister;
use netgraspd::device::{Effect, Manager};
use netgraspd::location::{LocationMap, Movement};
use netgraspd::people::{self, PersonState, Registry};
use netgraspd::types::{EventType, MacAddr, Observation, ObservationKind};

const PHONE: &str = "3c:22:fb:00:00:01";
const LAPTOP: &str = "3c:22:fb:00:00:02";
const WATCH: &str = "b8:27:eb:00:00:03";

fn base() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 14, 17, 0, 0)
        .single()
        .expect("valid time")
}

fn at(secs: i64) -> DateTime<Utc> {
    base() + Duration::seconds(secs)
}

fn mac(s: &str) -> MacAddr {
    s.parse().expect("test mac")
}

fn state_config() -> StateConfig {
    StateConfig {
        idle_timeout: HumanDuration::from_secs(1800),
        offline_timeout: HumanDuration::from_secs(10_800),
        ..StateConfig::default()
    }
}

/// The house this test suite lives in.
fn house() -> LocationMap {
    let mut cfg = UnifiConfig::default();
    for (ap, location) in [
        ("Driveway AP", "Driveway"),
        ("Garage AP", "Garage"),
        ("Living Room AP", "Living Room"),
        ("Kitchen AP", "Kitchen"),
        ("Backyard AP", "Backyard"),
    ] {
        cfg.locations.insert(ap.into(), location.into());
    }
    cfg.edge_aps = vec!["Driveway AP".into(), "Garage AP".into()];
    LocationMap::from_unifi(&cfg)
}

/// The daemon's moving parts, minus libpcap and minus the notifier.
struct Harness {
    manager: Manager,
    persister: Persister,
    registry: Registry,
    map: LocationMap,
    /// Every person event produced, in order, for assertions and for the demo.
    person_events: Vec<people::PersonEvent>,
}

impl Harness {
    fn new() -> Self {
        Harness {
            manager: Manager::new(state_config(), false),
            persister: Persister::new(),
            registry: Registry::new(),
            map: house(),
            person_events: Vec::new(),
        }
    }

    /// Creates a device by observing it, exactly as a captured frame would.
    async fn see(&mut self, db: &common::TestDb, m: &str, when: DateTime<Utc>) {
        let observation = Observation::new(
            mac(m),
            Some("192.168.1.40".parse().expect("ip")),
            "eth0",
            "arp",
            ObservationKind::Request,
            when,
        );
        self.registry.device_seen(mac(m), when);
        let effects = self.manager.observe(&observation);
        self.apply(db, &effects, when).await;
    }

    /// Places a device at an access point, as an enrichment poll would.
    async fn place(&mut self, db: &common::TestDb, m: &str, ap: &str, when: DateTime<Utc>) {
        let place = self.map.place(ap);
        let previous = self.manager.current_ap(mac(m));
        let movement = self.map.movement(previous.as_deref(), ap);
        let effects = self
            .manager
            .set_location(mac(m), &place, movement, None, when);
        if effects.is_empty() {
            return;
        }
        self.apply(db, &effects, when).await;
        let outcome = self.registry.device_moved(mac(m), &place, movement, when);
        self.record(db, outcome).await;
    }

    /// Runs the timeout sweep.
    async fn sweep(&mut self, db: &common::TestDb, now: DateTime<Utc>) {
        let effects = self.manager.sweep(now);
        self.apply(db, &effects, now).await;
    }

    /// Applies effects, then feeds the presence transitions to the registry, the
    /// same way `daemon::apply_and_track` does.
    async fn apply(&mut self, db: &common::TestDb, effects: &[Effect], _now: DateTime<Utc>) {
        if effects.is_empty() {
            return;
        }
        {
            let client = db.client().await;
            self.persister
                .apply(&client, effects)
                .await
                .expect("applying effects");
        }
        let mut outcome = people::Outcome::default();
        for effect in effects {
            match effect {
                Effect::PresenceOpened { mac, at, .. } => {
                    outcome.merge(self.registry.device_online(*mac, *at));
                }
                Effect::PresenceClosed { mac, at } => {
                    outcome.merge(self.registry.device_offline(*mac, *at));
                }
                _ => {}
            }
        }
        self.record(db, outcome).await;
    }

    /// Writes what the registry decided, as the daemon does.
    async fn record(&mut self, db: &common::TestDb, outcome: people::Outcome) {
        if outcome.is_empty() {
            return;
        }
        let client = db.client().await;
        for update in &outcome.updates {
            queries::update_person(
                &client,
                &update.item_id,
                update.state.as_str(),
                update.current_location.as_deref(),
                update.last_arrived_at,
                update.last_departed_at,
            )
            .await
            .expect("updating a person");
        }
        for event in &outcome.events {
            let effects = self.manager.person_event(event);
            self.persister
                .apply(&client, &effects)
                .await
                .expect("recording a person event");
        }
        self.person_events.extend(outcome.events);
    }

    /// Adds a person and the devices they own.
    async fn add_person(&mut self, db: &common::TestDb, name: &str, macs: &[&str]) -> String {
        let client = db.client().await;
        let item_id = queries::ensure_person(&client, name, true, true)
            .await
            .expect("creating a person");
        self.registry.insert_person(people::Person {
            item_id: item_id.clone(),
            name: name.to_string(),
            notify_arrive: true,
            notify_depart: true,
            state: PersonState::Away,
            current_location: None,
            last_arrived_at: None,
            last_departed_at: None,
        });
        for m in macs {
            self.registry.set_owner(mac(m), item_id.clone());
        }
        item_id
    }

    /// Event types produced for people, in order.
    fn kinds(&self) -> Vec<EventType> {
        self.person_events.iter().map(|e| e.event_type).collect()
    }
}

/// The `ng_location_history` rows for one device, oldest first.
async fn stays(db: &common::TestDb, device_id: i64) -> Vec<(String, Option<String>, bool)> {
    let client = db.client().await;
    let rows = client
        .query(
            "SELECT location, ap_name, ended_at IS NULL AS open
               FROM ng_location_history
              WHERE device_id = $1 AND is_summary = FALSE
              ORDER BY started_at, id",
            &[&device_id],
        )
        .await
        .expect("reading stays");
    rows.iter()
        .map(|r| (r.get("location"), r.get("ap_name"), r.get("open")))
        .collect()
}

#[tokio::test]
async fn a_device_moving_between_access_points_opens_and_closes_one_stay_at_a_time() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut h = Harness::new();
    h.see(&db, PHONE, base()).await;
    let device_id = h.persister.id_for(mac(PHONE)).expect("device id");

    h.place(&db, PHONE, "Driveway AP", at(10)).await;
    h.place(&db, PHONE, "Living Room AP", at(60)).await;
    h.place(&db, PHONE, "Kitchen AP", at(120)).await;

    assert_eq!(
        stays(&db, device_id).await,
        vec![
            ("Driveway".into(), Some("Driveway AP".into()), false),
            ("Living Room".into(), Some("Living Room AP".into()), false),
            ("Kitchen".into(), Some("Kitchen AP".into()), true),
        ]
    );
    assert_eq!(
        db.scalar(
            "SELECT COUNT(*) FROM ng_location_history
              WHERE ended_at IS NULL AND is_summary = FALSE"
        )
        .await,
        1,
        "exactly one stay is ever open"
    );
}

#[tokio::test]
async fn the_same_access_point_reported_again_does_not_open_another_stay() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // The failure this prevents: an enricher polling every thirty seconds
    // reports the same association every time, and each one becomes a row. That
    // is the row-per-observation failure that killed the predecessor, arriving
    // through a different door.
    let mut h = Harness::new();
    h.see(&db, PHONE, base()).await;
    for tick in 0..20 {
        h.place(&db, PHONE, "Kitchen AP", at(10 + tick * 30)).await;
    }
    assert_eq!(db.count("ng_location_history").await, 1);
    assert_eq!(
        db.count("ng_events").await,
        2,
        "new_device, then one device_location_changed, and nothing for the          nineteen polls that reported the same association"
    );
}

#[tokio::test]
async fn an_unmapped_access_point_falls_back_to_its_own_name() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut h = Harness::new();
    h.see(&db, PHONE, base()).await;
    let device_id = h.persister.id_for(mac(PHONE)).expect("device id");
    h.place(&db, PHONE, "Attic AP", at(10)).await;

    assert_eq!(
        stays(&db, device_id).await,
        vec![("Attic AP".into(), Some("Attic AP".into()), true)],
        "a forgotten mapping shows the access point, never nothing"
    );

    // current_ap and current_location are denormalised copies of what the
    // history already records, so like state and last_ip they reach Postgres on
    // the ordinary flush rather than on every change.
    let dirty = h.manager.take_dirty();
    let client = db.client().await;
    h.persister.flush(&client, &dirty).await.expect("flush");
    let device = queries::find_device_by_mac(&client, mac(PHONE))
        .await
        .expect("lookup")
        .expect("the device");
    assert_eq!(device.current_location.as_deref(), Some("Attic AP"));
    assert_eq!(device.current_ap.as_deref(), Some("Attic AP"));
}

#[tokio::test]
async fn a_device_going_offline_closes_its_stay_and_clears_where_it_is() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut h = Harness::new();
    h.see(&db, PHONE, base()).await;
    let device_id = h.persister.id_for(mac(PHONE)).expect("device id");
    h.place(&db, PHONE, "Kitchen AP", at(10)).await;

    h.sweep(&db, at(20_000)).await;

    assert_eq!(
        db.scalar(
            "SELECT COUNT(*) FROM ng_location_history
              WHERE ended_at IS NULL AND is_summary = FALSE"
        )
        .await,
        0,
        "an offline device is nowhere"
    );
    assert_eq!(stays(&db, device_id).await.len(), 1);

    // The columns clear on the next flush, so the plugin does not show a device
    // that left last March as still being in the kitchen.
    let dirty = h.manager.take_dirty();
    let client = db.client().await;
    h.persister.flush(&client, &dirty).await.expect("flush");
    let device = queries::find_device_by_mac(&client, mac(PHONE))
        .await
        .expect("lookup")
        .expect("the device");
    assert_eq!(device.current_ap, None);
    assert_eq!(device.current_location, None);
}

#[tokio::test]
async fn a_returning_device_opens_a_fresh_stay_at_the_same_access_point() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // The bug this guards: if going offline cleared the stay but not the
    // remembered access point, the next enrichment poll would compare equal and
    // never open another stay. The device would be online and nowhere, forever.
    let mut h = Harness::new();
    h.see(&db, PHONE, base()).await;
    h.place(&db, PHONE, "Kitchen AP", at(10)).await;
    h.sweep(&db, at(20_000)).await;
    h.see(&db, PHONE, at(20_100)).await;
    h.place(&db, PHONE, "Kitchen AP", at(20_110)).await;

    let device_id = h.persister.id_for(mac(PHONE)).expect("device id");
    let all = stays(&db, device_id).await;
    assert_eq!(all.len(), 2, "{all:?}");
    assert!(all[1].2, "the second stay is open");
}

#[tokio::test]
async fn a_person_arrives_through_the_driveway_and_settles_in_the_backyard() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut h = Harness::new();
    h.add_person(&db, "Jeremy", &[PHONE, LAPTOP]).await;

    // The phone has been here before and is currently away: netgraspd knows the
    // device, and every device it owns is offline.
    h.see(&db, PHONE, base()).await;
    h.sweep(&db, at(20_000)).await;
    assert_eq!(
        h.registry.by_name("Jeremy").expect("Jeremy").state,
        PersonState::Away
    );

    // Jeremy pulls into the driveway. The phone associates with the driveway AP
    // and the controller says so on the next poll, before the phone has sent a
    // single broadcast frame. That ordering is the whole reason `via` can be
    // filled in at all: an arrival is decided by a packet, and the packet
    // arrives after the association.
    let t = 30_000;
    h.place(&db, PHONE, "Driveway AP", at(t)).await;
    h.see(&db, PHONE, at(t + 20)).await;
    h.place(&db, PHONE, "Living Room AP", at(t + 60)).await;
    h.place(&db, PHONE, "Backyard AP", at(t + 300)).await;

    let client = db.client().await;
    let people = queries::load_people(&client).await.expect("people");
    let jeremy = &people[0];
    assert_eq!(jeremy.state, "home");
    assert_eq!(jeremy.current_location.as_deref(), Some("Backyard"));
    assert_eq!(
        jeremy.last_arrived_at,
        Some(at(t + 20)),
        "the plugin orders its person listing by this column"
    );

    let arrival = h
        .person_events
        .iter()
        .rev()
        .find(|e| e.event_type == EventType::PersonArrived)
        .expect("an arrival");
    assert_eq!(arrival.details["via"], "Driveway AP");
    assert_eq!(arrival.details["location"], "Driveway");

    // Now they leave through the garage and the phone falls silent.
    h.place(&db, PHONE, "Garage AP", at(t + 3600)).await;
    h.sweep(&db, at(t + 3600 + 20_000)).await;

    let people = queries::load_people(&client).await.expect("people");
    let jeremy = &people[0];
    assert_eq!(jeremy.state, "away");
    assert_eq!(jeremy.current_location, None);
    assert!(jeremy.last_departed_at.is_some());

    // The most recent departure: this test produces an earlier one on purpose,
    // to get Jeremy out of the house before he arrives.
    let departure = h
        .person_events
        .iter()
        .rev()
        .find(|e| e.event_type == EventType::PersonDeparted)
        .expect("a departure");
    assert_eq!(departure.details["via"], "Garage AP");

    println!("--- arrival and departure demo ---");
    for event in &h.person_events {
        println!(
            "{}  {:<24} {}",
            event.at.format("%H:%M:%S"),
            event.event_type.to_string(),
            event.details
        );
    }
    println!(
        "final: {} is {}, location {:?}",
        jeremy.name, jeremy.state, jeremy.current_location
    );
    println!("--- end demo ---");
}

#[tokio::test]
async fn a_person_stays_home_while_one_device_is_online_and_their_location_follows_it() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut h = Harness::new();
    h.add_person(&db, "Jamie", &[PHONE, LAPTOP]).await;

    h.see(&db, PHONE, base()).await;
    h.see(&db, LAPTOP, at(1)).await;
    h.place(&db, LAPTOP, "Kitchen AP", at(10)).await;
    h.place(&db, PHONE, "Backyard AP", at(20)).await;

    let client = db.client().await;
    let location = |people: &[queries::PersonRecord]| people[0].current_location.clone();
    assert_eq!(
        location(&queries::load_people(&client).await.expect("people")).as_deref(),
        Some("Backyard"),
        "the phone spoke last"
    );

    // The laptop keeps talking; the phone does not. Sweeping just past the
    // phone's offline timeout takes only the phone.
    h.see(&db, LAPTOP, at(11_000)).await;
    h.sweep(&db, at(11_100)).await;

    let people = queries::load_people(&client).await.expect("people");
    assert_eq!(people[0].state, "home", "the laptop is still online");
    assert_eq!(
        people[0].current_location.as_deref(),
        Some("Kitchen"),
        "their location follows the device that is still there"
    );
    assert!(
        !h.kinds().contains(&EventType::PersonDeparted),
        "{:?}",
        h.kinds()
    );
}

#[tokio::test]
async fn roaming_between_interior_rooms_never_reads_as_an_arrival_or_a_departure() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut h = Harness::new();
    h.add_person(&db, "Aurora", &[PHONE]).await;
    h.see(&db, PHONE, base()).await;

    for (ap, secs) in [
        ("Kitchen AP", 10),
        ("Living Room AP", 60),
        ("Kitchen AP", 120),
        ("Backyard AP", 180),
    ] {
        h.place(&db, PHONE, ap, at(secs)).await;
    }

    let arrivals = h
        .kinds()
        .iter()
        .filter(|k| **k == EventType::PersonArrived)
        .count();
    assert_eq!(arrivals, 1, "exactly the one when the phone came online");
    assert!(!h.kinds().contains(&EventType::PersonDeparted));

    // Every crossing between interior rooms was classified as roaming.
    let client = db.client().await;
    let rows = client
        .query(
            "SELECT details->>'movement' AS movement
               FROM ng_events
              WHERE event_type = 'device_location_changed'
              ORDER BY id",
            &[],
        )
        .await
        .expect("reading movements");
    let movements: Vec<String> = rows
        .iter()
        .map(|r| r.get::<_, String>("movement"))
        .collect();
    assert_eq!(
        movements,
        vec![
            Movement::Unknown.as_str(),
            Movement::Roaming.as_str(),
            Movement::Roaming.as_str(),
            Movement::Roaming.as_str(),
        ]
    );
}

#[tokio::test]
async fn a_device_nobody_owns_moves_without_producing_a_person_event() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut h = Harness::new();
    h.add_person(&db, "Jeremy", &[PHONE]).await;
    h.see(&db, WATCH, base()).await;
    h.place(&db, WATCH, "Kitchen AP", at(10)).await;

    assert!(h.person_events.is_empty(), "{:?}", h.person_events);
    let client = db.client().await;
    let people = queries::load_people(&client).await.expect("people");
    assert_eq!(
        people[0].state, "away",
        "Jeremy is not home because of a watch"
    );
}

#[tokio::test]
async fn a_person_is_adopted_by_name_rather_than_duplicated() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // The safe-to-list-in-both-places property: a person mirrored from Trovato
    // and also named in netgrasp.toml must not become two Jeremys.
    let client = db.client().await;
    let first = queries::ensure_person(&client, "Jeremy", true, false)
        .await
        .expect("creating");
    let second = queries::ensure_person(&client, "jeremy", false, true)
        .await
        .expect("adopting");
    assert_eq!(first, second, "matched case-insensitively");
    assert_eq!(db.count("ng_people").await, 1);

    // Adoption leaves the plugin-owned columns exactly as they were.
    let people = queries::load_people(&client).await.expect("people");
    assert!(people[0].notify_arrive, "the first call's flags survive");
    assert!(!people[0].notify_depart);
}

#[tokio::test]
async fn the_daemon_never_writes_a_plugin_owned_person_column() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let client = db.client().await;
    let item_id = queries::ensure_person(&client, "Jeremy", true, true)
        .await
        .expect("creating");
    client
        .execute(
            "UPDATE ng_people SET name = 'Jeremiah', notes = 'edited in the admin UI',
                                  notify_arrive = FALSE
              WHERE item_id = ($1::text)::uuid",
            &[&item_id],
        )
        .await
        .expect("the plugin edits its own columns");

    queries::update_person(
        &client,
        &item_id,
        "home",
        Some("Kitchen"),
        Some(base()),
        None,
    )
    .await
    .expect("the daemon writes its own");

    let people = queries::load_people(&client).await.expect("people");
    assert_eq!(
        people[0].name, "Jeremiah",
        "the daemon did not undo the rename"
    );
    assert!(!people[0].notify_arrive, "nor the notification choice");
    assert_eq!(people[0].state, "home");
    assert_eq!(people[0].current_location.as_deref(), Some("Kitchen"));
}

#[tokio::test]
async fn a_stay_left_open_by_a_crash_is_closed_at_startup() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let device_id = db.seed_device("3c:22:fb:00:00:09", "offline").await;
    let online_id = db.seed_device("3c:22:fb:00:00:0a", "online").await;
    let client = db.client().await;
    for id in [device_id, online_id] {
        client
            .execute(
                "INSERT INTO ng_location_history (device_id, location, started_at)
                 VALUES ($1, 'Kitchen', $2)",
                &[&id, &base()],
            )
            .await
            .expect("an open stay");
    }

    let closed = queries::close_stale_location_stays(&client, at(60))
        .await
        .expect("closing");
    assert_eq!(closed, 1, "only the offline device's stay");
    assert_eq!(
        queries::count_open_locations(&client).await.expect("count"),
        1,
        "the online device keeps its stay"
    );
}
