//! End-to-end: synthetic packet stream in, database rows and bus events out.
//!
//! These drive the same path the daemon does, minus libpcap: fixture frames go
//! through the real parsers, the real dedup, the real state machine, the real
//! persister and the real event bus. What they assert is the contract the
//! Trovato plugin will read.
//!
//! The load-bearing one is [`the_database_never_grows_a_row_per_packet`]. That
//! is the failure that killed the predecessor, and it is the reason this rewrite
//! exists.

mod common;

use chrono::{DateTime, Duration, TimeZone, Utc};
use netgraspd::capture::{ObservationDedup, arp, fixtures, mdns};
use netgraspd::config::{HumanDuration, NotifyConfig, StateConfig};
use netgraspd::db::queries;
use netgraspd::device::persist::Persister;
use netgraspd::device::{Effect, Manager};
use netgraspd::events::EventBus;
use netgraspd::notify::{Delivery, Dispatcher};
use netgraspd::types::{DeviceState, EventType, MacAddr, Observation, Signal, SignalKind};

/// A pipeline with everything but libpcap.
struct Pipeline {
    manager: Manager,
    persister: Persister,
    dedup: ObservationDedup,
    bus: EventBus,
    admitted: usize,
    offered: usize,
}

impl Pipeline {
    fn new(state: StateConfig, learning: bool) -> Self {
        Pipeline {
            manager: Manager::new(state, learning),
            persister: Persister::new(),
            dedup: ObservationDedup::new(4096, 1),
            bus: EventBus::new(1024),
            admitted: 0,
            offered: 0,
        }
    }

    /// Feeds one raw frame, exactly as a capture thread would.
    async fn frame(&mut self, db: &common::TestDb, bytes: &[u8], iface: &str, at: DateTime<Utc>) {
        let parsed =
            arp::parse_frame(bytes, iface, at).or_else(|| mdns::parse_frame(bytes, iface, at));
        let Some(observation) = parsed else {
            return;
        };
        self.observe(db, &observation).await;
    }

    async fn observe(&mut self, db: &common::TestDb, observation: &Observation) {
        self.offered += 1;
        if !self.dedup.admit(observation) {
            return;
        }
        self.admitted += 1;
        let effects = self.manager.observe(observation);
        self.apply(db, &effects).await;
    }

    async fn signal(
        &mut self,
        db: &common::TestDb,
        mac: MacAddr,
        signal: &Signal,
        at: DateTime<Utc>,
    ) {
        let effects = self.manager.add_signal(mac, signal, at);
        self.apply(db, &effects).await;
    }

    async fn sweep(&mut self, db: &common::TestDb, now: DateTime<Utc>) {
        let effects = self.manager.sweep(now);
        self.apply(db, &effects).await;
    }

    async fn apply(&mut self, db: &common::TestDb, effects: &[Effect]) {
        if effects.is_empty() {
            return;
        }
        let client = db.client().await;
        let recorded = self
            .persister
            .apply(&client, effects)
            .await
            .expect("applying effects");
        self.bus.publish_all(recorded);
    }

    async fn flush(&mut self, db: &common::TestDb) {
        let dirty = self.manager.take_dirty();
        if dirty.is_empty() {
            return;
        }
        let client = db.client().await;
        self.persister
            .flush(&client, &dirty)
            .await
            .expect("flushing");
    }
}

fn base() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 2, 2, 9, 0, 0)
        .single()
        .expect("valid time")
}

fn at(secs: i64) -> DateTime<Utc> {
    base() + Duration::seconds(secs)
}

fn state_config() -> StateConfig {
    StateConfig {
        idle_timeout: HumanDuration::from_secs(1800),
        offline_timeout: HumanDuration::from_secs(10_800),
        ..StateConfig::default()
    }
}

fn mac(s: &str) -> MacAddr {
    s.parse().expect("test mac")
}

#[tokio::test]
async fn a_synthetic_packet_stream_produces_devices_presence_and_events() {
    let Some(db) = common::test_db().await else {
        return;
    };
    common::assert_empty(&db, "ng_devices").await;

    let mut p = Pipeline::new(state_config(), false);
    // The phone ARPs for the gateway, the gateway replies, the media box
    // announces itself over mDNS, and the printer announces over IPv6.
    p.frame(&db, &fixtures::arp_request(), "eth0", at(0)).await;
    p.frame(&db, &fixtures::arp_reply(), "eth0", at(1)).await;
    p.frame(&db, &fixtures::mdns_response_ipv4(), "eth0", at(2))
        .await;
    p.frame(&db, &fixtures::mdns_response_ipv6(), "eth0", at(3))
        .await;
    p.flush(&db).await;

    // Three distinct MACs: the phone, the gateway (which also sends the mDNS
    // response in the fixture set) and the printer.
    let client = db.client().await;
    let devices = queries::load_devices(&client).await.expect("devices");
    assert_eq!(devices.len(), 3, "{devices:#?}");

    let phone = devices
        .iter()
        .find(|d| d.mac == mac("3c:22:fb:9a:1b:2c"))
        .expect("the phone was recorded");
    assert_eq!(phone.vendor.as_deref(), Some("Apple, Inc."));
    assert_eq!(phone.last_ip.as_deref(), Some("192.168.1.40"));
    assert_eq!(phone.state, DeviceState::Online);

    let media = devices
        .iter()
        .find(|d| d.mac == mac("b8:27:eb:44:55:66"))
        .expect("the mDNS responder was recorded");
    assert_eq!(
        media.display(),
        "Living Room Apple TV",
        "the mDNS instance name beats the vendor"
    );
    assert_eq!(media.identity_source.as_deref(), Some("mdns_name"));

    let printer = devices
        .iter()
        .find(|d| d.mac == mac("3c:2a:f4:11:22:33"))
        .expect("the printer was recorded");
    assert_eq!(printer.display(), "Office Printer");
    assert_eq!(
        printer.last_ip, None,
        "an IPv6-only sighting must not populate last_ip"
    );

    // One open presence session per device, none closed.
    assert_eq!(db.count("ng_presence").await, 3);
    assert_eq!(
        queries::count_open_presence(&client).await.expect("open"),
        3
    );

    // Three discoveries, plus the two changes the fixture set implies: the mDNS
    // responder shares a MAC with the ARP replier, and announces from a
    // different address under a name, so it changes both its address and its
    // identity after being discovered.
    let events = queries::recent_events(&client, 100).await.expect("events");
    let count = |kind: &str| events.iter().filter(|e| e.event_type == kind).count();
    assert_eq!(count("new_device"), 3, "{events:#?}");
    assert_eq!(count("ip_changed"), 1, "{events:#?}");
    assert_eq!(count("name_updated"), 1, "{events:#?}");
    assert_eq!(events.len(), 5, "and nothing else: {events:#?}");

    // Signals are stored raw, including the service types milestone 2 will use.
    let signals = queries::load_all_signals(&client).await.expect("signals");
    let media_signals = signals.get(&media.id).expect("the responder has signals");
    assert!(
        media_signals
            .iter()
            .any(|s| s.kind == SignalKind::MdnsName && s.value == "Living Room Apple TV")
    );
    assert!(
        media_signals
            .iter()
            .any(|s| s.kind == SignalKind::MdnsService && s.value == "_airplay._tcp")
    );
    assert!(media_signals.iter().any(|s| s.kind == SignalKind::Vendor));

    // Addresses seen are in the history table, IPv6 included.
    assert!(db.count("ng_ip_history").await >= 3);
    assert_eq!(
        db.scalar("SELECT COUNT(*) FROM ng_ip_history WHERE ip = 'fe80::3e2a:f4ff:fe11:2233'")
            .await,
        1,
        "the v6 address is recorded even though it does not move last_ip"
    );
}

#[tokio::test]
async fn the_database_never_grows_a_row_per_packet() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut p = Pipeline::new(state_config(), false);

    // A thousand ARP packets from one device across ten minutes, which is what
    // a chatty device on a real network looks like.
    for i in 0..1000i64 {
        let obs = Observation::new(
            mac("3c:22:fb:00:00:07"),
            Some("192.168.1.50".parse().expect("ip")),
            "eth0",
            "arp",
            netgraspd::types::ObservationKind::Request,
            at(i),
        );
        p.observe(&db, &obs).await;
    }
    p.flush(&db).await;

    assert_eq!(db.count("ng_devices").await, 1);
    assert_eq!(
        db.count("ng_presence").await,
        1,
        "a thousand packets is one presence session"
    );
    assert_eq!(
        db.count("ng_events").await,
        1,
        "a thousand packets is one event: the discovery"
    );
    assert_eq!(
        db.count("ng_ip_history").await,
        1,
        "one device holding one address is one history row"
    );
    // The volume is a counter on the session, which is the only place packet
    // volume is allowed to be represented.
    assert_eq!(
        db.scalar("SELECT observation_count FROM ng_presence").await,
        1000
    );
}

#[tokio::test]
async fn dedup_collapses_the_same_frame_seen_on_two_interfaces() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut p = Pipeline::new(state_config(), false);

    // The same broadcast reaching a bridged host on two interfaces.
    for iface in ["eth0", "eth1", "wlan0"] {
        p.frame(&db, &fixtures::arp_request(), iface, at(0)).await;
    }
    assert_eq!(p.offered, 3);
    assert_eq!(p.admitted, 1, "two of the three were duplicates");
    assert_eq!(p.dedup.duplicates_suppressed(), 2);
    assert_eq!(db.count("ng_devices").await, 1);
    assert_eq!(db.count("ng_events").await, 1);
}

#[tokio::test]
async fn a_device_goes_offline_and_returns_with_the_right_events_and_sessions() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut p = Pipeline::new(state_config(), false);

    p.frame(&db, &fixtures::arp_request(), "eth0", at(0)).await;
    p.sweep(&db, at(2000)).await; // idle
    p.sweep(&db, at(20_000)).await; // offline
    p.flush(&db).await;

    let client = db.client().await;
    assert_eq!(
        queries::count_open_presence(&client).await.expect("open"),
        0,
        "going offline closes the session"
    );
    assert_eq!(
        db.scalar("SELECT COUNT(*) FROM ng_presence WHERE ended_at IS NOT NULL")
            .await,
        1
    );

    // ...and coming back opens a new one.
    let mut back = fixtures::arp_request();
    back.truncate(60);
    p.frame(&db, &back, "eth0", at(20_100)).await;
    p.flush(&db).await;

    assert_eq!(db.count("ng_presence").await, 2, "a second session");
    assert_eq!(
        queries::count_open_presence(&client).await.expect("open"),
        1
    );
    let types: Vec<String> = queries::recent_events(&client, 10)
        .await
        .expect("events")
        .into_iter()
        .map(|e| e.event_type)
        .collect();
    assert_eq!(types, vec!["returned", "went_offline", "new_device"]);

    let devices = queries::load_devices(&client).await.expect("devices");
    assert_eq!(devices[0].state, DeviceState::Online);
}

#[tokio::test]
async fn a_restart_reloads_state_and_does_not_re_announce_the_network() {
    let Some(db) = common::test_db().await else {
        return;
    };

    // First run: discover two devices and give one an mDNS name.
    {
        let mut p = Pipeline::new(state_config(), false);
        p.frame(&db, &fixtures::arp_request(), "eth0", at(0)).await;
        p.frame(&db, &fixtures::mdns_response_ipv4(), "eth0", at(1))
            .await;
        p.flush(&db).await;
    }
    assert_eq!(db.count("ng_devices").await, 2);
    assert_eq!(db.count("ng_events").await, 2);

    // Second run: rehydrate and see the same devices again.
    let client = db.client().await;
    let records = queries::load_devices(&client).await.expect("devices");
    let signals = queries::load_all_signals(&client).await.expect("signals");
    let mut p = Pipeline::new(state_config(), false);
    p.persister.seed(&records);
    p.manager.restore(records, signals);
    assert_eq!(p.manager.len(), 2, "the table was rehydrated");

    p.frame(&db, &fixtures::arp_request(), "eth0", at(100))
        .await;
    p.frame(&db, &fixtures::mdns_response_ipv4(), "eth0", at(101))
        .await;
    p.flush(&db).await;

    assert_eq!(db.count("ng_devices").await, 2, "no duplicate rows");
    assert_eq!(
        db.count("ng_events").await,
        2,
        "a restart must not re-announce the whole network"
    );
    // The identity survived the restart rather than being rebuilt from scratch.
    let reloaded = queries::load_devices(&client).await.expect("devices");
    assert!(
        reloaded
            .iter()
            .any(|d| d.display() == "Living Room Apple TV"),
        "{reloaded:#?}"
    );
}

#[tokio::test]
async fn a_learning_window_records_every_event_and_notifies_none_of_them() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut p = Pipeline::new(state_config(), true);
    let mut rx = p.bus.subscribe();

    p.frame(&db, &fixtures::arp_request(), "eth0", at(0)).await;
    p.frame(&db, &fixtures::arp_reply(), "eth0", at(1)).await;
    p.flush(&db).await;

    // The security-relevant half: the events exist.
    let client = db.client().await;
    assert_eq!(
        queries::count_events_of_type(&client, EventType::NewDevice)
            .await
            .expect("count"),
        2
    );
    assert_eq!(
        queries::count_baseline_devices(&client)
            .await
            .expect("count"),
        2,
        "both joined the baseline"
    );
    assert_eq!(
        db.scalar("SELECT COUNT(*) FROM ng_events WHERE notified")
            .await,
        0
    );

    // The quiet half: the dispatcher refuses to deliver any of them.
    let mut dispatcher = Dispatcher::new(
        NotifyConfig::default(),
        netgraspd::config::SecurityNotifyConfig::default(),
        chrono::FixedOffset::east_opt(0).expect("utc"),
    );
    let mut deliveries: Vec<Delivery> = Vec::new();
    while let Ok(event) = rx.try_recv() {
        deliveries.extend(dispatcher.offer(event, at(2)));
    }
    deliveries.extend(dispatcher.drain());
    assert!(deliveries.is_empty(), "{deliveries:#?}");
    assert_eq!(dispatcher.suppressed().not_deliverable, 2);

    // After learning ends, a genuinely new device does notify.
    p.manager.end_learning();
    let newcomer = Observation::new(
        mac("00:11:32:aa:bb:cc"),
        Some("192.168.1.99".parse().expect("ip")),
        "eth0",
        "arp",
        netgraspd::types::ObservationKind::Announcement,
        at(10),
    );
    p.observe(&db, &newcomer).await;
    let event = rx.try_recv().expect("the newcomer was published");
    assert_eq!(event.event.event_type, EventType::NewDevice);
    assert!(event.event.deliverable());
    assert!(!event.event.baseline);

    let deliveries = dispatcher.offer(event, at(10));
    assert!(deliveries.is_empty(), "still inside the batch window");
    assert_eq!(dispatcher.drain().len(), 1, "and delivered when it closes");
}

#[tokio::test]
async fn a_later_signal_refines_the_identity_and_records_the_change() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut p = Pipeline::new(state_config(), false);

    // Seen first as a bare Apple device.
    p.frame(&db, &fixtures::arp_request(), "eth0", at(0)).await;
    p.flush(&db).await;
    let client = db.client().await;
    let before = queries::load_devices(&client).await.expect("devices");
    assert_eq!(before[0].display(), "Apple, Inc. device");
    assert_eq!(before[0].identity_source.as_deref(), Some("vendor"));

    // A reverse DNS answer arrives out of band.
    p.signal(
        &db,
        mac("3c:22:fb:9a:1b:2c"),
        &Signal::new(SignalKind::ReverseDns, "auroras-ipad.lan"),
        at(30),
    )
    .await;
    p.flush(&db).await;

    let after = queries::load_devices(&client).await.expect("devices");
    assert_eq!(after[0].display(), "auroras-ipad.lan");
    assert_eq!(after[0].identity_source.as_deref(), Some("reverse_dns"));
    assert_eq!(
        queries::count_events_of_type(&client, EventType::NameUpdated)
            .await
            .expect("count"),
        1
    );

    // The vendor signal was not overwritten, only outranked.
    let signals = queries::load_all_signals(&client).await.expect("signals");
    let stored = signals.get(&after[0].id).expect("signals for the device");
    assert!(stored.iter().any(|s| s.kind == SignalKind::Vendor));
    assert!(stored.iter().any(|s| s.kind == SignalKind::ReverseDns));
    assert_eq!(after[0].vendor.as_deref(), Some("Apple, Inc."));
}

#[tokio::test]
async fn a_user_assigned_name_is_never_overwritten_by_the_daemon() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut p = Pipeline::new(state_config(), false);
    p.frame(&db, &fixtures::mdns_response_ipv4(), "eth0", at(0))
        .await;
    p.flush(&db).await;

    // Trovato renames the device, the way the plugin's write-back tap would.
    {
        let client = db.client().await;
        client
            .execute(
                "UPDATE ng_devices SET display_name = 'Jamie''s telly', notes = 'in the lounge', \
                 hidden = TRUE, notify = FALSE",
                &[],
            )
            .await
            .expect("the user renames a device");
    }

    // The daemon keeps observing and flushing.
    for i in 1..20 {
        p.frame(&db, &fixtures::mdns_response_ipv4(), "eth0", at(i * 10))
            .await;
        p.flush(&db).await;
    }

    let client = db.client().await;
    let devices = queries::load_devices(&client).await.expect("devices");
    let device = devices
        .iter()
        .find(|d| d.mac == mac("b8:27:eb:44:55:66"))
        .expect("the device");
    assert_eq!(device.display_name.as_deref(), Some("Jamie's telly"));
    assert_eq!(device.notes.as_deref(), Some("in the lounge"));
    assert!(device.hidden);
    assert!(!device.notify);
    assert_eq!(
        device.resolved_name.as_deref(),
        Some("Living Room Apple TV"),
        "the daemon still records what it worked out"
    );
    assert_eq!(
        device.display(),
        "Jamie's telly",
        "but the user's name wins"
    );
}

#[tokio::test]
async fn an_address_change_is_one_event_and_two_history_rows() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut p = Pipeline::new(state_config(), false);

    for (secs, ip) in [
        (0i64, "192.168.1.40"),
        (60, "192.168.1.41"),
        (120, "192.168.1.41"),
    ] {
        let obs = Observation::new(
            mac("3c:22:fb:00:00:07"),
            Some(ip.parse().expect("ip")),
            "eth0",
            "arp",
            netgraspd::types::ObservationKind::Reply,
            at(secs),
        );
        p.observe(&db, &obs).await;
    }
    p.flush(&db).await;

    let client = db.client().await;
    assert_eq!(
        queries::count_events_of_type(&client, EventType::IpChanged)
            .await
            .expect("count"),
        1,
        "one change, not one per packet at the new address"
    );
    assert_eq!(db.count("ng_ip_history").await, 2);
    let devices = queries::load_devices(&client).await.expect("devices");
    assert_eq!(devices[0].last_ip.as_deref(), Some("192.168.1.41"));
}

#[tokio::test]
async fn every_daemon_write_marks_the_row_dirty_for_the_plugin() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut p = Pipeline::new(state_config(), false);
    p.frame(&db, &fixtures::arp_request(), "eth0", at(0)).await;
    p.flush(&db).await;

    // The plugin's sweep would clear these.
    {
        let client = db.client().await;
        client
            .batch_execute("UPDATE ng_devices SET sync_state = 'clean'; UPDATE ng_events SET sync_state = 'clean'")
            .await
            .expect("the plugin marks rows synced");
    }
    assert_eq!(
        db.scalar("SELECT COUNT(*) FROM ng_devices WHERE sync_state = 'dirty'")
            .await,
        0
    );

    // Any further daemon activity re-dirties them.
    p.sweep(&db, at(20_000)).await;
    p.flush(&db).await;
    assert_eq!(
        db.scalar("SELECT COUNT(*) FROM ng_devices WHERE sync_state = 'dirty'")
            .await,
        1
    );
    assert_eq!(
        db.scalar("SELECT COUNT(*) FROM ng_events WHERE sync_state = 'dirty'")
            .await,
        1,
        "the went_offline event is new and therefore dirty"
    );
}
