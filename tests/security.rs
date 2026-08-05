//! End-to-end: mixed multi-protocol traffic in, identities and security events
//! out.
//!
//! `pipeline.rs` proves the milestone 1 contract, the load-bearing part of which
//! is that the database never grows a row per packet. This proves the milestone 2
//! one: that six protocols' worth of frames go through the real parsers, the real
//! scorer, the real classifier, the real analyzer chain and the real persister,
//! and produce devices that know what they are and alerts about the things that
//! are actually wrong.
//!
//! The two assertions that matter most here are negative. A network doing
//! nothing wrong must produce **no** security events at all, and the analyzers
//! must see the observations the deduplicator throws away, because a scan burst
//! is exactly what dedup collapses.

mod common;

use chrono::{DateTime, Duration, TimeZone, Utc};
use netgraspd::analyze::Chain;
use netgraspd::capture::{ObservationDedup, arp, dhcp, fixtures, mdns, nbns, ndp, ssdp};
use netgraspd::config::{
    ArpScanConfig, HumanDuration, IdentityChangeConfig, SecurityConfig, StateConfig,
};
use netgraspd::db::queries;
use netgraspd::device::persist::Persister;
use netgraspd::device::{Effect, Manager};
use netgraspd::events::EventBus;
use netgraspd::types::{EventType, MacAddr, Observation};

/// The whole daemon minus libpcap and the notifier, wired the way `daemon.rs`
/// wires it: the state machine sees the deduplicated stream, the analyzers see
/// everything.
struct Pipeline {
    manager: Manager,
    persister: Persister,
    dedup: ObservationDedup,
    analyzers: Chain,
    bus: EventBus,
    alerts: Vec<EventType>,
}

impl Pipeline {
    fn new(security: SecurityConfig) -> Self {
        Pipeline {
            manager: Manager::new(state_config(), false),
            persister: Persister::new(),
            dedup: ObservationDedup::new(4096, 1),
            analyzers: Chain::new(&security),
            bus: EventBus::new(1024),
            alerts: Vec::new(),
        }
    }

    /// Feeds one raw frame through every parser, exactly as the six capture
    /// threads would.
    async fn frame(&mut self, db: &common::TestDb, bytes: &[u8], iface: &str, at: DateTime<Utc>) {
        let parsed = arp::parse_frame(bytes, iface, at)
            .or_else(|| mdns::parse_frame(bytes, iface, at))
            .or_else(|| dhcp::parse_frame(bytes, iface, at))
            .or_else(|| ssdp::parse_frame(bytes, iface, at))
            .or_else(|| ndp::parse_frame(bytes, iface, at))
            .or_else(|| nbns::parse_frame(bytes, iface, at));
        let Some(observation) = parsed else {
            return;
        };
        self.observe(db, &observation).await;
    }

    async fn observe(&mut self, db: &common::TestDb, observation: &Observation) {
        if self.dedup.admit(observation) {
            let effects = self.manager.observe(observation);
            self.apply(db, &effects).await;
        }
        // Every observation reaches the analyzers, deduplicated or not.
        let alerts = self.analyzers.observe(observation);
        self.record_alerts(db, alerts).await;
        self.drain_reclassifications(db).await;
    }

    async fn drain_reclassifications(&mut self, db: &common::TestDb) {
        for change in self.manager.take_reclassifications() {
            let alerts = self.analyzers.reclassified(&change);
            self.record_alerts(db, alerts).await;
        }
    }

    async fn record_alerts(
        &mut self,
        db: &common::TestDb,
        alerts: Vec<netgraspd::analyze::SecurityAlert>,
    ) {
        for alert in alerts {
            self.alerts.push(alert.event_type);
            let effects = self.manager.security_event(&alert);
            self.apply(db, &effects).await;
        }
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

    fn alert_count(&self, kind: EventType) -> usize {
        self.alerts.iter().filter(|k| **k == kind).count()
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

/// Every fixture frame a healthy network emits, in a plausible order.
fn healthy_traffic() -> Vec<Vec<u8>> {
    vec![
        fixtures::dhcp_discover(),
        fixtures::dhcp_offer(),
        fixtures::dhcp_ack(),
        fixtures::arp_request(),
        fixtures::arp_reply(),
        fixtures::arp_gratuitous(),
        fixtures::arp_probe(),
        fixtures::mdns_response_ipv4(),
        fixtures::mdns_response_ipv6(),
        fixtures::mdns_query(),
        fixtures::ssdp_notify(),
        fixtures::ssdp_msearch(),
        fixtures::ssdp_response(),
        fixtures::ndp_solicitation(),
        fixtures::ndp_advertisement(),
        fixtures::ndp_router_advertisement(),
        fixtures::ndp_dad(),
        fixtures::nbns_registration(),
        fixtures::nbns_query(),
        fixtures::nbns_datagram(),
    ]
}

/// An ARP request from `from` asking about `target`.
fn arp_request(from: &str, target: [u8; 4], when: DateTime<Utc>) -> Observation {
    let mut frame = fixtures::arp_request();
    let source = mac(from).octets();
    frame[6..12].copy_from_slice(&source);
    frame[22..28].copy_from_slice(&source);
    frame[38..42].copy_from_slice(&target);
    arp::parse_frame(&frame, "eth0", when).expect("parsed")
}

/// An ARP reply from `from` claiming `claimed`.
fn arp_claim(from: &str, claimed: [u8; 4], when: DateTime<Utc>) -> Observation {
    let mut frame = fixtures::arp_reply();
    let source = mac(from).octets();
    frame[6..12].copy_from_slice(&source);
    frame[22..28].copy_from_slice(&source);
    frame[28..32].copy_from_slice(&claimed);
    arp::parse_frame(&frame, "eth0", when).expect("parsed")
}

/// A DHCP Offer from `from`.
fn dhcp_offer_from(from: &str, when: DateTime<Utc>) -> Observation {
    let mut frame = fixtures::dhcp_offer();
    frame[6..12].copy_from_slice(&mac(from).octets());
    dhcp::parse_frame(&frame, "eth0", when).expect("parsed")
}

#[tokio::test]
async fn mixed_multi_protocol_traffic_identifies_devices_and_classifies_them() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut pipeline = Pipeline::new(SecurityConfig::default());

    // Two rounds so that repeat traffic exercises the refinement path rather
    // than only first sightings.
    for round in 0..2i64 {
        for (n, frame) in healthy_traffic().into_iter().enumerate() {
            let offset = round * 100 + i64::try_from(n).expect("small");
            pipeline.frame(&db, &frame, "eth0", at(offset)).await;
        }
    }
    pipeline.flush(&db).await;

    let client = db.client().await;
    let devices = queries::load_devices(&client).await.expect("devices load");
    let by_mac = |m: &str| {
        devices
            .iter()
            .find(|d| d.mac == mac(m))
            .unwrap_or_else(|| panic!("{m} should be a known device"))
    };

    // The Apple device names itself over DHCP and is classified by its vendor
    // class, because its option 55 fingerprint knows the OS but not the type.
    let phone = by_mac("3c:22:fb:9a:1b:2c");
    assert_eq!(phone.display(), "auroras-ipad", "the DHCP hostname wins");
    assert_eq!(phone.os_family.as_deref(), Some("iOS"));
    assert_eq!(phone.device_type.as_deref(), Some("phone"));
    assert_eq!(phone.vendor.as_deref(), Some("Apple, Inc."));

    // The gateway advertises IPv6 routes, which is the least ambiguous
    // device-type evidence on the network and beats its mDNS media services.
    let gateway = by_mac("b8:27:eb:44:55:66");
    assert_eq!(gateway.device_type.as_deref(), Some("router"));
    assert!(
        gateway.device_type_confidence.unwrap_or(0.0) > 0.9,
        "a router advertisement is not a guess: {:?}",
        gateway.device_type_confidence
    );
    assert_eq!(
        gateway.last_ipv6.as_deref(),
        Some("2001:db8::1"),
        "the global address is preferred over the link-local one"
    );

    // The NAS announces a UPnP MediaServer over SSDP and registers a NetBIOS
    // name; the self-declared UPnP class wins over the NetBIOS inference.
    let nas = by_mac("00:11:32:aa:bb:cc");
    assert_eq!(nas.device_type.as_deref(), Some("nas"));
    assert_eq!(nas.display(), "JEREMY-PC", "the NetBIOS name is the name");
    assert_eq!(
        nas.os_family.as_deref(),
        Some("Linux"),
        "the SSDP SERVER header names the OS outright and beats the NetBIOS \
         workgroup, which would have guessed Windows off a Samba share"
    );

    // The television volunteers a base64 friendly name in an SSDP header. It is
    // never fetched from the LOCATION URL, which would mean transmitting.
    let tv = by_mac("b0:a7:37:0a:0b:0c");
    assert_eq!(tv.display(), "Living Room TV");
    assert_eq!(tv.device_type.as_deref(), Some("tv"));
    assert_eq!(tv.vendor.as_deref(), Some("Roku, Inc."));

    // The printer announces over mDNS and does DAD over IPv6.
    let printer = by_mac("3c:2a:f4:11:22:33");
    assert_eq!(printer.display(), "Office Printer");
    assert_eq!(printer.device_type.as_deref(), Some("printer"));

    // How many devices got past a bare vendor guess. This is the number the
    // milestone is judged on.
    let typed = devices.iter().filter(|d| d.device_type.is_some()).count();
    assert_eq!(typed, devices.len(), "every device got a type: {devices:?}");
}

#[tokio::test]
async fn a_healthy_network_never_trips_a_wire_analyzer() {
    // The most important negative in the suite. A detector that alerts on
    // ordinary traffic is worse than no detector, because it trains its operator
    // to ignore it. Twenty rounds of every protocol, and the five analyzers that
    // watch the wire stay completely silent.
    //
    // `identity_change` is excluded from that claim, and deliberately so: the
    // fixture set gives the gateway and the mDNS responder the same MAC on
    // purpose (see tests/fixtures/README.md), so that one host is a media player
    // by its mDNS services and a router by its Router Advertisement. Higher-rank
    // evidence contradicting lower-rank evidence is precisely what that analyzer
    // fires on, and it fires once, not once per round.
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut pipeline = Pipeline::new(SecurityConfig::default());

    for round in 0..20i64 {
        for (n, frame) in healthy_traffic().into_iter().enumerate() {
            let offset = round * 60 + i64::try_from(n).expect("small");
            pipeline.frame(&db, &frame, "eth0", at(offset)).await;
        }
    }
    pipeline.flush(&db).await;

    for wire in [
        EventType::ArpScan,
        EventType::ArpSpoof,
        EventType::RogueDhcp,
        EventType::IpConflict,
        EventType::GratuitousArp,
    ] {
        assert_eq!(
            pipeline.alert_count(wire),
            0,
            "{wire} fired on ordinary traffic: {:?}",
            pipeline.alerts
        );
    }
    assert_eq!(
        pipeline.alert_count(EventType::IdentityChange),
        1,
        "the dual-personality fixture host resolves once and then settles"
    );

    let client = db.client().await;
    let security = queries::recent_security_events(&client, 100)
        .await
        .expect("security events load");
    assert_eq!(security.len(), 1, "{security:?}");
}

#[tokio::test]
async fn a_scan_burst_fires_even_though_dedup_collapses_it() {
    // The ordering the daemon depends on. Dedup keys on (MAC, kind, second), so
    // two hundred ARP requests in one second are ONE observation to the state
    // machine and are the entire signal to arp_scan. Running the analyzers on the
    // deduplicated stream would make this test fail and the analyzer useless.
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut pipeline = Pipeline::new(SecurityConfig::default());

    for n in 1..=30u8 {
        let observation = arp_request("02:aa:bb:cc:dd:ee", [192, 168, 1, n], at(0));
        pipeline.observe(&db, &observation).await;
    }
    pipeline.flush(&db).await;

    assert_eq!(
        pipeline.alert_count(EventType::ArpScan),
        1,
        "one sweep is one alert: {:?}",
        pipeline.alerts
    );
    assert_eq!(
        pipeline.dedup.duplicates_suppressed(),
        29,
        "the state machine saw one of those thirty packets"
    );

    let client = db.client().await;
    let events = queries::recent_security_events(&client, 10)
        .await
        .expect("security events load");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "arp_scan");
    assert_eq!(
        events[0].details["security"], true,
        "the flag the plugin renders on"
    );
    assert_eq!(events[0].details["distinct_targets"], 10);
    assert!(
        events[0].device_id.is_some(),
        "the scanner became a device before the alert was recorded"
    );
}

#[tokio::test]
async fn a_gateway_spoof_fires_immediately_and_a_reassignment_does_not() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut pipeline = Pipeline::new(SecurityConfig::default());

    // Let the gateway establish itself the way it would in real traffic: the
    // DHCP Offer states option 3 and is sourced from the gateway's address.
    let offer = dhcp_offer_from("b8:27:eb:44:55:66", at(0));
    pipeline.observe(&db, &offer).await;
    assert_eq!(
        pipeline.analyzers.gateway().mac(),
        Some(mac("b8:27:eb:44:55:66")),
        "the gateway was learned passively from option 3"
    );

    // A laptop leaves and its address is handed to a tablet an hour later. Not
    // an attack, and it must not alert.
    pipeline
        .observe(
            &db,
            &arp_claim("3c:22:fb:9a:1b:2c", [192, 168, 1, 40], at(10)),
        )
        .await;
    pipeline
        .observe(
            &db,
            &arp_claim("00:11:32:aa:bb:cc", [192, 168, 1, 40], at(3610)),
        )
        .await;
    assert_eq!(
        pipeline.alert_count(EventType::ArpSpoof),
        0,
        "a lease reassignment is not a spoof: {:?}",
        pipeline.alerts
    );

    // Somebody claims the gateway's address. However long the gateway has been
    // quiet, this is not innocent.
    pipeline
        .observe(
            &db,
            &arp_claim("02:de:ad:be:ef:01", [192, 168, 1, 1], at(7200)),
        )
        .await;
    pipeline.flush(&db).await;

    assert_eq!(pipeline.alert_count(EventType::ArpSpoof), 1);
    let client = db.client().await;
    let events = queries::recent_security_events(&client, 10)
        .await
        .expect("security events load");
    let spoof = events
        .iter()
        .find(|e| e.event_type == "arp_spoof")
        .expect("an arp_spoof event");
    assert_eq!(spoof.details["gateway_impersonation"], true);
    assert_eq!(spoof.details["claimed_ip"], "192.168.1.1");
    assert_eq!(spoof.details["priority"], "urgent");
}

#[tokio::test]
async fn a_second_dhcp_server_fires_and_the_real_one_does_not() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut pipeline = Pipeline::new(SecurityConfig::default());

    for n in 0..5i64 {
        pipeline
            .observe(&db, &dhcp_offer_from("b8:27:eb:44:55:66", at(n)))
            .await;
    }
    assert!(pipeline.alerts.is_empty(), "{:?}", pipeline.alerts);

    pipeline
        .observe(&db, &dhcp_offer_from("02:de:ad:be:ef:02", at(10)))
        .await;
    pipeline.flush(&db).await;

    assert_eq!(pipeline.alert_count(EventType::RogueDhcp), 1);
    let client = db.client().await;
    let events = queries::recent_security_events(&client, 10)
        .await
        .expect("security events load");
    let rogue = events
        .iter()
        .find(|e| e.event_type == "rogue_dhcp")
        .expect("a rogue_dhcp event");
    assert_eq!(rogue.details["expected_server"], "b8:27:eb:44:55:66");
    assert_eq!(rogue.details["offered_router"], "192.168.1.1");
}

#[tokio::test]
async fn a_device_changing_what_it_is_fires_and_learning_what_it_is_does_not() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut pipeline = Pipeline::new(SecurityConfig::default());

    // The printer announces itself over mDNS: a first classification, which is
    // a refinement rather than a change.
    pipeline
        .frame(&db, &fixtures::mdns_response_ipv6(), "eth0", at(0))
        .await;
    assert_eq!(
        pipeline.alert_count(EventType::IdentityChange),
        0,
        "learning what a device is must not alert: {:?}",
        pipeline.alerts
    );

    // The same MAC now declares a UPnP MediaServer class over SSDP. A
    // self-declared UPnP class outranks an mDNS service type, so printer becomes
    // nas: higher-rank evidence contradicting what lower-rank evidence said,
    // which is exactly what a category change is.
    let mut frame = fixtures::ssdp_notify();
    frame[6..12].copy_from_slice(&mac("3c:2a:f4:11:22:33").octets());
    pipeline.frame(&db, &frame, "eth0", at(60)).await;
    pipeline.flush(&db).await;

    assert_eq!(pipeline.alert_count(EventType::IdentityChange), 1);
    let client = db.client().await;
    let events = queries::recent_security_events(&client, 10)
        .await
        .expect("security events load");
    let change = events
        .iter()
        .find(|e| e.event_type == "identity_change")
        .expect("an identity_change event");
    assert_eq!(change.details["previous_device_type"], "printer");
    assert_eq!(change.details["device_type"], "nas");
    assert_eq!(change.details["category_change"], true);
    assert_eq!(change.details["sensitivity"], "category");
    assert_eq!(change.details["priority"], "urgent");

    // And the device row carries the new classification.
    let devices = queries::load_devices(&client).await.expect("devices load");
    let printer = devices
        .iter()
        .find(|d| d.mac == mac("3c:2a:f4:11:22:33"))
        .expect("the device");
    assert_eq!(printer.device_type.as_deref(), Some("nas"));
}

#[tokio::test]
async fn an_exempt_mac_is_never_alerted_on_by_any_analyzer() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let security = SecurityConfig {
        exempt_macs: vec!["02:aa:bb:cc:dd:ee".into()],
        ..SecurityConfig::default()
    };
    let mut pipeline = Pipeline::new(security);

    // The monitoring box the exemption exists for, sweeping the whole subnet.
    for n in 1..=50u8 {
        pipeline
            .observe(
                &db,
                &arp_request("02:aa:bb:cc:dd:ee", [192, 168, 1, n], at(0)),
            )
            .await;
    }
    pipeline.flush(&db).await;

    assert!(
        pipeline.alerts.is_empty(),
        "an exempt MAC is silent: {:?}",
        pipeline.alerts
    );
    let client = db.client().await;
    let security = queries::recent_security_events(&client, 10)
        .await
        .expect("security events load");
    assert!(security.is_empty(), "{security:?}");
    // The exemption silences the analyzers, not the state machine: the
    // monitoring box is still a device and its arrival is still recorded.
    assert_eq!(
        queries::count_events_of_type(&client, EventType::NewDevice)
            .await
            .expect("count"),
        1
    );
}

#[tokio::test]
async fn a_disabled_analyzer_stops_firing_and_the_others_keep_working() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let security = SecurityConfig {
        arp_scan: ArpScanConfig {
            enabled: false,
            ..ArpScanConfig::default()
        },
        ..SecurityConfig::default()
    };
    let mut pipeline = Pipeline::new(security);

    for n in 1..=50u8 {
        pipeline
            .observe(
                &db,
                &arp_request("02:aa:bb:cc:dd:ee", [192, 168, 1, n], at(0)),
            )
            .await;
    }
    assert_eq!(pipeline.alert_count(EventType::ArpScan), 0);

    // The rest of the chain is untouched.
    pipeline
        .observe(&db, &dhcp_offer_from("b8:27:eb:44:55:66", at(0)))
        .await;
    pipeline
        .observe(&db, &dhcp_offer_from("02:de:ad:be:ef:02", at(1)))
        .await;
    assert_eq!(pipeline.alert_count(EventType::RogueDhcp), 1);
}

#[tokio::test]
async fn security_events_are_recorded_during_a_learning_window() {
    // A monitor that forgets attacks during its own warm-up is worse than one
    // that stays quiet, and the learning window is exactly when a network is
    // least understood.
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut pipeline = Pipeline::new(SecurityConfig::default());
    pipeline.manager = Manager::new(state_config(), true);
    assert!(pipeline.manager.is_learning());

    for n in 1..=30u8 {
        pipeline
            .observe(
                &db,
                &arp_request("02:aa:bb:cc:dd:ee", [192, 168, 1, n], at(0)),
            )
            .await;
    }
    pipeline.flush(&db).await;

    let client = db.client().await;
    let events = queries::recent_security_events(&client, 10)
        .await
        .expect("security events load");
    assert_eq!(events.len(), 1, "the record is written either way");

    // And unlike a device-lifecycle event, it is deliverable.
    let recorded = queries::recent_events(&client, 50)
        .await
        .expect("events load");
    let scan = recorded
        .iter()
        .find(|e| e.event_type == "arp_scan")
        .expect("the scan event");
    assert_eq!(scan.details["security"], true);
}

#[tokio::test]
async fn any_sensitivity_fires_on_a_first_classification_and_category_does_not() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let security = SecurityConfig {
        identity_change: IdentityChangeConfig {
            enabled: true,
            sensitivity: "any".into(),
        },
        ..SecurityConfig::default()
    };
    let mut pipeline = Pipeline::new(security);

    pipeline
        .frame(&db, &fixtures::mdns_response_ipv6(), "eth0", at(0))
        .await;
    pipeline.flush(&db).await;

    assert_eq!(
        pipeline.alert_count(EventType::IdentityChange),
        1,
        "under `any`, learning what a device is does fire"
    );
    let client = db.client().await;
    let events = queries::recent_security_events(&client, 10)
        .await
        .expect("security events load");
    let change = &events[0];
    assert_eq!(change.details["category_change"], false);
    assert_eq!(
        change.details["priority"], "normal",
        "a first classification does not warrant waking somebody"
    );
}

#[tokio::test]
async fn the_analyzers_never_write_a_row_per_packet_either() {
    // The rule the whole rewrite exists to enforce, restated for the analyzer
    // chain: an attack lasting an hour is a handful of events, not one per frame.
    let Some(db) = common::test_db().await else {
        return;
    };
    let mut pipeline = Pipeline::new(SecurityConfig::default());

    let mut offered = 0u32;
    for second in 0..1800i64 {
        // A continuous sweep, a continuous poisoning attempt and a rogue server,
        // all at once, for half an hour.
        for n in 1..=4u8 {
            pipeline
                .observe(
                    &db,
                    &arp_request(
                        "02:aa:bb:cc:dd:ee",
                        [10, 0, (second % 250) as u8, n],
                        at(second),
                    ),
                )
                .await;
            offered += 1;
        }
        pipeline
            .observe(
                &db,
                &arp_claim("02:de:ad:be:ef:01", [192, 168, 1, 40], at(second)),
            )
            .await;
        pipeline
            .observe(
                &db,
                &arp_claim("3c:22:fb:9a:1b:2c", [192, 168, 1, 40], at(second)),
            )
            .await;
        offered += 2;
    }
    pipeline.flush(&db).await;

    let client = db.client().await;
    let security = queries::count_events_of_type(&client, EventType::ArpScan)
        .await
        .expect("count")
        + queries::count_events_of_type(&client, EventType::ArpSpoof)
            .await
            .expect("count");
    assert!(offered > 10_000, "the test needs real volume: {offered}");
    assert!(
        security < 200,
        "{offered} packets produced {security} security events; the cooldowns are not working"
    );
    assert!(
        security > 0,
        "half an hour of attack must produce something"
    );
}
