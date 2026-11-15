//! The trip export, against a real Postgres.
//!
//! Seeds a database with what a short run on a foreign network leaves behind,
//! a status file with a visibility report and an unknown-device sample, then
//! exports and reads the bundle back the way somebody without a database would:
//! as files. Every section has to be there, and no secret from the
//! configuration may survive anywhere in it, the pcap included.

mod common;

use std::path::{Path, PathBuf};

use chrono::{TimeDelta, Utc};
use netgraspd::capture::{fixtures, sample};
use netgraspd::config::{Config, NtfyConfig};
use netgraspd::export;
use netgraspd::runtime::{Status, visibility};

/// A directory of this test's own under the system temporary directory.
fn temp_dir(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "netgraspd-export-test-{}-{test}",
        std::process::id()
    ));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// The password in a `scheme://user:password@host` URL, when it has one.
fn url_password(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let userinfo = rest.split_once('@')?.0;
    Some(userinfo.split_once(':')?.1.to_string())
}

/// Two devices, one named by mDNS and typed by its services, one named by
/// nothing, and a few events about them.
async fn seed(db: &common::TestDb) {
    let client = db.client().await;
    let now = Utc::now();
    client
        .execute(
            "INSERT INTO ng_devices
                 (mac, resolved_name, identity_source, identity_confidence, mdns_name,
                  vendor, device_type, device_type_confidence, os_family, state,
                  last_ip, last_interface, first_seen_at, last_seen_at)
             VALUES ('00:11:22:33:44:01', 'Hotel Gateway', 'mdns_name', 0.9,
                     'Hotel Gateway', 'Ubiquiti Inc', 'router', 0.95, NULL, 'online',
                     '10.20.0.1', 'en0', $1, $1),
                    ('da:a1:19:00:00:02', NULL, 'mac', 0.1, NULL, NULL, NULL, NULL,
                     NULL, 'online', '10.20.0.77', 'en0', $1, $1)",
            &[&now],
        )
        .await
        .expect("seeding devices");
    client
        .execute(
            "INSERT INTO ng_device_signals (device_id, signal_type, value, first_seen_at, last_seen_at)
             SELECT id, 'ndp_role', 'router', $1::timestamptz, $1::timestamptz FROM ng_devices WHERE mac = '00:11:22:33:44:01'
             UNION ALL
             SELECT id, 'mdns_name', 'Hotel Gateway', $1::timestamptz, $1::timestamptz FROM ng_devices WHERE mac = '00:11:22:33:44:01'",
            &[&now],
        )
        .await
        .expect("seeding signals");
    client
        .execute(
            "INSERT INTO ng_events (device_id, event_type, \"timestamp\", details)
             SELECT id, 'new_device', $1::timestamptz, '{\"mac\": \"00:11:22:33:44:01\"}'::jsonb
               FROM ng_devices WHERE mac = '00:11:22:33:44:01'
             UNION ALL
             SELECT id, 'new_device', $1::timestamptz, '{\"mac\": \"da:a1:19:00:00:02\"}'::jsonb
               FROM ng_devices WHERE mac = 'da:a1:19:00:00:02'
             UNION ALL
             SELECT NULL::bigint, 'arp_scan', $1::timestamptz, '{\"targets\": 40}'::jsonb",
            &[&now],
        )
        .await
        .expect("seeding events");
}

/// The configuration a trip runs with, every secret field filled with
/// something distinctive.
fn config(dir: &Path) -> (Config, Vec<String>) {
    let mut config = Config::default();
    config.database.url = common::test_url();
    config.runtime.status_path = dir.join("status.json");
    config.capture.unknown_sample.enabled = true;
    config.capture.unknown_sample.path = dir.join("unknown-sample.pcap");
    config.notify.enabled = false;
    config.notify.ntfy = Some(NtfyConfig {
        topic: "export-topic-secret-a".into(),
        token: Some("tk_export-secret-b".into()),
        ..NtfyConfig::default()
    });
    config.enrichment.unifi.username = "export-user-secret-c".into();
    config.enrichment.unifi.password = "export-password-secret-d".into();
    config.enrichment.unifi.api_key = "export-key-secret-e".into();

    let mut secrets: Vec<String> = [
        "export-topic-secret-a",
        "tk_export-secret-b",
        "export-user-secret-c",
        "export-password-secret-d",
        "export-key-secret-e",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    if let Some(password) = url_password(&config.database.url) {
        // As it appears in the URL, which is the only place it could leak from.
        secrets.push(format!(":{password}@"));
    }
    (config, secrets)
}

/// A status file as an isolated guest network leaves it.
fn write_status(path: &Path) {
    let now = Utc::now();
    let mut status = Status::new(now - TimeDelta::minutes(10));
    status.updated_at = now;
    status.interfaces.insert(
        "en0".into(),
        visibility::InterfaceVisibility {
            listening_since: Some(now - TimeDelta::minutes(10)),
            frames: 40,
            senders: 2,
            senders_capped: false,
            this_host_seen: true,
            gateway_seen: true,
            last_frame_at: Some(now),
            sources: std::collections::BTreeMap::new(),
        },
    );
    status.gateway = Some(visibility::GatewayBelief {
        ip: Some("10.20.0.1".into()),
        mac: Some("00:11:22:33:44:01".into()),
        ip_source: "route".into(),
        mac_source: "inferred".into(),
    });
    status.write(path).expect("writes the status file");
}

/// An unknown-device sample with one frame in it.
fn write_sample(path: &Path) {
    let mut sampler = sample::UnknownSampler::new(
        path.to_path_buf(),
        sample::SampleLimits {
            frames_per_device: 3,
            max_devices: 3,
            max_bytes: 1 << 20,
            settle: TimeDelta::seconds(1),
        },
    );
    let mut frame = fixtures::arp_request();
    frame[6..12].copy_from_slice(&[0xda, 0xa1, 0x19, 0, 0, 2]);
    let at = Utc::now() - TimeDelta::minutes(5);
    let len = u32::try_from(frame.len()).expect("small");
    sampler.offer(
        sample::Frame::from_ethernet(&frame, len, at).expect("a unicast sender"),
        Some(false),
    );
    sampler.settle(Utc::now(), |_| Some(false));
    assert!(path.exists(), "the fixture sample was written");
}

#[tokio::test]
async fn a_trip_export_has_every_section_and_no_secret() {
    let Some(db) = common::test_db().await else {
        return;
    };
    seed(&db).await;
    let dir = temp_dir("bundle");
    let (config, secrets) = config(&dir);
    write_status(&config.runtime.status_path);
    write_sample(&config.capture.unknown_sample.path);

    let bundle = dir.join("trip");
    let report = export::export(&config, &bundle)
        .await
        .expect("the export runs");
    assert_eq!(report.devices, 2);
    assert_eq!(report.events, 3);

    for file in [
        export::SUMMARY_FILE,
        export::DEVICES_FILE,
        export::EVENTS_FILE,
        export::VISIBILITY_FILE,
        export::CONFIG_FILE,
        export::SAMPLE_FILE,
    ] {
        assert!(bundle.join(file).is_file(), "{file} is in the bundle");
        assert!(report.files.iter().any(|f| f == file), "{file} is reported");
    }

    let summary = std::fs::read_to_string(bundle.join(export::SUMMARY_FILE)).expect("summary");
    for heading in [
        "# netgraspd trip export",
        "## Visibility",
        "## Devices",
        "## Events",
        "## Unknown device sample",
        "## Configuration",
    ] {
        assert!(summary.contains(heading), "{heading} missing:\n{summary}");
    }
    assert!(
        summary.contains("consistent with client isolation"),
        "the verdict is in the summary:\n{summary}"
    );
    assert!(summary.contains("Hotel Gateway"), "{summary}");
    assert!(summary.contains("da:a1:19:00:00:02"), "{summary}");

    // The raw data parses, and carries what named and what typed each device.
    let devices: serde_json::Value =
        serde_json::from_slice(&std::fs::read(bundle.join(export::DEVICES_FILE)).expect("devices"))
            .expect("devices.json is JSON");
    let devices = devices.as_array().expect("an array of devices");
    assert_eq!(devices.len(), 2);
    let gateway = devices
        .iter()
        .find(|d| d["mac"] == "00:11:22:33:44:01")
        .expect("the gateway is exported");
    assert_eq!(gateway["name"], "Hotel Gateway");
    assert_eq!(gateway["named_by"], "mdns_name");
    assert_eq!(gateway["device_type"], "router");
    assert!(
        gateway["typed_by"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty()),
        "{gateway}"
    );
    let unknown = devices
        .iter()
        .find(|d| d["mac"] == "da:a1:19:00:00:02")
        .expect("the unnamed device is exported");
    assert_eq!(unknown["named"], false);

    let events: serde_json::Value =
        serde_json::from_slice(&std::fs::read(bundle.join(export::EVENTS_FILE)).expect("events"))
            .expect("events.json is JSON");
    assert_eq!(events.as_array().expect("an array").len(), 3);

    let visibility: serde_json::Value = serde_json::from_slice(
        &std::fs::read(bundle.join(export::VISIBILITY_FILE)).expect("visibility"),
    )
    .expect("visibility.json is JSON");
    assert_eq!(
        visibility["verdicts"]["en0"]["kind"], "isolated",
        "{visibility}"
    );

    let sample = std::fs::read(bundle.join(export::SAMPLE_FILE)).expect("sample");
    assert_eq!(
        sample,
        std::fs::read(&config.capture.unknown_sample.path).expect("original"),
        "the sample is copied unchanged"
    );

    // No secret anywhere, in any file, binary ones included.
    for entry in std::fs::read_dir(&bundle).expect("lists the bundle") {
        let path = entry.expect("an entry").path();
        let bytes = std::fs::read(&path).expect("reads");
        let text = String::from_utf8_lossy(&bytes);
        for secret in &secrets {
            assert!(
                !text.contains(secret.as_str()),
                "{secret} survived in {}",
                path.display()
            );
        }
    }
    let config_json = std::fs::read_to_string(bundle.join(export::CONFIG_FILE)).expect("config");
    assert!(
        config_json.contains("***"),
        "redacted, not dropped: {config_json}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn an_export_without_a_status_file_or_sample_says_so_rather_than_failing() {
    let Some(db) = common::test_db().await else {
        return;
    };
    seed(&db).await;
    let dir = temp_dir("bare");
    let (mut config, _) = config(&dir);
    config.capture.unknown_sample.enabled = false;

    let bundle = dir.join("trip");
    let report = export::export(&config, &bundle)
        .await
        .expect("the export runs");
    assert!(!bundle.join(export::SAMPLE_FILE).exists());
    assert!(!report.files.iter().any(|f| f == export::SAMPLE_FILE));
    let summary = std::fs::read_to_string(bundle.join(export::SUMMARY_FILE)).expect("summary");
    assert!(summary.contains("no status file"), "{summary}");
    assert!(summary.contains("## Unknown device sample"), "{summary}");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn an_export_refuses_a_directory_that_already_holds_something() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let dir = temp_dir("occupied");
    let (config, _) = config(&dir);
    let bundle = dir.join("trip");
    std::fs::create_dir_all(&bundle).expect("creates");
    std::fs::write(bundle.join("keep.txt"), b"mine").expect("writes");
    let err = export::export(&config, &bundle)
        .await
        .expect_err("must refuse");
    assert!(err.to_string().contains("not empty"), "{err}");
    assert_eq!(
        std::fs::read(bundle.join("keep.txt")).expect("still there"),
        b"mine"
    );
    drop(db);
    std::fs::remove_dir_all(&dir).ok();
}
