//! Delivery status and test alerts, end to end against a real Postgres and a
//! real HTTP listener standing in for ntfy.
//!
//! The web side cannot read the daemon's configuration and has no outbound
//! HTTP, so two things only the daemon can know are written where the plugin
//! can read them: whether delivery is configured (`ng_notify_status`), and the
//! outcome of a test alert somebody asked for (`ng_notify_requests`). These
//! tests pin both, and pin that neither ever carries the topic or the token.

mod common;

use jiff::SignedDuration;
use jiff::tz::{Offset, TimeZone};
use netgraspd::clock::Timestamp;
use netgraspd::config::{HumanDuration, NtfyConfig};
use netgraspd::notify::ntfy::NtfyNotifier;
use netgraspd::notify::{self, Notifier, TestOutcome};

const TOPIC: &str = "secret-topic-4f1c";
const TOKEN: &str = "tk_secret_token_9a2b";

fn base() -> Timestamp {
    Timestamp::from_utc(2026, 11, 17, 17, 42, 0).expect("valid time")
}

fn rome() -> TimeZone {
    TimeZone::fixed(Offset::from_seconds(3600).expect("offset"))
}

fn ntfy(server: &str) -> Box<dyn Notifier> {
    let cfg = NtfyConfig {
        topic: TOPIC.into(),
        server: server.into(),
        priority: 3,
        urgent_priority: 5,
        token: Some(TOKEN.into()),
        timeout: HumanDuration::from_secs(5),
    };
    Box::new(NtfyNotifier::with_time_zone(&cfg, rome()).expect("a usable notifier"))
}

/// Every text column of the two tables, concatenated, for the secrecy check.
async fn everything_the_plugin_can_read(db: &common::TestDb) -> String {
    let client = db.client().await;
    let mut all = String::new();
    for sql in [
        "SELECT row_to_json(s)::text FROM ng_notify_status s",
        "SELECT row_to_json(r)::text FROM ng_notify_requests r",
    ] {
        for row in client.query(sql, &[]).await.expect("reading") {
            all.push_str(&row.get::<_, String>(0));
            all.push('\n');
        }
    }
    all
}

#[tokio::test]
async fn the_status_row_says_whether_delivery_is_configured_and_by_what() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let (server, _log) = common::fake_ntfy(200).await;

    notify::publish_status(&db.db, &[ntfy(&server)], true, base())
        .await
        .expect("publishing the status");
    let client = db.client().await;
    let row = client
        .query_one(
            "SELECT notify_configured, notify_backend, last_delivery_ok, last_delivery_at_epoch,
                    updated_at_epoch
               FROM ng_notify_status",
            &[],
        )
        .await
        .expect("one status row");
    assert!(row.get::<_, bool>(0));
    assert_eq!(row.get::<_, Option<String>>(1).as_deref(), Some("ntfy"));
    assert_eq!(row.get::<_, Option<bool>>(2), None, "nothing delivered yet");
    assert_eq!(row.get::<_, Option<i64>>(3), None);
    assert_eq!(row.get::<_, Option<i64>>(4), Some(base().unix_seconds()));

    // No notifier: configured is false and there is no backend to name.
    notify::publish_status(&db.db, &[], true, base())
        .await
        .expect("publishing the status");
    let row = client
        .query_one(
            "SELECT notify_configured, notify_backend FROM ng_notify_status",
            &[],
        )
        .await
        .expect("still one status row");
    assert!(!row.get::<_, bool>(0));
    assert_eq!(row.get::<_, Option<String>>(1), None);

    // A notifier behind the master switch is not delivery either.
    notify::publish_status(&db.db, &[ntfy(&server)], false, base())
        .await
        .expect("publishing the status");
    assert_eq!(
        db.scalar("SELECT COUNT(*) FROM ng_notify_status WHERE NOT notify_configured")
            .await,
        1
    );
    assert_eq!(db.count("ng_notify_status").await, 1, "one row, always");
    assert!(!everything_the_plugin_can_read(&db).await.contains(TOPIC));
}

#[tokio::test]
async fn a_requested_test_is_sent_once_and_marked_done() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let (server, log) = common::fake_ntfy(200).await;
    let notifiers = vec![ntfy(&server)];
    notify::publish_status(&db.db, &notifiers, true, base())
        .await
        .expect("publishing the status");

    // Nothing asked for: nothing sent.
    assert_eq!(
        notify::handle_test_requests(&db.db, &notifiers, true, base())
            .await
            .expect("handling requests"),
        None
    );
    assert!(log.lock().expect("log").is_empty());

    // Somebody pressed Send test, twice, before the tick came round.
    db.execute(
        "INSERT INTO ng_notify_requests (requested_by) VALUES ('jeremy');
         INSERT INTO ng_notify_requests (requested_by) VALUES ('jeremy');",
    )
    .await;
    let now = base() + SignedDuration::from_secs(60);
    assert_eq!(
        notify::handle_test_requests(&db.db, &notifiers, true, now)
            .await
            .expect("handling requests"),
        Some(TestOutcome::Sent)
    );

    let sent = log.lock().expect("log").clone();
    assert_eq!(sent.len(), 1, "two presses waiting together are one test");
    assert_eq!(sent[0].path, format!("/{TOPIC}"));
    assert_eq!(sent[0].title, "Netgrasp test alert");
    assert_eq!(
        sent[0].body,
        "Alerts from netgraspd reach this device. Sent at 18:43."
    );
    assert_eq!(
        sent[0].authorization.as_deref(),
        Some(format!("Bearer {TOKEN}").as_str())
    );

    let client = db.client().await;
    let rows = client
        .query(
            "SELECT outcome, handled_at_epoch FROM ng_notify_requests ORDER BY id",
            &[],
        )
        .await
        .expect("reading requests");
    assert_eq!(rows.len(), 2);
    for row in &rows {
        assert_eq!(row.get::<_, Option<String>>(0).as_deref(), Some("sent"));
        assert_eq!(row.get::<_, Option<i64>>(1), Some(now.unix_seconds()));
    }
    let status = client
        .query_one(
            "SELECT last_delivery_ok, last_delivery_at_epoch FROM ng_notify_status",
            &[],
        )
        .await
        .expect("status");
    assert_eq!(status.get::<_, Option<bool>>(0), Some(true));
    assert_eq!(status.get::<_, Option<i64>>(1), Some(now.unix_seconds()));

    // Handled requests are not handled again.
    assert_eq!(
        notify::handle_test_requests(&db.db, &notifiers, true, now)
            .await
            .expect("handling requests"),
        None
    );
    assert_eq!(log.lock().expect("log").len(), 1);

    let readable = everything_the_plugin_can_read(&db).await;
    assert!(!readable.contains(TOPIC), "{readable}");
    assert!(!readable.contains(TOKEN), "{readable}");
}

#[tokio::test]
async fn a_failed_test_says_so_without_the_error_text() {
    // The transport error names the URL, and the URL contains the topic. So the
    // outcome is a word, never the error.
    let Some(db) = common::test_db().await else {
        return;
    };
    let (server, log) = common::fake_ntfy(500).await;
    let notifiers = vec![ntfy(&server)];
    db.execute("INSERT INTO ng_notify_requests (requested_by) VALUES ('jeremy')")
        .await;

    assert_eq!(
        notify::handle_test_requests(&db.db, &notifiers, true, base())
            .await
            .expect("handling requests"),
        Some(TestOutcome::Failed)
    );
    assert_eq!(log.lock().expect("log").len(), 1, "it was attempted");
    assert_eq!(
        db.scalar("SELECT COUNT(*) FROM ng_notify_requests WHERE outcome = 'failed'")
            .await,
        1
    );
    assert_eq!(
        db.scalar("SELECT COUNT(*) FROM ng_notify_status WHERE last_delivery_ok = FALSE")
            .await,
        1
    );
    assert!(!everything_the_plugin_can_read(&db).await.contains(TOPIC));
}

#[tokio::test]
async fn a_test_with_nowhere_to_send_it_is_answered_not_left_waiting() {
    let Some(db) = common::test_db().await else {
        return;
    };
    db.execute("INSERT INTO ng_notify_requests (requested_by) VALUES ('jeremy')")
        .await;
    assert_eq!(
        notify::handle_test_requests(&db.db, &[], true, base())
            .await
            .expect("handling requests"),
        Some(TestOutcome::NotConfigured)
    );
    assert_eq!(
        db.scalar(
            "SELECT COUNT(*) FROM ng_notify_requests
              WHERE outcome = 'not_configured' AND handled_at IS NOT NULL"
        )
        .await,
        1
    );
}

#[tokio::test]
async fn a_delivered_alert_is_recorded_as_the_last_delivery() {
    let Some(db) = common::test_db().await else {
        return;
    };
    notify::record_delivery(&db.db, true, base())
        .await
        .expect("recording a delivery");
    assert_eq!(
        db.maybe_scalar("SELECT last_delivery_at_epoch FROM ng_notify_status")
            .await,
        Some(base().unix_seconds())
    );
    let later = base() + SignedDuration::from_secs(5);
    notify::record_delivery(&db.db, false, later)
        .await
        .expect("recording a delivery");
    assert_eq!(
        db.scalar("SELECT COUNT(*) FROM ng_notify_status WHERE last_delivery_ok = FALSE")
            .await,
        1
    );
    assert_eq!(
        db.maybe_scalar("SELECT last_delivery_at_epoch FROM ng_notify_status")
            .await,
        Some(later.unix_seconds())
    );
}

#[tokio::test]
async fn an_arrival_reaches_ntfy_in_words() {
    // The whole message, as the phone gets it.
    let Some(_db) = common::test_db().await else {
        return;
    };
    let (server, log) = common::fake_ntfy(200).await;
    let notifier = ntfy(&server);
    let event = netgraspd::device::DeviceEvent {
        event_type: netgraspd::types::EventType::PersonArrived,
        mac: "3c:22:fb:00:00:01".parse().expect("mac"),
        display_name: "Jamie".into(),
        vendor: Some("Apple, Inc.".into()),
        ip: Some("192.168.1.40".into()),
        interface: Some("eth0".into()),
        at: base(),
        baseline: false,
        during_learning: false,
        notify: true,
        approved: false,
        priority: netgraspd::types::EventPriority::Normal,
        details: serde_json::json!({
            "person": "Jamie",
            "device": "3c:22:fb:00:00:01",
            "device_name": "Jamie's iPhone",
        }),
    };
    notifier.send(&event).await.expect("delivered");
    let sent = log.lock().expect("log").clone();
    assert_eq!(
        sent[0].title,
        "Jamie is home: Jamie's iPhone joined at 18:42"
    );
}

#[tokio::test]
async fn notify_tables_the_plugin_created_first_do_not_stop_the_daemon_migrating() {
    // The plugin ships a guarded copy of these two tables. A site that upgrades
    // the plugin before the daemon has them already when V4 runs.
    let Some(db) = common::test_db().await else {
        return;
    };
    // Back to a V3 site whose plugin already created V4's tables: V5 to V7 are
    // undone first, because refinery refuses a history with a later version
    // applied and V4 not. V6 created nothing, and runs again harmlessly. V7's
    // columns are left in place on purpose: the plugin's guarded copy may have
    // added them first, and V7 must apply over them.
    db.execute(
        "INSERT INTO ng_notify_requests (requested_by) VALUES ('before the upgrade');
         DROP TABLE IF EXISTS ng_enrichment_status, ng_daemon_status;
         ALTER TABLE ng_events DROP COLUMN IF EXISTS person_item_id;
         ALTER TABLE ng_people DROP COLUMN IF EXISTS last_arrived_at_epoch,
                               DROP COLUMN IF EXISTS last_departed_at_epoch;
         DELETE FROM refinery_schema_history WHERE version >= 4;",
    )
    .await;
    netgraspd::db::Db::migrate(&common::test_url())
        .await
        .expect("V4 applies over tables that already exist");
    assert_eq!(
        db.count("ng_notify_requests").await,
        1,
        "nothing was dropped"
    );
    assert_eq!(
        db.scalar("SELECT COUNT(*) FROM refinery_schema_history WHERE version = 4")
            .await,
        1
    );
    let client = db.client().await;
    netgraspd::db::schema::preflight(&client)
        .await
        .expect("the columns are the daemon's");
}
