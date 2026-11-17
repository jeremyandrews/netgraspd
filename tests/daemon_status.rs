//! What the daemon publishes about itself for the web side: which time zone a
//! day is measured in, and whether enrichment is configured, working or
//! failing. Plus the one migration in this series that has to carry old rows
//! forward, proven against a database left at the previous release's schema.
//!
//! All of it against a real Postgres, because every assertion here is about
//! what another process will read out of a table.

mod common;

use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use netgraspd::db::Db;
use netgraspd::db::status::{self, DaemonStatus, TimezoneSource};
use netgraspd::device::DeviceSnapshot;
use netgraspd::enrich::{self, Enricher, Enrichment, EnrichmentState, Orchestrator};
use tokio::time::Instant;

fn at(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_786_000_000 + secs, 0)
        .single()
        .expect("valid timestamp")
}

/// An enricher that answers from a script.
struct Scripted {
    name: &'static str,
    answers: std::sync::Mutex<Vec<Result<Vec<Enrichment>, String>>>,
}

impl Scripted {
    fn new(name: &'static str, answers: Vec<Result<Vec<Enrichment>, String>>) -> Self {
        Scripted {
            name,
            answers: std::sync::Mutex::new(answers),
        }
    }
}

#[async_trait]
impl Enricher for Scripted {
    fn name(&self) -> &str {
        self.name
    }

    fn poll_interval(&self) -> Option<Duration> {
        // Due again at once, so a test can poll twice in a row.
        Some(Duration::ZERO)
    }

    async fn enrich(&self, _devices: &[DeviceSnapshot]) -> Result<Vec<Enrichment>> {
        let mut answers = self.answers.lock().expect("answers");
        match answers.remove(0) {
            Ok(found) => Ok(found),
            Err(message) => anyhow::bail!(message),
        }
    }
}

/// One `ng_enrichment_status` row, as the web side would read it.
#[derive(Debug)]
struct Row {
    configured: bool,
    state: String,
    polls: i64,
    failures: i64,
    last_success_at_epoch: Option<i64>,
    last_failure_at_epoch: Option<i64>,
    last_error: Option<String>,
    updated_at_epoch: Option<i64>,
}

async fn enrichment_row(db: &common::TestDb, enricher: &str) -> Option<Row> {
    let client = db.client().await;
    client
        .query_opt(
            "SELECT configured, state, polls, failures, last_success_at_epoch,
                    last_failure_at_epoch, last_error, updated_at_epoch
               FROM ng_enrichment_status WHERE enricher = $1",
            &[&enricher],
        )
        .await
        .expect("reading ng_enrichment_status")
        .map(|r| Row {
            configured: r.get(0),
            state: r.get(1),
            polls: r.get(2),
            failures: r.get(3),
            last_success_at_epoch: r.get(4),
            last_failure_at_epoch: r.get(5),
            last_error: r.get(6),
            updated_at_epoch: r.get(7),
        })
}

#[tokio::test]
async fn an_install_with_no_enrichment_says_so_for_every_enricher() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // The web side's question is "why does this device have no location". With
    // nothing configured the answer is a row that says so, not an absent table.
    let orchestrator = Orchestrator::from_config(&netgraspd::config::EnrichmentConfig::default())
        .expect("an empty orchestrator");
    let statuses = enrich::with_unconfigured(orchestrator.statuses());
    let client = db.client().await;
    status::write_enrichment_status(&client, &statuses, at(0))
        .await
        .expect("writing the status");

    for name in enrich::KNOWN_ENRICHERS {
        let row = enrichment_row(&db, name)
            .await
            .unwrap_or_else(|| panic!("no ng_enrichment_status row for {name}"));
        assert!(!row.configured, "{name}: {row:?}");
        assert_eq!(row.state, "not_configured", "{name}: {row:?}");
        assert_eq!(row.polls, 0);
        assert_eq!(row.updated_at_epoch, Some(at(0).timestamp()));
    }
}

#[tokio::test]
async fn a_failing_enricher_says_it_is_failing_and_why() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let scripted = Scripted::new(
        "unifi",
        vec![
            Ok(Vec::new()),
            Err("controller at 192.168.1.1 refused the connection".into()),
        ],
    );
    let mut orchestrator = Orchestrator::with_enrichers(true, vec![Box::new(scripted)]);
    let client = db.client().await;

    // Configured but not yet asked.
    let statuses = enrich::with_unconfigured(orchestrator.statuses());
    assert_eq!(
        statuses
            .iter()
            .find(|s| s.name == "unifi")
            .expect("unifi")
            .state(),
        EnrichmentState::Starting
    );
    status::write_enrichment_status(&client, &statuses, at(0))
        .await
        .expect("writing the status");
    assert_eq!(
        enrichment_row(&db, "unifi").await.expect("row").state,
        "starting"
    );

    // One good poll.
    let _ = orchestrator.poll_due(Instant::now(), &[]).await;
    status::write_enrichment_status(
        &client,
        &enrich::with_unconfigured(orchestrator.statuses()),
        at(30),
    )
    .await
    .expect("writing the status");
    let row = enrichment_row(&db, "unifi").await.expect("row");
    assert!(row.configured);
    assert_eq!(row.state, "ok", "{row:?}");
    assert_eq!(row.polls, 1);
    assert!(row.last_success_at_epoch.is_some(), "{row:?}");
    assert_eq!(row.last_error, None);

    // Then the controller goes away.
    let _ = orchestrator.poll_due(Instant::now(), &[]).await;
    status::write_enrichment_status(
        &client,
        &enrich::with_unconfigured(orchestrator.statuses()),
        at(60),
    )
    .await
    .expect("writing the status");
    let row = enrichment_row(&db, "unifi").await.expect("row");
    assert_eq!(row.state, "failing", "{row:?}");
    assert_eq!(row.polls, 2);
    assert_eq!(row.failures, 1);
    assert!(row.last_failure_at_epoch.is_some(), "{row:?}");
    assert!(
        row.last_success_at_epoch.is_some(),
        "the last success is kept"
    );
    assert!(
        row.last_error
            .as_deref()
            .is_some_and(|e| e.contains("refused the connection")),
        "{row:?}"
    );
    assert_eq!(row.updated_at_epoch, Some(at(60).timestamp()));

    // Reverse DNS is not configured in this test and says so beside it.
    let rdns = enrichment_row(&db, "reverse_dns").await.expect("row");
    assert_eq!(rdns.state, "not_configured");
    assert_eq!(
        db.count("ng_enrichment_status").await,
        2,
        "one row per enricher"
    );
}

#[tokio::test]
async fn a_configured_time_zone_is_published_and_a_day_is_measured_in_it() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let client = db.client().await;
    let zone = status::resolve_timezone(&client, Some("Europe/Rome"))
        .await
        .expect("a real zone");
    assert_eq!(zone.name, "Europe/Rome");
    assert_eq!(zone.source, TimezoneSource::Config);

    let daemon = DaemonStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        timezone: zone,
        started_at: at(0),
    };
    status::write_daemon_status(&client, &daemon, at(10))
        .await
        .expect("writing the daemon status");
    status::write_daemon_status(&client, &daemon, at(40))
        .await
        .expect("writing it again");
    assert_eq!(db.count("ng_daemon_status").await, 1, "one row, rewritten");
    assert_eq!(
        db.scalar("SELECT updated_at_epoch FROM ng_daemon_status")
            .await,
        at(40).timestamp()
    );
    assert_eq!(
        db.scalar("SELECT started_at_epoch FROM ng_daemon_status")
            .await,
        at(0).timestamp()
    );

    // 23:30 UTC on 17 November is already the 18th in Rome. The web side asks
    // for a day in the published zone and gets the household's day, whatever
    // TimeZone its own session happens to carry.
    let row = client
        .query_one(
            "SELECT to_char(TIMESTAMPTZ '2026-11-17 23:30:00+00' AT TIME ZONE s.timezone, 'YYYY-MM-DD'),
                    s.timezone, s.timezone_source, s.version
               FROM ng_daemon_status s",
            &[],
        )
        .await
        .expect("reading the day");
    let day: String = row.get(0);
    let timezone: String = row.get(1);
    let source: String = row.get(2);
    let version: String = row.get(3);
    assert_eq!(day, "2026-11-18");
    assert_eq!(timezone, "Europe/Rome");
    assert_eq!(source, "config");
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn an_unset_time_zone_publishes_the_database_s_own() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let client = db.client().await;
    let zone = status::resolve_timezone(&client, None)
        .await
        .expect("the database's zone");
    let row = client
        .query_one("SELECT current_setting('TimeZone')", &[])
        .await
        .expect("the session zone");
    let session: String = row.get(0);
    assert_eq!(zone.name, session);
    assert_eq!(zone.source, TimezoneSource::Database);
}

#[tokio::test]
async fn a_time_zone_postgres_does_not_know_is_refused_by_name() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let client = db.client().await;
    let err = status::resolve_timezone(&client, Some("Mars/Olympus_Mons"))
        .await
        .expect_err("not a zone");
    let message = format!("{err:#}");
    assert!(message.contains("Mars/Olympus_Mons"), "{message}");
    assert!(message.contains("timezone"), "{message}");
}

/// A scratch database, migrated to `version` by this build's own migrations.
async fn scratch_database(name: &str, version: u32) -> Option<String> {
    let admin = common::test_url();
    let (client, connection) = tokio_postgres::connect(&admin, tokio_postgres::NoTls)
        .await
        .ok()?;
    tokio::spawn(connection);
    client
        .batch_execute(&format!(
            "DROP DATABASE IF EXISTS {name} WITH (FORCE); CREATE DATABASE {name}"
        ))
        .await
        .expect("creating a scratch database");
    let (base, _) = admin.rsplit_once('/').expect("a URL with a database name");
    let url = format!("{base}/{name}");
    Db::migrate_to(&url, version)
        .await
        .expect("migrating the scratch database");
    Some(url)
}

#[tokio::test]
async fn person_events_recorded_before_the_column_existed_are_backfilled() {
    // Holds the shared lock, so it does not race the other tests, and skips
    // with them when there is no Postgres.
    let Some(_db) = common::test_db().await else {
        return;
    };
    let Some(url) = scratch_database("netgrasp_backfill_test", 3).await else {
        return;
    };
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("the scratch database");
    tokio::spawn(connection);
    // What a v1.0.0 daemon recorded: the person only in details.
    client
        .batch_execute(
            r#"INSERT INTO ng_people (item_id, name, last_arrived_at)
                 VALUES ('11111111-2222-3333-4444-555555555555', 'Jeremy', '2026-11-17 07:30:00+00');
               INSERT INTO ng_events (event_type, "timestamp", details) VALUES
                 ('person_arrived', now(), '{"person":"Jeremy","person_item_id":"11111111-2222-3333-4444-555555555555"}'),
                 ('person_departed', now(), '{"person":"Jeremy","person_item_id":"11111111-2222-3333-4444-555555555555"}'),
                 ('person_location_changed', now(), '{"person":"Jeremy","person_item_id":"11111111-2222-3333-4444-555555555555"}'),
                 ('person_arrived', now(), '{"person":"Ghost","person_item_id":"not-a-uuid"}'),
                 ('new_device', now(), '{"person_item_id":"11111111-2222-3333-4444-555555555555"}');"#,
        )
        .await
        .expect("seeding v3 rows");

    Db::migrate(&url).await.expect("the upgrade applies");

    let count = |sql: &'static str| {
        let client = &client;
        async move {
            let row = client.query_one(sql, &[]).await.expect(sql);
            row.get::<_, i64>(0)
        }
    };
    assert_eq!(
        count(
            "SELECT COUNT(*) FROM ng_events
              WHERE person_item_id = '11111111-2222-3333-4444-555555555555'::uuid"
        )
        .await,
        3,
        "the three person events are backfilled"
    );
    assert_eq!(
        count("SELECT COUNT(*) FROM ng_events WHERE person_item_id IS NULL").await,
        2,
        "a malformed id and a device event are left alone rather than failing the migration"
    );
    assert_eq!(
        count("SELECT last_arrived_at_epoch FROM ng_people").await,
        Utc.with_ymd_and_hms(2026, 11, 17, 7, 30, 0)
            .single()
            .expect("time")
            .timestamp(),
        "the generated twin is filled for rows that existed before it"
    );
    drop(client);

    let (admin, connection) = tokio_postgres::connect(&common::test_url(), tokio_postgres::NoTls)
        .await
        .expect("the admin connection");
    tokio::spawn(connection);
    admin
        .batch_execute("DROP DATABASE IF EXISTS netgrasp_backfill_test WITH (FORCE)")
        .await
        .expect("dropping the scratch database");
}
