//! The nightly jobs, against a real Postgres.
//!
//! The claim these exist to support is "it runs unattended for months on a Pi".
//! That claim is only worth as much as the evidence for it, so
//! [`six_months_of_synthetic_history_rolls_up_without_losing_anything`] seeds a
//! six-month dataset, rolls it up, and asserts what survived.
//!
//! Assertions are written as invariants rather than as row counts wherever
//! possible. A count is a number somebody has to keep in step with the fixture;
//! "no observation was lost" and "no open session was compacted" are the
//! properties that actually matter, and they stay true when the fixture changes.

mod common;

use std::time::Instant;

use chrono::{DateTime, TimeZone, Utc};
use netgraspd::config::MaintenanceConfig;
use netgraspd::maintenance;

/// Devices in the synthetic dataset.
const DEVICES: i32 = 20;

/// Days of history.
const DAYS: i32 = 180;

/// Presence sessions per device per day.
const SESSIONS_PER_DAY: i32 = 4;

/// Location stays per device per day.
const STAYS_PER_DAY: i32 = 6;

/// Events per device per day.
const EVENTS_PER_DAY: i32 = 3;

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 14, 17, 0, 0)
        .single()
        .expect("valid time")
}

fn config() -> MaintenanceConfig {
    MaintenanceConfig {
        enabled: true,
        rollup_after_days: 30,
        event_retention_days: 90,
        vacuum_after_rollup: true,
        ..MaintenanceConfig::default()
    }
}

/// Seeds devices, presence sessions, location stays, addresses and events
/// spread over [`DAYS`] days ending at `now`.
///
/// Written as set-based SQL rather than a loop of inserts because six months of
/// history is a hundred thousand rows and a round trip each would make the test
/// take minutes.
async fn seed(db: &common::TestDb, end: DateTime<Utc>) {
    let client = db.client().await;

    client
        .execute(
            "INSERT INTO ng_devices (mac, state, first_seen_at, last_seen_at)
             SELECT format('02:00:00:00:%s:%s',
                           lpad(to_hex(g / 256), 2, '0'), lpad(to_hex(g % 256), 2, '0')),
                    CASE WHEN g % 4 = 0 THEN 'offline' ELSE 'online' END,
                    $1::timestamptz - make_interval(days => $2::int),
                    $1::timestamptz
               FROM generate_series(0, $3::int - 1) g",
            &[&end, &DAYS, &DEVICES],
        )
        .await
        .expect("seeding devices");

    // Closed presence sessions, SESSIONS_PER_DAY per device per day.
    client
        .execute(
            "INSERT INTO ng_presence
                 (device_id, interface, ip, started_at, ended_at, observation_count)
             SELECT d.id, 'eth0', '192.168.1.40',
                    $1::timestamptz - make_interval(days => day)
                        + make_interval(hours => slot * 5),
                    $1::timestamptz - make_interval(days => day)
                        + make_interval(hours => slot * 5, mins => 90),
                    10 + slot
               FROM ng_devices d,
                    generate_series(0, $2::int - 1) day,
                    generate_series(0, $3::int - 1) slot",
            &[&end, &DAYS, &SESSIONS_PER_DAY],
        )
        .await
        .expect("seeding presence");

    // One open session per online device, started today. The rollup must not
    // touch either the open-ness or the day.
    client
        .execute(
            "INSERT INTO ng_presence (device_id, interface, started_at, observation_count)
             SELECT id, 'eth0', $1::timestamptz - interval '30 minutes', 7
               FROM ng_devices WHERE state <> 'offline'",
            &[&end],
        )
        .await
        .expect("seeding open sessions");

    client
        .execute(
            "INSERT INTO ng_location_history
                 (device_id, ap_name, location, started_at, ended_at)
             SELECT d.id,
                    (ARRAY['Driveway AP','Kitchen AP','Living Room AP'])[1 + slot % 3],
                    (ARRAY['Driveway','Kitchen','Living Room'])[1 + slot % 3],
                    $1::timestamptz - make_interval(days => day)
                        + make_interval(hours => slot * 3),
                    $1::timestamptz - make_interval(days => day)
                        + make_interval(hours => slot * 3, mins => 45)
               FROM ng_devices d,
                    generate_series(0, $2::int - 1) day,
                    generate_series(0, $3::int - 1) slot",
            &[&end, &DAYS, &STAYS_PER_DAY],
        )
        .await
        .expect("seeding location history");

    client
        .execute(
            "INSERT INTO ng_events (device_id, event_type, \"timestamp\", details)
             SELECT d.id,
                    (ARRAY['new_device','returned','went_offline'])[1 + slot % 3],
                    $1::timestamptz - make_interval(days => day)
                        + make_interval(hours => slot * 7),
                    '{}'::jsonb
               FROM ng_devices d,
                    generate_series(0, $2::int - 1) day,
                    generate_series(0, $3::int - 1) slot",
            &[&end, &DAYS, &EVENTS_PER_DAY],
        )
        .await
        .expect("seeding events");

    client
        .execute(
            "INSERT INTO ng_ip_history (device_id, ip, interface, first_seen, last_seen)
             SELECT id, '192.168.1.40', 'eth0',
                    $1::timestamptz - make_interval(days => $2::int), $1::timestamptz
               FROM ng_devices",
            &[&end, &DAYS],
        )
        .await
        .expect("seeding addresses");
}

/// Total bytes across every `ng_` table.
async fn total_bytes(db: &common::TestDb) -> i64 {
    db.scalar(
        "SELECT COALESCE(SUM(pg_total_relation_size(c.oid)), 0)::bigint
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE c.relkind = 'r' AND n.nspname = current_schema()
            AND c.relname LIKE 'ng\\_%'",
    )
    .await
}

#[tokio::test]
async fn six_months_of_synthetic_history_rolls_up_without_losing_anything() {
    let Some(db) = common::test_db().await else {
        return;
    };
    seed(&db, now()).await;

    let before = Counts::read(&db).await;
    let bytes_before = total_bytes(&db).await;
    println!("--- six-month rollup ---");
    println!("before: {before:#?}");
    println!("before: {bytes_before} bytes across the ng_ tables");

    let started = Instant::now();
    let report = {
        let client = db.client().await;
        maintenance::run(&client, &config(), now())
            .await
            .expect("maintenance")
    };
    let wall = started.elapsed();

    let after = Counts::read(&db).await;
    let bytes_after = total_bytes(&db).await;
    println!("after:  {after:#?}");
    println!("after:  {bytes_after} bytes across the ng_ tables");
    println!("report: {}", report.summary());
    println!("wall clock: {:.2}s", wall.as_secs_f64());

    // The honest disk story. A plain VACUUM returns space to the table's free
    // space map, not to the filesystem, and the summary rows this run inserted
    // are new pages, so total_relation_size can legitimately *grow* across a
    // rollup and then stay flat forever after. What a Pi actually cares about is
    // the steady state, so measure what the data now occupies when packed.
    db.execute("VACUUM FULL ng_presence").await;
    db.execute("VACUUM FULL ng_location_history").await;
    db.execute("VACUUM FULL ng_events").await;
    let bytes_packed = total_bytes(&db).await;
    println!(
        "packed: {bytes_packed} bytes (a plain VACUUM reclaims to the free space map, \
         not to the filesystem; this is what the surviving data occupies)"
    );
    println!("--- end rollup ---");
    assert!(
        bytes_packed < bytes_before,
        "the rollup must leave less data than it started with: \
         {bytes_packed} packed vs {bytes_before} before"
    );

    // It did something, and said so accurately.
    assert!(report.presence_compacted > 0, "{report:?}");
    assert!(report.location_compacted > 0, "{report:?}");
    assert!(report.events_pruned > 0, "{report:?}");
    assert!(report.vacuumed, "a run that moved rows should vacuum");
    assert_eq!(
        before.presence - after.presence,
        i64::try_from(report.presence_compacted).expect("fits")
            - i64::try_from(report.presence_summaries).expect("fits"),
        "the report's numbers must match what the table actually lost"
    );
    assert_eq!(
        before.events - after.events,
        i64::try_from(report.events_pruned).expect("fits")
    );

    // Nothing was lost. This is the invariant that matters: a summary row
    // carries the observation counts of every session it replaced.
    assert_eq!(
        before.observation_total, after.observation_total,
        "the rollup dropped observations on the floor"
    );

    // No open session was compacted, and none was closed.
    assert_eq!(
        before.open_presence, after.open_presence,
        "an open session was compacted"
    );
    assert!(after.open_presence > 0, "the fixture had open sessions");
    assert_eq!(
        after.summary_open, 0,
        "a summary row must never be open: it is a closed day, not a session"
    );

    // The current day was not touched.
    assert_eq!(
        before.presence_today, after.presence_today,
        "the rollup reached into today"
    );

    // Referential integrity survived.
    assert_eq!(
        db.scalar(
            "SELECT COUNT(*) FROM ng_presence p
              WHERE NOT EXISTS (SELECT 1 FROM ng_devices d WHERE d.id = p.device_id)"
        )
        .await,
        0,
        "an orphan presence row"
    );
    assert_eq!(
        db.scalar(
            "SELECT COUNT(*) FROM ng_location_history l
              WHERE NOT EXISTS (SELECT 1 FROM ng_devices d WHERE d.id = l.device_id)"
        )
        .await,
        0,
        "an orphan location row"
    );

    // Nothing older than the retention window survived, and nothing inside it
    // was deleted.
    let events_cutoff = maintenance::cutoff(now(), config().event_retention_days);
    assert_eq!(
        db.scalar(&format!(
            "SELECT COUNT(*) FROM ng_events WHERE \"timestamp\" < '{}'",
            events_cutoff.format("%Y-%m-%d %H:%M:%S%:z")
        ))
        .await,
        0
    );
    assert!(after.events > 0, "the retention window kept recent events");

    // Summaries are one per device per day, so no day is represented twice.
    assert_eq!(
        db.scalar(
            "SELECT COUNT(*) FROM (
                 SELECT device_id, (started_at AT TIME ZONE 'UTC')::date
                   FROM ng_presence WHERE is_summary
                  GROUP BY 1, 2 HAVING COUNT(*) > 1) dupes"
        )
        .await,
        0,
        "a device has two presence summaries for one day"
    );
    // Location summaries are one per device per location per day, because
    // merging across locations would record a stay somewhere in between.
    assert_eq!(
        db.scalar(
            "SELECT COUNT(*) FROM (
                 SELECT device_id, location, (started_at AT TIME ZONE 'UTC')::date
                   FROM ng_location_history WHERE is_summary
                  GROUP BY 1, 2, 3 HAVING COUNT(*) > 1) dupes"
        )
        .await,
        0,
        "a device has two location summaries for one location and day"
    );
}

#[tokio::test]
async fn a_second_run_over_a_rolled_up_database_is_quiet() {
    let Some(db) = common::test_db().await else {
        return;
    };
    seed(&db, now()).await;
    let client = db.client().await;
    let first = maintenance::run(&client, &config(), now())
        .await
        .expect("first run");
    assert!(!first.is_quiet());

    let second = maintenance::run(&client, &config(), now())
        .await
        .expect("second run");
    assert!(
        second.is_quiet(),
        "a rolled-up database has nothing left to do: {second:?}"
    );
    assert!(
        !second.vacuumed,
        "a vacuum that reclaims nothing is pure I/O on a memory card"
    );
}

#[tokio::test]
async fn an_open_session_older_than_the_cutoff_is_still_never_compacted() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // A device that has been continuously online for a year: its session is
    // older than any cutoff and must survive every one of them, because it is
    // the device's current presence and there is no end to summarise.
    let device_id = db.seed_device("02:00:00:00:ff:01", "online").await;
    let client = db.client().await;
    client
        .execute(
            "INSERT INTO ng_presence (device_id, started_at, observation_count)
             VALUES ($1, $2::timestamptz - interval '365 days', 99)",
            &[&device_id, &now()],
        )
        .await
        .expect("a year-old open session");

    let report = maintenance::run(&client, &config(), now())
        .await
        .expect("maintenance");
    assert_eq!(report.presence_compacted, 0, "{report:?}");
    assert_eq!(
        db.scalar("SELECT COUNT(*) FROM ng_presence WHERE ended_at IS NULL")
            .await,
        1
    );
    assert_eq!(
        db.scalar("SELECT observation_count FROM ng_presence WHERE ended_at IS NULL")
            .await,
        99
    );
}

#[tokio::test]
async fn an_open_location_stay_survives_a_rollup_of_the_closed_ones_around_it() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let device_id = db.seed_device("02:00:00:00:ff:02", "online").await;
    let client = db.client().await;
    client
        .execute(
            "INSERT INTO ng_location_history (device_id, location, started_at, ended_at)
             VALUES ($1, 'Kitchen',
                     $2::timestamptz - interval '100 days',
                     $2::timestamptz - interval '100 days' + interval '1 hour')",
            &[&device_id, &now()],
        )
        .await
        .expect("an old closed stay");
    client
        .execute(
            "INSERT INTO ng_location_history (device_id, location, started_at)
             VALUES ($1, 'Backyard', $2::timestamptz - interval '200 days')",
            &[&device_id, &now()],
        )
        .await
        .expect("an ancient open stay");

    let report = maintenance::run(&client, &config(), now())
        .await
        .expect("maintenance");
    assert_eq!(report.location_compacted, 1);
    assert_eq!(
        db.scalar(
            "SELECT COUNT(*) FROM ng_location_history
              WHERE ended_at IS NULL AND is_summary = FALSE"
        )
        .await,
        1,
        "the open stay is untouched, and the unique index still holds"
    );
}

#[tokio::test]
async fn the_address_merge_is_a_structural_no_op_and_says_so() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // ng_ip_history carries UNIQUE (device_id, ip), so a second row for one pair
    // cannot exist and there is never anything to merge. The job runs anyway as
    // a safety net; this pins that it reports zero rather than quietly doing
    // something surprising.
    let device_id = db.seed_device("02:00:00:00:ff:03", "online").await;
    let client = db.client().await;
    client
        .execute(
            "INSERT INTO ng_ip_history (device_id, ip, first_seen, last_seen)
             VALUES ($1, '192.168.1.40', $2, $2)",
            &[&device_id, &now()],
        )
        .await
        .expect("one address");
    let err = client
        .execute(
            "INSERT INTO ng_ip_history (device_id, ip, first_seen, last_seen)
             VALUES ($1, '192.168.1.40', $2, $2)",
            &[&device_id, &now()],
        )
        .await
        .expect_err("a duplicate is impossible by construction");
    // tokio_postgres::Error renders as "db error"; the constraint name lives in
    // the wrapped DbError.
    assert_eq!(
        err.as_db_error()
            .and_then(tokio_postgres::error::DbError::constraint),
        Some("ng_ip_history_device_id_ip_key"),
        "{err:?}"
    );

    assert_eq!(
        maintenance::merge_ip_history(&client).await.expect("merge"),
        0
    );
    assert_eq!(db.count("ng_ip_history").await, 1);
}

#[tokio::test]
async fn the_vacuum_covers_every_ng_table_without_erroring() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // VACUUM cannot run inside a transaction block, and several statements in
    // one simple-query message form one. This asserts the one-per-call shape
    // actually works rather than only looking right.
    let client = db.client().await;
    maintenance::vacuum(&client).await.expect("vacuum");
}

/// The counts every rollup assertion is written against.
#[derive(Debug, PartialEq, Eq)]
struct Counts {
    presence: i64,
    presence_summaries: i64,
    open_presence: i64,
    summary_open: i64,
    presence_today: i64,
    observation_total: i64,
    location: i64,
    location_summaries: i64,
    events: i64,
}

impl Counts {
    async fn read(db: &common::TestDb) -> Self {
        Counts {
            presence: db.count("ng_presence").await,
            presence_summaries: db
                .scalar("SELECT COUNT(*) FROM ng_presence WHERE is_summary")
                .await,
            open_presence: db
                .scalar(
                    "SELECT COUNT(*) FROM ng_presence
                      WHERE ended_at IS NULL AND is_summary = FALSE",
                )
                .await,
            summary_open: db
                .scalar("SELECT COUNT(*) FROM ng_presence WHERE is_summary AND ended_at IS NULL")
                .await,
            presence_today: db
                .scalar(&format!(
                    "SELECT COUNT(*) FROM ng_presence WHERE started_at >= '{}'",
                    maintenance::cutoff(now(), 0).format("%Y-%m-%d %H:%M:%S%:z")
                ))
                .await,
            observation_total: db
                .scalar("SELECT COALESCE(SUM(observation_count), 0)::bigint FROM ng_presence")
                .await,
            location: db.count("ng_location_history").await,
            location_summaries: db
                .scalar("SELECT COUNT(*) FROM ng_location_history WHERE is_summary")
                .await,
            events: db.count("ng_events").await,
        }
    }
}
