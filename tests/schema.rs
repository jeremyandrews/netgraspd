//! The schema contract with the Trovato plugin, asserted against a real
//! Postgres.
//!
//! The plugin lives in another repository, declares these tables with
//! `CREATE TABLE IF NOT EXISTS`, ships a byte-identical copy of the V3 DDL as a
//! fixture, and runs a drift check against it. So a change to `migrations/` that
//! nobody notices here surfaces as a failing test *there*, in a repository whose
//! author has no idea why.
//!
//! This file is the tripwire that makes it fail here first. It asserts the full
//! expected column set and type of every `ng_` table, not just the columns this
//! build happens to read.

mod common;

use std::collections::BTreeSet;

use chrono::{DateTime, TimeZone, Utc};
use netgraspd::db::schema::{self, EXPECTED};

/// The server's message for a database error.
///
/// `tokio_postgres::Error` renders as the bare string "db error"; everything
/// worth asserting on lives in the wrapped `DbError`.
fn db_message(err: &tokio_postgres::Error) -> String {
    err.as_db_error()
        .map_or_else(|| err.to_string(), |db| db.to_string())
}

fn at(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_786_000_000 + secs, 0)
        .single()
        .expect("valid timestamp")
}

#[tokio::test]
async fn every_ng_table_has_exactly_the_columns_the_contract_names() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let client = db.client().await;

    for (table, expected) in EXPECTED {
        let actual = schema::columns_of(&client, table)
            .await
            .unwrap_or_else(|err| panic!("reading {table}: {err}"));
        assert!(!actual.is_empty(), "{table} does not exist");

        let expected_names: BTreeSet<&str> = expected.iter().map(|c| c.name).collect();
        let actual_names: BTreeSet<&str> = actual.keys().map(String::as_str).collect();
        assert_eq!(
            expected_names, actual_names,
            "{table} has a different column set than the contract names"
        );

        for column in *expected {
            let found = &actual[column.name];
            assert_eq!(
                found.data_type, column.data_type,
                "{table}.{} is the wrong type",
                column.name
            );
            assert_eq!(
                found.nullable, column.nullable,
                "{table}.{} has the wrong nullability",
                column.name
            );
        }
    }
}

#[tokio::test]
async fn the_preflight_passes_against_a_freshly_migrated_database() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let client = db.client().await;
    schema::preflight(&client)
        .await
        .expect("a database this build just migrated must satisfy its own preflight");
}

#[tokio::test]
async fn a_divergent_column_type_makes_startup_fail_and_names_the_column() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // The exact failure the plugin's CREATE TABLE IF NOT EXISTS would produce if
    // it declared a column at the wrong width: accepted in silence, and then a
    // broken device page weeks later.
    db.execute("ALTER TABLE ng_devices ALTER COLUMN vendor TYPE VARCHAR(8)")
        .await;

    let client = db.client().await;
    let err = schema::preflight(&client)
        .await
        .expect_err("a divergent type must refuse to start");
    let text = err.to_string();
    assert!(text.contains("ng_devices.vendor"), "{text}");
    assert!(text.contains("expected type text"), "{text}");
    assert!(text.contains("will not start"), "{text}");
    println!("--- operator sees ---\n{text}\n---");

    db.execute("ALTER TABLE ng_devices ALTER COLUMN vendor TYPE TEXT")
        .await;
}

#[tokio::test]
async fn a_divergent_nullability_is_caught_too() {
    let Some(db) = common::test_db().await else {
        return;
    };
    db.execute("ALTER TABLE ng_people ALTER COLUMN name DROP NOT NULL")
        .await;

    let client = db.client().await;
    let err = schema::preflight(&client)
        .await
        .expect_err("a column that lost NOT NULL must refuse to start");
    let text = err.to_string();
    assert!(text.contains("ng_people.name"), "{text}");
    assert!(text.contains("expected NOT NULL"), "{text}");

    db.execute("ALTER TABLE ng_people ALTER COLUMN name SET NOT NULL")
        .await;
}

#[tokio::test]
async fn a_missing_column_is_caught_and_named() {
    let Some(db) = common::test_db().await else {
        return;
    };
    db.execute("ALTER TABLE ng_location_history DROP COLUMN ap_name")
        .await;

    let client = db.client().await;
    let err = schema::preflight(&client)
        .await
        .expect_err("a missing column must refuse to start");
    assert!(
        err.to_string().contains("ng_location_history.ap_name"),
        "{err}"
    );

    db.execute("ALTER TABLE ng_location_history ADD COLUMN ap_name TEXT")
        .await;
}

#[tokio::test]
async fn an_extra_column_is_tolerated_because_a_newer_plugin_may_have_added_one() {
    let Some(db) = common::test_db().await else {
        return;
    };
    db.execute("ALTER TABLE ng_devices ADD COLUMN something_a_newer_plugin_added TEXT")
        .await;

    let client = db.client().await;
    schema::preflight(&client)
        .await
        .expect("a column this build does not read is not a divergence");

    db.execute("ALTER TABLE ng_devices DROP COLUMN something_a_newer_plugin_added")
        .await;
}

#[tokio::test]
async fn a_plugin_first_database_gets_a_message_an_operator_can_act_on() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // Reproduce the case exactly: the plugin's migration created the tables, so
    // ng_devices exists and refinery's history table does not. Without the
    // check, V1 fails with `relation "ng_devices" already exists`, which tells
    // an operator nothing about what to do.
    db.execute("DROP TABLE IF EXISTS refinery_schema_history")
        .await;

    let client = db.client().await;
    let err = schema::check_daemon_migrated_first(&client)
        .await
        .expect_err("a plugin-first database must be refused");
    let text = err.to_string();
    assert!(text.contains("netgraspd did not create them"), "{text}");
    assert!(text.contains("must migrate first"), "{text}");
    assert!(
        text.contains("Nothing was dropped and nothing was changed."),
        "{text}"
    );
    println!("--- operator sees ---\n{text}\n---");

    // And nothing was in fact dropped.
    assert!(
        schema::table_exists(&client, "ng_devices")
            .await
            .expect("table check"),
        "the check must not touch the tables it refuses to adopt"
    );

    // This test removed the migration history on purpose, which would make every
    // test after it in this binary skip rather than run.
    drop(client);
    common::rebuild_schema(&db).await;
}

#[tokio::test]
async fn an_ordinary_restart_is_not_mistaken_for_a_plugin_first_database() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let client = db.client().await;
    schema::check_daemon_migrated_first(&client)
        .await
        .expect("a database this daemon migrated is fine to migrate again");
}

#[tokio::test]
async fn an_empty_database_passes_the_plugin_first_check() {
    let Some(db) = common::test_db().await else {
        return;
    };
    db.execute(
        "DROP TABLE IF EXISTS ng_people, ng_location_history, ng_ip_history, ng_events,
                              ng_presence, ng_device_signals, ng_devices,
                              refinery_schema_history CASCADE",
    )
    .await;

    {
        let client = db.client().await;
        schema::check_daemon_migrated_first(&client)
            .await
            .expect("nothing to conflict with");
    }

    // Put the schema back for whatever runs next in this binary.
    common::rebuild_schema(&db).await;
}

#[tokio::test]
async fn every_epoch_column_matches_its_timestamp_is_null_when_it_is_and_cannot_be_written() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // The kernel's db host function decodes INT8 and returns null for a
    // timestamptz, so these twins are the only way the plugin sees a time at
    // all. Three properties matter: they agree, they carry null through, and
    // nothing can write one out of step with its source.
    let device_id = db.seed_device("3c:22:fb:00:00:01", "online").await;

    let client = db.client().await;
    client
        .execute(
            "UPDATE ng_devices SET first_seen_at = $1, last_seen_at = $2 WHERE id = $3",
            &[&at(0), &at(3600), &device_id],
        )
        .await
        .expect("setting timestamps");

    client
        .execute(
            "INSERT INTO ng_presence (device_id, started_at, ended_at) VALUES ($1, $2, $3)",
            &[&device_id, &at(10), &at(20)],
        )
        .await
        .expect("a closed presence session");
    client
        .execute(
            "INSERT INTO ng_presence (device_id, started_at) VALUES ($1, $2)",
            &[&device_id, &at(30)],
        )
        .await
        .expect("an open presence session");
    client
        .execute(
            "INSERT INTO ng_events (device_id, event_type, \"timestamp\") VALUES ($1, 'x', $2)",
            &[&device_id, &at(40)],
        )
        .await
        .expect("an event");
    client
        .execute(
            "INSERT INTO ng_ip_history (device_id, ip, first_seen, last_seen)
             VALUES ($1, '192.168.1.40', $2, $3)",
            &[&device_id, &at(50), &at(60)],
        )
        .await
        .expect("an address");
    client
        .execute(
            "INSERT INTO ng_location_history (device_id, location, started_at, ended_at)
             VALUES ($1, 'Kitchen', $2, $3)",
            &[&device_id, &at(70), &at(80)],
        )
        .await
        .expect("a closed stay");
    client
        .execute(
            "INSERT INTO ng_location_history (device_id, location, started_at)
             VALUES ($1, 'Backyard', $2)",
            &[&device_id, &at(90)],
        )
        .await
        .expect("an open stay");

    // Every epoch column equals the epoch of its source, everywhere.
    for (table, source, epoch) in [
        ("ng_devices", "first_seen_at", "first_seen_at_epoch"),
        ("ng_devices", "last_seen_at", "last_seen_at_epoch"),
        ("ng_presence", "started_at", "started_at_epoch"),
        ("ng_presence", "ended_at", "ended_at_epoch"),
        ("ng_events", "\"timestamp\"", "timestamp_epoch"),
        ("ng_ip_history", "first_seen", "first_seen_epoch"),
        ("ng_ip_history", "last_seen", "last_seen_epoch"),
        ("ng_location_history", "started_at", "started_at_epoch"),
        ("ng_location_history", "ended_at", "ended_at_epoch"),
    ] {
        let disagreements = db
            .scalar(&format!(
                "SELECT COUNT(*) FROM {table}
                  WHERE {source} IS NOT NULL
                    AND {epoch} IS DISTINCT FROM EXTRACT(EPOCH FROM {source})::bigint"
            ))
            .await;
        assert_eq!(disagreements, 0, "{table}.{epoch} disagrees with {source}");

        let null_mismatches = db
            .scalar(&format!(
                "SELECT COUNT(*) FROM {table}
                  WHERE ({source} IS NULL) <> ({epoch} IS NULL)"
            ))
            .await;
        assert_eq!(
            null_mismatches, 0,
            "{table}.{epoch} does not carry null through from {source}"
        );
    }

    // A specific value, so the test would catch a timezone applied twice rather
    // than only an internally consistent mistake.
    assert_eq!(
        db.scalar(&format!(
            "SELECT first_seen_at_epoch FROM ng_devices WHERE id = {device_id}"
        ))
        .await,
        at(0).timestamp(),
    );

    // An open session's ended_at is null, and so is its twin.
    assert_eq!(
        db.maybe_scalar("SELECT ended_at_epoch FROM ng_presence WHERE ended_at IS NULL LIMIT 1")
            .await,
        None
    );

    // And nothing can write one directly: they are GENERATED ALWAYS ... STORED,
    // which is what makes the timestamptz column the canonical one.
    let err = client
        .execute(
            "UPDATE ng_devices SET first_seen_at_epoch = 1 WHERE id = $1",
            &[&device_id],
        )
        .await
        .expect_err("a generated column must refuse a direct write");
    let message = db_message(&err);
    assert!(
        message.contains("generated column") || message.contains("can only be updated"),
        "{message}"
    );
}

#[tokio::test]
async fn the_item_join_columns_are_uuids_that_accept_a_uuid_and_refuse_a_bigint() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // The reason for the one destructive ALTER in the series: the kernel's
    // item.id is a UUID, and the V1 stub was a BIGINT.
    let device_id = db.seed_device("3c:22:fb:00:00:02", "online").await;
    let client = db.client().await;

    client
        .execute(
            "UPDATE ng_devices
                SET trovato_item_id = gen_random_uuid(), owner_item_id = gen_random_uuid()
              WHERE id = $1",
            &[&device_id],
        )
        .await
        .expect("both columns take a UUID");

    let err = client
        .execute(
            "UPDATE ng_devices SET trovato_item_id = 42 WHERE id = $1",
            &[&device_id],
        )
        .await
        .expect_err("a bigint is not a UUID any more");
    let message = db_message(&err);
    assert!(message.contains("uuid"), "{message}");
}

#[tokio::test]
async fn a_device_may_name_an_owner_whose_person_row_does_not_exist_yet() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // Deliberately no foreign key between ng_devices.owner_item_id and
    // ng_people.item_id: the plugin fills the column and mirrors the person on
    // separate cron passes, so this intermediate state is normal.
    let device_id = db.seed_device("3c:22:fb:00:00:03", "online").await;
    let client = db.client().await;
    client
        .execute(
            "UPDATE ng_devices SET owner_item_id = gen_random_uuid() WHERE id = $1",
            &[&device_id],
        )
        .await
        .expect("an owner with no person row is accepted");
    assert_eq!(db.count("ng_people").await, 0);
}

#[tokio::test]
async fn at_most_one_location_stay_is_open_per_device() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let device_id = db.seed_device("3c:22:fb:00:00:04", "online").await;
    let client = db.client().await;

    client
        .execute(
            "INSERT INTO ng_location_history (device_id, location, started_at)
             VALUES ($1, 'Kitchen', $2)",
            &[&device_id, &at(0)],
        )
        .await
        .expect("the first open stay");

    let err = client
        .execute(
            "INSERT INTO ng_location_history (device_id, location, started_at)
             VALUES ($1, 'Backyard', $2)",
            &[&device_id, &at(10)],
        )
        .await
        .expect_err("a second open stay must be refused");
    assert_eq!(
        err.as_db_error()
            .and_then(tokio_postgres::error::DbError::constraint),
        Some("ng_location_history_open_idx"),
        "{}",
        db_message(&err)
    );

    // A summary row is exempt, which is what lets the rollup write one while a
    // stay is open.
    client
        .execute(
            "INSERT INTO ng_location_history (device_id, location, started_at, is_summary)
             VALUES ($1, 'Kitchen', $2, TRUE)",
            &[&device_id, &at(-86_400)],
        )
        .await
        .expect("a summary is not an open stay");
}
