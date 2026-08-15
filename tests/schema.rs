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
use netgraspd::cli::DevicesArgs;
use netgraspd::config::Config;
use netgraspd::db::Db;
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

/// Pulls the table list out of the `DROP TABLE` the reconcile message suggests.
fn drop_list(message: &str) -> Vec<String> {
    let (_, after) = message
        .split_once("DROP TABLE IF EXISTS ")
        .unwrap_or_else(|| panic!("the message suggests no DROP:\n{message}"));
    after
        .split_once(" CASCADE;")
        .unwrap_or_else(|| panic!("the DROP is not terminated:\n{message}"))
        .0
        .split(", ")
        .map(str::to_string)
        .collect()
}

#[tokio::test]
async fn the_existence_check_does_not_depend_on_the_connecting_role() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // The bug in one sentence: `information_schema.tables` lists only what the
    // *connecting role* holds a privilege on, so when the plugin creates the
    // ng_ tables as one role and the daemon connects as another, the daemon is
    // told they are not there, waves its own migration through, and refinery
    // dies with `relation "ng_devices" already exists` — the exact error the
    // guard exists to prevent.
    //
    // The plugin-first test above cannot catch this: it drops the history table
    // from a database the daemon itself built, so both share one owner and the
    // role-visibility path is never walked.
    const PROBE: &str = "ng_probe_daemon";
    const PROBE_PASSWORD: &str = "probe";
    // A schema of its own, standing in for the plugin's database: tables one
    // role created, no privileges on them for the other, and no refinery
    // history because the plugin never writes one.
    const PLUGIN_SCHEMA: &str = "ng_plugin_first";

    {
        let owner = db.client().await;
        if let Err(err) = owner
            .batch_execute(&format!(
                "{}
                 CREATE ROLE {PROBE} LOGIN PASSWORD '{PROBE_PASSWORD}';
                 CREATE SCHEMA {PLUGIN_SCHEMA};
                 -- USAGE and nothing else: the daemon's role can reach into the
                 -- schema and cannot touch a single table in it, which is what
                 -- makes information_schema deny they are there.
                 GRANT USAGE ON SCHEMA {PLUGIN_SCHEMA} TO {PROBE};
                 CREATE TABLE {PLUGIN_SCHEMA}.ng_devices (
                     id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                     mac TEXT NOT NULL,
                     vendor TEXT);
                 CREATE TABLE {PLUGIN_SCHEMA}.ng_state (
                     key TEXT PRIMARY KEY,
                     value TEXT)",
                teardown_probe_sql(PROBE, PLUGIN_SCHEMA)
            ))
            .await
        {
            // Not a silent pass: the reason is printed, and CI's guard treats a
            // skip as a failure, so the coverage cannot be quietly lost there.
            eprintln!(
                "skipping: this test's Postgres role cannot create a role and a schema, so \
                 the cross-role visibility path cannot be exercised ({})",
                db_message(&err)
            );
            return;
        }
    }

    let probe_cfg = netgraspd::config::DatabaseConfig {
        url: common::test_url_as_role(PROBE, PROBE_PASSWORD),
        pool_size: 1,
    };
    let probe_db = Db::connect(&probe_cfg).expect("a valid probe connection URL");
    let probe = match probe_db.client().await {
        Ok(client) => client,
        Err(err) => {
            eprintln!(
                "skipping: the daemon's role cannot connect to {}, so the cross-role \
                 visibility path cannot be exercised ({err})",
                probe_cfg.url
            );
            drop(probe_db);
            cleanup_probe(&db, PROBE, PLUGIN_SCHEMA).await;
            return;
        }
    };
    probe
        .batch_execute(&format!("SET search_path = {PLUGIN_SCHEMA}"))
        .await
        .expect("pointing the daemon's role at the plugin's schema");

    // The premise, asserted rather than assumed: to this role information_schema
    // really does deny the table is there. If that ever stops holding, every
    // assertion below stops proving anything.
    let hidden: bool = probe
        .query_one(
            "SELECT NOT EXISTS (
                 SELECT 1 FROM information_schema.tables
                  WHERE table_schema = current_schema() AND table_name = 'ng_devices')",
            &[],
        )
        .await
        .expect("querying information_schema")
        .get(0);
    assert!(
        hidden,
        "the daemon's role can see ng_devices in information_schema, so it holds a \
         privilege somewhere and this test proves nothing"
    );

    // What the daemon asks instead, and the true answer.
    assert!(
        schema::table_exists(&probe, "ng_devices")
            .await
            .expect("the existence check"),
        "a table another role owns is still a table"
    );
    assert!(
        !schema::table_exists(&probe, "ng_not_a_table_anybody_made")
            .await
            .expect("the existence check"),
        "and one that is not there is still not there"
    );

    // The column reader has the same disease and the same cure: it used to read
    // information_schema.columns, which would report every column of this table
    // missing and make the preflight lie about which divergence it found.
    let columns = schema::columns_of(&probe, "ng_devices")
        .await
        .expect("reading the columns");
    assert_eq!(
        columns
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<&str>>(),
        BTreeSet::from(["id", "mac", "vendor"]),
        "a column's type is a property of the table, not of the reader"
    );
    assert!(!columns["mac"].nullable, "NOT NULL survived the round trip");

    // And the consequence the whole guard exists for: this is refused, loudly,
    // instead of being waved through into `relation "ng_devices" already exists`.
    let err = schema::check_daemon_migrated_first(&probe)
        .await
        .expect_err("a schema another role built must be refused");
    let text = err.to_string();
    assert!(text.contains("netgraspd did not create them"), "{text}");
    let named: BTreeSet<String> = drop_list(&text).into_iter().collect();
    assert!(named.contains("ng_devices"), "{named:?}");
    assert!(named.contains("ng_state"), "{named:?}");
    println!("--- operator sees ---\n{text}\n---");

    drop(probe);
    drop(probe_db);
    cleanup_probe(&db, PROBE, PLUGIN_SCHEMA).await;
}

/// Removes the second role and its schema, whatever state a previous run left.
///
/// Order matters and cost a run once: a role cannot be dropped while a schema
/// still grants to it, and `DROP OWNED BY` is what clears the grants. Getting it
/// wrong does not fail the test, it makes the test *skip* on every run after the
/// first, which is a green tick that proves nothing.
fn teardown_probe_sql(role: &str, schema_name: &str) -> String {
    format!(
        "DROP SCHEMA IF EXISTS {schema_name} CASCADE;
         DO $$ BEGIN
             IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                 BEGIN
                     EXECUTE 'DROP OWNED BY {role}';
                 EXCEPTION WHEN insufficient_privilege THEN
                     -- Dropping the schema above already removed the only grant
                     -- this role is ever given. This is belt and braces for a
                     -- run that died half way through, and a role with
                     -- CREATEROLE but no membership cannot do it.
                     NULL;
                 END;
             END IF;
         END $$;
         DROP ROLE IF EXISTS {role};"
    )
}

/// Removes the second role and its schema.
async fn cleanup_probe(db: &common::TestDb, role: &str, schema_name: &str) {
    let owner = db.client().await;
    owner
        .batch_execute(&teardown_probe_sql(role, schema_name))
        .await
        .unwrap_or_else(|err| panic!("cleaning up the probe role: {}", db_message(&err)));
}

#[tokio::test]
async fn an_empty_migration_history_is_still_a_plugin_first_database() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // What a failed first attempt leaves behind. refinery creates its history
    // table before it runs V1, and V1 is exactly what fails when the plugin got
    // there first, so the table survives with nothing in it. Treating its mere
    // existence as "the daemon has migrated before" turns a first-contact fault
    // into a permanent one: the guard never fires again on that installation.
    db.execute("DELETE FROM refinery_schema_history").await;

    {
        let client = db.client().await;
        assert!(
            schema::applied_migration_versions(&client)
                .await
                .expect("reading the history")
                .is_empty(),
            "the fixture is wrong: the history is not empty"
        );

        let err = schema::check_daemon_migrated_first(&client)
            .await
            .expect_err("an empty history is not an ordinary restart");
        let text = err.to_string();
        assert!(text.contains("no applied migration recorded"), "{text}");
        assert!(text.contains("must migrate first"), "{text}");
        assert!(
            text.contains("Nothing was dropped and nothing was changed."),
            "{text}"
        );
        println!("--- operator sees ---\n{text}\n---");
    }

    common::rebuild_schema(&db).await;
}

#[tokio::test]
async fn the_reconcile_message_names_every_ng_table_that_is_really_there() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // ng_state is the plugin's own scratch table and no version of this daemon
    // has heard of it, which is precisely why a hand-typed DROP list left it
    // behind. The list is now read from the database, so it cannot.
    db.execute("CREATE TABLE IF NOT EXISTS ng_state (key TEXT PRIMARY KEY, value TEXT)")
        .await;
    db.execute("DELETE FROM refinery_schema_history").await;

    {
        let client = db.client().await;
        let err = schema::check_daemon_migrated_first(&client)
            .await
            .expect_err("a plugin-first database must be refused");
        let text = err.to_string();
        println!("--- operator sees ---\n{text}\n---");

        let named: BTreeSet<String> = drop_list(&text).into_iter().collect();
        let present: BTreeSet<String> = schema::present_ng_tables(&client)
            .await
            .expect("listing ng_ tables")
            .into_iter()
            .collect();
        assert_eq!(
            named, present,
            "the message must name exactly the ng_ tables that are there"
        );
        for (table, _) in EXPECTED {
            assert!(named.contains(*table), "{table} is missing from {named:?}");
        }
        assert!(
            named.contains("ng_state"),
            "a table only the plugin creates is still one the operator has to drop: {named:?}"
        );
    }

    db.execute("DROP TABLE IF EXISTS ng_state").await;
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

/// A configuration pointed at the test database and nothing else.
fn test_config() -> Config {
    Config {
        database: netgraspd::config::DatabaseConfig {
            url: common::test_url(),
            pool_size: 2,
        },
        ..Config::default()
    }
}

#[tokio::test]
async fn a_read_command_against_an_under_migrated_database_names_the_version() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // Exactly what a machine looked like on the test drive: the daemon that
    // built this database shipped V2, this build ships V3, and `stats` answered
    // with `relation "ng_location_history" does not exist`. A read command runs
    // no migration, so nothing had ever checked.
    db.execute("DROP TABLE IF EXISTS ng_location_history, ng_people CASCADE")
        .await;
    db.execute("DELETE FROM refinery_schema_history WHERE version >= 3")
        .await;

    let config = test_config();
    for (name, result) in [
        ("stats", netgraspd::cli::stats(&config).await),
        (
            "devices",
            netgraspd::cli::devices(&config, &DevicesArgs { state: None }).await,
        ),
        ("people", netgraspd::cli::people(&config).await),
    ] {
        let err = result.expect_err("an under-migrated database must be refused");
        let text = format!("{err:#}");
        assert!(text.contains("migrated to V2"), "{name}: {text}");
        assert!(text.contains("through V3"), "{name}: {text}");
        assert!(
            !text.contains("does not exist"),
            "{name} still leaked the raw catalog error: {text}"
        );
        println!("--- {name} operator sees ---\n{text}\n---");
    }

    common::rebuild_schema(&db).await;
}

#[tokio::test]
async fn a_read_command_against_a_diverged_schema_names_the_table_not_the_relation() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // Migrated to the current version, but a table this build reads is gone:
    // the version check cannot catch this one, the preflight has to.
    db.execute("DROP TABLE IF EXISTS ng_location_history CASCADE")
        .await;

    let config = test_config();
    let err = netgraspd::cli::stats(&config)
        .await
        .expect_err("a missing table must be refused");
    let text = format!("{err:#}");
    assert!(text.contains("ng_location_history"), "{text}");
    assert!(text.contains("the table is missing"), "{text}");
    assert!(
        text.contains("The daemon owns this schema"),
        "the message has to say what to do about it: {text}"
    );
    assert!(!text.contains("does not exist"), "{text}");
    println!("--- operator sees ---\n{text}\n---");

    common::rebuild_schema(&db).await;
}

#[tokio::test]
async fn a_read_command_against_an_empty_database_says_to_run_the_daemon_first() {
    let Some(db) = common::test_db().await else {
        return;
    };
    db.execute(
        "DROP TABLE IF EXISTS ng_people, ng_location_history, ng_ip_history, ng_events,
                              ng_presence, ng_device_signals, ng_devices,
                              refinery_schema_history CASCADE",
    )
    .await;

    let err = netgraspd::cli::devices(&test_config(), &DevicesArgs { state: None })
        .await
        .expect_err("an empty database must be refused");
    let text = format!("{err:#}");
    assert!(text.contains("no netgrasp schema"), "{text}");
    assert!(text.contains("netgraspd run"), "{text}");
    assert!(!text.contains("does not exist"), "{text}");
    println!("--- operator sees ---\n{text}\n---");

    common::rebuild_schema(&db).await;
}

#[tokio::test]
async fn a_read_command_against_a_plugin_first_database_gets_the_reconcile_message() {
    let Some(db) = common::test_db().await else {
        return;
    };
    db.execute("DELETE FROM refinery_schema_history").await;

    let err = netgraspd::cli::devices(&test_config(), &DevicesArgs { state: None })
        .await
        .expect_err("a plugin-first database must be refused on the read path too");
    let text = format!("{err:#}");
    assert!(text.contains("netgraspd did not create them"), "{text}");
    assert!(text.contains("DROP TABLE IF EXISTS"), "{text}");

    common::rebuild_schema(&db).await;
}

#[tokio::test]
async fn a_read_command_against_a_healthy_database_is_not_refused() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // The other half of the guard: it must not stand between an operator and a
    // database that is fine. `devices` on an empty-but-migrated table prints
    // "No devices recorded yet" and returns Ok.
    assert_eq!(db.count("ng_devices").await, 0);
    netgraspd::cli::devices(&test_config(), &DevicesArgs { state: None })
        .await
        .expect("a migrated database must be readable");
    netgraspd::cli::stats(&test_config())
        .await
        .expect("and so must stats");
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
