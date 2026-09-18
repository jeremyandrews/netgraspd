//! The schema contract, and the two checks that keep it honest.
//!
//! The `ng_*` tables are read by a Trovato plugin that lives in a different
//! repository. The plugin declares them with `CREATE TABLE IF NOT EXISTS`, which
//! means a table that already exists with the wrong types is accepted in silence
//! and the failure surfaces much later as a broken device page. Two checks close
//! that:
//!
//! - [`check_daemon_migrated_first`] runs **before** migrations. If the plugin
//!   created the tables first, refinery's `V1` fails with `relation "ng_devices"
//!   already exists` and the daemon never starts, with a message an operator
//!   cannot act on. This detects that case and says what to do instead.
//! - [`preflight`] runs **after** migrations. It compares every `ng_` table
//!   against [`EXPECTED`] and refuses to start on a divergence, naming the table
//!   and the column.
//! - [`check_readable`] is the read-only half of both, for `devices`, `events`,
//!   `people`, `stats` and `maintain`. Those never migrate, so they cannot rely
//!   on the daemon having run the two checks above, and without this they emit a
//!   bare `relation "ng_location_history" does not exist` at an operator.
//!
//! [`EXPECTED`] is also what the contract test in `tests/schema.rs` asserts, so a
//! future change to the schema breaks this repository's suite rather than the
//! plugin's.
//!
//! **Every catalog lookup here reads `pg_catalog`, never `information_schema`.**
//! The `information_schema` views only list objects the *connecting role* holds
//! a privilege on. When the plugin creates the `ng_` tables as one role and the
//! daemon connects as another, `information_schema` reports them absent, the
//! guards wave the migration through, and refinery dies with the exact raw error
//! they exist to prevent. `pg_catalog` answers what is there, not what this role
//! may touch.

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;

use crate::db::queries::Client;

/// One column, as this build expects to find it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedColumn {
    /// Column name.
    pub name: &'static str,
    /// The type as `pg_catalog.format_type` spells it, for example `timestamp
    /// with time zone`. Deliberately the SQL-standard spelling rather than the
    /// internal `udt_name`, because that is what an operator reading the error
    /// can look up, and it is the spelling `information_schema` reported for
    /// every type named here before the catalog lookups moved off it.
    pub data_type: &'static str,
    /// Whether the column is nullable. A plugin-created table with a nullable
    /// column where the daemon needs `NOT NULL` is exactly the divergence these
    /// checks exist to catch.
    pub nullable: bool,
}

/// Shorthand for a nullable column.
const fn null(name: &'static str, data_type: &'static str) -> ExpectedColumn {
    ExpectedColumn {
        name,
        data_type,
        nullable: true,
    }
}

/// Shorthand for a `NOT NULL` column.
const fn not_null(name: &'static str, data_type: &'static str) -> ExpectedColumn {
    ExpectedColumn {
        name,
        data_type,
        nullable: false,
    }
}

/// The `timestamptz` spelling the catalog reports.
const TS: &str = "timestamp with time zone";

/// Every `ng_` table and every column this build expects in it.
///
/// This is the schema contract with the Trovato plugin, in one place. Changing
/// anything here without changing `migrations/` breaks the preflight; changing
/// both without telling the plugin breaks the plugin's drift test.
pub const EXPECTED: &[(&str, &[ExpectedColumn])] = &[
    (
        "ng_devices",
        &[
            not_null("id", "bigint"),
            not_null("mac", "text"),
            null("display_name", "text"),
            null("notes", "text"),
            not_null("hidden", "boolean"),
            not_null("notify", "boolean"),
            null("resolved_name", "text"),
            null("identity_source", "text"),
            null("identity_confidence", "real"),
            null("hostname", "text"),
            null("mdns_name", "text"),
            null("vendor", "text"),
            null("device_type", "text"),
            null("device_type_confidence", "real"),
            null("os_family", "text"),
            not_null("state", "text"),
            null("last_ip", "text"),
            null("last_ipv6", "text"),
            null("last_interface", "text"),
            not_null("first_seen_at", TS),
            not_null("last_seen_at", TS),
            not_null("baseline", "boolean"),
            null("current_ap", "text"),
            null("current_location", "text"),
            not_null("sync_state", "text"),
            null("trovato_item_id", "uuid"),
            null("owner_item_id", "uuid"),
            null("first_seen_at_epoch", "bigint"),
            null("last_seen_at_epoch", "bigint"),
        ],
    ),
    (
        "ng_device_signals",
        &[
            not_null("id", "bigint"),
            not_null("device_id", "bigint"),
            not_null("signal_type", "text"),
            not_null("value", "text"),
            not_null("first_seen_at", TS),
            not_null("last_seen_at", TS),
        ],
    ),
    (
        "ng_presence",
        &[
            not_null("id", "bigint"),
            not_null("device_id", "bigint"),
            null("interface", "text"),
            null("ip", "text"),
            not_null("started_at", TS),
            null("ended_at", TS),
            not_null("is_summary", "boolean"),
            not_null("observation_count", "bigint"),
            null("started_at_epoch", "bigint"),
            null("ended_at_epoch", "bigint"),
        ],
    ),
    (
        "ng_events",
        &[
            not_null("id", "bigint"),
            null("device_id", "bigint"),
            not_null("event_type", "text"),
            not_null("timestamp", TS),
            not_null("details", "jsonb"),
            not_null("notified", "boolean"),
            not_null("sync_state", "text"),
            null("timestamp_epoch", "bigint"),
        ],
    ),
    (
        "ng_ip_history",
        &[
            not_null("id", "bigint"),
            not_null("device_id", "bigint"),
            not_null("ip", "text"),
            null("interface", "text"),
            not_null("first_seen", TS),
            not_null("last_seen", TS),
            null("first_seen_epoch", "bigint"),
            null("last_seen_epoch", "bigint"),
        ],
    ),
    (
        "ng_location_history",
        &[
            not_null("id", "bigint"),
            not_null("device_id", "bigint"),
            null("ap_name", "text"),
            not_null("location", "text"),
            not_null("started_at", TS),
            null("ended_at", TS),
            not_null("is_summary", "boolean"),
            null("started_at_epoch", "bigint"),
            null("ended_at_epoch", "bigint"),
        ],
    ),
    (
        "ng_people",
        &[
            not_null("item_id", "uuid"),
            not_null("name", "text"),
            null("notes", "text"),
            not_null("notify_arrive", "boolean"),
            not_null("notify_depart", "boolean"),
            not_null("state", "text"),
            null("current_location", "text"),
            null("last_arrived_at", TS),
            null("last_departed_at", TS),
        ],
    ),
];

/// The name refinery records applied migrations under.
///
/// Held as a constant because [`check_daemon_migrated_first`] distinguishes "the
/// daemon built these tables" from "something else did" purely by whether this
/// table exists alongside them.
pub const MIGRATION_TABLE: &str = "refinery_schema_history";

/// One column as the live database actually has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActualColumn {
    /// Column name.
    pub name: String,
    /// `information_schema.columns.data_type`.
    pub data_type: String,
    /// Whether the column is nullable.
    pub nullable: bool,
}

/// Reads one table's columns out of `pg_catalog`.
///
/// Returns an empty map when the table does not exist, which the callers
/// distinguish from an empty table by checking [`table_exists`] first.
///
/// `format_type` is the same spelling `information_schema.columns.data_type`
/// reports for every type in [`EXPECTED`], and it is more specific for the types
/// that are not: a divergent column reads as `character varying(8)` rather than
/// `character varying`, which is more use to whoever has to fix it.
///
/// # Errors
///
/// Returns an error when the query fails.
pub async fn columns_of(client: &Client, table: &str) -> Result<BTreeMap<String, ActualColumn>> {
    let rows = client
        .query(
            "SELECT a.attname AS column_name,
                    pg_catalog.format_type(a.atttypid, a.atttypmod) AS data_type,
                    NOT a.attnotnull AS nullable
               FROM pg_catalog.pg_attribute a
               JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
               JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = current_schema()
                AND c.relname = $1
                AND c.relkind IN ('r', 'p')
                AND a.attnum > 0
                AND NOT a.attisdropped",
            &[&table],
        )
        .await?;
    let mut out = BTreeMap::new();
    for row in &rows {
        let name: String = row.try_get("column_name")?;
        let data_type: String = row.try_get("data_type")?;
        let nullable: bool = row.try_get("nullable")?;
        out.insert(
            name.clone(),
            ActualColumn {
                name,
                data_type,
                nullable,
            },
        );
    }
    Ok(out)
}

/// Whether a table exists in the current schema, whoever owns it.
///
/// `to_regclass` resolves a name against the catalog itself and is indifferent
/// to what the connecting role may do with the result. That indifference is the
/// whole point: the previous `information_schema.tables` query answered "is
/// there a table here I have a privilege on", which is a different question, and
/// answering it wrongly let both guards below wave a foreign schema through.
///
/// # Errors
///
/// Returns an error when the query fails.
pub async fn table_exists(client: &Client, table: &str) -> Result<bool> {
    let row = client
        .query_one(
            // $1 is cast explicitly: format() is variadic "any", so Postgres has
            // nothing to infer the parameter's type from and refuses to plan.
            "SELECT to_regclass(format('%I.%I', current_schema(), $1::text)) IS NOT NULL",
            &[&table],
        )
        .await?;
    Ok(row.try_get(0)?)
}

/// Every `ng_`-prefixed table that exists in the current schema.
///
/// Ordered children first, so the `DROP TABLE` the reconcile message suggests
/// reads sensibly: the tables this build knows about in reverse [`EXPECTED`]
/// order, then anything else `ng_`-prefixed that is there. That last part is
/// what keeps the message honest about a plugin whose table set is not this
/// build's, which is the normal case rather than an exotic one: the plugin
/// creates `ng_state`, which no version of this daemon has ever heard of.
///
/// # Errors
///
/// Returns an error when the query fails.
pub async fn present_ng_tables(client: &Client) -> Result<Vec<String>> {
    let rows = client
        .query(
            r"SELECT c.relname
                FROM pg_catalog.pg_class c
                JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
               WHERE n.nspname = current_schema()
                 AND c.relkind IN ('r', 'p')
                 AND c.relname LIKE 'ng\_%'
               ORDER BY c.relname",
            &[],
        )
        .await?;
    let mut found: Vec<String> = Vec::with_capacity(rows.len());
    for row in &rows {
        found.push(row.try_get(0)?);
    }

    let mut ordered: Vec<String> = EXPECTED
        .iter()
        .rev()
        .map(|(table, _)| (*table).to_string())
        .filter(|table| found.iter().any(|f| f == table))
        .collect();
    ordered.extend(
        found
            .into_iter()
            .filter(|f| !EXPECTED.iter().any(|(table, _)| table == f)),
    );
    Ok(ordered)
}

/// The migration versions refinery records as applied.
///
/// Empty when the history table does not exist **and** when it exists but holds
/// nothing. Those are the same fact for every caller here: this daemon has never
/// finished a migration against this database. They are not the same fact to a
/// naive existence check, which is how a first attempt that failed half way
/// through disarms the plugin-first guard permanently.
///
/// # Errors
///
/// Returns an error when the history table exists but cannot be read.
pub async fn applied_migration_versions(client: &Client) -> Result<Vec<i32>> {
    if !table_exists(client, MIGRATION_TABLE).await? {
        return Ok(Vec::new());
    }
    let rows = client
        .query(
            &format!("SELECT version FROM {MIGRATION_TABLE} WHERE version >= 1 ORDER BY version"),
            &[],
        )
        .await
        .with_context(|| {
            format!(
                "{MIGRATION_TABLE} is there but this role cannot read it, so whether netgraspd \
                 built this schema cannot be established. The daemon owns the ng_ tables and \
                 needs full privileges on them; connect as the role that created them, or grant \
                 this one those privileges."
            )
        })?;
    let mut versions = Vec::with_capacity(rows.len());
    for row in &rows {
        versions.push(row.try_get(0)?);
    }
    Ok(versions)
}

/// Refuses to run migrations against a database the plugin built first.
///
/// The plugin's own migration creates the `ng_` tables with
/// `CREATE TABLE IF NOT EXISTS`. If it ran first, refinery's `V1` fails with
/// `relation "ng_devices" already exists` and the daemon never starts. That is
/// not hypothetical: it reproduces by applying the plugin's migration and then
/// `V1`.
///
/// The tables are neither adopted nor dropped. Adopting them would mean trusting
/// types nobody checked, and dropping them would delete an operator's data to
/// fix a startup message.
///
/// "The daemon has migrated this database before" means refinery recorded an
/// applied migration, not that the history table is sitting there. A first
/// attempt that failed after refinery created the table and before `V1`
/// succeeded leaves it there and empty, and treating that as an ordinary restart
/// disarms this guard for the life of the installation.
///
/// # Errors
///
/// Returns an error naming the situation and what to do about it when `ng_`
/// tables exist that this daemon did not create.
pub async fn check_daemon_migrated_first(client: &Client) -> Result<()> {
    if !table_exists(client, "ng_devices").await? {
        return Ok(());
    }
    if !applied_migration_versions(client).await?.is_empty() {
        // The daemon has applied a migration here before. Ordinary restart.
        return Ok(());
    }
    Err(anyhow::Error::msg(reconcile_message(
        &present_ng_tables(client).await?,
    )))
}

/// The message an operator gets when somebody else built this schema.
///
/// Takes the tables that are actually there rather than naming a set from
/// memory. A hand-typed `DROP TABLE` list drifts twice over: away from this
/// build's own schema, and away from the plugin's, which is not the same set.
/// The plugin creates `ng_state` and does not create `ng_device_signals`, so the
/// list that used to be inlined here named a table the operator did not have and
/// left behind one they did.
#[must_use]
pub fn reconcile_message(present: &[String]) -> String {
    let drop_list = if present.is_empty() {
        // Nothing to enumerate. Cannot happen from the caller above, which only
        // reaches here with ng_devices present, but a message that reads as a
        // syntax error would be worse than one that reads as a note.
        "-- no ng_ tables are present to drop".to_string()
    } else {
        format!("DROP TABLE IF EXISTS {} CASCADE;", present.join(", "))
    };
    format!(
        "this database already has ng_ tables, but netgraspd did not create them: \
         there is no applied migration recorded in {MIGRATION_TABLE}.\n\n\
         The Trovato netgrasp plugin was installed before the daemon ever ran, or a \
         first run failed part way through. The daemon owns this schema and must \
         migrate first, so these tables cannot be adopted as they are.\n\n\
         To reconcile, either:\n  \
         1. point netgraspd at an empty database (recommended: create one, run \
         netgraspd once, then point the plugin at it), or\n  \
         2. if these tables hold nothing worth keeping, drop them and let \
         netgraspd rebuild:\n     \
         {drop_list}\n\n\
         Nothing was dropped and nothing was changed."
    )
}

/// Verifies the live schema matches [`EXPECTED`], and refuses to start if not.
///
/// Extra columns are tolerated and logged: a newer plugin or a later migration
/// may legitimately add one, and this build does not read it. A *missing* column,
/// a wrong type or a wrong nullability is fatal, because every one of those makes
/// a query fail or a value silently arrive as null.
///
/// # Errors
///
/// Returns an error naming every divergence found.
pub async fn preflight(client: &Client) -> Result<()> {
    let problems = schema_problems(client).await?;
    if problems.is_empty() {
        tracing::info!(tables = EXPECTED.len(), "schema preflight passed");
        return Ok(());
    }
    bail!(
        "the database schema does not match what this build of netgraspd expects, \
         so it will not start:\n  {}\n\n\
         This usually means another writer created or altered an ng_ table. The \
         daemon owns this schema; see the README section \"How the Trovato plugin \
         relates\".",
        problems.join("\n  ")
    )
}

/// Every way the live schema diverges from [`EXPECTED`], as sentences.
///
/// Empty means the database is usable. Split out from [`preflight`] because the
/// read-only commands need the same findings under a different sentence: "will
/// not start" is the wrong thing to tell somebody who typed `netgraspd devices`.
///
/// # Errors
///
/// Returns an error when the catalog cannot be read.
pub async fn schema_problems(client: &Client) -> Result<Vec<String>> {
    let mut problems: Vec<String> = Vec::new();

    for (table, expected) in EXPECTED {
        if !table_exists(client, table).await? {
            problems.push(format!("{table}: the table is missing"));
            continue;
        }
        let actual = columns_of(client, table).await?;
        for column in *expected {
            let Some(found) = actual.get(column.name) else {
                problems.push(format!("{table}.{}: the column is missing", column.name));
                continue;
            };
            if found.data_type != column.data_type {
                problems.push(format!(
                    "{table}.{}: expected type {}, found {}",
                    column.name, column.data_type, found.data_type
                ));
            }
            if found.nullable != column.nullable {
                problems.push(format!(
                    "{table}.{}: expected {}, found {}",
                    column.name,
                    if column.nullable {
                        "a nullable column"
                    } else {
                        "NOT NULL"
                    },
                    if found.nullable {
                        "a nullable column"
                    } else {
                        "NOT NULL"
                    },
                ));
            }
        }
        for name in actual.keys() {
            if !expected.iter().any(|c| c.name == name.as_str()) {
                tracing::debug!(
                    table,
                    column = %name,
                    "the database has a column this build does not know about; ignoring it"
                );
            }
        }
    }

    Ok(problems)
}

/// The guard every read-only command runs after connecting.
///
/// `devices`, `events`, `people`, `stats` and `maintain` never migrate, so
/// nothing has run [`check_daemon_migrated_first`] or [`preflight`] for them.
/// Pointed at an empty, an under-migrated or a foreign database they used to
/// query straight away and hand the operator whatever Postgres said, which on a
/// database migrated only as far as `V2` is `relation "ng_location_history" does
/// not exist`. That names a table the operator has never heard of and suggests
/// nothing to do about it.
///
/// `expected_version` is the highest migration this build embeds; see
/// [`crate::db::embedded_max_version`].
///
/// # Errors
///
/// Returns an error naming the situation and what to do about it when the
/// database has no netgrasp schema, has one somebody else built, is migrated
/// short of this build, or diverges from [`EXPECTED`].
pub async fn check_readable(client: &Client, expected_version: i32) -> Result<()> {
    let applied = applied_migration_versions(client).await?;

    if applied.is_empty() {
        // Either the plugin built this schema, or nothing has.
        check_daemon_migrated_first(client).await?;
        bail!(
            "this database has no netgrasp schema: nothing is recorded in \
             {MIGRATION_TABLE}.\n\n\
             netgraspd creates and owns the ng_ tables. Run `netgraspd migrate` against \
             this database to create them; it applies every pending migration, checks \
             the result and exits. Starting the daemon does the same thing on its way \
             up, and docker-compose.yml runs `migrate` as a one-shot service that \
             everything else waits for.\n\n\
             If that is not the database you meant, check which one this command is \
             using: it is logged at startup, and with no netgrasp.toml in reach it is \
             the compiled default rather than the one the daemon is writing to."
        );
    }

    let highest = applied.iter().copied().max().unwrap_or(0);
    if highest < expected_version {
        bail!(
            "this database is migrated to V{highest}, but this build of netgraspd ships \
             migrations through V{expected_version}, so tables and columns it reads are \
             not there yet.\n\n\
             The daemon applies migrations when it starts. Run `netgraspd run` once with \
             this build, or upgrade the daemon that owns this database, before reading \
             from it."
        );
    }

    let problems = schema_problems(client).await?;
    if problems.is_empty() {
        return Ok(());
    }
    bail!(
        "the database schema does not match what this build of netgraspd expects, so \
         this command cannot answer honestly:\n  {}\n\n\
         This usually means another writer created or altered an ng_ table. The daemon \
         owns this schema; see the README section \"How the Trovato plugin relates\".",
        problems.join("\n  ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_expected_table_is_ng_prefixed_and_listed_once() {
        let names: Vec<&str> = EXPECTED.iter().map(|(t, _)| *t).collect();
        for name in &names {
            assert!(name.starts_with("ng_"), "{name} is not an ng_ table");
        }
        let unique: std::collections::HashSet<&&str> = names.iter().collect();
        assert_eq!(unique.len(), names.len(), "a table is listed twice");
    }

    #[test]
    fn no_expected_table_lists_a_column_twice() {
        for (table, columns) in EXPECTED {
            let unique: std::collections::HashSet<&str> = columns.iter().map(|c| c.name).collect();
            assert_eq!(
                unique.len(),
                columns.len(),
                "{table} lists a column more than once"
            );
        }
    }

    #[test]
    fn the_expected_types_are_information_schema_spellings() {
        // A typo here would make the preflight reject a correct database, which
        // is worse than not checking at all.
        let allowed = [
            "bigint",
            "text",
            "boolean",
            "real",
            "jsonb",
            "uuid",
            "timestamp with time zone",
        ];
        for (table, columns) in EXPECTED {
            for column in *columns {
                assert!(
                    allowed.contains(&column.data_type),
                    "{table}.{} has an unrecognised type {:?}",
                    column.name,
                    column.data_type
                );
            }
        }
    }

    #[test]
    fn the_seven_tables_the_plugin_reads_are_all_covered() {
        let names: Vec<&str> = EXPECTED.iter().map(|(t, _)| *t).collect();
        for required in [
            "ng_devices",
            "ng_device_signals",
            "ng_presence",
            "ng_events",
            "ng_ip_history",
            "ng_location_history",
            "ng_people",
        ] {
            assert!(names.contains(&required), "{required} is not in EXPECTED");
        }
        assert_eq!(names.len(), 7, "an unexpected table joined the contract");
    }

    #[test]
    fn the_reconcile_message_names_every_table_it_was_given_and_no_other() {
        // The defect this pins: the DROP list used to be typed out by hand, so
        // it named a set that was neither this build's nor the plugin's.
        let present: Vec<String> = EXPECTED
            .iter()
            .rev()
            .map(|(table, _)| (*table).to_string())
            .collect();
        let message = reconcile_message(&present);

        let (_, drop_line) = message
            .split_once("DROP TABLE IF EXISTS ")
            .expect("the message suggests a DROP");
        let named: Vec<&str> = drop_line
            .split_once(" CASCADE;")
            .expect("the DROP is terminated")
            .0
            .split(", ")
            .collect();
        assert_eq!(
            named,
            present.iter().map(String::as_str).collect::<Vec<&str>>(),
            "the message must name exactly the tables it was told are there"
        );
        for (table, _) in EXPECTED {
            assert!(named.contains(table), "{table} is not in the DROP list");
        }
    }

    #[test]
    fn the_reconcile_message_names_a_table_this_build_has_never_heard_of() {
        // ng_state is the plugin's own scratch table. No version of this daemon
        // knows it exists, and an operator following the message has to drop it
        // all the same or the next plugin install adopts a half-cleared schema.
        let present = vec!["ng_devices".to_string(), "ng_state".to_string()];
        let message = reconcile_message(&present);
        assert!(message.contains("ng_state"), "{message}");
        assert!(
            !message.contains("ng_device_signals"),
            "a table that is not there must not be named: {message}"
        );
    }

    #[test]
    fn the_reconcile_message_stays_readable_with_nothing_to_drop() {
        let message = reconcile_message(&[]);
        assert!(
            !message.contains("DROP TABLE IF EXISTS  CASCADE"),
            "{message}"
        );
        assert!(message.contains("no ng_ tables are present"), "{message}");
    }

    #[test]
    fn every_epoch_column_has_the_timestamptz_it_twins() {
        // The plugin reads the epoch column because it cannot decode the
        // timestamptz. One without the other is a contract the plugin cannot
        // satisfy.
        for (table, columns) in EXPECTED {
            for column in *columns {
                let Some(source) = column.name.strip_suffix("_epoch") else {
                    continue;
                };
                assert_eq!(column.data_type, "bigint", "{table}.{}", column.name);
                assert!(
                    columns
                        .iter()
                        .any(|c| c.name == source && c.data_type == TS),
                    "{table}.{} twins {source}, which is not a timestamptz here",
                    column.name
                );
            }
        }
    }
}
