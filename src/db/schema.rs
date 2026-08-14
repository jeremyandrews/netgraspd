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
//!
//! [`EXPECTED`] is also what the contract test in `tests/schema.rs` asserts, so a
//! future change to the schema breaks this repository's suite rather than the
//! plugin's.

use anyhow::{Result, bail};
use std::collections::BTreeMap;

use crate::db::queries::Client;

/// One column, as this build expects to find it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedColumn {
    /// Column name.
    pub name: &'static str,
    /// `information_schema.columns.data_type`, for example `timestamp with time
    /// zone`. Deliberately the SQL-standard spelling rather than the internal
    /// `udt_name`, because that is what an operator reading the error can look
    /// up.
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

/// The `timestamptz` spelling `information_schema` reports.
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

/// Reads one table's columns out of `information_schema`.
///
/// Returns an empty map when the table does not exist, which the callers
/// distinguish from an empty table by checking [`table_exists`] first.
///
/// # Errors
///
/// Returns an error when the query fails.
pub async fn columns_of(client: &Client, table: &str) -> Result<BTreeMap<String, ActualColumn>> {
    let rows = client
        .query(
            "SELECT column_name, data_type, is_nullable
               FROM information_schema.columns
              WHERE table_schema = current_schema() AND table_name = $1",
            &[&table],
        )
        .await?;
    let mut out = BTreeMap::new();
    for row in &rows {
        let name: String = row.try_get("column_name")?;
        let data_type: String = row.try_get("data_type")?;
        let is_nullable: String = row.try_get("is_nullable")?;
        out.insert(
            name.clone(),
            ActualColumn {
                name,
                data_type,
                nullable: is_nullable == "YES",
            },
        );
    }
    Ok(out)
}

/// Whether a table exists in the current schema.
///
/// # Errors
///
/// Returns an error when the query fails.
pub async fn table_exists(client: &Client, table: &str) -> Result<bool> {
    let row = client
        .query_one(
            "SELECT EXISTS (
                 SELECT 1 FROM information_schema.tables
                  WHERE table_schema = current_schema() AND table_name = $1)",
            &[&table],
        )
        .await?;
    Ok(row.try_get(0)?)
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
/// # Errors
///
/// Returns an error naming the situation and what to do about it when `ng_`
/// tables exist that this daemon did not create.
pub async fn check_daemon_migrated_first(client: &Client) -> Result<()> {
    if !table_exists(client, "ng_devices").await? {
        return Ok(());
    }
    if table_exists(client, MIGRATION_TABLE).await? {
        // The daemon has migrated this database before. Ordinary restart.
        return Ok(());
    }
    bail!(
        "this database already has ng_ tables, but netgraspd did not create them: \
         there is no {MIGRATION_TABLE} table.\n\n\
         The Trovato netgrasp plugin was installed before the daemon ever ran. The \
         daemon owns this schema and must migrate first, so its tables cannot be \
         adopted as they are.\n\n\
         To reconcile, either:\n  \
         1. point netgraspd at an empty database (recommended: create one, run \
         netgraspd once, then point the plugin at it), or\n  \
         2. if the plugin's tables hold nothing worth keeping, drop them and let \
         netgraspd rebuild:\n     \
         DROP TABLE IF EXISTS ng_people, ng_location_history, ng_ip_history, \
         ng_events, ng_presence, ng_device_signals, ng_devices CASCADE;\n\n\
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
