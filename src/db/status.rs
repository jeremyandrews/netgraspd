//! What the daemon publishes about itself: `ng_daemon_status` and
//! `ng_enrichment_status`.
//!
//! Both tables are daemon owned in full and rewritten on every runtime status
//! tick, beside the status file `netgraspd stats` reads. The file is for the
//! operator on this host; these rows are for the web side, which cannot read a
//! file on another machine.
//!
//! **The time zone has one owner.** "Today", "this week" and every other day
//! boundary a reader draws over these tables is measured in
//! `ng_daemon_status.timezone`, written as `ts AT TIME ZONE <that zone>`, and
//! never in the reading session's own `TimeZone`. A kernel connection, a `psql`
//! session and the daemon can each carry a different `TimeZone`; the published
//! zone is the same for all of them. It is the daemon's `timezone` setting when
//! one is configured, and the database's own setting, as the daemon's session
//! sees it, otherwise. None of the daemon's own SQL depends on a session zone:
//! the maintenance rollups bucket by UTC day explicitly.

use anyhow::{Context, Result, bail};

use crate::clock::Timestamp;
use crate::db::queries::Client;
use crate::enrich::EnricherStatus;

/// Where the published time zone came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimezoneSource {
    /// The daemon's `timezone` setting.
    Config,
    /// The database's `TimeZone`, because nothing was configured.
    Database,
}

impl TimezoneSource {
    /// The `ng_daemon_status.timezone_source` value.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            TimezoneSource::Config => "config",
            TimezoneSource::Database => "database",
        }
    }
}

/// The time zone the daemon publishes, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTimezone {
    /// An IANA name Postgres knows, such as `Europe/Rome`.
    pub name: String,
    /// Where it came from.
    pub source: TimezoneSource,
}

/// Decides the zone to publish.
///
/// A configured zone is checked against `pg_timezone_names`, because the zone
/// is only useful if every reader's `AT TIME ZONE` accepts it, and Postgres is
/// who will be asked.
///
/// # Errors
///
/// Returns an error naming the setting and the value when Postgres does not
/// know the configured zone, or when the query fails.
pub async fn resolve_timezone(
    client: &Client,
    configured: Option<&str>,
) -> Result<ResolvedTimezone> {
    if let Some(name) = configured.map(str::trim).filter(|n| !n.is_empty()) {
        let row = client
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM pg_timezone_names WHERE name = $1)",
                &[&name],
            )
            .await
            .context("checking the configured timezone failed")?;
        if !row.try_get::<_, bool>(0)? {
            bail!(
                "timezone {name:?} is not a time zone Postgres knows; set timezone to an \
                 IANA name such as \"Europe/Rome\", or leave it unset to use the database's"
            );
        }
        return Ok(ResolvedTimezone {
            name: name.to_string(),
            source: TimezoneSource::Config,
        });
    }
    let row = client
        .query_one("SELECT current_setting('TimeZone')", &[])
        .await
        .context("reading the database's TimeZone failed")?;
    Ok(ResolvedTimezone {
        name: row.try_get(0)?,
        source: TimezoneSource::Database,
    })
}

/// The one `ng_daemon_status` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonStatus {
    /// This build's version.
    pub version: String,
    /// The zone day boundaries are measured in.
    pub timezone: ResolvedTimezone,
    /// When this daemon process started.
    pub started_at: Timestamp,
    /// The install's `presence_tracking` switch, so the web side can say that
    /// nobody is tracked because it is off.
    pub presence_tracking: bool,
}

/// Writes the `ng_daemon_status` row, stamping it `now`.
///
/// # Errors
///
/// Returns an error when the upsert fails.
pub async fn write_daemon_status(
    client: &Client,
    status: &DaemonStatus,
    now: Timestamp,
) -> Result<()> {
    client
        .execute(
            "INSERT INTO ng_daemon_status
                 (id, version, timezone, timezone_source, started_at, updated_at,
                  presence_tracking)
             VALUES (1, $1, $2, $3, $4, $5, $6)
             ON CONFLICT (id) DO UPDATE SET
                 version = EXCLUDED.version,
                 timezone = EXCLUDED.timezone,
                 timezone_source = EXCLUDED.timezone_source,
                 started_at = EXCLUDED.started_at,
                 updated_at = EXCLUDED.updated_at,
                 presence_tracking = EXCLUDED.presence_tracking",
            &[
                &status.version,
                &status.timezone.name,
                &status.timezone.source.as_str(),
                &status.started_at,
                &now,
                &status.presence_tracking,
            ],
        )
        .await
        .context("writing ng_daemon_status failed")?;
    Ok(())
}

/// Writes one `ng_enrichment_status` row per status given, stamping each `now`.
///
/// # Errors
///
/// Returns an error when an upsert fails.
pub async fn write_enrichment_status(
    client: &Client,
    statuses: &[EnricherStatus],
    now: Timestamp,
) -> Result<()> {
    for status in statuses {
        let polls = i64::try_from(status.polls).unwrap_or(i64::MAX);
        let failures = i64::try_from(status.failures).unwrap_or(i64::MAX);
        client
            .execute(
                "INSERT INTO ng_enrichment_status
                     (enricher, configured, state, polls, failures, last_success_at,
                      last_failure_at, last_error, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                 ON CONFLICT (enricher) DO UPDATE SET
                     configured = EXCLUDED.configured,
                     state = EXCLUDED.state,
                     polls = EXCLUDED.polls,
                     failures = EXCLUDED.failures,
                     last_success_at = EXCLUDED.last_success_at,
                     last_failure_at = EXCLUDED.last_failure_at,
                     last_error = EXCLUDED.last_error,
                     updated_at = EXCLUDED.updated_at",
                &[
                    &status.name,
                    &status.configured,
                    &status.state().as_str(),
                    &polls,
                    &failures,
                    &status.last_success_at,
                    &status.last_failure_at,
                    &status.last_error,
                    &now,
                ],
            )
            .await
            .with_context(|| format!("writing ng_enrichment_status for {} failed", status.name))?;
    }
    Ok(())
}
