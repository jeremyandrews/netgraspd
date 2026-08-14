//! The nightly jobs that make an unattended year survivable.
//!
//! Without these, `ng_presence` grows one row per session forever, `ng_events`
//! never stops, and a Raspberry Pi with a memory card runs out of somewhere to
//! put it. With them the database reaches a steady size a few weeks in and stays
//! there.
//!
//! Four jobs, in this order:
//!
//! 1. **Presence rollup.** Sessions older than `rollup_after_days` compact into
//!    one summary row per device per day.
//! 2. **Location rollup.** Stays compact the same way, per device per *location*
//!    per day. Grouping across locations as well would produce a row that says
//!    the device was somewhere between the kitchen and the driveway, which is
//!    not a fact anybody can use.
//! 3. **Event prune.** Events older than `event_retention_days` are deleted.
//! 4. **IP history merge.** See [`merge_ip_history`] for why this is a no-op
//!    under the current schema and is here anyway.
//!
//! Then `VACUUM ANALYZE`, but only if something actually moved: a vacuum that
//! reclaims nothing is pure write amplification on a memory card.
//!
//! ## Two invariants the rollup must never break
//!
//! **The current day is never touched.** Every cutoff is derived from the start
//! of today in UTC, so the oldest thing a rollup can reach is `rollup_after_days`
//! whole days ago.
//!
//! **An open session is never compacted.** Every rollup query requires
//! `ended_at IS NOT NULL`. A session that is still being written has no end to
//! summarise, and compacting it would both lose the device's current presence
//! and violate the partial unique index that keeps at most one open session per
//! device.
//!
//! Cutoffs are computed in Rust from a `now` passed in, rather than from the
//! database's `now()`. That is what lets a test seed six months of synthetic
//! history and roll it up without waiting six months.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, Timelike, Utc};

use crate::config::MaintenanceConfig;
use crate::db::queries::Client;

/// Every table the vacuum covers.
const NG_TABLES: [&str; 7] = [
    "ng_devices",
    "ng_device_signals",
    "ng_presence",
    "ng_events",
    "ng_ip_history",
    "ng_location_history",
    "ng_people",
];

/// What one maintenance run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Presence sessions compacted away.
    pub presence_compacted: u64,
    /// Presence summary rows created.
    pub presence_summaries: u64,
    /// Location stays compacted away.
    pub location_compacted: u64,
    /// Location summary rows created.
    pub location_summaries: u64,
    /// Events deleted.
    pub events_pruned: u64,
    /// Duplicate address ranges merged. Structurally always zero; see
    /// [`merge_ip_history`].
    pub ip_ranges_merged: u64,
    /// Whether the vacuum ran.
    pub vacuumed: bool,
    /// Wall clock for the whole run.
    pub took: Duration,
}

impl Report {
    /// True when the run moved nothing, which is the steady state on a database
    /// that has already been rolled up.
    #[must_use]
    pub const fn is_quiet(&self) -> bool {
        self.presence_compacted == 0
            && self.location_compacted == 0
            && self.events_pruned == 0
            && self.ip_ranges_merged == 0
    }

    /// One line an operator can read in a log.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "presence {} rows into {} summaries, location {} rows into {} summaries, \
             {} events pruned, {} address ranges merged, vacuum {}, {:.1}s",
            self.presence_compacted,
            self.presence_summaries,
            self.location_compacted,
            self.location_summaries,
            self.events_pruned,
            self.ip_ranges_merged,
            if self.vacuumed { "ran" } else { "skipped" },
            self.took.as_secs_f64()
        )
    }
}

/// The start of the UTC day `days` days before `now`.
///
/// This is the only place a cutoff is computed, so "never touch the current day"
/// is one function rather than a rule four queries have to remember.
#[must_use]
pub fn cutoff(now: DateTime<Utc>, days: u32) -> DateTime<Utc> {
    now.date_naive().and_time(chrono::NaiveTime::MIN).and_utc()
        - chrono::TimeDelta::days(i64::from(days))
}

/// Runs every job, in order.
///
/// # Errors
///
/// Returns an error when any statement fails. The jobs are independent, so a
/// failure leaves the earlier ones applied; each is its own transaction and none
/// half-applies.
pub async fn run(
    client: &Client,
    config: &MaintenanceConfig,
    now: DateTime<Utc>,
) -> Result<Report> {
    let started = Instant::now();
    let rollup_before = cutoff(now, config.rollup_after_days);
    let events_before = cutoff(now, config.event_retention_days);
    tracing::info!(
        rollup_before = %rollup_before,
        events_before = %events_before,
        "maintenance starting"
    );

    let (presence_compacted, presence_summaries) = roll_up_presence(client, rollup_before).await?;
    let (location_compacted, location_summaries) =
        roll_up_location_history(client, rollup_before).await?;
    let events_pruned = prune_events(client, events_before).await?;
    let ip_ranges_merged = merge_ip_history(client).await?;

    let mut report = Report {
        presence_compacted,
        presence_summaries,
        location_compacted,
        location_summaries,
        events_pruned,
        ip_ranges_merged,
        vacuumed: false,
        took: Duration::ZERO,
    };
    if config.vacuum_after_rollup && !report.is_quiet() {
        vacuum(client).await?;
        report.vacuumed = true;
    }
    report.took = started.elapsed();
    tracing::info!(summary = %report.summary(), "maintenance finished");
    Ok(report)
}

/// Compacts closed presence sessions older than the cutoff into one summary row
/// per device per UTC day.
///
/// Returns the number of rows compacted away and the number of summaries
/// created.
///
/// # Errors
///
/// Returns an error when the statement fails.
pub async fn roll_up_presence(client: &Client, before: DateTime<Utc>) -> Result<(u64, u64)> {
    let row = client
        .query_one(
            // One statement so the insert and the delete share a snapshot: the
            // summaries this creates are not visible to the delete, and the rows
            // the delete removes are exactly the ones the insert read.
            "WITH victims AS (
                 SELECT id, device_id, interface, ip, started_at, ended_at, observation_count,
                        (started_at AT TIME ZONE 'UTC')::date AS day
                   FROM ng_presence
                  WHERE is_summary = FALSE
                    -- Never an open session: it has no end to summarise, and
                    -- compacting it would drop the device's current presence.
                    AND ended_at IS NOT NULL
                    -- Never the current day; see maintenance::cutoff.
                    AND started_at < $1
             ),
             inserted AS (
                 INSERT INTO ng_presence
                     (device_id, interface, ip, started_at, ended_at, is_summary,
                      observation_count)
                 SELECT device_id,
                        (array_agg(interface ORDER BY started_at)
                             FILTER (WHERE interface IS NOT NULL))[1],
                        (array_agg(ip ORDER BY started_at)
                             FILTER (WHERE ip IS NOT NULL))[1],
                        MIN(started_at), MAX(ended_at), TRUE, SUM(observation_count)
                   FROM victims
                  GROUP BY device_id, day
                 RETURNING 1
             ),
             deleted AS (
                 DELETE FROM ng_presence WHERE id IN (SELECT id FROM victims) RETURNING 1
             )
             SELECT (SELECT COUNT(*) FROM deleted), (SELECT COUNT(*) FROM inserted)",
            &[&before],
        )
        .await
        .context("rolling up presence sessions failed")?;
    let compacted: i64 = row.try_get(0)?;
    let summaries: i64 = row.try_get(1)?;
    Ok((compacted.max(0) as u64, summaries.max(0) as u64))
}

/// Compacts closed location stays older than the cutoff into one summary row per
/// device per location per UTC day.
///
/// Grouped by location as well as by day, unlike presence. A summary that merged
/// the kitchen and the driveway would record a stay somewhere in between, which
/// is not a place and not a fact.
///
/// # Errors
///
/// Returns an error when the statement fails.
pub async fn roll_up_location_history(
    client: &Client,
    before: DateTime<Utc>,
) -> Result<(u64, u64)> {
    let row = client
        .query_one(
            "WITH victims AS (
                 SELECT id, device_id, ap_name, location, started_at, ended_at,
                        (started_at AT TIME ZONE 'UTC')::date AS day
                   FROM ng_location_history
                  WHERE is_summary = FALSE
                    AND ended_at IS NOT NULL
                    AND started_at < $1
             ),
             inserted AS (
                 INSERT INTO ng_location_history
                     (device_id, ap_name, location, started_at, ended_at, is_summary)
                 SELECT device_id,
                        (array_agg(ap_name ORDER BY started_at)
                             FILTER (WHERE ap_name IS NOT NULL))[1],
                        location, MIN(started_at), MAX(ended_at), TRUE
                   FROM victims
                  GROUP BY device_id, location, day
                 RETURNING 1
             ),
             deleted AS (
                 DELETE FROM ng_location_history WHERE id IN (SELECT id FROM victims)
                 RETURNING 1
             )
             SELECT (SELECT COUNT(*) FROM deleted), (SELECT COUNT(*) FROM inserted)",
            &[&before],
        )
        .await
        .context("rolling up location history failed")?;
    let compacted: i64 = row.try_get(0)?;
    let summaries: i64 = row.try_get(1)?;
    Ok((compacted.max(0) as u64, summaries.max(0) as u64))
}

/// Deletes events older than the cutoff.
///
/// # Errors
///
/// Returns an error when the statement fails.
pub async fn prune_events(client: &Client, before: DateTime<Utc>) -> Result<u64> {
    client
        .execute("DELETE FROM ng_events WHERE \"timestamp\" < $1", &[&before])
        .await
        .context("pruning events failed")
}

/// Merges overlapping or adjacent address ranges for one device and address.
///
/// **This is a no-op under the current schema, on purpose.** `ng_ip_history`
/// carries `UNIQUE (device_id, ip)`, so a second row for the same pair cannot
/// exist and there is never anything to merge; `upsert_ip` widens the existing
/// row instead. The job is kept because it is cheap, because it is the safety net
/// if that index is ever dropped, and because a maintenance routine that silently
/// omits a job it claims to run is worse than one that runs a job and reports
/// zero.
///
/// # Errors
///
/// Returns an error when the statement fails.
pub async fn merge_ip_history(client: &Client) -> Result<u64> {
    let row = client
        .query_one(
            "WITH ranked AS (
                 SELECT id, device_id, ip,
                        MIN(first_seen) OVER (PARTITION BY device_id, ip) AS merged_first,
                        MAX(last_seen)  OVER (PARTITION BY device_id, ip) AS merged_last,
                        ROW_NUMBER()    OVER (PARTITION BY device_id, ip ORDER BY id)
                            AS position
                   FROM ng_ip_history
             ),
             widened AS (
                 UPDATE ng_ip_history h
                    SET first_seen = r.merged_first,
                        last_seen  = r.merged_last
                   FROM ranked r
                  WHERE h.id = r.id
                    AND r.position = 1
                    AND (h.first_seen <> r.merged_first OR h.last_seen <> r.merged_last)
                 RETURNING 1
             ),
             removed AS (
                 DELETE FROM ng_ip_history
                  WHERE id IN (SELECT id FROM ranked WHERE position > 1)
                 RETURNING 1
             )
             SELECT (SELECT COUNT(*) FROM removed)",
            &[],
        )
        .await
        .context("merging address history failed")?;
    let merged: i64 = row.try_get(0)?;
    Ok(merged.max(0) as u64)
}

/// Runs `VACUUM ANALYZE` over every `ng_` table.
///
/// One statement per call rather than one batch: several statements in a single
/// simple-query message form an implicit transaction block, and `VACUUM` cannot
/// run inside one.
///
/// # Errors
///
/// Returns an error when a vacuum fails.
pub async fn vacuum(client: &Client) -> Result<()> {
    for table in NG_TABLES {
        client
            .batch_execute(&format!("VACUUM ANALYZE {table}"))
            .await
            .with_context(|| format!("vacuuming {table} failed"))?;
    }
    tracing::debug!(tables = NG_TABLES.len(), "vacuum analyze complete");
    Ok(())
}

/// Whether the nightly job is due, given when it last ran.
///
/// The daemon checks this on a coarse timer rather than sleeping until the
/// configured time, so that a machine which was suspended over the scheduled
/// minute still runs the job when it wakes rather than skipping a day.
#[must_use]
pub fn is_due(
    config: &MaintenanceConfig,
    now: DateTime<Utc>,
    last_run: Option<DateTime<Utc>>,
    offset: chrono::FixedOffset,
) -> bool {
    if !config.enabled {
        return false;
    }
    let local = now.with_timezone(&offset);
    let minutes = local.hour() * 60 + local.minute();
    if minutes < config.run_at.minutes() {
        return false;
    }
    match last_run {
        // Once a day: the job has already run since the scheduled time today.
        Some(last) => {
            let last_local = last.with_timezone(&offset);
            last_local.date_naive() != local.date_naive()
        }
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClockTime;
    use chrono::TimeZone;

    fn utc() -> chrono::FixedOffset {
        chrono::FixedOffset::east_opt(0).expect("utc")
    }

    fn stamp(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, min, 0)
            .single()
            .expect("valid time")
    }

    fn config() -> MaintenanceConfig {
        MaintenanceConfig::default()
    }

    #[test]
    fn a_cutoff_is_the_start_of_a_utc_day() {
        let now = stamp(2026, 8, 14, 17, 42);
        assert_eq!(cutoff(now, 0), stamp(2026, 8, 14, 0, 0));
        assert_eq!(cutoff(now, 1), stamp(2026, 8, 13, 0, 0));
        assert_eq!(cutoff(now, 30), stamp(2026, 7, 15, 0, 0));
    }

    #[test]
    fn a_cutoff_never_reaches_into_the_current_day() {
        // The invariant the whole rollup rests on: with the default 30 days, the
        // newest thing reachable is a month ago, and today is untouchable even
        // one second before midnight.
        let midnight_minus_one = stamp(2026, 8, 14, 23, 59);
        assert!(cutoff(midnight_minus_one, 1) < stamp(2026, 8, 14, 0, 0));
        assert!(cutoff(midnight_minus_one, 30) < stamp(2026, 8, 14, 0, 0));
    }

    #[test]
    fn a_cutoff_crosses_a_year_boundary_correctly() {
        assert_eq!(
            cutoff(stamp(2027, 1, 5, 3, 0), 10),
            stamp(2026, 12, 26, 0, 0)
        );
    }

    #[test]
    fn the_job_is_not_due_before_its_scheduled_time() {
        let config = config(); // 03:30
        assert!(!is_due(&config, stamp(2026, 8, 14, 3, 29), None, utc()));
        assert!(is_due(&config, stamp(2026, 8, 14, 3, 30), None, utc()));
    }

    #[test]
    fn the_job_runs_once_a_day_and_not_again() {
        let config = config();
        let this_morning = stamp(2026, 8, 14, 3, 30);
        assert!(is_due(&config, this_morning, None, utc()));
        assert!(
            !is_due(&config, stamp(2026, 8, 14, 9, 0), Some(this_morning), utc()),
            "already ran today"
        );
        assert!(
            is_due(
                &config,
                stamp(2026, 8, 15, 3, 30),
                Some(this_morning),
                utc()
            ),
            "due again tomorrow"
        );
    }

    #[test]
    fn a_machine_asleep_over_the_scheduled_minute_still_runs_when_it_wakes() {
        // The reason this is a due-check on a coarse timer rather than a sleep
        // until 03:30: a suspended laptop would otherwise skip the day entirely.
        let config = config();
        assert!(is_due(&config, stamp(2026, 8, 14, 11, 15), None, utc()));
    }

    #[test]
    fn a_disabled_job_is_never_due() {
        let config = MaintenanceConfig {
            enabled: false,
            ..config()
        };
        assert!(!is_due(&config, stamp(2026, 8, 14, 23, 0), None, utc()));
    }

    #[test]
    fn the_schedule_is_read_in_local_time() {
        let config = MaintenanceConfig {
            run_at: ClockTime {
                hour: 3,
                minute: 30,
            },
            ..config()
        };
        // Rome in summer is UTC+2, so 02:00 UTC is 04:00 local and due.
        let rome = chrono::FixedOffset::east_opt(2 * 3600).expect("offset");
        assert!(is_due(&config, stamp(2026, 8, 14, 2, 0), None, rome));
        assert!(!is_due(&config, stamp(2026, 8, 14, 2, 0), None, utc()));
    }

    #[test]
    fn a_quiet_report_is_one_that_moved_nothing() {
        assert!(Report::default().is_quiet());
        assert!(
            Report {
                presence_summaries: 3,
                ..Report::default()
            }
            .is_quiet(),
            "summaries without compaction cannot happen, and are not movement"
        );
        assert!(
            !Report {
                events_pruned: 1,
                ..Report::default()
            }
            .is_quiet()
        );
    }

    #[test]
    fn the_summary_line_names_every_job() {
        let text = Report {
            presence_compacted: 10,
            presence_summaries: 2,
            location_compacted: 4,
            location_summaries: 1,
            events_pruned: 7,
            ip_ranges_merged: 0,
            vacuumed: true,
            took: Duration::from_millis(1500),
        }
        .summary();
        for fragment in ["presence 10", "location 4", "7 events pruned", "vacuum ran"] {
            assert!(
                text.contains(fragment),
                "{fragment:?} missing from {text:?}"
            );
        }
    }

    #[test]
    fn every_ng_table_is_vacuumed() {
        // A table missing from this list would never be analysed, and its query
        // plans would drift as it grew.
        for table in crate::db::schema::EXPECTED.iter().map(|(t, _)| *t) {
            assert!(NG_TABLES.contains(&table), "{table} is not vacuumed");
        }
        assert_eq!(NG_TABLES.len(), crate::db::schema::EXPECTED.len());
    }
}
