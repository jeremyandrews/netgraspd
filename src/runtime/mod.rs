//! The runtime status file: what a running daemon tells `netgraspd stats`.
//!
//! `stats` is a separate process. Uptime, resident memory and the per-source
//! capture rates are facts about the daemon, not about the database, and there
//! is no honest way for another process to read them out of Postgres. The
//! obvious alternative, a `ng_stats` table, would be a schema change the Trovato
//! plugin has not seen, written once a minute forever, to hold numbers that are
//! meaningless the moment the daemon stops.
//!
//! So the daemon writes a small JSON file instead, and `stats` reads it. When it
//! is missing or stale, `stats` says so and answers the database half regardless:
//! "is this thing healthy" has a useful answer even when the answer is "it is not
//! running".
//!
//! Writes are atomic (write a sibling temporary file, then rename), so `stats`
//! never reads half a file. A path that cannot be written is a warning logged
//! once, never a reason to stop watching the network.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// How much older than the write interval a status file may be before `stats`
/// calls it stale.
///
/// Three intervals: one missed write is a busy moment, three is a daemon that
/// has stopped or wedged.
pub const STALE_AFTER_INTERVALS: u32 = 3;

/// How one enricher is doing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnricherCounters {
    /// Polls attempted.
    pub polls: u64,
    /// Polls that failed.
    pub failures: u64,
}

/// What a running daemon publishes about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// The daemon's version, so `stats` from a different build says so.
    pub version: String,
    /// Process id, for an operator who wants to signal it.
    pub pid: u32,
    /// When this run started.
    pub started_at: DateTime<Utc>,
    /// When this file was last written.
    pub updated_at: DateTime<Utc>,
    /// Whether a learning window is in progress.
    pub learning: bool,
    /// Observations accepted after deduplication.
    pub observations: u64,
    /// Observations discarded as duplicates.
    pub duplicates: u64,
    /// Events recorded.
    pub events: u64,
    /// Security events recorded, a subset of `events`.
    pub security_events: u64,
    /// Naming evidence that named an address no known device holds, and so
    /// became nobody's name. A responder answering for hosts on a segment this
    /// daemon cannot see drives this up; a large number beside a small device
    /// count means the daemon is watching less of the network than it thinks.
    ///
    /// Defaulted on read so that a status file written by an older build still
    /// parses rather than making `stats` report a dead daemon.
    #[serde(default)]
    pub unattributed_names: u64,
    /// Addresses the gateway has been seen proxy-ARPing for. Zero on a network
    /// whose router does not proxy; see `security.proxy_arp_gateway`.
    #[serde(default)]
    pub proxy_arp_addresses: usize,
    /// Devices in the in-memory table.
    pub devices: usize,
    /// How many of them are online, idle and offline.
    pub online: usize,
    /// Idle devices.
    pub idle: usize,
    /// Offline devices.
    pub offline: usize,
    /// Observations seen per capture source, before deduplication.
    pub sources: BTreeMap<String, u64>,
    /// Poll and failure counts per enricher.
    pub enrichers: BTreeMap<String, EnricherCounters>,
    /// Resident set size, when the platform can report it without unsafe code.
    ///
    /// Linux only: `/proc/self/status`. macOS is a development platform for this
    /// daemon and reporting nothing there is better than shelling out to `ps`.
    pub resident_bytes: Option<u64>,
}

impl Status {
    /// A status for a run that has just started.
    #[must_use]
    pub fn new(started_at: DateTime<Utc>) -> Self {
        Status {
            version: env!("CARGO_PKG_VERSION").to_string(),
            pid: std::process::id(),
            started_at,
            updated_at: started_at,
            learning: false,
            observations: 0,
            duplicates: 0,
            events: 0,
            security_events: 0,
            unattributed_names: 0,
            proxy_arp_addresses: 0,
            devices: 0,
            online: 0,
            idle: 0,
            offline: 0,
            sources: BTreeMap::new(),
            enrichers: BTreeMap::new(),
            resident_bytes: None,
        }
    }

    /// How long the daemon has been running, as of the last write.
    #[must_use]
    pub fn uptime(&self) -> chrono::TimeDelta {
        self.updated_at - self.started_at
    }

    /// Whether this file is too old to describe a running daemon.
    #[must_use]
    pub fn is_stale(&self, now: DateTime<Utc>, interval: std::time::Duration) -> bool {
        let allowance = chrono::TimeDelta::from_std(interval * STALE_AFTER_INTERVALS)
            .unwrap_or_else(|_| chrono::TimeDelta::minutes(5));
        now - self.updated_at > allowance
    }

    /// Observations per second per source, over the whole run.
    ///
    /// A lifetime average rather than a recent rate, which is the honest thing a
    /// file rewritten from counters can offer. It answers the question `stats`
    /// exists for: whether a source that should be seeing traffic is seeing any.
    #[must_use]
    pub fn source_rates(&self) -> Vec<(String, u64, f64)> {
        let seconds = self.uptime().num_milliseconds().max(1) as f64 / 1000.0;
        self.sources
            .iter()
            .map(|(name, count)| {
                #[allow(clippy::cast_precision_loss)] // A count large enough to
                // lose precision here would be trillions of packets.
                (name.clone(), *count, *count as f64 / seconds)
            })
            .collect()
    }

    /// Writes the file atomically.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory cannot be created or the file cannot
    /// be written or renamed.
    pub fn write(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }
        let json = serde_json::to_vec_pretty(self).context("could not encode the status")?;
        // A sibling rather than a temporary directory, so the rename stays on
        // one filesystem and is therefore atomic.
        let temporary = temporary_path(path);
        std::fs::write(&temporary, &json)
            .with_context(|| format!("could not write {}", temporary.display()))?;
        std::fs::rename(&temporary, path)
            .with_context(|| format!("could not replace {}", path.display()))?;
        Ok(())
    }

    /// Reads the file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is absent or is not a status file.
    pub fn read(path: &Path) -> Result<Self> {
        let bytes =
            std::fs::read(path).with_context(|| format!("could not read {}", path.display()))?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("{} is not a netgraspd status file", path.display()))
    }
}

/// The sibling path a status file is staged at before being renamed into place.
fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

/// Resident set size of this process, where it can be read without unsafe code.
///
/// Returns `None` anywhere but Linux. The deployment target is Linux and the
/// development platform is macOS; a number that is only available on one of them
/// is better reported as absent than as a lie or as a subprocess.
#[must_use]
pub fn resident_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        let Some(rest) = line.strip_prefix("VmRSS:") else {
            continue;
        };
        let kb: u64 = rest
            .split_whitespace()
            .next()
            .and_then(|n| n.parse().ok())?;
        return Some(kb * 1024);
    }
    None
}

/// Renders a byte count the way an operator reads one.
#[must_use]
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    #[allow(clippy::cast_precision_loss)] // Only the rendering loses precision.
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Renders a duration the way an operator reads one.
#[must_use]
pub fn human_duration(delta: chrono::TimeDelta) -> String {
    let total = delta.num_seconds().max(0);
    let (days, hours, minutes, seconds) = (
        total / 86_400,
        (total % 86_400) / 3600,
        (total % 3600) / 60,
        total % 60,
    );
    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn base() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 9, 0, 0)
            .single()
            .expect("valid time")
    }

    /// A directory of this test's own.
    ///
    /// Keyed on the caller's name rather than on a thread id. Thread ids are
    /// reused once a thread exits, so two tests could land in one directory and
    /// whichever finished first would delete the other's files.
    fn temp_dir(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netgraspd-status-test-{}-{test}",
            std::process::id()
        ));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn a_status_round_trips_through_a_file() {
        let dir = temp_dir("round_trip");
        let path = dir.join("status.json");
        let mut status = Status::new(base());
        status.observations = 1234;
        status.sources.insert("arp".into(), 900);
        status.sources.insert("mdns".into(), 334);
        status.enrichers.insert(
            "unifi".into(),
            EnricherCounters {
                polls: 10,
                failures: 1,
            },
        );
        status.write(&path).expect("writes");

        let read = Status::read(&path).expect("reads");
        assert_eq!(read, status);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn writing_leaves_no_temporary_file_behind() {
        let dir = temp_dir("no_temporary_left");
        let path = dir.join("status.json");
        Status::new(base()).write(&path).expect("writes");
        assert!(path.exists());
        assert!(
            !temporary_path(&path).exists(),
            "the staging file must be renamed, not left"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn writing_creates_the_directory_it_needs() {
        let dir = temp_dir("creates_the_directory");
        let path = dir.join("nested").join("deeper").join("status.json");
        Status::new(base()).write(&path).expect("writes");
        assert!(path.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reading_something_that_is_not_a_status_file_says_so() {
        let dir = temp_dir("not_a_status_file");
        let path = dir.join("rubbish.json");
        std::fs::write(&path, b"this is not JSON").expect("writes");
        let err = Status::read(&path).expect_err("must reject");
        assert!(
            err.to_string().contains("not a netgraspd status file"),
            "{err}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reading_an_absent_file_says_which_one() {
        let err =
            Status::read(Path::new("/nonexistent/netgraspd/status.json")).expect_err("must fail");
        assert!(err.to_string().contains("could not read"), "{err}");
    }

    #[test]
    fn a_status_written_recently_is_not_stale_and_an_old_one_is() {
        let interval = std::time::Duration::from_secs(30);
        let mut status = Status::new(base());
        status.updated_at = base();
        assert!(!status.is_stale(base() + chrono::Duration::seconds(60), interval));
        assert!(
            status.is_stale(base() + chrono::Duration::seconds(91), interval),
            "three missed writes means it has stopped"
        );
    }

    #[test]
    fn source_rates_are_counts_over_uptime() {
        let mut status = Status::new(base());
        status.updated_at = base() + chrono::Duration::seconds(100);
        status.sources.insert("arp".into(), 500);
        let rates = status.source_rates();
        assert_eq!(rates.len(), 1);
        assert_eq!(rates[0].0, "arp");
        assert_eq!(rates[0].1, 500);
        assert!((rates[0].2 - 5.0).abs() < 0.001, "{:?}", rates[0]);
    }

    #[test]
    fn a_zero_length_run_does_not_divide_by_zero() {
        let mut status = Status::new(base());
        status.sources.insert("arp".into(), 7);
        let rates = status.source_rates();
        assert!(rates[0].2.is_finite(), "{:?}", rates[0]);
    }

    #[test]
    fn bytes_render_at_the_right_scale() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1024 * 1024 * 3 / 2), "1.5 MiB");
        assert_eq!(human_bytes(1024 * 1024 * 1024), "1.0 GiB");
    }

    #[test]
    fn durations_render_at_the_right_scale() {
        assert_eq!(human_duration(chrono::TimeDelta::seconds(45)), "45s");
        assert_eq!(human_duration(chrono::TimeDelta::seconds(125)), "2m 5s");
        assert_eq!(human_duration(chrono::TimeDelta::seconds(3725)), "1h 2m");
        assert_eq!(
            human_duration(chrono::TimeDelta::seconds(90 * 86_400 + 3725)),
            "90d 1h 2m"
        );
        assert_eq!(human_duration(chrono::TimeDelta::seconds(-5)), "0s");
    }

    #[test]
    fn resident_memory_is_read_on_linux_and_absent_elsewhere() {
        // Asserting the platform contract rather than a number, because the
        // number is whatever the test runner happens to be using.
        let rss = resident_bytes();
        if cfg!(target_os = "linux") {
            assert!(rss.is_some_and(|b| b > 0), "Linux must report a real RSS");
        } else {
            assert!(rss.is_none(), "only Linux is claimed");
        }
    }
}
