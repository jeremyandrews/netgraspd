//! Command-line surface.
//!
//! `run` starts the daemon with a live device table; `devices`, `events` and
//! `people` print one table and exit; `stats` answers whether the installation
//! is healthy; `maintain` runs the nightly jobs by hand; `update-fingerprints`
//! refreshes the DHCP fingerprint table.
//!
//! Every flag that overrides configuration is expressed as a dotted
//! [`Override`] rather than as a partial `Config`, so that an absent flag leaves
//! the layer beneath it alone instead of overwriting it with a null.
//!
//! Every command that touches the database calls [`Db::require_schema`] straight
//! after connecting. None of them migrate, so without it a database that is
//! empty, under-migrated or built by the Trovato plugin answers with whatever
//! Postgres says: `relation "ng_location_history" does not exist` names a table
//! the operator has never heard of and suggests nothing to do about it.

pub mod table;

use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};

use crate::config::{self, Config, ConfigSource, Override};
use crate::daemon::RunOptions;
use crate::db::{Db, queries};
use crate::identity::FingerprintDb;
use crate::maintenance;
use crate::runtime;

/// Passive network device monitor. Watches LAN broadcast and multicast traffic
/// and never transmits.
#[derive(Debug, Parser)]
#[command(name = "netgraspd", version, about, long_about = None)]
pub struct Cli {
    /// Configuration file. Defaults to ./netgrasp.toml if it exists.
    #[arg(short, long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Postgres connection URL, overriding every other source.
    #[arg(long, global = true, value_name = "URL")]
    pub database_url: Option<String>,

    /// Log filter, in the tracing env-filter syntax.
    #[arg(long, global = true, default_value = "info", value_name = "FILTER")]
    pub log: String,

    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// The subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Watch the network, with a live-updating device table.
    Run(RunArgs),
    /// Print the device table once and exit.
    Devices(DevicesArgs),
    /// Print recent events and exit.
    Events(EventsArgs),
    /// Print who is home and where, then exit.
    People,
    /// Report whether this installation is healthy, then exit.
    Stats,
    /// Run the nightly rollup, prune and vacuum now.
    Maintain(MaintainArgs),
    /// Download a fresh DHCP fingerprint table.
    UpdateFingerprints(UpdateFingerprintsArgs),
}

/// Arguments to `run`.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Interface to capture on. Repeatable. Defaults to every non-loopback
    /// interface that is up.
    #[arg(short, long, value_name = "NAME")]
    pub interface: Vec<String>,

    /// Run a learning window even if devices are already known.
    #[arg(long)]
    pub learn: bool,

    /// How long the learning window lasts, for example 5m.
    #[arg(long, value_name = "DURATION")]
    pub learn_duration: Option<String>,

    /// Do not draw the live table, even on a terminal.
    #[arg(long)]
    pub no_table: bool,

    /// Record events but deliver no notifications.
    #[arg(long)]
    pub no_notify: bool,
}

/// Arguments to `devices`.
#[derive(Debug, Args)]
pub struct DevicesArgs {
    /// Show only devices in this state: online, idle or offline.
    #[arg(long, value_name = "STATE")]
    pub state: Option<String>,
}

/// Arguments to `events`.
#[derive(Debug, Args)]
pub struct EventsArgs {
    /// How many events to show.
    #[arg(long, default_value_t = 50)]
    pub limit: i64,

    /// Show only security events from the analyzer chain.
    #[arg(long)]
    pub security: bool,
}

/// Arguments to `maintain`.
#[derive(Debug, Args)]
pub struct MaintainArgs {
    /// Report what would be compacted and pruned, without changing anything.
    #[arg(long)]
    pub dry_run: bool,
}

/// Arguments to `update-fingerprints`.
#[derive(Debug, Args)]
pub struct UpdateFingerprintsArgs {
    /// Where to download from. Defaults to `identity.fingerprint_url`.
    #[arg(value_name = "URL")]
    pub url: Option<String>,

    /// Where to write it. Defaults to `identity.fingerprint_path`.
    #[arg(long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Parse and report, without writing anything.
    #[arg(long)]
    pub dry_run: bool,
}

impl Cli {
    /// Collects every configuration override implied by the flags.
    ///
    /// Only flags the user actually passed produce an override, which is what
    /// makes the precedence chain work.
    #[must_use]
    pub fn overrides(&self) -> Vec<Override> {
        let mut out = Vec::new();
        if let Some(url) = &self.database_url {
            out.push(Override::new("database.url", url.clone()));
        }
        if let Command::Run(args) = &self.command {
            if !args.interface.is_empty() {
                out.push(Override::new("capture.interfaces", args.interface.clone()));
            }
            if let Some(duration) = &args.learn_duration {
                out.push(Override::new("learning.duration", duration.clone()));
            }
            if args.no_notify {
                out.push(Override::new("notify.enabled", false));
            }
        }
        out
    }

    /// Loads configuration through every layer, applying these flags last.
    ///
    /// # Errors
    ///
    /// Returns an error when a layer cannot be read or the result fails
    /// validation.
    pub fn load_config(&self) -> Result<Config> {
        Config::load(self.config.as_deref(), &self.overrides())
    }

    /// Loads configuration and reports which file layer produced it.
    ///
    /// # Errors
    ///
    /// The same as [`Cli::load_config`].
    pub fn load_config_with_source(&self) -> Result<(Config, ConfigSource)> {
        Config::load_with_source(self.config.as_deref(), &self.overrides())
    }
}

/// Logs where the configuration came from and which database it names.
///
/// Runs for every subcommand, before anything connects. A read command that
/// silently fell back to the compiled `database.url` used to report on a
/// different database than the running daemon with nothing to say that it had,
/// and the numbers it printed looked like an answer rather than a mistake.
pub fn log_config_provenance(source: &ConfigSource, config: &Config) {
    match source {
        ConfigSource::File(path) => {
            tracing::info!(path = %path.display(), "configuration read from file");
        }
        ConfigSource::Defaults { looked_for } => {
            tracing::warn!(
                looked_for = %looked_for.display(),
                "no configuration file found; every setting not given as a flag or a \
                 NETGRASP_ variable is a compiled default, database.url included"
            );
        }
    }
    tracing::info!(
        url = %config::redact_database_url(&config.database.url),
        "effective database"
    );
}

/// Runs `devices`.
///
/// # Errors
///
/// Returns an error when the database is unreachable, its schema is not one this
/// build can read, or the state filter is not a state.
pub async fn devices(config: &Config, args: &DevicesArgs) -> Result<()> {
    if let Some(state) = &args.state
        && !["online", "idle", "offline"].contains(&state.as_str())
    {
        anyhow::bail!("--state must be online, idle or offline, not {state:?}");
    }

    let db = Db::connect(&config.database)?;
    db.require_schema().await?;
    let client = db.client().await?;
    let mut records = queries::load_devices(&client).await?;
    if let Some(state) = &args.state {
        records.retain(|d| d.state.as_str() == state);
    }
    if records.is_empty() {
        println!("No devices recorded yet.");
        return Ok(());
    }
    print!("{}", table::device_record_table(&records, Utc::now()));
    Ok(())
}

/// Runs `events`.
///
/// # Errors
///
/// Returns an error when the database is unreachable, its schema is not one this
/// build can read, or the limit is not positive.
pub async fn events(config: &Config, args: &EventsArgs) -> Result<()> {
    if args.limit <= 0 {
        anyhow::bail!("--limit must be at least 1");
    }
    let db = Db::connect(&config.database)?;
    db.require_schema().await?;
    let client = db.client().await?;
    let records = if args.security {
        queries::recent_security_events(&client, args.limit).await?
    } else {
        queries::recent_events(&client, args.limit).await?
    };
    if records.is_empty() {
        if args.security {
            println!("No security events recorded yet.");
        } else {
            println!("No events recorded yet.");
        }
        return Ok(());
    }
    print!("{}", table::event_table(&records, Utc::now()));
    Ok(())
}

/// Runs `people`.
///
/// # Errors
///
/// Returns an error when the database is unreachable or its schema is not one
/// this build can read.
pub async fn people(config: &Config) -> Result<()> {
    let db = Db::connect(&config.database)?;
    db.require_schema().await?;
    let client = db.client().await?;
    let rows = queries::load_people(&client).await?;
    if rows.is_empty() {
        println!(
            "Nobody is tracked yet. Add a [[people]] block to netgrasp.toml, or let the \
             Trovato plugin fill ng_devices.owner_item_id."
        );
        return Ok(());
    }
    print!("{}", table::people_table(&rows, Utc::now()));
    Ok(())
}

/// Runs `stats`.
///
/// The command an operator runs on a Pi three months in to answer "is this thing
/// healthy". It reads two independent sources and says plainly when one of them
/// is missing: the runtime status file for facts about the process, and the
/// database for facts about what it has recorded.
///
/// # Errors
///
/// Returns an error when the database is unreachable or its schema is not one
/// this build can read. A missing or stale status file is reported, not an
/// error: "the daemon is not running" is one of the answers this command exists
/// to give.
pub async fn stats(config: &Config) -> Result<()> {
    let now = Utc::now();
    println!("netgraspd {}", env!("CARGO_PKG_VERSION"));
    println!();

    print_runtime_section(config, now);

    let db = Db::connect(&config.database)?;
    db.require_schema().await?;
    let client = db.client().await?;

    println!("Devices");
    let states = queries::device_state_counts(&client).await?;
    if states.is_empty() {
        println!("  none recorded yet");
    } else {
        let total: i64 = states.iter().map(|(_, n)| *n).sum();
        let breakdown: Vec<String> = states
            .iter()
            .map(|(state, n)| format!("{n} {state}"))
            .collect();
        println!("  {total} known ({})", breakdown.join(", "));
    }
    println!(
        "  {}, {}",
        plural(
            queries::count_open_presence(&client).await?,
            "open presence session"
        ),
        plural(
            queries::count_open_locations(&client).await?,
            "open location stay"
        ),
    );
    println!();

    println!("Events");
    let counts = queries::event_counts(&client).await?;
    if counts.is_empty() {
        println!("  none recorded yet");
    } else {
        for (event_type, n) in counts.iter().take(EVENT_TYPES_SHOWN) {
            println!("  {n:>8}  {event_type}");
        }
        if counts.len() > EVENT_TYPES_SHOWN {
            println!("  ...and {} more types", counts.len() - EVENT_TYPES_SHOWN);
        }
    }
    let (oldest, newest) = queries::event_span(&client).await?;
    if let (Some(oldest), Some(newest)) = (oldest, newest) {
        println!(
            "  spanning {} to {} ({} of retention configured)",
            oldest.format("%Y-%m-%d"),
            newest.format("%Y-%m-%d"),
            format_args!("{} days", config.maintenance.event_retention_days)
        );
    }
    println!();

    println!("Rollup");
    for (table, high_water, summaries) in queries::rollup_high_water(&client).await? {
        match high_water {
            Some(mark) => println!(
                "  {table}: {summaries} summary rows, newest day {}",
                mark.format("%Y-%m-%d")
            ),
            None => println!(
                "  {table}: nothing summarised yet (rollup starts at {} days)",
                config.maintenance.rollup_after_days
            ),
        }
    }
    println!();

    println!("Database");
    let sizes = queries::table_sizes(&client).await?;
    let total: i64 = sizes.iter().map(|s| s.bytes).sum();
    for size in &sizes {
        let rows = size.rows.map_or_else(
            || "not analysed yet".to_string(),
            |rows| format!("~{rows} rows"),
        );
        println!(
            "  {:<22} {:>10}  {rows}",
            size.table,
            runtime::human_bytes(size.bytes.max(0).unsigned_abs()),
        );
    }
    println!(
        "  {:<22} {:>10}",
        "total",
        runtime::human_bytes(total.max(0).unsigned_abs())
    );
    Ok(())
}

/// How many event types `stats` lists before it starts counting instead.
const EVENT_TYPES_SHOWN: usize = 8;

/// Renders a count with an "s" only when one is wanted.
///
/// "1 open location stays" is the sort of thing that makes an operator wonder
/// whether the number is wrong too.
fn plural(count: i64, noun: &str) -> String {
    if count == 1 {
        format!("1 {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

/// Prints the half of `stats` that comes from the running daemon.
fn print_runtime_section(config: &Config, now: chrono::DateTime<Utc>) {
    let path = &config.runtime.status_path;
    let status = match runtime::Status::read(path) {
        Ok(status) => status,
        Err(_) => {
            println!("Daemon");
            println!(
                "  not running, or has never run: no status file at {}",
                path.display()
            );
            println!("  (everything below comes from the database and is still current)");
            println!();
            return;
        }
    };

    println!("Daemon");
    if status.is_stale(now, config.runtime.status_interval.get()) {
        println!(
            "  STALE: last wrote {} ago, so it is probably not running",
            runtime::human_duration(now - status.updated_at)
        );
    }
    println!("  pid {}, version {}", status.pid, status.version);
    println!("  up {}", runtime::human_duration(status.uptime()));
    if status.learning {
        println!("  a learning window is in progress");
    }
    match status.resident_bytes {
        Some(bytes) => println!("  resident memory {}", runtime::human_bytes(bytes)),
        None => println!("  resident memory unavailable on this platform"),
    }
    println!(
        "  {} observations, {} duplicates suppressed, {} events ({} security)",
        status.observations, status.duplicates, status.events, status.security_events
    );

    println!("  Capture");
    if status.sources.is_empty() {
        println!("    no source has seen a packet yet");
    } else {
        for (source, count, rate) in status.source_rates() {
            println!("    {source:<8} {count:>10} observations  {rate:>8.2}/s");
        }
    }

    if !status.enrichers.is_empty() {
        println!("  Enrichment");
        for (name, counters) in &status.enrichers {
            let note = if counters.failures == 0 {
                String::new()
            } else {
                format!("  ({} failed)", counters.failures)
            };
            println!("    {name:<8} {} polls{note}", counters.polls);
        }
    }
    println!();
}

/// Runs `maintain`.
///
/// # Errors
///
/// Returns an error when the database is unreachable, its schema is not one this
/// build can read, or a job fails.
pub async fn maintain(config: &Config, args: &MaintainArgs) -> Result<()> {
    let db = Db::connect(&config.database)?;
    db.require_schema().await?;
    let client = db.client().await?;
    let now = Utc::now();
    let rollup_before = maintenance::cutoff(now, config.maintenance.rollup_after_days);
    let events_before = maintenance::cutoff(now, config.maintenance.event_retention_days);

    println!(
        "Rolling up presence and location before {}, pruning events before {}.",
        rollup_before.format("%Y-%m-%d"),
        events_before.format("%Y-%m-%d")
    );

    if args.dry_run {
        let presence: i64 = db_scalar(
            &client,
            "SELECT COUNT(*) FROM ng_presence
              WHERE is_summary = FALSE AND ended_at IS NOT NULL AND started_at < $1",
            rollup_before,
        )
        .await?;
        let location: i64 = db_scalar(
            &client,
            "SELECT COUNT(*) FROM ng_location_history
              WHERE is_summary = FALSE AND ended_at IS NOT NULL AND started_at < $1",
            rollup_before,
        )
        .await?;
        let events: i64 = db_scalar(
            &client,
            "SELECT COUNT(*) FROM ng_events WHERE \"timestamp\" < $1",
            events_before,
        )
        .await?;
        println!(
            "Dry run: {presence} presence sessions and {location} location stays would be \
             compacted, {events} events would be deleted. Nothing was changed."
        );
        return Ok(());
    }

    let report = maintenance::run(&client, &config.maintenance, now).await?;
    println!("{}", report.summary());
    if report.is_quiet() {
        println!("Nothing needed doing, which is what a healthy database looks like.");
    }
    Ok(())
}

/// Runs a counting query with one timestamp parameter.
async fn db_scalar(
    client: &queries::Client,
    sql: &str,
    before: chrono::DateTime<Utc>,
) -> Result<i64> {
    let row = client.query_one(sql, &[&before]).await?;
    Ok(row.try_get(0)?)
}

/// Runs `update-fingerprints`.
///
/// Downloads a fingerprint table, **parses it before writing anything**, and
/// installs it only if it parses. A vendor serving an error page, a captive
/// portal serving a login form, or a truncated download must not be able to
/// replace a working table with rubbish.
///
/// This is the one command that reaches the internet, it only runs when a person
/// types it, and it never touches the monitored segment.
///
/// # Errors
///
/// Returns an error when no URL is configured, the download fails, the result is
/// not a fingerprint table, or the output file cannot be written.
pub async fn update_fingerprints(config: &Config, args: &UpdateFingerprintsArgs) -> Result<()> {
    let url = args
        .url
        .clone()
        .filter(|u| !u.trim().is_empty())
        .or_else(|| Some(config.identity.fingerprint_url.clone()).filter(|u| !u.trim().is_empty()))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no URL given and identity.fingerprint_url is empty; pass one as an argument"
            )
        })?;
    let path = args
        .output
        .clone()
        .unwrap_or_else(|| config.identity.fingerprint_path.clone());

    println!("Downloading {url}");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .user_agent(concat!("netgraspd/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("could not reach {url}"))?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("{url} returned {status}");
    }
    let text = response
        .text()
        .await
        .context("could not read the response")?;

    let table = FingerprintDb::parse(&text).with_context(|| {
        format!("what {url} returned is not a DHCP fingerprint table; nothing was written")
    })?;
    println!(
        "Parsed {} classes covering {} option lists.",
        table.len(),
        table.list_count()
    );

    if args.dry_run {
        println!("Dry run: {} was not written.", path.display());
        return Ok(());
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
    }
    std::fs::write(&path, text.as_bytes())
        .with_context(|| format!("could not write {}", path.display()))?;
    println!("Wrote {}.", path.display());
    Ok(())
}

/// Turns `run` arguments into daemon options.
#[must_use]
pub const fn run_options(args: &RunArgs) -> RunOptions {
    RunOptions {
        learn: args.learn,
        no_table: args.no_table,
    }
}

#[cfg(test)]
#[allow(clippy::result_large_err)] // Jail::expect_with fixes the closure's error type as
// figment::Error, which clippy considers oversized. Nothing here can change that.
mod tests {
    use super::*;
    use clap::CommandFactory;
    use figment::Jail;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("arguments parse")
    }

    #[test]
    fn the_command_definition_is_internally_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn run_is_the_daemon_command() {
        let cli = parse(&["netgraspd", "run"]);
        assert!(matches!(cli.command, Command::Run(_)));
        assert!(cli.overrides().is_empty(), "no flags means no overrides");
    }

    #[test]
    fn absent_flags_produce_no_overrides() {
        // The whole point of building overrides by hand: a flag the user did not
        // pass must not overwrite the config file with a null.
        for args in [
            vec!["netgraspd", "run"],
            vec!["netgraspd", "devices"],
            vec!["netgraspd", "events"],
        ] {
            assert!(parse(&args).overrides().is_empty(), "{args:?}");
        }
    }

    #[test]
    fn each_flag_maps_to_the_config_key_it_names() {
        let cli = parse(&[
            "netgraspd",
            "--database-url",
            "postgres://x/y",
            "run",
            "-i",
            "eth0",
            "-i",
            "wlan0",
            "--learn-duration",
            "90s",
            "--no-notify",
        ]);
        let overrides = cli.overrides();
        let keys: Vec<&str> = overrides.iter().map(|o| o.key.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "database.url",
                "capture.interfaces",
                "learning.duration",
                "notify.enabled"
            ]
        );
    }

    #[test]
    fn flags_beat_the_config_file_and_the_environment() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "netgrasp.toml",
                "[database]\nurl = \"postgres://from-file/db\"\n\n[learning]\nduration = \"9m\"\n",
            )?;
            jail.set_env("NETGRASP_LEARNING__DURATION", "8m");
            let cli = Cli::try_parse_from([
                "netgraspd",
                "--database-url",
                "postgres://from-flag/db",
                "run",
                "--learn-duration",
                "30s",
            ])
            .expect("parses");
            let config = cli.load_config().expect("loads");
            assert_eq!(config.database.url, "postgres://from-flag/db");
            assert_eq!(config.learning.duration.as_secs(), 30);
            Ok(())
        });
    }

    #[test]
    fn interfaces_from_flags_reach_the_capture_config() {
        Jail::expect_with(|_| {
            let cli = Cli::try_parse_from(["netgraspd", "run", "-i", "eth0", "-i", "eth1"])
                .expect("parses");
            let config = cli.load_config().expect("loads");
            assert_eq!(config.capture.interfaces, vec!["eth0", "eth1"]);
            Ok(())
        });
    }

    #[test]
    fn no_notify_switches_notifications_off_without_touching_anything_else() {
        Jail::expect_with(|_| {
            let cli = Cli::try_parse_from(["netgraspd", "run", "--no-notify"]).expect("parses");
            let config = cli.load_config().expect("loads");
            assert!(!config.notify.enabled);
            assert_eq!(config.notify.debounce.as_secs(), 300, "defaults survive");
            Ok(())
        });
    }

    #[test]
    fn events_defaults_to_fifty() {
        let cli = parse(&["netgraspd", "events"]);
        match cli.command {
            Command::Events(args) => assert_eq!(args.limit, 50),
            other => panic!("expected events, got {other:?}"),
        }
    }

    #[test]
    fn run_options_carry_the_learning_and_table_flags() {
        let cli = parse(&["netgraspd", "run", "--learn", "--no-table"]);
        match &cli.command {
            Command::Run(args) => {
                let opts = run_options(args);
                assert!(opts.learn);
                assert!(opts.no_table);
            }
            other => panic!("expected run, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_invalid_state_filter_is_rejected_before_any_query() {
        let config = Config::default();
        let err = devices(
            &config,
            &DevicesArgs {
                state: Some("asleep".into()),
            },
        )
        .await
        .expect_err("must reject");
        assert!(err.to_string().contains("--state must be"), "{err}");
    }

    #[tokio::test]
    async fn a_non_positive_limit_is_rejected_before_any_query() {
        let config = Config::default();
        for limit in [0, -1] {
            let err = events(
                &config,
                &EventsArgs {
                    limit,
                    security: false,
                },
            )
            .await
            .expect_err("must reject");
            assert!(err.to_string().contains("--limit must be"), "{err}");
        }
    }
}
