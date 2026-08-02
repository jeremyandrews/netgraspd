//! Command-line surface.
//!
//! Three commands: `run` starts the daemon with a live device table, `devices`
//! prints the table once and exits, `events` prints the recent event log.
//!
//! Every flag that overrides configuration is expressed as a dotted
//! [`Override`] rather than as a partial `Config`, so that an absent flag leaves
//! the layer beneath it alone instead of overwriting it with a null.

pub mod table;

use std::path::PathBuf;

use anyhow::Result;
use chrono::Utc;
use clap::{Args, Parser, Subcommand};

use crate::config::{Config, Override};
use crate::daemon::RunOptions;
use crate::db::{Db, queries};

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
}

/// Runs `devices`.
///
/// # Errors
///
/// Returns an error when the database is unreachable or the state filter is not
/// a state.
pub async fn devices(config: &Config, args: &DevicesArgs) -> Result<()> {
    if let Some(state) = &args.state
        && !["online", "idle", "offline"].contains(&state.as_str())
    {
        anyhow::bail!("--state must be online, idle or offline, not {state:?}");
    }

    let db = Db::connect(&config.database)?;
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
/// Returns an error when the database is unreachable or the limit is not
/// positive.
pub async fn events(config: &Config, args: &EventsArgs) -> Result<()> {
    if args.limit <= 0 {
        anyhow::bail!("--limit must be at least 1");
    }
    let db = Db::connect(&config.database)?;
    let client = db.client().await?;
    let records = queries::recent_events(&client, args.limit).await?;
    if records.is_empty() {
        println!("No events recorded yet.");
        return Ok(());
    }
    print!("{}", table::event_table(&records, Utc::now()));
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
            let err = events(&config, &EventsArgs { limit })
                .await
                .expect_err("must reject");
            assert!(err.to_string().contains("--limit must be"), "{err}");
        }
    }
}
