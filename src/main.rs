//! `netgraspd`: a passive network device monitor.
//!
//! Watches LAN broadcast and multicast traffic, identifies devices by combining
//! signals from several protocols, tracks a per-device state machine, and alerts
//! when something new appears. It never transmits a packet on the segment it is
//! watching.

use anyhow::Result;
use clap::Parser;
use netgraspd::cli::{self, Cli, Command};
use netgraspd::daemon;
use tokio::signal;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log);

    // Which file, and which database. Every subcommand, before anything
    // connects: a command that quietly answered from the compiled default URL
    // was indistinguishable from one answering from the daemon's own database.
    let (config, source) = cli.load_config_with_source()?;
    cli::log_config_provenance(&source, &config);

    match &cli.command {
        Command::Run(args) => {
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            tokio::spawn(async move {
                wait_for_signal().await;
                tracing::info!("shutdown signal received");
                let _ = shutdown_tx.send(true);
            });

            let summary = daemon::run(&config, cli::run_options(args), shutdown_rx).await?;
            println!();
            println!(
                "Stopped. {} observations ({} duplicates suppressed), {} events, {} devices known.",
                summary.observations, summary.duplicates, summary.events, summary.devices
            );
            Ok(())
        }
        Command::Devices(args) => cli::devices(&config, args).await,
        Command::Events(args) => cli::events(&config, args).await,
        Command::People => cli::people(&config).await,
        Command::Stats => cli::stats(&config).await,
        Command::Maintain(args) => cli::maintain(&config, args).await,
        Command::UpdateFingerprints(args) => cli::update_fingerprints(&config, args).await,
    }
}

/// Installs the tracing subscriber.
///
/// `RUST_LOG` wins over `--log` when it is set, which is the convention every
/// Rust operator already expects. Logs go to stderr so that the live table on
/// stdout stays readable.
fn init_tracing(default_filter: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

/// Resolves on the first shutdown signal.
///
/// SIGTERM matters as much as SIGINT here: the daemon is meant to run under
/// systemd, and a unit that only handles Ctrl-C gets killed rather than stopped.
async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use signal::unix::{SignalKind, signal as unix_signal};
        let mut term = match unix_signal(SignalKind::terminate()) {
            Ok(stream) => stream,
            Err(err) => {
                tracing::warn!(%err, "could not listen for SIGTERM; Ctrl-C only");
                let _ = signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
    }
}
