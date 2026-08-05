//! The daemon runtime: everything wired together and turning.
//!
//! One task owns the state machine and drains the observation channel; separate
//! tasks own capture (one blocking thread per interface per source) and
//! notification delivery. The state machine is never shared across tasks, so
//! there is no lock on the hot path.
//!
//! Timers, all configurable:
//!
//! - **sweep** applies idle and offline timeouts.
//! - **flush** writes changed devices to Postgres. A crash loses at most one
//!   flush interval of `last_seen_at` precision, never a state change: those go
//!   to `ng_events` the moment they happen.
//! - **learning** ends the baseline window.
//! - **render** redraws the live table when stdout is a terminal.

use std::io::{IsTerminal, Write};
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use tokio::sync::{broadcast, mpsc, watch};
use tokio::time::{Instant, MissedTickBehavior, interval_at};

use crate::analyze::Chain;
use crate::capture::{self, ObservationDedup};
use crate::cli::table;
use crate::config::Config;
use crate::db::{Db, queries};
use crate::device::persist::Persister;
use crate::device::{Effect, Manager};
use crate::events::EventBus;
use crate::identity::ReverseResolver;
use crate::notify::ntfy::NtfyNotifier;
use crate::notify::{Dispatcher, Notifier, deliver};
use crate::types::{MacAddr, Observation, Signal, SignalKind};

/// How often the learning-mode progress line is redrawn.
const LEARNING_TICK: Duration = Duration::from_secs(2);

/// How often the live device table is redrawn.
const RENDER_TICK: Duration = Duration::from_secs(2);

/// How often the notifier task closes a due batch window even if nothing new
/// arrived.
const DISPATCH_TICK: Duration = Duration::from_secs(1);

/// Options that come from the command line rather than the config file.
#[derive(Debug, Clone, Copy, Default)]
pub struct RunOptions {
    /// Force a learning window even when devices are already known.
    pub learn: bool,
    /// Suppress the live table even on a terminal.
    pub no_table: bool,
}

/// What a run did, reported when it stops.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunSummary {
    /// Observations accepted after dedup.
    pub observations: u64,
    /// Observations discarded as duplicates.
    pub duplicates: u64,
    /// Events recorded.
    pub events: u64,
    /// Security events recorded, which are a subset of `events`.
    pub security_events: u64,
    /// Devices known when the run ended.
    pub devices: usize,
    /// Whether a learning window ran.
    pub learned: bool,
}

/// Starts capture, processes observations, and returns when shutdown is
/// signalled.
///
/// # Errors
///
/// Returns an error when the database is unreachable, the schema cannot be
/// migrated, no interface can be captured on, or a capture source fails to
/// start.
pub async fn run(
    config: &Config,
    opts: RunOptions,
    shutdown: watch::Receiver<bool>,
) -> Result<RunSummary> {
    let db = Db::connect(&config.database)?;
    Db::migrate(&config.database.url).await?;
    db.health_check().await?;
    install_fingerprints(config);

    // Rehydrate. A restart must not re-announce the whole network.
    let (mut manager, mut persister, device_count) = {
        let client = db.client().await?;
        let records = queries::load_devices(&client).await?;
        let signals = queries::load_all_signals(&client).await?;
        let count = records.len();
        let mut persister = Persister::new();
        persister.seed(&records);
        let learning = opts.learn || (config.learning.on_first_run && count == 0);
        let mut manager = Manager::new(config.state.clone(), learning);
        manager.restore(records, signals);
        (manager, persister, count)
    };
    let learning = manager.is_learning();
    tracing::info!(
        devices = device_count,
        learning,
        "restored device table from Postgres"
    );

    let interfaces = capture::resolve_interfaces(&config.capture.interfaces)?;
    let first = interfaces
        .first()
        .context("no capture interfaces resolved")?
        .clone();
    capture::check_capture_permission(&first)?;
    tracing::info!(interfaces = ?interfaces, "capture permission confirmed");

    let (obs_tx, mut obs_rx) = mpsc::channel::<Observation>(config.capture.channel_capacity);
    let mut source_handles = Vec::new();
    for source in capture::build_sources(&config.capture, &interfaces)? {
        let name = source.name().to_string();
        source_handles.push((name, source.run(obs_tx.clone(), shutdown.clone())));
    }
    // The pipeline holds no sender of its own, so the channel closes when every
    // capture source has stopped.
    drop(obs_tx);

    let bus = EventBus::default();
    let notifier_handle = spawn_notifier(config, &db, &bus, shutdown.clone());

    // Reverse DNS answers arrive out of band and re-enter the state machine as
    // ordinary signals.
    let (signal_tx, mut signal_rx) = mpsc::channel::<(MacAddr, Signal, DateTime<Utc>)>(256);
    let resolver = if config.identity.reverse_dns {
        match ReverseResolver::from_system(config.identity.reverse_dns_ttl.get()) {
            Ok(resolver) => Some(resolver),
            Err(err) => {
                tracing::warn!(%err, "reverse DNS is enabled but no resolver could be built");
                None
            }
        }
    } else {
        None
    };

    let mut dedup = ObservationDedup::new(
        config.capture.dedup_capacity,
        config.capture.dedup_resolution_secs,
    );
    let mut analyzers = Chain::new(&config.security);
    if analyzers.is_active() {
        tracing::info!(analyzers = ?analyzers.names(), "security analyzers running");
    } else {
        tracing::info!("security analyzers are disabled");
    }
    let mut summary = RunSummary {
        learned: learning,
        ..RunSummary::default()
    };

    let mut sweep = ticker(config.state.sweep_interval.get());
    let mut flush = ticker(config.state.flush_interval.get());
    let mut learning_tick = ticker(LEARNING_TICK);
    let mut render = ticker(RENDER_TICK);
    let learning_deadline = Instant::now() + config.learning.duration.get();
    let show_table = !opts.no_table && std::io::stdout().is_terminal();
    let mut shutdown_rx = shutdown.clone();
    let mut asked_for_rdns: std::collections::HashSet<String> = std::collections::HashSet::new();

    loop {
        tokio::select! {
            // Biased so that shutdown is noticed even on a busy network.
            biased;

            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }

            observation = obs_rx.recv() => {
                let Some(observation) = observation else {
                    tracing::info!("every capture source has stopped");
                    break;
                };

                // The state machine runs first, on the deduplicated stream, so
                // that a brand-new attacker's device row exists before any alert
                // about it is recorded and the event can carry a device_id.
                if dedup.admit(&observation) {
                    summary.observations += 1;

                    if let (Some(resolver), Some(ip)) = (resolver.as_ref(), observation.ip)
                        && ip.is_ipv4()
                        && asked_for_rdns.insert(ip.to_string())
                    {
                        spawn_reverse_lookup(
                            resolver.clone(),
                            observation.mac,
                            ip,
                            signal_tx.clone(),
                        );
                    }

                    let effects = manager.observe(&observation);
                    summary.events += apply(&db, &mut persister, &bus, &effects).await;
                }

                // The analyzers see *every* observation, deduplicated or not.
                // Dedup collapses on (MAC, kind, second), which is exactly the
                // shape of a scan burst: two hundred ARP requests in one second
                // are one observation to the state machine and are the whole
                // signal to arp_scan.
                summary.security_events += analyze(
                    &db, &mut persister, &bus, &mut analyzers, &mut manager, &observation,
                ).await;
            }

            signal = signal_rx.recv() => {
                if let Some((mac, signal, at)) = signal {
                    let effects = manager.add_signal(mac, &signal, at);
                    summary.events += apply(&db, &mut persister, &bus, &effects).await;
                    summary.security_events += drain_reclassifications(
                        &db, &mut persister, &bus, &mut analyzers, &mut manager,
                    ).await;
                }
            }

            _ = sweep.tick() => {
                let effects = manager.sweep(Utc::now());
                summary.events += apply(&db, &mut persister, &bus, &effects).await;
            }

            _ = flush.tick() => {
                flush_devices(&db, &persister, &mut manager).await;
            }

            _ = learning_tick.tick(), if manager.is_learning() => {
                if Instant::now() >= learning_deadline {
                    manager.end_learning();
                    finish_learning(&db, &manager).await;
                } else if show_table {
                    print_learning_progress(&manager, learning_deadline);
                }
            }

            _ = render.tick(), if show_table => {
                if !manager.is_learning() {
                    draw(&manager, &dedup);
                }
            }
        }
    }

    tracing::info!("shutting down");
    flush_devices(&db, &persister, &mut manager).await;
    summary.devices = manager.len();
    summary.duplicates = dedup.duplicates_suppressed();

    for (name, handle) in source_handles {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                tracing::warn!(source = %name, %err, "capture source ended with an error")
            }
            Err(err) => tracing::warn!(source = %name, %err, "capture source did not stop cleanly"),
        }
    }
    if let Err(err) = notifier_handle.await {
        tracing::warn!(%err, "notifier task did not stop cleanly");
    }
    Ok(summary)
}

/// Applies effects and publishes the events they produced. Returns how many
/// events were recorded.
///
/// A database failure here is logged rather than propagated: losing a write is
/// bad, but stopping the daemon because Postgres hiccupped is worse for a
/// monitor whose job is to keep watching.
async fn apply(db: &Db, persister: &mut Persister, bus: &EventBus, effects: &[Effect]) -> u64 {
    if effects.is_empty() {
        return 0;
    }
    let client = match db.client().await {
        Ok(client) => client,
        Err(err) => {
            tracing::error!(%err, effects = effects.len(), "dropping effects: no database connection");
            return 0;
        }
    };
    match persister.apply(&client, effects).await {
        Ok(recorded) => {
            let count = recorded.len() as u64;
            bus.publish_all(recorded);
            count
        }
        Err(err) => {
            tracing::error!(%err, "applying effects failed");
            0
        }
    }
}

/// Installs the DHCP fingerprint table, preferring a downloaded one.
///
/// A missing file is the normal case, not an error: the embedded table ships
/// with the binary and `netgraspd update-fingerprints` is the only thing that
/// ever writes the other one. A file that exists but does not parse *is* worth a
/// warning, because it means somebody put something there on purpose and it is
/// silently doing nothing.
fn install_fingerprints(config: &Config) {
    let path = &config.identity.fingerprint_path;
    let table = if path.exists() {
        match crate::identity::FingerprintDb::from_file(path) {
            Ok(table) => {
                tracing::info!(
                    path = %path.display(),
                    classes = table.len(),
                    lists = table.list_count(),
                    "loaded the downloaded DHCP fingerprint table"
                );
                table
            }
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    %err,
                    "the downloaded fingerprint table is unusable; falling back to the embedded one"
                );
                crate::identity::FingerprintDb::embedded()
            }
        }
    } else {
        crate::identity::FingerprintDb::embedded()
    };
    if !crate::identity::fingerprint::install(table) {
        tracing::debug!("a fingerprint table was already installed");
    }
}

/// Runs the analyzer chain over one observation and records what it found.
///
/// Also drains the classification changes the state machine queued while
/// handling the same observation, because `identity_change` watches those rather
/// than the wire. Returns how many security events were recorded.
async fn analyze(
    db: &Db,
    persister: &mut Persister,
    bus: &EventBus,
    analyzers: &mut Chain,
    manager: &mut Manager,
    observation: &Observation,
) -> u64 {
    let mut recorded = 0;
    for alert in analyzers.observe(observation) {
        tracing::warn!(
            event = %alert.event_type,
            mac = %alert.mac,
            details = %alert.details,
            "security event"
        );
        let effects = manager.security_event(&alert);
        recorded += apply(db, persister, bus, &effects).await;
    }
    recorded + drain_reclassifications(db, persister, bus, analyzers, manager).await
}

/// Feeds queued classification changes to the chain and records what it found.
async fn drain_reclassifications(
    db: &Db,
    persister: &mut Persister,
    bus: &EventBus,
    analyzers: &mut Chain,
    manager: &mut Manager,
) -> u64 {
    let mut recorded = 0;
    for change in manager.take_reclassifications() {
        for alert in analyzers.reclassified(&change) {
            tracing::warn!(
                event = %alert.event_type,
                mac = %alert.mac,
                details = %alert.details,
                "security event"
            );
            let effects = manager.security_event(&alert);
            recorded += apply(db, persister, bus, &effects).await;
        }
    }
    recorded
}

/// Writes changed devices to Postgres.
async fn flush_devices(db: &Db, persister: &Persister, manager: &mut Manager) {
    let dirty = manager.take_dirty();
    if dirty.is_empty() {
        return;
    }
    let client = match db.client().await {
        Ok(client) => client,
        Err(err) => {
            tracing::error!(%err, devices = dirty.len(), "flush skipped: no database connection");
            return;
        }
    };
    if let Err(err) = persister.flush(&client, &dirty).await {
        tracing::error!(%err, "flush failed");
    }
}

/// Spawns the task that turns recorded events into notifications.
fn spawn_notifier(
    config: &Config,
    db: &Db,
    bus: &EventBus,
    shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let mut dispatcher =
        Dispatcher::with_local_offset(config.notify.clone(), config.security.notifications.clone());
    let mut notifiers: Vec<Box<dyn Notifier>> = Vec::new();
    if let Some(ntfy) = &config.notify.ntfy {
        match NtfyNotifier::new(ntfy) {
            Ok(notifier) => {
                tracing::info!(notifier = notifier.name(), "notifier configured");
                notifiers.push(Box::new(notifier));
            }
            Err(err) => tracing::warn!(%err, "ntfy is configured but unusable"),
        }
    }
    if notifiers.is_empty() {
        tracing::info!("no notifier is configured; events are recorded but not delivered");
    }

    let mut rx = bus.subscribe();
    let db = db.clone();
    let mut shutdown_rx = shutdown;

    tokio::spawn(async move {
        let mut tick = ticker(DISPATCH_TICK);
        loop {
            let deliveries = tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        // Send whatever is held rather than losing it.
                        let final_batch = dispatcher.drain();
                        send_all(&notifiers, &db, &final_batch).await;
                        return;
                    }
                    Vec::new()
                }
                event = rx.recv() => match event {
                    Ok(event) => dispatcher.offer(event, Utc::now()),
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "the notifier fell behind the event bus");
                        Vec::new()
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        let final_batch = dispatcher.drain();
                        send_all(&notifiers, &db, &final_batch).await;
                        return;
                    }
                },
                _ = tick.tick() => dispatcher.tick(Utc::now()),
            };
            send_all(&notifiers, &db, &deliveries).await;
        }
    })
}

/// Delivers each decision through every notifier, marking events as notified
/// when at least one transport accepted them.
async fn send_all(
    notifiers: &[Box<dyn Notifier>],
    db: &Db,
    deliveries: &[crate::notify::Delivery],
) {
    for delivery in deliveries {
        let mut delivered = false;
        for notifier in notifiers {
            delivered |= deliver(notifier.as_ref(), delivery).await;
        }
        if !delivered {
            continue;
        }
        let Ok(client) = db.client().await else {
            tracing::warn!("could not mark events notified: no database connection");
            continue;
        };
        for event in delivery.events() {
            if let Err(err) = queries::mark_event_notified(&client, event.id).await {
                tracing::warn!(event_id = event.id, %err, "could not mark an event notified");
            }
        }
    }
}

/// Resolves one address and feeds the answer back as a signal.
fn spawn_reverse_lookup(
    resolver: ReverseResolver,
    mac: MacAddr,
    ip: std::net::IpAddr,
    tx: mpsc::Sender<(MacAddr, Signal, DateTime<Utc>)>,
) {
    tokio::spawn(async move {
        if let Some(name) = resolver.lookup(ip).await {
            let _ = tx
                .send((mac, Signal::new(SignalKind::ReverseDns, name), Utc::now()))
                .await;
        }
    });
}

/// Builds a timer that does not try to catch up after a slow cycle.
fn ticker(period: Duration) -> tokio::time::Interval {
    let period = period.max(Duration::from_millis(100));
    let mut interval = interval_at(Instant::now() + period, period);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval
}

/// Prints the learning-mode progress line, in place.
fn print_learning_progress(manager: &Manager, deadline: Instant) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let (mins, secs) = (remaining.as_secs() / 60, remaining.as_secs() % 60);
    print!(
        "\r\u{1b}[KLearning network... {} devices found, {mins}:{secs:02} remaining",
        manager.len()
    );
    let _ = std::io::stdout().flush();
}

/// Prints the learning-mode completion summary.
async fn finish_learning(db: &Db, manager: &Manager) {
    let (online, idle, offline) = manager.state_counts();
    println!(
        "\r\u{1b}[KLearning complete: {} devices on the baseline ({online} online, {idle} idle, {offline} offline).",
        manager.len()
    );
    println!("New devices from now on will notify.");
    if let Ok(client) = db.client().await
        && let Ok(recorded) =
            queries::count_events_of_type(&client, crate::types::EventType::NewDevice).await
    {
        println!("{recorded} discovery events were recorded during the window (none notified).");
    }
}

/// Redraws the live device table.
fn draw(manager: &Manager, dedup: &ObservationDedup) {
    let now = Utc::now();
    let devices = manager.snapshot();
    let (online, idle, offline) = manager.state_counts();
    // Home the cursor and clear to the end of the screen, rather than clearing
    // first, so the table does not flicker.
    print!("\u{1b}[H\u{1b}[J");
    println!(
        "netgraspd  {} devices  {online} online  {idle} idle  {offline} offline  {} duplicates suppressed",
        devices.len(),
        dedup.duplicates_suppressed()
    );
    println!();
    print!("{}", table::device_table(&devices, now));
    let _ = std::io::stdout().flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_ticker_never_has_a_zero_period() {
        // A zero interval would spin the select loop at full speed, so the
        // floor is what stops a misconfigured interval from burning a core.
        let mut zero = ticker(Duration::ZERO);
        let start = Instant::now();
        zero.tick().await;
        assert!(
            start.elapsed() >= Duration::from_millis(50),
            "a zero period must be clamped, not honoured"
        );
    }

    #[tokio::test]
    async fn run_options_default_to_no_forced_learning_and_a_table() {
        let opts = RunOptions::default();
        assert!(!opts.learn);
        assert!(!opts.no_table);
    }

    #[test]
    fn a_run_summary_starts_empty() {
        let s = RunSummary::default();
        assert_eq!(s.observations, 0);
        assert_eq!(s.events, 0);
        assert!(!s.learned);
    }
}
