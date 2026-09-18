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
//! - **enrich** asks the orchestrator whether any enricher is due, which is what
//!   places devices at access points and therefore in rooms.
//! - **maintenance** asks whether the nightly rollup is due. Coarse rather than
//!   a sleep until the configured minute, so a machine suspended over that
//!   minute runs the job when it wakes rather than skipping a day.
//! - **status** rewrites the runtime file `netgraspd stats` reads.

use std::collections::BTreeMap;
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
use crate::enrich::Orchestrator;
use crate::events::EventBus;
use crate::identity::ReverseResolver;
use crate::location::LocationMap;
use crate::maintenance;
use crate::notify::ntfy::NtfyNotifier;
use crate::notify::{Dispatcher, Notifier, deliver};
use crate::people::{self, Registry};
use crate::runtime::Status;
use crate::types::{DeviceState, MacAddr, Observation, Signal, SignalKind};

/// How often the learning-mode progress line is redrawn.
const LEARNING_TICK: Duration = Duration::from_secs(2);

/// How often the live device table is redrawn.
const RENDER_TICK: Duration = Duration::from_secs(2);

/// How often the notifier task closes a due batch window even if nothing new
/// arrived.
const DISPATCH_TICK: Duration = Duration::from_secs(1);

/// How often the daemon asks whether the nightly maintenance job is due.
///
/// Coarse on purpose. Sleeping until the configured minute would mean a machine
/// suspended over that minute skips a day; checking every minute means it runs
/// as soon as it wakes.
const MAINTENANCE_TICK: Duration = Duration::from_secs(60);

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
    /// Observations seen per capture source, before deduplication.
    ///
    /// Before rather than after, because this answers "is this source seeing
    /// traffic at all", and a source whose every packet is a duplicate of
    /// another source's is still working.
    pub sources: BTreeMap<String, u64>,
    /// Location changes applied from enrichment.
    pub location_changes: u64,
    /// Person arrivals and departures recorded.
    pub person_events: u64,
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
    // The schema is a contract with a plugin in another repository, so a
    // divergence is refused here rather than discovered later as a broken page.
    db.preflight().await?;
    install_fingerprints(config);

    // Rehydrate. A restart must not re-announce the whole network.
    let (mut manager, mut persister, mut registry, device_count) = {
        let client = db.client().await?;
        let records = queries::load_devices(&client).await?;
        let signals = queries::load_all_signals(&client).await?;
        let count = records.len();
        let mut persister = Persister::new();
        persister.seed(&records);

        // A device that went offline while the daemon was not running left its
        // location stay open. Close them before anything reads the table.
        match queries::close_stale_location_stays(&client, Utc::now()).await {
            Ok(0) => {}
            Ok(closed) => tracing::info!(closed, "closed location stays left open by a restart"),
            Err(err) => tracing::warn!(%err, "could not close stale location stays"),
        }

        let registry = build_registry(&client, config, &records).await;
        let learning = opts.learn || (config.learning.on_first_run && count == 0);
        let mut manager = Manager::new(config.state.clone(), learning);
        manager.restore(records, signals);
        (manager, persister, registry, count)
    };
    let learning = manager.is_learning();
    tracing::info!(
        devices = device_count,
        learning,
        people = registry.len(),
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

    let enrichers = Orchestrator::from_config(&config.enrichment)?;
    let location_map = LocationMap::from_unifi(&config.enrichment.unifi);
    let enrichment_active = enrichers.is_active();
    if enrichment_active {
        tracing::info!(
            enrichers = ?enrichers.names(),
            mapped_aps = location_map.len(),
            edge_aps = location_map.edge_count(),
            "enrichment running"
        );
    } else {
        tracing::info!("no enrichers are configured; devices will have no location");
    }
    // Enrichment runs in a task of its own rather than inline in the select
    // loop below. An unreachable controller takes the full request timeout twice
    // over, and awaiting that in the loop stops observations being processed for
    // half a minute at a time. Worse, the loop is `biased`: an arm that is
    // always ready and slow starves every arm after it, which is how a
    // misconfigured controller once stopped the maintenance and status ticks
    // firing at all.
    //
    // The shape is the one reverse DNS already uses: hand the work to a task,
    // take the answer back through a channel.
    let (snapshot_tx, snapshot_rx) = mpsc::channel::<Vec<crate::device::DeviceSnapshot>>(1);
    let (enriched_tx, mut enriched_rx) = mpsc::channel::<Enriched>(4);
    // Seeded before the orchestrator moves into the task, so that a configured
    // enricher appears in `netgraspd stats` from the first second with zero
    // polls. The first poll against an unreachable controller takes half a
    // minute to fail, and an empty list until then reads as "none configured".
    let mut enricher_counters: Vec<(String, u64, u64)> = enrichers
        .counters()
        .into_iter()
        .map(|(name, polls, failures)| (name.to_string(), polls, failures))
        .collect();
    let enrich_handle = spawn_enricher(enrichers, snapshot_rx, enriched_tx);

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
    let mut reconcile = ticker(config.state.reconcile_interval.get());
    let mut learning_tick = ticker(LEARNING_TICK);
    let mut render = ticker(RENDER_TICK);
    let mut enrich_tick = ticker(crate::enrich::TICK);
    let mut maintenance_tick = ticker(MAINTENANCE_TICK);
    let mut status_tick = ticker(config.runtime.status_interval.get());
    let learning_deadline = Instant::now() + config.learning.duration.get();
    let show_table = !opts.no_table && std::io::stdout().is_terminal();
    let mut shutdown_rx = shutdown.clone();
    let mut asked_for_rdns: std::collections::HashSet<String> = std::collections::HashSet::new();
    let local_offset = *chrono::Local::now().offset();
    let mut last_maintenance: Option<DateTime<Utc>> = None;
    let started_at = Utc::now();

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

                // Counted before dedup, because this answers "is this source
                // seeing traffic at all" and a source whose every packet
                // duplicates another's is still working.
                *summary.sources.entry(observation.source.to_string()).or_default() += 1;

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

                    registry.device_seen(observation.mac, observation.observed_at);
                    let effects = manager.observe(&observation);
                    let (events, people) = apply_and_track(
                        &db, &mut persister, &bus, &mut manager, &mut registry, &effects,
                    ).await;
                    summary.events += events;
                    summary.person_events += people;
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
                let (events, people) = apply_and_track(
                    &db, &mut persister, &bus, &mut manager, &mut registry, &effects,
                ).await;
                summary.events += events;
                summary.person_events += people;
            }

            _ = flush.tick() => {
                flush_devices(&db, &persister, &mut manager).await;
            }

            // Notice what somebody changed from the web or through the
            // assistant. Nothing else in this loop ever reads those columns
            // again after the rehydrate above, so without this a muted device
            // stays unmuted until the daemon is restarted.
            _ = reconcile.tick() => {
                reconcile_user_state(&db, &mut manager, &mut registry).await;
            }

            // Offer the enrichment task a fresh device list. A bounded channel
            // of one plus try_send is the backpressure: while the task is busy
            // with a slow controller the offer is simply dropped, and the loop
            // carries on processing packets.
            _ = enrich_tick.tick(), if enrichment_active => {
                let _ = snapshot_tx.try_send(manager.snapshot());
            }

            enriched = enriched_rx.recv() => {
                if let Some(enriched) = enriched {
                    enricher_counters = enriched.counters;
                    if !enriched.enrichments.is_empty() {
                        let mut sinks = Sinks {
                            db: &db,
                            persister: &mut persister,
                            bus: &bus,
                            manager: &mut manager,
                            registry: &mut registry,
                        };
                        let applied = apply_enrichments(
                            &mut sinks, &location_map, &enriched.enrichments, Utc::now(),
                        ).await;
                        summary.location_changes += applied.locations;
                        summary.events += applied.events;
                        summary.person_events += applied.person_events;
                    }
                }
            }

            _ = maintenance_tick.tick() => {
                if maintenance::is_due(
                    &config.maintenance, Utc::now(), last_maintenance, local_offset,
                ) {
                    last_maintenance = Some(Utc::now());
                    run_maintenance(&db, &config.maintenance).await;
                }
            }

            _ = status_tick.tick() => {
                write_status(
                    config, started_at, &summary, &manager, &dedup, &enricher_counters,
                    analyzers.gateway().proxied().len(),
                );
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

    // Dropping the sender is what tells the enrichment task to stop. It is not
    // awaited: a poll against an unreachable controller has up to a request
    // timeout left to run, and shutdown should not wait for a machine that is
    // not answering. Nothing it could still produce is worth blocking on.
    drop(snapshot_tx);
    enrich_handle.abort();

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

/// Applies effects, then feeds the presence transitions among them to the people
/// registry and records whatever it made of them.
///
/// Presence is the signal rather than the `returned` and `went_offline` events,
/// because `PresenceOpened` and `PresenceClosed` are exactly "this device is now
/// online" and "this device is now offline" with no other meaning attached, and
/// a discovery opens a session without producing a `returned`.
///
/// Returns the number of ordinary events and the number of person events
/// recorded.
async fn apply_and_track(
    db: &Db,
    persister: &mut Persister,
    bus: &EventBus,
    manager: &mut Manager,
    registry: &mut Registry,
    effects: &[Effect],
) -> (u64, u64) {
    let events = apply(db, persister, bus, effects).await;
    if !registry.is_active() {
        return (events, 0);
    }
    let mut outcome = people::Outcome::default();
    for effect in effects {
        match effect {
            Effect::PresenceOpened { mac, at, .. } => {
                outcome.merge(registry.device_online(*mac, *at));
            }
            Effect::PresenceClosed { mac, at } => {
                outcome.merge(registry.device_offline(*mac, *at));
            }
            _ => {}
        }
    }
    let people = record_people(db, persister, bus, manager, &outcome).await;
    (events, people)
}

/// Writes the people the registry changed and records the events it produced.
///
/// Returns how many person events were recorded.
async fn record_people(
    db: &Db,
    persister: &mut Persister,
    bus: &EventBus,
    manager: &Manager,
    outcome: &people::Outcome,
) -> u64 {
    if outcome.is_empty() {
        return 0;
    }
    if let Ok(client) = db.client().await {
        for update in &outcome.updates {
            if let Err(err) = queries::update_person(
                &client,
                &update.item_id,
                update.state.as_str(),
                update.current_location.as_deref(),
                update.last_arrived_at,
                update.last_departed_at,
            )
            .await
            {
                tracing::warn!(person = %update.item_id, %err, "could not update a person");
            }
        }
    } else {
        tracing::warn!("could not write people: no database connection");
    }

    let mut recorded = 0;
    for event in &outcome.events {
        tracing::info!(
            event = %event.event_type,
            person = %event.name,
            details = %event.details,
            "person event"
        );
        let effects = manager.person_event(event);
        recorded += apply(db, persister, bus, &effects).await;
    }
    recorded
}

/// What one round of enrichment produced.
#[derive(Debug, Default)]
struct Applied {
    /// Devices that moved.
    locations: u64,
    /// Events recorded for those moves.
    events: u64,
    /// Person events recorded as a consequence.
    person_events: u64,
}

/// Everything one round of work writes to.
///
/// Bundled rather than passed as five arguments because they always travel
/// together and always in the same order, and a five-argument list of borrows is
/// where a `&mut` ends up pointing at the wrong thing.
struct Sinks<'a> {
    /// The connection pool.
    db: &'a Db,
    /// The MAC-to-id map.
    persister: &'a mut Persister,
    /// The event bus.
    bus: &'a EventBus,
    /// The device state machine.
    manager: &'a mut Manager,
    /// The people registry.
    registry: &'a mut Registry,
}

/// Turns enrichments into location stays, device events and person events.
async fn apply_enrichments(
    sinks: &mut Sinks<'_>,
    map: &LocationMap,
    enrichments: &[crate::enrich::Enrichment],
    now: DateTime<Utc>,
) -> Applied {
    let mut applied = Applied::default();
    let mut outcome = people::Outcome::default();
    for enrichment in enrichments {
        // A source that knows the place itself overrides the operator's map;
        // one that only knows the access point goes through it.
        let Some(ap) = enrichment.ap_name.as_deref() else {
            continue;
        };
        let mut place = map.place(ap);
        if let Some(location) = enrichment.ap_location.as_deref()
            && !location.trim().is_empty()
        {
            place.location = location.trim().to_string();
        }
        let previous = sinks.manager.current_ap(enrichment.mac);
        let movement = map.movement(previous.as_deref(), &place.ap_name);

        let effects = sinks.manager.set_location(
            enrichment.mac,
            &place,
            movement,
            enrichment.telemetry(),
            now,
        );
        if effects.is_empty() {
            // Already on that access point. An enricher polling every thirty
            // seconds says so every time, and turning each into a stay would be
            // the row-per-observation failure this daemon exists to avoid.
            continue;
        }
        applied.locations += 1;
        applied.events += apply(sinks.db, sinks.persister, sinks.bus, &effects).await;
        if sinks.registry.is_active() {
            outcome.merge(
                sinks
                    .registry
                    .device_moved(enrichment.mac, &place, movement, now),
            );
        }
    }
    applied.person_events = record_people(
        sinks.db,
        sinks.persister,
        sinks.bus,
        sinks.manager,
        &outcome,
    )
    .await;
    applied
}

/// One round of enrichment, as the enrichment task hands it back.
#[derive(Debug)]
struct Enriched {
    /// What the enrichers found.
    enrichments: Vec<crate::enrich::Enrichment>,
    /// Poll and failure counts per enricher, carried along because the
    /// orchestrator lives in the task and `netgraspd stats` needs them here.
    counters: Vec<(String, u64, u64)>,
}

/// Owns the orchestrator and polls it off the main loop.
///
/// Takes device lists in and hands results back, so that a controller which
/// takes half a minute to time out cannot stop the daemon processing packets.
/// The task ends when the main loop drops its sender, which is shutdown.
fn spawn_enricher(
    mut enrichers: Orchestrator,
    mut snapshots: mpsc::Receiver<Vec<crate::device::DeviceSnapshot>>,
    results: mpsc::Sender<Enriched>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(devices) = snapshots.recv().await {
            let enrichments = enrichers.poll_due(Instant::now(), &devices).await;
            let counters = enrichers
                .counters()
                .into_iter()
                .map(|(name, polls, failures)| (name.to_string(), polls, failures))
                .collect();
            // Nothing found is still worth sending: the counters are how
            // `netgraspd stats` shows an enricher that is failing every time.
            if results
                .send(Enriched {
                    enrichments,
                    counters,
                })
                .await
                .is_err()
            {
                return;
            }
        }
    })
}

/// Runs the nightly maintenance job, logging rather than propagating a failure.
///
/// A rollup that fails is a database that grows for another day. Stopping the
/// daemon over it would be a monitor that stops watching the network because it
/// could not tidy up, which is the wrong trade every time.
async fn run_maintenance(db: &Db, config: &crate::config::MaintenanceConfig) {
    let client = match db.client().await {
        Ok(client) => client,
        Err(err) => {
            tracing::error!(%err, "maintenance skipped: no database connection");
            return;
        }
    };
    match maintenance::run(&client, config, Utc::now()).await {
        Ok(report) => tracing::info!(summary = %report.summary(), "nightly maintenance complete"),
        Err(err) => tracing::error!(%err, "nightly maintenance failed"),
    }
}

/// Rewrites the runtime status file that `netgraspd stats` reads.
///
/// A path that cannot be written is logged at debug and otherwise ignored: an
/// operator who has not created `/var/lib/netgraspd` should get a daemon that
/// watches the network, not one that complains once a minute.
fn write_status(
    config: &Config,
    started_at: DateTime<Utc>,
    summary: &RunSummary,
    manager: &Manager,
    dedup: &ObservationDedup,
    enricher_counters: &[(String, u64, u64)],
    proxy_arp_addresses: usize,
) {
    let (online, idle, offline) = manager.state_counts();
    let mut status = Status::new(started_at);
    status.updated_at = Utc::now();
    status.learning = manager.is_learning();
    status.observations = summary.observations;
    status.duplicates = dedup.duplicates_suppressed();
    status.events = summary.events;
    status.security_events = summary.security_events;
    status.unattributed_names = manager.unattributed_claims();
    status.proxy_arp_addresses = proxy_arp_addresses;
    status.devices = manager.len();
    status.online = online;
    status.idle = idle;
    status.offline = offline;
    status.sources = summary.sources.clone();
    status.enrichers = enricher_counters
        .iter()
        .map(|(name, polls, failures)| {
            (
                name.clone(),
                crate::runtime::EnricherCounters {
                    polls: *polls,
                    failures: *failures,
                },
            )
        })
        .collect();
    status.resident_bytes = crate::runtime::resident_bytes();

    if let Err(err) = status.write(&config.runtime.status_path) {
        tracing::debug!(
            path = %config.runtime.status_path.display(),
            %err,
            "could not write the runtime status file"
        );
    }
}

/// Builds the people registry from configuration and from the database.
///
/// Configuration is applied first and the database wins on conflict, because the
/// database is what somebody edited most recently through an admin UI, and a
/// config file that has not been touched since the install should not undo it.
///
/// Every failure here is a warning rather than an error: a daemon that refuses
/// to watch the network because it could not work out who owns a phone is worse
/// than one that watches the network and knows about nobody.
async fn build_registry(
    client: &queries::Client,
    config: &Config,
    records: &[queries::DeviceRecord],
) -> Registry {
    let mut owners: Vec<(MacAddr, String)> = Vec::new();
    let mut config_owners: Vec<(MacAddr, String)> = Vec::new();

    for person in &config.people {
        let name = person.name.trim();
        match queries::ensure_person(client, name, person.notify_arrive, person.notify_depart).await
        {
            Ok(item_id) => {
                for mac in person.macs() {
                    owners.push((mac, item_id.clone()));
                    config_owners.push((mac, item_id.clone()));
                }
            }
            Err(err) => tracing::warn!(person = name, %err, "could not create or adopt a person"),
        }
    }

    // The database wins: pushed after configuration, and the registry keeps the
    // last owner recorded for a MAC.
    for record in records {
        if let Some(item_id) = &record.owner_item_id {
            owners.push((record.mac, item_id.clone()));
        }
    }

    let people = match queries::load_people(client).await {
        Ok(rows) => rows.into_iter().map(person_from_record).collect(),
        Err(err) => {
            tracing::warn!(%err, "could not load people; nobody will be tracked");
            Vec::new()
        }
    };

    let mut registry = people::Roster {
        people,
        owners,
        config_owners,
    }
    .into_registry();
    // Seed device states without announcing anything: the whole household being
    // home is not news every time the daemon restarts.
    for record in records {
        registry.restore_device(
            record.mac,
            record.state != DeviceState::Offline,
            record.last_seen_at,
        );
    }
    registry
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

/// Reads the user-owned columns back and folds them into memory.
///
/// The daemon owns state; a person owns the name, the notes, the hidden flag,
/// the notify toggle and who a device belongs to. This is the only place the
/// second half travels from Postgres into a running daemon, and it travels in
/// that direction only.
///
/// Polling rather than `LISTEN`. The daemon's connections come from a pool whose
/// driver task consumes asynchronous messages itself, so a notification never
/// reaches a pooled client: `LISTEN` would mean a dedicated connection outside
/// the pool *and* a `NOTIFY` the plugin does not send today, which is a contract
/// line two repositories would have to agree on. The read it replaces costs
/// under a millisecond of server time for a couple of thousand devices, so the
/// poll buys responsiveness for nothing. `ARCHITECTURE.md` records the `LISTEN`
/// design for the day the plugin can send one.
///
/// Every failure is a warning rather than an error, for the reason every other
/// database failure in this file is: a daemon that stops watching the network
/// because it could not re-read a checkbox is the wrong trade.
///
/// Public because the integration suite drives this exact function against a
/// real Postgres rather than a copy of it: a reconcile that only a copy exercises
/// is a reconcile nothing tests.
pub async fn reconcile_user_state(db: &Db, manager: &mut Manager, registry: &mut Registry) {
    let client = match db.client().await {
        Ok(client) => client,
        Err(err) => {
            tracing::warn!(%err, "reconcile skipped: no database connection");
            return;
        }
    };
    let settings = match queries::load_user_settings(&client).await {
        Ok(settings) => settings,
        Err(err) => {
            tracing::warn!(%err, "could not read the user-owned device columns");
            return;
        }
    };
    let people = match queries::load_people(&client).await {
        Ok(rows) => rows.into_iter().map(person_from_record).collect(),
        Err(err) => {
            tracing::warn!(%err, "could not read people; ownership is unchanged this tick");
            return;
        }
    };

    for change in manager.apply_user_settings(&settings) {
        tracing::info!(
            mac = %change.mac,
            column = change.column,
            from = %change.from,
            to = %change.to,
            "a user-owned device setting changed"
        );
    }

    let owners: Vec<(MacAddr, Option<String>)> = settings
        .iter()
        .map(|setting| (setting.mac, setting.owner_item_id.clone()))
        .collect();
    let changes = registry.reconcile(people, &owners);
    for change in &changes {
        match change {
            people::RegistryChange::PersonAdded { item_id, name } => {
                tracing::info!(person = %name, item_id = %item_id, "a person appeared");
            }
            people::RegistryChange::PersonEdited {
                item_id,
                name,
                fields,
            } => {
                tracing::info!(
                    person = %name,
                    item_id = %item_id,
                    changed = %fields.join(", "),
                    "a person changed"
                );
            }
            people::RegistryChange::PersonRemoved { item_id, name } => {
                tracing::info!(person = %name, item_id = %item_id, "a person went away");
            }
            people::RegistryChange::OwnerChanged { mac, from, to } => {
                tracing::info!(
                    %mac,
                    from = from.as_deref().unwrap_or("nobody"),
                    to = to.as_deref().unwrap_or("nobody"),
                    "a device changed owner"
                );
                // Seed the new owner's view of the device from the device table,
                // silently. A restart does exactly this, and announcing that
                // somebody arrived because a phone that was already online has
                // just been assigned to them would be a lie with a notification
                // attached.
                if to.is_some()
                    && let Some((state, last_seen_at)) = manager.state_of(*mac)
                {
                    registry.restore_device(*mac, state != DeviceState::Offline, last_seen_at);
                }
            }
        }
    }
    if changes.is_empty() {
        tracing::debug!(
            devices = settings.len(),
            people = registry.len(),
            "reconciled; nothing had changed"
        );
    }
}

/// Turns a stored person into the registry's view of them.
fn person_from_record(row: queries::PersonRecord) -> people::Person {
    people::Person {
        item_id: row.item_id,
        name: row.name,
        notify_arrive: row.notify_arrive,
        notify_depart: row.notify_depart,
        state: people::PersonState::from_db(&row.state),
        current_location: row.current_location,
        last_arrived_at: row.last_arrived_at,
        last_departed_at: row.last_departed_at,
    }
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
