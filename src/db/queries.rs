//! Hand-written queries over the `ng_*` tables.
//!
//! Two rules govern everything here.
//!
//! 1. **The daemon never writes `ng_devices.display_name`, `notes`, `hidden` or
//!    `notify`.** Those four columns belong to the user, through the Trovato
//!    admin UI, and every UPDATE in this file names its columns explicitly so
//!    that a careless `SELECT *`-shaped write cannot clobber them. It does
//!    *read* them, and not only at startup: [`load_user_settings`] is what the
//!    daemon's reconcile tick uses to notice a change made from the web without
//!    being restarted.
//! 2. **Every daemon write sets `sync_state = 'dirty'`.** That is the contract
//!    stub the Trovato plugin's cron sweep consumes. Nothing here reads it.
//!
//! `ng_events.timestamp` is named after a Postgres type, so every reference to
//! it is double-quoted.

use std::collections::HashMap;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde_json::Value as Json;
use tokio_postgres::Row;

use crate::types::{DeviceState, EventType, MacAddr, Signal, SignalKind};

/// Anything that can run a query: a pooled client or a transaction.
pub type Client = tokio_postgres::Client;

/// One row of `ng_devices`.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceRecord {
    /// Primary key.
    pub id: i64,
    /// Hardware address, the join key with Trovato.
    pub mac: MacAddr,
    /// User-assigned name. The daemon never writes this.
    pub display_name: Option<String>,
    /// Name the identity scorer picked.
    pub resolved_name: Option<String>,
    /// Which signal kind produced `resolved_name`.
    pub identity_source: Option<String>,
    /// Weight of that signal kind.
    pub identity_confidence: Option<f32>,
    /// Best reverse-DNS or mDNS host name seen.
    pub hostname: Option<String>,
    /// Best mDNS instance name seen.
    pub mdns_name: Option<String>,
    /// IEEE-registered vendor for the MAC prefix.
    pub vendor: Option<String>,
    /// Classified device type.
    pub device_type: Option<String>,
    /// How much to trust `device_type`.
    pub device_type_confidence: Option<f32>,
    /// Classified operating system family.
    pub os_family: Option<String>,
    /// Lifecycle state.
    pub state: DeviceState,
    /// Most recent IPv4 address.
    pub last_ip: Option<String>,
    /// Most recent IPv6 address, global preferred over link-local.
    pub last_ipv6: Option<String>,
    /// Interface the device was last seen on.
    pub last_interface: Option<String>,
    /// When the device was first discovered.
    pub first_seen_at: DateTime<Utc>,
    /// When the device was last seen.
    pub last_seen_at: DateTime<Utc>,
    /// True when the device was learned during a baseline window.
    pub baseline: bool,
    /// Access point it is associated with.
    pub current_ap: Option<String>,
    /// Place that access point is in.
    pub current_location: Option<String>,
    /// User-owned: hide from the dashboard.
    pub hidden: bool,
    /// User-owned: whether this device is worth a notification.
    pub notify: bool,
    /// User-owned free text.
    pub notes: Option<String>,
    /// User-owned: the person Item that owns this device, as UUID text.
    ///
    /// Read as text rather than as a UUID because the daemon only ever compares
    /// it and hands it back, and decoding it properly would mean a `uuid` crate
    /// and a `tokio-postgres` feature for a value nothing here inspects.
    pub owner_item_id: Option<String>,
}

/// Columns selected by every device read, in one place so the row decoder and
/// the query cannot drift apart.
const DEVICE_COLUMNS: &str = "id, mac, display_name, resolved_name, identity_source, \
     identity_confidence, hostname, mdns_name, vendor, device_type, device_type_confidence, \
     os_family, state, last_ip, last_ipv6, last_interface, first_seen_at, last_seen_at, \
     baseline, current_ap, current_location, hidden, notify, notes, \
     owner_item_id::text AS owner_item_id";

impl DeviceRecord {
    /// Decodes a row selected with [`DEVICE_COLUMNS`].
    fn from_row(row: &Row) -> Result<Self> {
        let mac: String = row.try_get("mac")?;
        let state: String = row.try_get("state")?;
        Ok(DeviceRecord {
            id: row.try_get("id")?,
            mac: mac
                .parse()
                .with_context(|| format!("ng_devices holds an unparseable MAC: {mac:?}"))?,
            display_name: row.try_get("display_name")?,
            resolved_name: row.try_get("resolved_name")?,
            identity_source: row.try_get("identity_source")?,
            identity_confidence: row.try_get("identity_confidence")?,
            hostname: row.try_get("hostname")?,
            mdns_name: row.try_get("mdns_name")?,
            vendor: row.try_get("vendor")?,
            device_type: row.try_get("device_type")?,
            device_type_confidence: row.try_get("device_type_confidence")?,
            os_family: row.try_get("os_family")?,
            state: DeviceState::from_db(&state),
            last_ip: row.try_get("last_ip")?,
            last_ipv6: row.try_get("last_ipv6")?,
            last_interface: row.try_get("last_interface")?,
            first_seen_at: row.try_get("first_seen_at")?,
            last_seen_at: row.try_get("last_seen_at")?,
            baseline: row.try_get("baseline")?,
            current_ap: row.try_get("current_ap")?,
            current_location: row.try_get("current_location")?,
            hidden: row.try_get("hidden")?,
            notify: row.try_get("notify")?,
            notes: row.try_get("notes")?,
            owner_item_id: row.try_get("owner_item_id")?,
        })
    }

    /// The name to show a human: the user's choice if there is one, otherwise
    /// what the scorer picked, otherwise the bare MAC.
    #[must_use]
    pub fn display(&self) -> String {
        self.display_name
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .or(self.resolved_name.as_deref())
            .filter(|s| !s.trim().is_empty())
            .map_or_else(|| self.mac.to_string(), str::to_string)
    }
}

/// Fields written when a device is created.
#[derive(Debug, Clone)]
pub struct NewDevice {
    /// Hardware address.
    pub mac: MacAddr,
    /// Address it was using, if any.
    pub last_ip: Option<String>,
    /// Interface it was seen on.
    pub last_interface: Option<String>,
    /// Discovery time, used for both first and last seen.
    pub seen_at: DateTime<Utc>,
    /// True when discovered during a baseline learning window.
    pub baseline: bool,
    /// Vendor from the MAC prefix, if the registry knows one.
    pub vendor: Option<String>,
}

/// Daemon-owned fields written on every flush.
#[derive(Debug, Clone)]
pub struct DeviceUpdate {
    /// Which device.
    pub id: i64,
    /// Current lifecycle state.
    pub state: DeviceState,
    /// Most recent IPv4 address.
    pub last_ip: Option<String>,
    /// Most recent IPv6 address.
    pub last_ipv6: Option<String>,
    /// Most recent interface.
    pub last_interface: Option<String>,
    /// Most recent sighting.
    pub last_seen_at: DateTime<Utc>,
    /// Name chosen by the scorer.
    pub resolved_name: Option<String>,
    /// Signal kind behind that name.
    pub identity_source: Option<String>,
    /// Weight of that signal kind.
    pub identity_confidence: Option<f32>,
    /// Best host name.
    pub hostname: Option<String>,
    /// Best mDNS instance name.
    pub mdns_name: Option<String>,
    /// Vendor.
    pub vendor: Option<String>,
    /// Classified device type.
    pub device_type: Option<String>,
    /// How much to trust the device type.
    pub device_type_confidence: Option<f32>,
    /// Classified operating system family.
    pub os_family: Option<String>,
    /// Access point the device is on.
    pub current_ap: Option<String>,
    /// Place that access point is in.
    pub current_location: Option<String>,
}

/// Fields written when an event is recorded.
#[derive(Debug, Clone)]
pub struct NewEvent {
    /// Device the event is about, when there is one.
    pub device_id: Option<i64>,
    /// What happened.
    pub event_type: EventType,
    /// When it happened.
    pub timestamp: DateTime<Utc>,
    /// Structured detail, free-form by design so that milestone 2's analyzers
    /// need no schema change.
    pub details: Json,
    /// Whether a notification was delivered. False during a learning window.
    pub notified: bool,
}

/// One row of `ng_events`, joined with its device's display name.
#[derive(Debug, Clone, PartialEq)]
pub struct EventRecord {
    /// Primary key.
    pub id: i64,
    /// Device the event is about.
    pub device_id: Option<i64>,
    /// Device name at read time, resolved the same way the CLI resolves it.
    pub device_label: Option<String>,
    /// What happened.
    pub event_type: String,
    /// When it happened.
    pub timestamp: DateTime<Utc>,
    /// Structured detail.
    pub details: Json,
    /// Whether a notification was delivered.
    pub notified: bool,
}

/// Counts devices. Zero means this is a first run, which triggers learning mode.
///
/// # Errors
///
/// Returns an error when the query fails.
pub async fn count_devices(client: &Client) -> Result<i64> {
    let row = client
        .query_one("SELECT COUNT(*) FROM ng_devices", &[])
        .await
        .context("counting devices failed")?;
    Ok(row.try_get(0)?)
}

/// Loads every device, most recently seen first.
///
/// # Errors
///
/// Returns an error when the query fails or a stored MAC is unparseable.
pub async fn load_devices(client: &Client) -> Result<Vec<DeviceRecord>> {
    let sql = format!("SELECT {DEVICE_COLUMNS} FROM ng_devices ORDER BY last_seen_at DESC");
    let rows = client
        .query(&sql, &[])
        .await
        .context("loading devices failed")?;
    rows.iter().map(DeviceRecord::from_row).collect()
}

/// Loads one device by MAC.
///
/// # Errors
///
/// Returns an error when the query fails.
pub async fn find_device_by_mac(client: &Client, mac: MacAddr) -> Result<Option<DeviceRecord>> {
    let sql = format!("SELECT {DEVICE_COLUMNS} FROM ng_devices WHERE mac = $1");
    let row = client
        .query_opt(&sql, &[&mac.to_string()])
        .await
        .context("device lookup failed")?;
    row.as_ref().map(DeviceRecord::from_row).transpose()
}

/// Every user-owned column of `ng_devices`, named once so the reconcile read
/// and the guards over it cannot drift apart.
///
/// `trovato_item_id` is the plugin's own join key rather than something a person
/// edits, so it is not here: nothing in the daemon reads it and the write guards
/// name it separately.
pub const USER_OWNED_DEVICE_COLUMNS: [&str; 5] =
    ["display_name", "notes", "hidden", "notify", "owner_item_id"];

/// The user-owned columns of one device, as the reconcile read returns them.
///
/// This is the whole of what a person can change from the Trovato admin UI or
/// through the assistant. The daemon reads it and never writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSettings {
    /// Hardware address, the join key with the in-memory table.
    pub mac: MacAddr,
    /// User-assigned name.
    pub display_name: Option<String>,
    /// Free text.
    ///
    /// Read for completeness and applied nowhere: nothing in the daemon has an
    /// opinion about a note.
    pub notes: Option<String>,
    /// Hide the device from the web listings.
    ///
    /// Presentation only, and deliberately so. It hides a row in Trovato and
    /// does nothing else: a hidden device is still captured, still recorded,
    /// still produces presence and still alerts. `notify` is the flag that
    /// silences alerts. Anything stronger would mean a checkbox labelled "hide"
    /// quietly creating a blind spot in a security tool.
    pub hidden: bool,
    /// Whether this device is worth a notification.
    pub notify: bool,
    /// The person Item that owns this device, as UUID text.
    pub owner_item_id: Option<String>,
}

/// The one statement that reads the user-owned columns back.
///
/// Held as a constant so that the test asserting it names no daemon-owned column
/// inspects the statement itself rather than a copy of it. It is the mirror of
/// [`UPDATE_DEVICE_SQL`]: that one may not write these columns, this one may not
/// read any other.
const LOAD_USER_SETTINGS_SQL: &str = "SELECT mac, display_name, notes, hidden, notify,
                owner_item_id::text AS owner_item_id
           FROM ng_devices";

/// Loads the user-owned columns of every device.
///
/// Deliberately not [`load_devices`]: the reconcile tick must not re-read state,
/// timestamps or identity, because the in-memory copies of those are newer than
/// the database's between flushes and reading them back would walk the daemon's
/// own state backwards.
///
/// # Errors
///
/// Returns an error when the query fails or a stored MAC is unparseable.
pub async fn load_user_settings(client: &Client) -> Result<Vec<UserSettings>> {
    let rows = client
        .query(LOAD_USER_SETTINGS_SQL, &[])
        .await
        .context("loading user-owned device settings failed")?;
    rows.iter()
        .map(|row| {
            let mac: String = row.try_get("mac")?;
            Ok(UserSettings {
                mac: mac
                    .parse()
                    .with_context(|| format!("ng_devices holds an unparseable MAC: {mac:?}"))?,
                display_name: row.try_get("display_name")?,
                notes: row.try_get("notes")?,
                hidden: row.try_get("hidden")?,
                notify: row.try_get("notify")?,
                owner_item_id: row.try_get("owner_item_id")?,
            })
        })
        .collect()
}

/// Creates a device, or returns the existing row's id if the MAC is already
/// known.
///
/// The upsert is not defensive coding for its own sake: two capture sources can
/// produce the first sighting of the same MAC within the same flush window, and
/// a plain INSERT would make one of them fail.
///
/// # Errors
///
/// Returns an error when the insert fails.
pub async fn insert_device(client: &Client, new: &NewDevice) -> Result<i64> {
    let row = client
        .query_one(
            "INSERT INTO ng_devices
                 (mac, last_ip, last_interface, first_seen_at, last_seen_at, baseline, vendor,
                  state, sync_state)
             VALUES ($1, $2, $3, $4, $4, $5, $6, 'online', 'dirty')
             ON CONFLICT (mac) DO UPDATE
                 SET last_seen_at = EXCLUDED.last_seen_at,
                     sync_state   = 'dirty'
             RETURNING id",
            &[
                &new.mac.to_string(),
                &new.last_ip,
                &new.last_interface,
                &new.seen_at,
                &new.baseline,
                &new.vendor,
            ],
        )
        .await
        .context("inserting a device failed")?;
    Ok(row.try_get(0)?)
}

/// The one statement that writes device state.
///
/// Held as a constant so that the test asserting no user-owned column appears in
/// it inspects the statement itself rather than a copy of it.
const UPDATE_DEVICE_SQL: &str = "UPDATE ng_devices
        SET state                  = $2,
            last_ip                = $3,
            last_interface         = $4,
            last_seen_at           = $5,
            resolved_name          = $6,
            identity_source        = $7,
            identity_confidence    = $8,
            hostname               = $9,
            mdns_name              = $10,
            vendor                 = $11,
            device_type            = $12,
            device_type_confidence = $13,
            os_family              = $14,
            last_ipv6              = $15,
            current_ap             = $16,
            current_location       = $17,
            sync_state             = 'dirty'
      WHERE id = $1";

/// Writes the daemon-owned columns of one device.
///
/// The user-owned columns are absent from the statement by design.
///
/// # Errors
///
/// Returns an error when the update fails.
pub async fn update_device(client: &Client, update: &DeviceUpdate) -> Result<()> {
    client
        .execute(
            UPDATE_DEVICE_SQL,
            &[
                &update.id,
                &update.state.as_str(),
                &update.last_ip,
                &update.last_interface,
                &update.last_seen_at,
                &update.resolved_name,
                &update.identity_source,
                &update.identity_confidence,
                &update.hostname,
                &update.mdns_name,
                &update.vendor,
                &update.device_type,
                &update.device_type_confidence,
                &update.os_family,
                &update.last_ipv6,
                &update.current_ap,
                &update.current_location,
            ],
        )
        .await
        .context("updating a device failed")?;
    Ok(())
}

/// Counts devices learned during a baseline window.
///
/// # Errors
///
/// Returns an error when the query fails.
pub async fn count_baseline_devices(client: &Client) -> Result<i64> {
    let row = client
        .query_one("SELECT COUNT(*) FROM ng_devices WHERE baseline", &[])
        .await
        .context("counting baseline devices failed")?;
    Ok(row.try_get(0)?)
}

/// Records a signal, refreshing `last_seen_at` if it is already known.
///
/// Signals are never replaced, only added and touched, which is what lets a
/// later signal refine an identity instead of overwriting it.
///
/// # Errors
///
/// Returns an error when the upsert fails.
pub async fn upsert_signal(
    client: &Client,
    device_id: i64,
    kind: SignalKind,
    value: &str,
    seen_at: DateTime<Utc>,
) -> Result<()> {
    client
        .execute(
            "INSERT INTO ng_device_signals
                 (device_id, signal_type, value, first_seen_at, last_seen_at)
             VALUES ($1, $2, $3, $4, $4)
             ON CONFLICT (device_id, signal_type, value) DO UPDATE
                 SET last_seen_at = EXCLUDED.last_seen_at",
            &[&device_id, &kind.as_str(), &value, &seen_at],
        )
        .await
        .context("recording a signal failed")?;
    Ok(())
}

/// Loads every signal for every device, keyed by device id and ordered most
/// recently confirmed first, which is the order the scorer expects.
///
/// # Errors
///
/// Returns an error when the query fails.
pub async fn load_all_signals(client: &Client) -> Result<HashMap<i64, Vec<Signal>>> {
    let rows = client
        .query(
            // The id tie-break is load-bearing, not cosmetic: several signals
            // from one packet share a timestamp, and without it the reload order
            // is whatever Postgres felt like. A device would then rescore to a
            // different name on every restart and emit a spurious name_updated.
            // Ascending id is insertion order, which is the order the source
            // listed them in.
            "SELECT device_id, signal_type, value
               FROM ng_device_signals
              ORDER BY device_id, last_seen_at DESC, id ASC",
            &[],
        )
        .await
        .context("loading signals failed")?;
    let mut out: HashMap<i64, Vec<Signal>> = HashMap::new();
    for row in &rows {
        let device_id: i64 = row.try_get("device_id")?;
        let kind: String = row.try_get("signal_type")?;
        let value: String = row.try_get("value")?;
        // A signal type this build does not know about came from a newer
        // daemon. Skipping it is right: scoring an unknown weight would be a
        // guess.
        if let Some(kind) = SignalKind::from_str_opt(&kind) {
            out.entry(device_id)
                .or_default()
                .push(Signal { kind, value });
        }
    }
    Ok(out)
}

/// Opens a presence session, or bumps the observation count of the one already
/// open.
///
/// A partial unique index guarantees at most one open session per device, so the
/// upsert is the enforcement point rather than a hopeful convention.
///
/// # Errors
///
/// Returns an error when the statement fails.
pub async fn open_presence(
    client: &Client,
    device_id: i64,
    interface: Option<&str>,
    ip: Option<&str>,
    started_at: DateTime<Utc>,
) -> Result<()> {
    client
        .execute(
            // observation_count starts at zero, not at the column default of
            // one: the observation that opened the session is itself counted by
            // the next flush, and seeding the counter would double it.
            "INSERT INTO ng_presence (device_id, interface, ip, started_at, observation_count)
             SELECT $1, $2, $3, $4, 0
              WHERE NOT EXISTS (
                    SELECT 1 FROM ng_presence
                     WHERE device_id = $1 AND ended_at IS NULL AND is_summary = FALSE)",
            &[&device_id, &interface, &ip, &started_at],
        )
        .await
        .context("opening a presence session failed")?;
    Ok(())
}

/// Counts one more observation against the open session.
///
/// # Errors
///
/// Returns an error when the statement fails.
pub async fn bump_presence(client: &Client, device_id: i64, count: i64) -> Result<()> {
    client
        .execute(
            "UPDATE ng_presence
                SET observation_count = observation_count + $2
              WHERE device_id = $1 AND ended_at IS NULL AND is_summary = FALSE",
            &[&device_id, &count],
        )
        .await
        .context("counting a presence observation failed")?;
    Ok(())
}

/// Closes the open presence session for a device.
///
/// # Errors
///
/// Returns an error when the statement fails.
pub async fn close_presence(
    client: &Client,
    device_id: i64,
    ended_at: DateTime<Utc>,
) -> Result<()> {
    client
        .execute(
            "UPDATE ng_presence
                SET ended_at = $2
              WHERE device_id = $1 AND ended_at IS NULL AND is_summary = FALSE",
            &[&device_id, &ended_at],
        )
        .await
        .context("closing a presence session failed")?;
    Ok(())
}

/// Counts open presence sessions. Used by tests and by the status line.
///
/// # Errors
///
/// Returns an error when the query fails.
pub async fn count_open_presence(client: &Client) -> Result<i64> {
    let row = client
        .query_one(
            "SELECT COUNT(*) FROM ng_presence WHERE ended_at IS NULL AND is_summary = FALSE",
            &[],
        )
        .await
        .context("counting open presence sessions failed")?;
    Ok(row.try_get(0)?)
}

/// Records that a device holds an address, collapsing repeats into one row.
///
/// # Errors
///
/// Returns an error when the upsert fails.
pub async fn upsert_ip(
    client: &Client,
    device_id: i64,
    ip: &str,
    interface: Option<&str>,
    seen_at: DateTime<Utc>,
) -> Result<()> {
    client
        .execute(
            "INSERT INTO ng_ip_history (device_id, ip, interface, first_seen, last_seen)
             VALUES ($1, $2, $3, $4, $4)
             ON CONFLICT (device_id, ip) DO UPDATE
                 SET last_seen = EXCLUDED.last_seen,
                     interface = COALESCE(EXCLUDED.interface, ng_ip_history.interface)",
            &[&device_id, &ip, &interface, &seen_at],
        )
        .await
        .context("recording an address failed")?;
    Ok(())
}

/// Records an event.
///
/// # Errors
///
/// Returns an error when the insert fails.
pub async fn insert_event(client: &Client, event: &NewEvent) -> Result<i64> {
    let row = client
        .query_one(
            "INSERT INTO ng_events (device_id, event_type, \"timestamp\", details, notified, sync_state)
             VALUES ($1, $2, $3, $4, $5, 'dirty')
             RETURNING id",
            &[
                &event.device_id,
                &event.event_type.as_str(),
                &event.timestamp,
                &event.details,
                &event.notified,
            ],
        )
        .await
        .context("recording an event failed")?;
    Ok(row.try_get(0)?)
}

/// Marks an event as delivered.
///
/// # Errors
///
/// Returns an error when the update fails.
pub async fn mark_event_notified(client: &Client, event_id: i64) -> Result<()> {
    client
        .execute(
            "UPDATE ng_events SET notified = TRUE, sync_state = 'dirty' WHERE id = $1",
            &[&event_id],
        )
        .await
        .context("marking an event notified failed")?;
    Ok(())
}

/// Loads the most recent events, newest first.
///
/// # Errors
///
/// Returns an error when the query fails.
pub async fn recent_events(client: &Client, limit: i64) -> Result<Vec<EventRecord>> {
    let rows = client
        .query(
            "SELECT e.id, e.device_id, e.event_type, e.\"timestamp\", e.details, e.notified,
                    COALESCE(NULLIF(TRIM(d.display_name), ''), NULLIF(TRIM(d.resolved_name), ''), d.mac)
                        AS device_label
               FROM ng_events e
               LEFT JOIN ng_devices d ON d.id = e.device_id
              ORDER BY e.\"timestamp\" DESC, e.id DESC
              LIMIT $1",
            &[&limit],
        )
        .await
        .context("loading events failed")?;
    rows.iter().map(decode_event).collect()
}

/// Decodes one row of the event query, shared by both event readers so their
/// column lists cannot drift apart.
fn decode_event(row: &Row) -> Result<EventRecord> {
    Ok(EventRecord {
        id: row.try_get("id")?,
        device_id: row.try_get("device_id")?,
        device_label: row.try_get("device_label")?,
        event_type: row.try_get("event_type")?,
        timestamp: row.try_get("timestamp")?,
        details: row.try_get("details")?,
        notified: row.try_get("notified")?,
    })
}

/// Loads the most recent security events, newest first.
///
/// The `IN` list is the same one the partial index in migration V2 covers, so
/// this query uses it rather than scanning.
///
/// # Errors
///
/// Returns an error when the query fails.
pub async fn recent_security_events(client: &Client, limit: i64) -> Result<Vec<EventRecord>> {
    let rows = client
        .query(
            "SELECT e.id, e.device_id, e.event_type, e.\"timestamp\", e.details, e.notified,
                    COALESCE(NULLIF(TRIM(d.display_name), \'\'), NULLIF(TRIM(d.resolved_name), \'\'), d.mac)
                        AS device_label
               FROM ng_events e
               LEFT JOIN ng_devices d ON d.id = e.device_id
              WHERE e.event_type IN (
                    \'arp_scan\', \'arp_spoof\', \'rogue_dhcp\',
                    \'identity_change\', \'ip_conflict\', \'gratuitous_arp\')
              ORDER BY e.\"timestamp\" DESC, e.id DESC
              LIMIT $1",
            &[&limit],
        )
        .await
        .context("loading security events failed")?;
    rows.iter().map(decode_event).collect()
}

/// Ends the open location stay for a device and opens a new one.
///
/// One statement pair rather than an upsert, because the invariant is "at most
/// one open stay", enforced by a partial unique index, and the only way to
/// satisfy it is to close before opening. Both run on the same connection back
/// to back; a crash between them leaves a device with no open stay, which the
/// next enrichment poll fixes.
///
/// # Errors
///
/// Returns an error when either statement fails.
pub async fn change_location(
    client: &Client,
    device_id: i64,
    ap_name: Option<&str>,
    location: &str,
    at: DateTime<Utc>,
) -> Result<()> {
    close_location(client, device_id, at).await?;
    client
        .execute(
            "INSERT INTO ng_location_history (device_id, ap_name, location, started_at)
             VALUES ($1, $2, $3, $4)",
            &[&device_id, &ap_name, &location, &at],
        )
        .await
        .context("opening a location stay failed")?;
    Ok(())
}

/// Ends the open location stay for a device, if there is one.
///
/// # Errors
///
/// Returns an error when the statement fails.
pub async fn close_location(
    client: &Client,
    device_id: i64,
    ended_at: DateTime<Utc>,
) -> Result<u64> {
    client
        .execute(
            "UPDATE ng_location_history
                SET ended_at = $2
              WHERE device_id = $1 AND ended_at IS NULL AND is_summary = FALSE",
            &[&device_id, &ended_at],
        )
        .await
        .context("closing a location stay failed")
}

/// Ends every open location stay belonging to a device that is offline.
///
/// Run once at startup. A crash, or a device that went offline while the daemon
/// was not running, otherwise leaves a stay open forever and the device
/// apparently still in the kitchen.
///
/// # Errors
///
/// Returns an error when the statement fails.
pub async fn close_stale_location_stays(client: &Client, at: DateTime<Utc>) -> Result<u64> {
    client
        .execute(
            "UPDATE ng_location_history h
                SET ended_at = $1
               FROM ng_devices d
              WHERE d.id = h.device_id
                AND h.ended_at IS NULL
                AND h.is_summary = FALSE
                AND d.state = 'offline'",
            &[&at],
        )
        .await
        .context("closing stale location stays failed")
}

/// Counts open location stays. Used by tests and by `netgraspd stats`.
///
/// # Errors
///
/// Returns an error when the query fails.
pub async fn count_open_locations(client: &Client) -> Result<i64> {
    let row = client
        .query_one(
            "SELECT COUNT(*) FROM ng_location_history
              WHERE ended_at IS NULL AND is_summary = FALSE",
            &[],
        )
        .await
        .context("counting open location stays failed")?;
    Ok(row.try_get(0)?)
}

/// One row of `ng_people`, with its UUID rendered as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonRecord {
    /// Primary key, as UUID text.
    pub item_id: String,
    /// Display name. Plugin owned.
    pub name: String,
    /// Notify on arrival. Plugin owned.
    pub notify_arrive: bool,
    /// Notify on departure. Plugin owned.
    pub notify_depart: bool,
    /// Whether they are home. Daemon owned.
    pub state: String,
    /// Where they are. Daemon owned.
    pub current_location: Option<String>,
    /// When they last arrived. Daemon owned.
    pub last_arrived_at: Option<DateTime<Utc>>,
    /// When they last left. Daemon owned.
    pub last_departed_at: Option<DateTime<Utc>>,
}

/// Loads every person.
///
/// # Errors
///
/// Returns an error when the query fails.
pub async fn load_people(client: &Client) -> Result<Vec<PersonRecord>> {
    let rows = client
        .query(
            "SELECT item_id::text AS item_id, name, notify_arrive, notify_depart, state,
                    current_location, last_arrived_at, last_departed_at
               FROM ng_people
              ORDER BY name",
            &[],
        )
        .await
        .context("loading people failed")?;
    rows.iter()
        .map(|row| {
            Ok(PersonRecord {
                item_id: row.try_get("item_id")?,
                name: row.try_get("name")?,
                notify_arrive: row.try_get("notify_arrive")?,
                notify_depart: row.try_get("notify_depart")?,
                state: row.try_get("state")?,
                current_location: row.try_get("current_location")?,
                last_arrived_at: row.try_get("last_arrived_at")?,
                last_departed_at: row.try_get("last_departed_at")?,
            })
        })
        .collect()
}

/// Adopts an existing person by name, or creates one with a generated UUID.
///
/// Returns the person's item id.
///
/// This is the only place the daemon writes a plugin-owned column, and it does
/// so only when creating a row that did not exist. Adopting by name is what
/// makes it safe to list somebody in `netgrasp.toml` who is also mirrored from
/// Trovato: the daemon finds them and leaves their identity alone rather than
/// creating a second Jeremy.
///
/// The UUID comes from Postgres's `gen_random_uuid()` rather than from a Rust
/// crate, which keeps a dependency out of the daemon for a value it never
/// inspects.
///
/// # Errors
///
/// Returns an error when the statement fails.
pub async fn ensure_person(
    client: &Client,
    name: &str,
    notify_arrive: bool,
    notify_depart: bool,
) -> Result<String> {
    if let Some(row) = client
        .query_opt(
            "SELECT item_id::text FROM ng_people WHERE lower(name) = lower($1)",
            &[&name],
        )
        .await
        .context("looking up a person failed")?
    {
        return Ok(row.try_get(0)?);
    }
    let row = client
        .query_one(
            "INSERT INTO ng_people (item_id, name, notify_arrive, notify_depart)
             VALUES (gen_random_uuid(), $1, $2, $3)
             RETURNING item_id::text",
            &[&name, &notify_arrive, &notify_depart],
        )
        .await
        .context("creating a person failed")?;
    Ok(row.try_get(0)?)
}

/// The one statement that writes person state.
///
/// Held as a constant so the test asserting no plugin-owned column appears in it
/// inspects the statement itself rather than a copy of it.
/// The `($1::text)::uuid` spelling is load-bearing. Writing `$1::uuid` makes
/// Postgres infer the parameter's own type as `uuid`, and tokio-postgres then
/// refuses to send a Rust `&str` for it. Casting from an explicitly-typed text
/// parameter keeps the parameter text and still lets the comparison use the
/// primary key index.
const UPDATE_PERSON_SQL: &str = "UPDATE ng_people
        SET state            = $2,
            current_location = $3,
            last_arrived_at  = $4,
            last_departed_at = $5
      WHERE item_id = ($1::text)::uuid";

/// Writes the daemon-owned columns of one person.
///
/// `name`, `notes`, `notify_arrive` and `notify_depart` are absent from the
/// statement by design: they belong to the plugin and to whoever edits them in
/// the admin UI.
///
/// # Errors
///
/// Returns an error when the update fails.
pub async fn update_person(
    client: &Client,
    item_id: &str,
    state: &str,
    current_location: Option<&str>,
    last_arrived_at: Option<DateTime<Utc>>,
    last_departed_at: Option<DateTime<Utc>>,
) -> Result<()> {
    client
        .execute(
            UPDATE_PERSON_SQL,
            &[
                &item_id,
                &state,
                &current_location,
                &last_arrived_at,
                &last_departed_at,
            ],
        )
        .await
        .context("updating a person failed")?;
    Ok(())
}

/// Counts events of one type. Used by tests and the learning-mode summary.
///
/// # Errors
///
/// Returns an error when the query fails.
pub async fn count_events_of_type(client: &Client, event_type: EventType) -> Result<i64> {
    let row = client
        .query_one(
            "SELECT COUNT(*) FROM ng_events WHERE event_type = $1",
            &[&event_type.as_str()],
        )
        .await
        .context("counting events failed")?;
    Ok(row.try_get(0)?)
}

/// One table's size on disk and row count, for `netgraspd stats`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableSize {
    /// Table name.
    pub table: String,
    /// Live rows, as the planner's estimate rather than a count, and `None`
    /// until the table has been analysed at all.
    ///
    /// An estimate on purpose: `SELECT COUNT(*)` on `ng_events` after a year is
    /// a sequential scan, and `stats` is a command an operator runs to check
    /// whether the machine is healthy, not one that should make it less so.
    /// Postgres reports `-1` for a table it has never analysed, which is
    /// reported as unknown rather than rounded up into a confident zero.
    pub rows: Option<i64>,
    /// Total bytes including indexes and TOAST.
    pub bytes: i64,
}

/// Sizes of every `ng_` table, largest first.
///
/// # Errors
///
/// Returns an error when the query fails.
pub async fn table_sizes(client: &Client) -> Result<Vec<TableSize>> {
    let rows = client
        .query(
            "SELECT c.relname AS table_name,
                    NULLIF(c.reltuples, -1)::bigint AS rows,
                    pg_total_relation_size(c.oid)::bigint AS bytes
               FROM pg_class c
               JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE c.relkind = 'r'
                AND n.nspname = current_schema()
                AND c.relname LIKE 'ng\\_%'
              ORDER BY bytes DESC",
            &[],
        )
        .await
        .context("reading table sizes failed")?;
    rows.iter()
        .map(|row| {
            Ok(TableSize {
                table: row.try_get("table_name")?,
                rows: row.try_get("rows")?,
                bytes: row.try_get("bytes")?,
            })
        })
        .collect()
}

/// How far the rollup has compacted, per table.
///
/// The high-water mark is the newest summarised day. An operator comparing it to
/// today minus `rollup_after_days` can see at a glance whether the nightly job
/// is keeping up.
///
/// # Errors
///
/// Returns an error when the query fails.
pub async fn rollup_high_water(
    client: &Client,
) -> Result<Vec<(String, Option<DateTime<Utc>>, i64)>> {
    let mut out = Vec::with_capacity(2);
    for table in ["ng_presence", "ng_location_history"] {
        let row = client
            .query_one(
                &format!("SELECT MAX(started_at), COUNT(*) FROM {table} WHERE is_summary = TRUE"),
                &[],
            )
            .await
            .with_context(|| format!("reading the rollup high-water mark for {table} failed"))?;
        out.push((table.to_string(), row.try_get(0)?, row.try_get(1)?));
    }
    Ok(out)
}

/// Counts rows in `ng_events` grouped by type, newest activity first.
///
/// # Errors
///
/// Returns an error when the query fails.
pub async fn event_counts(client: &Client) -> Result<Vec<(String, i64)>> {
    let rows = client
        .query(
            "SELECT event_type, COUNT(*) AS n
               FROM ng_events
              GROUP BY event_type
              ORDER BY n DESC, event_type",
            &[],
        )
        .await
        .context("counting events by type failed")?;
    rows.iter()
        .map(|row| Ok((row.try_get("event_type")?, row.try_get("n")?)))
        .collect()
}

/// Counts devices in each lifecycle state.
///
/// # Errors
///
/// Returns an error when the query fails.
pub async fn device_state_counts(client: &Client) -> Result<Vec<(String, i64)>> {
    let rows = client
        .query(
            "SELECT state, COUNT(*) AS n FROM ng_devices GROUP BY state ORDER BY state",
            &[],
        )
        .await
        .context("counting devices by state failed")?;
    rows.iter()
        .map(|row| Ok((row.try_get("state")?, row.try_get("n")?)))
        .collect()
}

/// The oldest and newest event timestamps, which bound the retention window.
///
/// # Errors
///
/// Returns an error when the query fails.
pub async fn event_span(client: &Client) -> Result<(Option<DateTime<Utc>>, Option<DateTime<Utc>>)> {
    let row = client
        .query_one(
            "SELECT MIN(\"timestamp\"), MAX(\"timestamp\") FROM ng_events",
            &[],
        )
        .await
        .context("reading the event span failed")?;
    Ok((row.try_get(0)?, row.try_get(1)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(display: Option<&str>, resolved: Option<&str>) -> DeviceRecord {
        DeviceRecord {
            id: 1,
            mac: "3c:22:fb:00:11:22".parse().expect("mac"),
            display_name: display.map(str::to_string),
            resolved_name: resolved.map(str::to_string),
            identity_source: None,
            identity_confidence: None,
            hostname: None,
            mdns_name: None,
            vendor: None,
            device_type: None,
            device_type_confidence: None,
            os_family: None,
            state: DeviceState::Online,
            last_ip: None,
            last_ipv6: None,
            last_interface: None,
            first_seen_at: Utc::now(),
            last_seen_at: Utc::now(),
            baseline: false,
            hidden: false,
            notify: true,
            notes: None,
            current_ap: None,
            current_location: None,
            owner_item_id: None,
        }
    }

    #[test]
    fn the_user_name_wins_when_there_is_one() {
        assert_eq!(
            record(Some("Jamie's telly"), Some("Living Room Apple TV")).display(),
            "Jamie's telly"
        );
    }

    #[test]
    fn the_resolved_name_is_used_when_the_user_has_not_named_it() {
        assert_eq!(
            record(None, Some("Living Room Apple TV")).display(),
            "Living Room Apple TV"
        );
    }

    #[test]
    fn a_blank_user_name_does_not_beat_a_real_resolved_name() {
        assert_eq!(
            record(Some("   "), Some("Office Printer")).display(),
            "Office Printer"
        );
    }

    #[test]
    fn the_mac_is_the_floor() {
        assert_eq!(record(None, None).display(), "3c:22:fb:00:11:22");
        assert_eq!(record(Some(""), Some("  ")).display(), "3c:22:fb:00:11:22");
    }

    #[test]
    fn the_device_update_never_writes_a_user_owned_column() {
        // A guard against the most likely future regression: somebody adding a
        // column to the update statement without noticing whose it is.
        // owner_item_id and trovato_item_id joined the list in V3; both are
        // written by the Trovato plugin and only ever read here.
        for column in [
            "display_name",
            "notes",
            "hidden",
            "notify",
            "owner_item_id",
            "trovato_item_id",
        ] {
            assert!(
                !UPDATE_DEVICE_SQL.contains(&format!("{column} ")),
                "the device update writes the user-owned column {column}"
            );
        }
        // ...and a guard against the guard silently passing because the columns
        // were renamed out from under it.
        assert!(UPDATE_DEVICE_SQL.contains("resolved_name"));
        assert!(UPDATE_DEVICE_SQL.contains("device_type_confidence"));
        assert!(UPDATE_DEVICE_SQL.contains("current_location"));
        assert!(UPDATE_DEVICE_SQL.contains("sync_state             = 'dirty'"));
    }

    #[test]
    fn the_people_update_never_writes_a_plugin_owned_column() {
        // ng_people is split the other way round from ng_devices: the plugin
        // owns the identity and the notification flags, the daemon owns the
        // state. A daemon write that touched notify_arrive would silently undo
        // somebody's choice in the admin UI.
        for column in ["name", "notes", "notify_arrive", "notify_depart"] {
            assert!(
                !UPDATE_PERSON_SQL.contains(&format!("{column} ")),
                "the person update writes the plugin-owned column {column}"
            );
        }
        assert!(UPDATE_PERSON_SQL.contains("last_arrived_at"));
        assert!(UPDATE_PERSON_SQL.contains("last_departed_at"));
        assert!(UPDATE_PERSON_SQL.contains("current_location"));
    }

    #[test]
    fn the_reconcile_read_reads_the_user_owned_columns_and_nothing_else() {
        // The mirror of the write guards above. A daemon-owned column creeping
        // into this statement would have the reconcile tick overwrite live
        // in-memory state with whatever was last flushed, which is a device
        // going quietly stale rather than an obvious failure.
        for column in USER_OWNED_DEVICE_COLUMNS {
            assert!(
                LOAD_USER_SETTINGS_SQL.contains(column),
                "the reconcile read is missing the user-owned column {column}"
            );
        }
        for column in [
            "state",
            "last_seen_at",
            "first_seen_at",
            "resolved_name",
            "identity_source",
            "device_type",
            "os_family",
            "last_ip",
            "current_ap",
            "current_location",
            "baseline",
            "sync_state",
        ] {
            assert!(
                !LOAD_USER_SETTINGS_SQL.contains(column),
                "the reconcile read names the daemon-owned column {column}"
            );
        }
        // And it reads. A statement that writes has no business here whatever
        // it names.
        for verb in ["UPDATE", "INSERT", "DELETE"] {
            assert!(!LOAD_USER_SETTINGS_SQL.contains(verb), "{verb}");
        }
    }

    #[test]
    fn the_device_insert_never_writes_a_user_owned_column() {
        // insert_device names its columns explicitly; this asserts the list.
        let inserted =
            "mac, last_ip, last_interface, first_seen_at, last_seen_at, baseline, vendor";
        for column in ["display_name", "notes", "hidden", "notify"] {
            assert!(!inserted.contains(column), "{column} must not be inserted");
        }
    }
}
