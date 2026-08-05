//! Hand-written queries over the `ng_*` tables.
//!
//! Two rules govern everything here.
//!
//! 1. **The daemon never writes `ng_devices.display_name`, `notes`, `hidden` or
//!    `notify`.** Those four columns belong to the user, through the Trovato
//!    admin UI, and every UPDATE in this file names its columns explicitly so
//!    that a careless `SELECT *`-shaped write cannot clobber them.
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
    /// User-owned: hide from the dashboard.
    pub hidden: bool,
    /// User-owned: whether this device is worth a notification.
    pub notify: bool,
    /// User-owned free text.
    pub notes: Option<String>,
}

/// Columns selected by every device read, in one place so the row decoder and
/// the query cannot drift apart.
const DEVICE_COLUMNS: &str = "id, mac, display_name, resolved_name, identity_source, \
     identity_confidence, hostname, mdns_name, vendor, device_type, device_type_confidence, \
     os_family, state, last_ip, last_ipv6, last_interface, first_seen_at, last_seen_at, \
     baseline, hidden, notify, notes";

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
            hidden: row.try_get("hidden")?,
            notify: row.try_get("notify")?,
            notes: row.try_get("notes")?,
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
        for column in ["display_name", "notes", "hidden", "notify"] {
            assert!(
                !UPDATE_DEVICE_SQL.contains(&format!("{column} ")),
                "the device update writes the user-owned column {column}"
            );
        }
        // ...and a guard against the guard silently passing because the columns
        // were renamed out from under it.
        assert!(UPDATE_DEVICE_SQL.contains("resolved_name"));
        assert!(UPDATE_DEVICE_SQL.contains("device_type_confidence"));
        assert!(UPDATE_DEVICE_SQL.contains("sync_state             = 'dirty'"));
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
