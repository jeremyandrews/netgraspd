//! Applies state-machine effects to Postgres.
//!
//! The state machine speaks MAC addresses; the database speaks primary keys.
//! [`Persister`] is the only thing that knows both, which is what lets
//! [`super::Manager`] stay free of database concerns.
//!
//! Note what is missing: there is no method here that writes a row per
//! observation. Presence sessions accumulate a counter instead.

use std::collections::HashMap;

use anyhow::{Context, Result};

use crate::db::queries::{self, Client, DeviceRecord, DeviceUpdate, NewDevice, NewEvent};
use crate::device::{DeviceEvent, DeviceSnapshot, Effect};
use crate::types::MacAddr;

/// An event as recorded, paired with its row id so the notifier can mark it
/// delivered.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordedEvent {
    /// `ng_events.id`.
    pub id: i64,
    /// What was recorded.
    pub event: DeviceEvent,
}

/// Maps MAC addresses to device row ids and applies effects.
#[derive(Debug, Default)]
pub struct Persister {
    ids: HashMap<MacAddr, i64>,
}

impl Persister {
    /// Builds an empty persister.
    #[must_use]
    pub fn new() -> Self {
        Persister::default()
    }

    /// Seeds the id map from the rows loaded at startup.
    pub fn seed(&mut self, records: &[DeviceRecord]) {
        for record in records {
            self.ids.insert(record.mac, record.id);
        }
    }

    /// The row id for a MAC, if the device is known.
    #[must_use]
    pub fn id_for(&self, mac: MacAddr) -> Option<i64> {
        self.ids.get(&mac).copied()
    }

    /// How many devices are mapped.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// True when nothing is mapped.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Applies a batch of effects, returning the events that were recorded.
    ///
    /// Effects arrive in the order the state machine produced them, so a
    /// `Discovered` always precedes any effect that needs its id.
    ///
    /// # Errors
    ///
    /// Returns an error when any statement fails.
    pub async fn apply(
        &mut self,
        client: &Client,
        effects: &[Effect],
    ) -> Result<Vec<RecordedEvent>> {
        let mut recorded = Vec::new();
        for effect in effects {
            match effect {
                Effect::Discovered(snapshot) => {
                    let id = queries::insert_device(
                        client,
                        &NewDevice {
                            mac: snapshot.mac,
                            last_ip: snapshot.last_ip.clone(),
                            last_interface: snapshot.last_interface.clone(),
                            seen_at: snapshot.first_seen_at,
                            baseline: snapshot.baseline,
                            vendor: snapshot.vendor.clone(),
                        },
                    )
                    .await
                    .with_context(|| format!("creating device {}", snapshot.mac))?;
                    self.ids.insert(snapshot.mac, id);
                }
                Effect::Signal { mac, signal, at } => {
                    if let Some(id) = self.id_for(*mac) {
                        queries::upsert_signal(client, id, signal.kind, &signal.value, *at)
                            .await
                            .with_context(|| format!("recording a signal for {mac}"))?;
                    }
                }
                Effect::Address {
                    mac,
                    ip,
                    interface,
                    at,
                } => {
                    if let Some(id) = self.id_for(*mac) {
                        queries::upsert_ip(client, id, ip, Some(interface), *at)
                            .await
                            .with_context(|| format!("recording an address for {mac}"))?;
                    }
                }
                Effect::PresenceOpened {
                    mac,
                    interface,
                    ip,
                    at,
                } => {
                    if let Some(id) = self.id_for(*mac) {
                        queries::open_presence(client, id, Some(interface), ip.as_deref(), *at)
                            .await
                            .with_context(|| format!("opening a presence session for {mac}"))?;
                    }
                }
                Effect::PresenceClosed { mac, at } => {
                    if let Some(id) = self.id_for(*mac) {
                        queries::close_presence(client, id, *at)
                            .await
                            .with_context(|| format!("closing a presence session for {mac}"))?;
                    }
                }
                Effect::LocationChanged {
                    mac,
                    ap_name,
                    location,
                    at,
                } => {
                    if let Some(id) = self.id_for(*mac) {
                        queries::change_location(client, id, ap_name.as_deref(), location, *at)
                            .await
                            .with_context(|| format!("recording a location change for {mac}"))?;
                    }
                }
                Effect::LocationClosed { mac, at } => {
                    if let Some(id) = self.id_for(*mac) {
                        queries::close_location(client, id, *at)
                            .await
                            .with_context(|| format!("closing a location stay for {mac}"))?;
                    }
                }
                Effect::Event(event) => {
                    let device_id = self.id_for(event.mac);
                    let id = queries::insert_event(
                        client,
                        &NewEvent {
                            device_id,
                            event_type: event.event_type,
                            timestamp: event.at,
                            details: event.details.clone(),
                            // Delivery has not been attempted yet; the notifier
                            // flips this once it succeeds.
                            notified: false,
                        },
                    )
                    .await
                    .with_context(|| format!("recording a {} event", event.event_type))?;
                    recorded.push(RecordedEvent {
                        id,
                        event: (**event).clone(),
                    });
                }
            }
        }
        Ok(recorded)
    }

    /// Writes the daemon-owned columns of every changed device, and folds each
    /// device's observation count into its open presence session.
    ///
    /// # Errors
    ///
    /// Returns an error when any statement fails.
    pub async fn flush(&self, client: &Client, snapshots: &[DeviceSnapshot]) -> Result<()> {
        for snapshot in snapshots {
            let Some(id) = self.id_for(snapshot.mac) else {
                // A device the state machine knows and the database does not
                // means the insert failed earlier and was logged there.
                tracing::warn!(mac = %snapshot.mac, "flush skipped: no database id");
                continue;
            };
            queries::update_device(
                client,
                &DeviceUpdate {
                    id,
                    state: snapshot.state,
                    last_ip: snapshot.last_ip.clone(),
                    last_ipv6: snapshot.last_ipv6.clone(),
                    last_interface: snapshot.last_interface.clone(),
                    last_seen_at: snapshot.last_seen_at,
                    resolved_name: Some(snapshot.identity.display_name.clone()),
                    identity_source: Some(snapshot.identity.source.as_str().to_string()),
                    #[allow(clippy::cast_possible_truncation)] // Confidence is a weight in
                    // [0.0, 1.0] stored as REAL; f64 to f32 loses nothing that matters.
                    identity_confidence: Some(snapshot.identity.confidence as f32),
                    hostname: snapshot.hostname.clone(),
                    mdns_name: snapshot.mdns_name.clone(),
                    vendor: snapshot.vendor.clone(),
                    device_type: snapshot.device_type.clone(),
                    device_type_confidence: snapshot.device_type_confidence,
                    os_family: snapshot.os_family.clone(),
                    current_ap: snapshot.current_ap.clone(),
                    current_location: snapshot.current_location.clone(),
                },
            )
            .await
            .with_context(|| format!("flushing device {}", snapshot.mac))?;

            if snapshot.observations_since_flush > 0 {
                queries::bump_presence(client, id, snapshot.observations_since_flush)
                    .await
                    .with_context(|| format!("counting observations for {}", snapshot.mac))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DeviceState;
    use chrono::{TimeZone, Utc};

    fn record(mac: &str, id: i64) -> DeviceRecord {
        DeviceRecord {
            id,
            mac: mac.parse().expect("mac"),
            display_name: None,
            resolved_name: None,
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
            first_seen_at: Utc.timestamp_opt(0, 0).single().expect("epoch"),
            last_seen_at: Utc.timestamp_opt(0, 0).single().expect("epoch"),
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
    fn seeding_maps_every_loaded_device() {
        let mut p = Persister::new();
        assert!(p.is_empty());
        p.seed(&[
            record("3c:22:fb:00:00:01", 7),
            record("b8:27:eb:00:00:02", 9),
        ]);
        assert_eq!(p.len(), 2);
        assert_eq!(p.id_for("3c:22:fb:00:00:01".parse().expect("mac")), Some(7));
        assert_eq!(p.id_for("b8:27:eb:00:00:02".parse().expect("mac")), Some(9));
        assert_eq!(p.id_for("00:00:00:00:00:99".parse().expect("mac")), None);
    }
}
