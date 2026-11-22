//! A device somebody has approved stays quiet about its routine behaviour.
//!
//! A Mac waking up re-announces its address and can look like a different kind
//! of device for a moment. On a device a person has already named or assigned
//! to somebody, `identity_change` and `gratuitous_arp` are noise, and they used
//! to reach the phone as security alerts every time. This drives the real path:
//! the device table builds the event, the dispatcher decides, and a whole day
//! passes so that nothing is merely waiting for a batch window, a pooled summary
//! or the digest.
//!
//! No database: the device comes in through `Manager::restore`, the same door
//! the daemon uses at startup.

use std::collections::HashMap;

use jiff::SignedDuration;
use jiff::tz::Offset;
use netgraspd::analyze::SecurityAlert;
use netgraspd::clock::Timestamp;
use netgraspd::config::{NotifyConfig, SecurityNotifyConfig, StateConfig};
use netgraspd::db::queries::DeviceRecord;
use netgraspd::device::persist::RecordedEvent;
use netgraspd::device::{Effect, Manager};
use netgraspd::notify::{Delivery, Dispatcher};
use netgraspd::types::{DeviceState, EventPriority, EventType, MacAddr};

const MAC: &str = "12:9d:e5:b1:7f:49";

fn base() -> Timestamp {
    Timestamp::from_utc(2026, 11, 18, 9, 0, 0).expect("valid time")
}

/// A device a person has named, with `notify` off as schema V6 leaves it.
fn named_device(mac: MacAddr) -> DeviceRecord {
    DeviceRecord {
        id: 1,
        mac,
        display_name: Some("Studio".into()),
        resolved_name: Some("BEAF9A552805@Jeremy's Mac Studio (2)".into()),
        identity_source: None,
        identity_confidence: None,
        hostname: None,
        mdns_name: None,
        vendor: None,
        device_type: Some("media_player".into()),
        device_type_confidence: None,
        os_family: None,
        state: DeviceState::Online,
        last_ip: Some("10.20.228.235".into()),
        last_ipv6: None,
        last_interface: Some("end0".into()),
        first_seen_at: base(),
        last_seen_at: base(),
        baseline: true,
        current_ap: None,
        current_location: None,
        hidden: false,
        notify: false,
        notes: None,
        owner_item_id: None,
    }
}

#[test]
fn an_approved_device_emitting_identity_change_and_gratuitous_arp_delivers_nothing() {
    let mac: MacAddr = MAC.parse().expect("mac");
    let mut manager = Manager::new(StateConfig::default(), false);
    manager.restore(vec![named_device(mac)], HashMap::new());
    let mut dispatcher = Dispatcher::new(
        NotifyConfig::default(),
        SecurityNotifyConfig::default(),
        Offset::from_seconds(3600).expect("offset"),
    );

    let mut deliveries: Vec<Delivery> = Vec::new();
    let mut id = 0;
    // A morning of wake-ups: both kinds, every ten minutes for three hours.
    for step in 0..18 {
        let at = base() + SignedDuration::from_mins(step * 10);
        for kind in [EventType::IdentityChange, EventType::GratuitousArp] {
            let alert =
                SecurityAlert::new(kind, mac, at, EventPriority::High, serde_json::json!({}));
            for effect in manager.security_event(&alert) {
                if let Effect::Event(event) = effect {
                    id += 1;
                    deliveries.extend(dispatcher.offer(RecordedEvent { id, event: *event }, at));
                }
            }
        }
    }
    assert_eq!(id, 36, "every alert became an event, recorded either way");

    // A whole day later: every batch window, pool period and digest time has
    // come and gone.
    for minute in 0..=(26 * 60) {
        deliveries.extend(dispatcher.tick(base() + SignedDuration::from_mins(minute)));
    }
    deliveries.extend(dispatcher.drain());
    assert!(
        deliveries.is_empty(),
        "an approved device must deliver nothing for identity_change or gratuitous_arp: \
         {deliveries:#?}"
    );
}
