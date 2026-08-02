//! The event bus.
//!
//! A tokio broadcast channel carrying every recorded event to every subscriber.
//! Broadcast rather than mpsc because there will be more than one consumer: the
//! notification dispatcher today, and the security analyzers and the live table
//! later.
//!
//! Publishing never blocks and never fails the caller. An event that nobody is
//! listening to is dropped on the floor, and a slow subscriber that falls behind
//! loses the oldest events with a warning. That is the right trade for a
//! monitoring daemon: `ng_events` is the durable record, and the bus is only the
//! fast path to a notifier.

use tokio::sync::broadcast;

use crate::device::persist::RecordedEvent;

/// Default channel depth. Deep enough to absorb a network restart discovering a
/// hundred devices at once without any subscriber lagging.
pub const DEFAULT_CAPACITY: usize = 1024;

/// A broadcast bus for recorded events.
#[derive(Debug, Clone)]
pub struct EventBus {
    tx: broadcast::Sender<RecordedEvent>,
}

impl EventBus {
    /// Builds a bus with the given channel depth.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity.max(1));
        EventBus { tx }
    }

    /// Publishes an event.
    ///
    /// Returns the number of subscribers it reached, which is zero when nobody
    /// is listening. That is not an error: the durable record is already in
    /// `ng_events` by the time this is called.
    pub fn publish(&self, event: RecordedEvent) -> usize {
        self.tx.send(event).unwrap_or(0)
    }

    /// Publishes a batch.
    pub fn publish_all(&self, events: impl IntoIterator<Item = RecordedEvent>) {
        for event in events {
            self.publish(event);
        }
    }

    /// Subscribes. A receiver only sees events published after it subscribed.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<RecordedEvent> {
        self.tx.subscribe()
    }

    /// How many receivers are currently subscribed.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        EventBus::new(DEFAULT_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceEvent;
    use crate::types::EventType;
    use chrono::{TimeZone, Utc};

    fn recorded(id: i64) -> RecordedEvent {
        RecordedEvent {
            id,
            event: DeviceEvent {
                event_type: EventType::NewDevice,
                mac: "3c:22:fb:00:00:01".parse().expect("mac"),
                display_name: "test".into(),
                vendor: None,
                ip: None,
                interface: None,
                at: Utc.timestamp_opt(0, 0).single().expect("epoch"),
                baseline: false,
                during_learning: false,
                notify: true,
                details: serde_json::Value::Null,
            },
        }
    }

    #[tokio::test]
    async fn every_subscriber_sees_every_event() {
        let bus = EventBus::new(16);
        let mut a = bus.subscribe();
        let mut b = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);
        assert_eq!(bus.publish(recorded(1)), 2);
        assert_eq!(a.recv().await.expect("a receives").id, 1);
        assert_eq!(b.recv().await.expect("b receives").id, 1);
    }

    #[tokio::test]
    async fn publishing_with_no_subscribers_is_not_an_error() {
        let bus = EventBus::new(16);
        assert_eq!(bus.publish(recorded(1)), 0);
    }

    #[tokio::test]
    async fn a_lagging_subscriber_loses_the_oldest_events_rather_than_stalling_the_bus() {
        let bus = EventBus::new(2);
        let mut rx = bus.subscribe();
        for id in 1..=5 {
            bus.publish(recorded(id));
        }
        // The first receive reports the lag rather than silently skipping.
        let err = rx.recv().await.expect_err("expected a lag error");
        assert!(
            matches!(err, broadcast::error::RecvError::Lagged(_)),
            "{err:?}"
        );
        // ...and the channel is still usable afterwards.
        assert_eq!(rx.recv().await.expect("still usable").id, 4);
    }

    #[tokio::test]
    async fn a_batch_arrives_in_order() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();
        bus.publish_all((1..=3).map(recorded));
        for expected in 1..=3 {
            assert_eq!(rx.recv().await.expect("in order").id, expected);
        }
    }
}
