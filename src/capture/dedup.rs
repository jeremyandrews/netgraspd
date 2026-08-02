//! Cross-interface observation dedup.
//!
//! A host listening on several interfaces of the same bridged LAN sees the same
//! broadcast twice, and a device that ARPs in a tight loop produces a burst of
//! identical sightings. Neither adds information.
//!
//! The key is `(MAC, observation kind, timestamp rounded to one second)`,
//! deliberately excluding the interface so that the same frame arriving on two
//! interfaces collapses. The set is bounded and evicts in insertion order, so a
//! busy network cannot grow it without limit.

use std::collections::{HashSet, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};

use crate::types::Observation;

/// Bounded set of recently seen observation keys.
#[derive(Debug)]
pub struct ObservationDedup {
    seen: HashSet<u64>,
    order: VecDeque<u64>,
    capacity: usize,
    resolution_secs: i64,
    duplicates: u64,
}

impl ObservationDedup {
    /// Builds a deduper.
    ///
    /// `resolution_secs` of zero is treated as one, because rounding to a
    /// zero-width bucket would make every observation unique and quietly
    /// disable the whole mechanism.
    #[must_use]
    pub fn new(capacity: usize, resolution_secs: u64) -> Self {
        ObservationDedup {
            seen: HashSet::with_capacity(capacity.min(1 << 16)),
            order: VecDeque::with_capacity(capacity.min(1 << 16)),
            capacity: capacity.max(1),
            resolution_secs: i64::try_from(resolution_secs.max(1)).unwrap_or(1),
            duplicates: 0,
        }
    }

    /// Records an observation and reports whether it is new.
    ///
    /// Returns `true` when the caller should process it, `false` when it is a
    /// duplicate of something seen in the same time bucket.
    pub fn admit(&mut self, obs: &Observation) -> bool {
        let key = self.key(obs);
        if !self.seen.insert(key) {
            self.duplicates += 1;
            return false;
        }
        self.order.push_back(key);
        while self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }

    /// How many duplicates have been suppressed since startup.
    #[must_use]
    pub const fn duplicates_suppressed(&self) -> u64 {
        self.duplicates
    }

    /// How many keys are currently retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// True when nothing is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    fn key(&self, obs: &Observation) -> u64 {
        let bucket = obs.observed_at.timestamp().div_euclid(self.resolution_secs);
        let mut hasher = DefaultHasher::new();
        obs.mac.hash(&mut hasher);
        obs.kind.as_str().hash(&mut hasher);
        bucket.hash(&mut hasher);
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{MacAddr, ObservationKind};
    use chrono::{DateTime, TimeZone, Utc};

    fn at(secs: i64, millis: u32) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, millis * 1_000_000)
            .single()
            .expect("valid timestamp")
    }

    fn obs(mac: &str, iface: &str, kind: ObservationKind, ts: DateTime<Utc>) -> Observation {
        Observation::new(
            mac.parse::<MacAddr>().expect("mac"),
            None,
            iface,
            "test",
            kind,
            ts,
        )
    }

    #[test]
    fn the_same_frame_on_two_interfaces_is_one_observation() {
        let mut d = ObservationDedup::new(64, 1);
        let a = obs(
            "aa:bb:cc:00:00:01",
            "eth0",
            ObservationKind::Request,
            at(100, 10),
        );
        let b = obs(
            "aa:bb:cc:00:00:01",
            "wlan0",
            ObservationKind::Request,
            at(100, 90),
        );
        assert!(d.admit(&a));
        assert!(
            !d.admit(&b),
            "same MAC, kind and second on another interface"
        );
        assert_eq!(d.duplicates_suppressed(), 1);
    }

    #[test]
    fn different_kinds_in_the_same_second_both_pass() {
        let mut d = ObservationDedup::new(64, 1);
        let ts = at(100, 0);
        assert!(d.admit(&obs(
            "aa:bb:cc:00:00:01",
            "eth0",
            ObservationKind::Request,
            ts
        )));
        assert!(d.admit(&obs(
            "aa:bb:cc:00:00:01",
            "eth0",
            ObservationKind::Announcement,
            ts
        )));
    }

    #[test]
    fn different_macs_in_the_same_second_both_pass() {
        let mut d = ObservationDedup::new(64, 1);
        let ts = at(100, 0);
        assert!(d.admit(&obs(
            "aa:bb:cc:00:00:01",
            "eth0",
            ObservationKind::Request,
            ts
        )));
        assert!(d.admit(&obs(
            "aa:bb:cc:00:00:02",
            "eth0",
            ObservationKind::Request,
            ts
        )));
    }

    #[test]
    fn the_next_second_is_a_new_bucket() {
        let mut d = ObservationDedup::new(64, 1);
        assert!(d.admit(&obs(
            "aa:bb:cc:00:00:01",
            "eth0",
            ObservationKind::Request,
            at(100, 999)
        )));
        assert!(d.admit(&obs(
            "aa:bb:cc:00:00:01",
            "eth0",
            ObservationKind::Request,
            at(101, 0)
        )));
    }

    #[test]
    fn a_coarser_resolution_collapses_more() {
        let mut d = ObservationDedup::new(64, 10);
        assert!(d.admit(&obs(
            "aa:bb:cc:00:00:01",
            "eth0",
            ObservationKind::Request,
            at(100, 0)
        )));
        assert!(!d.admit(&obs(
            "aa:bb:cc:00:00:01",
            "eth0",
            ObservationKind::Request,
            at(109, 0)
        )));
        assert!(d.admit(&obs(
            "aa:bb:cc:00:00:01",
            "eth0",
            ObservationKind::Request,
            at(110, 0)
        )));
    }

    #[test]
    fn zero_resolution_is_clamped_rather_than_dividing_by_zero() {
        let mut d = ObservationDedup::new(64, 0);
        let ts = at(100, 0);
        assert!(d.admit(&obs(
            "aa:bb:cc:00:00:01",
            "eth0",
            ObservationKind::Request,
            ts
        )));
        assert!(!d.admit(&obs(
            "aa:bb:cc:00:00:01",
            "eth0",
            ObservationKind::Request,
            ts
        )));
    }

    #[test]
    fn the_set_is_bounded_and_evicts_oldest_first() {
        let mut d = ObservationDedup::new(4, 1);
        for i in 0..10u8 {
            let mac = format!("aa:bb:cc:00:00:{i:02x}");
            assert!(d.admit(&obs(&mac, "eth0", ObservationKind::Request, at(100, 0))));
        }
        assert_eq!(d.len(), 4, "capacity must hold");
        // The oldest key has been evicted, so it is admitted again rather than
        // being remembered forever.
        assert!(d.admit(&obs(
            "aa:bb:cc:00:00:00",
            "eth0",
            ObservationKind::Request,
            at(100, 0)
        )));
        // The newest is still remembered.
        assert!(!d.admit(&obs(
            "aa:bb:cc:00:00:09",
            "eth0",
            ObservationKind::Request,
            at(100, 0)
        )));
    }

    #[test]
    fn a_flapping_device_is_collapsed_within_the_bucket() {
        let mut d = ObservationDedup::new(1024, 1);
        let mut admitted = 0;
        for ms in 0..1000u32 {
            let o = obs(
                "aa:bb:cc:00:00:01",
                "eth0",
                ObservationKind::Request,
                at(500, ms),
            );
            if d.admit(&o) {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 1, "1000 packets in one second is one observation");
        assert_eq!(d.duplicates_suppressed(), 999);
    }
}
