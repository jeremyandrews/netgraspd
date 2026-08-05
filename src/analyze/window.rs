//! Bounded sliding windows, the one data structure every analyzer needs.
//!
//! An analyzer keeps per-MAC or per-address state, and the traffic that makes it
//! interesting is exactly the traffic that makes that state grow: a scanner
//! forging a new source address per packet would otherwise be able to exhaust
//! the daemon's memory by scanning it. Every structure here is capacity-bounded
//! and evicts its least recently touched entry, so the worst a hostile network
//! can do is push a legitimate device out of the window.
//!
//! Nothing here is persisted. The analyzers rebuild from live traffic in
//! seconds, and a security detector that trusted state written before a crash
//! would be trusting state written by whatever caused the crash.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::Duration;

use chrono::{DateTime, Utc};

/// A map with a hard entry cap that evicts the least recently touched key.
///
/// Not an LRU cache with a linked list: the maps here hold thousands of entries
/// at most, and a linear scan for the oldest on the rare eviction is simpler,
/// allocation-free, and impossible to get subtly wrong.
#[derive(Debug)]
pub struct BoundedMap<K, V> {
    entries: HashMap<K, (V, DateTime<Utc>)>,
    capacity: usize,
    evictions: u64,
}

impl<K: Eq + Hash + Clone, V> BoundedMap<K, V> {
    /// Builds a map holding at most `capacity` entries.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        BoundedMap {
            entries: HashMap::new(),
            capacity: capacity.max(1),
            evictions: 0,
        }
    }

    /// The value for a key, without touching its recency.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key).map(|(value, _)| value)
    }

    /// The value for a key, marking it as touched now.
    pub fn get_mut(&mut self, key: &K, now: DateTime<Utc>) -> Option<&mut V> {
        self.entries.get_mut(key).map(|(value, seen)| {
            *seen = now;
            value
        })
    }

    /// The value for a key, inserting the default if absent, evicting first if
    /// that would exceed the capacity.
    pub fn entry_or_insert_with(
        &mut self,
        key: K,
        now: DateTime<Utc>,
        default: impl FnOnce() -> V,
    ) -> &mut V {
        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            self.evict_oldest();
        }
        let slot = self.entries.entry(key).or_insert_with(|| (default(), now));
        slot.1 = now;
        &mut slot.0
    }

    /// Inserts or replaces a value.
    pub fn insert(&mut self, key: K, value: V, now: DateTime<Utc>) {
        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            self.evict_oldest();
        }
        self.entries.insert(key, (value, now));
    }

    /// Drops every entry untouched for longer than `max_age`.
    pub fn prune(&mut self, now: DateTime<Utc>, max_age: Duration) {
        let Ok(max_age) = chrono::Duration::from_std(max_age) else {
            return;
        };
        self.entries
            .retain(|_, (_, seen)| now.signed_duration_since(*seen) <= max_age);
    }

    /// How many entries are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many entries have been evicted for capacity since construction.
    ///
    /// A number that keeps climbing means `security.max_tracked` is too small
    /// for the network, or that something is forging source addresses.
    #[must_use]
    pub const fn evictions(&self) -> u64 {
        self.evictions
    }

    /// Removes the least recently touched entry.
    fn evict_oldest(&mut self) {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, (_, seen))| *seen)
            .map(|(key, _)| key.clone());
        if let Some(key) = oldest {
            self.entries.remove(&key);
            self.evictions += 1;
        }
    }
}

/// A count of distinct values seen inside a sliding time window.
///
/// Used by `arp_scan` for distinct target addresses per MAC, and shaped so that
/// counting the same target repeatedly cannot fake a scan: a device retrying one
/// unanswered ARP two hundred times is not sweeping anything.
#[derive(Debug, Default)]
pub struct DistinctWindow<T> {
    seen: Vec<(T, DateTime<Utc>)>,
    capacity: usize,
}

impl<T: Eq + Clone> DistinctWindow<T> {
    /// Builds a window holding at most `capacity` distinct values.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        DistinctWindow {
            seen: Vec::new(),
            capacity: capacity.max(1),
        }
    }

    /// Records a value and returns how many distinct values are inside the
    /// window as of `now`.
    pub fn record(&mut self, value: T, now: DateTime<Utc>, window: Duration) -> usize {
        let Ok(window) = chrono::Duration::from_std(window) else {
            return self.seen.len();
        };
        self.seen
            .retain(|(_, at)| now.signed_duration_since(*at) <= window);
        match self
            .seen
            .iter_mut()
            .find(|(existing, _)| *existing == value)
        {
            Some((_, at)) => *at = now,
            None => {
                if self.seen.len() >= self.capacity {
                    // Drop the oldest rather than refusing the new one: the
                    // count is already over any sane threshold by this point,
                    // and refusing would freeze the window.
                    self.seen.remove(0);
                }
                self.seen.push((value, now));
            }
        }
        self.seen.len()
    }

    /// How many distinct values are currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// True when nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Forgets everything, used after an alert fires so the next one needs a
    /// fresh burst rather than re-firing on the same evidence.
    pub fn clear(&mut self) {
        self.seen.clear();
    }
}

/// A count of events inside a sliding time window.
#[derive(Debug, Default)]
pub struct RateWindow {
    events: Vec<DateTime<Utc>>,
    capacity: usize,
}

impl RateWindow {
    /// Builds a window holding at most `capacity` timestamps.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        RateWindow {
            events: Vec::new(),
            capacity: capacity.max(1),
        }
    }

    /// Records an event and returns how many are inside the window.
    pub fn record(&mut self, now: DateTime<Utc>, window: Duration) -> usize {
        let Ok(window) = chrono::Duration::from_std(window) else {
            return self.events.len();
        };
        self.events
            .retain(|at| now.signed_duration_since(*at) <= window);
        if self.events.len() >= self.capacity {
            self.events.remove(0);
        }
        self.events.push(now);
        self.events.len()
    }

    /// Forgets everything.
    pub fn clear(&mut self) {
        self.events.clear();
    }

    /// How many timestamps are currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// True when nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_770_000_000 + secs, 0)
            .single()
            .expect("valid timestamp")
    }

    #[test]
    fn a_bounded_map_evicts_the_least_recently_touched_entry() {
        let mut map: BoundedMap<u8, u8> = BoundedMap::new(3);
        map.insert(1, 10, at(0));
        map.insert(2, 20, at(1));
        map.insert(3, 30, at(2));
        // Touch key 1 so key 2 becomes the oldest.
        assert_eq!(map.get_mut(&1, at(3)).copied(), Some(10));
        map.insert(4, 40, at(4));
        assert_eq!(map.len(), 3);
        assert_eq!(map.get(&2), None, "the least recently touched went");
        assert_eq!(map.get(&1).copied(), Some(10));
        assert_eq!(map.get(&4).copied(), Some(40));
        assert_eq!(map.evictions(), 1);
    }

    #[test]
    fn a_bounded_map_cannot_be_grown_past_its_capacity() {
        // The hostile case: a new key per packet.
        let mut map: BoundedMap<u32, u32> = BoundedMap::new(16);
        for n in 0..10_000u32 {
            map.insert(n, n, at(i64::from(n)));
        }
        assert_eq!(map.len(), 16);
        assert!(map.evictions() > 9_000);
    }

    #[test]
    fn a_zero_capacity_map_still_holds_one_entry() {
        let mut map: BoundedMap<u8, u8> = BoundedMap::new(0);
        map.insert(1, 1, at(0));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn pruning_drops_only_what_has_aged_out() {
        let mut map: BoundedMap<u8, u8> = BoundedMap::new(16);
        map.insert(1, 1, at(0));
        map.insert(2, 2, at(50));
        map.prune(at(60), Duration::from_secs(30));
        assert_eq!(map.get(&1), None);
        assert_eq!(map.get(&2).copied(), Some(2));
    }

    #[test]
    fn a_distinct_window_counts_values_not_packets() {
        // The false positive this prevents: one device retrying one ARP.
        let mut window = DistinctWindow::new(64);
        for _ in 0..200 {
            assert_eq!(window.record(42u8, at(0), Duration::from_secs(30)), 1);
        }
    }

    #[test]
    fn a_distinct_window_forgets_values_older_than_the_window() {
        let mut window = DistinctWindow::new(64);
        window.record(1u8, at(0), Duration::from_secs(30));
        window.record(2u8, at(10), Duration::from_secs(30));
        assert_eq!(window.record(3u8, at(20), Duration::from_secs(30)), 3);
        // At t=40 the first value is 40 seconds old and falls out.
        assert_eq!(window.record(4u8, at(40), Duration::from_secs(30)), 3);
    }

    #[test]
    fn a_distinct_window_is_bounded() {
        let mut window = DistinctWindow::new(8);
        for n in 0..1000u32 {
            window.record(n, at(0), Duration::from_secs(3600));
        }
        assert_eq!(window.len(), 8);
    }

    #[test]
    fn clearing_a_window_makes_the_next_alert_need_fresh_evidence() {
        let mut window = DistinctWindow::new(64);
        for n in 0..10u8 {
            window.record(n, at(0), Duration::from_secs(30));
        }
        assert_eq!(window.len(), 10);
        window.clear();
        assert!(window.is_empty());
        assert_eq!(window.record(0u8, at(1), Duration::from_secs(30)), 1);
    }

    #[test]
    fn a_rate_window_counts_events_inside_the_window() {
        let mut window = RateWindow::new(64);
        for n in 0..5 {
            assert_eq!(
                window.record(at(n), Duration::from_secs(10)),
                usize::try_from(n + 1).expect("small")
            );
        }
        // At t=20 everything before t=10 has aged out.
        assert_eq!(window.record(at(20), Duration::from_secs(10)), 1);
    }

    #[test]
    fn a_rate_window_is_bounded() {
        let mut window = RateWindow::new(4);
        for n in 0..100 {
            window.record(at(n), Duration::from_secs(3600));
        }
        assert_eq!(window.len(), 4);
    }
}
