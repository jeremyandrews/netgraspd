//! Where a device is, and what a change of place means.
//!
//! Passive capture cannot see location: an ARP request looks the same from the
//! driveway as from the kitchen. An enricher supplies the access point a device
//! is associated with, and this module turns that into two things worth knowing.
//!
//! - A **location**, from the operator's AP-to-room map. An AP with no entry
//!   falls back to its own name, so a newly adopted access point shows up as
//!   itself rather than disappearing.
//! - A **movement**, from the pair of APs the device crossed between. This is
//!   the whole reason edge APs exist: a device that goes from the driveway to
//!   the living room is somebody arriving, and a device that goes from the
//!   living room to the driveway and then falls silent is somebody leaving.
//!   A device that goes from the kitchen to the living room is somebody walking
//!   about, and firing an arrival for that would make the feature useless.

use std::collections::{BTreeMap, BTreeSet};

use crate::config::UnifiConfig;

/// What a device crossing from one access point to another means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Movement {
    /// An edge AP to an interior one: somebody came in.
    Arriving,
    /// An interior AP to an edge one: somebody is on their way out. On its own
    /// this is not a departure; the person has left when their last device goes
    /// offline, and this is the evidence for *how* they left.
    Departing,
    /// Interior to interior, or edge to edge. Somebody moving about, which must
    /// never read as an arrival or a departure.
    Roaming,
    /// There is no previous access point to compare against, so the crossing
    /// cannot be classified. The first time a device is seen, and the first
    /// enrichment poll after a restart.
    Unknown,
}

impl Movement {
    /// Stable string, used in event details.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Movement::Arriving => "arriving",
            Movement::Departing => "departing",
            Movement::Roaming => "roaming",
            Movement::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for Movement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a device is, resolved from an access point name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    /// The access point, as the controller named it.
    pub ap_name: String,
    /// The human-readable location, or the AP's own name when unmapped.
    pub location: String,
    /// Whether this AP is one that sees arrivals and departures first.
    pub edge: bool,
}

/// The operator's map from access points to places.
///
/// Names are matched case-insensitively after trimming, because an AP name is
/// typed into the controller by a human and typed into `netgrasp.toml` by the
/// same human on a different day.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocationMap {
    /// Lowercased AP name to location.
    locations: BTreeMap<String, String>,
    /// Lowercased AP names that are edges.
    edge_aps: BTreeSet<String>,
}

impl LocationMap {
    /// Builds a map from the UniFi enricher's configuration.
    #[must_use]
    pub fn from_unifi(cfg: &UnifiConfig) -> Self {
        let mut locations = BTreeMap::new();
        for (ap, location) in &cfg.locations {
            let location = location.trim();
            if !location.is_empty() {
                locations.insert(key(ap), location.to_string());
            }
        }
        let edge_aps = cfg
            .edge_aps
            .iter()
            .map(|ap| key(ap))
            .filter(|ap| !ap.is_empty())
            .collect();
        LocationMap {
            locations,
            edge_aps,
        }
    }

    /// How many APs have an explicit location.
    #[must_use]
    pub fn len(&self) -> usize {
        self.locations.len()
    }

    /// True when no AP has an explicit location.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }

    /// How many APs are marked as edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edge_aps.len()
    }

    /// True when the named AP sees arrivals and departures first.
    #[must_use]
    pub fn is_edge(&self, ap: &str) -> bool {
        self.edge_aps.contains(&key(ap))
    }

    /// The location for an AP, falling back to the AP's own name.
    ///
    /// The fallback is deliberate. An operator who adds an access point and
    /// forgets to map it should see `Garage AP` in the device list, not an empty
    /// cell and not a device that appears to have no location at all.
    #[must_use]
    pub fn location_of(&self, ap: &str) -> String {
        self.locations
            .get(&key(ap))
            .cloned()
            .unwrap_or_else(|| ap.trim().to_string())
    }

    /// Resolves an AP name into a full place.
    #[must_use]
    pub fn place(&self, ap: &str) -> Place {
        Place {
            ap_name: ap.trim().to_string(),
            location: self.location_of(ap),
            edge: self.is_edge(ap),
        }
    }

    /// Classifies a crossing from one access point to another.
    ///
    /// `previous` is `None` the first time a device is placed, which is
    /// [`Movement::Unknown`] rather than an arrival: a device that was already
    /// in the house when the daemon started has not arrived, and saying so on
    /// every restart would be a notification storm.
    #[must_use]
    pub fn movement(&self, previous: Option<&str>, current: &str) -> Movement {
        let Some(previous) = previous else {
            return Movement::Unknown;
        };
        if key(previous) == key(current) {
            return Movement::Roaming;
        }
        match (self.is_edge(previous), self.is_edge(current)) {
            (true, false) => Movement::Arriving,
            (false, true) => Movement::Departing,
            // Interior to interior is somebody walking about. Edge to edge is
            // somebody still outside, moving between the driveway and the
            // garage; neither is a crossing of the threshold.
            (false, false) | (true, true) => Movement::Roaming,
        }
    }
}

/// Normalises an AP name for comparison.
fn key(ap: &str) -> String {
    ap.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> LocationMap {
        let mut cfg = UnifiConfig::default();
        cfg.locations
            .insert("Driveway AP".into(), "Driveway".into());
        cfg.locations.insert("Garage AP".into(), "Garage".into());
        cfg.locations
            .insert("Living Room AP".into(), "Living Room".into());
        cfg.locations.insert("Kitchen AP".into(), "Kitchen".into());
        cfg.edge_aps = vec!["Driveway AP".into(), "Garage AP".into()];
        LocationMap::from_unifi(&cfg)
    }

    #[test]
    fn a_mapped_ap_resolves_to_its_location() {
        assert_eq!(map().location_of("Living Room AP"), "Living Room");
    }

    #[test]
    fn an_unmapped_ap_falls_back_to_its_own_name() {
        // The failure this avoids: an operator adds an access point, forgets to
        // map it, and every device on it appears to have no location.
        assert_eq!(map().location_of("Backyard AP"), "Backyard AP");
        assert!(!map().is_edge("Backyard AP"));
    }

    #[test]
    fn ap_names_match_regardless_of_case_and_padding() {
        let m = map();
        assert_eq!(m.location_of("  living room ap  "), "Living Room");
        assert_eq!(m.location_of("DRIVEWAY AP"), "Driveway");
        assert!(m.is_edge(" driveway ap "));
    }

    #[test]
    fn a_place_carries_the_ap_the_location_and_the_edge_flag() {
        let p = map().place("Driveway AP");
        assert_eq!(p.ap_name, "Driveway AP");
        assert_eq!(p.location, "Driveway");
        assert!(p.edge);

        let p = map().place("Kitchen AP");
        assert_eq!(p.location, "Kitchen");
        assert!(!p.edge);
    }

    #[test]
    fn edge_then_interior_is_arriving() {
        assert_eq!(
            map().movement(Some("Driveway AP"), "Living Room AP"),
            Movement::Arriving
        );
    }

    #[test]
    fn interior_then_edge_is_departing() {
        assert_eq!(
            map().movement(Some("Living Room AP"), "Garage AP"),
            Movement::Departing
        );
    }

    #[test]
    fn interior_to_interior_is_only_roaming() {
        // The case that must not fire. Somebody carrying a phone from the
        // kitchen to the living room has not arrived and has not left.
        let m = map();
        assert_eq!(
            m.movement(Some("Kitchen AP"), "Living Room AP"),
            Movement::Roaming
        );
        assert_eq!(
            m.movement(Some("Living Room AP"), "Kitchen AP"),
            Movement::Roaming
        );
    }

    #[test]
    fn edge_to_edge_is_roaming_because_they_are_still_outside() {
        assert_eq!(
            map().movement(Some("Driveway AP"), "Garage AP"),
            Movement::Roaming
        );
    }

    #[test]
    fn staying_on_the_same_ap_is_roaming_not_an_arrival() {
        let m = map();
        assert_eq!(
            m.movement(Some("Driveway AP"), "Driveway AP"),
            Movement::Roaming
        );
        assert_eq!(
            m.movement(Some("driveway ap"), "Driveway AP"),
            Movement::Roaming,
            "case must not manufacture a crossing"
        );
    }

    #[test]
    fn a_first_placement_is_unknown_rather_than_an_arrival() {
        // A device already in the house when the daemon starts has not arrived.
        assert_eq!(map().movement(None, "Living Room AP"), Movement::Unknown);
        assert_eq!(map().movement(None, "Driveway AP"), Movement::Unknown);
    }

    #[test]
    fn an_unmapped_ap_counts_as_interior_which_keeps_arrivals_conservative() {
        // Whether an unknown AP is an edge is a guess either way. Treating it as
        // interior means a forgotten mapping produces no arrival rather than a
        // false one.
        let m = map();
        assert_eq!(
            m.movement(Some("Driveway AP"), "Attic AP"),
            Movement::Arriving,
            "leaving an edge for anywhere else is still arriving"
        );
        assert_eq!(
            m.movement(Some("Attic AP"), "Kitchen AP"),
            Movement::Roaming
        );
    }

    #[test]
    fn the_map_reports_what_it_was_built_from() {
        let m = map();
        assert_eq!(m.len(), 4);
        assert_eq!(m.edge_count(), 2);
        assert!(!m.is_empty());
        assert!(LocationMap::default().is_empty());
    }

    #[test]
    fn a_blank_location_mapping_is_ignored_rather_than_stored() {
        let mut cfg = UnifiConfig::default();
        cfg.locations.insert("Ghost AP".into(), "   ".into());
        let m = LocationMap::from_unifi(&cfg);
        assert!(m.is_empty());
        assert_eq!(m.location_of("Ghost AP"), "Ghost AP");
    }

    #[test]
    fn movement_strings_are_distinct() {
        let names: std::collections::HashSet<&str> = [
            Movement::Arriving,
            Movement::Departing,
            Movement::Roaming,
            Movement::Unknown,
        ]
        .iter()
        .map(Movement::as_str)
        .collect();
        assert_eq!(names.len(), 4);
    }
}
