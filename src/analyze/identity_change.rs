//! Detects a device becoming a different kind of device.
//!
//! The other five analyzers watch the wire. This one watches the classifier: it
//! is fed a [`Reclassification`] whenever the state machine recomputes what a
//! device is, and decides whether the change is worth an alert.
//!
//! A device does not usually change what it is. When one does, the interesting
//! readings are:
//!
//! - A MAC has been cloned, and two different machines are now answering to it.
//! - Firmware was replaced, wholesale, on something that should not have been.
//! - Somebody has plugged a laptop into the socket the printer was in.
//!
//! ## `category` versus `any`
//!
//! The default, `category`, fires only when a *known* device type or OS family
//! becomes a *different known* one. Learning a classification for the first time
//! is a refinement, not a change: every device on a fresh install goes from
//! nothing to something, and firing on that would mean an alert per device on
//! the first day and none of them meaningful.
//!
//! `any` also fires on that first classification. It is noisy by design and
//! exists for hunting, where "this device just told me what it is" is the event
//! somebody is watching for.
//!
//! ## What a category change actually is, given how signals accumulate
//!
//! Worth stating plainly, because it is not obvious and it decides how often
//! this fires. Signals are never removed: a device that once advertised
//! `_ipp._tcp` advertises it forever as far as `ng_device_signals` is concerned.
//! The classifier resolves the pile by evidence rank, first hit wins. So a
//! device's type changes **only when evidence of a higher rank contradicts what
//! a lower rank said**: a host classified `media_player` from an mDNS service
//! becomes `router` when it emits a Router Advertisement, or a host classified
//! `printer` becomes `nas` when it declares a UPnP MediaServer class.
//!
//! That is the right thing to alert on. Weaker evidence arriving later cannot
//! move the classification and so cannot produce noise, and the changes that do
//! get through are exactly the cases where the device is now asserting something
//! about itself that contradicts what it asserted before.

use chrono::{DateTime, Utc};
use serde_json::json;

use crate::analyze::{Analyzer, Context, SecurityAlert, Stimulus, cooled_down};
use crate::config::IdentityChangeConfig;
use crate::device::Reclassification;
use crate::types::{EventPriority, EventType, MacAddr};

/// How long after alerting about one device before alerting about it again.
///
/// A device flapping between two classifications because two signals disagree
/// would otherwise alert continuously. Long, because a real identity change
/// happens once.
const COOLDOWN: std::time::Duration = std::time::Duration::from_secs(3600);

/// How many devices are tracked for cooldown purposes.
const MAX_TRACKED: usize = 512;

/// Which changes are worth an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    /// One known classification becoming a different known one.
    Category,
    /// Any change at all, including a first classification.
    Any,
}

impl Sensitivity {
    /// Reads the configured value, defaulting to the quieter reading.
    ///
    /// `config.validate()` rejects anything else before startup; falling back to
    /// `Category` here rather than panicking means a config that somehow slipped
    /// through produces fewer alerts, not more.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "any" => Sensitivity::Any,
            _ => Sensitivity::Category,
        }
    }

    /// Stable name, used in alert details.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Sensitivity::Category => "category",
            Sensitivity::Any => "any",
        }
    }
}

/// The `identity_change` analyzer.
pub struct IdentityChange {
    sensitivity: Sensitivity,
    alerted: Vec<(MacAddr, DateTime<Utc>)>,
}

impl IdentityChange {
    /// Builds the analyzer.
    #[must_use]
    pub fn new(config: &IdentityChangeConfig) -> Self {
        IdentityChange {
            sensitivity: Sensitivity::parse(&config.sensitivity),
            alerted: Vec::new(),
        }
    }

    /// When this device was last alerted about.
    fn last_alert(&self, mac: MacAddr) -> Option<DateTime<Utc>> {
        self.alerted
            .iter()
            .find(|(m, _)| *m == mac)
            .map(|(_, at)| *at)
    }

    /// Records that a device was alerted about.
    fn record_alert(&mut self, mac: MacAddr, at: DateTime<Utc>) {
        if let Some(slot) = self.alerted.iter_mut().find(|(m, _)| *m == mac) {
            slot.1 = at;
            return;
        }
        if self.alerted.len() >= MAX_TRACKED {
            self.alerted.remove(0);
        }
        self.alerted.push((mac, at));
    }
}

impl Analyzer for IdentityChange {
    fn name(&self) -> &'static str {
        "identity_change"
    }

    fn analyze(&mut self, stimulus: &Stimulus<'_>, context: &Context) -> Vec<SecurityAlert> {
        let Stimulus::Reclassified(change) = stimulus else {
            return Vec::new();
        };
        let worth_alerting = match self.sensitivity {
            Sensitivity::Category => change.current.changed_category(&change.previous),
            Sensitivity::Any => change.current.changed_at_all(&change.previous),
        };
        if !worth_alerting {
            return Vec::new();
        }
        if !cooled_down(self.last_alert(change.mac), change.at, COOLDOWN) {
            return Vec::new();
        }
        self.record_alert(change.mac, change.at);

        // A first classification is not a threat even under `any`, so it is
        // reported one notch quieter than a real category change.
        let category = change.current.changed_category(&change.previous);
        let priority = if category {
            context.priority
        } else {
            EventPriority::Normal
        };

        vec![build_alert(change, self.sensitivity, category, priority)]
    }
}

/// Builds the alert for one reclassification.
fn build_alert(
    change: &Reclassification,
    sensitivity: Sensitivity,
    category: bool,
    priority: EventPriority,
) -> SecurityAlert {
    let mut alert = SecurityAlert::new(
        EventType::IdentityChange,
        change.mac,
        change.at,
        priority,
        json!({
            "analyzer": "identity_change",
            "sensitivity": sensitivity.as_str(),
            "category_change": category,
            "previous_device_type": change.previous.device_type,
            "device_type": change.current.device_type,
            "previous_os_family": change.previous.os_family,
            "os_family": change.current.os_family,
            "confidence": change.current.confidence,
            "reason": change.current.reason,
        }),
    );
    if let Some(interface) = &change.interface {
        alert = alert.with_interface(interface.clone());
    }
    alert
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::GatewayTracker;
    use crate::identity::Classification;
    use chrono::TimeZone;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_770_000_000 + secs, 0)
            .single()
            .expect("valid timestamp")
    }

    fn mac(s: &str) -> MacAddr {
        s.parse().expect("test mac")
    }

    fn context() -> Context {
        Context {
            gateway: GatewayTracker::new(None, None),
            exempt: Vec::new(),
            priority: EventPriority::Urgent,
            max_tracked: 1024,
        }
    }

    fn classification(device_type: Option<&str>, os: Option<&str>) -> Classification {
        Classification {
            device_type: device_type.map(str::to_string),
            os_family: os.map(str::to_string),
            confidence: 0.85,
            reason: Some("test".into()),
        }
    }

    fn change(
        previous: Classification,
        current: Classification,
        when: DateTime<Utc>,
    ) -> Reclassification {
        Reclassification {
            mac: mac("3c:22:fb:00:00:01"),
            display_name: "Office Printer".into(),
            previous,
            current,
            interface: Some("eth0".into()),
            at: when,
        }
    }

    fn config(sensitivity: &str) -> IdentityChangeConfig {
        IdentityChangeConfig {
            enabled: true,
            sensitivity: sensitivity.to_string(),
        }
    }

    #[test]
    fn a_printer_becoming_a_computer_fires() {
        let mut analyzer = IdentityChange::new(&config("category"));
        let alerts = analyzer.analyze(
            &Stimulus::Reclassified(&change(
                classification(Some("printer"), Some("embedded")),
                classification(Some("computer"), Some("Windows")),
                at(0),
            )),
            &context(),
        );
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].event_type, EventType::IdentityChange);
        assert_eq!(alerts[0].details["previous_device_type"], "printer");
        assert_eq!(alerts[0].details["device_type"], "computer");
        assert_eq!(alerts[0].details["category_change"], true);
        assert_eq!(alerts[0].priority, EventPriority::Urgent);
        assert_eq!(alerts[0].interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn learning_a_classification_for_the_first_time_is_not_a_change() {
        // Every device on a fresh install does this. Alerting on it would mean
        // an alert per device on day one and none of them meaningful.
        let mut analyzer = IdentityChange::new(&config("category"));
        assert!(
            analyzer
                .analyze(
                    &Stimulus::Reclassified(&change(
                        Classification::default(),
                        classification(Some("printer"), Some("embedded")),
                        at(0),
                    )),
                    &context()
                )
                .is_empty()
        );
    }

    #[test]
    fn under_any_sensitivity_a_first_classification_does_fire_but_quietly() {
        let mut analyzer = IdentityChange::new(&config("any"));
        let alerts = analyzer.analyze(
            &Stimulus::Reclassified(&change(
                Classification::default(),
                classification(Some("printer"), None),
                at(0),
            )),
            &context(),
        );
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].details["category_change"], false);
        assert_eq!(
            alerts[0].priority,
            EventPriority::Normal,
            "learning what a device is does not warrant waking somebody"
        );
    }

    #[test]
    fn an_os_swap_alone_is_a_category_change() {
        let mut analyzer = IdentityChange::new(&config("category"));
        let alerts = analyzer.analyze(
            &Stimulus::Reclassified(&change(
                classification(Some("computer"), Some("Windows")),
                classification(Some("computer"), Some("Linux")),
                at(0),
            )),
            &context(),
        );
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].details["previous_os_family"], "Windows");
        assert_eq!(alerts[0].details["os_family"], "Linux");
    }

    #[test]
    fn an_unchanged_classification_fires_nothing_under_either_sensitivity() {
        for sensitivity in ["category", "any"] {
            let mut analyzer = IdentityChange::new(&config(sensitivity));
            let same = classification(Some("printer"), Some("embedded"));
            assert!(
                analyzer
                    .analyze(
                        &Stimulus::Reclassified(&change(same.clone(), same, at(0))),
                        &context()
                    )
                    .is_empty(),
                "{sensitivity}"
            );
        }
    }

    #[test]
    fn a_device_flapping_between_two_readings_alerts_at_a_bounded_rate() {
        let mut analyzer = IdentityChange::new(&config("category"));
        let context = context();
        let a = classification(Some("printer"), None);
        let b = classification(Some("computer"), None);
        let mut alerts = Vec::new();
        // Flapping every minute for a day.
        for minute in 0..1440i64 {
            let (previous, current) = if minute % 2 == 0 {
                (a.clone(), b.clone())
            } else {
                (b.clone(), a.clone())
            };
            alerts.extend(analyzer.analyze(
                &Stimulus::Reclassified(&change(previous, current, at(minute * 60))),
                &context,
            ));
        }
        assert!(
            (20..=30).contains(&alerts.len()),
            "a 3600s cooldown over 24 hours, got {}",
            alerts.len()
        );
    }

    #[test]
    fn an_observation_is_not_this_analyzers_business() {
        let mut analyzer = IdentityChange::new(&config("category"));
        let observation = crate::capture::arp::parse_frame(
            &crate::capture::fixtures::arp_request(),
            "eth0",
            at(0),
        )
        .expect("parsed");
        assert!(
            analyzer
                .analyze(&Stimulus::Observed(&observation), &context())
                .is_empty()
        );
    }

    #[test]
    fn an_unknown_sensitivity_reads_as_the_quieter_one() {
        assert_eq!(Sensitivity::parse("category"), Sensitivity::Category);
        assert_eq!(Sensitivity::parse("ANY"), Sensitivity::Any);
        assert_eq!(Sensitivity::parse(" any "), Sensitivity::Any);
        assert_eq!(
            Sensitivity::parse("nonsense"),
            Sensitivity::Category,
            "a config that slipped past validation must produce fewer alerts, not more"
        );
    }

    #[test]
    fn the_cooldown_list_is_bounded() {
        let mut analyzer = IdentityChange::new(&config("category"));
        let context = context();
        for n in 0..5000u32 {
            let who = format!(
                "02:00:{:02x}:{:02x}:{:02x}:{:02x}",
                n >> 24,
                (n >> 16) & 0xff,
                (n >> 8) & 0xff,
                n & 0xff
            );
            let mut c = change(
                classification(Some("printer"), None),
                classification(Some("computer"), None),
                at(0),
            );
            c.mac = mac(&who);
            let _ = analyzer.analyze(&Stimulus::Reclassified(&c), &context);
        }
        assert!(analyzer.alerted.len() <= MAX_TRACKED);
    }
}
