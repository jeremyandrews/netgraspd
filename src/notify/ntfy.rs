//! ntfy.sh notifier.
//!
//! Publishes a plain-text body with ntfy's `X-` headers for title, priority and
//! tags, which works against ntfy.sh and against a self-hosted instance without
//! change.
//!
//! There is no rate limiting here. Debounce, batching and quiet hours are the
//! dispatcher's job; see the module documentation in `notify/mod.rs` for why.

use anyhow::{Context, Result, bail};
use async_trait::async_trait;

use crate::config::NtfyConfig;
use crate::device::DeviceEvent;
use crate::notify::Notifier;
use crate::types::{EventPriority, EventType};

/// Publishes notifications to an ntfy topic.
pub struct NtfyNotifier {
    client: reqwest::Client,
    url: String,
    token: Option<String>,
    priority: u8,
    urgent_priority: u8,
}

impl NtfyNotifier {
    /// Builds a notifier from configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the topic is empty or the HTTP client cannot be
    /// built.
    pub fn new(cfg: &NtfyConfig) -> Result<Self> {
        let topic = cfg.topic.trim();
        if topic.is_empty() {
            bail!("notify.ntfy.topic is empty, so there is nowhere to publish");
        }
        let client = reqwest::Client::builder()
            .timeout(cfg.timeout.get())
            .user_agent(concat!("netgraspd/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("could not build the ntfy HTTP client")?;
        Ok(NtfyNotifier {
            client,
            url: format!("{}/{}", cfg.server.trim_end_matches('/'), topic),
            token: cfg.token.clone(),
            priority: cfg.priority,
            urgent_priority: cfg.urgent_priority,
        })
    }

    /// The ntfy priority header value for an event priority.
    ///
    /// `High` sits between the two configured levels rather than getting a third
    /// setting: an operator who wants a specific number for it is really asking
    /// for a different urgent level.
    #[must_use]
    fn header_priority(&self, priority: EventPriority) -> u8 {
        match priority {
            EventPriority::Normal => self.priority,
            EventPriority::High => self.priority.max(4).min(self.urgent_priority.max(4)),
            EventPriority::Urgent => self.urgent_priority,
        }
    }

    /// Posts one message.
    async fn post(&self, title: &str, body: &str, tags: &str, priority: u8) -> Result<()> {
        let mut request = self
            .client
            .post(&self.url)
            .header("X-Title", title)
            .header("X-Priority", priority.to_string())
            .header("X-Tags", tags)
            .body(body.to_string());
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .with_context(|| format!("could not reach ntfy at {}", self.url))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            bail!("ntfy returned {status}: {}", body.trim());
        }
        Ok(())
    }
}

#[async_trait]
impl Notifier for NtfyNotifier {
    fn name(&self) -> &str {
        "ntfy"
    }

    async fn send(&self, event: &DeviceEvent) -> Result<()> {
        self.post(
            &title_for(event),
            &body_for(event),
            tags_for(event.event_type),
            self.header_priority(event.priority),
        )
        .await
    }

    async fn send_batch(&self, events: &[DeviceEvent]) -> Result<()> {
        match events {
            [] => Ok(()),
            [only] => self.send(only).await,
            many => {
                // A batch takes the loudest priority in it. A summary that
                // included one urgent event must not arrive quietly.
                let priority = many
                    .iter()
                    .map(|e| e.priority)
                    .max()
                    .unwrap_or(EventPriority::Normal);
                self.post(
                    &format!("{} devices appeared", many.len()),
                    &summary_body(many),
                    "satellite",
                    self.header_priority(priority),
                )
                .await
            }
        }
    }

    fn supports_priority(&self) -> bool {
        true
    }
}

/// Notification title for one event.
///
/// A security title leads with the threat rather than the device, because the
/// first three words are all a lock-screen notification shows and "ARP spoof" is
/// the part that decides whether somebody gets out of bed.
#[must_use]
pub fn title_for(event: &DeviceEvent) -> String {
    match event.event_type {
        EventType::NewDevice => format!("New device: {}", event.display_name),
        EventType::Returned => format!("Back online: {}", event.display_name),
        EventType::WentOffline => format!("Offline: {}", event.display_name),
        EventType::IpChanged => format!("Address changed: {}", event.display_name),
        EventType::NameUpdated => format!("Identified: {}", event.display_name),
        EventType::ArpScan => format!("ARP scan from {}", event.display_name),
        EventType::ArpSpoof => format!("ARP spoof by {}", event.display_name),
        EventType::RogueDhcp => format!("Rogue DHCP server: {}", event.display_name),
        EventType::IpConflict => format!("Address conflict: {}", event.display_name),
        EventType::GratuitousArp => format!("Gratuitous ARP flood from {}", event.display_name),
        EventType::IdentityChange => format!("Device changed identity: {}", event.display_name),
    }
}

/// Notification body for one event.
///
/// The new-device case carries everything a person needs to decide whether to
/// care, because that is the alert they will read at 2am: identity, vendor,
/// address, MAC, and when it turned up.
#[must_use]
pub fn body_for(event: &DeviceEvent) -> String {
    let mut lines = vec![event.display_name.clone()];
    if let Some(vendor) = &event.vendor {
        lines.push(format!("Vendor: {vendor}"));
    }
    if let Some(ip) = &event.ip {
        lines.push(format!("IP: {ip}"));
    }
    lines.push(format!("MAC: {}", event.mac));
    if let Some(interface) = &event.interface {
        lines.push(format!("Interface: {interface}"));
    }
    let when = match event.event_type {
        EventType::NewDevice => "First seen",
        EventType::WentOffline => "Last seen",
        _ => "Seen",
    };
    lines.push(format!(
        "{when}: {}",
        event.at.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    lines.join("\n")
}

/// Body for a collapsed summary.
#[must_use]
pub fn summary_body(events: &[DeviceEvent]) -> String {
    let mut lines = Vec::with_capacity(events.len() + 1);
    for event in events.iter().take(SUMMARY_LIST_LIMIT) {
        let ip = event.ip.as_deref().unwrap_or("no address");
        lines.push(format!("{} ({ip}) {}", event.display_name, event.mac));
    }
    if events.len() > SUMMARY_LIST_LIMIT {
        lines.push(format!("...and {} more", events.len() - SUMMARY_LIST_LIMIT));
    }
    lines.join("\n")
}

/// How many devices a summary lists before it starts counting instead.
const SUMMARY_LIST_LIMIT: usize = 15;

/// ntfy tag (an emoji shortcode) for an event type.
#[must_use]
pub const fn tags_for(event_type: EventType) -> &'static str {
    match event_type {
        EventType::NewDevice => "bell",
        EventType::Returned => "arrow_right",
        EventType::WentOffline => "zzz",
        EventType::IpChanged => "arrows_counterclockwise",
        EventType::NameUpdated => "label",
        EventType::ArpScan => "mag",
        EventType::ArpSpoof => "rotating_light",
        EventType::RogueDhcp => "no_entry",
        EventType::IpConflict => "warning",
        EventType::GratuitousArp => "loudspeaker",
        EventType::IdentityChange => "twisted_rightwards_arrows",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HumanDuration;
    use chrono::{TimeZone, Utc};

    fn cfg(topic: &str) -> NtfyConfig {
        NtfyConfig {
            topic: topic.into(),
            server: "https://ntfy.sh".into(),
            priority: 3,
            urgent_priority: 5,
            token: None,
            timeout: HumanDuration::from_secs(10),
        }
    }

    fn event(kind: EventType) -> DeviceEvent {
        DeviceEvent {
            event_type: kind,
            mac: "3c:22:fb:9a:1b:2c".parse().expect("mac"),
            display_name: "Aurora's iPad".into(),
            vendor: Some("Apple, Inc.".into()),
            ip: Some("192.168.1.40".into()),
            interface: Some("eth0".into()),
            at: Utc
                .with_ymd_and_hms(2026, 2, 2, 14, 30, 0)
                .single()
                .expect("valid time"),
            baseline: false,
            during_learning: false,
            notify: true,
            priority: crate::types::EventPriority::Normal,
            details: serde_json::Value::Null,
        }
    }

    #[test]
    fn an_empty_topic_is_rejected_at_construction() {
        let err = match NtfyNotifier::new(&cfg("   ")) {
            Ok(_) => panic!("an empty topic must be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("topic is empty"), "{err}");
    }

    #[test]
    fn the_url_joins_server_and_topic_without_doubling_the_slash() {
        let n = NtfyNotifier::new(&NtfyConfig {
            server: "https://ntfy.example.com/".into(),
            ..cfg("home-network")
        })
        .expect("builds");
        assert_eq!(n.url, "https://ntfy.example.com/home-network");
    }

    #[test]
    fn a_new_device_notification_carries_everything_needed_to_judge_it() {
        let event = event(EventType::NewDevice);
        assert_eq!(title_for(&event), "New device: Aurora's iPad");
        let body = body_for(&event);
        assert!(body.contains("Aurora's iPad"), "{body}");
        assert!(body.contains("Vendor: Apple, Inc."), "{body}");
        assert!(body.contains("IP: 192.168.1.40"), "{body}");
        assert!(body.contains("MAC: 3c:22:fb:9a:1b:2c"), "{body}");
        assert!(
            body.contains("First seen: 2026-02-02 14:30:00 UTC"),
            "{body}"
        );
    }

    #[test]
    fn a_device_with_no_vendor_or_address_still_produces_a_usable_body() {
        let mut e = event(EventType::NewDevice);
        e.vendor = None;
        e.ip = None;
        let body = body_for(&e);
        assert!(!body.contains("Vendor:"), "{body}");
        assert!(!body.contains("IP:"), "{body}");
        assert!(body.contains("MAC: 3c:22:fb:9a:1b:2c"), "{body}");
    }

    #[test]
    fn each_event_type_gets_its_own_title_and_tag() {
        let mut seen = Vec::new();
        for kind in [
            EventType::NewDevice,
            EventType::Returned,
            EventType::WentOffline,
            EventType::IpChanged,
            EventType::NameUpdated,
        ] {
            let mut e = event(kind);
            e.event_type = kind;
            seen.push((title_for(&e), tags_for(kind)));
        }
        let titles: Vec<&String> = seen.iter().map(|(t, _)| t).collect();
        let tags: Vec<&&str> = seen.iter().map(|(_, g)| g).collect();
        assert_eq!(
            titles.len(),
            titles
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            "titles must be distinguishable"
        );
        assert_eq!(
            tags.len(),
            tags.iter().collect::<std::collections::HashSet<_>>().len(),
            "tags must be distinguishable"
        );
    }

    #[test]
    fn a_summary_lists_devices_and_then_counts_the_rest() {
        let events: Vec<DeviceEvent> = (0..20)
            .map(|n| {
                let mut e = event(EventType::NewDevice);
                e.display_name = format!("device {n}");
                e
            })
            .collect();
        let body = summary_body(&events);
        assert!(body.contains("device 0"), "{body}");
        assert!(body.contains("device 14"), "{body}");
        assert!(!body.contains("device 15"), "{body}");
        assert!(body.contains("...and 5 more"), "{body}");
    }

    #[test]
    fn a_summary_of_a_device_with_no_address_says_so() {
        let mut e = event(EventType::NewDevice);
        e.ip = None;
        assert!(summary_body(&[e]).contains("(no address)"));
    }
}
