//! ntfy.sh notifier.
//!
//! Publishes a plain-text body with ntfy's `X-` headers for title, priority and
//! tags, which works against ntfy.sh and against a self-hosted instance without
//! change.
//!
//! There is no rate limiting here. Debounce, batching and quiet hours are the
//! dispatcher's job; see the module documentation in `notify/mod.rs` for why.
//!
//! ## Why the title is encoded and the body is not
//!
//! The **body** is the HTTP request body, sent as UTF-8 and read as UTF-8.
//! Nothing needs doing to it.
//!
//! The **title** is an HTTP header, and a header is not a place where UTF-8
//! means UTF-8. A name like `Jeremy's iPhone`, whose apostrophe is the U+2019
//! that macOS substitutes, arrived on the phone as `Jeremyâs`: the two
//! continuation bytes of the three-byte sequence were each read as a separate
//! Latin-1 character. ntfy documents RFC 2047 encoded words as the way to put
//! non-ASCII in one, so that is what goes on the wire.
//!
//! Pure ASCII is left exactly as it was. Encoding everything would work, but it
//! would make every header unreadable in a packet capture and in ntfy's own
//! logs for the sake of the minority of titles that need it.

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
    ///
    /// Every header carrying free text goes through [`encode_header`]. The
    /// title is the one that needed it, but tags are configurable emoji
    /// shortcodes and a self-hosted ntfy accepts any string, so encoding both
    /// costs nothing and removes the question. `X-Priority` is a number.
    async fn post(&self, title: &str, body: &str, tags: &str, priority: u8) -> Result<()> {
        let mut request = self
            .client
            .post(&self.url)
            .header("X-Title", encode_header(title))
            .header("X-Priority", priority.to_string())
            .header("X-Tags", encode_header(tags))
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

/// The longest an RFC 2047 encoded word may be, including its delimiters.
const MAX_ENCODED_WORD: usize = 75;

/// The fixed cost of one encoded word: `=?UTF-8?B?` and the closing `?=`.
const ENCODED_WORD_OVERHEAD: usize = 12;

/// How many bytes of input one encoded word can carry.
///
/// Base64 emits four characters per three input bytes and only in whole groups,
/// so the budget is rounded down to a multiple of three. 45 bytes in, 60
/// characters out, 72 with the delimiters, inside the 75 the RFC allows.
const MAX_CHUNK: usize = ((MAX_ENCODED_WORD - ENCODED_WORD_OVERHEAD) / 4) * 3;

/// Encodes a header value as RFC 2047 encoded words when it is not plain ASCII.
///
/// ASCII is returned untouched, so `New device: Aurora's iPad` stays readable on
/// the wire. Anything else is base64 in UTF-8 encoded words, which is what ntfy
/// documents for non-ASCII headers and what every mail-derived header parser has
/// understood since 1996.
///
/// A value that already contains `=?` is encoded even when it is ASCII.
/// Otherwise a device whose name happened to contain that sequence would be
/// decoded as an encoded word by the receiver, and the one place device names
/// come from is the network.
///
/// Long values become several encoded words separated by a space. RFC 2047
/// requires the whitespace between adjacent encoded words to be dropped when
/// they are decoded, so the value reassembles exactly.
#[must_use]
pub fn encode_header(value: &str) -> String {
    if value.is_ascii() && !value.contains("=?") && !value.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return value.to_string();
    }

    let mut words: Vec<String> = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        // Never split a character in half: an encoded word holds whole UTF-8,
        // and half a sequence decodes to a replacement character at best.
        let mut take = MAX_CHUNK.min(rest.len());
        while take > 0 && !rest.is_char_boundary(take) {
            take -= 1;
        }
        // One character longer than the budget. Take it whole rather than
        // looping forever on a chunk of zero.
        if take == 0 {
            take = rest
                .char_indices()
                .nth(1)
                .map_or(rest.len(), |(index, _)| index);
        }
        let (chunk, remainder) = rest.split_at(take);
        words.push(format!("=?UTF-8?B?{}?=", base64(chunk.as_bytes())));
        rest = remainder;
    }
    words.join(" ")
}

/// Encodes bytes as standard-alphabet base64, with padding.
///
/// Hand-rolled, for the same reason `capture::ssdp::base64_text` decodes by
/// hand: it is a dozen lines against a table, and a dependency for it would have
/// to be justified to everybody who ever audits this tree. The two are
/// deliberately not shared, because one belongs to a packet parser and the other
/// to an HTTP client, and giving them a common home would couple them.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for group in input.chunks(3) {
        let b = [
            group[0],
            group.get(1).copied().unwrap_or(0),
            group.get(2).copied().unwrap_or(0),
        ];
        let bits = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let index = |shift: u32| usize::try_from((bits >> shift) & 0x3f).unwrap_or(0);
        out.push(char::from(ALPHABET[index(18)]));
        out.push(char::from(ALPHABET[index(12)]));
        out.push(if group.len() > 1 {
            char::from(ALPHABET[index(6)])
        } else {
            '='
        });
        out.push(if group.len() > 2 {
            char::from(ALPHABET[index(0)])
        } else {
            '='
        });
    }
    out
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
        EventType::DeviceLocationChanged => format!("Moved: {}", event.display_name),
        // A person event leads with the name rather than a label, because
        // "Jeremy arrived" is the entire message and prefixing it would only
        // push the name out of the three words a lock screen shows.
        EventType::PersonArrived => format!("{} arrived", event.display_name),
        EventType::PersonDeparted => format!("{} left", event.display_name),
        EventType::PersonLocationChanged => format!("{} moved", event.display_name),
    }
}

/// Notification body for one event.
///
/// The new-device case carries everything a person needs to decide whether to
/// care, because that is the alert they will read at 2am: identity, vendor,
/// address, MAC, and when it turned up.
#[must_use]
pub fn body_for(event: &DeviceEvent) -> String {
    if event.event_type.is_person() {
        return person_body(event);
    }
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

/// Body for an event about a person rather than a device.
///
/// Reads the place and the way in from `details` rather than listing the MAC and
/// the vendor. "Jeremy arrived, through the Driveway" is what somebody wants on a
/// lock screen; the hardware address of the phone that proved it is not.
fn person_body(event: &DeviceEvent) -> String {
    let text = |key: &str| {
        event
            .details
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };
    let mut lines = Vec::new();
    match (text("location"), text("via")) {
        (Some(location), Some(via)) => lines.push(format!("In the {location}, via the {via}")),
        (Some(location), None) => lines.push(format!("In the {location}")),
        (None, Some(via)) => lines.push(format!("Via the {via}")),
        (None, None) => {}
    }
    if let Some(previous) = text("previous_location")
        && event.event_type == EventType::PersonLocationChanged
    {
        lines.push(format!("Was in the {previous}"));
    }
    lines.push(format!("At: {}", event.at.format("%Y-%m-%d %H:%M:%S UTC")));
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
        EventType::DeviceLocationChanged => "round_pushpin",
        EventType::PersonArrived => "house",
        EventType::PersonDeparted => "door",
        EventType::PersonLocationChanged => "walking",
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

    /// Decodes an RFC 2047 encoded-word header back to the text it carries,
    /// which is what a receiver does.
    fn decode_header(value: &str) -> String {
        value
            .split(' ')
            .map(|word| {
                word.strip_prefix("=?UTF-8?B?")
                    .and_then(|rest| rest.strip_suffix("?="))
                    .map_or_else(
                        || word.to_string(),
                        |payload| {
                            crate::capture::ssdp::base64_text(payload)
                                .unwrap_or_else(|| panic!("{payload} should decode"))
                        },
                    )
            })
            .collect()
    }

    #[test]
    fn a_plain_ascii_title_is_left_exactly_as_it_was() {
        // Encoding everything would work and would make every header
        // unreadable in a packet capture for no gain.
        let title = title_for(&event(EventType::NewDevice));
        assert_eq!(title, "New device: Aurora's iPad");
        assert_eq!(encode_header(&title), "New device: Aurora's iPad");
    }

    #[test]
    fn the_curly_apostrophe_that_arrived_as_jeremy_a_s_survives() {
        // The 2026-09-17 report, as a test. U+2019 is what macOS substitutes
        // for a typed apostrophe, and its three bytes were being read one at a
        // time as Latin-1.
        let mut e = event(EventType::NewDevice);
        e.display_name = "Jeremy\u{2019}s iPhone".into();
        let encoded = encode_header(&title_for(&e));
        assert!(
            encoded.starts_with("=?UTF-8?B?"),
            "a non-ASCII title must be an encoded word: {encoded}"
        );
        assert!(
            !encoded.contains('\u{2019}'),
            "no raw UTF-8 may reach the header: {encoded}"
        );
        assert_eq!(
            decode_header(&encoded),
            "New device: Jeremy\u{2019}s iPhone"
        );
    }

    #[test]
    fn an_accented_name_and_an_emoji_both_survive() {
        for name in [
            "Chambre d\u{2019}Aurore",
            "Caffè",
            "Ospiti 🏠",
            "日本語のデバイス",
        ] {
            let mut e = event(EventType::PersonArrived);
            e.display_name = name.into();
            let title = title_for(&e);
            let encoded = encode_header(&title);
            assert!(encoded.is_ascii(), "{name} left non-ASCII bytes: {encoded}");
            assert_eq!(decode_header(&encoded), title, "{name} did not round-trip");
        }
    }

    #[test]
    fn every_encoded_word_stays_inside_the_rfc_2047_length_limit() {
        // A long device name must not become one enormous encoded word, which
        // a strict parser is entitled to reject.
        let mut e = event(EventType::NewDevice);
        e.display_name = "Aurora\u{2019}s ".repeat(40);
        let title = title_for(&e);
        let encoded = encode_header(&title);
        for word in encoded.split(' ') {
            assert!(
                word.len() <= MAX_ENCODED_WORD,
                "{} chars is over the limit: {word}",
                word.len()
            );
        }
        assert!(encoded.split(' ').count() > 1, "it should have been split");
        assert_eq!(decode_header(&encoded), title);
    }

    #[test]
    fn a_character_is_never_split_across_two_encoded_words() {
        // Each word must hold whole UTF-8. Half a sequence decodes to a
        // replacement character, so a name whose multi-byte characters land on
        // the chunk boundary is the case that catches it.
        for count in 1..80usize {
            let title = "é".repeat(count);
            let encoded = encode_header(&title);
            assert_eq!(decode_header(&encoded), title, "{count} characters");
        }
    }

    #[test]
    fn an_ascii_value_that_looks_like_an_encoded_word_is_encoded() {
        // Device names come off the network, so one containing `=?` is
        // somebody else's choice. Passing it through would have the receiver
        // decode it as an encoded word.
        let encoded = encode_header("=?UTF-8?B?bm90IG1pbmU=?=");
        assert_eq!(decode_header(&encoded), "=?UTF-8?B?bm90IG1pbmU=?=");
    }

    #[test]
    fn tags_are_encoded_on_the_same_rule_as_titles() {
        // Every tag this build emits is an ASCII shortcode and must stay one.
        for kind in EventType::ALL {
            let tags = tags_for(kind);
            assert_eq!(encode_header(tags), tags, "{kind} tags must pass through");
        }
    }

    #[test]
    fn base64_matches_the_decoder_this_repository_already_has() {
        // The encoder is hand-rolled, so it is pinned against the hand-rolled
        // decoder in the SSDP parser rather than against itself.
        for text in ["", "a", "ab", "abc", "abcd", "Jeremy\u{2019}s iPhone", "🏠"] {
            let encoded = base64(text.as_bytes());
            if text.is_empty() {
                assert_eq!(encoded, "");
                continue;
            }
            assert_eq!(
                crate::capture::ssdp::base64_text(&encoded).as_deref(),
                Some(text),
                "{text} did not round-trip through {encoded}"
            );
        }
    }

    #[test]
    fn an_empty_value_encodes_to_nothing_rather_than_an_empty_word() {
        assert_eq!(encode_header(""), "");
    }
}
