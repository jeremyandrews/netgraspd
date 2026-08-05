//! Plain-text table rendering.
//!
//! The predecessor's one universally liked feature was a live device table, so
//! it is here from the first commit. Everything in this module is a pure
//! function from data to a `String`, which keeps the formatting testable and
//! keeps terminal handling out of it.

use chrono::{DateTime, Utc};

use crate::db::queries::{DeviceRecord, EventRecord};
use crate::device::DeviceSnapshot;

/// Longest any single cell is allowed to be before it is truncated. Wide enough
/// for a long mDNS instance name, narrow enough that five columns fit an
/// 80-column terminal.
pub const MAX_CELL: usize = 32;

/// Renders a table with a header row and a rule beneath it.
///
/// Columns are sized to their widest cell. Cells longer than [`MAX_CELL`] are
/// truncated with a single-character ellipsis so that one absurd device name
/// cannot destroy the layout.
#[must_use]
pub fn render(headers: &[&str], rows: &[Vec<String>]) -> String {
    let cols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    let truncated: Vec<Vec<String>> = rows
        .iter()
        .map(|row| row.iter().map(|c| truncate(c, MAX_CELL)).collect())
        .collect();

    for row in &truncated {
        for (i, cell) in row.iter().enumerate().take(cols) {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }

    let mut out = String::new();
    push_row(&mut out, headers.iter().copied(), &widths);
    out.push_str(
        &widths
            .iter()
            .map(|w| "-".repeat(*w))
            .collect::<Vec<_>>()
            .join("  "),
    );
    out.push('\n');
    for row in &truncated {
        push_row(&mut out, row.iter().map(String::as_str), &widths);
    }
    out
}

/// Appends one padded row, without trailing whitespace on the last column.
fn push_row<'a>(out: &mut String, cells: impl Iterator<Item = &'a str>, widths: &[usize]) {
    let cells: Vec<&str> = cells.collect();
    let last = cells.len().saturating_sub(1);
    for (i, cell) in cells.iter().enumerate() {
        if i == last {
            out.push_str(cell);
        } else {
            let pad = widths.get(i).copied().unwrap_or(0);
            out.push_str(cell);
            for _ in cell.chars().count()..pad {
                out.push(' ');
            }
            out.push_str("  ");
        }
    }
    out.push('\n');
}

/// Truncates on a character boundary, marking the cut with a single dot.
#[must_use]
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let kept: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}\u{2026}")
}

/// Renders a duration as a compact "how long ago".
#[must_use]
pub fn ago(then: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let secs = now.signed_duration_since(then).num_seconds();
    if secs < 0 {
        // A packet timestamped in the future means clock skew, not time travel.
        return "just now".into();
    }
    match secs {
        0..=4 => "just now".into(),
        5..=89 => format!("{secs}s ago"),
        90..=5399 => format!("{}m ago", secs / 60),
        5400..=172_799 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86_400),
    }
}

/// Renders the live device table shown by `netgraspd run`.
#[must_use]
pub fn device_table(devices: &[DeviceSnapshot], now: DateTime<Utc>) -> String {
    let rows: Vec<Vec<String>> = devices
        .iter()
        .map(|d| {
            vec![
                d.display(),
                d.vendor.clone().unwrap_or_else(|| "-".into()),
                d.last_ip.clone().unwrap_or_else(|| "-".into()),
                d.state.to_string(),
                ago(d.last_seen_at, now),
            ]
        })
        .collect();
    render(&["NAME", "VENDOR", "IP", "STATE", "LAST SEEN"], &rows)
}

/// Renders the one-shot table shown by `netgraspd devices`.
#[must_use]
pub fn device_record_table(devices: &[DeviceRecord], now: DateTime<Utc>) -> String {
    let rows: Vec<Vec<String>> = devices
        .iter()
        .map(|d| {
            vec![
                d.display(),
                d.vendor.clone().unwrap_or_else(|| "-".into()),
                d.last_ip.clone().unwrap_or_else(|| "-".into()),
                d.state.to_string(),
                ago(d.last_seen_at, now),
                d.mac.to_string(),
            ]
        })
        .collect();
    render(
        &["NAME", "VENDOR", "IP", "STATE", "LAST SEEN", "MAC"],
        &rows,
    )
}

/// Renders the table shown by `netgraspd events`.
#[must_use]
pub fn event_table(events: &[EventRecord], now: DateTime<Utc>) -> String {
    let rows: Vec<Vec<String>> = events
        .iter()
        .map(|e| {
            vec![
                ago(e.timestamp, now),
                e.event_type.clone(),
                e.device_label.clone().unwrap_or_else(|| "-".into()),
                if e.notified {
                    "yes".into()
                } else {
                    "no".into()
                },
                detail_summary(&e.details),
            ]
        })
        .collect();
    render(&["WHEN", "EVENT", "DEVICE", "NOTIFIED", "DETAIL"], &rows)
}

/// Detail keys worth showing, in the order they read best.
///
/// One list rather than one per event type: a security event and a lifecycle
/// event never carry the same keys, so a single pass over this picks out
/// whichever apply. A key that is absent, null or blank contributes nothing,
/// which is what keeps the column narrow.
const DETAIL_KEYS: [&str; 17] = [
    // Device lifecycle.
    "previous_ip",
    "new_ip",
    "previous_name",
    "new_source",
    "silent_for_secs",
    // Security. Without these the DETAIL column is empty for exactly the events
    // an operator most needs to read at a glance.
    "claimed_ip",
    "previous_holder",
    "gateway_impersonation",
    "distinct_targets",
    "announcements",
    "other_mac",
    "expected_server",
    "message_type",
    "previous_device_type",
    "device_type",
    "category_change",
    "interface",
];

/// Flattens the interesting parts of an event's JSON detail into one line.
#[must_use]
fn detail_summary(details: &serde_json::Value) -> String {
    let Some(object) = details.as_object() else {
        return String::new();
    };
    let mut parts = Vec::new();
    for key in DETAIL_KEYS {
        if let Some(value) = object.get(key) {
            let rendered = value
                .as_str()
                .map_or_else(|| value.to_string(), str::to_string);
            if rendered != "null" && !rendered.is_empty() {
                parts.push(format!("{key}={rendered}"));
            }
        }
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::types::{DeviceState, SignalKind};
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 2, 2, 12, 0, 0)
            .single()
            .expect("valid time")
    }

    fn snapshot(name: &str, vendor: Option<&str>, ago_secs: i64) -> DeviceSnapshot {
        DeviceSnapshot {
            mac: "3c:22:fb:00:00:01".parse().expect("mac"),
            state: DeviceState::Online,
            last_ip: Some("192.168.1.40".into()),
            last_ipv6: None,
            last_interface: Some("eth0".into()),
            first_seen_at: now(),
            last_seen_at: now() - chrono::Duration::seconds(ago_secs),
            baseline: false,
            identity: Identity {
                display_name: name.into(),
                source: SignalKind::MdnsName,
                confidence: 0.9,
            },
            display_name: None,
            hostname: None,
            mdns_name: Some(name.into()),
            vendor: vendor.map(str::to_string),
            device_type: None,
            device_type_confidence: None,
            os_family: None,
            observations_since_flush: 0,
        }
    }

    #[test]
    fn columns_line_up_under_their_headers() {
        let table = render(
            &["NAME", "IP"],
            &[
                vec!["a".into(), "192.168.1.1".into()],
                vec!["a longer name".into(), "10.0.0.1".into()],
            ],
        );
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 4, "header, rule, two rows");
        let ip_column = lines[0].find("IP").expect("header has IP");
        for line in &lines[2..] {
            assert!(
                line[ip_column..].starts_with(|c: char| c.is_ascii_digit()),
                "row {line:?} does not align at column {ip_column}"
            );
        }
    }

    #[test]
    fn the_rule_matches_the_header_width() {
        let table = render(&["NAME", "IP"], &[vec!["abcdef".into(), "1".into()]]);
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines[1], "------  --");
    }

    #[test]
    fn an_absurd_name_is_truncated_rather_than_destroying_the_layout() {
        let long = "x".repeat(200);
        let table = render(&["NAME"], &[vec![long]]);
        let widest = table.lines().map(|l| l.chars().count()).max().unwrap_or(0);
        assert_eq!(widest, MAX_CELL);
        assert!(table.contains('\u{2026}'), "the cut is marked");
    }

    #[test]
    fn multibyte_names_are_cut_on_a_character_boundary() {
        let name = "é".repeat(100);
        let table = render(&["NAME"], &[vec![name]]);
        // Reaching here without a panic is most of the test; check the width too.
        assert_eq!(
            table.lines().nth(2).map(|l| l.chars().count()),
            Some(MAX_CELL)
        );
    }

    #[test]
    fn an_empty_table_still_has_a_header() {
        let table = render(&["NAME", "IP"], &[]);
        assert_eq!(table.lines().count(), 2);
        assert!(table.starts_with("NAME"));
    }

    #[test]
    fn relative_times_read_the_way_a_human_would_say_them() {
        let n = now();
        assert_eq!(ago(n, n), "just now");
        assert_eq!(ago(n - chrono::Duration::seconds(30), n), "30s ago");
        assert_eq!(ago(n - chrono::Duration::seconds(600), n), "10m ago");
        assert_eq!(ago(n - chrono::Duration::seconds(7200), n), "2h ago");
        assert_eq!(ago(n - chrono::Duration::seconds(200_000), n), "2d ago");
    }

    #[test]
    fn a_future_timestamp_is_clock_skew_not_time_travel() {
        let n = now();
        assert_eq!(ago(n + chrono::Duration::seconds(60), n), "just now");
    }

    #[test]
    fn the_device_table_shows_what_the_predecessor_showed() {
        let table = device_table(
            &[
                snapshot("Aurora's iPad", Some("Apple, Inc."), 30),
                snapshot("Office Printer", None, 7200),
            ],
            now(),
        );
        assert!(table.starts_with("NAME"), "{table}");
        assert!(table.contains("Aurora's iPad"), "{table}");
        assert!(table.contains("Apple, Inc."), "{table}");
        assert!(table.contains("192.168.1.40"), "{table}");
        assert!(table.contains("online"), "{table}");
        assert!(table.contains("30s ago"), "{table}");
        assert!(table.contains("2h ago"), "{table}");
        assert!(table.contains('-'), "a missing vendor shows as a dash");
    }

    #[test]
    fn event_details_are_flattened_to_one_readable_line() {
        let details = serde_json::json!({
            "previous_ip": "192.168.1.40",
            "new_ip": "192.168.1.41",
            "interface": "eth0",
            "irrelevant": "ignored",
        });
        let line = detail_summary(&details);
        assert!(line.contains("previous_ip=192.168.1.40"), "{line}");
        assert!(line.contains("new_ip=192.168.1.41"), "{line}");
        assert!(!line.contains("irrelevant"), "{line}");
    }

    #[test]
    fn a_security_events_detail_column_is_not_empty() {
        // The regression this catches: `events --security` rendering a column of
        // blanks, which is the one view where the evidence is the whole point.
        let spoof = detail_summary(&serde_json::json!({
            "analyzer": "arp_spoof",
            "claimed_ip": "192.168.1.1",
            "previous_holder": serde_json::Value::Null,
            "gateway_impersonation": true,
            "security": true,
        }));
        assert!(spoof.contains("claimed_ip=192.168.1.1"), "{spoof}");
        assert!(spoof.contains("gateway_impersonation=true"), "{spoof}");
        assert!(
            !spoof.contains("previous_holder"),
            "a null contributes nothing: {spoof}"
        );

        let scan = detail_summary(&serde_json::json!({
            "distinct_targets": 10,
            "threshold": 10,
        }));
        assert!(scan.contains("distinct_targets=10"), "{scan}");
    }

    #[test]
    fn non_object_details_do_not_panic() {
        assert_eq!(detail_summary(&serde_json::Value::Null), "");
        assert_eq!(detail_summary(&serde_json::json!([1, 2, 3])), "");
    }
}
