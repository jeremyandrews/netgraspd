//! mDNS capture source.
//!
//! Captured through pcap with a BPF filter, not through a service-discovery
//! library. Every such library discovers by asking, and joining the multicast
//! group with an ordinary UDP socket emits an IGMP membership report; both
//! break the one rule Netgrasp has. A pcap handle reads what is already on the
//! wire and transmits nothing.
//!
//! What is extracted:
//!
//! - **Instance names** from PTR targets and from SRV and TXT owner names.
//!   `Living Room Apple TV._airplay._tcp.local` yields `Living Room Apple TV`,
//!   the 0.9-weight identity signal.
//! - **Host names** from A and AAAA owner names, `printer.local` yielding
//!   `printer`. Also a 0.9 mDNS signal, but ranked behind instance names
//!   because a human named the instance and a vendor named the host.
//! - **Service types** such as `_airplay._tcp`, stored at weight zero as input
//!   to milestone 2's device-type classification.

use std::collections::HashSet;
use std::net::IpAddr;

use chrono::{DateTime, Utc};

use crate::capture::dns;
use crate::capture::ethernet::{
    ETHERTYPE_IPV4, ETHERTYPE_IPV6, IPPROTO_UDP, parse_ethernet, parse_ipv4, parse_ipv6, parse_udp,
};
use crate::types::{Observation, ObservationKind, Signal, SignalKind};

/// Short name of this source, stored on every observation it produces.
pub const SOURCE: &str = "mdns";

/// BPF filter narrowing the capture to mDNS.
pub const FILTER: &str = "udp port 5353";

/// The mDNS port.
const MDNS_PORT: u16 = 5353;

/// Longest name Netgrasp will show. Anything longer is a responder being
/// creative rather than descriptive.
const MAX_NAME_LEN: usize = 96;

/// Parses one captured frame into an observation.
///
/// Returns `None` when the frame is not mDNS, when the source MAC cannot
/// identify a device, or when the DNS payload is unreadable.
#[must_use]
pub fn parse_frame(
    bytes: &[u8],
    interface: &str,
    observed_at: DateTime<Utc>,
) -> Option<Observation> {
    let frame = parse_ethernet(bytes)?;
    let ip = match frame.ethertype {
        ETHERTYPE_IPV4 => parse_ipv4(frame.payload)?,
        ETHERTYPE_IPV6 => parse_ipv6(frame.payload)?,
        _ => return None,
    };
    if ip.protocol != IPPROTO_UDP {
        return None;
    }
    let udp = parse_udp(ip.payload)?;
    if udp.dst_port != MDNS_PORT && udp.src_port != MDNS_PORT {
        return None;
    }
    if frame.src.is_group() || frame.src.is_zero() {
        return None;
    }

    let msg = dns::parse_message(udp.payload)?;
    let kind = if msg.is_response {
        ObservationKind::Announcement
    } else {
        ObservationKind::Query
    };

    Some(Observation {
        mac: frame.src,
        ip: Some(ip.src),
        interface: interface.to_string(),
        source: SOURCE,
        kind,
        signals: extract_signals(udp.payload, &msg),
        observed_at,
    })
}

/// Pulls identity signals out of a parsed mDNS message.
///
/// Instance names come first, then host names, then service types, because the
/// scorer breaks same-kind ties by slice order and an instance name is the one a
/// human chose.
#[must_use]
pub fn extract_signals(msg_bytes: &[u8], msg: &dns::Message<'_>) -> Vec<Signal> {
    let mut instances: Vec<String> = Vec::new();
    let mut hosts: Vec<String> = Vec::new();
    let mut services: Vec<String> = Vec::new();

    for record in &msg.records {
        match record.rtype {
            dns::TYPE_PTR => {
                if let Some(target) = dns::ptr_target(msg_bytes, record) {
                    collect_instance(&target, &mut instances, &mut services);
                }
                // The owner name of a service-enumeration PTR is itself a
                // service type: `_services._dns-sd._udp.local` answers name
                // one.
                collect_service(&record.name, &mut services);
            }
            dns::TYPE_SRV | dns::TYPE_TXT => {
                collect_instance(&record.name, &mut instances, &mut services);
            }
            dns::TYPE_A | dns::TYPE_AAAA => {
                if let Some(host) = host_label(&record.name) {
                    push_unique(&mut hosts, host);
                }
            }
            _ => {}
        }
    }

    // A probe asks for the name it intends to claim, so the question names of a
    // query are as good a signal as an answer.
    if !msg.is_response {
        for question in &msg.questions {
            collect_instance(question, &mut instances, &mut services);
            if let Some(host) = host_label(question) {
                push_unique(&mut hosts, host);
            }
        }
    }

    let mut out = Vec::with_capacity(instances.len() + hosts.len() + services.len());
    out.extend(
        instances
            .into_iter()
            .map(|v| Signal::new(SignalKind::MdnsName, v)),
    );
    out.extend(
        hosts
            .into_iter()
            .map(|v| Signal::new(SignalKind::MdnsName, v)),
    );
    out.extend(
        services
            .into_iter()
            .map(|v| Signal::new(SignalKind::MdnsService, v)),
    );
    out
}

/// Records the instance name and service type of a `instance._svc._proto.local`
/// name, if it has that shape.
fn collect_instance(labels: &[String], instances: &mut Vec<String>, services: &mut Vec<String>) {
    // Shape: instance, _service, _proto, local. The meta-service
    // `_services._dns-sd._udp.local` matches the label count but its first
    // label is underscore-prefixed, so it falls out as a service type instead.
    if labels.len() < 4 {
        collect_service(labels, services);
        return;
    }
    let first = labels[0].as_str();
    if first.starts_with('_') {
        collect_service(labels, services);
        return;
    }
    if !labels[1].starts_with('_') {
        return;
    }
    if let Some(name) = usable_name(first) {
        push_unique(instances, name);
    }
    collect_service(&labels[1..], services);
}

/// Records a `_service._proto` pair from a name that starts with one.
fn collect_service(labels: &[String], services: &mut Vec<String>) {
    if labels.len() < 2 {
        return;
    }
    let (svc, proto) = (labels[0].as_str(), labels[1].as_str());
    if !svc.starts_with('_') || !proto.starts_with('_') {
        return;
    }
    // The meta-service that enumerates other services names no device.
    if svc == "_services" {
        return;
    }
    push_unique(services, format!("{svc}.{proto}"));
}

/// Extracts a host label from an A or AAAA owner name such as `printer.local`.
fn host_label(labels: &[String]) -> Option<String> {
    if labels.len() != 2 || !labels[1].eq_ignore_ascii_case("local") {
        return None;
    }
    let first = labels[0].as_str();
    if first.starts_with('_') {
        return None;
    }
    usable_name(first)
}

/// Rejects names not worth showing a human: blank, over-long, or an address
/// written with separators swapped for dots.
fn usable_name(raw: &str) -> Option<String> {
    let name = raw.trim();
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return None;
    }
    if name
        .chars()
        .all(|c| c.is_ascii_digit() || c == '-' || c == '_' || c == '.')
    {
        return None;
    }
    Some(name.to_string())
}

/// Appends a value unless it is already present, preserving first-seen order.
fn push_unique(out: &mut Vec<String>, value: String) {
    let mut seen: HashSet<&str> = HashSet::with_capacity(out.len());
    seen.extend(out.iter().map(String::as_str));
    if !seen.contains(value.as_str()) {
        out.push(value);
    }
}

/// True when an address belongs to a device rather than to the multicast group
/// itself. Used by the pipeline to avoid recording the mDNS group address as a
/// device address.
#[must_use]
pub fn is_device_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_multicast() && !v4.is_unspecified() && !v4.is_broadcast(),
        IpAddr::V6(v6) => !v6.is_multicast() && !v6.is_unspecified(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::fixtures;

    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::timestamp_opt(&Utc, 1_770_000_000, 0)
            .single()
            .expect("valid timestamp")
    }

    fn names(obs: &Observation, kind: SignalKind) -> Vec<&str> {
        obs.signals
            .iter()
            .filter(|s| s.kind == kind)
            .map(|s| s.value.as_str())
            .collect()
    }

    #[test]
    fn parses_a_real_mdns_response_over_ipv4() {
        let obs = parse_frame(&fixtures::mdns_response_ipv4(), "eth0", ts()).expect("parsed");
        assert_eq!(obs.mac, "b8:27:eb:44:55:66".parse().expect("mac"));
        assert_eq!(obs.ip, Some("192.168.1.55".parse().expect("ip")));
        assert_eq!(obs.kind, ObservationKind::Announcement);
        assert_eq!(obs.source, "mdns");
        assert_eq!(
            names(&obs, SignalKind::MdnsName),
            vec!["Living Room Apple TV", "living-room-apple-tv"],
            "the human-chosen instance name must outrank the host name"
        );
        assert_eq!(names(&obs, SignalKind::MdnsService), vec!["_airplay._tcp"]);
    }

    #[test]
    fn parses_an_mdns_response_over_ipv6() {
        let obs = parse_frame(&fixtures::mdns_response_ipv6(), "eth0", ts()).expect("parsed");
        assert_eq!(obs.mac, "3c:2a:f4:11:22:33".parse().expect("mac"));
        assert_eq!(
            obs.ip,
            Some("fe80::3e2a:f4ff:fe11:2233".parse().expect("ip"))
        );
        assert_eq!(names(&obs, SignalKind::MdnsName), vec!["Office Printer"]);
        assert_eq!(names(&obs, SignalKind::MdnsService), vec!["_ipp._tcp"]);
    }

    #[test]
    fn a_query_is_a_query_and_still_proves_presence() {
        let obs = parse_frame(&fixtures::mdns_query(), "eth0", ts()).expect("parsed");
        assert_eq!(obs.kind, ObservationKind::Query);
        assert_eq!(obs.mac, "3c:22:fb:9a:1b:2c".parse().expect("mac"));
        assert!(
            names(&obs, SignalKind::MdnsName).is_empty(),
            "the meta-service query names no device"
        );
    }

    #[test]
    fn the_meta_service_is_never_an_instance_name() {
        let obs = parse_frame(&fixtures::mdns_query(), "eth0", ts()).expect("parsed");
        for s in &obs.signals {
            assert_ne!(s.value, "_services");
            assert!(!s.value.starts_with("_services"));
        }
    }

    #[test]
    fn non_mdns_frames_are_rejected() {
        assert!(parse_frame(&fixtures::arp_request(), "eth0", ts()).is_none());
        assert!(parse_frame(&[], "eth0", ts()).is_none());
    }

    #[test]
    fn truncated_mdns_frames_do_not_panic() {
        let full = fixtures::mdns_response_ipv4();
        for n in 0..full.len() {
            let _ = parse_frame(&full[..n], "eth0", ts());
        }
    }

    #[test]
    fn instance_extraction_handles_the_shapes_that_matter() {
        let mut inst = Vec::new();
        let mut svc = Vec::new();
        let labels = |v: &[&str]| v.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();

        collect_instance(
            &labels(&["Kitchen Sonos", "_sonos", "_tcp", "local"]),
            &mut inst,
            &mut svc,
        );
        assert_eq!(inst, vec!["Kitchen Sonos"]);
        assert_eq!(svc, vec!["_sonos._tcp"]);

        // The meta-service must not become an instance.
        collect_instance(
            &labels(&["_services", "_dns-sd", "_udp", "local"]),
            &mut inst,
            &mut svc,
        );
        assert_eq!(inst, vec!["Kitchen Sonos"], "unchanged");

        // A bare host name is not a service instance.
        collect_instance(&labels(&["printer", "local"]), &mut inst, &mut svc);
        assert_eq!(inst, vec!["Kitchen Sonos"], "unchanged");
    }

    #[test]
    fn host_labels_only_come_from_dot_local_pairs() {
        let labels = |v: &[&str]| v.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        assert_eq!(host_label(&labels(&["nas", "local"])), Some("nas".into()));
        assert_eq!(host_label(&labels(&["nas", "LOCAL"])), Some("nas".into()));
        assert_eq!(host_label(&labels(&["nas", "example", "com"])), None);
        assert_eq!(host_label(&labels(&["_ipp", "local"])), None);
        assert_eq!(host_label(&labels(&["local"])), None);
    }

    #[test]
    fn names_that_are_really_addresses_are_rejected() {
        assert_eq!(usable_name("192-168-1-40"), None);
        assert_eq!(usable_name("10.0.0.5"), None);
        assert_eq!(usable_name(""), None);
        assert_eq!(usable_name(&"x".repeat(200)), None);
        assert_eq!(usable_name("pi4"), Some("pi4".into()));
    }

    #[test]
    fn duplicate_signals_are_collapsed() {
        let mut out = Vec::new();
        push_unique(&mut out, "a".into());
        push_unique(&mut out, "a".into());
        push_unique(&mut out, "b".into());
        assert_eq!(out, vec!["a", "b"]);
    }

    #[test]
    fn multicast_group_addresses_are_not_device_addresses() {
        assert!(!is_device_address("224.0.0.251".parse().expect("ip")));
        assert!(!is_device_address("ff02::fb".parse().expect("ip")));
        assert!(!is_device_address("0.0.0.0".parse().expect("ip")));
        assert!(is_device_address("192.168.1.55".parse().expect("ip")));
        assert!(is_device_address("fe80::1".parse().expect("ip")));
    }
}
