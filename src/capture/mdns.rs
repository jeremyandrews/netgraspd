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
//!
//! ## Whose name is it
//!
//! **A name in an mDNS response is not evidence about whoever sent the frame.**
//! That assumption is the one this module made until 2026-09-17, and it is
//! wrong in the most ordinary case there is: a Bonjour Sleep Proxy answers on
//! behalf of machines that are asleep, so one phone's frames carry the names,
//! services and models of every host it is covering. Responders also answer for
//! several of their own hostnames at once, and a response to a service query
//! carries the additional records of whoever the service belongs to.
//!
//! So nothing here attributes anything to the transmitter. Each piece of
//! evidence is resolved to the address the *message* gave it: an A or AAAA
//! record names its own address directly, and an instance name reaches one
//! through its SRV target's address records. The pair travels as a
//! [`NameClaim`] and [`crate::device::Manager`] decides which device holds that
//! address, because it is the only layer holding the ARP and DHCP evidence that
//! answers the question. A sleep proxy's answer then lands on the sleeping host,
//! which is what it was always evidence about.
//!
//! Evidence the message tied to no address at all keeps the old behaviour and
//! falls back to the sender, because a device announcing a service without
//! repeating its own address record is the common shape and nothing in the
//! message contradicts it. The one exception is a message that demonstrably
//! speaks for somebody else, which the manager treats as untrustworthy
//! throughout; see `Manager::observe`.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};

use crate::capture::dns;
use crate::capture::ethernet::{
    ETHERTYPE_IPV4, ETHERTYPE_IPV6, IPPROTO_UDP, parse_ethernet, parse_ipv4, parse_ipv6, parse_udp,
};
use crate::types::{NameClaim, Observation, ObservationKind, Signal, SignalKind};

/// Short name of this source, stored on every observation it produces.
pub const SOURCE: &str = "mdns";

/// BPF filter narrowing the capture to mDNS.
pub const FILTER: &str = "udp port 5353";

/// The mDNS port.
const MDNS_PORT: u16 = 5353;

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
        // Nothing mDNS carries is evidence about the sender by virtue of having
        // been sent; see the module documentation.
        signals: Vec::new(),
        claims: extract_claims(udp.payload, &msg),
        // mDNS carries no field a security analyzer acts on.
        detail: None,
        observed_at,
    })
}

/// TXT record keys that carry a hardware or OS model.
///
/// `model` is what `_device-info._tcp` publishes and is the single best mDNS
/// operating-system signal there is: an Apple device announces
/// `model=MacBookPro18,1` unprompted. `am` is the same thing under AirPlay's
/// abbreviated key set, and `ty` and `usb_MDL` are what a printer publishes
/// under `_ipp._tcp`.
const MODEL_KEYS: [&str; 4] = ["model", "am", "ty", "usb_MDL"];

/// Which host a piece of evidence belongs to, as the message named it.
///
/// This is a name, not an address. Resolving it to an address is the second
/// pass, because a message routinely names a host before it carries the address
/// record that gives it one.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Owner {
    /// A service instance, `instance._svc._proto.local`, whose address is
    /// reached through its SRV target.
    Instance(String),
    /// A host, `host.local`, whose address records are in the message directly.
    Host(String),
    /// The message named no owner, so the sender is the only candidate.
    Sender,
}

/// One value and the owner the message gave it.
type Owned = (String, Owner);

/// Pulls identity evidence out of a parsed mDNS message, each piece carrying the
/// addresses the message proved for it.
///
/// Instance names come first, then host names, then service types, because the
/// scorer breaks same-kind ties by slice order and an instance name is the one a
/// human chose.
#[must_use]
pub fn extract_claims(msg_bytes: &[u8], msg: &dns::Message<'_>) -> Vec<NameClaim> {
    let mut instances: Vec<Owned> = Vec::new();
    let mut hosts: Vec<Owned> = Vec::new();
    let mut services: Vec<Owned> = Vec::new();
    let mut models: Vec<Owned> = Vec::new();
    // Address records, keyed by the owner name they were published under.
    let mut addresses: Vec<(String, IpAddr)> = Vec::new();
    // Which host each service instance lives on, from its SRV target.
    let mut targets: Vec<(String, String)> = Vec::new();

    for record in &msg.records {
        match record.rtype {
            dns::TYPE_PTR => {
                let target = dns::ptr_target(msg_bytes, record);
                if let Some(target) = &target {
                    collect_instance(target, &mut instances, &mut services);
                }
                // The owner name of a service-enumeration PTR is itself a
                // service type: `_services._dns-sd._udp.local` answers name
                // one. It belongs to whoever the target instance belongs to,
                // which for the meta-service is nobody in particular.
                let owner = target.as_deref().map_or(Owner::Sender, instance_owner);
                collect_service(&record.name, &owner, &mut services);
            }
            dns::TYPE_SRV => {
                collect_instance(&record.name, &mut instances, &mut services);
                // The SRV target is the whole reason an instance name can be
                // tied to an address at all.
                if let Some(target) = dns::srv_target(msg_bytes, record) {
                    targets.push((key(&record.name), key(&target)));
                }
            }
            dns::TYPE_TXT => {
                collect_instance(&record.name, &mut instances, &mut services);
                collect_models(record, &instance_owner(&record.name), &mut models);
            }
            dns::TYPE_A | dns::TYPE_AAAA => {
                if let Some(address) = record_address(record) {
                    addresses.push((key(&record.name), address));
                }
                if let Some(host) = host_label(&record.name) {
                    push_owned(&mut hosts, host, Owner::Host(key(&record.name)));
                }
            }
            _ => {}
        }
    }

    // A probe asks for the name it intends to claim, so the question names of a
    // query are as good a signal as an answer. A question carries no records,
    // so it can only ever be about the sender.
    if !msg.is_response {
        for question in &msg.questions {
            collect_instance(question, &mut instances, &mut services);
            if let Some(host) = host_label(question) {
                push_owned(&mut hosts, host, Owner::Sender);
            }
        }
    }

    let resolve = |owner: &Owner| -> Vec<IpAddr> {
        match owner {
            Owner::Sender => Vec::new(),
            Owner::Host(host) => addresses_of(&addresses, host),
            Owner::Instance(instance) => targets
                .iter()
                .find(|(named, _)| named == instance)
                .map_or_else(Vec::new, |(_, host)| addresses_of(&addresses, host)),
        }
    };

    let mut out = Vec::with_capacity(instances.len() + hosts.len() + services.len() + models.len());
    for (values, kind) in [
        (instances, SignalKind::MdnsName),
        (hosts, SignalKind::MdnsName),
        (services, SignalKind::MdnsService),
        (models, SignalKind::MdnsModel),
    ] {
        for (value, owner) in values {
            out.push(NameClaim {
                signal: Signal::new(kind, value),
                addresses: resolve(&owner),
            });
        }
    }
    out
}

/// Every address published under one owner name.
fn addresses_of(addresses: &[(String, IpAddr)], host: &str) -> Vec<IpAddr> {
    addresses
        .iter()
        .filter(|(named, _)| named == host)
        .map(|(_, address)| *address)
        .collect()
}

/// The address an A or AAAA record carries.
///
/// A record whose rdata is not exactly four or sixteen bytes is malformed and
/// names no address; it is dropped rather than padded into one.
fn record_address(record: &dns::Record<'_>) -> Option<IpAddr> {
    match record.rtype {
        dns::TYPE_A => <[u8; 4]>::try_from(record.rdata)
            .ok()
            .map(|o| IpAddr::V4(Ipv4Addr::from(o))),
        dns::TYPE_AAAA => <[u8; 16]>::try_from(record.rdata)
            .ok()
            .map(|o| IpAddr::V6(Ipv6Addr::from(o))),
        _ => None,
    }
}

/// A name flattened into the key the address and target tables are keyed on.
///
/// Lowercased because DNS names are case-insensitive and a responder is entitled
/// to publish its SRV target in a different case from its address record. That
/// happens, and comparing the two case-sensitively would silently fail to tie an
/// instance to its address.
fn key(labels: &[String]) -> String {
    labels.join(".").to_ascii_lowercase()
}

/// The owner a `instance._svc._proto.local` name denotes, or [`Owner::Sender`]
/// when the name does not have that shape.
fn instance_owner(labels: &[String]) -> Owner {
    if labels.len() >= 4 && !labels[0].starts_with('_') && labels[1].starts_with('_') {
        Owner::Instance(key(labels))
    } else {
        Owner::Sender
    }
}

/// Pulls model strings out of a TXT record's key/value pairs.
///
/// TXT strings are `key=value`; a string with no `=` is a bare flag and names
/// nothing.
fn collect_models(record: &dns::Record<'_>, owner: &Owner, models: &mut Vec<Owned>) {
    for entry in dns::txt_strings(record) {
        let Some((key, value)) = entry.split_once('=') else {
            continue;
        };
        if !MODEL_KEYS
            .iter()
            .any(|k| k.eq_ignore_ascii_case(key.trim()))
        {
            continue;
        }
        if let Some(model) = crate::capture::names::clean_value(value) {
            push_owned(models, model, owner.clone());
        }
    }
}

/// Records the instance name and service type of a `instance._svc._proto.local`
/// name, if it has that shape.
fn collect_instance(labels: &[String], instances: &mut Vec<Owned>, services: &mut Vec<Owned>) {
    // Shape: instance, _service, _proto, local. The meta-service
    // `_services._dns-sd._udp.local` matches the label count but its first
    // label is underscore-prefixed, so it falls out as a service type instead.
    if labels.len() < 4 {
        collect_service(labels, &Owner::Sender, services);
        return;
    }
    let first = labels[0].as_str();
    if first.starts_with('_') {
        collect_service(labels, &Owner::Sender, services);
        return;
    }
    if !labels[1].starts_with('_') {
        return;
    }
    let owner = Owner::Instance(key(labels));
    if let Some(name) = usable_name(first) {
        push_owned(instances, name, owner.clone());
    }
    collect_service(&labels[1..], &owner, services);
}

/// Records a `_service._proto` pair from a name that starts with one.
fn collect_service(labels: &[String], owner: &Owner, services: &mut Vec<Owned>) {
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
    push_owned(services, format!("{svc}.{proto}"), owner.clone());
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
///
/// The rules are shared with every other protocol that volunteers a name; see
/// [`crate::capture::names`].
fn usable_name(raw: &str) -> Option<String> {
    crate::capture::names::clean_name(raw)
}

/// Appends a value and its owner unless the value is already present,
/// preserving first-seen order.
///
/// The first owner wins on a repeat. A message that publishes one name under two
/// owners has already contradicted itself, and the earlier record is the one the
/// responder led with.
fn push_owned(out: &mut Vec<Owned>, value: String, owner: Owner) {
    let mut seen: HashSet<&str> = HashSet::with_capacity(out.len());
    seen.extend(out.iter().map(|(v, _)| v.as_str()));
    if !seen.contains(value.as_str()) {
        out.push((value, owner));
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
        obs.claims
            .iter()
            .map(|c| &c.signal)
            .filter(|s| s.kind == kind)
            .map(|s| s.value.as_str())
            .collect()
    }

    /// The addresses the message proved for one named piece of evidence.
    fn addresses_for(obs: &Observation, value: &str) -> Vec<String> {
        obs.claims
            .iter()
            .find(|c| c.signal.value == value)
            .map(|c| c.addresses.iter().map(ToString::to_string).collect())
            .unwrap_or_default()
    }

    fn values(claims: &[NameClaim], kind: SignalKind) -> Vec<&str> {
        claims
            .iter()
            .map(|c| &c.signal)
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
        for claim in &obs.claims {
            assert_ne!(claim.signal.value, "_services");
            assert!(!claim.signal.value.starts_with("_services"));
        }
    }

    #[test]
    fn a_self_announcement_proves_its_own_address() {
        // The ordinary case, and the one that must keep working: the A record's
        // address is the frame's own source address, so both names are the
        // sender's and the manager will say so.
        let obs = parse_frame(&fixtures::mdns_response_ipv4(), "eth0", ts()).expect("parsed");
        assert_eq!(
            addresses_for(&obs, "Living Room Apple TV"),
            vec!["192.168.1.55"],
            "the instance name reaches its address through the SRV target"
        );
        assert_eq!(
            addresses_for(&obs, "living-room-apple-tv"),
            vec!["192.168.1.55"],
            "the host name reaches its address directly"
        );
    }

    #[test]
    fn a_response_with_no_address_record_proves_no_address() {
        // The printer announces a service and never repeats its own address.
        // Nothing contradicts the sender, so the claim travels unaddressed and
        // the manager falls back to the sender. Requiring an address here would
        // throw away a perfectly good name.
        let obs = parse_frame(&fixtures::mdns_response_ipv6(), "eth0", ts()).expect("parsed");
        assert_eq!(names(&obs, SignalKind::MdnsName), vec!["Office Printer"]);
        assert!(
            addresses_for(&obs, "Office Printer").is_empty(),
            "the message carried no address record to tie the name to"
        );
    }

    #[test]
    fn a_sleep_proxy_answer_ties_each_name_to_the_host_it_belongs_to() {
        // The 2026-09-17 defect, at the layer it starts on. One source MAC,
        // three hosts. Before the fix every name here came out as the phone's.
        let obs = parse_frame(&fixtures::mdns_sleep_proxy(), "eth0", ts()).expect("parsed");
        assert_eq!(obs.mac, "3c:22:fb:9a:1b:2c".parse().expect("mac"));
        assert_eq!(obs.ip, Some("192.168.1.40".parse().expect("ip")));

        assert_eq!(
            addresses_for(&obs, "Jeremy's iPhone"),
            vec!["192.168.1.40"],
            "the sender's own name is proved for the sender's own address"
        );
        for (name, address) in [
            ("Jeremy's iMac", "192.168.1.60"),
            ("Ospiti", "192.168.1.61"),
        ] {
            assert_eq!(
                addresses_for(&obs, name),
                vec![address],
                "{name} is evidence about {address}, not about the responder"
            );
        }

        // The service types go the same way. A proxied host's service must not
        // classify the proxy either: the phone is not a screen-sharing Mac.
        for (service, address) in [("_rfb._tcp", "192.168.1.60"), ("_smb._tcp", "192.168.1.61")] {
            assert_eq!(addresses_for(&obs, service), vec![address], "{service}");
        }
    }

    #[test]
    fn an_srv_target_in_a_different_case_still_reaches_its_address() {
        // DNS names are case-insensitive and responders are entitled to
        // disagree with themselves about case. Comparing case-sensitively would
        // silently fail to tie the instance to its address, which would make
        // every such name unattributed.
        let msg = message(&[
            (
                vec!["Kitchen Speaker", "_sonos", "_tcp", "local"],
                dns::TYPE_SRV,
                srv_rdata(&["KITCHEN-SPEAKER", "Local"]),
            ),
            (
                vec!["kitchen-speaker", "local"],
                dns::TYPE_A,
                vec![192, 168, 1, 70],
            ),
        ]);
        let parsed = dns::parse_message(&msg).expect("parsed");
        let claims = extract_claims(&msg, &parsed);
        let speaker = claims
            .iter()
            .find(|c| c.signal.value == "Kitchen Speaker")
            .expect("the instance name");
        assert_eq!(
            speaker.addresses,
            vec!["192.168.1.70".parse::<IpAddr>().expect("ip")]
        );
    }

    #[test]
    fn a_malformed_address_record_names_no_address() {
        // Four bytes or sixteen, or it is not an address. Padding a short rdata
        // into one would invent an address and attribute a name to it.
        let msg = message(&[(vec!["truncated", "local"], dns::TYPE_A, vec![192, 168, 1])]);
        let parsed = dns::parse_message(&msg).expect("parsed");
        let claims = extract_claims(&msg, &parsed);
        assert_eq!(values(&claims, SignalKind::MdnsName), vec!["truncated"]);
        assert!(claims[0].addresses.is_empty());
    }

    /// SRV rdata whose fixed fields are zero and whose target is `target`.
    fn srv_rdata(target: &[&str]) -> Vec<u8> {
        let mut rdata = vec![0, 0, 0, 0, 0, 0];
        for label in target {
            rdata.push(u8::try_from(label.len()).expect("label fits"));
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        rdata
    }

    /// Builds an mDNS response message from `(name, type, rdata)` triples.
    fn message(answers: &[(Vec<&str>, u16, Vec<u8>)]) -> Vec<u8> {
        let mut m = vec![0, 0, 0x84, 0x00];
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&u16::try_from(answers.len()).expect("few").to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        for (name, rtype, rdata) in answers {
            for label in name {
                m.push(u8::try_from(label.len()).expect("label fits"));
                m.extend_from_slice(label.as_bytes());
            }
            m.push(0);
            m.extend_from_slice(&rtype.to_be_bytes());
            m.extend_from_slice(&0x8001u16.to_be_bytes());
            m.extend_from_slice(&120u32.to_be_bytes());
            m.extend_from_slice(&u16::try_from(rdata.len()).expect("fits").to_be_bytes());
            m.extend_from_slice(rdata);
        }
        m
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
        let mut inst: Vec<Owned> = Vec::new();
        let mut svc: Vec<Owned> = Vec::new();
        let labels = |v: &[&str]| v.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        fn just(v: &[Owned]) -> Vec<&str> {
            v.iter().map(|(x, _)| x.as_str()).collect()
        }

        collect_instance(
            &labels(&["Kitchen Sonos", "_sonos", "_tcp", "local"]),
            &mut inst,
            &mut svc,
        );
        assert_eq!(just(&inst), vec!["Kitchen Sonos"]);
        assert_eq!(just(&svc), vec!["_sonos._tcp"]);
        assert_eq!(
            inst[0].1,
            Owner::Instance("kitchen sonos._sonos._tcp.local".into()),
            "the instance owns its own name, so its address can be looked up"
        );

        // The meta-service must not become an instance.
        collect_instance(
            &labels(&["_services", "_dns-sd", "_udp", "local"]),
            &mut inst,
            &mut svc,
        );
        assert_eq!(just(&inst), vec!["Kitchen Sonos"], "unchanged");

        // A bare host name is not a service instance.
        collect_instance(&labels(&["printer", "local"]), &mut inst, &mut svc);
        assert_eq!(just(&inst), vec!["Kitchen Sonos"], "unchanged");
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
    fn a_device_info_txt_record_yields_the_model_that_names_the_os() {
        // `_device-info._tcp` is what Apple devices publish unprompted, and
        // `model=` in it is the strongest OS evidence mDNS carries.
        let msg = txt_message(
            &["Jeremy's MacBook", "_device-info", "_tcp", "local"],
            &["model=MacBookPro18,1", "osxvers=21"],
        );
        let parsed = dns::parse_message(&msg).expect("parsed");
        let claims = extract_claims(&msg, &parsed);
        assert_eq!(
            values(&claims, SignalKind::MdnsModel),
            vec!["MacBookPro18,1"]
        );
        assert_eq!(
            values(&claims, SignalKind::MdnsName),
            vec!["Jeremy's MacBook"],
            "the instance name is still the naming signal"
        );
    }

    #[test]
    fn a_printer_txt_record_yields_its_model_under_a_different_key() {
        let msg = txt_message(
            &["Office Printer", "_ipp", "_tcp", "local"],
            &["ty=Brother HL-L2350DW", "note=", "rp=ipp/print"],
        );
        let parsed = dns::parse_message(&msg).expect("parsed");
        let claims = extract_claims(&msg, &parsed);
        assert_eq!(
            values(&claims, SignalKind::MdnsModel),
            vec!["Brother HL-L2350DW"]
        );
    }

    #[test]
    fn txt_strings_that_are_not_key_value_pairs_name_nothing() {
        let msg = txt_message(
            &["Thing", "_http", "_tcp", "local"],
            &["flagonly", "=novalue", "model="],
        );
        let parsed = dns::parse_message(&msg).expect("parsed");
        assert!(
            extract_claims(&msg, &parsed)
                .iter()
                .all(|c| c.signal.kind != SignalKind::MdnsModel)
        );
    }

    /// Builds an mDNS response holding one TXT record with the given strings.
    fn txt_message(owner: &[&str], strings: &[&str]) -> Vec<u8> {
        let mut m = vec![0, 0, 0x84, 0x00];
        m.extend_from_slice(&0u16.to_be_bytes()); // questions
        m.extend_from_slice(&1u16.to_be_bytes()); // answers
        m.extend_from_slice(&0u16.to_be_bytes()); // authority
        m.extend_from_slice(&0u16.to_be_bytes()); // additional
        for label in owner {
            m.push(u8::try_from(label.len()).expect("label fits"));
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&dns::TYPE_TXT.to_be_bytes());
        m.extend_from_slice(&0x8001u16.to_be_bytes());
        m.extend_from_slice(&120u32.to_be_bytes());
        let mut rdata = Vec::new();
        for s in strings {
            rdata.push(u8::try_from(s.len()).expect("string fits"));
            rdata.extend_from_slice(s.as_bytes());
        }
        m.extend_from_slice(
            &u16::try_from(rdata.len())
                .expect("rdata fits")
                .to_be_bytes(),
        );
        m.extend_from_slice(&rdata);
        m
    }

    #[test]
    fn duplicate_signals_are_collapsed() {
        let mut out: Vec<Owned> = Vec::new();
        push_owned(&mut out, "a".into(), Owner::Sender);
        push_owned(&mut out, "a".into(), Owner::Host("elsewhere".into()));
        push_owned(&mut out, "b".into(), Owner::Sender);
        assert_eq!(
            out.iter().map(|(v, _)| v.as_str()).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert_eq!(out[0].1, Owner::Sender, "the first owner wins on a repeat");
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
