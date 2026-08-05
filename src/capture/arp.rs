//! ARP capture source.
//!
//! ARP is the workhorse signal: almost everything on an IPv4 LAN broadcasts it,
//! and it carries a MAC and an IPv4 address in one packet. Only the **sender**
//! fields are trusted. A request also names a target, but the target is the
//! address being asked about, not a device known to be present, and treating it
//! as a sighting invents devices that do not exist.

use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, Utc};

use crate::capture::ethernet::{ETHERTYPE_ARP, parse_ethernet};
use crate::types::{ArpDetail, ArpOp, MacAddr, Observation, ObservationKind, ProtocolDetail};

/// Short name of this source, stored on every observation it produces.
pub const SOURCE: &str = "arp";

/// BPF filter narrowing the capture to ARP frames.
pub const FILTER: &str = "arp";

/// ARP hardware type for Ethernet.
const HTYPE_ETHERNET: u16 = 1;
/// ARP protocol type for IPv4.
const PTYPE_IPV4: u16 = 0x0800;
/// Opcode for a request.
const OP_REQUEST: u16 = 1;
/// Opcode for a reply.
const OP_REPLY: u16 = 2;

/// Parses one captured frame into an observation.
///
/// Returns `None` for anything that is not a well-formed Ethernet/IPv4 ARP
/// packet, and for packets whose sender hardware address cannot identify a
/// device (broadcast, multicast or all-zero).
#[must_use]
pub fn parse_frame(
    bytes: &[u8],
    interface: &str,
    observed_at: DateTime<Utc>,
) -> Option<Observation> {
    let frame = parse_ethernet(bytes)?;
    if frame.ethertype != ETHERTYPE_ARP {
        return None;
    }
    let arp = frame.payload;
    if arp.len() < 28 {
        return None;
    }
    let htype = u16::from_be_bytes([arp[0], arp[1]]);
    let ptype = u16::from_be_bytes([arp[2], arp[3]]);
    let hlen = arp[4];
    let plen = arp[5];
    if htype != HTYPE_ETHERNET || ptype != PTYPE_IPV4 || hlen != 6 || plen != 4 {
        return None;
    }
    let opcode = u16::from_be_bytes([arp[6], arp[7]]);

    let sender_mac = MacAddr(arp[8..14].try_into().ok()?);
    let sender_ip = ipv4(&arp[14..18])?;
    let target_ip = ipv4(&arp[24..28])?;

    if sender_mac.is_group() || sender_mac.is_zero() {
        return None;
    }
    // The Ethernet source and the ARP sender disagreeing is either a proxy ARP
    // device or a spoof attempt. Here the link-layer source is the device that
    // actually transmitted, so it wins; the analyzers see the sender field
    // unaltered in ArpDetail and can compare the two for themselves.
    let mac = if frame.src.is_group() || frame.src.is_zero() {
        sender_mac
    } else {
        frame.src
    };

    // A sender address of 0.0.0.0 is an ARP probe: the device is present but has
    // no address yet, so it must not be recorded as owning 0.0.0.0.
    let claimed = (!sender_ip.is_unspecified()).then_some(sender_ip);
    let ip = claimed.map(IpAddr::V4);
    let gratuitous = claimed.is_some() && sender_ip == target_ip;

    let (op, kind) = match opcode {
        // A gratuitous ARP announces the sender's own address rather than
        // asking about somebody else's.
        OP_REQUEST if gratuitous => (ArpOp::Request, ObservationKind::Announcement),
        OP_REQUEST => (ArpOp::Request, ObservationKind::Request),
        OP_REPLY if gratuitous => (ArpOp::Reply, ObservationKind::Announcement),
        OP_REPLY => (ArpOp::Reply, ObservationKind::Reply),
        _ => return None,
    };

    Some(
        Observation::new(mac, ip, interface, SOURCE, kind, observed_at).with_detail(
            ProtocolDetail::Arp(ArpDetail {
                op,
                sender_mac,
                sender_ip: claimed,
                target_ip,
                gratuitous,
            }),
        ),
    )
}

/// Reads four bytes as an IPv4 address.
fn ipv4(bytes: &[u8]) -> Option<Ipv4Addr> {
    let octets: [u8; 4] = bytes.try_into().ok()?;
    Some(Ipv4Addr::from(octets))
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

    #[test]
    fn parses_a_real_arp_request() {
        let obs = parse_frame(&fixtures::arp_request(), "eth0", ts()).expect("parsed");
        assert_eq!(obs.mac, "3c:22:fb:9a:1b:2c".parse().expect("mac"));
        assert_eq!(obs.ip, Some("192.168.1.40".parse().expect("ip")));
        assert_eq!(obs.kind, ObservationKind::Request);
        assert_eq!(obs.source, "arp");
        assert_eq!(obs.interface, "eth0");
        assert!(obs.signals.is_empty(), "ARP carries no identity evidence");
    }

    #[test]
    fn parses_a_real_arp_reply() {
        let obs = parse_frame(&fixtures::arp_reply(), "eth0", ts()).expect("parsed");
        assert_eq!(obs.mac, "b8:27:eb:44:55:66".parse().expect("mac"));
        assert_eq!(obs.ip, Some("192.168.1.1".parse().expect("ip")));
        assert_eq!(obs.kind, ObservationKind::Reply);
    }

    #[test]
    fn a_gratuitous_arp_is_an_announcement() {
        let obs = parse_frame(&fixtures::arp_gratuitous(), "eth0", ts()).expect("parsed");
        assert_eq!(obs.kind, ObservationKind::Announcement);
        assert_eq!(obs.ip, Some("192.168.1.77".parse().expect("ip")));
    }

    #[test]
    fn an_arp_probe_records_presence_without_an_address() {
        let obs = parse_frame(&fixtures::arp_probe(), "eth0", ts()).expect("parsed");
        assert_eq!(obs.mac, "3c:22:fb:9a:1b:2c".parse().expect("mac"));
        assert_eq!(obs.ip, None, "0.0.0.0 must never be stored as an address");
        assert_eq!(obs.kind, ObservationKind::Request);
    }

    #[test]
    fn a_vlan_tagged_arp_still_parses() {
        let obs = parse_frame(&fixtures::arp_request_vlan(), "eth0", ts()).expect("parsed");
        assert_eq!(obs.mac, "3c:22:fb:9a:1b:2c".parse().expect("mac"));
        assert_eq!(obs.ip, Some("192.168.1.40".parse().expect("ip")));
    }

    #[test]
    fn the_target_of_a_request_is_never_treated_as_a_sighting() {
        // The fixture asks about 192.168.1.1 at the broadcast MAC. Only one
        // observation comes out of it, and it is the sender.
        let obs = parse_frame(&fixtures::arp_request(), "eth0", ts()).expect("parsed");
        assert_ne!(obs.ip, Some("192.168.1.1".parse().expect("ip")));
    }

    #[test]
    fn non_arp_and_malformed_frames_are_rejected() {
        assert!(parse_frame(&fixtures::mdns_response_ipv4(), "eth0", ts()).is_none());
        assert!(parse_frame(&[], "eth0", ts()).is_none());
        let full = fixtures::arp_request();
        for n in [0, 13, 14, 20, 41] {
            assert!(
                parse_frame(&full[..n.min(full.len())], "eth0", ts()).is_none(),
                "len {n}"
            );
        }
    }

    #[test]
    fn unsupported_hardware_or_protocol_types_are_rejected() {
        let mut f = fixtures::arp_request();
        f[15] = 0x06; // hardware type 6, not Ethernet
        assert!(parse_frame(&f, "eth0", ts()).is_none());

        let mut f = fixtures::arp_request();
        f[17] = 0x86; // protocol type not IPv4
        assert!(parse_frame(&f, "eth0", ts()).is_none());
    }

    #[test]
    fn an_unknown_opcode_is_rejected() {
        let mut f = fixtures::arp_request();
        f[21] = 0x09; // RARP-ish opcode
        assert!(parse_frame(&f, "eth0", ts()).is_none());
    }

    #[test]
    fn a_request_carries_the_target_the_analyzers_need() {
        // The state machine collapses an ARP request to "this MAC was here".
        // arp_scan counts distinct targets, so the target has to survive.
        let obs = parse_frame(&fixtures::arp_request(), "eth0", ts()).expect("parsed");
        let arp = obs.arp().expect("arp detail");
        assert_eq!(arp.op, ArpOp::Request);
        assert_eq!(arp.sender_mac, "3c:22:fb:9a:1b:2c".parse().expect("mac"));
        assert_eq!(arp.sender_ip, Some(Ipv4Addr::new(192, 168, 1, 40)));
        assert_eq!(arp.target_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert!(!arp.gratuitous);
    }

    #[test]
    fn a_gratuitous_arp_is_flagged_as_such_in_the_detail() {
        let obs = parse_frame(&fixtures::arp_gratuitous(), "eth0", ts()).expect("parsed");
        let arp = obs.arp().expect("arp detail");
        assert!(arp.gratuitous);
        assert_eq!(arp.sender_ip, Some(Ipv4Addr::new(192, 168, 1, 77)));
        assert_eq!(arp.target_ip, Ipv4Addr::new(192, 168, 1, 77));
    }

    #[test]
    fn a_probe_claims_no_address_in_the_detail_either() {
        let obs = parse_frame(&fixtures::arp_probe(), "eth0", ts()).expect("parsed");
        let arp = obs.arp().expect("arp detail");
        assert_eq!(arp.sender_ip, None, "0.0.0.0 is not a claim");
        assert!(!arp.gratuitous, "a probe is not an announcement");
    }

    #[test]
    fn the_sender_field_survives_even_when_it_disagrees_with_the_frame() {
        // The shape of a spoof: the Ethernet source is the real transmitter and
        // the ARP sender is the identity being borrowed. Both must reach the
        // analyzers.
        let mut f = fixtures::arp_reply();
        f[22..28].copy_from_slice(&[0x00, 0x11, 0x32, 0xaa, 0xbb, 0xcc]);
        let obs = parse_frame(&f, "eth0", ts()).expect("parsed");
        assert_eq!(
            obs.mac,
            "b8:27:eb:44:55:66".parse().expect("mac"),
            "the link-layer source is who actually transmitted"
        );
        assert_eq!(
            obs.arp().expect("arp detail").sender_mac,
            "00:11:32:aa:bb:cc".parse().expect("mac"),
            "the claim is preserved unaltered"
        );
    }

    #[test]
    fn a_group_sender_address_is_rejected() {
        let mut f = fixtures::arp_request();
        // Set both the Ethernet source and the ARP sender to broadcast.
        f[6..12].copy_from_slice(&[0xff; 6]);
        f[22..28].copy_from_slice(&[0xff; 6]);
        assert!(parse_frame(&f, "eth0", ts()).is_none());
    }
}
