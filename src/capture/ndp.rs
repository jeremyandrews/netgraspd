//! IPv6 Neighbor Discovery capture source.
//!
//! NDP is the IPv6 equivalent of ARP, and the same rule governs it: only the
//! **sender** is a sighting. A Neighbor Solicitation names a target address, but
//! that target is the address being asked about, not a device known to be
//! present, and treating it as one invents devices.
//!
//! Neighbor Advertisements are the exception worth spelling out. There the
//! target address *is* the advertiser's own address, so it is both a sighting
//! and the best address the packet carries.
//!
//! ## Router Advertisements identify routers, definitively
//!
//! A device that emits a Router Advertisement is a router. No other passive
//! signal is that unambiguous, so an RA yields a [`SignalKind::NdpRole`] signal
//! that the classifier trusts above every vendor guess.
//!
//! ## Privacy extensions
//!
//! RFC 4941 temporary addresses mean one MAC legitimately shows many IPv6
//! addresses, rotating as often as daily. Netgrasp is MAC-keyed, so this is not
//! a source of phantom devices; each address is one more row in
//! `ng_ip_history`, which is what that table is for.
//!
//! ## Why `last_ip` is still IPv4
//!
//! The B1 note asked for this decision to be revisited once NDP landed. It was,
//! and it stands with one addition. `ng_devices.last_ip` remains IPv4-only,
//! because it feeds `ip_changed` and a rotating temporary address would emit an
//! `ip_changed` event every day per device for no operator benefit. What was
//! missing is a *current* IPv6 address at all, so `ng_devices.last_ipv6` was
//! added: written on flush, never event-generating, and preferring a global
//! address over a link-local one, because every device always has a link-local
//! and it is the least informative address it holds.

use std::net::{IpAddr, Ipv6Addr};

use chrono::{DateTime, Utc};

use crate::capture::ethernet::{ETHERTYPE_IPV6, parse_ethernet, parse_ipv6};
use crate::types::{MacAddr, Observation, ObservationKind, Signal, SignalKind};

/// Short name of this source, stored on every observation it produces.
pub const SOURCE: &str = "ndp";

/// BPF filter narrowing the capture to the five Neighbor Discovery messages.
pub const FILTER: &str = "icmp6 and ip6[40] >= 133 and ip6[40] <= 137";

/// IP protocol number for ICMPv6.
pub const IPPROTO_ICMPV6: u8 = 58;

/// ICMPv6 type: Router Solicitation.
const ROUTER_SOLICITATION: u8 = 133;
/// ICMPv6 type: Router Advertisement.
const ROUTER_ADVERTISEMENT: u8 = 134;
/// ICMPv6 type: Neighbor Solicitation.
const NEIGHBOR_SOLICITATION: u8 = 135;
/// ICMPv6 type: Neighbor Advertisement.
const NEIGHBOR_ADVERTISEMENT: u8 = 136;
/// ICMPv6 type: Redirect.
const REDIRECT: u8 = 137;

/// NDP option type: source link-layer address.
const OPT_SOURCE_LINK_ADDR: u8 = 1;
/// NDP option type: target link-layer address.
const OPT_TARGET_LINK_ADDR: u8 = 2;

/// Value of the [`SignalKind::NdpRole`] signal emitted for a router.
pub const ROLE_ROUTER: &str = "router";

/// Which Neighbor Discovery message a frame carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdpMessage {
    /// A host asking routers to advertise.
    RouterSolicitation,
    /// A router advertising itself and its prefixes.
    RouterAdvertisement,
    /// A node asking who holds an address.
    NeighborSolicitation,
    /// A node answering, or announcing, that it holds an address.
    NeighborAdvertisement,
    /// A router telling a host about a better first hop.
    Redirect,
}

impl NdpMessage {
    /// Reads a message from an ICMPv6 type byte.
    #[must_use]
    const fn from_type(icmp_type: u8) -> Option<Self> {
        Some(match icmp_type {
            ROUTER_SOLICITATION => NdpMessage::RouterSolicitation,
            ROUTER_ADVERTISEMENT => NdpMessage::RouterAdvertisement,
            NEIGHBOR_SOLICITATION => NdpMessage::NeighborSolicitation,
            NEIGHBOR_ADVERTISEMENT => NdpMessage::NeighborAdvertisement,
            REDIRECT => NdpMessage::Redirect,
            _ => return None,
        })
    }

    /// Offset of the message body's options, past its fixed fields.
    ///
    /// All five share the four-byte ICMPv6 header; what follows differs.
    #[must_use]
    const fn options_offset(&self) -> usize {
        match self {
            // Reserved (4) only.
            NdpMessage::RouterSolicitation => 8,
            // Hop limit, flags, lifetime, reachable time, retrans timer.
            NdpMessage::RouterAdvertisement => 16,
            // Reserved or flags (4) plus a 16-byte target address.
            NdpMessage::NeighborSolicitation | NdpMessage::NeighborAdvertisement => 24,
            // Reserved (4) plus target and destination addresses.
            NdpMessage::Redirect => 40,
        }
    }

    /// How this message maps onto the protocol-independent observation kinds.
    #[must_use]
    const fn observation_kind(&self) -> ObservationKind {
        match self {
            NdpMessage::RouterSolicitation | NdpMessage::NeighborSolicitation => {
                ObservationKind::Request
            }
            NdpMessage::NeighborAdvertisement => ObservationKind::Reply,
            NdpMessage::RouterAdvertisement | NdpMessage::Redirect => ObservationKind::Announcement,
        }
    }
}

/// Parses one captured frame into an observation.
///
/// Returns `None` for anything that is not a well-formed Neighbor Discovery
/// message, and for messages whose source MAC cannot identify a device.
#[must_use]
pub fn parse_frame(
    bytes: &[u8],
    interface: &str,
    observed_at: DateTime<Utc>,
) -> Option<Observation> {
    let frame = parse_ethernet(bytes)?;
    if frame.ethertype != ETHERTYPE_IPV6 {
        return None;
    }
    let ip = parse_ipv6(frame.payload)?;
    if ip.protocol != IPPROTO_ICMPV6 {
        return None;
    }
    let icmp = ip.payload;
    let message = NdpMessage::from_type(*icmp.first()?)?;

    // The link-layer address option normally repeats the Ethernet source, and
    // where the two disagree the frame source is who actually transmitted, so it
    // wins. The option is the fallback for the frames where the Ethernet source
    // is unusable, which happens behind bridges that rewrite it.
    let mac = if frame.src.is_group() || frame.src.is_zero() {
        link_layer_address(icmp, message)?
    } else {
        frame.src
    };
    if mac.is_group() || mac.is_zero() {
        return None;
    }

    let ip_addr = sender_address(icmp, message, &ip.src);

    let mut observation = Observation::new(
        mac,
        ip_addr,
        interface,
        SOURCE,
        message.observation_kind(),
        observed_at,
    );
    if message == NdpMessage::RouterAdvertisement {
        observation = observation.with_signal(Signal::new(SignalKind::NdpRole, ROLE_ROUTER));
    }
    Some(observation)
}

/// The address that belongs to the sender, when the message reveals one.
///
/// A Neighbor Advertisement's target address is the sender's own, and is
/// preferred over the IPv6 source because an unsolicited advertisement is often
/// sourced from a link-local address while advertising a global one.
///
/// Duplicate Address Detection sends a solicitation from the unspecified
/// address, which proves presence but names no address.
fn sender_address(icmp: &[u8], message: NdpMessage, src: &IpAddr) -> Option<IpAddr> {
    if message == NdpMessage::NeighborAdvertisement
        && let Some(target) = address_at(icmp, 8)
        && is_device_address(target)
    {
        return Some(IpAddr::V6(target));
    }
    match src {
        IpAddr::V6(v6) if is_device_address(*v6) => Some(*src),
        _ => None,
    }
}

/// Reads a 16-byte IPv6 address out of the ICMPv6 body.
fn address_at(icmp: &[u8], offset: usize) -> Option<Ipv6Addr> {
    let raw: [u8; 16] = icmp.get(offset..offset + 16)?.try_into().ok()?;
    Some(Ipv6Addr::from(raw))
}

/// True when an address belongs to a device rather than being a placeholder or
/// a group.
#[must_use]
pub fn is_device_address(addr: Ipv6Addr) -> bool {
    !addr.is_unspecified() && !addr.is_multicast() && !addr.is_loopback()
}

/// True for a link-local address, `fe80::/10`.
///
/// Every IPv6 device has one and it is derived from the MAC, so it is the least
/// informative address a device holds and loses to a global one.
#[must_use]
pub fn is_link_local(addr: Ipv6Addr) -> bool {
    addr.segments()[0] & 0xffc0 == 0xfe80
}

/// Walks the option list for a link-layer address.
///
/// A solicitation carries the sender's address as option 1; an advertisement
/// carries it as option 2, because from the advertiser's point of view it is
/// answering about a target.
fn link_layer_address(icmp: &[u8], message: NdpMessage) -> Option<MacAddr> {
    let wanted = match message {
        NdpMessage::NeighborAdvertisement => OPT_TARGET_LINK_ADDR,
        _ => OPT_SOURCE_LINK_ADDR,
    };
    let mut offset = message.options_offset();
    // A malformed option list with a zero length would loop; the length check
    // below is what stops it, and this bounds the walk regardless.
    for _ in 0..16 {
        let kind = *icmp.get(offset)?;
        let units = usize::from(*icmp.get(offset + 1)?);
        if units == 0 {
            return None;
        }
        let end = offset + units * 8;
        if (kind == wanted || kind == OPT_SOURCE_LINK_ADDR)
            && let Some(raw) = icmp.get(offset + 2..offset + 8)
        {
            let mac = MacAddr(raw.try_into().ok()?);
            if !mac.is_zero() && !mac.is_group() {
                return Some(mac);
            }
        }
        offset = end;
    }
    None
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
    fn parses_a_real_neighbor_solicitation() {
        let obs = parse_frame(&fixtures::ndp_solicitation(), "eth0", ts()).expect("parsed");
        assert_eq!(obs.mac, "3c:22:fb:9a:1b:2c".parse().expect("mac"));
        assert_eq!(
            obs.ip,
            Some("fe80::3e22:fbff:fe9a:1b2c".parse().expect("ip")),
            "the sender's address, not the address it is asking about"
        );
        assert_eq!(obs.kind, ObservationKind::Request);
        assert_eq!(obs.source, "ndp");
        assert!(obs.signals.is_empty());
    }

    #[test]
    fn the_target_of_a_solicitation_is_never_a_sighting() {
        // The fixture asks about 2001:db8::1. That address must not appear.
        let obs = parse_frame(&fixtures::ndp_solicitation(), "eth0", ts()).expect("parsed");
        assert_ne!(obs.ip, Some("2001:db8::1".parse().expect("ip")));
    }

    #[test]
    fn an_advertisement_reports_the_address_it_advertises() {
        let obs = parse_frame(&fixtures::ndp_advertisement(), "eth0", ts()).expect("parsed");
        assert_eq!(obs.mac, "b8:27:eb:44:55:66".parse().expect("mac"));
        assert_eq!(
            obs.ip,
            Some("2001:db8::1".parse().expect("ip")),
            "the target of an advertisement is the advertiser's own address"
        );
        assert_eq!(obs.kind, ObservationKind::Reply);
    }

    #[test]
    fn a_router_advertisement_identifies_a_router_beyond_argument() {
        let obs = parse_frame(&fixtures::ndp_router_advertisement(), "eth0", ts()).expect("parsed");
        assert_eq!(obs.kind, ObservationKind::Announcement);
        assert_eq!(obs.signals.len(), 1);
        assert_eq!(obs.signals[0].kind, SignalKind::NdpRole);
        assert_eq!(obs.signals[0].value, ROLE_ROUTER);
    }

    #[test]
    fn duplicate_address_detection_proves_presence_without_an_address() {
        // A DAD solicitation is sourced from :: because the sender has not
        // claimed anything yet. Recording :: as an address would be wrong.
        let obs = parse_frame(&fixtures::ndp_dad(), "eth0", ts()).expect("parsed");
        assert_eq!(obs.mac, "3c:2a:f4:11:22:33".parse().expect("mac"));
        assert_eq!(obs.ip, None);
        assert_eq!(obs.kind, ObservationKind::Request);
    }

    #[test]
    fn link_local_addresses_are_recognised_and_globals_are_not() {
        assert!(is_link_local("fe80::1".parse().expect("ip")));
        assert!(is_link_local(
            "fe80::3e22:fbff:fe9a:1b2c".parse().expect("ip")
        ));
        assert!(is_link_local("feb0::1".parse().expect("ip")), "fe80::/10");
        assert!(!is_link_local("2001:db8::1".parse().expect("ip")));
        assert!(
            !is_link_local("fc00::1".parse().expect("ip")),
            "unique local"
        );
    }

    #[test]
    fn placeholder_and_group_addresses_are_not_device_addresses() {
        assert!(!is_device_address("::".parse().expect("ip")));
        assert!(!is_device_address("ff02::1".parse().expect("ip")));
        assert!(!is_device_address("::1".parse().expect("ip")));
        assert!(is_device_address("fe80::1".parse().expect("ip")));
        assert!(is_device_address("2001:db8::5".parse().expect("ip")));
    }

    #[test]
    fn an_option_list_with_a_zero_length_cannot_loop() {
        // Length is in eight-byte units, so a zero would advance the walk by
        // nothing and spin forever.
        let mut icmp = vec![NEIGHBOR_SOLICITATION, 0, 0, 0];
        icmp.extend_from_slice(&[0u8; 4]); // reserved
        icmp.extend_from_slice(&[0u8; 16]); // target
        icmp.extend_from_slice(&[OPT_SOURCE_LINK_ADDR, 0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(
            link_layer_address(&icmp, NdpMessage::NeighborSolicitation),
            None
        );
    }

    #[test]
    fn non_ndp_and_malformed_frames_are_rejected() {
        assert!(parse_frame(&fixtures::arp_request(), "eth0", ts()).is_none());
        assert!(parse_frame(&fixtures::mdns_response_ipv6(), "eth0", ts()).is_none());
        assert!(parse_frame(&[], "eth0", ts()).is_none());
    }

    #[test]
    fn an_unknown_icmpv6_type_is_not_neighbor_discovery() {
        let mut bytes = fixtures::ndp_solicitation();
        // 14 Ethernet + 40 IPv6 = the ICMPv6 type byte.
        bytes[54] = 128; // echo request
        assert!(parse_frame(&bytes, "eth0", ts()).is_none());
    }

    #[test]
    fn truncated_ndp_frames_do_not_panic() {
        for fixture in [
            fixtures::ndp_solicitation(),
            fixtures::ndp_advertisement(),
            fixtures::ndp_router_advertisement(),
            fixtures::ndp_dad(),
        ] {
            for n in 0..fixture.len() {
                let _ = parse_frame(&fixture[..n], "eth0", ts());
            }
        }
    }
}
