//! Link and network layer framing shared by the protocol parsers.
//!
//! Everything here is a pure function over a byte slice with no panicking
//! indexing, so a malformed or truncated frame from a hostile device produces
//! `None` rather than a crashed capture thread.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::types::MacAddr;

/// EtherType for ARP.
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// EtherType for IPv4.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType for IPv6.
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
/// EtherType for an 802.1Q VLAN tag.
pub const ETHERTYPE_VLAN: u16 = 0x8100;
/// EtherType for an 802.1ad stacked VLAN tag.
pub const ETHERTYPE_QINQ: u16 = 0x88A8;
/// IP protocol number for UDP.
pub const IPPROTO_UDP: u8 = 17;

/// How many stacked VLAN tags to walk before giving up. Two covers Q-in-Q; a
/// deeper stack is either exotic or an attempt to hide a header behind a wall of
/// tags, and neither is worth parsing.
const MAX_VLAN_TAGS: usize = 2;

/// A parsed Ethernet II frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame<'a> {
    /// Destination hardware address.
    pub dst: MacAddr,
    /// Source hardware address, which is the device Netgrasp is identifying.
    pub src: MacAddr,
    /// EtherType after any VLAN tags have been stripped.
    pub ethertype: u16,
    /// Everything after the (possibly tagged) header.
    pub payload: &'a [u8],
}

/// Parses an Ethernet II frame, transparently stripping VLAN tags.
///
/// Returns `None` when the frame is too short to hold a header.
#[must_use]
pub fn parse_ethernet(bytes: &[u8]) -> Option<EthernetFrame<'_>> {
    if bytes.len() < 14 {
        return None;
    }
    let dst = MacAddr(bytes[0..6].try_into().ok()?);
    let src = MacAddr(bytes[6..12].try_into().ok()?);

    let mut offset = 12;
    let mut ethertype = read_u16(bytes, offset)?;
    for _ in 0..MAX_VLAN_TAGS {
        if ethertype != ETHERTYPE_VLAN && ethertype != ETHERTYPE_QINQ {
            break;
        }
        // A tag is 2 bytes of TCI followed by the real (or next) EtherType.
        offset += 4;
        ethertype = read_u16(bytes, offset)?;
    }
    offset += 2;
    Some(EthernetFrame {
        dst,
        src,
        ethertype,
        payload: bytes.get(offset..)?,
    })
}

/// The parts of an IP header the daemon cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpHeader<'a> {
    /// Source address.
    pub src: IpAddr,
    /// Destination address, used to confirm that multicast traffic really was
    /// multicast.
    pub dst: IpAddr,
    /// Transport protocol number.
    pub protocol: u8,
    /// Transport layer payload.
    pub payload: &'a [u8],
}

/// Parses an IPv4 header, honouring IHL and the total-length field.
///
/// Fragments other than the first are rejected: reassembly is out of scope and a
/// later fragment has no transport header to read.
#[must_use]
pub fn parse_ipv4(bytes: &[u8]) -> Option<IpHeader<'_>> {
    if bytes.len() < 20 {
        return None;
    }
    let version = bytes[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = usize::from(bytes[0] & 0x0f) * 4;
    if ihl < 20 || bytes.len() < ihl {
        return None;
    }
    let frag = read_u16(bytes, 6)?;
    if frag & 0x1fff != 0 {
        return None;
    }
    let total_len = usize::from(read_u16(bytes, 2)?);
    // Trust the header only as far as the captured bytes go: a snaplen-truncated
    // packet has a total_len larger than what is present.
    let end = total_len.clamp(ihl, bytes.len());
    Some(IpHeader {
        src: IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
        dst: IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])),
        protocol: bytes[9],
        payload: bytes.get(ihl..end)?,
    })
}

/// Parses an IPv6 header.
///
/// Extension headers are not walked: mDNS and the other passive protocols never
/// use them, and skipping an unknown chain is how parsers get confused.
#[must_use]
pub fn parse_ipv6(bytes: &[u8]) -> Option<IpHeader<'_>> {
    if bytes.len() < 40 {
        return None;
    }
    if bytes[0] >> 4 != 6 {
        return None;
    }
    let payload_len = usize::from(read_u16(bytes, 4)?);
    let end = (40 + payload_len).clamp(40, bytes.len());
    let src: [u8; 16] = bytes[8..24].try_into().ok()?;
    let dst: [u8; 16] = bytes[24..40].try_into().ok()?;
    Some(IpHeader {
        src: IpAddr::V6(Ipv6Addr::from(src)),
        dst: IpAddr::V6(Ipv6Addr::from(dst)),
        protocol: bytes[6],
        payload: bytes.get(40..end)?,
    })
}

/// A parsed UDP datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Datagram body.
    pub payload: &'a [u8],
}

/// Parses a UDP header and returns the body.
#[must_use]
pub fn parse_udp(bytes: &[u8]) -> Option<UdpDatagram<'_>> {
    if bytes.len() < 8 {
        return None;
    }
    let length = usize::from(read_u16(bytes, 4)?);
    let end = length.clamp(8, bytes.len());
    Some(UdpDatagram {
        src_port: read_u16(bytes, 0)?,
        dst_port: read_u16(bytes, 2)?,
        payload: bytes.get(8..end)?,
    })
}

/// Reads a big-endian `u16` at `offset`, or `None` if it does not fit.
#[must_use]
fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let hi = *bytes.get(offset)?;
    let lo = *bytes.get(offset + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// dst ff:ff:.., src 3c:22:fb:01:02:03, EtherType ARP, then two payload
    /// bytes.
    const PLAIN: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3c, 0x22, 0xfb, 0x01, 0x02, 0x03, 0x08, 0x06, 0xaa,
        0xbb,
    ];

    #[test]
    fn parses_a_plain_frame() {
        let f = parse_ethernet(PLAIN).expect("frame");
        assert_eq!(f.dst, MacAddr::BROADCAST);
        assert_eq!(f.src, "3c:22:fb:01:02:03".parse().expect("mac"));
        assert_eq!(f.ethertype, ETHERTYPE_ARP);
        assert_eq!(f.payload, &[0xaa, 0xbb]);
    }

    #[test]
    fn strips_a_single_vlan_tag() {
        let mut tagged = PLAIN[..12].to_vec();
        tagged.extend_from_slice(&[0x81, 0x00, 0x00, 0x64]); // VLAN 100
        tagged.extend_from_slice(&[0x08, 0x06, 0xaa, 0xbb]);
        let f = parse_ethernet(&tagged).expect("frame");
        assert_eq!(f.ethertype, ETHERTYPE_ARP);
        assert_eq!(f.payload, &[0xaa, 0xbb]);
    }

    #[test]
    fn strips_stacked_vlan_tags() {
        let mut tagged = PLAIN[..12].to_vec();
        tagged.extend_from_slice(&[0x88, 0xa8, 0x00, 0x0a]);
        tagged.extend_from_slice(&[0x81, 0x00, 0x00, 0x64]);
        tagged.extend_from_slice(&[0x08, 0x06, 0xaa, 0xbb]);
        let f = parse_ethernet(&tagged).expect("frame");
        assert_eq!(f.ethertype, ETHERTYPE_ARP);
        assert_eq!(f.payload, &[0xaa, 0xbb]);
    }

    #[test]
    fn truncated_frames_do_not_panic() {
        for n in 0..14 {
            assert!(parse_ethernet(&PLAIN[..n]).is_none(), "len {n}");
        }
        // A frame that claims a VLAN tag but is cut off inside it.
        let mut tagged = PLAIN[..12].to_vec();
        tagged.extend_from_slice(&[0x81, 0x00, 0x00]);
        assert!(parse_ethernet(&tagged).is_none());
    }

    #[test]
    fn ipv4_header_respects_ihl_and_total_length() {
        // IHL 6 (24 bytes) with 4 bytes of options, total length 28.
        let mut pkt = vec![
            0x46,
            0x00,
            0x00,
            0x1c,
            0x00,
            0x00,
            0x00,
            0x00,
            0x40,
            IPPROTO_UDP,
            0x00,
            0x00,
            192,
            168,
            1,
            40,
            224,
            0,
            0,
            251,
        ];
        pkt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // options
        pkt.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // payload
        pkt.extend_from_slice(&[0xff, 0xff]); // trailing padding, must be cut
        let h = parse_ipv4(&pkt).expect("ipv4");
        assert_eq!(h.src, "192.168.1.40".parse::<IpAddr>().expect("ip"));
        assert_eq!(h.dst, "224.0.0.251".parse::<IpAddr>().expect("ip"));
        assert_eq!(h.protocol, IPPROTO_UDP);
        assert_eq!(h.payload, &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn ipv4_rejects_later_fragments_and_wrong_versions() {
        let mut pkt = vec![
            0x45,
            0x00,
            0x00,
            0x1c,
            0x00,
            0x00,
            0x00,
            0x01,
            0x40,
            IPPROTO_UDP,
            0x00,
            0x00,
            192,
            168,
            1,
            40,
            224,
            0,
            0,
            251,
        ];
        pkt.extend_from_slice(&[0u8; 8]);
        assert!(parse_ipv4(&pkt).is_none(), "fragment offset 1");
        pkt[0] = 0x65; // version 6 in an IPv4 slot
        assert!(parse_ipv4(&pkt).is_none());
        assert!(parse_ipv4(&pkt[..19]).is_none(), "short header");
    }

    #[test]
    fn ipv4_tolerates_snaplen_truncation() {
        // total_len says 1500, only 24 bytes captured.
        let pkt = vec![
            0x45,
            0x00,
            0x05,
            0xdc,
            0x00,
            0x00,
            0x00,
            0x00,
            0x40,
            IPPROTO_UDP,
            0x00,
            0x00,
            10,
            0,
            0,
            1,
            10,
            0,
            0,
            2,
            0xaa,
            0xbb,
            0xcc,
            0xdd,
        ];
        let h = parse_ipv4(&pkt).expect("ipv4");
        assert_eq!(h.payload, &[0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn ipv6_header_parses() {
        let mut pkt = vec![0x60, 0, 0, 0, 0x00, 0x04, IPPROTO_UDP, 0x40];
        pkt.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        pkt.extend_from_slice(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb]);
        pkt.extend_from_slice(&[1, 2, 3, 4]);
        let h = parse_ipv6(&pkt).expect("ipv6");
        assert_eq!(h.src, "fe80::1".parse::<IpAddr>().expect("ip"));
        assert_eq!(h.dst, "ff02::fb".parse::<IpAddr>().expect("ip"));
        assert_eq!(h.payload, &[1, 2, 3, 4]);
        assert!(parse_ipv6(&pkt[..39]).is_none());
    }

    #[test]
    fn udp_respects_its_length_field() {
        let pkt = [
            0x14, 0xe9, 0x14, 0xe9, 0x00, 0x0c, 0x00, 0x00, 1, 2, 3, 4, 9, 9,
        ];
        let d = parse_udp(&pkt).expect("udp");
        assert_eq!(d.src_port, 5353);
        assert_eq!(d.dst_port, 5353);
        assert_eq!(d.payload, &[1, 2, 3, 4]);
        assert!(parse_udp(&pkt[..7]).is_none());
    }
}
