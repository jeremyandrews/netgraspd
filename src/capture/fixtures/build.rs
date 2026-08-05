//! Constructors for the milestone 2 fixture frames.
//!
//! The milestone 1 fixtures were assembled by hand and their layouts documented
//! in `tests/fixtures/README.md`. That worked for five ARP frames and three DNS
//! messages. It does not scale to DHCP, where the BOOTP header is 236 bytes
//! before the options start, or to anything carrying a length field that has to
//! agree with the payload.
//!
//! So the milestone 2 frames are built here instead, written to
//! `tests/fixtures/*.bin` by `cargo run --example build-fixtures`, and committed.
//! The committed bytes are what the parsers read; a test in the parent module
//! asserts that each file still equals what this module produces, which is what
//! turns "documented layout" into something a compiler checks.
//!
//! Nothing here is used by the release binary. It is `pub` so that the example
//! and the integration tests can reach it.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::capture::ethernet::{ETHERTYPE_IPV4, ETHERTYPE_IPV6, IPPROTO_UDP};
use crate::capture::nbns::encode_name;
use crate::capture::ndp::IPPROTO_ICMPV6;

/// The phone: an Apple device at `192.168.1.40`.
pub const PHONE: [u8; 6] = [0x3c, 0x22, 0xfb, 0x9a, 0x1b, 0x2c];
/// The gateway and mDNS responder: a Raspberry Pi at `192.168.1.1`.
pub const GATEWAY: [u8; 6] = [0xb8, 0x27, 0xeb, 0x44, 0x55, 0x66];
/// The printer: a Brother device.
pub const PRINTER: [u8; 6] = [0x3c, 0x2a, 0xf4, 0x11, 0x22, 0x33];
/// The NAS: a Synology at `192.168.1.77`.
pub const NAS: [u8; 6] = [0x00, 0x11, 0x32, 0xaa, 0xbb, 0xcc];
/// The television: a Roku at `192.168.1.90`.
pub const TV: [u8; 6] = [0xb0, 0xa7, 0x37, 0x0a, 0x0b, 0x0c];
/// The broadcast address.
pub const BROADCAST: [u8; 6] = [0xff; 6];

/// Every buildable fixture, paired with the file name it is written to.
///
/// The example writes these; the drift test reads them back.
#[must_use]
pub fn all() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("dhcp_discover", dhcp_discover()),
        ("dhcp_offer", dhcp_offer()),
        ("dhcp_ack", dhcp_ack()),
        ("dhcp_request_overloaded", dhcp_request_overloaded()),
        ("ssdp_notify", ssdp_notify()),
        ("ssdp_msearch", ssdp_msearch()),
        ("ssdp_response", ssdp_response()),
        ("ndp_solicitation", ndp_solicitation()),
        ("ndp_advertisement", ndp_advertisement()),
        ("ndp_router_advertisement", ndp_router_advertisement()),
        ("ndp_dad", ndp_dad()),
        ("nbns_registration", nbns_registration()),
        ("nbns_query", nbns_query()),
        ("nbns_datagram", nbns_datagram()),
    ]
}

// ---------------------------------------------------------------- framing ---

/// Wraps a payload in an Ethernet II header, padded to the 60-byte minimum a
/// real NIC emits.
#[must_use]
pub fn ethernet(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&dst);
    frame.extend_from_slice(&src);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame.resize(frame.len().max(60), 0);
    frame
}

/// Wraps a payload in a 20-byte IPv4 header with a correct total length.
///
/// The header checksum is left zero. Netgrasp never verifies it: pcap hands over
/// frames the NIC already checked, and a parser that recomputed checksums would
/// reject every frame from an interface doing checksum offload.
#[must_use]
pub fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut header = Vec::with_capacity(total);
    header.push(0x45); // version 4, IHL 5
    header.push(0x00); // DSCP
    header.extend_from_slice(&u16::try_from(total).unwrap_or(u16::MAX).to_be_bytes());
    header.extend_from_slice(&[0x00, 0x01]); // identification
    header.extend_from_slice(&[0x00, 0x00]); // flags, fragment offset
    header.push(64); // TTL
    header.push(protocol);
    header.extend_from_slice(&[0x00, 0x00]); // checksum
    header.extend_from_slice(&src.octets());
    header.extend_from_slice(&dst.octets());
    header.extend_from_slice(payload);
    header
}

/// Wraps a payload in a 40-byte IPv6 header.
#[must_use]
pub fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload: &[u8]) -> Vec<u8> {
    let mut header = Vec::with_capacity(40 + payload.len());
    header.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // version 6, no traffic class
    header.extend_from_slice(
        &u16::try_from(payload.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    header.push(next_header);
    header.push(255); // hop limit, as Neighbor Discovery requires
    header.extend_from_slice(&src.octets());
    header.extend_from_slice(&dst.octets());
    header.extend_from_slice(payload);
    header
}

/// Wraps a payload in a UDP header with a correct length. Checksum left zero,
/// which is legal for IPv4 and which no parser here reads.
#[must_use]
pub fn udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut header = Vec::with_capacity(8 + payload.len());
    header.extend_from_slice(&src_port.to_be_bytes());
    header.extend_from_slice(&dst_port.to_be_bytes());
    header.extend_from_slice(
        &u16::try_from(8 + payload.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    header.extend_from_slice(&[0x00, 0x00]);
    header.extend_from_slice(payload);
    header
}

// ------------------------------------------------------------------- DHCP ---

/// Builds a BOOTP message with its magic cookie and an option block.
///
/// `file` and `sname` are the two fields option 52 can overload; passing bytes
/// for either is how the overload fixture is built.
fn bootp(
    op: u8,
    chaddr: [u8; 6],
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    options: &[u8],
    file: &[u8],
    sname: &[u8],
) -> Vec<u8> {
    let mut msg = vec![0u8; 240];
    msg[0] = op;
    msg[1] = 1; // htype: Ethernet
    msg[2] = 6; // hlen
    msg[4..8].copy_from_slice(&[0x39, 0x03, 0xf3, 0x26]); // xid
    msg[12..16].copy_from_slice(&ciaddr.octets());
    msg[16..20].copy_from_slice(&yiaddr.octets());
    msg[28..34].copy_from_slice(&chaddr);
    msg[44..44 + sname.len().min(64)].copy_from_slice(&sname[..sname.len().min(64)]);
    msg[108..108 + file.len().min(128)].copy_from_slice(&file[..file.len().min(128)]);
    msg[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    msg.extend_from_slice(options);
    msg
}

/// One DHCP option: code, length, value.
fn option(code: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + value.len());
    out.push(code);
    out.push(u8::try_from(value.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(value);
    out
}

/// A DHCP Discover from the phone, with the fingerprint iOS actually sends.
#[must_use]
pub fn dhcp_discover() -> Vec<u8> {
    let mut options = Vec::new();
    options.extend(option(53, &[1])); // Discover
    options.extend(option(12, b"auroras-ipad"));
    options.extend(option(55, &[1, 121, 3, 6, 15, 119, 252]));
    options.extend(option(60, b"iPhone-iOS17.4"));
    options.push(255);
    let dhcp = bootp(
        1,
        PHONE,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        &options,
        &[],
        &[],
    );
    let datagram = udp(68, 67, &dhcp);
    let packet = ipv4(
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
        IPPROTO_UDP,
        &datagram,
    );
    ethernet(BROADCAST, PHONE, ETHERTYPE_IPV4, &packet)
}

/// The gateway's Offer, carrying the option 3 router the gateway tracker reads.
#[must_use]
pub fn dhcp_offer() -> Vec<u8> {
    let mut options = Vec::new();
    options.extend(option(53, &[2])); // Offer
    options.extend(option(54, &[192, 168, 1, 1])); // server identifier
    options.extend(option(51, &86_400u32.to_be_bytes())); // lease time
    options.extend(option(1, &[255, 255, 255, 0])); // subnet mask
    options.extend(option(3, &[192, 168, 1, 1])); // router
    options.extend(option(6, &[192, 168, 1, 1])); // DNS
    options.push(255);
    let dhcp = bootp(
        2,
        PHONE,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::new(192, 168, 1, 40),
        &options,
        &[],
        &[],
    );
    let datagram = udp(67, 68, &dhcp);
    let packet = ipv4(
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::BROADCAST,
        IPPROTO_UDP,
        &datagram,
    );
    ethernet(BROADCAST, GATEWAY, ETHERTYPE_IPV4, &packet)
}

/// The gateway's Ack. It echoes the client's hostname exactly as a real server
/// does, which is the trap the parser has to not fall into.
#[must_use]
pub fn dhcp_ack() -> Vec<u8> {
    let mut options = Vec::new();
    options.extend(option(53, &[5])); // Ack
    options.extend(option(54, &[192, 168, 1, 1]));
    options.extend(option(51, &86_400u32.to_be_bytes()));
    options.extend(option(12, b"auroras-ipad")); // the client's name, echoed
    options.extend(option(3, &[192, 168, 1, 1]));
    options.push(255);
    let dhcp = bootp(
        2,
        PHONE,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::new(192, 168, 1, 40),
        &options,
        &[],
        &[],
    );
    let datagram = udp(67, 68, &dhcp);
    let packet = ipv4(
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::BROADCAST,
        IPPROTO_UDP,
        &datagram,
    );
    ethernet(BROADCAST, GATEWAY, ETHERTYPE_IPV4, &packet)
}

/// A Request that uses option 52 to put its hostname in the `file` field.
#[must_use]
pub fn dhcp_request_overloaded() -> Vec<u8> {
    let mut options = Vec::new();
    options.extend(option(53, &[3])); // Request
    options.extend(option(52, &[0x01])); // file field holds options
    options.push(255);

    let mut file = Vec::new();
    file.extend(option(12, b"overflow-host"));
    file.push(255);

    let dhcp = bootp(
        1,
        PRINTER,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        &options,
        &file,
        &[],
    );
    let datagram = udp(68, 67, &dhcp);
    let packet = ipv4(
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
        IPPROTO_UDP,
        &datagram,
    );
    ethernet(BROADCAST, PRINTER, ETHERTYPE_IPV4, &packet)
}

// ------------------------------------------------------------------- SSDP ---

/// The SSDP multicast group.
const SSDP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
/// The Ethernet multicast address the SSDP group maps to.
const SSDP_GROUP_MAC: [u8; 6] = [0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa];

/// Wraps an SSDP payload in UDP, IPv4 and Ethernet.
fn ssdp_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    body: &str,
) -> Vec<u8> {
    let datagram = udp(1900, 1900, body.as_bytes());
    let packet = ipv4(src, dst, IPPROTO_UDP, &datagram);
    ethernet(dst_mac, src_mac, ETHERTYPE_IPV4, &packet)
}

/// A `NOTIFY` announcement from the NAS.
#[must_use]
pub fn ssdp_notify() -> Vec<u8> {
    let body = concat!(
        "NOTIFY * HTTP/1.1\r\n",
        "HOST: 239.255.255.250:1900\r\n",
        "CACHE-CONTROL: max-age=1800\r\n",
        "LOCATION: http://192.168.1.77:5000/desc.xml\r\n",
        "NT: urn:schemas-upnp-org:device:MediaServer:1\r\n",
        "NTS: ssdp:alive\r\n",
        "SERVER: Linux/4.19 UPnP/1.0 Synology-DLNA/1.0\r\n",
        "USN: uuid:4c2c2b4e-0000-1000-8000-001132aabbcc::",
        "urn:schemas-upnp-org:device:MediaServer:1\r\n",
        "\r\n"
    );
    ssdp_frame(
        NAS,
        SSDP_GROUP_MAC,
        Ipv4Addr::new(192, 168, 1, 77),
        SSDP_GROUP,
        body,
    )
}

/// An `M-SEARCH` from the phone. Its `ST` is the search, not the searcher.
#[must_use]
pub fn ssdp_msearch() -> Vec<u8> {
    let body = concat!(
        "M-SEARCH * HTTP/1.1\r\n",
        "HOST: 239.255.255.250:1900\r\n",
        "MAN: \"ssdp:discover\"\r\n",
        "MX: 1\r\n",
        "ST: urn:dial-multiscreen-org:service:dial:1\r\n",
        "USER-AGENT: Google Chrome/124.0 Windows\r\n",
        "\r\n"
    );
    ssdp_frame(
        PHONE,
        SSDP_GROUP_MAC,
        Ipv4Addr::new(192, 168, 1, 40),
        SSDP_GROUP,
        body,
    )
}

/// A television's unicast answer, volunteering a base64 friendly name.
///
/// `TGl2aW5nIFJvb20gVFY=` is `Living Room TV`. Reading it costs nothing; the
/// `LOCATION` description it also advertises is never fetched.
#[must_use]
pub fn ssdp_response() -> Vec<u8> {
    let body = concat!(
        "HTTP/1.1 200 OK\r\n",
        "CACHE-CONTROL: max-age=1800\r\n",
        "LOCATION: http://192.168.1.90:8060/dial/dd.xml\r\n",
        "ST: urn:dial-multiscreen-org:service:dial:1\r\n",
        "SERVER: Roku UPnP/1.0 Roku/12.0\r\n",
        "X-friendly-name: TGl2aW5nIFJvb20gVFY=\r\n",
        "USN: uuid:roku:ecp:0a0b0c::urn:dial-multiscreen-org:service:dial:1\r\n",
        "\r\n"
    );
    ssdp_frame(
        TV,
        PHONE,
        Ipv4Addr::new(192, 168, 1, 90),
        Ipv4Addr::new(192, 168, 1, 40),
        body,
    )
}

// -------------------------------------------------------------------- NDP ---

/// One Neighbor Discovery option: type, length in eight-byte units, value.
fn ndp_option(kind: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![kind, 0];
    out.extend_from_slice(value);
    // Pad to a multiple of eight including the two header bytes.
    while out.len() % 8 != 0 {
        out.push(0);
    }
    out[1] = u8::try_from(out.len() / 8).unwrap_or(1);
    out
}

/// The link-layer address option carrying a MAC.
fn link_layer_option(kind: u8, mac: [u8; 6]) -> Vec<u8> {
    ndp_option(kind, &mac)
}

/// A Neighbor Solicitation from the phone asking about `2001:db8::1`.
#[must_use]
pub fn ndp_solicitation() -> Vec<u8> {
    let mut icmp = vec![135, 0, 0, 0]; // type, code, checksum
    icmp.extend_from_slice(&[0, 0, 0, 0]); // reserved
    icmp.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
    icmp.extend(link_layer_option(1, PHONE));
    let packet = ipv6(
        "fe80::3e22:fbff:fe9a:1b2c".parse().expect("valid address"),
        "ff02::1:ff00:1".parse().expect("valid address"),
        IPPROTO_ICMPV6,
        &icmp,
    );
    ethernet(
        [0x33, 0x33, 0xff, 0x00, 0x00, 0x01],
        PHONE,
        ETHERTYPE_IPV6,
        &packet,
    )
}

/// A Neighbor Advertisement from the gateway, advertising `2001:db8::1` as its
/// own while sourced from its link-local address.
#[must_use]
pub fn ndp_advertisement() -> Vec<u8> {
    let mut icmp = vec![136, 0, 0, 0];
    icmp.extend_from_slice(&[0x60, 0, 0, 0]); // solicited + override flags
    icmp.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
    icmp.extend(link_layer_option(2, GATEWAY));
    let packet = ipv6(
        "fe80::ba27:ebff:fe44:5566".parse().expect("valid address"),
        "ff02::1".parse().expect("valid address"),
        IPPROTO_ICMPV6,
        &icmp,
    );
    ethernet(
        [0x33, 0x33, 0x00, 0x00, 0x00, 0x01],
        GATEWAY,
        ETHERTYPE_IPV6,
        &packet,
    )
}

/// A Router Advertisement from the gateway, with a prefix information option.
#[must_use]
pub fn ndp_router_advertisement() -> Vec<u8> {
    let mut icmp = vec![134, 0, 0, 0];
    icmp.push(64); // current hop limit
    icmp.push(0x08); // other-config flag
    icmp.extend_from_slice(&1800u16.to_be_bytes()); // router lifetime
    icmp.extend_from_slice(&0u32.to_be_bytes()); // reachable time
    icmp.extend_from_slice(&0u32.to_be_bytes()); // retransmit timer
    icmp.extend(link_layer_option(1, GATEWAY));
    let mut prefix = vec![64, 0xc0]; // /64, on-link + autonomous
    prefix.extend_from_slice(&2_592_000u32.to_be_bytes()); // valid lifetime
    prefix.extend_from_slice(&604_800u32.to_be_bytes()); // preferred lifetime
    prefix.extend_from_slice(&0u32.to_be_bytes()); // reserved
    prefix.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0).octets());
    icmp.extend(ndp_option(3, &prefix));
    let packet = ipv6(
        "fe80::ba27:ebff:fe44:5566".parse().expect("valid address"),
        "ff02::1".parse().expect("valid address"),
        IPPROTO_ICMPV6,
        &icmp,
    );
    ethernet(
        [0x33, 0x33, 0x00, 0x00, 0x00, 0x01],
        GATEWAY,
        ETHERTYPE_IPV6,
        &packet,
    )
}

/// A Duplicate Address Detection solicitation from the printer.
///
/// Sourced from `::` and carrying no source link-layer option, exactly as RFC
/// 4862 requires: the sender has no address to advertise yet.
#[must_use]
pub fn ndp_dad() -> Vec<u8> {
    let mut icmp = vec![135, 0, 0, 0];
    icmp.extend_from_slice(&[0, 0, 0, 0]);
    icmp.extend_from_slice(
        &"fe80::3e2a:f4ff:fe11:2233"
            .parse::<Ipv6Addr>()
            .expect("valid address")
            .octets(),
    );
    let packet = ipv6(
        Ipv6Addr::UNSPECIFIED,
        "ff02::1:ff11:2233".parse().expect("valid address"),
        IPPROTO_ICMPV6,
        &icmp,
    );
    ethernet(
        [0x33, 0x33, 0xff, 0x11, 0x22, 0x33],
        PRINTER,
        ETHERTYPE_IPV6,
        &packet,
    )
}

// ---------------------------------------------------------------- NetBIOS ---

/// The subnet broadcast address the NetBIOS fixtures use.
const LAN_BROADCAST: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 255);

/// Builds a Name Service header.
fn nbns_header(flags: u16, qdcount: u16, ancount: u16, arcount: u16) -> Vec<u8> {
    let mut header = Vec::with_capacity(12);
    header.extend_from_slice(&[0x9a, 0x3f]); // transaction id
    header.extend_from_slice(&flags.to_be_bytes());
    header.extend_from_slice(&qdcount.to_be_bytes());
    header.extend_from_slice(&ancount.to_be_bytes());
    header.extend_from_slice(&0u16.to_be_bytes()); // authority
    header.extend_from_slice(&arcount.to_be_bytes());
    header
}

/// A NetBIOS name registration: the NAS claiming `JEREMY-PC`.
///
/// Flags `0x2910` are opcode 5 (registration) with recursion desired and the
/// broadcast bit set, which is what a Windows machine puts on the wire.
#[must_use]
pub fn nbns_registration() -> Vec<u8> {
    let mut body = nbns_header(0x2910, 1, 0, 1);
    body.extend(encode_name("JEREMY-PC", 0x00));
    body.extend_from_slice(&[0x00, 0x20]); // type NB
    body.extend_from_slice(&[0x00, 0x01]); // class IN
    // Additional record: a pointer back to the question name, then the address.
    body.extend_from_slice(&[0xc0, 0x0c]);
    body.extend_from_slice(&[0x00, 0x20, 0x00, 0x01]);
    body.extend_from_slice(&300_000u32.to_be_bytes());
    body.extend_from_slice(&6u16.to_be_bytes());
    body.extend_from_slice(&[0x00, 0x00]); // NB flags: unique, B node
    body.extend_from_slice(&[192, 168, 1, 77]);

    let datagram = udp(137, 137, &body);
    let packet = ipv4(
        Ipv4Addr::new(192, 168, 1, 77),
        LAN_BROADCAST,
        IPPROTO_UDP,
        &datagram,
    );
    ethernet(BROADCAST, NAS, ETHERTYPE_IPV4, &packet)
}

/// A NetBIOS name query from the phone, looking for `JEREMY-PC`.
#[must_use]
pub fn nbns_query() -> Vec<u8> {
    let mut body = nbns_header(0x0110, 1, 0, 0);
    body.extend(encode_name("JEREMY-PC", 0x00));
    body.extend_from_slice(&[0x00, 0x20]);
    body.extend_from_slice(&[0x00, 0x01]);

    let datagram = udp(137, 137, &body);
    let packet = ipv4(
        Ipv4Addr::new(192, 168, 1, 40),
        LAN_BROADCAST,
        IPPROTO_UDP,
        &datagram,
    );
    ethernet(BROADCAST, PHONE, ETHERTYPE_IPV4, &packet)
}

/// A browser announcement datagram: `JEREMY-PC` addressing its workgroup.
#[must_use]
pub fn nbns_datagram() -> Vec<u8> {
    let mut body = vec![0x12, 0x02]; // broadcast datagram, first fragment
    body.extend_from_slice(&[0x9a, 0x40]); // datagram id
    body.extend_from_slice(&[192, 168, 1, 77]); // source address
    body.extend_from_slice(&138u16.to_be_bytes()); // source port
    body.extend_from_slice(&0u16.to_be_bytes()); // datagram length, filled below
    body.extend_from_slice(&0u16.to_be_bytes()); // packet offset
    body.extend(encode_name("JEREMY-PC", 0x00));
    body.extend(encode_name("WORKGROUP", 0x1d));
    // A short slice of SMB mailslot data, so the frame looks like the real thing
    // rather than stopping dead after the names.
    body.extend_from_slice(b"\xffSMB\x25\x00\x00\x00\x00");
    let length = u16::try_from(body.len() - 14).unwrap_or(0);
    body[10..12].copy_from_slice(&length.to_be_bytes());

    let datagram = udp(138, 138, &body);
    let packet = ipv4(
        Ipv4Addr::new(192, 168, 1, 77),
        LAN_BROADCAST,
        IPPROTO_UDP,
        &datagram,
    );
    ethernet(BROADCAST, NAS, ETHERTYPE_IPV4, &packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_built_frame_is_a_plausible_ethernet_frame() {
        for (name, bytes) in all() {
            assert!(
                bytes.len() >= 60,
                "{name} is {} bytes, shorter than a real Ethernet frame",
                bytes.len()
            );
            assert!(bytes.len() <= 1514, "{name} exceeds the Ethernet MTU");
        }
    }

    #[test]
    fn the_ipv4_total_length_agrees_with_the_payload() {
        let packet = ipv4(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            IPPROTO_UDP,
            &[1, 2, 3, 4],
        );
        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 24);
        assert_eq!(packet.len(), 24);
    }

    #[test]
    fn the_udp_length_includes_its_own_header() {
        let datagram = udp(68, 67, &[1, 2, 3, 4]);
        assert_eq!(u16::from_be_bytes([datagram[4], datagram[5]]), 12);
    }

    #[test]
    fn ndp_options_are_padded_to_eight_byte_units() {
        let option = link_layer_option(1, PHONE);
        assert_eq!(option.len(), 8);
        assert_eq!(option[1], 1, "length is counted in eight-byte units");
        let long = ndp_option(3, &[0u8; 30]);
        assert_eq!(long.len(), 32);
        assert_eq!(long[1], 4);
    }

    #[test]
    fn the_committed_fixtures_match_the_builders() {
        // The committed .bin files are what the parsers read. If a builder
        // changes and the files are not regenerated, every parser test is still
        // green while testing the old bytes, which is the exact failure this
        // catches. Fix by running `cargo run --example build-fixtures`.
        for (name, built) in all() {
            let committed = super::super::all()
                .into_iter()
                .find(|(n, _)| *n == name)
                .map(|(_, bytes)| bytes)
                .unwrap_or_else(|| panic!("{name} is built but not committed"));
            assert_eq!(
                committed, built,
                "tests/fixtures/{name}.bin is stale; run cargo run --example build-fixtures"
            );
        }
    }

    #[test]
    fn the_fixture_macs_are_the_ones_the_readme_documents() {
        for (mac, expected) in [
            (PHONE, "Apple, Inc."),
            (GATEWAY, "Raspberry Pi Foundation"),
            (PRINTER, "Brother Industries, LTD."),
            (NAS, "Synology Incorporated"),
            (TV, "Roku, Inc."),
        ] {
            let mac = crate::types::MacAddr(mac);
            assert_eq!(crate::identity::oui::lookup(mac), Some(expected), "{mac}");
        }
    }
}
