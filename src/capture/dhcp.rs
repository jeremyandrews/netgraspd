//! DHCP capture source.
//!
//! DHCP is the richest passive identity source on a LAN. A single Discover
//! carries the hostname the owner typed into the device, the vendor class its
//! firmware advertises, and the option 55 parameter request list, which is the
//! closest thing to an operating-system fingerprint that exists without sending
//! a packet.
//!
//! Written by hand rather than delegated to a crate. Every Rust DHCP library is
//! built to *be* a client or a server, so it wants to bind port 68, allocate
//! leases, and answer. Netgrasp only reads, and the wire format is two hundred
//! lines.
//!
//! ## Which device a message is about
//!
//! A DHCP conversation has two participants and the naive reading attributes
//! both halves to whoever transmitted.
//!
//! - **Client messages** (Discover, Request, Decline, Release, Inform) carry the
//!   client's own identity. The device is `chaddr`, the client hardware address
//!   in the BOOTP header, which is the client even when a relay forwarded the
//!   packet. Hostname, fingerprint and vendor class attach here.
//! - **Server messages** (Offer, Ack, Nak) are transmitted by the server *about*
//!   a client. The device is the Ethernet source, and no identity signal is
//!   taken from them at all: the hostname in an Ack echoes the client's, and
//!   attributing it to the server would name the router after the laptop.
//!
//! The client MAC, the assigned address and the option 3 router survive in
//! [`DhcpDetail`] for the rogue-server analyzer and the gateway tracker.
//!
//! ## Option overload
//!
//! RFC 2132 option 52 lets a server spill the option block into the otherwise
//! unused `sname` and `file` fields. It is rare and it is trivial to support, and
//! a parser that ignores it silently loses every option after the overflow.

use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, Utc};

use crate::capture::ethernet::{
    ETHERTYPE_IPV4, IPPROTO_UDP, parse_ethernet, parse_ipv4, parse_udp,
};
use crate::capture::names::{clean_name, clean_value, text};
use crate::types::{
    DhcpDetail, DhcpMessageType, MacAddr, Observation, ObservationKind, ProtocolDetail, Signal,
    SignalKind,
};

/// Short name of this source, stored on every observation it produces.
pub const SOURCE: &str = "dhcp";

/// BPF filter narrowing the capture to DHCP.
pub const FILTER: &str = "udp port 67 or udp port 68";

/// The server port.
const SERVER_PORT: u16 = 67;
/// The client port.
const CLIENT_PORT: u16 = 68;

/// Offset of the fixed BOOTP header's end, where the magic cookie begins.
const MAGIC_OFFSET: usize = 236;
/// The DHCP magic cookie that distinguishes DHCP from plain BOOTP.
const MAGIC: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// Option code: subnet router list. The first entry is the default gateway.
const OPT_ROUTER: u8 = 3;
/// Option code: host name.
const OPT_HOSTNAME: u8 = 12;
/// Option code: option overload, marking `file` and `sname` as option space.
const OPT_OVERLOAD: u8 = 52;
/// Option code: DHCP message type.
const OPT_MESSAGE_TYPE: u8 = 53;
/// Option code: parameter request list, the fingerprint.
const OPT_PARAM_LIST: u8 = 55;
/// Option code: vendor class identifier.
const OPT_VENDOR_CLASS: u8 = 60;
/// Option code: padding, one byte with no length.
const OPT_PAD: u8 = 0;
/// Option code: end of options.
const OPT_END: u8 = 255;

/// Longest option 55 list Netgrasp will record. Real lists are under thirty
/// entries; a longer one is a device being strange and would only bloat the
/// signal value.
const MAX_PARAM_LIST: usize = 64;

/// Parses one captured frame into an observation.
///
/// Returns `None` for anything that is not a well-formed DHCP message over
/// IPv4/UDP, and for messages whose device MAC cannot identify a device.
#[must_use]
pub fn parse_frame(
    bytes: &[u8],
    interface: &str,
    observed_at: DateTime<Utc>,
) -> Option<Observation> {
    let frame = parse_ethernet(bytes)?;
    if frame.ethertype != ETHERTYPE_IPV4 {
        return None;
    }
    let ip = parse_ipv4(frame.payload)?;
    if ip.protocol != IPPROTO_UDP {
        return None;
    }
    let udp = parse_udp(ip.payload)?;
    let ports = [udp.src_port, udp.dst_port];
    if !ports.contains(&SERVER_PORT) && !ports.contains(&CLIENT_PORT) {
        return None;
    }
    if frame.src.is_group() || frame.src.is_zero() {
        return None;
    }

    let message = parse_message(udp.payload)?;
    build(&message, frame.src, ip.src, interface, observed_at)
}

/// The parts of a DHCP message Netgrasp reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpMessage {
    /// Option 53 message type. A message without one is BOOTP, not DHCP.
    pub message_type: DhcpMessageType,
    /// Client hardware address from the BOOTP header, when it is a usable
    /// Ethernet MAC.
    pub client_mac: Option<MacAddr>,
    /// `ciaddr`: the address the client already holds, when it holds one.
    pub client_ip: Option<Ipv4Addr>,
    /// `yiaddr`: the address the server is assigning.
    pub assigned_ip: Option<Ipv4Addr>,
    /// Option 12 host name, cleaned.
    pub hostname: Option<String>,
    /// Option 55 parameter request list, rendered as comma-separated decimals.
    pub fingerprint: Option<String>,
    /// Option 60 vendor class identifier, cleaned.
    pub vendor_class: Option<String>,
    /// First address in option 3, the default gateway being handed out.
    pub router: Option<Ipv4Addr>,
}

/// Parses the BOOTP header and the DHCP option block.
///
/// Returns `None` when the header is truncated, the magic cookie is absent
/// (plain BOOTP, which carries none of the fields wanted here), or option 53 is
/// missing.
#[must_use]
pub fn parse_message(buf: &[u8]) -> Option<DhcpMessage> {
    if buf.len() < MAGIC_OFFSET + 4 {
        return None;
    }
    if buf[MAGIC_OFFSET..MAGIC_OFFSET + 4] != MAGIC {
        return None;
    }

    let htype = buf[1];
    let hlen = buf[2];
    let client_mac = if htype == 1 && hlen == 6 {
        buf[28..34]
            .try_into()
            .ok()
            .map(MacAddr)
            .filter(|m: &MacAddr| !m.is_zero() && !m.is_group())
    } else {
        None
    };
    let client_ip = address(&buf[12..16]);
    let assigned_ip = address(&buf[16..20]);

    let mut options = Options::default();
    options.walk(&buf[MAGIC_OFFSET + 4..]);
    // Option overload means the server put more options in the fields normally
    // holding a boot file name and a server name. RFC 2132 reads file first.
    if options.overload & 0x01 != 0 {
        options.walk(&buf[108..236]);
    }
    if options.overload & 0x02 != 0 {
        options.walk(&buf[44..108]);
    }

    Some(DhcpMessage {
        message_type: options.message_type?,
        client_mac,
        client_ip,
        assigned_ip,
        hostname: options.hostname,
        fingerprint: options.fingerprint,
        vendor_class: options.vendor_class,
        router: options.router,
    })
}

/// Accumulates the options Netgrasp reads while walking the option block.
#[derive(Debug, Default)]
struct Options {
    message_type: Option<DhcpMessageType>,
    hostname: Option<String>,
    fingerprint: Option<String>,
    vendor_class: Option<String>,
    router: Option<Ipv4Addr>,
    overload: u8,
}

impl Options {
    /// Walks one option block, filling in whatever it finds.
    ///
    /// A field already set is not overwritten: with option overload the same
    /// code can legally appear twice, and the primary block is the authoritative
    /// one.
    fn walk(&mut self, block: &[u8]) {
        let mut i = 0usize;
        while i < block.len() {
            let code = block[i];
            if code == OPT_PAD {
                i += 1;
                continue;
            }
            if code == OPT_END {
                return;
            }
            let Some(len) = block.get(i + 1).map(|l| usize::from(*l)) else {
                return;
            };
            let start = i + 2;
            let Some(value) = block.get(start..start + len) else {
                // A length running past the block is a truncated capture or a
                // malformed packet; either way there is nothing after it worth
                // guessing at.
                return;
            };
            self.absorb(code, value);
            i = start + len;
        }
    }

    /// Records one option value.
    fn absorb(&mut self, code: u8, value: &[u8]) {
        match code {
            OPT_MESSAGE_TYPE => {
                if self.message_type.is_none()
                    && let Some(first) = value.first()
                {
                    self.message_type = DhcpMessageType::from_code(*first);
                }
            }
            OPT_HOSTNAME => {
                if self.hostname.is_none() {
                    self.hostname = clean_name(&text(value));
                }
            }
            OPT_PARAM_LIST => {
                if self.fingerprint.is_none() {
                    self.fingerprint = render_param_list(value);
                }
            }
            OPT_VENDOR_CLASS => {
                if self.vendor_class.is_none() {
                    self.vendor_class = clean_value(&text(value));
                }
            }
            OPT_ROUTER => {
                if self.router.is_none() {
                    self.router = address(value.get(..4).unwrap_or_default());
                }
            }
            OPT_OVERLOAD => {
                if let Some(first) = value.first() {
                    self.overload |= *first;
                }
            }
            _ => {}
        }
    }
}

/// Renders an option 55 parameter request list as comma-separated decimals.
///
/// **The order is preserved.** Two operating systems routinely ask for the same
/// set of options in a different order, and that order is most of what makes the
/// fingerprint discriminating; sorting it would throw the signal away.
#[must_use]
pub fn render_param_list(value: &[u8]) -> Option<String> {
    if value.is_empty() || value.len() > MAX_PARAM_LIST {
        return None;
    }
    let mut out = String::with_capacity(value.len() * 4);
    for (i, code) in value.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        // Infallible: writing a u8 into a String cannot fail.
        use std::fmt::Write as _;
        let _ = write!(out, "{code}");
    }
    Some(out)
}

/// Reads four bytes as an IPv4 address, rejecting the addresses that are really
/// "this field is unused".
///
/// `0.0.0.0` fills every BOOTP address field a message is not using, so treating
/// it as an address would record every Discover as owning it.
fn address(bytes: &[u8]) -> Option<Ipv4Addr> {
    let octets: [u8; 4] = bytes.try_into().ok()?;
    let addr = Ipv4Addr::from(octets);
    (!addr.is_unspecified() && !addr.is_broadcast() && !addr.is_multicast()).then_some(addr)
}

/// Turns a parsed message into an observation about the right device.
fn build(
    message: &DhcpMessage,
    frame_src: MacAddr,
    ip_src: IpAddr,
    interface: &str,
    observed_at: DateTime<Utc>,
) -> Option<Observation> {
    let server_message = message.message_type.is_server_message();

    // Whose message is this? See the module documentation.
    let mac = if server_message {
        frame_src
    } else {
        message.client_mac.unwrap_or(frame_src)
    };
    if mac.is_group() || mac.is_zero() {
        return None;
    }

    let ip = if server_message {
        // The server's own address, from the IP header. A server answering a
        // Discover sources from its real address even though the datagram is
        // broadcast at layer two.
        match ip_src {
            IpAddr::V4(v4) if !v4.is_unspecified() && !v4.is_broadcast() => Some(ip_src),
            _ => None,
        }
    } else {
        message.client_ip.map(IpAddr::V4)
    };

    let kind = match message.message_type {
        DhcpMessageType::Discover | DhcpMessageType::Request | DhcpMessageType::Inform => {
            ObservationKind::Query
        }
        DhcpMessageType::Offer | DhcpMessageType::Ack | DhcpMessageType::Nak => {
            ObservationKind::Reply
        }
        DhcpMessageType::Decline | DhcpMessageType::Release => ObservationKind::Announcement,
    };

    let mut observation = Observation::new(mac, ip, interface, SOURCE, kind, observed_at)
        .with_detail(ProtocolDetail::Dhcp(DhcpDetail {
            message_type: message.message_type,
            client_mac: message.client_mac,
            assigned_ip: message.assigned_ip,
            router: message.router,
        }));

    // Identity evidence belongs to the client and only the client.
    if !server_message {
        if let Some(hostname) = &message.hostname {
            observation = observation.with_signal(Signal::new(SignalKind::DhcpHostname, hostname));
        }
        if let Some(fingerprint) = &message.fingerprint {
            observation =
                observation.with_signal(Signal::new(SignalKind::DhcpFingerprint, fingerprint));
        }
        if let Some(vendor_class) = &message.vendor_class {
            observation =
                observation.with_signal(Signal::new(SignalKind::DhcpVendorClass, vendor_class));
        }
    }
    Some(observation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::fixtures;

    /// Offset of the DHCP payload inside the fixture frames: Ethernet, then a
    /// 20-byte IPv4 header, then UDP.
    const PAYLOAD: usize = 14 + 20 + 8;

    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::timestamp_opt(&Utc, 1_770_000_000, 0)
            .single()
            .expect("valid timestamp")
    }

    fn signal(obs: &Observation, kind: SignalKind) -> Option<&str> {
        obs.signals
            .iter()
            .find(|s| s.kind == kind)
            .map(|s| s.value.as_str())
    }

    #[test]
    fn parses_a_real_discover_with_its_fingerprint() {
        let obs = parse_frame(&fixtures::dhcp_discover(), "eth0", ts()).expect("parsed");
        assert_eq!(obs.mac, "3c:22:fb:9a:1b:2c".parse().expect("mac"));
        assert_eq!(obs.source, "dhcp");
        assert_eq!(obs.kind, ObservationKind::Query);
        assert_eq!(
            obs.ip, None,
            "a Discover has no ciaddr, and 0.0.0.0 is not an address"
        );
        assert_eq!(signal(&obs, SignalKind::DhcpHostname), Some("auroras-ipad"));
        assert_eq!(
            signal(&obs, SignalKind::DhcpFingerprint),
            Some("1,121,3,6,15,119,252")
        );
        assert_eq!(
            signal(&obs, SignalKind::DhcpVendorClass),
            Some("iPhone-iOS17.4")
        );
        let dhcp = obs.dhcp().expect("dhcp detail");
        assert_eq!(dhcp.message_type, DhcpMessageType::Discover);
        assert_eq!(
            dhcp.client_mac,
            Some("3c:22:fb:9a:1b:2c".parse().expect("mac"))
        );
    }

    #[test]
    fn parses_a_real_offer_and_attributes_it_to_the_server() {
        let obs = parse_frame(&fixtures::dhcp_offer(), "eth0", ts()).expect("parsed");
        assert_eq!(
            obs.mac,
            "b8:27:eb:44:55:66".parse().expect("mac"),
            "an Offer is the server's packet, not the client's"
        );
        assert_eq!(obs.ip, Some("192.168.1.1".parse().expect("ip")));
        assert_eq!(obs.kind, ObservationKind::Reply);
        let dhcp = obs.dhcp().expect("dhcp detail");
        assert_eq!(dhcp.message_type, DhcpMessageType::Offer);
        assert_eq!(
            dhcp.client_mac,
            Some("3c:22:fb:9a:1b:2c".parse().expect("mac")),
            "the client survives in the detail"
        );
        assert_eq!(dhcp.assigned_ip, Some(Ipv4Addr::new(192, 168, 1, 40)));
        assert_eq!(dhcp.router, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn a_server_message_contributes_no_identity_signal() {
        // The Ack fixture echoes the client's hostname, exactly as a real server
        // does. Attributing it would name the router after the tablet.
        let obs = parse_frame(&fixtures::dhcp_ack(), "eth0", ts()).expect("parsed");
        assert!(
            obs.signals.is_empty(),
            "a server message names nobody: {:?}",
            obs.signals
        );
        assert_eq!(obs.mac, "b8:27:eb:44:55:66".parse().expect("mac"));
    }

    #[test]
    fn the_parameter_request_list_keeps_its_order() {
        // Windows and macOS ask for overlapping sets in different orders, and
        // that order is most of the discriminating power.
        assert_eq!(
            render_param_list(&[1, 121, 3, 6, 15]),
            Some("1,121,3,6,15".into())
        );
        assert_eq!(
            render_param_list(&[121, 1, 6, 3, 15]),
            Some("121,1,6,3,15".into()),
            "a different order is a different fingerprint"
        );
        assert_eq!(render_param_list(&[]), None);
        assert_eq!(render_param_list(&[0; MAX_PARAM_LIST + 1]), None);
        assert_eq!(render_param_list(&[255, 0]), Some("255,0".into()));
    }

    #[test]
    fn option_overload_is_followed_into_the_file_field() {
        let bytes = fixtures::dhcp_request_overloaded();
        let obs = parse_frame(&bytes, "eth0", ts()).expect("parsed");
        assert_eq!(
            signal(&obs, SignalKind::DhcpHostname),
            Some("overflow-host"),
            "the hostname lives in the overloaded file field"
        );
        assert_eq!(
            obs.dhcp().expect("detail").message_type,
            DhcpMessageType::Request
        );
    }

    #[test]
    fn plain_bootp_without_the_magic_cookie_is_not_dhcp() {
        let mut bytes = fixtures::dhcp_discover();
        bytes[PAYLOAD + MAGIC_OFFSET] = 0x00;
        assert!(parse_frame(&bytes, "eth0", ts()).is_none());
    }

    #[test]
    fn a_message_without_option_53_is_rejected() {
        let mut bytes = fixtures::dhcp_discover();
        // The fixture's first option is 53 (three bytes); blanking it to pad
        // leaves a walkable but typeless block.
        let opt = PAYLOAD + MAGIC_OFFSET + 4;
        bytes[opt] = OPT_PAD;
        bytes[opt + 1] = OPT_PAD;
        bytes[opt + 2] = OPT_PAD;
        assert!(parse_frame(&bytes, "eth0", ts()).is_none());
    }

    #[test]
    fn non_dhcp_and_malformed_frames_are_rejected() {
        assert!(parse_frame(&fixtures::arp_request(), "eth0", ts()).is_none());
        assert!(parse_frame(&fixtures::mdns_response_ipv4(), "eth0", ts()).is_none());
        assert!(parse_frame(&[], "eth0", ts()).is_none());
    }

    #[test]
    fn truncated_dhcp_frames_do_not_panic() {
        for fixture in [
            fixtures::dhcp_discover(),
            fixtures::dhcp_offer(),
            fixtures::dhcp_ack(),
            fixtures::dhcp_request_overloaded(),
        ] {
            for n in 0..fixture.len() {
                let _ = parse_frame(&fixture[..n], "eth0", ts());
            }
        }
    }

    #[test]
    fn an_option_length_running_past_the_buffer_stops_the_walk() {
        let mut options = Options::default();
        // Code 53, length 200, one byte of value.
        options.walk(&[OPT_MESSAGE_TYPE, 200, 1]);
        assert_eq!(
            options.message_type, None,
            "a length past the end must not be read as a value"
        );
    }

    #[test]
    fn padding_and_end_markers_are_honoured() {
        let mut options = Options::default();
        options.walk(&[
            OPT_PAD,
            OPT_PAD,
            OPT_MESSAGE_TYPE,
            1,
            3,
            OPT_END,
            OPT_HOSTNAME,
            4,
            b'j',
            b'u',
            b'n',
            b'k',
        ]);
        assert_eq!(options.message_type, Some(DhcpMessageType::Request));
        assert_eq!(
            options.hostname, None,
            "nothing after the end marker is read"
        );
    }

    #[test]
    fn a_zero_or_broadcast_address_field_is_not_an_address() {
        assert_eq!(address(&[0, 0, 0, 0]), None);
        assert_eq!(address(&[255, 255, 255, 255]), None);
        assert_eq!(address(&[224, 0, 0, 1]), None);
        assert_eq!(
            address(&[192, 168, 1, 1]),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(address(&[1, 2, 3]), None, "short slice");
    }

    #[test]
    fn a_hostname_that_is_really_an_address_is_not_a_name() {
        let mut options = Options::default();
        options.absorb(OPT_HOSTNAME, b"192-168-1-40");
        assert_eq!(options.hostname, None);
    }
}
