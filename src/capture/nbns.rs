//! NetBIOS capture source.
//!
//! Two protocols share this source because they share a name encoding and a
//! purpose: naming Windows machines.
//!
//! - **UDP 137, the Name Service.** DNS-shaped. A name registration is a machine
//!   claiming a name, and a name query is a machine asking about somebody
//!   else's.
//! - **UDP 138, the Datagram Service.** Its header carries a source name and a
//!   destination name in the clear, which makes a browser announcement the
//!   cheapest workgroup evidence on the network.
//!
//! ## Only a claim is a sighting of a name
//!
//! The same rule that governs ARP governs this. A registration, a refresh, a
//! query *response* and a datagram source name are the sender naming itself. A
//! query *request* names somebody else, and reading it as the sender's name
//! would label every machine after whatever it last looked for.
//!
//! ## The encoding
//!
//! RFC 1001 section 4.1 first-level encoding: each nibble of each byte is added
//! to `'A'`, so sixteen bytes become thirty-two characters of `A` to `P`. The
//! sixteen decoded bytes are fifteen characters of space-padded name plus a
//! one-byte **service suffix** that says what kind of name it is. `0x00` and
//! `0x20` are a machine; `0x1b` through `0x1e` are a workgroup or domain, which
//! is why the suffix decides which signal a name becomes rather than being
//! discarded as trivia.

use chrono::{DateTime, Utc};

use crate::capture::ethernet::{
    ETHERTYPE_IPV4, IPPROTO_UDP, parse_ethernet, parse_ipv4, parse_udp,
};
use crate::capture::names::clean_name;
use crate::types::{Observation, ObservationKind, Signal, SignalKind};

/// Short name of this source, stored on every observation it produces.
pub const SOURCE: &str = "nbns";

/// BPF filter narrowing the capture to the NetBIOS name and datagram services.
pub const FILTER: &str = "udp port 137 or udp port 138";

/// The Name Service port.
const NAME_PORT: u16 = 137;
/// The Datagram Service port.
const DATAGRAM_PORT: u16 = 138;

/// Length of an encoded NetBIOS name on the wire: a length byte, thirty-two
/// encoded characters, and a terminating zero.
const ENCODED_NAME_LEN: usize = 34;
/// Length byte that introduces a first-level encoded name.
const ENCODED_LABEL_LEN: u8 = 32;

/// Offset of the source name in a Datagram Service header.
const DGM_SOURCE_NAME: usize = 14;
/// Offset of the destination name in a Datagram Service header.
const DGM_DEST_NAME: usize = DGM_SOURCE_NAME + ENCODED_NAME_LEN;

/// Datagram Service message types that carry both names.
const DGM_DIRECT_UNIQUE: u8 = 0x10;
/// Direct group datagram.
const DGM_DIRECT_GROUP: u8 = 0x11;
/// Broadcast datagram, which is what a browser announcement is.
const DGM_BROADCAST: u8 = 0x12;

/// Name Service opcode: a query.
const OP_QUERY: u16 = 0;
/// Name Service opcode: a registration, the sender claiming a name.
const OP_REGISTRATION: u16 = 5;
/// Name Service opcode: a refresh, the sender re-claiming a name.
const OP_REFRESH: u16 = 8;
/// An older refresh opcode some stacks still emit.
const OP_REFRESH_ALT: u16 = 9;

/// The magic browser name that means "every master browser", never a device.
const MSBROWSE: &str = "\u{1}\u{2}__MSBROWSE__\u{2}";

/// What a decoded NetBIOS name refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameScope {
    /// A single machine: suffix `0x00` (workstation), `0x03` (messenger) or
    /// `0x20` (file server).
    Machine,
    /// A workgroup or domain: suffix `0x1b` through `0x1e`.
    Workgroup,
    /// A suffix Netgrasp does not interpret.
    Other,
}

/// A decoded NetBIOS name and its service suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetbiosName {
    /// The name with its padding removed.
    pub name: String,
    /// The service suffix, the sixteenth decoded byte.
    pub suffix: u8,
}

impl NetbiosName {
    /// What this name refers to, from its suffix.
    #[must_use]
    pub const fn scope(&self) -> NameScope {
        match self.suffix {
            0x00 | 0x03 | 0x20 => NameScope::Machine,
            0x1b..=0x1e => NameScope::Workgroup,
            _ => NameScope::Other,
        }
    }
}

/// Parses one captured frame into an observation.
///
/// Returns `None` when the frame is not NetBIOS over UDP, when the source MAC
/// cannot identify a device, or when nothing readable is in the payload.
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
    if frame.src.is_group() || frame.src.is_zero() {
        return None;
    }

    let (kind, names) = match (udp.src_port, udp.dst_port) {
        (NAME_PORT, _) | (_, NAME_PORT) => parse_name_service(udp.payload)?,
        (DATAGRAM_PORT, _) | (_, DATAGRAM_PORT) => parse_datagram_service(udp.payload)?,
        _ => return None,
    };

    let mut observation = Observation::new(
        frame.src,
        Some(ip.src),
        interface,
        SOURCE,
        kind,
        observed_at,
    );
    for name in names {
        let signal_kind = match name.scope() {
            NameScope::Machine => SignalKind::NetbiosName,
            NameScope::Workgroup => SignalKind::NetbiosWorkgroup,
            // A suffix Netgrasp does not interpret is not worth guessing at.
            NameScope::Other => continue,
        };
        if let Some(clean) = clean_name(&name.name) {
            observation = observation.with_signal(Signal::new(signal_kind, clean));
        }
    }
    Some(observation)
}

/// Parses a Name Service message, returning the names the **sender** claimed.
///
/// A query request claims nothing, so it yields presence and no names.
#[must_use]
pub fn parse_name_service(buf: &[u8]) -> Option<(ObservationKind, Vec<NetbiosName>)> {
    if buf.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let is_response = flags & 0x8000 != 0;
    let opcode = (flags >> 11) & 0x0f;
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);

    // The name is the first question when there is one, otherwise the first
    // answer's owner name. Both start at offset 12.
    if qdcount == 0 && ancount == 0 {
        return None;
    }
    let name = decode_name_at(buf, 12)?;

    let claims_the_name = match opcode {
        OP_REGISTRATION | OP_REFRESH | OP_REFRESH_ALT => true,
        // A positive query response is the responder saying "that is me".
        OP_QUERY => is_response,
        _ => false,
    };

    let kind = match (opcode, is_response) {
        (_, true) => ObservationKind::Reply,
        (OP_QUERY, false) => ObservationKind::Query,
        (_, false) => ObservationKind::Announcement,
    };

    let names = if claims_the_name && name.name != MSBROWSE {
        vec![name]
    } else {
        Vec::new()
    };
    Some((kind, names))
}

/// Parses a Datagram Service header, returning the sender's name and the name it
/// addressed.
///
/// The destination of a browser announcement is the workgroup, which is the one
/// place a workgroup name appears without having to parse SMB.
#[must_use]
pub fn parse_datagram_service(buf: &[u8]) -> Option<(ObservationKind, Vec<NetbiosName>)> {
    let msg_type = *buf.first()?;
    if !matches!(
        msg_type,
        DGM_DIRECT_UNIQUE | DGM_DIRECT_GROUP | DGM_BROADCAST
    ) {
        // Datagram error, query and positive/negative response messages carry no
        // names at all.
        return None;
    }
    if buf.len() < DGM_DEST_NAME + ENCODED_NAME_LEN {
        return None;
    }

    let mut names = Vec::with_capacity(2);
    if let Some(source) = decode_name_at(buf, DGM_SOURCE_NAME)
        && source.name != MSBROWSE
    {
        names.push(source);
    }
    if let Some(dest) = decode_name_at(buf, DGM_DEST_NAME)
        && dest.scope() == NameScope::Workgroup
        && dest.name != MSBROWSE
    {
        names.push(dest);
    }
    if names.is_empty() {
        return None;
    }
    Some((ObservationKind::Announcement, names))
}

/// Decodes a first-level encoded NetBIOS name at an offset.
///
/// Returns `None` when the length byte is not 32, when a character is outside
/// the `A` to `P` alphabet the encoding produces, or when the decoded name is
/// empty after its padding is stripped.
#[must_use]
pub fn decode_name_at(buf: &[u8], offset: usize) -> Option<NetbiosName> {
    if *buf.get(offset)? != ENCODED_LABEL_LEN {
        return None;
    }
    let encoded = buf.get(offset + 1..offset + 1 + 32)?;
    let mut decoded = [0u8; 16];
    for (i, pair) in encoded.chunks_exact(2).enumerate() {
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        decoded[i] = (hi << 4) | lo;
    }
    // Fifteen characters of space-padded name, then the service suffix.
    let name = String::from_utf8_lossy(&decoded[..15])
        .trim_end()
        .to_string();
    if name.is_empty() {
        return None;
    }
    Some(NetbiosName {
        name,
        suffix: decoded[15],
    })
}

/// Decodes one encoded character back to its nibble.
const fn nibble(c: u8) -> Option<u8> {
    if c.is_ascii_uppercase() && c <= b'P' {
        Some(c - b'A')
    } else {
        None
    }
}

/// Encodes a name and suffix the way a NetBIOS stack does.
///
/// Lives here rather than in the fixtures so that the encoder and the decoder
/// sit next to each other and a round-trip test can hold them to account.
#[must_use]
pub fn encode_name(name: &str, suffix: u8) -> Vec<u8> {
    let mut raw = [b' '; 16];
    for (slot, byte) in raw.iter_mut().zip(name.bytes()).take(15) {
        *slot = byte;
    }
    raw[15] = suffix;
    let mut out = Vec::with_capacity(ENCODED_NAME_LEN);
    out.push(ENCODED_LABEL_LEN);
    for byte in raw {
        out.push(b'A' + (byte >> 4));
        out.push(b'A' + (byte & 0x0f));
    }
    out.push(0);
    out
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

    fn signal(obs: &Observation, kind: SignalKind) -> Option<&str> {
        obs.signals
            .iter()
            .find(|s| s.kind == kind)
            .map(|s| s.value.as_str())
    }

    #[test]
    fn parses_a_real_name_registration() {
        let obs = parse_frame(&fixtures::nbns_registration(), "eth0", ts()).expect("parsed");
        assert_eq!(obs.mac, "00:11:32:aa:bb:cc".parse().expect("mac"));
        assert_eq!(obs.ip, Some("192.168.1.77".parse().expect("ip")));
        assert_eq!(obs.kind, ObservationKind::Announcement);
        assert_eq!(obs.source, "nbns");
        assert_eq!(signal(&obs, SignalKind::NetbiosName), Some("JEREMY-PC"));
    }

    #[test]
    fn a_query_names_what_it_is_looking_for_not_who_is_asking() {
        let obs = parse_frame(&fixtures::nbns_query(), "eth0", ts()).expect("parsed");
        assert_eq!(obs.kind, ObservationKind::Query);
        assert!(
            obs.signals.is_empty(),
            "a query request claims nothing: {:?}",
            obs.signals
        );
    }

    #[test]
    fn a_browser_datagram_yields_both_the_machine_and_its_workgroup() {
        let obs = parse_frame(&fixtures::nbns_datagram(), "eth0", ts()).expect("parsed");
        assert_eq!(obs.kind, ObservationKind::Announcement);
        assert_eq!(signal(&obs, SignalKind::NetbiosName), Some("JEREMY-PC"));
        assert_eq!(
            signal(&obs, SignalKind::NetbiosWorkgroup),
            Some("WORKGROUP")
        );
    }

    #[test]
    fn the_suffix_decides_whether_a_name_is_a_machine_or_a_workgroup() {
        for suffix in [0x00, 0x03, 0x20] {
            assert_eq!(
                NetbiosName {
                    name: "X".into(),
                    suffix
                }
                .scope(),
                NameScope::Machine,
                "suffix {suffix:#04x}"
            );
        }
        for suffix in [0x1b, 0x1c, 0x1d, 0x1e] {
            assert_eq!(
                NetbiosName {
                    name: "X".into(),
                    suffix
                }
                .scope(),
                NameScope::Workgroup,
                "suffix {suffix:#04x}"
            );
        }
        assert_eq!(
            NetbiosName {
                name: "X".into(),
                suffix: 0x06
            }
            .scope(),
            NameScope::Other
        );
    }

    #[test]
    fn the_encoding_round_trips_including_the_suffix() {
        let encoded = encode_name("JEREMY-PC", 0x20);
        assert_eq!(encoded.len(), ENCODED_NAME_LEN);
        let decoded = decode_name_at(&encoded, 0).expect("decodes");
        assert_eq!(decoded.name, "JEREMY-PC");
        assert_eq!(decoded.suffix, 0x20);

        // Fifteen characters is the maximum a NetBIOS name can hold.
        let long = encode_name("ABCDEFGHIJKLMNOPQRSTUV", 0x00);
        assert_eq!(
            decode_name_at(&long, 0).expect("decodes").name,
            "ABCDEFGHIJKLMNO"
        );
    }

    #[test]
    fn a_name_outside_the_encoding_alphabet_is_refused() {
        let mut encoded = encode_name("JEREMY-PC", 0x00);
        encoded[1] = b'Z'; // beyond 'P', so not a nibble
        assert_eq!(decode_name_at(&encoded, 0), None);
        encoded[1] = b'a';
        assert_eq!(decode_name_at(&encoded, 0), None);
    }

    #[test]
    fn a_wrong_length_byte_is_refused() {
        let mut encoded = encode_name("JEREMY-PC", 0x00);
        encoded[0] = 16;
        assert_eq!(decode_name_at(&encoded, 0), None);
    }

    #[test]
    fn an_all_padding_name_is_not_a_name() {
        let encoded = encode_name("", 0x00);
        assert_eq!(decode_name_at(&encoded, 0), None);
    }

    #[test]
    fn the_msbrowse_magic_name_is_never_a_device() {
        let mut buf = vec![DGM_BROADCAST, 0x02, 0x00, 0x01];
        buf.extend_from_slice(&[192, 168, 1, 77, 0x00, 0x8a, 0x00, 0x20, 0x00, 0x00]);
        buf.extend_from_slice(&encode_name(MSBROWSE, 0x01));
        buf.extend_from_slice(&encode_name("WORKGROUP", 0x1d));
        let (_, names) = parse_datagram_service(&buf).expect("parsed");
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].name, "WORKGROUP");
    }

    #[test]
    fn a_datagram_destined_for_a_machine_yields_no_workgroup() {
        let mut buf = vec![DGM_DIRECT_UNIQUE, 0x02, 0x00, 0x01];
        buf.extend_from_slice(&[192, 168, 1, 77, 0x00, 0x8a, 0x00, 0x20, 0x00, 0x00]);
        buf.extend_from_slice(&encode_name("JEREMY-PC", 0x00));
        buf.extend_from_slice(&encode_name("OTHER-PC", 0x20));
        let (_, names) = parse_datagram_service(&buf).expect("parsed");
        assert_eq!(names.len(), 1, "the destination machine is not a sighting");
        assert_eq!(names[0].name, "JEREMY-PC");
    }

    #[test]
    fn a_datagram_error_message_carries_no_names() {
        assert_eq!(parse_datagram_service(&[0x13, 0, 0, 0]), None);
        assert_eq!(parse_datagram_service(&[]), None);
    }

    #[test]
    fn non_netbios_and_malformed_frames_are_rejected() {
        assert!(parse_frame(&fixtures::arp_request(), "eth0", ts()).is_none());
        assert!(parse_frame(&fixtures::mdns_response_ipv4(), "eth0", ts()).is_none());
        assert!(parse_frame(&[], "eth0", ts()).is_none());
    }

    #[test]
    fn truncated_netbios_frames_do_not_panic() {
        for fixture in [
            fixtures::nbns_registration(),
            fixtures::nbns_query(),
            fixtures::nbns_datagram(),
        ] {
            for n in 0..fixture.len() {
                let _ = parse_frame(&fixture[..n], "eth0", ts());
            }
        }
    }
}
