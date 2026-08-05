//! SSDP capture source.
//!
//! SSDP is HTTP over UDP multicast. Three message shapes matter:
//!
//! - `NOTIFY * HTTP/1.1` with `NTS: ssdp:alive` or `ssdp:byebye`, which a device
//!   emits unprompted. This is the announcement Netgrasp mostly reads.
//! - `M-SEARCH * HTTP/1.1`, which a control point sends looking for services.
//!   The transmitter is a phone or a TV app, and its `ST` says what it *wants*,
//!   never what it *is*.
//! - `HTTP/1.1 200 OK`, a unicast answer to an `M-SEARCH`. Netgrasp sees these
//!   only when they cross a segment it is watching.
//!
//! ## The friendly name, and the fetch that does not happen here
//!
//! The B1 design note flagged this and it survives the implementation: the UPnP
//! `friendlyName` lives in the device description XML at the `LOCATION` URL, and
//! reading it means an HTTP GET **to the monitored device**. Netgrasp does not
//! transmit on the segment it watches, so that fetch does not happen, is not
//! configurable, and must not be added.
//!
//! What is taken instead is a friendly name a device *volunteered in a header*.
//! Chromecast and other DIAL devices send `X-friendly-name` (base64), and some
//! DLNA stacks send `FRIENDLYNAME.DLNA.ORG` in the clear. Those bytes are
//! already on the wire, so reading them costs nothing and stays passive. A
//! device that does not volunteer one simply has no 0.5-weight signal, and the
//! scorer falls through to the next rung as designed.
//!
//! ## Which announcements become signals
//!
//! A UPnP root device announces itself a dozen times, once per service it
//! offers. Only the **device** URNs and `upnp:rootdevice` are recorded, because
//! a service URN says what the device can do rather than what it is, and
//! recording all of them would put a dozen rows per device into
//! `ng_device_signals` to no purpose. `urn:dial-multiscreen-org:service:dial` is
//! the one service URN kept, because in practice it means "television".

use chrono::{DateTime, Utc};

use crate::capture::ethernet::{
    ETHERTYPE_IPV4, ETHERTYPE_IPV6, IPPROTO_UDP, parse_ethernet, parse_ipv4, parse_ipv6, parse_udp,
};
use crate::capture::names::{clean_name, clean_value};
use crate::types::{Observation, ObservationKind, Signal, SignalKind};

/// Short name of this source, stored on every observation it produces.
pub const SOURCE: &str = "ssdp";

/// BPF filter narrowing the capture to SSDP.
pub const FILTER: &str = "udp port 1900";

/// The SSDP port.
const SSDP_PORT: u16 = 1900;

/// The one service URN worth keeping: DIAL means television.
const DIAL_URN: &str = "urn:dial-multiscreen-org:service:dial";

/// What kind of SSDP message a payload is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsdpKind {
    /// A device announcing or withdrawing itself.
    Notify,
    /// A control point searching.
    Search,
    /// A device answering a search.
    Response,
}

/// A parsed SSDP message, reduced to the headers Netgrasp reads.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SsdpMessage {
    /// `NT` on a NOTIFY, `ST` on a response. Absent on an M-SEARCH, whose `ST`
    /// describes the search rather than the searcher.
    pub device_type: Option<String>,
    /// The `SERVER` header on a device message, or `USER-AGENT` on a search.
    /// Both are the software stack naming itself.
    pub server: Option<String>,
    /// A friendly name the device volunteered in a header. Never fetched.
    pub friendly_name: Option<String>,
}

/// Parses one captured frame into an observation.
///
/// Returns `None` when the frame is not SSDP, when the source MAC cannot
/// identify a device, or when the payload is not a recognisable SSDP message.
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
    if udp.dst_port != SSDP_PORT && udp.src_port != SSDP_PORT {
        return None;
    }
    if frame.src.is_group() || frame.src.is_zero() {
        return None;
    }

    let payload = String::from_utf8_lossy(udp.payload);
    let (kind, message) = parse_message(&payload)?;

    let observation_kind = match kind {
        SsdpKind::Notify => ObservationKind::Announcement,
        SsdpKind::Search => ObservationKind::Query,
        SsdpKind::Response => ObservationKind::Reply,
    };

    let mut observation = Observation::new(
        frame.src,
        Some(ip.src),
        interface,
        SOURCE,
        observation_kind,
        observed_at,
    );
    if let Some(name) = message.friendly_name {
        observation = observation.with_signal(Signal::new(SignalKind::SsdpFriendlyName, name));
    }
    if let Some(device_type) = message.device_type {
        observation = observation.with_signal(Signal::new(SignalKind::SsdpDeviceType, device_type));
    }
    if let Some(server) = message.server {
        observation = observation.with_signal(Signal::new(SignalKind::SsdpServer, server));
    }
    Some(observation)
}

/// Parses an SSDP payload into its kind and the headers Netgrasp reads.
///
/// Returns `None` for a payload whose start line is not one of the three SSDP
/// shapes, which is how a stray datagram on port 1900 is rejected.
#[must_use]
pub fn parse_message(payload: &str) -> Option<(SsdpKind, SsdpMessage)> {
    let mut lines = payload.split('\n').map(|l| l.trim_end_matches('\r'));
    let start = lines.next()?.trim();
    let kind = classify_start_line(start)?;

    let mut message = SsdpMessage::default();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match () {
            // A NOTIFY's NT and a response's ST both name the sender. An
            // M-SEARCH's ST names what the sender is looking for.
            () if name.eq_ignore_ascii_case("NT") && kind == SsdpKind::Notify => {
                set_device_type(&mut message, value);
            }
            () if name.eq_ignore_ascii_case("ST") && kind == SsdpKind::Response => {
                set_device_type(&mut message, value);
            }
            () if name.eq_ignore_ascii_case("SERVER") => {
                message.server = message.server.take().or_else(|| clean_value(value));
            }
            () if name.eq_ignore_ascii_case("USER-AGENT") && kind == SsdpKind::Search => {
                message.server = message.server.take().or_else(|| clean_value(value));
            }
            () if name.eq_ignore_ascii_case("X-FRIENDLY-NAME") => {
                // Chromecast and other DIAL devices base64 this. A value that
                // does not decode to text is used as-is rather than discarded.
                let decoded = base64_text(value);
                message.friendly_name = message
                    .friendly_name
                    .take()
                    .or_else(|| clean_name(decoded.as_deref().unwrap_or(value)));
            }
            () if name.eq_ignore_ascii_case("FRIENDLYNAME.DLNA.ORG") => {
                message.friendly_name = message.friendly_name.take().or_else(|| clean_name(value));
            }
            () => {}
        }
    }
    Some((kind, message))
}

/// Reads the message kind from an SSDP start line.
fn classify_start_line(start: &str) -> Option<SsdpKind> {
    let upper = start.to_ascii_uppercase();
    if upper.starts_with("NOTIFY ") {
        Some(SsdpKind::Notify)
    } else if upper.starts_with("M-SEARCH ") {
        Some(SsdpKind::Search)
    } else if upper.starts_with("HTTP/1.") {
        Some(SsdpKind::Response)
    } else {
        None
    }
}

/// Records a device type, keeping only the URNs that say what a device is.
///
/// A `uuid:` value is an instance identifier and names nothing; a service URN
/// says what the device can do. Both are dropped. See the module documentation.
fn set_device_type(message: &mut SsdpMessage, value: &str) {
    if message.device_type.is_some() {
        return;
    }
    let lower = value.to_ascii_lowercase();
    let usable = lower == "upnp:rootdevice"
        || lower.starts_with(DIAL_URN)
        || (lower.starts_with("urn:") && lower.contains(":device:"));
    if usable {
        message.device_type = clean_value(value);
    }
}

/// Decodes standard-alphabet base64 into a string, or `None` when the input is
/// not base64 or does not decode to text.
///
/// Hand-rolled because this is the only base64 in the daemon and the alternative
/// is a dependency for thirty lines.
#[must_use]
pub fn base64_text(input: &str) -> Option<String> {
    /// Decodes one base64 character to its six-bit value.
    const fn sextet(c: u8) -> Option<u8> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }

    let trimmed = input.trim().trim_end_matches('=');
    if trimmed.is_empty() || trimmed.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(trimmed.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for byte in trimmed.bytes() {
        let value = sextet(byte)?;
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            // Infallible: the mask keeps the value inside a u8.
            out.push(u8::try_from((acc >> bits) & 0xff).unwrap_or(0));
        }
    }
    String::from_utf8(out).ok()
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
    fn parses_a_real_notify_announcement() {
        let obs = parse_frame(&fixtures::ssdp_notify(), "eth0", ts()).expect("parsed");
        assert_eq!(obs.mac, "00:11:32:aa:bb:cc".parse().expect("mac"));
        assert_eq!(obs.ip, Some("192.168.1.77".parse().expect("ip")));
        assert_eq!(obs.kind, ObservationKind::Announcement);
        assert_eq!(obs.source, "ssdp");
        assert_eq!(
            signal(&obs, SignalKind::SsdpDeviceType),
            Some("urn:schemas-upnp-org:device:MediaServer:1")
        );
        assert_eq!(
            signal(&obs, SignalKind::SsdpServer),
            Some("Linux/4.19 UPnP/1.0 Synology-DLNA/1.0")
        );
    }

    #[test]
    fn a_search_names_what_it_wants_not_what_it_is() {
        let obs = parse_frame(&fixtures::ssdp_msearch(), "eth0", ts()).expect("parsed");
        assert_eq!(obs.kind, ObservationKind::Query);
        assert_eq!(
            signal(&obs, SignalKind::SsdpDeviceType),
            None,
            "an M-SEARCH ST describes the search, not the searcher"
        );
        assert_eq!(
            signal(&obs, SignalKind::SsdpServer),
            Some("Google Chrome/124.0 Windows"),
            "the user agent is still the sender naming itself"
        );
    }

    #[test]
    fn a_volunteered_friendly_name_is_read_and_the_description_is_never_fetched() {
        let obs = parse_frame(&fixtures::ssdp_response(), "eth0", ts()).expect("parsed");
        assert_eq!(obs.kind, ObservationKind::Reply);
        assert_eq!(
            signal(&obs, SignalKind::SsdpFriendlyName),
            Some("Living Room TV"),
            "X-friendly-name is base64 on the wire"
        );
        assert_eq!(
            signal(&obs, SignalKind::SsdpDeviceType),
            Some("urn:dial-multiscreen-org:service:dial:1")
        );
    }

    #[test]
    fn service_urns_and_uuids_are_not_device_types() {
        let mut m = SsdpMessage::default();
        set_device_type(&mut m, "uuid:4c2c2b4e-0000-1000-8000-001132aabbcc");
        assert_eq!(m.device_type, None, "a uuid names an instance, not a class");
        set_device_type(&mut m, "urn:schemas-upnp-org:service:ContentDirectory:1");
        assert_eq!(m.device_type, None, "a service says what, not who");
        set_device_type(&mut m, "upnp:rootdevice");
        assert_eq!(m.device_type.as_deref(), Some("upnp:rootdevice"));
    }

    #[test]
    fn the_first_usable_device_type_wins() {
        let (_, m) = parse_message(concat!(
            "NOTIFY * HTTP/1.1\r\n",
            "NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n",
            "NT: urn:schemas-upnp-org:device:MediaServer:1\r\n\r\n"
        ))
        .expect("parsed");
        assert_eq!(
            m.device_type.as_deref(),
            Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1")
        );
    }

    #[test]
    fn header_names_are_matched_case_insensitively() {
        let (kind, m) = parse_message(concat!(
            "notify * HTTP/1.1\r\n",
            "nt: urn:schemas-upnp-org:device:Printer:1\r\n",
            "server: Brother/1.0\r\n\r\n"
        ))
        .expect("parsed");
        assert_eq!(kind, SsdpKind::Notify);
        assert_eq!(
            m.device_type.as_deref(),
            Some("urn:schemas-upnp-org:device:Printer:1")
        );
        assert_eq!(m.server.as_deref(), Some("Brother/1.0"));
    }

    #[test]
    fn bare_line_feeds_parse_as_well_as_crlf() {
        // Some embedded stacks emit LF only, and rejecting them would lose every
        // signal from a whole class of device.
        let (kind, m) =
            parse_message("NOTIFY * HTTP/1.1\nNT: urn:schemas-upnp-org:device:MediaRenderer:1\n\n")
                .expect("parsed");
        assert_eq!(kind, SsdpKind::Notify);
        assert!(m.device_type.is_some());
    }

    #[test]
    fn a_payload_that_is_not_ssdp_is_rejected() {
        assert_eq!(parse_message("GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(parse_message(""), None);
        assert_eq!(parse_message("\r\n\r\n"), None);
        assert_eq!(parse_message("random bytes"), None);
    }

    #[test]
    fn base64_decodes_padded_and_unpadded_input() {
        assert_eq!(
            base64_text("TGl2aW5nIFJvb20gVFY="),
            Some("Living Room TV".into())
        );
        assert_eq!(
            base64_text("TGl2aW5nIFJvb20gVFY"),
            Some("Living Room TV".into())
        );
        assert_eq!(base64_text("aGk="), Some("hi".into()));
        assert_eq!(base64_text(""), None);
        assert_eq!(base64_text("!!!!"), None, "not base64");
        assert_eq!(base64_text("A"), None, "an impossible length");
        assert_eq!(base64_text("//8="), None, "decodes to invalid UTF-8");
    }

    #[test]
    fn a_plain_friendly_name_that_is_not_base64_is_used_as_written() {
        let (_, m) = parse_message(concat!(
            "HTTP/1.1 200 OK\r\n",
            "ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n",
            "X-friendly-name: Kitchen Display\r\n\r\n"
        ))
        .expect("parsed");
        assert_eq!(m.friendly_name.as_deref(), Some("Kitchen Display"));
    }

    #[test]
    fn non_ssdp_and_malformed_frames_are_rejected() {
        assert!(parse_frame(&fixtures::arp_request(), "eth0", ts()).is_none());
        assert!(parse_frame(&fixtures::mdns_response_ipv4(), "eth0", ts()).is_none());
        assert!(parse_frame(&[], "eth0", ts()).is_none());
    }

    #[test]
    fn truncated_ssdp_frames_do_not_panic() {
        for fixture in [
            fixtures::ssdp_notify(),
            fixtures::ssdp_msearch(),
            fixtures::ssdp_response(),
        ] {
            for n in 0..fixture.len() {
                let _ = parse_frame(&fixture[..n], "eth0", ts());
            }
        }
    }
}
