//! Captured frames used by the parser tests.
//!
//! The bytes live in `tests/fixtures/*.bin` as raw Ethernet frames, one frame
//! per file, and are embedded here rather than read at runtime so that the
//! tests have no working-directory dependency.
//!
//! These frames were assembled byte by byte to the on-wire layouts in RFC 826
//! (ARP), RFC 1035 (DNS) and RFC 6762 (mDNS), including the details that break
//! naive parsers: 60-byte Ethernet padding, an 802.1Q tag, a DNS compression
//! pointer inside PTR rdata, the mDNS cache-flush class bit, and an IPv6
//! link-local source. They were not sniffed from a live network, because the
//! machine this was built on has no packet-capture permission. `tests/fixtures/
//! README.md` documents the layout of each so a real capture can replace one
//! without guesswork.
//!
//! Available outside `cfg(test)` so integration tests can drive the same frames
//! through the whole pipeline.

/// A broadcast ARP request from an Apple device asking for the gateway.
#[must_use]
pub fn arp_request() -> Vec<u8> {
    include_bytes!("../../tests/fixtures/arp_request.bin").to_vec()
}

/// The gateway's unicast ARP reply.
#[must_use]
pub fn arp_reply() -> Vec<u8> {
    include_bytes!("../../tests/fixtures/arp_reply.bin").to_vec()
}

/// A gratuitous ARP: sender and target addresses are the same, so the device is
/// announcing rather than asking.
#[must_use]
pub fn arp_gratuitous() -> Vec<u8> {
    include_bytes!("../../tests/fixtures/arp_gratuitous.bin").to_vec()
}

/// An ARP probe with a sender address of 0.0.0.0, sent while a device is still
/// checking whether the address it wants is free.
#[must_use]
pub fn arp_probe() -> Vec<u8> {
    include_bytes!("../../tests/fixtures/arp_probe.bin").to_vec()
}

/// The same request as [`arp_request`] carried inside an 802.1Q VLAN tag.
#[must_use]
pub fn arp_request_vlan() -> Vec<u8> {
    include_bytes!("../../tests/fixtures/arp_request_vlan.bin").to_vec()
}

/// An mDNS response over IPv4 announcing an AirPlay service, with a compression
/// pointer in the PTR rdata and the cache-flush bit set on the A record.
#[must_use]
pub fn mdns_response_ipv4() -> Vec<u8> {
    include_bytes!("../../tests/fixtures/mdns_response_ipv4.bin").to_vec()
}

/// An mDNS response over IPv6 from a printer, carrying SRV and TXT records and
/// no address record.
#[must_use]
pub fn mdns_response_ipv6() -> Vec<u8> {
    include_bytes!("../../tests/fixtures/mdns_response_ipv6.bin").to_vec()
}

/// An mDNS service-enumeration query, which proves presence but names nothing.
#[must_use]
pub fn mdns_query() -> Vec<u8> {
    include_bytes!("../../tests/fixtures/mdns_query.bin").to_vec()
}

/// Every fixture, paired with its file name. Used by tests that assert
/// pipeline-wide properties such as "no parser panics on any truncation".
#[must_use]
pub fn all() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("arp_request", arp_request()),
        ("arp_reply", arp_reply()),
        ("arp_gratuitous", arp_gratuitous()),
        ("arp_probe", arp_probe()),
        ("arp_request_vlan", arp_request_vlan()),
        ("mdns_response_ipv4", mdns_response_ipv4()),
        ("mdns_response_ipv6", mdns_response_ipv6()),
        ("mdns_query", mdns_query()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_fixture_is_present_and_frame_sized() {
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
    fn no_parser_panics_on_any_truncation_of_any_fixture() {
        let ts = chrono::TimeZone::timestamp_opt(&chrono::Utc, 1_770_000_000, 0)
            .single()
            .expect("valid timestamp");
        for (name, bytes) in all() {
            for n in 0..=bytes.len() {
                let slice = &bytes[..n];
                let _ = crate::capture::arp::parse_frame(slice, "eth0", ts);
                let _ = crate::capture::mdns::parse_frame(slice, "eth0", ts);
                assert!(n <= bytes.len(), "{name}");
            }
        }
    }
}
