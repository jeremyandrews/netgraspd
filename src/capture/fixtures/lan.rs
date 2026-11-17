//! Frames from the home LAN behind issues #10, #11 and #12.
//!
//! The addresses and MACs are the ones in the issues and in the live
//! database's top offenders on 2026-11-17, so a test failure reads in the same
//! terms as the report it came from:
//!
//! | Who | MAC | Addresses |
//! |---|---|---|
//! | The gateway (Routerboard) | `18:fd:74:39:e5:23` | `10.20.0.1` |
//! | A second, multi-homed router (Ubiquiti) that also reflects mDNS | `d0:21:f9:dc:a1:19` | `10.20.0.2`, `10.30.0.1`, `10.40.0.1` |
//! | A MacBook whose mDNS records get reflected | `3a:6a:31:8e:75:0d` | `10.20.229.236` |
//! | A Kubernetes node answering for a MetalLB VIP | `9c:76:0e:30:aa:b0` | `10.20.229.65`, VIP `10.20.250.1` |
//!
//! Built rather than committed as `.bin` files: nothing here is a parser
//! fixture, and the builders say what each frame is in the terms that matter.

use std::net::Ipv4Addr;

use crate::capture::dns::{TYPE_A, TYPE_PTR, TYPE_SRV, TYPE_TXT};

use super::build::{dns_name, ethernet, ipv4, mdns_response, srv_rdata, udp};

/// The gateway the hosts route through.
pub const GATEWAY: [u8; 6] = [0x18, 0xfd, 0x74, 0x39, 0xe5, 0x23];
/// The gateway's address.
pub const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 1);

/// The second router, which is also an mDNS reflector.
pub const ROUTER: [u8; 6] = [0xd0, 0x21, 0xf9, 0xdc, 0xa1, 0x19];
/// Its three addresses, one per routed segment, all on the captured wire.
pub const ROUTER_IPS: [Ipv4Addr; 3] = [
    Ipv4Addr::new(10, 20, 0, 2),
    Ipv4Addr::new(10, 40, 0, 1),
    Ipv4Addr::new(10, 30, 0, 1),
];

/// The MacBook whose records the router reflects.
pub const MACBOOK: [u8; 6] = [0x3a, 0x6a, 0x31, 0x8e, 0x75, 0x0d];
/// The MacBook's address.
pub const MACBOOK_IP: Ipv4Addr = Ipv4Addr::new(10, 20, 229, 236);
/// The MacBook's mDNS host label.
pub const MACBOOK_HOST: &str = "Jeremys-MacBook-Pro-5";

/// A Kubernetes node running a MetalLB speaker.
pub const NODE: [u8; 6] = [0x9c, 0x76, 0x0e, 0x30, 0xaa, 0xb0];
/// The node's own address.
pub const NODE_IP: Ipv4Addr = Ipv4Addr::new(10, 20, 229, 65);
/// The load-balancer VIP the node answers for.
pub const VIP: Ipv4Addr = Ipv4Addr::new(10, 20, 250, 1);

/// The broadcast address.
const BROADCAST: [u8; 6] = [0xff; 6];
/// The ARP ethertype.
const ETHERTYPE_ARP: u16 = 0x0806;
/// The IPv4 mDNS group.
const MDNS_GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// The Ethernet destination for the IPv4 mDNS group.
const MDNS_GROUP_MAC: [u8; 6] = [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb];
/// The mDNS port.
const MDNS_PORT: u16 = 5353;

/// An ARP frame. Requests are broadcast; replies go to `target_mac`.
fn arp(
    op: u16,
    src: [u8; 6],
    sender_ip: Ipv4Addr,
    target_mac: [u8; 6],
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut payload = vec![0x00, 0x01, 0x08, 0x00, 6, 4];
    payload.extend_from_slice(&op.to_be_bytes());
    payload.extend_from_slice(&src);
    payload.extend_from_slice(&sender_ip.octets());
    payload.extend_from_slice(&target_mac);
    payload.extend_from_slice(&target_ip.octets());
    let dst = if op == 1 { BROADCAST } else { target_mac };
    ethernet(dst, src, ETHERTYPE_ARP, &payload)
}

/// An ARP request from `src`, which says it is `sender_ip`, asking for
/// `target_ip`.
#[must_use]
pub fn arp_request(src: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    arp(1, src, sender_ip, [0; 6], target_ip)
}

/// An ARP reply from `src` saying that `sender_ip` is at `src`, addressed to
/// `to` at `to_ip`.
#[must_use]
pub fn arp_reply(src: [u8; 6], sender_ip: Ipv4Addr, to: [u8; 6], to_ip: Ipv4Addr) -> Vec<u8> {
    arp(2, src, sender_ip, to, to_ip)
}

/// **A reflected mDNS response that proves who it is about.** The router
/// re-sends, from its own MAC and its `10.20.0.2`, the MacBook's
/// `_companion-link._tcp` instance with an SRV record and the A record that
/// gives the instance its address, `10.20.229.236`.
#[must_use]
pub fn mdns_reflected_addressed() -> Vec<u8> {
    let host = vec![MACBOOK_HOST, "local"];
    mdns_response(
        ROUTER,
        ROUTER_IPS[0],
        &[
            (
                vec![MACBOOK_HOST, "_companion-link", "_tcp", "local"],
                TYPE_SRV,
                srv_rdata(49_152, &host),
            ),
            (host.clone(), TYPE_A, MACBOOK_IP.octets().to_vec()),
        ],
    )
}

/// **A reflected mDNS response that names nobody's address.** The router
/// re-sends, from `10.40.0.1`, the MacBook's AirPlay PTR and TXT records: an
/// instance name, a service type and a model, and no SRV or A record to tie
/// them to any address. Nothing in the frame says whose they are except the
/// Ethernet source, which is the reflector's.
#[must_use]
pub fn mdns_reflected_unaddressed() -> Vec<u8> {
    let instance = vec![MACBOOK_HOST, "_airplay", "_tcp", "local"];
    let mut txt = Vec::new();
    for entry in ["model=Mac15,14", "srcvers=870.14.1"] {
        txt.push(u8::try_from(entry.len()).expect("a fixture TXT string fits"));
        txt.extend_from_slice(entry.as_bytes());
    }
    mdns_response(
        ROUTER,
        ROUTER_IPS[1],
        &[
            (
                vec!["_airplay", "_tcp", "local"],
                TYPE_PTR,
                dns_name(&instance),
            ),
            (instance, TYPE_TXT, txt),
        ],
    )
}

/// **A reflected mDNS probe.** The MacBook asking whether its own host name is
/// taken, re-sent by the router from `10.30.0.1`. A query carries no records,
/// so the question name is the only evidence and it says nothing about the
/// reflector.
#[must_use]
pub fn mdns_reflected_probe() -> Vec<u8> {
    let mut msg = vec![0x00, 0x00, 0x00, 0x00]; // query
    msg.extend_from_slice(&1u16.to_be_bytes()); // questions
    msg.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // answers, authority, additional
    msg.extend_from_slice(&dns_name(&[MACBOOK_HOST, "local"]));
    msg.extend_from_slice(&255u16.to_be_bytes()); // ANY
    msg.extend_from_slice(&1u16.to_be_bytes()); // IN
    let datagram = udp(MDNS_PORT, MDNS_PORT, &msg);
    let packet = ipv4(ROUTER_IPS[2], MDNS_GROUP_V4, 17, &datagram);
    ethernet(MDNS_GROUP_MAC, ROUTER, 0x0800, &packet)
}

/// The MacBook announcing itself: its own instance and the A record for its
/// own address, from that address.
#[must_use]
pub fn mdns_macbook_announcement() -> Vec<u8> {
    let host = vec![MACBOOK_HOST, "local"];
    mdns_response(
        MACBOOK,
        MACBOOK_IP,
        &[
            (
                vec![MACBOOK_HOST, "_companion-link", "_tcp", "local"],
                TYPE_SRV,
                srv_rdata(49_152, &host),
            ),
            (host.clone(), TYPE_A, MACBOOK_IP.octets().to_vec()),
        ],
    )
}
