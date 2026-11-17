//! Replays the home LAN's top event sources through the state machine and the
//! analyzer chain, wired the way `daemon.rs` wires them, and counts what comes
//! out per event type.
//!
//! The sources are the ones a read-only count of the live database found on
//! 2026-11-17, over the seven days before it:
//!
//! | Pattern | Live, 7 days |
//! |---|---|
//! | `d0:21:f9:dc:a1:19`, a second router ARPing from three addresses of its own | 19,857 `arp_scan`, 526,735 `ip_changed` |
//! | the same router reflecting other segments' mDNS | 167 `identity_change`, 4,278 mDNS names held |
//! | Apple devices announcing several services, one at a time | ~1,000 `identity_change` |
//! | MetalLB nodes answering for their VIPs, the gateway proxy-ARPing for them | 219 + 24 `ip_changed` |
//!
//! No database: only the state machine's events and the chain's alerts are
//! counted. Every frame is built here from the public fixture helpers, so the
//! same file runs against the code before the fix and after it; the one line
//! that differs is marked in [`Replay::feed`].
//!
//! `cargo test --test replay -- --nocapture` prints the table.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use chrono::{DateTime, Duration, TimeZone, Utc};
use netgraspd::analyze::Chain;
use netgraspd::capture::fixtures::build::{dns_name, ethernet, ipv4, mdns_response, udp};
use netgraspd::capture::{ObservationDedup, arp, mdns};
use netgraspd::config::{HumanDuration, SecurityConfig, StateConfig};
use netgraspd::device::{Effect, Manager};
use netgraspd::types::Observation;

const GATEWAY: [u8; 6] = [0x18, 0xfd, 0x74, 0x39, 0xe5, 0x23];
const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 1);
const ROUTER: [u8; 6] = [0xd0, 0x21, 0xf9, 0xdc, 0xa1, 0x19];
const ROUTER_IPS: [Ipv4Addr; 3] = [
    Ipv4Addr::new(10, 20, 0, 2),
    Ipv4Addr::new(10, 30, 0, 1),
    Ipv4Addr::new(10, 40, 0, 1),
];
const MACBOOK: [u8; 6] = [0x3a, 0x6a, 0x31, 0x8e, 0x75, 0x0d];
const MACBOOK_IP: Ipv4Addr = Ipv4Addr::new(10, 20, 229, 236);
const IMAC: [u8; 6] = [0x04, 0x9d, 0x05, 0x19, 0xdb, 0xb5];
const IMAC_IP: Ipv4Addr = Ipv4Addr::new(10, 20, 231, 25);
const NODES: [([u8; 6], Ipv4Addr, Ipv4Addr); 2] = [
    (
        [0xa4, 0xfc, 0x14, 0x0e, 0x73, 0x85],
        Ipv4Addr::new(10, 20, 229, 43),
        Ipv4Addr::new(10, 20, 250, 53),
    ),
    (
        [0xa4, 0xfc, 0x14, 0x16, 0x67, 0x19],
        Ipv4Addr::new(10, 20, 229, 45),
        Ipv4Addr::new(10, 20, 250, 6),
    ),
];

/// How long the replay runs.
const HOURS: i64 = 6;

fn at(second: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 17, 12, 0, 0)
        .single()
        .expect("valid time")
        + Duration::seconds(second)
}

fn arp_frame(op: u16, src: [u8; 6], sender: Ipv4Addr, target: Ipv4Addr) -> Vec<u8> {
    let mut payload = vec![0x00, 0x01, 0x08, 0x00, 6, 4];
    payload.extend_from_slice(&op.to_be_bytes());
    payload.extend_from_slice(&src);
    payload.extend_from_slice(&sender.octets());
    payload.extend_from_slice(&[0; 6]);
    payload.extend_from_slice(&target.octets());
    let dst = if op == 1 { [0xff; 6] } else { MACBOOK };
    ethernet(dst, src, 0x0806, &payload)
}

fn srv(port: u16, target: &[&str]) -> Vec<u8> {
    let mut rdata = vec![0, 0, 0, 0];
    rdata.extend_from_slice(&port.to_be_bytes());
    rdata.extend_from_slice(&dns_name(target));
    rdata
}

fn txt(entries: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        out.push(u8::try_from(entry.len()).expect("short"));
        out.extend_from_slice(entry.as_bytes());
    }
    out
}

/// A host announcing one of its own services: SRV and A, from itself.
fn own_service(src: [u8; 6], ip: Ipv4Addr, host: &str, service: &str) -> Vec<u8> {
    mdns_response(
        src,
        ip,
        &[
            (
                vec![host, service, "_tcp", "local"],
                33,
                srv(7000, &[host, "local"]),
            ),
            (vec![host, "local"], 1, ip.octets().to_vec()),
        ],
    )
}

/// The router re-sending another host's addressed record.
fn reflected_addressed(from: Ipv4Addr, host: &str, address: Ipv4Addr, service: &str) -> Vec<u8> {
    mdns_response(
        ROUTER,
        from,
        &[
            (
                vec![host, service, "_tcp", "local"],
                33,
                srv(7000, &[host, "local"]),
            ),
            (vec![host, "local"], 1, address.octets().to_vec()),
        ],
    )
}

/// The router re-sending another host's PTR and TXT, which name no address.
fn reflected_unaddressed(from: Ipv4Addr, host: &str, service: &str, model: &str) -> Vec<u8> {
    let instance = vec![host, service, "_tcp", "local"];
    let model = format!("model={model}");
    mdns_response(
        ROUTER,
        from,
        &[
            (vec![service, "_tcp", "local"], 12, dns_name(&instance)),
            (instance.clone(), 16, txt(&[model.as_str()])),
        ],
    )
}

/// The router re-sending another host's probe for its own name.
fn reflected_probe(from: Ipv4Addr, host: &str) -> Vec<u8> {
    let mut msg = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    msg.extend_from_slice(&dns_name(&[host, "local"]));
    msg.extend_from_slice(&255u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    let packet = ipv4(
        from,
        Ipv4Addr::new(224, 0, 0, 251),
        17,
        &udp(5353, 5353, &msg),
    );
    ethernet(
        [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb],
        ROUTER,
        0x0800,
        &packet,
    )
}

/// Every frame the replay sends in one second.
fn frames(second: i64) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let s = usize::try_from(second).expect("positive");

    // The second router: two ARP requests a second, each from its leg on the
    // target's segment, cycling through 120 hosts per segment. Sixty distinct
    // targets in thirty seconds, the most the live database recorded.
    for k in 0..2 {
        let n = (2 * s + k) % 360;
        let leg = ROUTER_IPS[n % 3];
        let [a, b, c, _] = leg.octets();
        let target = Ipv4Addr::new(a, b, c, u8::try_from(10 + n / 3).expect("small"));
        out.push(arp_frame(1, ROUTER, leg, target));
    }

    // The gateway answering for itself, and proxy-ARPing for the VIPs.
    if s % 5 == 0 {
        out.push(arp_frame(2, GATEWAY, GATEWAY_IP, MACBOOK_IP));
    }
    if s % 7 == 3 {
        out.push(arp_frame(2, GATEWAY, NODES[(s / 7) % 2].2, MACBOOK_IP));
    }
    // MetalLB nodes answering for themselves and for their VIPs.
    for (n, (mac, own, vip)) in NODES.iter().enumerate() {
        if (s + n) % 10 == 0 {
            out.push(arp_frame(2, *mac, *own, MACBOOK_IP));
        }
        if (s + n) % 13 == 6 {
            out.push(arp_frame(2, *mac, *vip, MACBOOK_IP));
        }
    }

    // The MacBook announcing itself once a minute.
    if s % 60 == 1 {
        out.push(own_service(
            MACBOOK,
            MACBOOK_IP,
            "Jeremys-MacBook-Pro-5",
            "_companion-link",
        ));
    }
    // The iMac re-announcing its services one at a time, AirPlay and AFP
    // taking turns every five minutes.
    if s % 300 == 2 {
        let service = if (s / 300) % 2 == 0 {
            "_airplay"
        } else {
            "_afpovertcp"
        };
        out.push(own_service(IMAC, IMAC_IP, "Jeremys-iMac", service));
    }
    // The router reflecting other segments' mDNS: one addressed record, then
    // unaddressed records for hosts on segments this wire does not see.
    match s % 40 {
        4 => out.push(reflected_addressed(
            ROUTER_IPS[0],
            "Jeremys-MacBook-Pro-5",
            MACBOOK_IP,
            "_companion-link",
        )),
        14 => out.push(reflected_unaddressed(
            ROUTER_IPS[2],
            "Living Room",
            "_airplay",
            "AppleTV14,1",
        )),
        24 => out.push(reflected_unaddressed(
            ROUTER_IPS[1],
            "Office",
            if (s / 40) % 2 == 0 { "_smb" } else { "_hap" },
            "Mac15,14",
        )),
        34 => out.push(reflected_probe(ROUTER_IPS[2], "Marantz-M4")),
        _ => {}
    }
    out
}

/// The daemon minus libpcap, the database and the notifier.
struct Replay {
    manager: Manager,
    dedup: ObservationDedup,
    chain: Chain,
    counts: BTreeMap<String, u64>,
}

impl Replay {
    fn new() -> Self {
        let state = StateConfig {
            idle_timeout: HumanDuration::from_secs(1800),
            offline_timeout: HumanDuration::from_secs(10_800),
            ..StateConfig::default()
        };
        // The gateway's address as the capture host's default route gives it
        // on main since C1c; its MAC is learned from the wire.
        let security = SecurityConfig {
            gateway_ip: GATEWAY_IP.to_string(),
            ..SecurityConfig::default()
        };
        Replay {
            manager: Manager::new(state, false),
            dedup: ObservationDedup::new(4096, 1),
            chain: Chain::new(&security),
            counts: BTreeMap::new(),
        }
    }

    fn feed(&mut self, observation: &Observation) {
        if self.dedup.admit(observation) {
            // The one line that differs before the fix, where the daemon
            // called `self.manager.observe(observation)`.
            let effects = self
                .manager
                .observe_with_gateway(observation, self.chain.gateway());
            for effect in effects {
                if let Effect::Event(event) = effect {
                    *self.counts.entry(event.event_type.to_string()).or_default() += 1;
                }
            }
        }
        let mut alerts = self.chain.observe(observation);
        for change in self.manager.take_reclassifications() {
            alerts.extend(self.chain.reclassified(&change));
        }
        for alert in alerts {
            *self
                .counts
                .entry(format!("{} (security)", alert.event_type))
                .or_default() += 1;
        }
    }
}

#[test]
fn the_home_lans_top_sources_replayed_produce_a_readable_event_stream() {
    let mut replay = Replay::new();
    for second in 0..HOURS * 3600 {
        for frame in frames(second) {
            let parsed = arp::parse_frame(&frame, "eth0", at(second))
                .or_else(|| mdns::parse_frame(&frame, "eth0", at(second)));
            let observation = parsed.expect("every replayed frame parses");
            replay.feed(&observation);
        }
    }

    println!("replay of {HOURS} hours of the home LAN's top sources:");
    println!("{:<28} {:>8}", "event type", "count");
    for (kind, count) in &replay.counts {
        println!("{kind:<28} {count:>8}");
    }

    let count = |kind: &str| replay.counts.get(kind).copied().unwrap_or(0);
    // Six new devices: the router, the gateway, two nodes, the MacBook and
    // the iMac. Nothing else is new.
    assert_eq!(count("new_device"), 6, "{:?}", replay.counts);
    // One per further address first seen: two for the router's second and
    // third legs, one for each node's VIP. Never one for the gateway.
    assert!(count("ip_changed") <= 4, "{:?}", replay.counts);
    assert_eq!(count("arp_scan (security)"), 0, "{:?}", replay.counts);
    assert_eq!(
        count("identity_change (security)"),
        0,
        "{:?}",
        replay.counts
    );
    assert_eq!(count("ip_conflict (security)"), 0, "{:?}", replay.counts);
    assert_eq!(count("arp_spoof (security)"), 0, "{:?}", replay.counts);
}
