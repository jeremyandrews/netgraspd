//! What the capture host knows about itself: its default route, and the
//! hardware address of each of its interfaces.
//!
//! Both are facts the operating system already holds, and both were being
//! guessed from the wire. The first C1 run on 2026-11-14 showed what that
//! costs. Guessing the gateway from ARP popularity elected the capture host
//! itself, because three hosts asked for it within a second, and the real
//! router's proxy ARP then read as conflicts and an impersonation. And with
//! nothing in the device table knowing which MACs were the capture host's own,
//! a Mac capturing on Wi-Fi and six container bridges became seven devices.
//!
//! [`read`] is the only part that touches the operating system, through the
//! `netdev` crate: netlink on Linux, the routing sysctl and `getifaddrs` on
//! macOS. It is a local read of the host's own tables. It transmits nothing
//! and asks the network nothing. (To mark which interface carries the default
//! route, `netdev` connects an unbound UDP socket and reads back the source
//! address the kernel chose; connecting a UDP socket sends no datagram.)
//! Everything after it is a pure function over [`HostFacts`], tested from
//! constructed values.

use crate::analyze::gateway::DefaultRoute;
use crate::device::CaptureHost;
use crate::types::MacAddr;

/// One of the host's interfaces, as far as this module cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInterface {
    /// The name the operating system and libpcap know it by.
    pub name: String,
    /// Its hardware address, when it has one. Tunnels and loopback do not.
    pub mac: Option<MacAddr>,
}

/// What the operating system says about the host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostFacts {
    /// The IPv4 default route, when there is one.
    pub route: Option<DefaultRoute>,
    /// Every interface the operating system lists.
    pub interfaces: Vec<HostInterface>,
}

/// Reads the host's default route and interface hardware addresses.
///
/// Never fails: an operating system that will not say is a host with no route
/// and no known MACs, and the daemon then behaves as it did before it asked.
#[must_use]
pub fn read() -> HostFacts {
    let interfaces = netdev::get_interfaces();
    let route = interfaces.iter().find(|i| i.default).and_then(|i| {
        let gateway = i.gateway.as_ref()?;
        let address = gateway.ipv4.first().copied()?;
        Some(DefaultRoute {
            gateway: address,
            interface: i.name.clone(),
        })
    });
    HostFacts {
        route,
        interfaces: interfaces
            .into_iter()
            .map(|i| HostInterface {
                name: i.name,
                mac: i.mac_addr.map(|m| MacAddr(m.octets())),
            })
            .collect(),
    }
}

/// What Apple platforms report in place of a hardware address they decline to
/// disclose. Observed on the Mac Studio on 2026-11-15 for every interface, from
/// `ifconfig` and `getifaddrs` alike, as an ordinary user: it is a placeholder,
/// not an address, and no frame on the wire carries it.
pub const WITHHELD_MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0]);

/// The captured interfaces whose hardware address the operating system
/// withheld, so that the daemon can say why the capture host is not
/// identified rather than guess.
#[must_use]
pub fn withheld(facts: &HostFacts, captured: &[String]) -> Vec<String> {
    captured
        .iter()
        .filter(|name| {
            facts
                .interfaces
                .iter()
                .any(|i| i.name == **name && i.mac == Some(WITHHELD_MAC))
        })
        .cloned()
        .collect()
}

/// The capture host's own MACs on the interfaces it captures on.
///
/// The host is recorded under the MAC of the interface its default route
/// leaves by, when that interface is captured; otherwise under the first
/// captured interface that has a MAC. Every other captured interface's MAC is
/// an alias of it. `None` when no captured interface has a usable MAC (a
/// capture on tunnels only, or an operating system that withholds them; see
/// [`WITHHELD_MAC`]), in which case nothing is folded.
#[must_use]
pub fn capture_host(facts: &HostFacts, captured: &[String]) -> Option<CaptureHost> {
    let mac_of = |name: &str| {
        facts
            .interfaces
            .iter()
            .find(|i| i.name == name)
            .and_then(|i| i.mac)
            .filter(|m| !m.is_zero() && !m.is_group() && *m != WITHHELD_MAC)
    };
    let own: Vec<(&str, MacAddr)> = captured
        .iter()
        .filter_map(|name| mac_of(name).map(|mac| (name.as_str(), mac)))
        .collect();
    let routed = facts
        .route
        .as_ref()
        .and_then(|route| own.iter().find(|(name, _)| *name == route.interface));
    let (_, primary) = routed.or_else(|| own.first())?;
    let mut aliases: Vec<MacAddr> = Vec::new();
    for (_, mac) in &own {
        if mac != primary && !aliases.contains(mac) {
            aliases.push(*mac);
        }
    }
    Some(CaptureHost::new(*primary, aliases))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn mac(s: &str) -> MacAddr {
        s.parse().expect("test mac")
    }

    fn iface(name: &str, m: Option<&str>) -> HostInterface {
        HostInterface {
            name: name.to_string(),
            mac: m.map(mac),
        }
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    /// The Mac Studio in C1: Wi-Fi on the LAN, two of the OrbStack bridges,
    /// a tunnel and loopback. Constructed, not read.
    fn studio(route: Option<&str>) -> HostFacts {
        HostFacts {
            route: route.map(|interface| DefaultRoute {
                gateway: Ipv4Addr::new(10, 20, 0, 1),
                interface: interface.to_string(),
            }),
            interfaces: vec![
                iface("lo0", None),
                iface("bridge100", Some("36:e6:8a:a1:7b:64")),
                iface("en1", Some("9a:3b:5c:7d:20:c8")),
                iface("bridge101", Some("36:e6:8a:a1:7b:65")),
                iface("utun4", None),
            ],
        }
    }

    #[test]
    fn the_host_is_keyed_by_the_interface_its_default_route_leaves_by() {
        let host = capture_host(
            &studio(Some("en1")),
            &names(&["bridge100", "en1", "bridge101"]),
        )
        .expect("a capture host");
        assert_eq!(host.primary, mac("9a:3b:5c:7d:20:c8"));
        assert_eq!(
            host.aliases,
            vec![mac("36:e6:8a:a1:7b:64"), mac("36:e6:8a:a1:7b:65")]
        );
    }

    #[test]
    fn with_no_route_the_first_captured_interface_with_a_mac_is_the_host() {
        for facts in [studio(None), studio(Some("utun4"))] {
            let host = capture_host(&facts, &names(&["utun4", "bridge100", "en1"]))
                .expect("a capture host");
            assert_eq!(host.primary, mac("36:e6:8a:a1:7b:64"));
            assert_eq!(host.aliases, vec![mac("9a:3b:5c:7d:20:c8")]);
        }
    }

    #[test]
    fn an_interface_that_is_not_captured_is_not_an_alias() {
        let host = capture_host(&studio(Some("en1")), &names(&["en1"])).expect("a capture host");
        assert_eq!(host.primary, mac("9a:3b:5c:7d:20:c8"));
        assert!(host.aliases.is_empty());
    }

    #[test]
    fn capturing_only_on_tunnels_names_no_capture_host() {
        assert_eq!(capture_host(&studio(None), &names(&["utun4", "lo0"])), None);
    }

    #[test]
    fn a_withheld_hardware_address_is_not_a_hardware_address() {
        // What the Mac Studio's own OS answered on 2026-11-15, for every
        // interface: the placeholder, never the address.
        let facts = HostFacts {
            route: Some(DefaultRoute {
                gateway: Ipv4Addr::new(10, 20, 0, 1),
                interface: "en1".to_string(),
            }),
            interfaces: vec![
                iface("en1", Some("02:00:00:00:00:00")),
                iface("bridge100", Some("02:00:00:00:00:00")),
                iface("utun0", None),
            ],
        };
        let captured = names(&["en1", "bridge100", "utun0"]);
        assert_eq!(capture_host(&facts, &captured), None);
        assert_eq!(withheld(&facts, &captured), names(&["en1", "bridge100"]));

        // One withheld among real ones: the real ones still count.
        let mut facts = studio(Some("en1"));
        facts.interfaces[1].mac = Some(WITHHELD_MAC);
        let host = capture_host(&facts, &names(&["en1", "bridge100", "bridge101"]))
            .expect("a capture host");
        assert_eq!(host.primary, mac("9a:3b:5c:7d:20:c8"));
        assert_eq!(host.aliases, vec![mac("36:e6:8a:a1:7b:65")]);
    }
}
