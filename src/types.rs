//! Core value types shared by every layer of the daemon.
//!
//! A [`MacAddr`] is the identity key for a device, an [`Observation`] is the
//! single currency the capture layer produces, and a [`Signal`] is one piece of
//! identity evidence attached to an observation. Nothing here touches the
//! network or the database, which is what makes the whole layer trivially
//! testable.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A 48-bit IEEE 802 MAC address.
///
/// Stored as raw bytes and rendered canonically as lowercase colon-separated
/// hex (`aa:bb:cc:dd:ee:ff`), which is the form written to Postgres so that the
/// Trovato plugin can join on it without normalising.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// The all-ones broadcast address.
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);

    /// Returns the raw six bytes.
    #[must_use]
    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }

    /// True for the broadcast address or any multicast address (low bit of the
    /// first octet set). Neither ever identifies a real device, so the device
    /// manager drops observations keyed on one.
    #[must_use]
    pub const fn is_group(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// True for the all-zero address, which shows up in malformed frames and in
    /// DHCP discover padding.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        let o = self.0;
        o[0] == 0 && o[1] == 0 && o[2] == 0 && o[3] == 0 && o[4] == 0 && o[5] == 0
    }

    /// True when the locally-administered bit is set, which marks a randomised
    /// (privacy) address. Such a MAC is not a stable device identity, and the
    /// state machine still tracks it but identity scoring never promotes a
    /// vendor guess from one.
    #[must_use]
    pub const fn is_locally_administered(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// Uppercase hex with no separators, the form the IEEE registry uses. Only
    /// the first `n` nibbles are returned, for prefix lookups.
    #[must_use]
    pub fn hex_prefix(&self, nibbles: usize) -> String {
        let mut s = String::with_capacity(12);
        for b in self.0 {
            s.push_str(&format!("{b:02X}"));
        }
        s.truncate(nibbles.min(12));
        s
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let o = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            o[0], o[1], o[2], o[3], o[4], o[5]
        )
    }
}

/// Error returned when a string cannot be read as a MAC address.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid MAC address: {0}")]
pub struct ParseMacError(String);

impl FromStr for MacAddr {
    type Err = ParseMacError;

    /// Accepts colon, hyphen, dot or no separators, in any case.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex: String = s
            .chars()
            .filter(|c| !matches!(c, ':' | '-' | '.' | ' '))
            .collect();
        if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ParseMacError(s.to_string()));
        }
        let mut out = [0u8; 6];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| ParseMacError(s.to_string()))?;
        }
        Ok(MacAddr(out))
    }
}

impl TryFrom<String> for MacAddr {
    type Error = ParseMacError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<MacAddr> for String {
    fn from(value: MacAddr) -> Self {
        value.to_string()
    }
}

/// What a capture source saw, independent of which protocol saw it.
///
/// Deliberately coarse: the dedup key and the state machine care about "this
/// MAC was present", not about ARP opcodes. The specific protocol survives in
/// [`Observation::source`] for logging and in the attached signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    /// A device asked for an address (ARP request, NDP solicitation).
    Request,
    /// A device answered (ARP reply, NDP advertisement).
    Reply,
    /// A device announced itself unprompted (mDNS announcement, SSDP NOTIFY,
    /// gratuitous ARP).
    Announcement,
    /// A device asked the network a question that is not address resolution
    /// (mDNS query, SSDP M-SEARCH, NetBIOS name query).
    Query,
}

impl ObservationKind {
    /// Stable short name, used in the dedup key and in log lines.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            ObservationKind::Request => "request",
            ObservationKind::Reply => "reply",
            ObservationKind::Announcement => "announcement",
            ObservationKind::Query => "query",
        }
    }
}

/// The kind of identity evidence a signal carries.
///
/// The ordering of the variants is not significant; [`SignalKind::weight`] is
/// the single source of truth for scoring. Variants for protocols that
/// milestone 1 does not parse exist now so that adding a parser later adds rows
/// without touching the scorer or the schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// A name a human typed in the Trovato UI. Absolute: it beats everything.
    UserAssigned,
    /// mDNS instance name, for example `Living Room Apple TV`.
    MdnsName,
    /// Hostname from a DHCP request option 12. Reserved for milestone 2.
    DhcpHostname,
    /// PTR record for the device's current IP.
    ReverseDns,
    /// NetBIOS name service announcement. Reserved for milestone 2.
    NetbiosName,
    /// SSDP `friendlyName` from a device description. Reserved for milestone 2.
    SsdpFriendlyName,
    /// The IEEE-registered vendor for the MAC prefix.
    Vendor,
    /// The bare MAC address, the identity of last resort.
    Mac,
    /// An mDNS service type the device advertises, for example `_airplay._tcp`.
    ///
    /// Not a name, so it never competes for the display identity and carries
    /// weight zero. It is stored because it is the strongest available input to
    /// device-type classification, which is milestone 2 work.
    MdnsService,
}

impl SignalKind {
    /// Scoring weight. `UserAssigned` returns 1.0 but is handled as an absolute
    /// override before scoring, so its numeric value is never the deciding
    /// factor.
    #[must_use]
    pub const fn weight(&self) -> f64 {
        match self {
            SignalKind::UserAssigned => 1.0,
            SignalKind::MdnsName => 0.9,
            SignalKind::DhcpHostname => 0.8,
            SignalKind::ReverseDns => 0.7,
            SignalKind::NetbiosName => 0.6,
            SignalKind::SsdpFriendlyName => 0.5,
            SignalKind::Vendor => 0.3,
            SignalKind::Mac => 0.1,
            SignalKind::MdnsService => 0.0,
        }
    }

    /// Stable string used as the `ng_device_signals.signal_type` value. Changing
    /// one of these is a schema migration, not a rename.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            SignalKind::UserAssigned => "user_assigned",
            SignalKind::MdnsName => "mdns_name",
            SignalKind::DhcpHostname => "dhcp_hostname",
            SignalKind::ReverseDns => "reverse_dns",
            SignalKind::NetbiosName => "netbios_name",
            SignalKind::SsdpFriendlyName => "ssdp_friendly_name",
            SignalKind::Vendor => "vendor",
            SignalKind::Mac => "mac",
            SignalKind::MdnsService => "mdns_service",
        }
    }

    /// Inverse of [`SignalKind::as_str`], for reading rows back out of Postgres.
    #[must_use]
    pub fn from_str_opt(s: &str) -> Option<Self> {
        Some(match s {
            "user_assigned" => SignalKind::UserAssigned,
            "mdns_name" => SignalKind::MdnsName,
            "dhcp_hostname" => SignalKind::DhcpHostname,
            "reverse_dns" => SignalKind::ReverseDns,
            "netbios_name" => SignalKind::NetbiosName,
            "ssdp_friendly_name" => SignalKind::SsdpFriendlyName,
            "vendor" => SignalKind::Vendor,
            "mac" => SignalKind::Mac,
            "mdns_service" => SignalKind::MdnsService,
            _ => return None,
        })
    }
}

/// One piece of identity evidence about a device.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Signal {
    /// Which kind of evidence this is, which fixes its weight.
    pub kind: SignalKind,
    /// The evidence itself, for example an mDNS instance name.
    pub value: String,
}

impl Signal {
    /// Convenience constructor.
    pub fn new(kind: SignalKind, value: impl Into<String>) -> Self {
        Signal {
            kind,
            value: value.into(),
        }
    }
}

/// A single sighting of a device on one interface.
///
/// Observations are the only thing capture sources produce and are never
/// persisted individually. They mutate in-memory device state and are then
/// dropped; only state *changes* reach the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The device's hardware address.
    pub mac: MacAddr,
    /// The address the device was using, when the protocol reveals one.
    pub ip: Option<IpAddr>,
    /// Name of the interface the packet arrived on.
    pub interface: String,
    /// Short name of the capture source that produced this, for example `arp`.
    pub source: &'static str,
    /// What kind of traffic this was.
    pub kind: ObservationKind,
    /// Identity evidence carried by this packet, possibly empty.
    pub signals: Vec<Signal>,
    /// When the packet was seen.
    pub observed_at: DateTime<Utc>,
}

impl Observation {
    /// Minimal observation with no identity evidence.
    pub fn new(
        mac: MacAddr,
        ip: Option<IpAddr>,
        interface: impl Into<String>,
        source: &'static str,
        kind: ObservationKind,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Observation {
            mac,
            ip,
            interface: interface.into(),
            source,
            kind,
            signals: Vec::new(),
            observed_at,
        }
    }

    /// Attaches one signal, builder style.
    #[must_use]
    pub fn with_signal(mut self, signal: Signal) -> Self {
        self.signals.push(signal);
        self
    }
}

/// The lifecycle state of a device, as tracked by the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    /// Seen within the idle timeout.
    Online,
    /// Silent for longer than the idle timeout but less than the offline one.
    Idle,
    /// Silent for longer than the offline timeout.
    Offline,
}

impl DeviceState {
    /// Stable string used as the `ng_devices.state` value.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            DeviceState::Online => "online",
            DeviceState::Idle => "idle",
            DeviceState::Offline => "offline",
        }
    }

    /// Inverse of [`DeviceState::as_str`]. Unknown strings read back as
    /// `Offline`, the safe default: a device we cannot classify is one we have
    /// not seen, and the next observation will correct it.
    #[must_use]
    pub fn from_db(s: &str) -> Self {
        match s {
            "online" => DeviceState::Online,
            "idle" => DeviceState::Idle,
            _ => DeviceState::Offline,
        }
    }
}

impl fmt::Display for DeviceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A device state change worth telling somebody about.
///
/// These are the rows that land in `ng_events` and the messages that ride the
/// event bus to the notifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// A MAC never seen before appeared.
    NewDevice,
    /// A device that had gone offline came back.
    Returned,
    /// A known device is using a different IP.
    IpChanged,
    /// A device passed the offline timeout.
    WentOffline,
    /// Identity resolution promoted a different display name.
    NameUpdated,
}

impl EventType {
    /// Stable string used as the `ng_events.event_type` value.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            EventType::NewDevice => "new_device",
            EventType::Returned => "returned",
            EventType::IpChanged => "ip_changed",
            EventType::WentOffline => "went_offline",
            EventType::NameUpdated => "name_updated",
        }
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_parses_every_common_separator() {
        let expect = MacAddr([0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22]);
        for s in [
            "aa:bb:cc:00:11:22",
            "AA-BB-CC-00-11-22",
            "aabb.cc00.1122",
            "AABBCC001122",
        ] {
            assert_eq!(s.parse::<MacAddr>().expect("valid mac"), expect, "{s}");
        }
    }

    #[test]
    fn mac_rejects_junk() {
        for s in [
            "",
            "aa:bb:cc:00:11",
            "aa:bb:cc:00:11:22:33",
            "zz:bb:cc:00:11:22",
        ] {
            assert!(s.parse::<MacAddr>().is_err(), "{s} should not parse");
        }
    }

    #[test]
    fn mac_renders_lowercase_colons() {
        assert_eq!(
            MacAddr([0x3c, 0x22, 0xfb, 0x0a, 0x0b, 0x0c]).to_string(),
            "3c:22:fb:0a:0b:0c"
        );
    }

    #[test]
    fn mac_classifies_group_and_local_bits() {
        assert!(MacAddr::BROADCAST.is_group());
        assert!(MacAddr([0x01, 0x00, 0x5e, 0, 0, 0xfb]).is_group());
        assert!(!MacAddr([0x3c, 0x22, 0xfb, 0, 0, 1]).is_group());
        assert!(MacAddr([0x02, 0x11, 0x22, 0, 0, 1]).is_locally_administered());
        assert!(!MacAddr([0x3c, 0x22, 0xfb, 0, 0, 1]).is_locally_administered());
        assert!(MacAddr([0; 6]).is_zero());
    }

    #[test]
    fn hex_prefix_truncates_to_registry_widths() {
        let m = MacAddr([0x8c, 0x1f, 0x64, 0xaf, 0xa1, 0x00]);
        assert_eq!(m.hex_prefix(6), "8C1F64");
        assert_eq!(m.hex_prefix(7), "8C1F64A");
        assert_eq!(m.hex_prefix(9), "8C1F64AFA");
        assert_eq!(m.hex_prefix(99), "8C1F64AFA100");
    }

    #[test]
    fn signal_weights_match_the_design_record() {
        assert_eq!(SignalKind::MdnsName.weight(), 0.9);
        assert_eq!(SignalKind::DhcpHostname.weight(), 0.8);
        assert_eq!(SignalKind::ReverseDns.weight(), 0.7);
        assert_eq!(SignalKind::NetbiosName.weight(), 0.6);
        assert_eq!(SignalKind::SsdpFriendlyName.weight(), 0.5);
        assert_eq!(SignalKind::Vendor.weight(), 0.3);
        assert_eq!(SignalKind::Mac.weight(), 0.1);
    }

    #[test]
    fn signal_kind_strings_round_trip() {
        for k in [
            SignalKind::UserAssigned,
            SignalKind::MdnsName,
            SignalKind::DhcpHostname,
            SignalKind::ReverseDns,
            SignalKind::NetbiosName,
            SignalKind::SsdpFriendlyName,
            SignalKind::Vendor,
            SignalKind::Mac,
            SignalKind::MdnsService,
        ] {
            assert_eq!(SignalKind::from_str_opt(k.as_str()), Some(k));
        }
        assert_eq!(SignalKind::from_str_opt("nonsense"), None);
    }

    #[test]
    fn device_state_round_trips_and_defaults_offline() {
        for s in [DeviceState::Online, DeviceState::Idle, DeviceState::Offline] {
            assert_eq!(DeviceState::from_db(s.as_str()), s);
        }
        assert_eq!(DeviceState::from_db("garbage"), DeviceState::Offline);
    }
}
