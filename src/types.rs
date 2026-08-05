//! Core value types shared by every layer of the daemon.
//!
//! A [`MacAddr`] is the identity key for a device, an [`Observation`] is the
//! single currency the capture layer produces, and a [`Signal`] is one piece of
//! identity evidence attached to an observation. Nothing here touches the
//! network or the database, which is what makes the whole layer trivially
//! testable.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
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
/// the single source of truth for scoring.
///
/// Kinds split into two groups. **Naming** kinds carry a value a human would
/// recognise as the device's name and compete for the display identity at their
/// weight. **Classifying** kinds carry evidence about what the device *is*
/// rather than what it is called; they weigh zero, never compete for the display
/// name, and exist because [`crate::identity::classify`] needs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// A name a human typed in the Trovato UI. Absolute: it beats everything.
    UserAssigned,
    /// mDNS instance name, for example `Living Room Apple TV`.
    MdnsName,
    /// Hostname from a DHCP request option 12.
    DhcpHostname,
    /// PTR record for the device's current IP.
    ReverseDns,
    /// NetBIOS name service announcement.
    NetbiosName,
    /// A friendly name an SSDP responder volunteered in a header.
    ///
    /// Never fetched from the `LOCATION` description URL: that would be an HTTP
    /// GET to the monitored device. See `capture/ssdp.rs`.
    SsdpFriendlyName,
    /// The IEEE-registered vendor for the MAC prefix.
    Vendor,
    /// The bare MAC address, the identity of last resort.
    Mac,
    /// An mDNS service type the device advertises, for example `_airplay._tcp`.
    ///
    /// Not a name, so it never competes for the display identity and carries
    /// weight zero. It is the strongest single input to device-type
    /// classification.
    MdnsService,
    /// A hardware or OS model string from an mDNS `_device-info._tcp` TXT
    /// record, for example `MacBookPro18,1`. Classifying, weight zero.
    MdnsModel,
    /// The DHCP option 55 parameter request list, rendered as comma-separated
    /// decimal option numbers.
    ///
    /// This is the DHCP fingerprint. It classifies an operating system and it
    /// never names anything, so it weighs zero.
    DhcpFingerprint,
    /// The DHCP option 60 vendor class identifier, for example `MSFT 5.0` or
    /// `android-dhcp-14`. Classifying, weight zero.
    DhcpVendorClass,
    /// An SSDP `NT`/`ST` device type URN, for example
    /// `urn:schemas-upnp-org:device:MediaRenderer:1`. Classifying, weight zero.
    SsdpDeviceType,
    /// An SSDP `SERVER` header, which names the OS and the UPnP stack.
    /// Classifying, weight zero.
    SsdpServer,
    /// A NetBIOS workgroup or domain name. Classifying, weight zero: it names
    /// the network the device belongs to, not the device.
    NetbiosWorkgroup,
    /// A role a device revealed through IPv6 Neighbor Discovery. Currently only
    /// `router`, from a Router Advertisement, which is the least ambiguous
    /// passive device-type evidence there is. Classifying, weight zero.
    NdpRole,
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
            // Classifying kinds. They describe what a device is, never what it
            // is called, so they must never win the display identity.
            SignalKind::MdnsService
            | SignalKind::MdnsModel
            | SignalKind::DhcpFingerprint
            | SignalKind::DhcpVendorClass
            | SignalKind::SsdpDeviceType
            | SignalKind::SsdpServer
            | SignalKind::NetbiosWorkgroup
            | SignalKind::NdpRole => 0.0,
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
            SignalKind::MdnsModel => "mdns_model",
            SignalKind::DhcpFingerprint => "dhcp_fingerprint",
            SignalKind::DhcpVendorClass => "dhcp_vendor_class",
            SignalKind::SsdpDeviceType => "ssdp_device_type",
            SignalKind::SsdpServer => "ssdp_server",
            SignalKind::NetbiosWorkgroup => "netbios_workgroup",
            SignalKind::NdpRole => "ndp_role",
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
            "mdns_model" => SignalKind::MdnsModel,
            "dhcp_fingerprint" => SignalKind::DhcpFingerprint,
            "dhcp_vendor_class" => SignalKind::DhcpVendorClass,
            "ssdp_device_type" => SignalKind::SsdpDeviceType,
            "ssdp_server" => SignalKind::SsdpServer,
            "netbios_workgroup" => SignalKind::NetbiosWorkgroup,
            "ndp_role" => SignalKind::NdpRole,
            _ => return None,
        })
    }

    /// Every kind, for exhaustiveness tests and for the round-trip guard.
    pub const ALL: [SignalKind; 16] = [
        SignalKind::UserAssigned,
        SignalKind::MdnsName,
        SignalKind::DhcpHostname,
        SignalKind::ReverseDns,
        SignalKind::NetbiosName,
        SignalKind::SsdpFriendlyName,
        SignalKind::Vendor,
        SignalKind::Mac,
        SignalKind::MdnsService,
        SignalKind::MdnsModel,
        SignalKind::DhcpFingerprint,
        SignalKind::DhcpVendorClass,
        SignalKind::SsdpDeviceType,
        SignalKind::SsdpServer,
        SignalKind::NetbiosWorkgroup,
        SignalKind::NdpRole,
    ];
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

/// Which ARP operation a frame carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArpOp {
    /// "Who has this address?"
    Request,
    /// "I have this address."
    Reply,
}

/// The ARP fields the security analyzers need and the state machine does not.
///
/// The device manager works from [`Observation::mac`] and [`Observation::ip`],
/// which deliberately collapse an ARP packet down to "this MAC was present at
/// this address". Detecting a scan needs the *target* address, and detecting a
/// spoof needs the sender's claim as the sender made it, so both survive here
/// rather than being reconstructed later from something lossier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArpDetail {
    /// Request or reply.
    pub op: ArpOp,
    /// Hardware address in the ARP sender field, which a spoofer may set to
    /// something other than the Ethernet source.
    pub sender_mac: MacAddr,
    /// Sender protocol address. `None` for an ARP probe, whose sender address is
    /// `0.0.0.0`.
    pub sender_ip: Option<Ipv4Addr>,
    /// Target protocol address: the address being asked about in a request, and
    /// the address being answered to in a reply.
    pub target_ip: Ipv4Addr,
    /// True when sender and target protocol addresses are the same, which makes
    /// the packet an announcement rather than a question.
    pub gratuitous: bool,
}

/// DHCP message types, from option 53.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DhcpMessageType {
    /// Client looking for any server.
    Discover,
    /// Server offering a lease.
    Offer,
    /// Client asking for a specific lease.
    Request,
    /// Client refusing an address it found already in use.
    Decline,
    /// Server confirming a lease.
    Ack,
    /// Server refusing a lease.
    Nak,
    /// Client giving up a lease.
    Release,
    /// Client asking for configuration without a lease.
    Inform,
}

impl DhcpMessageType {
    /// Reads a message type from an option 53 value.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => DhcpMessageType::Discover,
            2 => DhcpMessageType::Offer,
            3 => DhcpMessageType::Request,
            4 => DhcpMessageType::Decline,
            5 => DhcpMessageType::Ack,
            6 => DhcpMessageType::Nak,
            7 => DhcpMessageType::Release,
            8 => DhcpMessageType::Inform,
            _ => return None,
        })
    }

    /// True for the message types only a DHCP server sends.
    ///
    /// This is the whole basis of rogue-server detection: a client that emits
    /// one of these is not a client.
    #[must_use]
    pub const fn is_server_message(&self) -> bool {
        matches!(
            self,
            DhcpMessageType::Offer | DhcpMessageType::Ack | DhcpMessageType::Nak
        )
    }

    /// Stable short name, used in event details.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            DhcpMessageType::Discover => "discover",
            DhcpMessageType::Offer => "offer",
            DhcpMessageType::Request => "request",
            DhcpMessageType::Decline => "decline",
            DhcpMessageType::Ack => "ack",
            DhcpMessageType::Nak => "nak",
            DhcpMessageType::Release => "release",
            DhcpMessageType::Inform => "inform",
        }
    }
}

/// The DHCP fields the security analyzers and the gateway tracker need.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DhcpDetail {
    /// Option 53 message type.
    pub message_type: DhcpMessageType,
    /// The client the message is about, from the BOOTP `chaddr` field. For a
    /// server message this is somebody other than the transmitter.
    pub client_mac: Option<MacAddr>,
    /// Address the server offered or acknowledged, from `yiaddr`.
    pub assigned_ip: Option<Ipv4Addr>,
    /// Option 3, the default gateway the server is handing out. The most
    /// authoritative passive source of the gateway address there is.
    pub router: Option<Ipv4Addr>,
}

/// Protocol-specific detail attached to an observation.
///
/// Only protocols with something a security analyzer needs carry one. Everything
/// else leaves it `None`, and the device state machine ignores it entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolDetail {
    /// ARP sender and target fields.
    Arp(ArpDetail),
    /// DHCP message type and lease fields.
    Dhcp(DhcpDetail),
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
    /// Protocol fields the security analyzers need, when the protocol has any.
    pub detail: Option<ProtocolDetail>,
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
            detail: None,
            observed_at,
        }
    }

    /// Attaches one signal, builder style.
    #[must_use]
    pub fn with_signal(mut self, signal: Signal) -> Self {
        self.signals.push(signal);
        self
    }

    /// Attaches protocol detail, builder style.
    #[must_use]
    pub const fn with_detail(mut self, detail: ProtocolDetail) -> Self {
        self.detail = Some(detail);
        self
    }

    /// The ARP detail, when this observation came from an ARP frame.
    #[must_use]
    pub const fn arp(&self) -> Option<&ArpDetail> {
        match &self.detail {
            Some(ProtocolDetail::Arp(arp)) => Some(arp),
            _ => None,
        }
    }

    /// The DHCP detail, when this observation came from a DHCP message.
    #[must_use]
    pub const fn dhcp(&self) -> Option<&DhcpDetail> {
        match &self.detail {
            Some(ProtocolDetail::Dhcp(dhcp)) => Some(dhcp),
            _ => None,
        }
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

/// How loudly a notification about an event should arrive.
///
/// The dispatcher decides *whether* to deliver; this decides *how*. A transport
/// that has no notion of priority ignores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventPriority {
    /// The transport's configured default.
    Normal,
    /// Above the default: worth interrupting for.
    High,
    /// The transport's maximum: worth waking somebody for.
    Urgent,
}

impl EventPriority {
    /// Stable string, used in config and in event details.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            EventPriority::Normal => "normal",
            EventPriority::High => "high",
            EventPriority::Urgent => "urgent",
        }
    }
}

impl fmt::Display for EventPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A device state change worth telling somebody about.
///
/// These are the rows that land in `ng_events` and the messages that ride the
/// event bus to the notifier.
///
/// The last six variants are **security** events, produced by the analyzer chain
/// rather than by the device state machine. [`EventType::is_security`] is the
/// single test for that, and everything downstream that treats them differently
/// (priority, quiet-hours bypass, learning-window suppression) asks it rather
/// than keeping its own list.
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
    /// One MAC asked about an implausible number of distinct addresses.
    ArpScan,
    /// A MAC claimed an address that a different, still-active MAC holds.
    ArpSpoof,
    /// A DHCP server answered from a MAC that is not the known server.
    RogueDhcp,
    /// A device reclassified into a different device type or OS family.
    IdentityChange,
    /// Two active MACs are using the same address at the same time.
    IpConflict,
    /// One MAC emitted a flood of gratuitous ARP announcements.
    GratuitousArp,
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
            EventType::ArpScan => "arp_scan",
            EventType::ArpSpoof => "arp_spoof",
            EventType::RogueDhcp => "rogue_dhcp",
            EventType::IdentityChange => "identity_change",
            EventType::IpConflict => "ip_conflict",
            EventType::GratuitousArp => "gratuitous_arp",
        }
    }

    /// True for events the analyzer chain produces.
    ///
    /// Security events are recorded and delivered under different rules from
    /// device-lifecycle events: they are never suppressed by a learning window,
    /// they do not have to appear in `notify.event_types`, and by default they
    /// bypass quiet hours, the per-device debounce and the batch window.
    #[must_use]
    pub const fn is_security(&self) -> bool {
        matches!(
            self,
            EventType::ArpScan
                | EventType::ArpSpoof
                | EventType::RogueDhcp
                | EventType::IdentityChange
                | EventType::IpConflict
                | EventType::GratuitousArp
        )
    }

    /// Every event type, for exhaustiveness tests.
    pub const ALL: [EventType; 11] = [
        EventType::NewDevice,
        EventType::Returned,
        EventType::IpChanged,
        EventType::WentOffline,
        EventType::NameUpdated,
        EventType::ArpScan,
        EventType::ArpSpoof,
        EventType::RogueDhcp,
        EventType::IdentityChange,
        EventType::IpConflict,
        EventType::GratuitousArp,
    ];
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

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
        for k in SignalKind::ALL {
            assert_eq!(SignalKind::from_str_opt(k.as_str()), Some(k));
        }
        assert_eq!(SignalKind::from_str_opt("nonsense"), None);
    }

    #[test]
    fn every_signal_kind_string_is_distinct() {
        // A collision would silently merge two kinds of evidence in
        // ng_device_signals, whose unique key includes signal_type.
        let names: std::collections::HashSet<&str> =
            SignalKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(names.len(), SignalKind::ALL.len());
    }

    #[test]
    fn classifying_signals_never_compete_for_the_display_name() {
        for k in [
            SignalKind::MdnsService,
            SignalKind::MdnsModel,
            SignalKind::DhcpFingerprint,
            SignalKind::DhcpVendorClass,
            SignalKind::SsdpDeviceType,
            SignalKind::SsdpServer,
            SignalKind::NetbiosWorkgroup,
            SignalKind::NdpRole,
        ] {
            assert_eq!(k.weight(), 0.0, "{k:?} must not be a naming signal");
        }
    }

    #[test]
    fn exactly_the_six_analyzer_events_are_security_events() {
        let security: Vec<&str> = EventType::ALL
            .iter()
            .filter(|e| e.is_security())
            .map(EventType::as_str)
            .collect();
        assert_eq!(
            security,
            vec![
                "arp_scan",
                "arp_spoof",
                "rogue_dhcp",
                "identity_change",
                "ip_conflict",
                "gratuitous_arp"
            ]
        );
        for lifecycle in [
            EventType::NewDevice,
            EventType::Returned,
            EventType::IpChanged,
            EventType::WentOffline,
            EventType::NameUpdated,
        ] {
            assert!(
                !lifecycle.is_security(),
                "{lifecycle} is not a security event"
            );
        }
    }

    #[test]
    fn every_event_type_string_is_distinct() {
        let names: std::collections::HashSet<&str> =
            EventType::ALL.iter().map(|e| e.as_str()).collect();
        assert_eq!(names.len(), EventType::ALL.len());
    }

    #[test]
    fn dhcp_server_messages_are_exactly_the_three_a_client_cannot_send() {
        let server: Vec<&str> = [
            DhcpMessageType::Discover,
            DhcpMessageType::Offer,
            DhcpMessageType::Request,
            DhcpMessageType::Decline,
            DhcpMessageType::Ack,
            DhcpMessageType::Nak,
            DhcpMessageType::Release,
            DhcpMessageType::Inform,
        ]
        .into_iter()
        .filter(DhcpMessageType::is_server_message)
        .map(|m| m.as_str())
        .collect();
        assert_eq!(server, vec!["offer", "ack", "nak"]);
    }

    #[test]
    fn dhcp_message_codes_map_to_the_rfc_2132_numbers() {
        assert_eq!(
            DhcpMessageType::from_code(1),
            Some(DhcpMessageType::Discover)
        );
        assert_eq!(DhcpMessageType::from_code(5), Some(DhcpMessageType::Ack));
        assert_eq!(DhcpMessageType::from_code(8), Some(DhcpMessageType::Inform));
        assert_eq!(DhcpMessageType::from_code(0), None);
        assert_eq!(DhcpMessageType::from_code(9), None);
        assert_eq!(DhcpMessageType::from_code(255), None);
    }

    #[test]
    fn protocol_detail_accessors_do_not_confuse_the_two_protocols() {
        let ts = Utc.timestamp_opt(0, 0).single().expect("epoch");
        let arp = Observation::new(
            "3c:22:fb:00:00:01".parse().expect("mac"),
            None,
            "eth0",
            "arp",
            ObservationKind::Request,
            ts,
        )
        .with_detail(ProtocolDetail::Arp(ArpDetail {
            op: ArpOp::Request,
            sender_mac: "3c:22:fb:00:00:01".parse().expect("mac"),
            sender_ip: Some(Ipv4Addr::new(192, 168, 1, 40)),
            target_ip: Ipv4Addr::new(192, 168, 1, 1),
            gratuitous: false,
        }));
        assert!(arp.arp().is_some());
        assert!(arp.dhcp().is_none());

        let bare = Observation::new(
            "3c:22:fb:00:00:01".parse().expect("mac"),
            None,
            "eth0",
            "mdns",
            ObservationKind::Query,
            ts,
        );
        assert!(bare.arp().is_none());
        assert!(bare.dhcp().is_none());
    }

    #[test]
    fn device_state_round_trips_and_defaults_offline() {
        for s in [DeviceState::Online, DeviceState::Idle, DeviceState::Offline] {
            assert_eq!(DeviceState::from_db(s.as_str()), s);
        }
        assert_eq!(DeviceState::from_db("garbage"), DeviceState::Offline);
    }
}
