//! Configuration, assembled by figment with a fixed precedence.
//!
//! Highest wins: **CLI flags**, then environment (`NETGRASP_` prefixed, `__`
//! separating nesting levels, e.g. `NETGRASP_DATABASE__URL`), then
//! `netgrasp.toml`, then the compiled defaults in this file.
//!
//! Durations are written as human strings (`30m`, `180m`, `24h`, `90s`) and a
//! bare integer means seconds. That form survives all four layers unchanged,
//! which is the reason it is a string rather than a serde-native number.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use figment::providers::{Env, Format, Serialized, Toml};
use figment::{Figment, value::Value};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Default file consulted when `--config` is not given.
pub const DEFAULT_CONFIG_FILE: &str = "netgrasp.toml";

/// A duration written as a human string in every configuration layer.
///
/// Accepts `s`, `m`, `h` and `d` suffixes, or a bare integer meaning seconds.
/// It serialises back to the same string form, so a round trip through figment
/// is lossless.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanDuration(pub Duration);

impl HumanDuration {
    /// Constructs from whole seconds.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        HumanDuration(Duration::from_secs(secs))
    }

    /// The wrapped [`Duration`].
    #[must_use]
    pub const fn get(&self) -> Duration {
        self.0
    }

    /// Whole seconds, saturating.
    #[must_use]
    pub const fn as_secs(&self) -> u64 {
        self.0.as_secs()
    }

    /// Parses `30m`, `2h`, `1d`, `90s`, or a bare integer meaning seconds.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty string, an unknown suffix, or a
    /// non-numeric magnitude.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            bail!("empty duration");
        }
        let (digits, unit) = match s.chars().last() {
            Some(c) if c.is_ascii_digit() => (s, 's'),
            Some(c) => (&s[..s.len() - c.len_utf8()], c.to_ascii_lowercase()),
            None => bail!("empty duration"),
        };
        let n: u64 = digits
            .trim()
            .parse()
            .with_context(|| format!("duration {s:?} has a non-numeric magnitude"))?;
        let secs = match unit {
            's' => n,
            'm' => n * 60,
            'h' => n * 3600,
            'd' => n * 86_400,
            other => bail!("duration {s:?} has unknown unit {other:?}, expected s, m, h or d"),
        };
        Ok(HumanDuration(Duration::from_secs(secs)))
    }

    /// Renders back to the most compact exact human form.
    #[must_use]
    pub fn to_human(&self) -> String {
        let s = self.0.as_secs();
        if s == 0 {
            return "0s".into();
        }
        for (unit, size) in [('d', 86_400u64), ('h', 3600), ('m', 60)] {
            if s.is_multiple_of(size) {
                return format!("{}{}", s / size, unit);
            }
        }
        format!("{s}s")
    }
}

impl Serialize for HumanDuration {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_human())
    }
}

impl<'de> Deserialize<'de> for HumanDuration {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        /// Accepts either the string form or a bare integer number of seconds,
        /// because TOML and the environment disagree about which they produce.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Str(String),
            Secs(u64),
        }
        match Raw::deserialize(de)? {
            Raw::Str(s) => HumanDuration::parse(&s).map_err(serde::de::Error::custom),
            Raw::Secs(n) => Ok(HumanDuration::from_secs(n)),
        }
    }
}

/// A wall-clock time of day, written `HH:MM`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ClockTime {
    /// Hour, 0 to 23.
    pub hour: u32,
    /// Minute, 0 to 59.
    pub minute: u32,
}

impl ClockTime {
    /// Minutes since local midnight, for interval comparisons.
    #[must_use]
    pub const fn minutes(&self) -> u32 {
        self.hour * 60 + self.minute
    }
}

impl TryFrom<String> for ClockTime {
    type Error = String;
    fn try_from(v: String) -> Result<Self, Self::Error> {
        let (h, m) = v
            .split_once(':')
            .ok_or_else(|| format!("time {v:?} is not HH:MM"))?;
        let hour: u32 = h.trim().parse().map_err(|_| format!("bad hour in {v:?}"))?;
        let minute: u32 = m
            .trim()
            .parse()
            .map_err(|_| format!("bad minute in {v:?}"))?;
        if hour > 23 || minute > 59 {
            return Err(format!("time {v:?} out of range"));
        }
        Ok(ClockTime { hour, minute })
    }
}

impl From<ClockTime> for String {
    fn from(v: ClockTime) -> Self {
        format!("{:02}:{:02}", v.hour, v.minute)
    }
}

/// Top-level daemon configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Postgres connection and pool settings.
    pub database: DatabaseConfig,
    /// Which interfaces and protocols to listen to.
    pub capture: CaptureConfig,
    /// State machine timeouts and flush cadence.
    pub state: StateConfig,
    /// Which identity signals to gather.
    pub identity: IdentityConfig,
    /// Baseline learning window behaviour.
    pub learning: LearningConfig,
    /// Notification dispatch and delivery.
    pub notify: NotifyConfig,
    /// The security analyzer chain.
    pub security: SecurityConfig,
}

/// Postgres connection settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseConfig {
    /// libpq-style connection URL.
    pub url: String,
    /// Maximum pooled connections. The daemon is not connection-hungry: the
    /// flush task and the CLI readers are the only consumers.
    pub pool_size: usize,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig {
            url: "postgres://netgrasp:netgrasp@localhost:5432/netgrasp".into(),
            pool_size: 4,
        }
    }
}

/// Capture layer settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CaptureConfig {
    /// Interfaces to listen on. Empty means every non-loopback interface that
    /// is up and has an address.
    pub interfaces: Vec<String>,
    /// Capture sources to start, by name. Milestone 1 implements `arp` and
    /// `mdns`; the rest are stubs that decline to start.
    pub sources: Vec<String>,
    /// Capacity of the observation channel. Full means the capture thread
    /// blocks, which is the correct backpressure: dropping packets silently
    /// would corrupt presence tracking.
    pub channel_capacity: usize,
    /// pcap snapshot length. mDNS announcements are the largest thing parsed
    /// and comfortably fit.
    pub snaplen: i32,
    /// pcap kernel buffer, in bytes.
    pub buffer_size: i32,
    /// Timestamp rounding, in seconds, used by the cross-interface dedup key.
    pub dedup_resolution_secs: u64,
    /// How many recent dedup keys to remember. Bounded so a busy network cannot
    /// grow the set without limit.
    pub dedup_capacity: usize,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        CaptureConfig {
            interfaces: Vec::new(),
            sources: vec!["arp".into(), "mdns".into()],
            channel_capacity: 4096,
            snaplen: 1600,
            buffer_size: 1 << 20,
            dedup_resolution_secs: 1,
            dedup_capacity: 8192,
        }
    }
}

/// State machine timings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StateConfig {
    /// Silence after which an online device becomes idle.
    pub idle_timeout: HumanDuration,
    /// Silence after which an idle device becomes offline.
    pub offline_timeout: HumanDuration,
    /// How often in-memory `last_seen_at` values are flushed to Postgres. A
    /// crash loses at most this much timestamp precision, never a state change.
    pub flush_interval: HumanDuration,
    /// How often the sweep looks for devices that have timed out.
    pub sweep_interval: HumanDuration,
    /// Per-device-type overrides, keyed by `device_type`.
    pub device_type_overrides: BTreeMap<String, TimeoutOverride>,
}

impl Default for StateConfig {
    fn default() -> Self {
        let mut overrides = BTreeMap::new();
        overrides.insert(
            "router".to_string(),
            TimeoutOverride {
                idle_timeout: Some(HumanDuration::from_secs(24 * 3600)),
                offline_timeout: Some(HumanDuration::from_secs(24 * 3600)),
            },
        );
        overrides.insert(
            "printer".to_string(),
            TimeoutOverride {
                idle_timeout: Some(HumanDuration::from_secs(12 * 3600)),
                offline_timeout: Some(HumanDuration::from_secs(12 * 3600)),
            },
        );
        StateConfig {
            idle_timeout: HumanDuration::from_secs(30 * 60),
            offline_timeout: HumanDuration::from_secs(180 * 60),
            flush_interval: HumanDuration::from_secs(60),
            sweep_interval: HumanDuration::from_secs(30),
            device_type_overrides: overrides,
        }
    }
}

impl StateConfig {
    /// Effective idle timeout for a device of the given type.
    #[must_use]
    pub fn idle_timeout_for(&self, device_type: Option<&str>) -> Duration {
        device_type
            .and_then(|t| self.device_type_overrides.get(t))
            .and_then(|o| o.idle_timeout)
            .unwrap_or(self.idle_timeout)
            .get()
    }

    /// Effective offline timeout for a device of the given type.
    ///
    /// An override that pushes idle past offline would make the idle state
    /// unreachable, so the result is never less than the effective idle
    /// timeout.
    #[must_use]
    pub fn offline_timeout_for(&self, device_type: Option<&str>) -> Duration {
        let base = device_type
            .and_then(|t| self.device_type_overrides.get(t))
            .and_then(|o| o.offline_timeout)
            .unwrap_or(self.offline_timeout)
            .get();
        base.max(self.idle_timeout_for(device_type))
    }
}

/// One device type's timeout overrides. Either field may be omitted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TimeoutOverride {
    /// Overrides [`StateConfig::idle_timeout`] for this device type.
    pub idle_timeout: Option<HumanDuration>,
    /// Overrides [`StateConfig::offline_timeout`] for this device type.
    pub offline_timeout: Option<HumanDuration>,
}

/// Which identity signals to collect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityConfig {
    /// Look the MAC prefix up in the embedded IEEE registry.
    pub oui: bool,
    /// Resolve PTR records for observed addresses.
    ///
    /// Off by default because it is the one thing the daemon does that puts
    /// packets on a wire. The queries go to the configured resolver, never to
    /// the monitored device, but "passive" deserves an explicit opt-in.
    pub reverse_dns: bool,
    /// How long before a reverse lookup for the same address is retried.
    pub reverse_dns_ttl: HumanDuration,
    /// Where `netgraspd update-fingerprints` writes its download, and where the
    /// daemon looks for a fingerprint table before falling back to the copy
    /// compiled into the binary.
    ///
    /// A missing file is not an error: the embedded table is the normal case and
    /// the daemon never downloads on its own.
    pub fingerprint_path: PathBuf,
    /// Where `netgraspd update-fingerprints` downloads from when no URL is
    /// given on the command line.
    pub fingerprint_url: String,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        IdentityConfig {
            oui: true,
            reverse_dns: false,
            reverse_dns_ttl: HumanDuration::from_secs(3600),
            fingerprint_path: PathBuf::from("/var/lib/netgraspd/dhcp_fingerprints.conf"),
            fingerprint_url: String::new(),
        }
    }
}

/// Baseline learning window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LearningConfig {
    /// Run a learning window automatically when `ng_devices` is empty.
    pub on_first_run: bool,
    /// How long the window lasts.
    pub duration: HumanDuration,
}

impl Default for LearningConfig {
    fn default() -> Self {
        LearningConfig {
            on_first_run: true,
            duration: HumanDuration::from_secs(5 * 60),
        }
    }
}

/// Notification dispatch settings. Rate limiting lives here, in the dispatcher,
/// not in any individual notifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotifyConfig {
    /// Master switch. Off means events are still recorded, just not delivered.
    pub enabled: bool,
    /// Minimum gap between two notifications about the same device.
    pub debounce: HumanDuration,
    /// How many devices appearing inside `batch_window` collapse into one
    /// summary notification. Covers the network-restart case.
    pub batch_threshold: usize,
    /// The window over which `batch_threshold` is counted.
    pub batch_window: HumanDuration,
    /// Which event types are worth a notification at all.
    pub event_types: Vec<String>,
    /// Optional daily quiet period.
    pub quiet_hours: Option<QuietHours>,
    /// ntfy.sh delivery settings. Absent means no notifier is configured.
    pub ntfy: Option<NtfyConfig>,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        NotifyConfig {
            enabled: true,
            debounce: HumanDuration::from_secs(5 * 60),
            batch_threshold: 10,
            batch_window: HumanDuration::from_secs(60),
            event_types: vec!["new_device".into(), "returned".into()],
            quiet_hours: None,
            ntfy: None,
        }
    }
}

/// A daily period during which notifications are held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuietHours {
    /// When the quiet period begins, local time.
    pub start: ClockTime,
    /// When it ends, local time. May be earlier than `start`, meaning the
    /// period wraps midnight.
    pub end: ClockTime,
}

impl QuietHours {
    /// True when the given local time falls inside the quiet period.
    ///
    /// The interval is half-open, `[start, end)`, so a period configured as
    /// `22:00` to `07:00` covers 22:00 through 06:59 and releases at 07:00.
    #[must_use]
    pub fn contains(&self, now_minutes: u32) -> bool {
        let (s, e) = (self.start.minutes(), self.end.minutes());
        if s == e {
            // A zero-length window silences nothing, which is the least
            // surprising reading of start == end.
            false
        } else if s < e {
            now_minutes >= s && now_minutes < e
        } else {
            now_minutes >= s || now_minutes < e
        }
    }
}

/// ntfy.sh delivery settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NtfyConfig {
    /// Topic to publish to. Required; an empty topic disables the notifier.
    pub topic: String,
    /// Server base URL, for self-hosted ntfy.
    pub server: String,
    /// Priority for ordinary events, 1 (min) to 5 (max).
    pub priority: u8,
    /// Priority for events that bypass quiet hours.
    pub urgent_priority: u8,
    /// Optional bearer token for protected topics.
    pub token: Option<String>,
    /// Per-request timeout.
    pub timeout: HumanDuration,
}

impl Default for NtfyConfig {
    fn default() -> Self {
        NtfyConfig {
            topic: String::new(),
            server: "https://ntfy.sh".into(),
            priority: 3,
            urgent_priority: 5,
            token: None,
            timeout: HumanDuration::from_secs(10),
        }
    }
}

/// The security analyzer chain.
///
/// Every analyzer can be switched off individually, because a network with a
/// legitimate scanner on it (a monitoring box, a vulnerability scanner) would
/// otherwise generate one alert per sweep forever, and an operator who cannot
/// silence one detector silences all of them.
///
/// Addresses are held as strings rather than parsed types so that a malformed
/// entry produces a configuration error naming the key, rather than a figment
/// deserialisation message about a type nobody wrote in the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    /// Master switch for the whole chain.
    pub enabled: bool,
    /// The gateway's hardware address. Empty means "work it out from traffic".
    pub gateway_mac: String,
    /// The gateway's address. Empty means "work it out from traffic".
    pub gateway_ip: String,
    /// MAC addresses no analyzer alerts on. For the monitoring box that is
    /// meant to sweep the network.
    pub exempt_macs: Vec<String>,
    /// How many MACs or addresses each analyzer tracks before evicting the
    /// least recently seen. Bounds memory on a hostile network: a scanner
    /// forging a new source MAC per packet must not be able to grow the daemon.
    pub max_tracked: usize,
    /// Detection of one MAC sweeping the address space.
    pub arp_scan: ArpScanConfig,
    /// Detection of a MAC claiming somebody else's address.
    pub arp_spoof: ArpSpoofConfig,
    /// Detection of an unexpected DHCP server.
    pub rogue_dhcp: RogueDhcpConfig,
    /// Detection of a device changing what it appears to be.
    pub identity_change: IdentityChangeConfig,
    /// Detection of two devices using one address.
    pub ip_conflict: IpConflictConfig,
    /// Detection of a gratuitous ARP flood.
    pub gratuitous_arp: GratuitousArpConfig,
    /// How security events are delivered, overriding the ordinary rules.
    pub notifications: SecurityNotifyConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            enabled: true,
            gateway_mac: String::new(),
            gateway_ip: String::new(),
            exempt_macs: Vec::new(),
            max_tracked: 4096,
            arp_scan: ArpScanConfig::default(),
            arp_spoof: ArpSpoofConfig::default(),
            rogue_dhcp: RogueDhcpConfig::default(),
            identity_change: IdentityChangeConfig::default(),
            ip_conflict: IpConflictConfig::default(),
            gratuitous_arp: GratuitousArpConfig::default(),
            notifications: SecurityNotifyConfig::default(),
        }
    }
}

impl SecurityConfig {
    /// The configured gateway MAC, if one was set and it parses.
    #[must_use]
    pub fn gateway_mac(&self) -> Option<crate::types::MacAddr> {
        parse_optional(&self.gateway_mac)
    }

    /// The configured gateway address, if one was set and it parses.
    #[must_use]
    pub fn gateway_ip(&self) -> Option<std::net::Ipv4Addr> {
        parse_optional(&self.gateway_ip)
    }

    /// The exemption list, as parsed addresses.
    #[must_use]
    pub fn exempt_macs(&self) -> Vec<crate::types::MacAddr> {
        self.exempt_macs
            .iter()
            .filter_map(|m| m.trim().parse().ok())
            .collect()
    }

    /// Rejects unusable combinations.
    ///
    /// # Errors
    ///
    /// Returns an error for an unparseable address, a zero window or threshold,
    /// or an unknown identity sensitivity.
    pub fn validate(&self) -> Result<()> {
        check_optional::<crate::types::MacAddr>(&self.gateway_mac, "security.gateway_mac")?;
        check_optional::<std::net::Ipv4Addr>(&self.gateway_ip, "security.gateway_ip")?;
        for (i, mac) in self.exempt_macs.iter().enumerate() {
            if mac.trim().parse::<crate::types::MacAddr>().is_err() {
                bail!("security.exempt_macs[{i}] is not a MAC address: {mac:?}");
            }
        }
        for (i, mac) in self.rogue_dhcp.known_servers.iter().enumerate() {
            if mac.trim().parse::<crate::types::MacAddr>().is_err() {
                bail!("security.rogue_dhcp.known_servers[{i}] is not a MAC address: {mac:?}");
            }
        }
        if self.max_tracked == 0 {
            bail!("security.max_tracked must be at least 1");
        }
        if self.arp_scan.window.as_secs() == 0 {
            bail!("security.arp_scan.window must be at least 1s");
        }
        if self.arp_scan.threshold == 0 {
            bail!("security.arp_scan.threshold must be at least 1");
        }
        if self.gratuitous_arp.window.as_secs() == 0 {
            bail!("security.gratuitous_arp.window must be at least 1s");
        }
        if self.gratuitous_arp.threshold == 0 {
            bail!("security.gratuitous_arp.threshold must be at least 1");
        }
        if self.ip_conflict.active_within.as_secs() == 0 {
            bail!("security.ip_conflict.active_within must be at least 1s");
        }
        if !matches!(
            self.identity_change.sensitivity.as_str(),
            "category" | "any"
        ) {
            bail!(
                "security.identity_change.sensitivity must be \"category\" or \"any\", not {:?}",
                self.identity_change.sensitivity
            );
        }
        Ok(())
    }
}

/// Parses an optional address field, treating blank as absent.
fn parse_optional<T: std::str::FromStr>(raw: &str) -> Option<T> {
    let trimmed = raw.trim();
    (!trimmed.is_empty())
        .then(|| trimmed.parse().ok())
        .flatten()
}

/// Confirms an optional address field is blank or parseable.
fn check_optional<T: std::str::FromStr>(raw: &str, key: &str) -> Result<()> {
    let trimmed = raw.trim();
    if !trimmed.is_empty() && trimmed.parse::<T>().is_err() {
        bail!("{key} is not a valid address: {trimmed:?}");
    }
    Ok(())
}

/// The `arp_scan` analyzer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ArpScanConfig {
    /// Whether the analyzer runs.
    pub enabled: bool,
    /// Sliding window over which distinct targets are counted.
    pub window: HumanDuration,
    /// Distinct target addresses inside the window that constitute a scan.
    pub threshold: usize,
    /// The same, for the gateway and anything in `exempt_macs`.
    ///
    /// A router legitimately ARPs for everything it forwards to, so holding it
    /// to the same threshold as a laptop produces one alert per minute forever.
    pub gateway_threshold: usize,
}

impl Default for ArpScanConfig {
    fn default() -> Self {
        ArpScanConfig {
            enabled: true,
            window: HumanDuration::from_secs(30),
            threshold: 10,
            gateway_threshold: 100,
        }
    }
}

/// The `arp_spoof` analyzer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ArpSpoofConfig {
    /// Whether the analyzer runs.
    pub enabled: bool,
    /// How recently the previous holder must have been heard from for a new
    /// claim to be a spoof rather than a DHCP reassignment.
    ///
    /// This is the whole difference between a security tool and a nuisance. A
    /// device goes offline, its lease expires, the address is handed to
    /// somebody else, and nothing is wrong. Only a claim on an address whose
    /// current holder is *still talking* is an attack.
    pub grace_period: HumanDuration,
}

impl Default for ArpSpoofConfig {
    fn default() -> Self {
        ArpSpoofConfig {
            enabled: true,
            grace_period: HumanDuration::from_secs(60),
        }
    }
}

/// The `rogue_dhcp` analyzer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RogueDhcpConfig {
    /// Whether the analyzer runs.
    pub enabled: bool,
    /// Hardware addresses that are allowed to answer DHCP.
    ///
    /// When empty the first server heard after startup is trusted, which is
    /// right on a healthy network and wrong on one where a rogue server is
    /// already running when the daemon starts. Listing the real server here is
    /// what closes that window.
    pub known_servers: Vec<String>,
}

impl Default for RogueDhcpConfig {
    fn default() -> Self {
        RogueDhcpConfig {
            enabled: true,
            known_servers: Vec::new(),
        }
    }
}

/// The `identity_change` analyzer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityChangeConfig {
    /// Whether the analyzer runs.
    pub enabled: bool,
    /// `category` fires only when a known device type or OS becomes a different
    /// known one. `any` also fires the first time a device is classified, which
    /// is noisy on a fresh install and useful when hunting.
    pub sensitivity: String,
}

impl Default for IdentityChangeConfig {
    fn default() -> Self {
        IdentityChangeConfig {
            enabled: true,
            sensitivity: "category".to_string(),
        }
    }
}

/// The `ip_conflict` analyzer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IpConflictConfig {
    /// Whether the analyzer runs.
    pub enabled: bool,
    /// How close together two MACs must use one address to count as
    /// simultaneous.
    pub active_within: HumanDuration,
}

impl Default for IpConflictConfig {
    fn default() -> Self {
        IpConflictConfig {
            enabled: true,
            active_within: HumanDuration::from_secs(60),
        }
    }
}

/// The gratuitous ARP flood analyzer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GratuitousArpConfig {
    /// Whether the analyzer runs.
    pub enabled: bool,
    /// Sliding window over which announcements are counted.
    pub window: HumanDuration,
    /// Announcements inside the window that constitute a flood.
    pub threshold: usize,
}

impl Default for GratuitousArpConfig {
    fn default() -> Self {
        GratuitousArpConfig {
            enabled: true,
            window: HumanDuration::from_secs(10),
            threshold: 5,
        }
    }
}

/// How security events are delivered.
///
/// Security events are not device-lifecycle events and the dispatcher's rules
/// for the latter are wrong for them. A rate limit that holds "somebody is
/// poisoning your ARP table" for five minutes because the same device was
/// mentioned recently is not a rate limit, it is a failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityNotifyConfig {
    /// Whether security events are delivered at all. They are recorded either
    /// way.
    pub enabled: bool,
    /// Priority to deliver them at, when the transport understands priority.
    pub priority: crate::types::EventPriority,
    /// Deliver during quiet hours.
    pub bypass_quiet_hours: bool,
    /// Ignore the per-device debounce.
    pub bypass_debounce: bool,
    /// Deliver immediately rather than waiting for the batch window to close.
    pub bypass_batch_window: bool,
}

impl Default for SecurityNotifyConfig {
    fn default() -> Self {
        SecurityNotifyConfig {
            enabled: true,
            priority: crate::types::EventPriority::Urgent,
            bypass_quiet_hours: true,
            bypass_debounce: true,
            bypass_batch_window: true,
        }
    }
}

/// A single CLI override, expressed as a dotted config path and a value.
///
/// The CLI layer builds these instead of a partial `Config`, because a partial
/// struct would serialise its `None` fields as nulls and clobber the layers
/// beneath it.
#[derive(Debug, Clone)]
pub struct Override {
    /// Dotted path, for example `database.url`.
    pub key: String,
    /// The value to place there.
    pub value: Value,
}

impl Override {
    /// Builds an override from anything figment can represent.
    pub fn new(key: impl Into<String>, value: impl Into<Value>) -> Self {
        Override {
            key: key.into(),
            value: value.into(),
        }
    }
}

impl Config {
    /// Assembles the configuration from all four layers.
    ///
    /// `config_path` is the file to read; when `None` the default file name is
    /// tried and silently skipped if absent.
    ///
    /// # Errors
    ///
    /// Returns an error when the file exists but cannot be parsed, when an
    /// environment variable holds an unusable value, or when the merged result
    /// fails validation.
    pub fn load(config_path: Option<&Path>, overrides: &[Override]) -> Result<Self> {
        let path =
            config_path.map_or_else(|| PathBuf::from(DEFAULT_CONFIG_FILE), Path::to_path_buf);
        let explicit = config_path.is_some();
        if explicit && !path.exists() {
            bail!("config file {} does not exist", path.display());
        }

        let mut figment = Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file(&path))
            .merge(Env::prefixed("NETGRASP_").split("__"));
        for ov in overrides {
            figment = figment.merge(Serialized::default(&ov.key, ov.value.clone()));
        }

        let config: Config = figment
            .extract()
            .context("failed to assemble configuration")?;
        config.validate()?;
        Ok(config)
    }

    /// Rejects combinations that would misbehave silently at runtime.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty database URL, a zero-capacity channel, an
    /// idle timeout at or beyond the offline timeout, a zero flush or sweep
    /// interval, or an out-of-range ntfy priority.
    pub fn validate(&self) -> Result<()> {
        if self.database.url.trim().is_empty() {
            bail!("database.url is empty");
        }
        if self.database.pool_size == 0 {
            bail!("database.pool_size must be at least 1");
        }
        if self.capture.channel_capacity == 0 {
            bail!("capture.channel_capacity must be at least 1");
        }
        if self.capture.sources.is_empty() {
            bail!("capture.sources is empty, so the daemon would observe nothing");
        }
        if self.state.idle_timeout.get() >= self.state.offline_timeout.get() {
            bail!(
                "state.idle_timeout ({}) must be shorter than state.offline_timeout ({}), \
                 otherwise the idle state is unreachable",
                self.state.idle_timeout.to_human(),
                self.state.offline_timeout.to_human()
            );
        }
        if self.state.flush_interval.as_secs() == 0 {
            bail!("state.flush_interval must be at least 1s");
        }
        if self.state.sweep_interval.as_secs() == 0 {
            bail!("state.sweep_interval must be at least 1s");
        }
        if self.learning.duration.as_secs() == 0 {
            bail!("learning.duration must be at least 1s");
        }
        if let Some(ntfy) = &self.notify.ntfy {
            if !(1..=5).contains(&ntfy.priority) || !(1..=5).contains(&ntfy.urgent_priority) {
                bail!("notify.ntfy priorities must be between 1 and 5");
            }
            if ntfy.server.trim().is_empty() {
                bail!("notify.ntfy.server is empty");
            }
        }
        self.security.validate()?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::result_large_err)] // Jail::expect_with fixes the closure's error type
// as figment::Error, which clippy considers oversized. Nothing here can change that.
mod tests {
    use super::*;
    use figment::Jail;

    #[test]
    fn duration_parses_every_unit() {
        assert_eq!(HumanDuration::parse("90s").expect("s").as_secs(), 90);
        assert_eq!(HumanDuration::parse("30m").expect("m").as_secs(), 1800);
        assert_eq!(HumanDuration::parse("2h").expect("h").as_secs(), 7200);
        assert_eq!(HumanDuration::parse("1d").expect("d").as_secs(), 86_400);
        assert_eq!(HumanDuration::parse("45").expect("bare").as_secs(), 45);
        assert_eq!(HumanDuration::parse(" 5m ").expect("padded").as_secs(), 300);
        assert_eq!(
            HumanDuration::parse("24H").expect("upper").as_secs(),
            86_400
        );
    }

    #[test]
    fn duration_rejects_junk() {
        for s in ["", "  ", "m", "5x", "five", "-5s"] {
            assert!(HumanDuration::parse(s).is_err(), "{s:?} should not parse");
        }
    }

    #[test]
    fn duration_renders_compactly() {
        assert_eq!(HumanDuration::from_secs(0).to_human(), "0s");
        assert_eq!(HumanDuration::from_secs(45).to_human(), "45s");
        assert_eq!(HumanDuration::from_secs(1800).to_human(), "30m");
        assert_eq!(HumanDuration::from_secs(7200).to_human(), "2h");
        assert_eq!(HumanDuration::from_secs(86_400).to_human(), "1d");
        assert_eq!(HumanDuration::from_secs(90).to_human(), "90s");
    }

    #[test]
    fn defaults_are_valid() {
        Config::default()
            .validate()
            .expect("defaults must validate");
    }

    #[test]
    fn defaults_load_with_no_file_and_no_env() {
        Jail::expect_with(|_| {
            let c = Config::load(None, &[]).expect("defaults load");
            assert_eq!(c, Config::default());
            Ok(())
        });
    }

    #[test]
    fn missing_explicit_config_file_is_an_error() {
        Jail::expect_with(|_| {
            let err = Config::load(Some(Path::new("nope.toml")), &[])
                .expect_err("explicit missing file must fail");
            assert!(err.to_string().contains("does not exist"), "{err}");
            Ok(())
        });
    }

    #[test]
    fn file_overrides_defaults() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "netgrasp.toml",
                r#"
                [database]
                url = "postgres://from-file/db"

                [state]
                idle_timeout = "10m"
                "#,
            )?;
            let c = Config::load(None, &[]).expect("load");
            assert_eq!(c.database.url, "postgres://from-file/db");
            assert_eq!(c.state.idle_timeout.as_secs(), 600);
            // Untouched keys keep their defaults.
            assert_eq!(c.state.offline_timeout.as_secs(), 180 * 60);
            Ok(())
        });
    }

    #[test]
    fn env_overrides_file() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "netgrasp.toml",
                r#"
                [database]
                url = "postgres://from-file/db"
                "#,
            )?;
            jail.set_env("NETGRASP_DATABASE__URL", "postgres://from-env/db");
            jail.set_env("NETGRASP_STATE__IDLE_TIMEOUT", "7m");
            let c = Config::load(None, &[]).expect("load");
            assert_eq!(c.database.url, "postgres://from-env/db");
            assert_eq!(c.state.idle_timeout.as_secs(), 420);
            Ok(())
        });
    }

    #[test]
    fn cli_overrides_env_and_file() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "netgrasp.toml",
                r#"
                [database]
                url = "postgres://from-file/db"
                "#,
            )?;
            jail.set_env("NETGRASP_DATABASE__URL", "postgres://from-env/db");
            let c = Config::load(
                None,
                &[Override::new("database.url", "postgres://from-cli/db")],
            )
            .expect("load");
            assert_eq!(c.database.url, "postgres://from-cli/db");
            Ok(())
        });
    }

    #[test]
    fn full_precedence_chain_in_one_assertion() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "netgrasp.toml",
                r#"
                [database]
                url = "file"
                pool_size = 7

                [capture]
                sources = ["arp"]

                [learning]
                duration = "9m"
                "#,
            )?;
            jail.set_env("NETGRASP_DATABASE__URL", "env");
            jail.set_env("NETGRASP_CAPTURE__SOURCES", "[\"arp\",\"mdns\"]");
            let c = Config::load(None, &[Override::new("learning.duration", "1m")]).expect("load");

            assert_eq!(c.database.url, "env", "env beats file");
            assert_eq!(c.database.pool_size, 7, "file beats default");
            assert_eq!(c.capture.snaplen, 1600, "default survives untouched");
            assert_eq!(c.capture.sources, vec!["arp", "mdns"], "env beats file");
            assert_eq!(c.learning.duration.as_secs(), 60, "cli beats file");
            Ok(())
        });
    }

    #[test]
    fn unknown_keys_are_rejected_rather_than_ignored() {
        Jail::expect_with(|jail| {
            jail.create_file("netgrasp.toml", "[database]\nurll = \"typo\"\n")?;
            assert!(
                Config::load(None, &[]).is_err(),
                "a typo must not be silently ignored"
            );
            Ok(())
        });
    }

    #[test]
    fn idle_beyond_offline_is_rejected() {
        let mut c = Config::default();
        c.state.idle_timeout = HumanDuration::from_secs(4000);
        c.state.offline_timeout = HumanDuration::from_secs(1000);
        let err = c.validate().expect_err("must reject");
        assert!(
            err.to_string().contains("idle state is unreachable"),
            "{err}"
        );
    }

    #[test]
    fn empty_source_list_is_rejected() {
        let mut c = Config::default();
        c.capture.sources.clear();
        assert!(c.validate().is_err());
    }

    #[test]
    fn device_type_overrides_apply_and_clamp() {
        let c = StateConfig::default();
        assert_eq!(c.idle_timeout_for(None), Duration::from_secs(1800));
        assert_eq!(
            c.idle_timeout_for(Some("router")),
            Duration::from_secs(86_400)
        );
        assert_eq!(
            c.offline_timeout_for(Some("printer")),
            Duration::from_secs(12 * 3600)
        );
        assert_eq!(
            c.idle_timeout_for(Some("unknown-type")),
            Duration::from_secs(1800),
            "an unknown type falls back to the global timeout"
        );

        // An override that would put idle past offline is clamped so that the
        // offline transition is never unreachable.
        let mut c = StateConfig::default();
        c.device_type_overrides.insert(
            "weird".into(),
            TimeoutOverride {
                idle_timeout: Some(HumanDuration::from_secs(9999)),
                offline_timeout: Some(HumanDuration::from_secs(10)),
            },
        );
        assert_eq!(
            c.offline_timeout_for(Some("weird")),
            Duration::from_secs(9999)
        );
    }

    #[test]
    fn quiet_hours_handle_the_midnight_wrap() {
        let qh = QuietHours {
            start: ClockTime {
                hour: 22,
                minute: 0,
            },
            end: ClockTime { hour: 7, minute: 0 },
        };
        assert!(qh.contains(22 * 60), "22:00 is the inclusive start");
        assert!(qh.contains(23 * 60 + 59));
        assert!(qh.contains(0));
        assert!(qh.contains(6 * 60 + 59));
        assert!(!qh.contains(7 * 60), "07:00 is the exclusive end");
        assert!(!qh.contains(12 * 60));
        assert!(!qh.contains(21 * 60 + 59));
    }

    #[test]
    fn quiet_hours_handle_the_same_day_case() {
        let qh = QuietHours {
            start: ClockTime {
                hour: 9,
                minute: 30,
            },
            end: ClockTime {
                hour: 17,
                minute: 0,
            },
        };
        assert!(!qh.contains(9 * 60 + 29));
        assert!(qh.contains(9 * 60 + 30));
        assert!(qh.contains(16 * 60 + 59));
        assert!(!qh.contains(17 * 60));
    }

    #[test]
    fn zero_length_quiet_window_silences_nothing() {
        let qh = QuietHours {
            start: ClockTime { hour: 3, minute: 0 },
            end: ClockTime { hour: 3, minute: 0 },
        };
        for m in [0, 179, 180, 181, 1439] {
            assert!(!qh.contains(m), "minute {m} must not be quiet");
        }
    }

    #[test]
    fn clock_time_parsing_rejects_out_of_range() {
        assert!(ClockTime::try_from("24:00".to_string()).is_err());
        assert!(ClockTime::try_from("12:60".to_string()).is_err());
        assert!(ClockTime::try_from("1200".to_string()).is_err());
        assert_eq!(
            ClockTime::try_from("07:05".to_string()).expect("valid"),
            ClockTime { hour: 7, minute: 5 }
        );
    }
}
