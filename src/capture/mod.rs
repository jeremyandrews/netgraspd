//! The capture layer: packets in, [`Observation`]s out.
//!
//! This is the only layer that touches libpcap, and it is the only layer that
//! needs elevated privilege. Everything below it works on plain byte slices,
//! which is why the parsers are unit-testable without a network.
//!
//! Netgrasp opens capture handles in **non-promiscuous** mode. It only wants
//! broadcast and multicast traffic, which the NIC delivers anyway, and leaving
//! promiscuous mode off is both less intrusive and less visible to anything
//! watching the segment.

pub mod arp;
pub mod dedup;
pub mod dhcp;
pub mod dns;
pub mod ethernet;
pub mod fixtures;
pub mod mdns;
pub mod names;
pub mod nbns;
pub mod ndp;
pub mod sample;
pub mod ssdp;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, TimeZone, Utc};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::config::CaptureConfig;
use crate::types::Observation;

pub use dedup::ObservationDedup;

/// How long a capture handle waits for a packet before returning control.
///
/// Belt and braces alongside non-blocking mode: libpcap does not honour this
/// consistently in immediate mode, which is why [`IDLE_POLL`] exists.
const POLL_TIMEOUT_MS: i32 = 250;

/// How long a capture thread sleeps when no packet is waiting.
///
/// This is the upper bound on how long one capture thread takes to notice that
/// the daemon is stopping, so it is also the floor on a clean shutdown.
const IDLE_POLL: std::time::Duration = std::time::Duration::from_millis(100);

/// Turns one captured frame into an observation, or discards it.
pub type FrameParser = fn(&[u8], &str, DateTime<Utc>) -> Option<Observation>;

/// A source of observations.
///
/// `run` takes `Box<Self>` rather than `self` so that a heterogeneous list of
/// sources can be held as trait objects and still be consumed when started; the
/// consuming-`self` shape is otherwise not object safe.
pub trait CaptureSource: Send {
    /// Short stable name, used in logs and in the configured source list.
    fn name(&self) -> &str;

    /// Starts the source.
    ///
    /// The returned handle resolves when every interface thread has stopped,
    /// which happens when `shutdown` goes true or when a capture handle fails
    /// unrecoverably. A thread that fails is reported on `failures` the moment
    /// it ends, while the others keep running; the handle does not repeat it.
    fn run(
        self: Box<Self>,
        tx: mpsc::Sender<Observation>,
        failures: mpsc::Sender<CaptureFailure>,
        shutdown: watch::Receiver<bool>,
    ) -> JoinHandle<Result<()>>;
}

/// A capture source backed by a BPF-filtered pcap handle per interface.
///
/// Both implemented sources are this type with a different filter and parser,
/// because the difference between watching ARP and watching mDNS really is only
/// those two things.
pub struct PcapSource {
    name: &'static str,
    filter: &'static str,
    parser: FrameParser,
    interfaces: Vec<String>,
    snaplen: i32,
    buffer_size: i32,
    tap: Tap,
}

/// What the capture threads hand over besides observations: the visibility
/// counts, always, and a copy of each frame for the unknown-device sample, when
/// it is on.
///
/// Both are taken before any parser looks at the frame, because both are about
/// what reached this machine rather than what could be understood.
#[derive(Debug, Clone, Default)]
pub struct Tap {
    /// Frames, distinct senders and listening time per interface and source.
    pub tally: std::sync::Arc<crate::runtime::visibility::Tally>,
    /// Where frame copies go for the unknown-device sample. Sent with
    /// `try_send`, so a full channel drops the copy and never slows capture.
    pub frames: Option<mpsc::Sender<sample::Frame>>,
}

impl Tap {
    /// Records one delivered frame.
    fn frame(
        &self,
        interface: &str,
        source: &'static str,
        packet: &pcap::Packet<'_>,
        at: DateTime<Utc>,
    ) {
        self.tally.frame(
            interface,
            source,
            crate::runtime::visibility::ethernet_source(packet.data),
            at,
        );
        if let Some(frames) = &self.frames
            && let Some(frame) = sample::Frame::from_ethernet(packet.data, packet.header.len, at)
        {
            // Full means the daemon is busy; the sample can spare a frame.
            let _ = frames.try_send(frame);
        }
    }
}

impl PcapSource {
    /// Builds a source.
    #[must_use]
    pub fn new(
        name: &'static str,
        filter: &'static str,
        parser: FrameParser,
        interfaces: Vec<String>,
        cfg: &CaptureConfig,
    ) -> Self {
        PcapSource {
            name,
            filter,
            parser,
            interfaces,
            snaplen: cfg.snaplen,
            buffer_size: cfg.buffer_size,
            tap: Tap::default(),
        }
    }

    /// Hands this source's frames to a tap as well as to its parser.
    #[must_use]
    pub fn with_tap(mut self, tap: Tap) -> Self {
        self.tap = tap;
        self
    }
}

impl CaptureSource for PcapSource {
    fn name(&self) -> &str {
        self.name
    }

    fn run(
        self: Box<Self>,
        tx: mpsc::Sender<Observation>,
        failures: mpsc::Sender<CaptureFailure>,
        shutdown: watch::Receiver<bool>,
    ) -> JoinHandle<Result<()>> {
        tokio::spawn(async move {
            let mut tasks = Vec::with_capacity(self.interfaces.len());
            for interface in self.interfaces.clone() {
                let tx = tx.clone();
                let shutdown = shutdown.clone();
                let (name, filter, parser) = (self.name, self.filter, self.parser);
                let (snaplen, buffer_size) = (self.snaplen, self.buffer_size);
                let tap = self.tap.clone();
                let thread = tokio::task::spawn_blocking({
                    let interface = interface.clone();
                    move || {
                        capture_loop(
                            name,
                            filter,
                            parser,
                            &interface,
                            snaplen,
                            buffer_size,
                            &tx,
                            &tap,
                            &shutdown,
                        )
                    }
                });
                tasks.push((interface, async move {
                    thread
                        .await
                        .unwrap_or_else(|err| Err(anyhow!("capture thread panicked: {err}")))
                }));
            }
            supervise(self.name, tasks, failures).await
        })
    }
}

/// One interface's capture thread ending in failure, as reported to the daemon
/// and recorded in the runtime status file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CaptureFailure {
    /// The capture source, for example `arp`.
    pub source: String,
    /// The interface the thread was capturing on.
    pub interface: String,
    /// What went wrong.
    pub error: String,
    /// When the thread ended.
    pub at: DateTime<Utc>,
}

/// Supervises one source's per-interface tasks, reporting each failure the
/// moment it happens.
///
/// The tasks run concurrently and are collected in the order they **finish**,
/// not the order they were started. That is the whole fix for the C1 run,
/// where the ARP filter was rejected on eleven `utun` interfaces at startup and
/// nothing was said until shutdown: the tasks used to be awaited in spawn
/// order, so a failure on a later interface waited behind an earlier one that
/// ran until SIGTERM.
///
/// Each failure is logged at `error` with the source, the interface and the
/// error, and sent on `failures` for the daemon to record in the runtime
/// status file. A task that stops cleanly is not reported. The other tasks keep
/// running either way.
///
/// Generic over the task so it can be tested with plain futures, without a
/// capture handle.
///
/// # Errors
///
/// None at present: every failure has already been reported on `failures`
/// by the time this returns, so the result is `Ok` and the caller does not log
/// it a second time. The `Result` keeps the shape [`CaptureSource::run`]
/// returns.
pub async fn supervise<F>(
    source: &'static str,
    tasks: Vec<(String, F)>,
    failures: mpsc::Sender<CaptureFailure>,
) -> Result<()>
where
    F: std::future::Future<Output = Result<()>> + Send + 'static,
{
    let mut running = tokio::task::JoinSet::new();
    let mut interfaces = std::collections::HashMap::new();
    for (interface, task) in tasks {
        let handle = running.spawn(task);
        interfaces.insert(handle.id(), interface);
    }
    while let Some(joined) = running.join_next_with_id().await {
        let (id, outcome) = match joined {
            Ok((id, outcome)) => (id, outcome),
            Err(err) => (err.id(), Err(anyhow!("capture task panicked: {err}"))),
        };
        let interface = interfaces.remove(&id).unwrap_or_default();
        match outcome {
            Ok(()) => tracing::debug!(source, interface, "capture thread stopped"),
            Err(err) => {
                let error = format!("{err:#}");
                tracing::error!(
                    source,
                    interface,
                    err = %error,
                    "capture thread failed; the source's other interfaces keep running"
                );
                // A closed channel means the daemon is already gone, and the
                // log line above is all that is left to say.
                let _ = failures
                    .send(CaptureFailure {
                        source: source.to_string(),
                        interface,
                        error,
                        at: Utc::now(),
                    })
                    .await;
            }
        }
    }
    Ok(())
}

/// Compiles and installs a BPF filter on a capture handle.
///
/// The error names the interface as well as the filter, because the same
/// filter is installed on every interface a source captures on and only some
/// of them may reject it.
///
/// # Errors
///
/// Returns an error when libpcap rejects the filter.
pub fn apply_filter<T: pcap::Activated + ?Sized>(
    cap: &mut pcap::Capture<T>,
    filter: &str,
    interface: &str,
) -> Result<()> {
    cap.filter(filter, true)
        .with_context(|| format!("BPF filter {filter:?} was rejected on {interface}"))
}

/// Blocking per-interface capture loop.
///
/// Runs on the blocking pool, so `blocking_send` is the correct way to hand
/// observations to the async side. A full channel blocks this loop, which is
/// deliberate backpressure: dropping packets silently would corrupt presence
/// tracking, and the kernel ring buffer is the right place for the queue to
/// build up.
#[allow(clippy::too_many_arguments)] // A capture handle genuinely needs all of these, and
// bundling them into a struct would only move the argument list somewhere else.
fn capture_loop(
    source: &'static str,
    filter: &'static str,
    parser: FrameParser,
    interface: &str,
    snaplen: i32,
    buffer_size: i32,
    tx: &mpsc::Sender<Observation>,
    tap: &Tap,
    shutdown: &watch::Receiver<bool>,
) -> Result<()> {
    let cap = pcap::Capture::from_device(interface)
        .with_context(|| format!("interface {interface} is not usable for capture"))?
        .snaplen(snaplen)
        .promisc(false)
        .immediate_mode(true)
        .buffer_size(buffer_size)
        .timeout(POLL_TIMEOUT_MS)
        .open()
        .map_err(|err| permission_error(interface, &err))?;

    // Non-blocking, which is what makes this loop stoppable.
    //
    // The read timeout above is not enough on its own. In immediate mode
    // libpcap delivers packets as they arrive and the timeout does not
    // reliably bound a read, so on a quiet interface `next_packet` blocks
    // until a packet turns up: possibly minutes, possibly never. The shutdown
    // flag at the top of the loop is then never reached, the blocking task
    // never finishes, and the process has to be killed. That is exactly what
    // happened: `docker stop` and `systemctl stop` both sat out their whole
    // grace period and ended in SIGKILL.
    //
    // In non-blocking mode a read with nothing waiting returns `TimeoutExpired`
    // immediately, so the loop sleeps briefly and comes back round to the flag.
    let mut cap = cap
        .setnonblock()
        .with_context(|| format!("could not set non-blocking mode on {interface}"))?;

    apply_filter(&mut cap, filter, interface)?;

    tracing::info!(source, interface, filter, "capture started");
    tap.tally.listening(interface, Utc::now());

    loop {
        if *shutdown.borrow() {
            tracing::debug!(source, interface, "capture stopping");
            return Ok(());
        }
        match cap.next_packet() {
            Ok(packet) => {
                let observed_at = packet_time(packet.header);
                tap.frame(interface, source, &packet, observed_at);
                if let Some(obs) = parser(packet.data, interface, observed_at)
                    && tx.blocking_send(obs).is_err()
                {
                    // The receiver is gone, which only happens during shutdown.
                    tracing::debug!(source, interface, "observation channel closed");
                    return Ok(());
                }
            }
            // Nothing waiting. Sleeping rather than spinning is the whole cost
            // of being stoppable: it bounds shutdown at one IDLE_POLL per
            // handle, and costs ten wakeups a second on an idle interface.
            Err(pcap::Error::TimeoutExpired) => std::thread::sleep(IDLE_POLL),
            Err(pcap::Error::NoMorePackets) => return Ok(()),
            Err(err) => {
                return Err(anyhow!("capture on {interface} failed: {err}"));
            }
        }
    }
}

/// Converts a pcap packet timestamp into a UTC datetime, falling back to the
/// current time if the kernel handed over something unrepresentable.
fn packet_time(header: &pcap::PacketHeader) -> DateTime<Utc> {
    // The libc timeval field widths differ by platform (tv_usec is i32 on macOS
    // and i64 on Linux), so these casts are load-bearing on one target and
    // redundant on the other.
    #[allow(clippy::unnecessary_cast)]
    let (secs, usecs) = (header.ts.tv_sec as i64, header.ts.tv_usec as i64);
    let nanos = u32::try_from(usecs.clamp(0, 999_999) * 1000).unwrap_or(0);
    Utc.timestamp_opt(secs, nanos)
        .single()
        .unwrap_or_else(Utc::now)
}

/// Wraps a pcap open failure with actionable guidance when it looks like a
/// privilege problem.
fn permission_error(interface: &str, err: &pcap::Error) -> anyhow::Error {
    let text = err.to_string();
    if looks_like_permission_denied(&text) {
        anyhow!(
            "cannot capture on {interface}: {text}\n\n\
             Packet capture needs raw socket access. Either run netgraspd as root, or grant \
             the capability once:\n\n    \
             sudo setcap cap_net_raw,cap_net_admin+ep $(which netgraspd)\n\n\
             On macOS there is no setcap: run under sudo, or give a group access to \
             /dev/bpf*. Permanently, install Wireshark's ChmodBPF helper (brew install --cask \
             wireshark-chmodbpf) so that members of the access_bpf group can open it; until \
             the next reboot, sudo chgrp admin /dev/bpf* && sudo chmod g+rw /dev/bpf*."
        )
    } else {
        anyhow!("cannot open capture on {interface}: {text}")
    }
}

/// True when a pcap error message describes a privilege problem.
///
/// libpcap has no error code for this, only prose, and the prose differs
/// between Linux and macOS.
#[must_use]
pub fn looks_like_permission_denied(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    m.contains("permission denied")
        || m.contains("you don't have permission")
        || m.contains("operation not permitted")
        || m.contains("socket: operation not permitted")
}

/// libpcap's link-layer type for Ethernet (`DLT_EN10MB`), which is also what
/// Wi-Fi presents in non-monitor mode on both Linux and macOS.
pub const LINK_TYPE_ETHERNET: i32 = 1;

/// What the default interface selection needs to know about one interface.
///
/// Plain data rather than a `pcap::Device`, so that the selection rule is a
/// pure function that can be tested on every platform against a recorded or
/// constructed interface list, without a live device list or capture
/// permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceDescription {
    /// The name libpcap knows it by.
    pub name: String,
    /// `IFF_UP`: administratively up.
    pub up: bool,
    /// `IFF_RUNNING`: the driver says it is operational.
    pub running: bool,
    /// `IFF_LOOPBACK`.
    pub loopback: bool,
    /// libpcap reports the link as disconnected (no carrier). macOS sets
    /// `IFF_RUNNING` on an Ethernet port with nothing plugged in, so the flag
    /// alone does not say there is a link; this does.
    pub disconnected: bool,
    /// libpcap's link-layer type, when it was read. `None` when the interface
    /// was not opened, or could not be.
    pub link_type: Option<i32>,
    /// Every address the interface holds.
    pub addresses: Vec<std::net::IpAddr>,
}

impl InterfaceDescription {
    /// Describes a libpcap device. The link type is left unread, because it
    /// can only be read by opening the device.
    fn from_device(device: &pcap::Device) -> Self {
        InterfaceDescription {
            name: device.name.clone(),
            up: device.flags.is_up(),
            running: device.flags.is_running(),
            loopback: device.flags.is_loopback(),
            disconnected: device.flags.connection_status == pcap::ConnectionStatus::Disconnected,
            link_type: None,
            addresses: device.addresses.iter().map(|a| a.addr).collect(),
        }
    }

    /// Why the default selection leaves this interface out, judged on
    /// everything except the link type; `None` when it may be kept.
    ///
    /// Split from [`exclusion`](Self::exclusion) so that the caller only opens
    /// a device to read its link type when nothing cheaper has ruled it out.
    #[must_use]
    pub fn exclusion_before_link_type(&self) -> Option<&'static str> {
        if self.loopback {
            Some("loopback")
        } else if !self.up {
            Some("down")
        } else if !self.running || self.disconnected {
            Some("no carrier")
        } else if !self.addresses.iter().any(std::net::IpAddr::is_ipv4) {
            Some("no IPv4 address")
        } else {
            None
        }
    }

    /// Why the default selection leaves this interface out, or `None` when it
    /// is kept.
    #[must_use]
    pub fn exclusion(&self) -> Option<&'static str> {
        self.exclusion_before_link_type().or(match self.link_type {
            Some(LINK_TYPE_ETHERNET) => None,
            Some(_) => Some("not an Ethernet link layer"),
            None => Some("link layer could not be read"),
        })
    }
}

/// The default interface selection: the names of the interfaces that carry a
/// broadcast LAN, in the order given.
///
/// Kept: up, running and not reported disconnected, not loopback, an Ethernet
/// link layer, and at least one IPv4 address. Every capture source is a
/// broadcast or link-local multicast protocol on Ethernet framing, so that is
/// what an interface has to carry to be worth a pcap handle per source.
///
/// What that drops, and why each matters:
///
/// - **Tunnels** (`utun*` on macOS, `tailscale0`, `wg0`): no Ethernet header,
///   so the ARP filter does not even compile on them, and nothing on them is a
///   LAN neighbour.
/// - **Link-local-only interfaces** (`awdl0`, `llw0`, `anpi*` and `anri0` on
///   macOS; `veth*` on Linux): they hold only an IPv6 link-local address,
///   because they are point-to-point links to one peer or to the host itself.
/// - **Ports with no carrier** (an unplugged `en0`, `docker0` with no
///   containers).
///
/// An addressed bridge with carrier is kept. That covers a router's LAN bridge
/// and also a hypervisor's or container runtime's host network (`bridge100`
/// on macOS, `docker0` with containers, `cni0`). Those two cannot be told apart
/// from the interface alone: both are an Ethernet bridge the host is the
/// gateway of, and dropping one by its shape would drop the other.
#[must_use]
pub fn select_default_interfaces(interfaces: &[InterfaceDescription]) -> Vec<String> {
    interfaces
        .iter()
        .filter(|i| i.exclusion().is_none())
        .map(|i| i.name.clone())
        .collect()
}

/// Reads an interface's link-layer type by opening it briefly.
///
/// `Ok(None)` when the device will not open for a reason other than privilege,
/// which leaves it out of the default selection. A privilege failure is an
/// error, so that a process without capture permission gets the permission
/// guidance rather than "no usable interfaces".
fn probe_link_type(name: &str) -> Result<Option<i32>> {
    let opened = pcap::Capture::from_device(name)
        .and_then(|cap| cap.snaplen(64).promisc(false).timeout(10).open());
    match opened {
        Ok(cap) => Ok(Some(cap.get_datalink().0)),
        Err(err) if looks_like_permission_denied(&err.to_string()) => {
            Err(permission_error(name, &err))
        }
        Err(err) => {
            tracing::debug!(interface = name, %err, "could not open interface to read its link type");
            Ok(None)
        }
    }
}

/// Resolves the interfaces to listen on.
///
/// An empty request means [`select_default_interfaces`] over every device
/// libpcap lists. An explicit list is honoured as given, and a name that does
/// not exist is an error rather than a silent omission.
///
/// # Errors
///
/// Returns an error when the device list cannot be read, when a requested
/// interface does not exist, when the process may not open a device to read
/// its link type, or when nothing usable is left.
pub fn resolve_interfaces(requested: &[String]) -> Result<Vec<String>> {
    let devices = pcap::Device::list().context("could not list capture devices")?;
    if !requested.is_empty() {
        let known: Vec<&str> = devices.iter().map(|d| d.name.as_str()).collect();
        for name in requested {
            if !known.contains(&name.as_str()) {
                bail!(
                    "interface {name:?} not found; available interfaces: {}",
                    known.join(", ")
                );
            }
        }
        return Ok(requested.to_vec());
    }

    let mut interfaces: Vec<InterfaceDescription> = devices
        .iter()
        .map(InterfaceDescription::from_device)
        .collect();
    for interface in &mut interfaces {
        if interface.exclusion_before_link_type().is_none() {
            interface.link_type = probe_link_type(&interface.name)?;
        }
    }
    for interface in &interfaces {
        if let Some(reason) = interface.exclusion() {
            tracing::debug!(interface = %interface.name, reason, "interface left out of the default selection");
        }
    }

    let usable = select_default_interfaces(&interfaces);
    if usable.is_empty() {
        bail!(
            "no usable capture interfaces found: none is up with carrier, non-loopback, Ethernet \
             and holding an IPv4 address; name one with capture.interfaces or -i"
        );
    }
    tracing::info!(
        selected = ?usable,
        left_out = interfaces.len() - usable.len(),
        "capture interfaces chosen by default; capture.interfaces or -i overrides this"
    );
    Ok(usable)
}

/// Opens and immediately closes a capture handle to confirm the process may
/// capture at all, producing the setcap guidance if it may not.
///
/// # Errors
///
/// Returns an error when no interface can be opened.
pub fn check_capture_permission(interface: &str) -> Result<()> {
    let cap = pcap::Capture::from_device(interface)
        .with_context(|| format!("interface {interface} is not usable for capture"))?
        .snaplen(64)
        .promisc(false)
        .timeout(10)
        .open()
        .map_err(|err| permission_error(interface, &err))?;
    drop(cap);
    Ok(())
}

/// Every capture source Netgrasp knows, paired with its BPF filter and parser.
///
/// One table rather than a match arm per source, because every source is the
/// same [`PcapSource`] with a different filter and parser, and a table cannot
/// drift out of step with the error message that lists the valid names.
const SOURCES: [(&str, &str, FrameParser); 6] = [
    (arp::SOURCE, arp::FILTER, arp::parse_frame),
    (mdns::SOURCE, mdns::FILTER, mdns::parse_frame),
    (dhcp::SOURCE, dhcp::FILTER, dhcp::parse_frame),
    (ssdp::SOURCE, ssdp::FILTER, ssdp::parse_frame),
    (ndp::SOURCE, ndp::FILTER, ndp::parse_frame),
    (nbns::SOURCE, nbns::FILTER, nbns::parse_frame),
];

/// Builds the configured capture sources.
///
/// # Errors
///
/// Returns an error for an unknown source name, or when the interface list
/// cannot be resolved.
pub fn build_sources(
    cfg: &CaptureConfig,
    interfaces: &[String],
) -> Result<Vec<Box<dyn CaptureSource>>> {
    build_tapped_sources(cfg, interfaces, &Tap::default())
}

/// Builds the configured sources, every one of them handing its frames to
/// `tap` as well.
///
/// # Errors
///
/// The same as [`build_sources`].
pub fn build_tapped_sources(
    cfg: &CaptureConfig,
    interfaces: &[String],
    tap: &Tap,
) -> Result<Vec<Box<dyn CaptureSource>>> {
    let mut sources: Vec<Box<dyn CaptureSource>> = Vec::with_capacity(cfg.sources.len());
    for name in &cfg.sources {
        let Some((source, filter, parser)) = SOURCES.iter().find(|(s, _, _)| *s == name) else {
            bail!(
                "unknown capture source {name:?}; known sources are {}",
                SOURCES
                    .iter()
                    .map(|(s, _, _)| *s)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        };
        sources.push(Box::new(
            PcapSource::new(source, filter, *parser, interfaces.to_vec(), cfg)
                .with_tap(tap.clone()),
        ));
    }
    Ok(sources)
}

/// A capture source that is not implemented yet.
///
/// Every protocol in [`SOURCES`] is now real. This remains for the next one that
/// is not: the `CaptureSource` trait leaves a slot for passive Bluetooth
/// scanning, and when that arrives it can be nameable in config and present in
/// the startup path before it can capture anything.
pub struct StubSource {
    name: &'static str,
    milestone: &'static str,
}

impl StubSource {
    /// Builds a stub for the named protocol.
    #[must_use]
    pub const fn new(name: &'static str, milestone: &'static str) -> Self {
        StubSource { name, milestone }
    }
}

impl CaptureSource for StubSource {
    fn name(&self) -> &str {
        self.name
    }

    fn run(
        self: Box<Self>,
        _tx: mpsc::Sender<Observation>,
        _failures: mpsc::Sender<CaptureFailure>,
        mut shutdown: watch::Receiver<bool>,
    ) -> JoinHandle<Result<()>> {
        tokio::spawn(async move {
            tracing::warn!(
                source = self.name,
                milestone = self.milestone,
                "capture source is configured but not implemented yet; it will observe nothing"
            );
            // Park until shutdown so that the source list has uniform lifetimes
            // and a stub cannot make the daemon look like it finished early.
            while !*shutdown.borrow() {
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_prose_is_recognised_on_both_platforms() {
        // Linux libpcap.
        assert!(looks_like_permission_denied(
            "socket: Operation not permitted"
        ));
        assert!(looks_like_permission_denied(
            "(cannot open device) /dev/bpf0: Permission denied"
        ));
        // macOS libpcap.
        assert!(looks_like_permission_denied(
            "en0: You don't have permission to capture on that device"
        ));
        assert!(!looks_like_permission_denied("No such device exists"));
    }

    #[test]
    fn the_permission_error_tells_the_user_what_to_run() {
        let err = permission_error(
            "eth0",
            &pcap::Error::PcapError("Permission denied".to_string()),
        );
        let text = err.to_string();
        assert!(text.contains("setcap cap_net_raw"), "{text}");
        assert!(text.contains("ChmodBPF"), "{text}");
        assert!(text.contains("chgrp admin /dev/bpf*"), "{text}");
    }

    #[test]
    fn a_non_permission_error_is_not_dressed_up_as_one() {
        let err = permission_error(
            "eth9",
            &pcap::Error::PcapError("No such device exists".to_string()),
        );
        assert!(!err.to_string().contains("setcap"), "{err}");
    }

    #[test]
    fn unknown_source_names_are_rejected_at_build_time() {
        let cfg = CaptureConfig {
            sources: vec!["telepathy".into()],
            ..CaptureConfig::default()
        };
        let err = match build_sources(&cfg, &["eth0".to_string()]) {
            Ok(_) => panic!("an unknown source name must be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("unknown capture source"), "{err}");
    }

    #[test]
    fn every_documented_source_name_builds() {
        let cfg = CaptureConfig {
            sources: vec![
                "arp".into(),
                "mdns".into(),
                "dhcp".into(),
                "ssdp".into(),
                "ndp".into(),
                "nbns".into(),
            ],
            ..CaptureConfig::default()
        };
        let sources = build_sources(&cfg, &["eth0".to_string()]).expect("all build");
        let names: Vec<&str> = sources.iter().map(|s| s.name()).collect();
        assert_eq!(names, vec!["arp", "mdns", "dhcp", "ssdp", "ndp", "nbns"]);
    }

    #[test]
    fn packet_timestamps_convert_without_panicking() {
        let header = pcap::PacketHeader {
            ts: libc_timeval(1_770_000_000, 500_000),
            caplen: 60,
            len: 60,
        };
        let t = packet_time(&header);
        assert_eq!(t.timestamp(), 1_770_000_000);
        assert_eq!(t.timestamp_subsec_millis(), 500);

        // Nonsense from a broken driver must not panic.
        let header = pcap::PacketHeader {
            ts: libc_timeval(i64::MAX, -1),
            caplen: 0,
            len: 0,
        };
        let _ = packet_time(&header);
    }

    /// Builds a `timeval` without hard-coding the platform-specific field
    /// widths, which differ between macOS and Linux.
    // The timeval field widths differ by platform, so the conversions are
    // load-bearing on Linux (i64 tv_usec) and redundant on macOS (i32).
    #[allow(clippy::useless_conversion)]
    fn libc_timeval(secs: i64, usecs: i64) -> libc::timeval {
        libc::timeval {
            tv_sec: secs.try_into().unwrap_or_default(),
            tv_usec: usecs.try_into().unwrap_or_default(),
        }
    }

    /// Turns `ifconfig` output from macOS into interface descriptions, the way
    /// libpcap would describe the same interfaces.
    ///
    /// `ifconfig` prints `ether` only for an Ethernet link layer, and
    /// `status: inactive` where libpcap reports the connection as
    /// disconnected. Checked against `pcap::Device::list()` and
    /// `pcap_datalink` on the same machine at the same moment: they agreed on
    /// every interface.
    fn parse_macos_ifconfig(text: &str) -> Vec<InterfaceDescription> {
        let mut interfaces: Vec<InterfaceDescription> = Vec::new();
        for line in text.lines() {
            if !line.starts_with(['\t', ' ']) {
                let (name, rest) = line.split_once(": flags=").expect("an interface header");
                let flags = rest
                    .split_once('<')
                    .and_then(|(_, f)| f.split_once('>'))
                    .map_or("", |(f, _)| f);
                let has = |flag: &str| flags.split(',').any(|f| f == flag);
                interfaces.push(InterfaceDescription {
                    name: name.to_string(),
                    up: has("UP"),
                    running: has("RUNNING"),
                    loopback: has("LOOPBACK"),
                    disconnected: false,
                    link_type: None,
                    addresses: Vec::new(),
                });
                continue;
            }
            let current = interfaces.last_mut().expect("a line inside an interface");
            let mut words = line.split_whitespace();
            match (words.next(), words.next()) {
                (Some("ether"), _) => current.link_type = Some(LINK_TYPE_ETHERNET),
                (Some("inet"), Some(addr)) => current.addresses.push(addr.parse().expect("IPv4")),
                (Some("inet6"), Some(addr)) => {
                    let addr = addr.split('%').next().unwrap_or(addr);
                    current.addresses.push(addr.parse().expect("IPv6"));
                }
                (Some("status:"), Some("inactive")) => current.disconnected = true,
                _ => {}
            }
        }
        // ifconfig prints no link-layer line for a tunnel; libpcap reports
        // DLT_NULL or DLT_RAW there, which is not Ethernet either way.
        for interface in &mut interfaces {
            interface.link_type.get_or_insert(0);
        }
        interfaces
    }

    /// The Mac Studio's interfaces on 2026-11-14: Wi-Fi on the LAN as `en1`,
    /// Tailscale and other VPN tunnels on `utun*`, OrbStack's VM networks on
    /// `bridge100` to `bridge105`, and every unplugged Thunderbolt and
    /// Ethernet port. Recorded with `ifconfig`; only the tailnet addresses were
    /// replaced.
    #[test]
    fn the_default_selection_on_a_recorded_mac_keeps_the_lan_and_drops_the_rest() {
        let interfaces =
            parse_macos_ifconfig(include_str!("../../tests/fixtures/macos_ifconfig.txt"));
        assert_eq!(interfaces.len(), 52, "the whole recorded list was parsed");

        let selected = select_default_interfaces(&interfaces);
        assert_eq!(
            selected,
            vec![
                "en1",
                // OrbStack's host networks: Ethernet bridges with carrier and
                // an IPv4 address, the same shape as a router's LAN bridge.
                // See select_default_interfaces for why they stay.
                "bridge100",
                "bridge101",
                "bridge102",
                "bridge103",
                // In the order the system lists them, which is not numeric.
                "bridge105",
                "bridge104",
            ]
        );

        let reason = |name: &str| {
            interfaces
                .iter()
                .find(|i| i.name == name)
                .unwrap_or_else(|| panic!("{name} is in the fixture"))
                .exclusion()
        };
        assert_eq!(reason("lo0"), Some("loopback"));
        assert_eq!(reason("ap1"), Some("down"));
        assert_eq!(reason("awdl0"), Some("no IPv4 address"));
        assert_eq!(reason("llw0"), Some("no IPv4 address"));
        assert_eq!(reason("anri0"), Some("no IPv4 address"));
        assert_eq!(reason("anpi0"), Some("no carrier"));
        assert_eq!(
            reason("en0"),
            Some("no carrier"),
            "an unplugged port still says RUNNING"
        );
        assert_eq!(reason("bridge0"), Some("no carrier"));
        assert_eq!(reason("utun0"), Some("no IPv4 address"));
        // The tailnet tunnel is the one utun with an IPv4 address; it has no
        // Ethernet header, so the ARP filter would not compile on it.
        assert_eq!(reason("utun4"), Some("not an Ethernet link layer"));
        for i in &interfaces {
            let name = i.name.as_str();
            if ["awdl0", "llw0", "ap1"].contains(&name)
                || ["utun", "anpi", "vmenet", "gif", "stf", "nan"]
                    .iter()
                    .any(|p| name.starts_with(p))
            {
                assert!(
                    !selected.iter().any(|s| s == name),
                    "{name} must be dropped"
                );
            }
        }
    }

    /// A k3s node running flannel and Docker. **Constructed, not captured**:
    /// the shape is what `ip addr` shows on such a node, written out by hand.
    #[test]
    fn the_default_selection_on_a_k3s_node_keeps_the_lan_and_the_pod_bridge() {
        let iface =
            |name: &str, running: bool, link_type: i32, addresses: &[&str]| InterfaceDescription {
                name: name.to_string(),
                up: true,
                running,
                loopback: name == "lo",
                disconnected: false,
                link_type: Some(link_type),
                addresses: addresses
                    .iter()
                    .map(|a| a.parse().expect("an address"))
                    .collect(),
            };
        let interfaces = vec![
            iface("lo", true, 772, &["127.0.0.1", "::1"]),
            iface(
                "enp3s0",
                true,
                1,
                &["192.168.1.20", "fe80::1e1d:d3ff:fe00:1"],
            ),
            // The bridge pods hang off. It is kept: the node is the gateway of
            // an Ethernet broadcast domain, the same shape as a router's LAN,
            // and pods answering ARP and mDNS on it are devices of a kind.
            iface("cni0", true, 1, &["10.42.0.1", "fe80::1"]),
            // VXLAN to the other nodes. Linux presents it as Ethernet and gives
            // it a /32, so it is kept by the same rule; it carries the
            // cluster's ARP between nodes, which is real traffic.
            iface("flannel.1", true, 1, &["10.42.0.0", "fe80::2"]),
            // One end of each pod's veth pair: link-local IPv6 only.
            iface("veth3a1b2c4d", true, 1, &["fe80::3"]),
            iface("vethd4e5f6a7", true, 1, &["fe80::4"]),
            // Docker with no containers: up, addressed, NO-CARRIER, so no
            // IFF_RUNNING.
            iface("docker0", false, 1, &["172.17.0.1"]),
            // A tailnet: an IPv4 address, but no Ethernet header (DLT_RAW).
            iface("tailscale0", true, 12, &["100.64.0.2", "fd7a:115c:a1e0::2"]),
        ];
        assert_eq!(
            select_default_interfaces(&interfaces),
            vec!["enp3s0", "cni0", "flannel.1"]
        );
    }

    #[test]
    fn an_interface_whose_link_type_was_not_read_is_left_out() {
        let interface = InterfaceDescription {
            name: "en1".into(),
            up: true,
            running: true,
            loopback: false,
            disconnected: false,
            link_type: None,
            addresses: vec!["10.0.0.2".parse().expect("an address")],
        };
        assert_eq!(interface.exclusion_before_link_type(), None);
        assert_eq!(interface.exclusion(), Some("link layer could not be read"));
    }

    #[tokio::test]
    async fn a_failed_interface_is_reported_while_the_others_still_run() {
        use std::future::Future;
        use std::pin::Pin;
        type Task = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (failures_tx, mut failures_rx) = mpsc::channel(8);

        // en1 runs until shutdown, as a healthy capture thread does. It is
        // listed first, which is the order that used to hide utun0's failure
        // behind it.
        let mut until_shutdown = shutdown_rx.clone();
        let en1: Task = Box::pin(async move {
            while !*until_shutdown.borrow() {
                if until_shutdown.changed().await.is_err() {
                    break;
                }
            }
            Ok(())
        });
        let utun0: Task = Box::pin(async {
            Err(anyhow!(
                "BPF filter \"arp\" was rejected on utun0: arp not supported"
            ))
        });
        let supervisor = tokio::spawn(supervise(
            "arp",
            vec![("en1".to_string(), en1), ("utun0".to_string(), utun0)],
            failures_tx,
        ));

        let failure = tokio::time::timeout(std::time::Duration::from_secs(2), failures_rx.recv())
            .await
            .expect("the failure is reported when it happens, not at shutdown")
            .expect("a failure");
        assert!(!*shutdown_rx.borrow(), "shutdown has not been asked for");
        assert_eq!(failure.source, "arp");
        assert_eq!(failure.interface, "utun0");
        assert!(failure.error.contains("rejected"), "{}", failure.error);
        assert!(!supervisor.is_finished(), "en1 is still capturing");

        shutdown_tx.send(true).expect("the supervisor is listening");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), supervisor)
            .await
            .expect("the supervisor stops with its tasks");
        assert!(
            failures_rx.recv().await.is_none(),
            "utun0 is reported once, and en1 stopping cleanly is not a failure"
        );
    }

    #[test]
    fn a_rejected_filter_names_the_interface() {
        // A raw IPv4 link has no Ethernet header, so "arp" cannot compile on
        // it, which is what happened on every utun in C1. A dead handle needs
        // no capture permission.
        let mut cap = pcap::Capture::dead(pcap::Linktype::IPV4).expect("a dead handle");
        let err = apply_filter(&mut cap, "arp", "utun0")
            .expect_err("arp does not compile on a raw IP link");
        let text = format!("{err:#}");
        assert!(text.contains("\"arp\""), "{text}");
        assert!(text.contains("utun0"), "the interface is named: {text}");
    }
}
