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
    /// unrecoverably.
    fn run(
        self: Box<Self>,
        tx: mpsc::Sender<Observation>,
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
        }
    }
}

impl CaptureSource for PcapSource {
    fn name(&self) -> &str {
        self.name
    }

    fn run(
        self: Box<Self>,
        tx: mpsc::Sender<Observation>,
        shutdown: watch::Receiver<bool>,
    ) -> JoinHandle<Result<()>> {
        tokio::spawn(async move {
            let mut handles = Vec::with_capacity(self.interfaces.len());
            for interface in self.interfaces.clone() {
                let tx = tx.clone();
                let shutdown = shutdown.clone();
                let (name, filter, parser) = (self.name, self.filter, self.parser);
                let (snaplen, buffer_size) = (self.snaplen, self.buffer_size);
                handles.push(tokio::task::spawn_blocking(move || {
                    capture_loop(
                        name,
                        filter,
                        parser,
                        &interface,
                        snaplen,
                        buffer_size,
                        &tx,
                        &shutdown,
                    )
                }));
            }

            let mut first_error = None;
            for handle in handles {
                match handle.await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        tracing::error!(source = self.name, %err, "capture thread failed");
                        first_error.get_or_insert(err);
                    }
                    Err(err) => {
                        tracing::error!(source = self.name, %err, "capture thread panicked");
                        first_error
                            .get_or_insert_with(|| anyhow!("capture thread panicked: {err}"));
                    }
                }
            }
            match first_error {
                Some(err) => Err(err),
                None => Ok(()),
            }
        })
    }
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

    cap.filter(filter, true)
        .with_context(|| format!("BPF filter {filter:?} was rejected"))?;

    tracing::info!(source, interface, filter, "capture started");

    loop {
        if *shutdown.borrow() {
            tracing::debug!(source, interface, "capture stopping");
            return Ok(());
        }
        match cap.next_packet() {
            Ok(packet) => {
                let observed_at = packet_time(packet.header);
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
             On macOS there is no setcap: run under sudo, or install Wireshark's ChmodBPF \
             helper so that members of the access_bpf group can open /dev/bpf*."
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

/// Resolves the interfaces to listen on.
///
/// An empty request means every non-loopback interface that is up. An explicit
/// list is honoured as given, and a name that does not exist is an error rather
/// than a silent omission.
///
/// # Errors
///
/// Returns an error when the device list cannot be read, when a requested
/// interface does not exist, or when nothing usable is left.
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

    let usable: Vec<String> = devices
        .into_iter()
        .filter(|d| !d.flags.is_loopback() && d.flags.is_up() && !d.addresses.is_empty())
        .map(|d| d.name)
        .collect();
    if usable.is_empty() {
        bail!("no usable capture interfaces found (none are up, non-loopback and addressed)");
    }
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
        sources.push(Box::new(PcapSource::new(
            source,
            filter,
            *parser,
            interfaces.to_vec(),
            cfg,
        )));
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
}
