//! The unknown-device sample: the first few frames from each device the
//! identifier could not name, written to one pcap file to learn from later.
//!
//! # The seam, and how it is crossed
//!
//! The bytes of a frame exist only in the capture thread, and observations
//! carry none. Whether a device was named is known only in the device manager,
//! and often not until later: an ARP request arrives before the DHCP request or
//! mDNS announcement that names the device, if one ever does.
//!
//! So nothing is decided where the bytes are. When sampling is on, each
//! capture thread hands a copy of every frame it is delivered to the daemon on
//! a bounded channel, without ever waiting: a full channel drops the copy and
//! capture carries on. The daemon offers each one to an [`UnknownSampler`]
//! together with what the device manager says about its sender at that moment:
//!
//! - **already named**: dropped at once, never held;
//! - **not named, or not a device yet**: held, at most
//!   [`SampleLimits::frames_per_device`] frames per sender, while the device has
//!   [`SampleLimits::settle`] to be named;
//! - once a sender has been held that long, the manager is asked again
//!   ([`UnknownSampler::settle`]). Named, or never a device at all: its frames
//!   are dropped. Still unnamed: they are written, and its later frames are
//!   written straight through, while it stays unnamed, up to its limit.
//!
//! So frames are held only for senders that were unnamed when they arrived,
//! for at most the settle time; a device that gets named in that time has its
//! held frames discarded without a byte written. No schema change: the sample
//! is a file, and the device table is untouched.
//!
//! # Bounds
//!
//! Three, each stopping something and each said once in the log:
//!
//! - frames per device: that device's further frames are not kept;
//! - devices: no new device is admitted, admitted ones finish their quota;
//! - total bytes, the file header included: nothing more is written at all.
//!
//! Held frames are bounded too: at most [`MAX_HELD_SENDERS`] senders, each with
//! at most `frames_per_device` frames of at most the capture snapshot length.
//!
//! # The file
//!
//! Classic pcap (the format every tool reads), microsecond timestamps,
//! `LINKTYPE_ETHERNET`, written by hand: twenty-four bytes of header and
//! sixteen per record, simpler than a libpcap dead handle and needing no
//! foreign types. A file that already exists with a valid header is appended
//! to, so a restart mid-trip keeps what the earlier run kept; its size counts
//! towards the byte limit.
//!
//! The frames are broadcast and multicast only. The filters alone do not
//! guarantee that: non-promiscuous capture also delivers frames unicast to
//! the capture host itself, so [`Frame::from_ethernet`] refuses any frame not
//! addressed to a group.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::clock::Timestamp;
use jiff::SignedDuration;
use serde::{Deserialize, Serialize};

use crate::types::MacAddr;

/// The pcap magic number, microsecond timestamps.
pub const PCAP_MAGIC: u32 = 0xa1b2_c3d4;

/// `LINKTYPE_ETHERNET`.
pub const LINKTYPE_ETHERNET: u32 = 1;

/// How many senders' frames may be held at once while they settle.
///
/// With the default five frames each and the default 1600-byte snapshot
/// length, at most about two megabytes. A sender arriving while this many are
/// held is not sampled.
pub const MAX_HELD_SENDERS: usize = 256;

/// Size of the pcap file header.
pub const FILE_HEADER_LEN: u64 = 24;

/// Size of each pcap record header.
pub const RECORD_HEADER_LEN: u64 = 16;

/// One captured frame, copied out of the capture thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The Ethernet source address.
    pub sender: MacAddr,
    /// When it was captured.
    pub at: Timestamp,
    /// The captured bytes, at most the snapshot length.
    pub data: Vec<u8>,
    /// The frame's length on the wire, which is more than `data` when the
    /// snapshot length cut it short.
    pub wire_len: u32,
}

impl Frame {
    /// Copies a captured Ethernet frame, or returns `None` when it is too short
    /// to have a source address, its sender is not a unicast device address,
    /// or it is not addressed to a broadcast or multicast group.
    ///
    /// The last check is what makes the sample broadcast and multicast only.
    /// The BPF filters are not enough on their own: non-promiscuous capture
    /// still delivers frames unicast to the capture host itself (the gateway's
    /// ARP replies to it, unicast mDNS answers), and those are this host's own
    /// conversations, not something to keep in a file meant for sharing.
    #[must_use]
    pub fn from_ethernet(data: &[u8], wire_len: u32, at: Timestamp) -> Option<Frame> {
        if data.first().is_none_or(|first| first & 0x01 == 0) {
            return None;
        }
        let sender = crate::runtime::visibility::ethernet_source(data)?;
        Some(Frame {
            sender,
            at,
            data: data.to_vec(),
            wire_len: wire_len.max(u32::try_from(data.len()).unwrap_or(u32::MAX)),
        })
    }

    /// The bytes this frame takes in the file, record header included.
    fn record_len(&self) -> u64 {
        RECORD_HEADER_LEN + self.data.len() as u64
    }
}

/// The three bounds and the settle time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SampleLimits {
    /// Frames kept per device.
    pub frames_per_device: u32,
    /// Devices kept.
    pub max_devices: usize,
    /// Bytes written, file header included.
    pub max_bytes: u64,
    /// How long a sender has to be named before its frames are kept.
    pub settle: SignedDuration,
}

/// Which bound stopped something.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Limit {
    /// A device reached its frame quota.
    FramesPerDevice,
    /// The device limit was reached.
    Devices,
    /// The byte limit was reached.
    Bytes,
}

impl Limit {
    /// Stable name, for the status file.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Limit::FramesPerDevice => "frames_per_device",
            Limit::Devices => "devices",
            Limit::Bytes => "bytes",
        }
    }
}

/// What the sample has done, for the status file and the export.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleStatus {
    /// Where the sample is written.
    pub path: String,
    /// Devices with frames in the file from this run.
    pub devices: usize,
    /// Frames written this run.
    pub frames: u64,
    /// The file's size.
    pub bytes: u64,
    /// Senders whose frames are held, waiting to see whether they get named.
    pub pending_devices: usize,
    /// Set once the device or byte limit has stopped the sample, naming which.
    pub stopped: Option<String>,
}

impl SampleStatus {
    /// One line for `netgraspd stats` and the export.
    #[must_use]
    pub fn line(&self) -> String {
        let mut line = format!(
            "{} frames from {} devices this run, {} in {}",
            self.frames,
            self.devices,
            crate::runtime::human_bytes(self.bytes),
            self.path
        );
        if self.pending_devices > 0 {
            line.push_str(&format!(
                "; {} more waiting to see whether they get named",
                self.pending_devices
            ));
        }
        if let Some(limit) = &self.stopped {
            line.push_str(&format!("; stopped at the {limit} limit"));
        }
        line
    }
}

/// Collects the sample. See the module documentation for the design.
#[derive(Debug)]
pub struct UnknownSampler {
    path: PathBuf,
    limits: SampleLimits,
    pending: HashMap<MacAddr, (Timestamp, Vec<Frame>)>,
    written: HashMap<MacAddr, u32>,
    frames: u64,
    bytes: u64,
    stopped: Option<Limit>,
    /// Whether the per-device limit has been logged, which happens once.
    quota_logged: bool,
    /// The open file, once anything has been written. `None` and `broken` set
    /// means it could not be opened, which is logged once and stops the sample.
    file: Option<std::fs::File>,
    broken: bool,
}

impl UnknownSampler {
    /// A sampler that will write to `path`. Nothing is created until the first
    /// frame is written.
    #[must_use]
    pub fn new(path: PathBuf, limits: SampleLimits) -> Self {
        UnknownSampler {
            path,
            limits,
            pending: HashMap::new(),
            written: HashMap::new(),
            frames: 0,
            bytes: 0,
            stopped: None,
            quota_logged: false,
            file: None,
            broken: false,
        }
    }

    /// Where the sample is written.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Offers one frame. `named` is what the device manager says about its
    /// sender right now: `Some(true)` named, `Some(false)` a device with no
    /// name, `None` not a device (yet).
    pub fn offer(&mut self, frame: Frame, named: Option<bool>) {
        let sender = frame.sender;
        if named == Some(true) {
            // Named: nothing of it is held, and anything held is let go.
            self.pending.remove(&sender);
            return;
        }
        if self.stopped == Some(Limit::Bytes) || self.broken {
            return;
        }
        if let Some(&count) = self.written.get(&sender) {
            // Admitted already. Written straight through while it stays
            // unnamed; a sender that is not a device any more is let go.
            if named == Some(false) {
                if count < self.limits.frames_per_device {
                    self.write(&frame);
                } else {
                    self.quota_reached();
                }
            }
            return;
        }
        if self.stopped == Some(Limit::Devices) {
            return;
        }
        if let Some((_, held)) = self.pending.get_mut(&sender) {
            if (held.len() as u64) < u64::from(self.limits.frames_per_device) {
                held.push(frame);
            }
            return;
        }
        // A new sender. Held senders are bounded on their own, because some
        // of them will turn out to be named and the device limit counts only
        // the ones that were not.
        if self.pending.len() < MAX_HELD_SENDERS {
            self.pending.insert(sender, (frame.at, vec![frame]));
        }
    }

    /// Decides every sender held for at least the settle time, asking `named`
    /// about each.
    pub fn settle(&mut self, now: Timestamp, named: impl Fn(MacAddr) -> Option<bool>) {
        let mut due: Vec<(Timestamp, MacAddr)> = self
            .pending
            .iter()
            .filter(|(_, (first, _))| now - *first >= self.limits.settle)
            .map(|(mac, (first, _))| (*first, *mac))
            .collect();
        // First come, first admitted, so the device limit is deterministic.
        due.sort();
        for (_, sender) in due {
            let Some((_, held)) = self.pending.remove(&sender) else {
                continue;
            };
            if named(sender) != Some(false) {
                continue;
            }
            if self.stopped.is_some() || self.broken {
                continue;
            }
            if self.written.len() >= self.limits.max_devices {
                self.stop(Limit::Devices);
                continue;
            }
            self.written.insert(sender, 0);
            for frame in held {
                self.write(&frame);
            }
        }
    }

    /// What the sample has done so far.
    #[must_use]
    pub fn status(&self) -> SampleStatus {
        SampleStatus {
            path: self.path.display().to_string(),
            devices: self.written.values().filter(|n| **n > 0).count(),
            frames: self.frames,
            bytes: self.bytes,
            pending_devices: self.pending.len(),
            stopped: self.stopped.map(|l| l.as_str().to_string()),
        }
    }

    /// Writes one frame from an admitted sender, within every bound.
    fn write(&mut self, frame: &Frame) {
        if self.stopped == Some(Limit::Bytes) || self.broken {
            return;
        }
        let count = self.written.get(&frame.sender).copied().unwrap_or(0);
        if count >= self.limits.frames_per_device {
            self.quota_reached();
            return;
        }
        if self.file.is_none() && !self.open() {
            return;
        }
        if self.bytes + frame.record_len() > self.limits.max_bytes {
            self.stop(Limit::Bytes);
            return;
        }
        let record = record(frame);
        let written = self
            .file
            .as_mut()
            .map(|file| std::io::Write::write_all(file, &record));
        match written {
            Some(Ok(())) => {
                self.bytes += record.len() as u64;
                self.frames += 1;
                self.written.insert(frame.sender, count + 1);
            }
            Some(Err(err)) => self.fail(&err.to_string()),
            None => {}
        }
    }

    /// Opens the file, appending to a valid existing sample or starting one.
    fn open(&mut self) -> bool {
        match open_sample(&self.path) {
            Ok((file, size)) => {
                self.bytes = size;
                self.file = Some(file);
                if size > FILE_HEADER_LEN {
                    tracing::info!(
                        path = %self.path.display(),
                        existing_bytes = size,
                        "appending to the unknown-device sample an earlier run started"
                    );
                } else {
                    tracing::info!(
                        path = %self.path.display(),
                        "writing the unknown-device sample"
                    );
                }
                true
            }
            Err(err) => {
                self.fail(&format!("{err:#}"));
                false
            }
        }
    }

    fn fail(&mut self, err: &str) {
        if !self.broken {
            tracing::warn!(
                path = %self.path.display(),
                err,
                "the unknown-device sample cannot be written; no more frames will be kept"
            );
        }
        self.broken = true;
        self.pending.clear();
    }

    fn quota_reached(&mut self) {
        if !self.quota_logged {
            self.quota_logged = true;
            tracing::info!(
                frames_per_device = self.limits.frames_per_device,
                "an unnamed device reached its frame quota in the unknown-device sample; \
                 further frames from any device past its quota are not kept (said once)"
            );
        }
    }

    /// Stops the sample at a device or byte limit, saying so once.
    fn stop(&mut self, limit: Limit) {
        if self.stopped.is_some() {
            return;
        }
        self.stopped = Some(limit);
        match limit {
            Limit::Devices => tracing::warn!(
                path = %self.path.display(),
                max_devices = self.limits.max_devices,
                "the unknown-device sample reached its device limit; no new device will be kept"
            ),
            Limit::Bytes => {
                tracing::warn!(
                    path = %self.path.display(),
                    max_bytes = self.limits.max_bytes,
                    "the unknown-device sample reached its size limit; nothing more will be written"
                );
                self.pending.clear();
            }
            Limit::FramesPerDevice => {}
        }
    }
}

/// The pcap file header: version 2.4, microsecond timestamps, Ethernet.
#[must_use]
pub fn file_header(snaplen: u32) -> [u8; 24] {
    let mut out = [0u8; 24];
    out[0..4].copy_from_slice(&PCAP_MAGIC.to_ne_bytes());
    out[4..6].copy_from_slice(&2u16.to_ne_bytes());
    out[6..8].copy_from_slice(&4u16.to_ne_bytes());
    // thiszone and sigfigs stay zero.
    out[16..20].copy_from_slice(&snaplen.to_ne_bytes());
    out[20..24].copy_from_slice(&LINKTYPE_ETHERNET.to_ne_bytes());
    out
}

/// The snapshot length written in the header: the largest a frame can be.
const HEADER_SNAPLEN: u32 = 65_535;

/// One pcap record: its header and the frame's bytes.
fn record(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + frame.data.len());
    let secs = u32::try_from(frame.at.unix_seconds().max(0)).unwrap_or(u32::MAX);
    let micros = frame.at.subsec_micros().min(999_999);
    let caplen = u32::try_from(frame.data.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&secs.to_ne_bytes());
    out.extend_from_slice(&micros.to_ne_bytes());
    out.extend_from_slice(&caplen.to_ne_bytes());
    out.extend_from_slice(&frame.wire_len.to_ne_bytes());
    out.extend_from_slice(&frame.data);
    out
}

/// Opens a sample for appending, writing a header when the file is new or
/// empty. Returns the file and its size.
///
/// An existing file that is not a pcap of this kind is refused rather than
/// overwritten: it may be somebody's capture.
fn open_sample(path: &Path) -> anyhow::Result<(std::fs::File, u64)> {
    use anyhow::Context;
    use std::io::Write;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
    }
    let existing = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if existing > 0 {
        let mut header = [0u8; 24];
        let mut file = std::fs::File::open(path)
            .with_context(|| format!("could not read {}", path.display()))?;
        std::io::Read::read_exact(&mut file, &mut header)
            .with_context(|| format!("{} is not a pcap file", path.display()))?;
        let magic = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]);
        let link = u32::from_ne_bytes([header[20], header[21], header[22], header[23]]);
        if magic != PCAP_MAGIC || link != LINKTYPE_ETHERNET {
            anyhow::bail!(
                "{} exists and is not an Ethernet pcap written here; refusing to append to it",
                path.display()
            );
        }
        let file = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .with_context(|| format!("could not append to {}", path.display()))?;
        return Ok((file, existing));
    }
    let mut file = std::fs::File::create(path)
        .with_context(|| format!("could not create {}", path.display()))?;
    file.write_all(&file_header(HEADER_SNAPLEN))
        .with_context(|| format!("could not write {}", path.display()))?;
    Ok((file, FILE_HEADER_LEN))
}

impl Drop for UnknownSampler {
    fn drop(&mut self) {
        if let Some(file) = self.file.as_mut() {
            let _ = std::io::Write::flush(file);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::fixtures;

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_utc(2026, 11, 14, 9, 0, 0).expect("valid time")
            + SignedDuration::from_secs(seconds)
    }

    fn temp_dir(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netgraspd-sample-test-{}-{test}",
            std::process::id()
        ));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn limits(frames_per_device: u32, max_devices: usize, max_bytes: u64) -> SampleLimits {
        SampleLimits {
            frames_per_device,
            max_devices,
            max_bytes,
            settle: SignedDuration::from_secs(60),
        }
    }

    /// A fixture frame, re-sent from a sender whose last octet is `device`.
    fn fixture_from(bytes: &[u8], device: u8, seconds: i64) -> Frame {
        let mut data = bytes.to_vec();
        data[11] = device;
        let wire_len = u32::try_from(data.len()).expect("small");
        Frame::from_ethernet(&data, wire_len, at(seconds)).expect("a unicast sender")
    }

    /// Every fixture frame, for variety in the file.
    fn fixtures() -> Vec<Vec<u8>> {
        vec![
            fixtures::arp_request(),
            fixtures::mdns_query(),
            fixtures::dhcp_discover(),
            fixtures::ssdp_msearch(),
            fixtures::nbns_query(),
        ]
    }

    /// Reads a sample back with libpcap itself: if libpcap reads it, it is a
    /// valid pcap file.
    fn read_back(path: &Path) -> Vec<(MacAddr, Vec<u8>)> {
        let mut cap = pcap::Capture::from_file(path).expect("libpcap opens the sample");
        assert_eq!(cap.get_datalink(), pcap::Linktype::ETHERNET);
        let mut out = Vec::new();
        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    let sender =
                        MacAddr(<[u8; 6]>::try_from(&packet.data[6..12]).expect("six bytes"));
                    out.push((sender, packet.data.to_vec()));
                }
                Err(pcap::Error::NoMorePackets) => break,
                Err(err) => panic!("reading the sample back: {err}"),
            }
        }
        out
    }

    #[test]
    fn the_file_starts_with_a_valid_pcap_header() {
        let dir = temp_dir("header");
        let path = dir.join("unknown.pcap");
        let mut sampler = UnknownSampler::new(path.clone(), limits(3, 10, 1 << 20));
        sampler.offer(fixture_from(&fixtures::arp_request(), 1, 0), Some(false));
        sampler.settle(at(61), |_| Some(false));

        let bytes = std::fs::read(&path).expect("the sample was written");
        assert!(bytes.len() as u64 > FILE_HEADER_LEN);
        assert_eq!(
            u32::from_ne_bytes(bytes[0..4].try_into().expect("four")),
            PCAP_MAGIC
        );
        assert_eq!(u16::from_ne_bytes(bytes[4..6].try_into().expect("two")), 2);
        assert_eq!(u16::from_ne_bytes(bytes[6..8].try_into().expect("two")), 4);
        assert_eq!(
            u32::from_ne_bytes(bytes[20..24].try_into().expect("four")),
            LINKTYPE_ETHERNET
        );
        let frames = read_back(&path);
        assert_eq!(frames.len(), 1);
        assert_eq!(
            frames[0].1,
            fixture_from(&fixtures::arp_request(), 1, 0).data
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn it_stops_at_the_frames_per_device_limit() {
        let dir = temp_dir("per_device");
        let path = dir.join("unknown.pcap");
        let mut sampler = UnknownSampler::new(path.clone(), limits(3, 10, 1 << 20));
        for (i, frame) in fixtures().iter().enumerate() {
            sampler.offer(fixture_from(frame, 7, i as i64), Some(false));
        }
        sampler.settle(at(120), |_| Some(false));
        // Written straight through once admitted, still bounded.
        sampler.offer(fixture_from(&fixtures::arp_request(), 7, 130), Some(false));

        let frames = read_back(&path);
        assert_eq!(frames.len(), 3, "three frames from the one device");
        let status = sampler.status();
        assert_eq!(status.frames, 3);
        assert_eq!(status.devices, 1);
        assert_eq!(
            status.stopped, None,
            "a device quota stops only that device"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn it_stops_at_the_device_limit() {
        let dir = temp_dir("devices");
        let path = dir.join("unknown.pcap");
        let mut sampler = UnknownSampler::new(path.clone(), limits(2, 2, 1 << 20));
        for device in 1..=5u8 {
            sampler.offer(
                fixture_from(&fixtures::arp_request(), device, i64::from(device)),
                Some(false),
            );
        }
        sampler.settle(at(120), |_| Some(false));
        for device in 1..=5u8 {
            sampler.offer(
                fixture_from(&fixtures::mdns_query(), device, 130),
                Some(false),
            );
        }

        let frames = read_back(&path);
        let mut senders: Vec<MacAddr> = frames.iter().map(|(m, _)| *m).collect();
        senders.sort();
        senders.dedup();
        assert_eq!(senders.len(), 2, "two devices and no more");
        assert_eq!(frames.len(), 4, "each admitted device finishes its quota");
        let status = sampler.status();
        assert_eq!(status.devices, 2);
        assert_eq!(status.stopped.as_deref(), Some("devices"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn it_stops_at_the_byte_limit_and_never_passes_it() {
        let dir = temp_dir("bytes");
        let path = dir.join("unknown.pcap");
        let arp = fixtures::arp_request();
        // Room for the header and exactly two ARP records.
        let max = FILE_HEADER_LEN + 2 * (RECORD_HEADER_LEN + arp.len() as u64) + 10;
        let mut sampler = UnknownSampler::new(path.clone(), limits(5, 10, max));
        for device in 1..=4u8 {
            sampler.offer(fixture_from(&arp, device, 0), Some(false));
        }
        sampler.settle(at(120), |_| Some(false));
        sampler.offer(fixture_from(&arp, 9, 130), Some(false));
        sampler.settle(at(300), |_| Some(false));

        let size = std::fs::metadata(&path).expect("written").len();
        assert!(size <= max, "{size} > {max}");
        assert_eq!(read_back(&path).len(), 2);
        let status = sampler.status();
        assert_eq!(status.bytes, size);
        assert_eq!(status.stopped.as_deref(), Some("bytes"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_device_that_has_a_name_never_has_a_frame_written() {
        let dir = temp_dir("named");
        let path = dir.join("unknown.pcap");
        let mut sampler = UnknownSampler::new(path.clone(), limits(5, 10, 1 << 20));
        // Named when its frames arrive.
        for frame in fixtures() {
            sampler.offer(fixture_from(&frame, 1, 0), Some(true));
        }
        // Unnamed when its frames arrive, named before they settle.
        for frame in fixtures() {
            sampler.offer(fixture_from(&frame, 2, 0), Some(false));
        }
        // Not a device when its frames arrive, named before they settle.
        sampler.offer(fixture_from(&fixtures::arp_request(), 3, 0), None);
        // Never a device at all.
        sampler.offer(fixture_from(&fixtures::arp_request(), 4, 0), None);
        let named = |mac: MacAddr| match mac.0[5] {
            1..=3 => Some(true),
            _ => None,
        };
        sampler.settle(at(120), named);
        // Named later still: frames after admission are not written either.
        sampler.offer(fixture_from(&fixtures::arp_request(), 2, 130), Some(true));

        assert!(
            !path.exists() || read_back(&path).is_empty(),
            "nothing from a named device"
        );
        assert_eq!(sampler.status().frames, 0);
        assert_eq!(sampler.status().pending_devices, 0, "nothing still held");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn only_unnamed_devices_are_written_when_both_are_present() {
        let dir = temp_dir("mixed");
        let path = dir.join("unknown.pcap");
        let mut sampler = UnknownSampler::new(path.clone(), limits(5, 10, 1 << 20));
        for device in 1..=4u8 {
            for frame in fixtures() {
                sampler.offer(fixture_from(&frame, device, 0), Some(false));
            }
        }
        // Even devices got names while they settled.
        sampler.settle(at(120), |mac| Some(mac.0[5] % 2 == 0));
        let frames = read_back(&path);
        assert_eq!(frames.len(), 10);
        assert!(frames.iter().all(|(mac, _)| mac.0[5] % 2 == 1), "odd only");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_sender_is_held_until_it_has_settled() {
        let dir = temp_dir("settle");
        let path = dir.join("unknown.pcap");
        let mut sampler = UnknownSampler::new(path.clone(), limits(5, 10, 1 << 20));
        sampler.offer(fixture_from(&fixtures::arp_request(), 1, 0), Some(false));
        sampler.settle(at(30), |_| Some(false));
        assert!(!path.exists(), "not yet: it has had thirty seconds");
        assert_eq!(sampler.status().pending_devices, 1);
        sampler.settle(at(61), |_| Some(false));
        assert_eq!(read_back(&path).len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_existing_sample_is_appended_to_and_counts_toward_the_byte_limit() {
        let dir = temp_dir("append");
        let path = dir.join("unknown.pcap");
        let mut first = UnknownSampler::new(path.clone(), limits(5, 10, 1 << 20));
        first.offer(fixture_from(&fixtures::arp_request(), 1, 0), Some(false));
        first.settle(at(61), |_| Some(false));
        let size = std::fs::metadata(&path).expect("written").len();

        let mut second = UnknownSampler::new(path.clone(), limits(5, 10, 1 << 20));
        second.offer(fixture_from(&fixtures::arp_request(), 2, 100), Some(false));
        second.settle(at(200), |_| Some(false));
        assert_eq!(
            read_back(&path).len(),
            2,
            "the earlier run's frame survives"
        );
        assert!(second.status().bytes > size);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_group_or_runt_sender_is_not_a_frame_to_keep() {
        let mut group = fixtures::arp_request();
        group[6] = 0x01;
        assert!(Frame::from_ethernet(&group, 60, at(0)).is_none());
        assert!(Frame::from_ethernet(&[0u8; 10], 10, at(0)).is_none());
    }

    #[test]
    fn a_frame_unicast_to_this_host_is_never_kept() {
        // Non-promiscuous capture still delivers frames addressed to the
        // capture host itself: on the 2026-11-15 home LAN run, 128 of the 150
        // sampled frames were the gateway's unicast ARP to this Mac. The sample
        // promises broadcast and multicast only, so those are refused.
        let mut to_us = fixtures::arp_reply();
        to_us[0..6].copy_from_slice(&[0x56, 0x2c, 0xd9, 0x00, 0x00, 0x01]);
        to_us[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x01]);
        assert!(Frame::from_ethernet(&to_us, 60, at(0)).is_none());
        for frame in fixtures() {
            assert!(
                frame[0] & 0x01 == 1,
                "every sampled fixture is addressed to a group"
            );
            assert!(Frame::from_ethernet(&frame, 60, at(0)).is_some());
        }
    }
}
