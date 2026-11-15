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
//! Held frames are bounded too: at most `max_devices` senders, each with at
//! most `frames_per_device` frames of at most the capture snapshot length.
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
//! The frames are broadcast and multicast only, because that is all the
//! daemon's filters ever deliver.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::types::MacAddr;

/// The pcap magic number, microsecond timestamps.
pub const PCAP_MAGIC: u32 = 0xa1b2_c3d4;

/// `LINKTYPE_ETHERNET`.
pub const LINKTYPE_ETHERNET: u32 = 1;

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
    pub at: DateTime<Utc>,
    /// The captured bytes, at most the snapshot length.
    pub data: Vec<u8>,
    /// The frame's length on the wire, which is more than `data` when the
    /// snapshot length cut it short.
    pub wire_len: u32,
}

impl Frame {
    /// Copies a captured Ethernet frame, or returns `None` when it is too short
    /// to have a source address or its sender is not a unicast device address.
    #[must_use]
    pub fn from_ethernet(data: &[u8], wire_len: u32, at: DateTime<Utc>) -> Option<Frame> {
        let _ = (data, wire_len, at);
        None
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
    pub settle: TimeDelta,
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

/// Collects the sample. See the module documentation for the design.
#[derive(Debug)]
pub struct UnknownSampler {
    path: PathBuf,
    limits: SampleLimits,
    pending: HashMap<MacAddr, (DateTime<Utc>, Vec<Frame>)>,
    written: HashMap<MacAddr, u32>,
    frames: u64,
    bytes: u64,
    stopped: Option<Limit>,
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
        let _ = (frame, named);
    }

    /// Decides every sender held for at least the settle time, asking `named`
    /// about each.
    pub fn settle(&mut self, now: DateTime<Utc>, named: impl Fn(MacAddr) -> Option<bool>) {
        let _ = (now, named);
    }

    /// What the sample has done so far.
    #[must_use]
    pub fn status(&self) -> SampleStatus {
        SampleStatus::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::fixtures;
    use chrono::TimeZone;

    fn at(seconds: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 14, 9, 0, 0)
            .single()
            .expect("valid time")
            + TimeDelta::seconds(seconds)
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
            settle: TimeDelta::seconds(60),
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
}
