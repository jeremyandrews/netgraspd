//! IPv6 Neighbor Discovery capture source. **Not implemented in milestone 1.**
//!
//! What attaches here: a BPF filter of `icmp6 and ip6[40] >= 133 and ip6[40] <=
//! 137`, and parsers for neighbor solicitations, neighbor advertisements and
//! router advertisements. The source link-layer address option carries the MAC,
//! which makes NDP the IPv6 equivalent of ARP.
//!
//! When this lands, revisit the milestone 1 decision that `ng_devices.last_ip`
//! tracks IPv4 only. Right now an IPv6 sighting is recorded in `ng_ip_history`
//! but does not move `last_ip`, because a dual-stack device would otherwise
//! flap between its two addresses and emit a stream of meaningless `ip_changed`
//! events. With NDP present the right model is one current address per family.

use anyhow::Result;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::capture::{CaptureSource, StubSource};
use crate::types::Observation;

/// Short name of this source.
pub const SOURCE: &str = "ndp";

/// BPF filter this source will use once implemented.
pub const FILTER: &str = "icmp6 and ip6[40] >= 133 and ip6[40] <= 137";

/// Placeholder NDP source.
#[derive(Debug, Default)]
pub struct NdpSource;

impl CaptureSource for NdpSource {
    fn name(&self) -> &str {
        SOURCE
    }

    fn run(
        self: Box<Self>,
        tx: mpsc::Sender<Observation>,
        shutdown: watch::Receiver<bool>,
    ) -> JoinHandle<Result<()>> {
        Box::new(StubSource::new(SOURCE, "milestone 2")).run(tx, shutdown)
    }
}
