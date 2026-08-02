//! DHCP capture source. **Not implemented in milestone 1.**
//!
//! This file exists so that milestone 2 adds a parser rather than a wiring
//! change: `dhcp` is already a valid `capture.sources` entry, already builds,
//! and already takes part in startup and shutdown.
//!
//! What attaches here: a BPF filter of `udp port 67 or udp port 68`, a parser
//! for the BOOTP header plus options, and two signals per request.
//! Option 12 (host name) becomes [`SignalKind::DhcpHostname`], weight 0.8. The
//! option-55 parameter request list is the fingerprint used for device-type and
//! OS classification, and needs a new signal kind at weight zero alongside
//! [`SignalKind::MdnsService`].
//!
//! [`SignalKind::DhcpHostname`]: crate::types::SignalKind::DhcpHostname
//! [`SignalKind::MdnsService`]: crate::types::SignalKind::MdnsService

use anyhow::Result;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::capture::{CaptureSource, StubSource};
use crate::types::Observation;

/// Short name of this source.
pub const SOURCE: &str = "dhcp";

/// BPF filter this source will use once implemented.
pub const FILTER: &str = "udp port 67 or udp port 68";

/// Placeholder DHCP source.
#[derive(Debug, Default)]
pub struct DhcpSource;

impl CaptureSource for DhcpSource {
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
