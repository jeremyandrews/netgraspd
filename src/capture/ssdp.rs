//! SSDP capture source. **Not implemented in milestone 1.**
//!
//! What attaches here: a BPF filter of `udp port 1900`, an HTTPU parser for
//! `NOTIFY` and `M-SEARCH` messages, and the `SERVER` and `NT`/`ST` headers as
//! device-type evidence.
//!
//! One design note the implementer needs: the SSDP `friendlyName` that carries
//! the 0.5-weight [`SignalKind::SsdpFriendlyName`] signal is **not** in the
//! multicast announcement. It lives in the device description XML at the
//! `LOCATION` URL, and fetching it means an HTTP GET to the device. That
//! transmits, so it is not passive and does not belong in this source. Either
//! the signal comes from an explicitly opt-in enricher in milestone 4 alongside
//! UniFi, or it is dropped. Do not quietly add a fetch here.
//!
//! [`SignalKind::SsdpFriendlyName`]: crate::types::SignalKind::SsdpFriendlyName

use anyhow::Result;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::capture::{CaptureSource, StubSource};
use crate::types::Observation;

/// Short name of this source.
pub const SOURCE: &str = "ssdp";

/// BPF filter this source will use once implemented.
pub const FILTER: &str = "udp port 1900";

/// Placeholder SSDP source.
#[derive(Debug, Default)]
pub struct SsdpSource;

impl CaptureSource for SsdpSource {
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
