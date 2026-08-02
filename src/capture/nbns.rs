//! NetBIOS Name Service capture source. **Not implemented in milestone 1.**
//!
//! What attaches here: a BPF filter of `udp port 137`, and a parser for name
//! registration and name query broadcasts. The encoded NetBIOS name yields the
//! 0.6-weight [`SignalKind::NetbiosName`] signal, and the sixteenth byte of the
//! decoded name is the service suffix, which distinguishes a workstation from a
//! file server or a domain controller.
//!
//! The wire format is the first-level encoding from RFC 1001 section 4.1: each
//! nibble of each byte is added to `'A'`, producing a 32-character name that has
//! to be decoded before it means anything. Trailing spaces are padding, not part
//! of the name.
//!
//! [`SignalKind::NetbiosName`]: crate::types::SignalKind::NetbiosName

use anyhow::Result;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::capture::{CaptureSource, StubSource};
use crate::types::Observation;

/// Short name of this source.
pub const SOURCE: &str = "nbns";

/// BPF filter this source will use once implemented.
pub const FILTER: &str = "udp port 137";

/// Placeholder NetBIOS source.
#[derive(Debug, Default)]
pub struct NbnsSource;

impl CaptureSource for NbnsSource {
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
