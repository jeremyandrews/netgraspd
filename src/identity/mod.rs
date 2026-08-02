//! Identity resolution: raw signals in, one display name out.
//!
//! Milestone 1 gathers three signals. [`oui`] resolves the MAC prefix against
//! the embedded IEEE registry, the mDNS capture source supplies instance names,
//! and [`rdns`] optionally resolves PTR records. [`scorer`] weighs whatever has
//! accumulated and picks a display identity.
//!
//! Every raw signal is stored, never replaced, so later signals refine the
//! identity rather than overwriting it.

pub mod oui;
pub mod rdns;
pub mod scorer;

pub use rdns::ReverseResolver;
pub use scorer::{Identity, IdentityInput, improves_on, resolve};

use crate::types::{MacAddr, Signal, SignalKind};

/// Builds the vendor signal for a MAC, if the registry knows one.
#[must_use]
pub fn vendor_signal(mac: MacAddr) -> Option<Signal> {
    oui::lookup(mac).map(|v| Signal::new(SignalKind::Vendor, v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_signal_wraps_the_registry_lookup() {
        let mac: MacAddr = "b8:27:eb:00:11:22".parse().expect("mac");
        let signal = vendor_signal(mac).expect("raspberry pi is in the registry");
        assert_eq!(signal.kind, SignalKind::Vendor);
        assert_eq!(signal.value, "Raspberry Pi Foundation");

        let randomised: MacAddr = "02:00:00:00:11:22".parse().expect("mac");
        assert!(vendor_signal(randomised).is_none());
    }
}
