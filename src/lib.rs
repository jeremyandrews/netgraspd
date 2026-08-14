//! Netgrasp daemon library.
//!
//! `netgraspd` watches LAN broadcast and multicast traffic and never transmits.
//! It identifies devices by combining signals from several protocols, keeps a
//! per-device state machine, and alerts when a device it has not seen before
//! appears.
//!
//! The layering, outermost first:
//!
//! - [`capture`] turns packets into [`types::Observation`]s. It is the only
//!   layer that touches libpcap.
//! - [`analyze`] watches that same observation stream for the six security
//!   conditions, keeping its own bounded in-memory state and nothing else.
//! - [`identity`] turns observation signals into a display identity.
//! - [`enrich`] is the one layer that asks a question rather than waiting to be
//!   told: it reads a controller the operator already runs, never a monitored
//!   device.
//! - [`location`] turns an access point into a place, and a pair of access
//!   points into an arrival, a departure or somebody wandering about.
//! - [`people`] tracks who is home from which of their devices are online.
//! - [`device`] holds the MAC-keyed state machine and decides which state
//!   changes are events.
//! - [`events`] is the broadcast bus those events ride.
//! - [`notify`] dispatches events to notifiers, applying all rate limiting in
//!   the dispatcher rather than in any individual notifier.
//! - [`db`] persists devices, signals, presence sessions, events, IP history,
//!   location stays and people, and owns the schema contract the Trovato plugin
//!   reads.
//! - [`maintenance`] rolls up, prunes and vacuums, which is what makes an
//!   unattended year on a Raspberry Pi survivable.
//! - [`runtime`] publishes the counters `netgraspd stats` reads out of band.
//!
//! **The rule the whole design serves: state changes are stored, raw packet
//! observations are not.** Nothing in this crate may write a row per packet.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod analyze;
pub mod capture;
pub mod cli;
pub mod config;
pub mod daemon;
pub mod db;
pub mod device;
pub mod enrich;
pub mod events;
pub mod identity;
pub mod location;
pub mod maintenance;
pub mod notify;
pub mod people;
pub mod runtime;
pub mod types;
