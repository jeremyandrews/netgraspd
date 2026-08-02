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
//! - [`identity`] turns observation signals into a display identity.
//! - [`device`] holds the MAC-keyed state machine and decides which state
//!   changes are events.
//! - [`events`] is the broadcast bus those events ride.
//! - [`notify`] dispatches events to notifiers, applying all rate limiting in
//!   the dispatcher rather than in any individual notifier.
//! - [`db`] persists devices, signals, presence sessions, events and IP
//!   history.
//!
//! **The rule the whole design serves: state changes are stored, raw packet
//! observations are not.** Nothing in this crate may write a row per packet.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod capture;
pub mod cli;
pub mod config;
pub mod daemon;
pub mod db;
pub mod device;
pub mod events;
pub mod identity;
pub mod notify;
pub mod types;
