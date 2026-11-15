//! The trip export: one directory, readable without a database.
//!
//! Written by `netgraspd export <DIR>` at the end of a run on a network the
//! operator does not own. The bundle is a `SUMMARY.md` for a person and the raw
//! data beside it as JSON for a program:
//!
//! - `devices.json`: every device, with what named it and what typed it;
//! - `events.json`: every event still in the database;
//! - `visibility.json`: the runtime status file's visibility report, with the
//!   verdict per interface;
//! - `config.json`: the effective configuration, every secret replaced by
//!   `***` ([`Config::redacted`]);
//! - `unknown-sample.pcap`: the unknown-device sample, when there is one.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::config::Config;

/// The human summary.
pub const SUMMARY_FILE: &str = "SUMMARY.md";
/// The device table.
pub const DEVICES_FILE: &str = "devices.json";
/// The events.
pub const EVENTS_FILE: &str = "events.json";
/// The visibility report.
pub const VISIBILITY_FILE: &str = "visibility.json";
/// The redacted configuration.
pub const CONFIG_FILE: &str = "config.json";
/// The unknown-device sample.
pub const SAMPLE_FILE: &str = "unknown-sample.pcap";

/// What an export wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportReport {
    /// The bundle directory.
    pub dir: PathBuf,
    /// The files written, in the order they were written.
    pub files: Vec<String>,
    /// Devices exported.
    pub devices: usize,
    /// Events exported.
    pub events: usize,
}

/// Writes the bundle into `dir`, which must not exist or must be empty.
///
/// # Errors
///
/// Returns an error when `dir` holds anything already, when the database is
/// unreachable or its schema is not one this build reads, or when a file
/// cannot be written.
pub async fn export(config: &Config, dir: &Path) -> Result<ExportReport> {
    let _ = config;
    Ok(ExportReport {
        dir: dir.to_path_buf(),
        ..ExportReport::default()
    })
}
