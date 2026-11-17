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

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::clock::Timestamp;
use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::json;

use crate::config::{self, Config};
use crate::db::{Db, queries};
use crate::identity::classify::{ClassifyInput, classify};
use crate::runtime::Status;
use crate::types::{Signal, SignalKind};

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

/// How many of the most recent events the summary lists; `events.json` has
/// them all.
const EVENTS_IN_SUMMARY: usize = 25;

/// One device as the bundle records it.
#[derive(Debug, Clone, Serialize)]
pub struct ExportedDevice {
    /// Hardware address.
    pub mac: String,
    /// The name a person would see.
    pub name: String,
    /// Whether anything named it: a person, or a naming signal. A vendor guess
    /// or the bare MAC is not a name.
    pub named: bool,
    /// Which kind of signal produced the name, for example `mdns_name`, or
    /// `vendor` and `mac` for the fallbacks.
    pub named_by: Option<String>,
    /// How much that kind of signal is trusted.
    pub name_confidence: Option<f32>,
    /// A name a person gave it, when one did.
    pub user_name: Option<String>,
    /// The classified device type.
    pub device_type: Option<String>,
    /// How much to trust the type.
    pub device_type_confidence: Option<f32>,
    /// Which evidence typed it, from the classifier run again over the stored
    /// signals. `None` when the classifier gives a different answer now, which
    /// happens when the type came from behaviour while the daemon was running.
    pub typed_by: Option<String>,
    /// The classified operating system family.
    pub os_family: Option<String>,
    /// The IEEE vendor for the MAC prefix.
    pub vendor: Option<String>,
    /// Best host name seen.
    pub hostname: Option<String>,
    /// Best mDNS instance name seen.
    pub mdns_name: Option<String>,
    /// Lifecycle state at export time.
    pub state: String,
    /// Most recent IPv4 address.
    pub last_ip: Option<String>,
    /// Most recent IPv6 address.
    pub last_ipv6: Option<String>,
    /// Interface last seen on.
    pub last_interface: Option<String>,
    /// First sighting.
    pub first_seen_at: Timestamp,
    /// Most recent sighting.
    pub last_seen_at: Timestamp,
    /// Every stored signal, as `{kind, value}`.
    pub signals: Vec<BTreeMap<&'static str, String>>,
}

impl ExportedDevice {
    /// Builds the exported form of one device from its row and its signals.
    #[must_use]
    pub fn new(record: &queries::DeviceRecord, signals: &[Signal]) -> Self {
        let user_name = record.display_name.clone().filter(|n| !n.trim().is_empty());
        let named_kind = record
            .identity_source
            .as_deref()
            .and_then(SignalKind::from_str_opt);
        let named = user_name.is_some()
            || named_kind.is_some_and(crate::device::is_naming_source)
                && record
                    .resolved_name
                    .as_deref()
                    .is_some_and(|n| !n.trim().is_empty());
        let again = classify(&ClassifyInput {
            mac: record.mac,
            signals,
            vendor: record.vendor.as_deref(),
            always_on: false,
        });
        let typed_by = record
            .device_type
            .as_ref()
            .filter(|t| again.device_type.as_ref() == Some(*t))
            .and(again.reason);
        ExportedDevice {
            mac: record.mac.to_string(),
            name: record.display(),
            named,
            named_by: record.identity_source.clone(),
            name_confidence: record.identity_confidence,
            user_name,
            device_type: record.device_type.clone(),
            device_type_confidence: record.device_type_confidence,
            typed_by,
            os_family: record.os_family.clone(),
            vendor: record.vendor.clone(),
            hostname: record.hostname.clone(),
            mdns_name: record.mdns_name.clone(),
            state: record.state.as_str().to_string(),
            last_ip: record.last_ip.clone(),
            last_ipv6: record.last_ipv6.clone(),
            last_interface: record.last_interface.clone(),
            first_seen_at: record.first_seen_at,
            last_seen_at: record.last_seen_at,
            signals: signals
                .iter()
                .map(|s| {
                    BTreeMap::from([
                        ("kind", s.kind.as_str().to_string()),
                        ("value", s.value.clone()),
                    ])
                })
                .collect(),
        }
    }
}

/// Writes the bundle into `dir`, which must not exist or must be empty.
///
/// Reads the database the configuration names, the runtime status file it
/// names, and the unknown-device sample it names, and writes nothing anywhere
/// but `dir`.
///
/// # Errors
///
/// Returns an error when `dir` holds anything already, when the database is
/// unreachable or its schema is not one this build reads, or when a file
/// cannot be written.
pub async fn export(config: &Config, dir: &Path) -> Result<ExportReport> {
    prepare(dir)?;

    let db = Db::connect(&config.database)?;
    db.require_schema().await?;
    let client = db.client().await?;
    let records = queries::load_devices(&client).await?;
    let signals = queries::load_all_signals(&client).await?;
    let events = queries::recent_events(&client, i64::MAX).await?;
    let now = Timestamp::now();

    let devices: Vec<ExportedDevice> = records
        .iter()
        .map(|r| ExportedDevice::new(r, signals.get(&r.id).map_or(&[][..], Vec::as_slice)))
        .collect();
    let status = Status::read(&config.runtime.status_path).ok();

    let mut report = ExportReport {
        dir: dir.to_path_buf(),
        files: Vec::new(),
        devices: devices.len(),
        events: events.len(),
    };

    write_json(dir, DEVICES_FILE, &devices, &mut report)?;
    let events_json: Vec<serde_json::Value> = events
        .iter()
        .map(|e| {
            json!({
                "id": e.id,
                "device_id": e.device_id,
                "device": e.device_label,
                "event_type": e.event_type,
                "timestamp": e.timestamp,
                "details": e.details,
                "notified": e.notified,
            })
        })
        .collect();
    write_json(dir, EVENTS_FILE, &events_json, &mut report)?;
    write_json(
        dir,
        VISIBILITY_FILE,
        &visibility_json(config, status.as_ref()),
        &mut report,
    )?;
    write_json(dir, CONFIG_FILE, &config.redacted(), &mut report)?;

    let sample_path = &config.capture.unknown_sample.path;
    let sample = if sample_path.is_file() {
        std::fs::copy(sample_path, dir.join(SAMPLE_FILE))
            .with_context(|| format!("could not copy the sample from {}", sample_path.display()))?;
        report.files.push(SAMPLE_FILE.to_string());
        Some(sample_facts(sample_path))
    } else {
        None
    };

    let summary = summary(
        config,
        now,
        status.as_ref(),
        &devices,
        &events,
        sample.as_ref(),
        &report,
    );
    std::fs::write(dir.join(SUMMARY_FILE), summary)
        .with_context(|| format!("could not write {}", dir.join(SUMMARY_FILE).display()))?;
    report.files.insert(0, SUMMARY_FILE.to_string());
    Ok(report)
}

/// Creates the bundle directory, or accepts an empty one.
fn prepare(dir: &Path) -> Result<()> {
    if dir.exists() {
        let mut entries =
            std::fs::read_dir(dir).with_context(|| format!("could not read {}", dir.display()))?;
        if entries.next().is_some() {
            bail!(
                "{} is not empty; export writes into a new or empty directory so it never \
                 overwrites anything",
                dir.display()
            );
        }
    }
    std::fs::create_dir_all(dir).with_context(|| format!("could not create {}", dir.display()))
}

/// Writes one JSON file into the bundle.
fn write_json<T: Serialize + ?Sized>(
    dir: &Path,
    name: &str,
    value: &T,
    report: &mut ExportReport,
) -> Result<()> {
    let path = dir.join(name);
    let bytes = serde_json::to_vec_pretty(value).with_context(|| format!("encoding {name}"))?;
    std::fs::write(&path, bytes).with_context(|| format!("could not write {}", path.display()))?;
    report.files.push(name.to_string());
    Ok(())
}

/// The visibility report as JSON: the status file's numbers and the verdicts
/// drawn from them, or a plain statement that there was no status file.
fn visibility_json(config: &Config, status: Option<&Status>) -> serde_json::Value {
    let path = config.runtime.status_path.display().to_string();
    let Some(status) = status else {
        return json!({
            "status_path": path,
            "status_found": false,
        });
    };
    let verdicts: BTreeMap<String, crate::runtime::visibility::Verdict> =
        status.verdicts().into_iter().collect();
    json!({
        "status_path": path,
        "status_found": true,
        "started_at": status.started_at,
        "updated_at": status.updated_at,
        "gateway": status.gateway,
        "interfaces": status.interfaces,
        "verdicts": verdicts,
        "sources": status.sources,
        "capture_failures": status.capture_failures,
        "unknown_sample": status.unknown_sample,
        "observations": status.observations,
        "events": status.events,
        "security_events": status.security_events,
        "devices": status.devices,
    })
}

/// What can be said about a sample file without reading it as pcap.
struct SampleFacts {
    bytes: u64,
    records: Option<u64>,
}

/// Counts the records in a sample by walking its record headers, which needs
/// no libpcap. `None` when the file is not shaped as this daemon writes it.
fn sample_facts(path: &Path) -> SampleFacts {
    let data = std::fs::read(path).unwrap_or_default();
    let bytes = data.len() as u64;
    let mut records = 0u64;
    let mut at = crate::capture::sample::FILE_HEADER_LEN as usize;
    let shaped = data.len() >= at
        && u32::from_ne_bytes([data[0], data[1], data[2], data[3]])
            == crate::capture::sample::PCAP_MAGIC;
    while shaped && at + 16 <= data.len() {
        let caplen = u32::from_ne_bytes([data[at + 8], data[at + 9], data[at + 10], data[at + 11]]);
        at += 16 + caplen as usize;
        if at > data.len() {
            return SampleFacts {
                bytes,
                records: None,
            };
        }
        records += 1;
    }
    SampleFacts {
        bytes,
        records: shaped.then_some(records),
    }
}

/// Makes a value safe inside a Markdown table cell.
fn cell(value: Option<&str>) -> String {
    value.map(str::trim).filter(|v| !v.is_empty()).map_or_else(
        || "-".to_string(),
        |v| v.replace('|', "\\|").replace('\n', " "),
    )
}

/// The human half of the bundle.
#[allow(clippy::too_many_lines)] // One section after another; splitting it
// would only scatter a document that reads top to bottom.
fn summary(
    config: &Config,
    now: Timestamp,
    status: Option<&Status>,
    devices: &[ExportedDevice],
    events: &[queries::EventRecord],
    sample: Option<&SampleFacts>,
    report: &ExportReport,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# netgraspd trip export\n");
    let _ = writeln!(
        out,
        "Written {} by netgraspd {}, from the database at `{}`.\n",
        now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        env!("CARGO_PKG_VERSION"),
        config::redact_database_url(&config.database.url)
    );

    let _ = writeln!(out, "## Visibility\n");
    match status {
        None => {
            let _ = writeln!(
                out,
                "There was no status file at `{}`, so there is no visibility report: the \
                 daemon was not run with this configuration, or could not write there.\n",
                config.runtime.status_path.display()
            );
        }
        Some(status) => {
            let _ = writeln!(
                out,
                "From the status file the daemon last wrote at {}, after running {}.\n",
                status.updated_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                crate::runtime::human_duration(status.uptime())
            );
            for (interface, verdict) in status.verdicts() {
                let _ = writeln!(out, "- **{interface}**: {}", verdict.line);
            }
            let _ = writeln!(out, "\n```");
            for line in status.visibility_lines() {
                let _ = writeln!(out, "{line}");
            }
            for line in status.capture_failure_lines() {
                let _ = writeln!(out, "{line}");
            }
            let _ = writeln!(out, "```\n");
        }
    }

    let named = devices.iter().filter(|d| d.named).count();
    let _ = writeln!(out, "## Devices\n");
    let _ = writeln!(
        out,
        "{} devices: {named} named, {} that nothing named. `devices.json` has every \
         signal behind each one.\n",
        devices.len(),
        devices.len() - named
    );
    if !devices.is_empty() {
        let _ = writeln!(
            out,
            "| MAC | Name | Named by | Type | Typed by | Vendor | Address | Last seen |"
        );
        let _ = writeln!(out, "|---|---|---|---|---|---|---|---|");
        for d in devices {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} | {} | {} | {} |",
                d.mac,
                cell(Some(&d.name)),
                cell(d.named_by.as_deref()),
                cell(d.device_type.as_deref()),
                cell(d.typed_by.as_deref()),
                cell(d.vendor.as_deref()),
                cell(d.last_ip.as_deref()),
                d.last_seen_at.strftime("%Y-%m-%d %H:%M"),
            );
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "## Events\n");
    if events.is_empty() {
        let _ = writeln!(out, "No events recorded.\n");
    } else {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for e in events {
            *counts.entry(e.event_type.as_str()).or_default() += 1;
        }
        let _ = writeln!(
            out,
            "{} events, all of them in `events.json`. By type:\n",
            events.len()
        );
        for (kind, n) in &counts {
            let _ = writeln!(out, "- {kind}: {n}");
        }
        let _ = writeln!(out, "\nThe most recent:\n");
        let _ = writeln!(out, "| When | Event | Device |");
        let _ = writeln!(out, "|---|---|---|");
        for e in events.iter().take(EVENTS_IN_SUMMARY) {
            let _ = writeln!(
                out,
                "| {} | {} | {} |",
                e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                e.event_type,
                cell(e.device_label.as_deref())
            );
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "## Unknown device sample\n");
    match sample {
        Some(facts) => {
            let records = facts
                .records
                .map_or_else(|| "an unknown number of".to_string(), |n| n.to_string());
            let _ = writeln!(
                out,
                "`{SAMPLE_FILE}`: {records} frames, {}, copied from `{}`. The first few \
                 broadcast and multicast frames from each device nothing named; open it in \
                 Wireshark or tcpdump.",
                crate::runtime::human_bytes(facts.bytes),
                config.capture.unknown_sample.path.display()
            );
            if let Some(s) = status.and_then(|s| s.unknown_sample.as_ref()) {
                let _ = writeln!(out, "\nThe last run: {}.", s.line());
            }
            let _ = writeln!(out);
        }
        None => {
            let _ = writeln!(
                out,
                "None: there is no sample at `{}`{}.\n",
                config.capture.unknown_sample.path.display(),
                if config.capture.unknown_sample.enabled {
                    ""
                } else {
                    " and the sample is switched off"
                }
            );
        }
    }

    let _ = writeln!(out, "## Configuration\n");
    let _ = writeln!(
        out,
        "`{CONFIG_FILE}` is the configuration this export ran with, every secret \
         replaced by `***`.\n"
    );
    let interfaces = if config.capture.interfaces.is_empty() {
        "the default selection".to_string()
    } else {
        config.capture.interfaces.join(", ")
    };
    let _ = writeln!(out, "- interfaces: {interfaces}");
    let _ = writeln!(out, "- sources: {}", config.capture.sources.join(", "));
    let _ = writeln!(out, "- notifications: {}", on_off(config.notify.enabled));
    let _ = writeln!(out, "- enrichment: {}", on_off(config.enrichment.enabled));
    let _ = writeln!(
        out,
        "- unknown device sample: {}",
        on_off(config.capture.unknown_sample.enabled)
    );
    let _ = writeln!(
        out,
        "- event retention: {} days, rollup after {} days\n",
        config.maintenance.event_retention_days, config.maintenance.rollup_after_days
    );

    let _ = writeln!(out, "## Files\n");
    let _ = writeln!(out, "- `{SUMMARY_FILE}`: this file");
    for file in &report.files {
        let _ = writeln!(out, "- `{file}`");
    }
    out
}

/// "on" or "off".
const fn on_off(on: bool) -> &'static str {
    if on { "on" } else { "off" }
}
