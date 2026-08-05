//! DHCP option 55 fingerprints, embedded at build time.
//!
//! `data/dhcp_fingerprints.conf` is a curated, Fingerbank-shaped table of
//! parameter request lists. It is compiled into the binary, so classification
//! works on a network with no internet access and with no runtime API
//! dependency, which is the whole point: a passive monitor that phones a vendor
//! to identify a device is not a passive monitor.
//!
//! `netgraspd update-fingerprints <url>` refreshes it. The downloaded file is
//! parsed and validated before it replaces anything, and the daemon prefers the
//! downloaded file when one exists. Nothing fetches on its own.
//!
//! ## Matching
//!
//! An **exact** match on the ordered list is what Fingerbank does and is what
//! this trusts, at 0.95 confidence. Exact matching alone identifies only devices
//! whose list is already in the table, so a **nearest** match follows: the
//! longest common subsequence of the two ordered lists, normalised by the longer
//! of them. That respects order, which matters because two operating systems
//! routinely request the same options in a different sequence, and it tolerates
//! the one or two extra options a point release adds. A near match is reported
//! at a confidence proportional to how near it is, always below an exact one, so
//! a downstream reader can tell a match from a guess.

use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};

/// The curated table compiled into the binary.
const EMBEDDED: &str = include_str!("../../data/dhcp_fingerprints.conf");

/// Confidence reported for an exact match on the ordered option list.
pub const EXACT_CONFIDENCE: f64 = 0.95;

/// Ceiling for a nearest match, scaled by how similar the lists are. Below the
/// exact confidence by construction, so an exact match always wins.
const NEAREST_CEILING: f64 = 0.8;

/// How similar two lists must be before a nearest match is reported at all.
///
/// At 0.85 a seven-option list may differ by one option and still match. Lower
/// than that and unrelated embedded stacks start matching each other, because
/// short lists share their first few options with everything.
pub const NEAREST_THRESHOLD: f64 = 0.85;

/// Longest fingerprint the parser will accept from a file, matching the cap the
/// DHCP parser puts on what it will record.
const MAX_LIST_LEN: usize = 64;

/// One fingerprint class: a description, the option lists that identify it, and
/// what those lists imply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintClass {
    /// Section name from the file, kept so a match can be traced back to a line.
    pub id: String,
    /// Human-readable name of the class.
    pub description: String,
    /// Operating system family this class implies, when it implies one.
    pub os_family: Option<String>,
    /// Device type this class implies, when it implies one.
    pub device_type: Option<String>,
    /// The option lists, in the order the device puts them on the wire.
    pub fingerprints: Vec<Vec<u8>>,
}

/// What a lookup found.
#[derive(Debug, Clone, PartialEq)]
pub struct FingerprintMatch<'a> {
    /// The class that matched.
    pub class: &'a FingerprintClass,
    /// How much to trust it.
    pub confidence: f64,
    /// True for an exact match on the ordered list, false for a nearest match.
    pub exact: bool,
}

/// A parsed fingerprint table.
#[derive(Debug, Clone, Default)]
pub struct FingerprintDb {
    classes: Vec<FingerprintClass>,
    /// Exact lists, rendered the same way the DHCP parser renders them, mapped
    /// to the class they belong to.
    exact: HashMap<String, usize>,
}

impl FingerprintDb {
    /// Parses a table.
    ///
    /// # Errors
    ///
    /// Returns an error when the text contains no usable class, which is how a
    /// download of an error page or an empty file is caught before it replaces
    /// a working table.
    pub fn parse(text: &str) -> Result<Self> {
        let mut classes: Vec<FingerprintClass> = Vec::new();
        let mut current: Option<FingerprintClass> = None;

        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            if let Some(id) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                if let Some(class) = current.take()
                    && !class.fingerprints.is_empty()
                {
                    classes.push(class);
                }
                current = Some(FingerprintClass {
                    id: id.trim().to_string(),
                    description: String::new(),
                    os_family: None,
                    device_type: None,
                    fingerprints: Vec::new(),
                });
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let Some(class) = current.as_mut() else {
                continue;
            };
            let value = value.trim();
            // Unknown keys are ignored rather than rejected, so the much larger
            // upstream Fingerbank file parses here unchanged.
            match key.trim().to_ascii_lowercase().as_str() {
                "description" => class.description = value.to_string(),
                "os" => class.os_family = non_empty(value),
                "device_type" => class.device_type = non_empty(value),
                "fingerprints" => class.fingerprints.extend(parse_lists(value)),
                _ => {}
            }
        }
        if let Some(class) = current.take()
            && !class.fingerprints.is_empty()
        {
            classes.push(class);
        }
        if classes.is_empty() {
            bail!("no usable fingerprint classes found");
        }

        let mut exact = HashMap::with_capacity(classes.len() * 2);
        for (index, class) in classes.iter().enumerate() {
            for list in &class.fingerprints {
                // First class wins a duplicate list. The alternative is a
                // silent last-writer-wins, which makes the file's order matter
                // without saying so.
                exact.entry(render(list)).or_insert(index);
            }
        }
        Ok(FingerprintDb { classes, exact })
    }

    /// Reads a table from a file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or does not parse.
    pub fn from_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("could not read {}", path.display()))?;
        FingerprintDb::parse(&text)
            .with_context(|| format!("{} is not a fingerprint table", path.display()))
    }

    /// The table compiled into the binary.
    ///
    /// # Panics
    ///
    /// Panics when the embedded table does not parse, which is a build-time
    /// mistake rather than a runtime condition: the file is checked in and a
    /// test parses it.
    #[must_use]
    pub fn embedded() -> Self {
        FingerprintDb::parse(EMBEDDED).expect("the embedded fingerprint table must parse")
    }

    /// How many classes are loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.classes.len()
    }

    /// True when nothing is loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }

    /// How many distinct option lists are loaded.
    #[must_use]
    pub fn list_count(&self) -> usize {
        self.classes.iter().map(|c| c.fingerprints.len()).sum()
    }

    /// Looks a rendered option 55 list up, exactly first and then by nearest
    /// ordered match.
    ///
    /// The argument is the comma-separated decimal form the DHCP parser
    /// produces, so caller and table never disagree about rendering.
    #[must_use]
    pub fn lookup(&self, rendered: &str) -> Option<FingerprintMatch<'_>> {
        if let Some(index) = self.exact.get(rendered) {
            return Some(FingerprintMatch {
                class: self.classes.get(*index)?,
                confidence: EXACT_CONFIDENCE,
                exact: true,
            });
        }
        let wanted = parse_list(rendered)?;
        let mut best: Option<(usize, f64)> = None;
        for (index, class) in self.classes.iter().enumerate() {
            for list in &class.fingerprints {
                let score = similarity(&wanted, list);
                if score >= NEAREST_THRESHOLD && best.is_none_or(|(_, b)| score > b) {
                    best = Some((index, score));
                }
            }
        }
        let (index, score) = best?;
        Some(FingerprintMatch {
            class: self.classes.get(index)?,
            confidence: score * NEAREST_CEILING,
            exact: false,
        })
    }
}

/// The process-wide table, installed once at startup.
static INSTALLED: OnceLock<FingerprintDb> = OnceLock::new();

/// Installs a table, if none has been installed yet.
///
/// Returns false when one was already in place, which happens when a lookup ran
/// before startup finished and installed the embedded copy.
pub fn install(db: FingerprintDb) -> bool {
    INSTALLED.set(db).is_ok()
}

/// The installed table, falling back to the embedded copy.
#[must_use]
pub fn db() -> &'static FingerprintDb {
    INSTALLED.get_or_init(FingerprintDb::embedded)
}

/// Renders an option list the way the DHCP parser does, so the two forms are
/// comparable without normalising at lookup time.
#[must_use]
pub fn render(list: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(list.len() * 4);
    for (i, code) in list.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        // Infallible: writing a u8 into a String cannot fail.
        let _ = write!(out, "{code}");
    }
    out
}

/// Reads one comma-separated list, rejecting anything with a non-numeric or
/// out-of-range entry.
#[must_use]
fn parse_list(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for part in text.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        out.push(part.parse::<u8>().ok()?);
    }
    (!out.is_empty() && out.len() <= MAX_LIST_LEN).then_some(out)
}

/// Reads the pipe-separated alternatives on a `fingerprints` line.
fn parse_lists(text: &str) -> Vec<Vec<u8>> {
    text.split('|').filter_map(parse_list).collect()
}

/// Trims a value and drops it if nothing is left.
fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Order-preserving similarity of two option lists, in `[0.0, 1.0]`.
///
/// The longest common subsequence normalised by the longer list. A subsequence
/// rather than a set intersection because the order carries most of the signal;
/// normalising by the longer list rather than the shorter one is what stops a
/// four-option embedded fingerprint from scoring 1.0 against a fourteen-option
/// Windows one that happens to start the same way.
#[must_use]
pub fn similarity(a: &[u8], b: &[u8]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let mut previous = vec![0usize; b.len() + 1];
    let mut current = vec![0usize; b.len() + 1];
    for x in a {
        for (j, y) in b.iter().enumerate() {
            current[j + 1] = if x == y {
                previous[j] + 1
            } else {
                current[j].max(previous[j + 1])
            };
        }
        std::mem::swap(&mut previous, &mut current);
        current.iter_mut().for_each(|slot| *slot = 0);
    }
    let common = previous[b.len()];
    #[allow(clippy::cast_precision_loss)] // Lists are capped at 64 entries, so
    // every count here converts to f64 exactly.
    let ratio = common as f64 / a.len().max(b.len()) as f64;
    ratio
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_table_parses_and_is_substantial() {
        let db = FingerprintDb::embedded();
        assert!(db.len() >= 20, "only {} classes", db.len());
        assert!(db.list_count() > db.len(), "classes should carry variants");
        assert!(!db.is_empty());
    }

    #[test]
    fn every_embedded_class_says_something_useful() {
        for class in &FingerprintDb::embedded().classes {
            assert!(
                !class.description.is_empty(),
                "class {} has no description",
                class.id
            );
            assert!(
                class.os_family.is_some() || class.device_type.is_some(),
                "class {} implies nothing, so matching it would be pointless",
                class.id
            );
        }
    }

    #[test]
    fn an_exact_match_beats_everything_and_says_so() {
        let db = FingerprintDb::embedded();
        let found = db
            .lookup("1,121,3,6,15,119,252")
            .expect("iOS is in the table");
        assert!(found.exact);
        assert_eq!(found.confidence, EXACT_CONFIDENCE);
        assert_eq!(found.class.os_family.as_deref(), Some("iOS"));
    }

    #[test]
    fn a_near_miss_matches_at_a_lower_confidence() {
        let db = FingerprintDb::embedded();
        // The iOS list with one extra option appended: still iOS, but a guess.
        let found = db
            .lookup("1,121,3,6,15,119,252,44")
            .expect("a near miss should still match");
        assert!(!found.exact);
        assert!(
            found.confidence < EXACT_CONFIDENCE,
            "a guess must never claim as much as a match: {}",
            found.confidence
        );
        assert!(found.confidence > 0.5, "{}", found.confidence);
    }

    #[test]
    fn an_unrelated_list_matches_nothing() {
        let db = FingerprintDb::embedded();
        assert_eq!(db.lookup("200,201,202,203,204,205,206,207"), None);
        assert_eq!(db.lookup(""), None);
        assert_eq!(db.lookup("not,a,list"), None);
    }

    #[test]
    fn order_is_part_of_the_fingerprint() {
        // The same options in a different order are a different device. The
        // similarity metric may still find them related, but the exact map must
        // not treat them as the same thing.
        let db = FingerprintDb::embedded();
        let forward = db.lookup("1,121,3,6,15,119,252").expect("exact");
        assert!(forward.exact);
        let reversed = db.lookup("252,119,15,6,3,121,1");
        assert!(
            reversed.is_none_or(|m| !m.exact),
            "a reversed list is not an exact match"
        );
    }

    #[test]
    fn similarity_respects_order_and_length() {
        assert_eq!(similarity(&[1, 2, 3], &[1, 2, 3]), 1.0);
        assert_eq!(similarity(&[], &[1]), 0.0);
        assert_eq!(similarity(&[1, 2, 3], &[]), 0.0);
        // One insertion into a three-element list: two of four in common.
        assert!((similarity(&[1, 2, 3], &[1, 9, 2, 3]) - 0.75).abs() < 1e-9);
        // Reversal shares only one element as a subsequence.
        assert!(similarity(&[1, 2, 3], &[3, 2, 1]) < 0.5);
        // A short list inside a long one must not score 1.0.
        assert!(
            similarity(&[1, 3], &[1, 3, 6, 15, 31, 33, 43, 44]) < 0.3,
            "normalising by the shorter list would make every stub match"
        );
    }

    #[test]
    fn parsing_rejects_a_file_that_is_not_a_table() {
        assert!(FingerprintDb::parse("").is_err());
        assert!(FingerprintDb::parse("<html>404 not found</html>").is_err());
        assert!(
            FingerprintDb::parse("[1]\ndescription = nothing\n").is_err(),
            "a class with no fingerprints is not usable"
        );
    }

    #[test]
    fn unknown_keys_are_ignored_so_the_upstream_file_still_parses() {
        let db = FingerprintDb::parse(
            "[42]\n\
             description = Something\n\
             os = Linux\n\
             mac_vendor = irrelevant\n\
             score = 100\n\
             fingerprints = 1,2,3\n",
        )
        .expect("parses");
        assert_eq!(db.len(), 1);
        let found = db.lookup("1,2,3").expect("matches");
        assert_eq!(found.class.os_family.as_deref(), Some("Linux"));
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let db = FingerprintDb::parse(
            "; a comment\n\
             # another\n\
             \n\
             [7]\n\
             description = X\n\
             device_type = printer\n\
             fingerprints = 1,2 | 3,4\n",
        )
        .expect("parses");
        assert_eq!(db.list_count(), 2, "pipes separate alternatives");
        assert_eq!(
            db.lookup("3,4")
                .expect("matches")
                .class
                .device_type
                .as_deref(),
            Some("printer")
        );
    }

    #[test]
    fn an_entry_outside_the_option_range_invalidates_its_list() {
        let db = FingerprintDb::parse("[1]\ndescription = X\nos = Y\nfingerprints = 1,2,999|5,6\n")
            .expect("parses");
        assert_eq!(db.list_count(), 1, "the bad list is dropped, not clamped");
        assert!(db.lookup("5,6").is_some());
    }

    #[test]
    fn rendering_matches_what_the_dhcp_parser_produces() {
        assert_eq!(render(&[1, 121, 3]), "1,121,3");
        assert_eq!(
            render(&[1, 121, 3]),
            crate::capture::dhcp::render_param_list(&[1, 121, 3]).expect("renders")
        );
    }

    #[test]
    fn the_installed_table_defaults_to_the_embedded_one() {
        // Whichever test runs first decides, so assert the property that holds
        // either way: a table is always available and it always parses.
        assert!(!db().is_empty());
    }
}
