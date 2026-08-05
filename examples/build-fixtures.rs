//! Regenerates the milestone 2 packet fixtures.
//!
//! ```text
//! cargo run --example build-fixtures
//! ```
//!
//! Writes every frame in [`netgraspd::capture::fixtures::build`] to
//! `tests/fixtures/*.bin`. The committed files are what the parsers actually
//! read; this exists so that "the documented layout" and "the bytes on disk"
//! cannot drift apart, and so that changing a fixture is an edit to readable
//! Rust rather than to a hex dump.
//!
//! `fixtures::build::tests::the_committed_fixtures_match_the_builders` fails if
//! somebody changes a builder and forgets to run this.

use std::path::Path;

fn main() -> std::io::Result<()> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::create_dir_all(&dir)?;
    for (name, bytes) in netgraspd::capture::fixtures::build::all() {
        let path = dir.join(format!("{name}.bin"));
        std::fs::write(&path, &bytes)?;
        println!("{} bytes -> {}", bytes.len(), path.display());
    }
    Ok(())
}
