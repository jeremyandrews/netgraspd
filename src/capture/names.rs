//! Shared rules for turning a name off the wire into a name worth showing.
//!
//! Five protocols volunteer device names and every one of them can carry
//! something useless: a blank string, a hostname that is really an address, a
//! control character from a firmware bug, or a kilobyte of padding. The rules
//! are identical for all of them, so they live here rather than being
//! reimplemented per parser with slightly different edges.

/// Longest name Netgrasp will show. Anything longer is a responder being
/// creative rather than descriptive.
pub const MAX_NAME_LEN: usize = 96;

/// Normalises a name from a packet, or rejects it.
///
/// Rejects the blank name, anything over [`MAX_NAME_LEN`], anything containing a
/// control character, and any name made only of digits and separators, which is
/// an address in disguise (`192-168-1-40`, `10.0.0.5`) rather than a name a
/// human chose.
#[must_use]
pub fn clean_name(raw: &str) -> Option<String> {
    let name = raw.trim().trim_end_matches('.').trim();
    if name.is_empty() || name.chars().count() > MAX_NAME_LEN {
        return None;
    }
    if name.chars().any(char::is_control) {
        return None;
    }
    if name
        .chars()
        .all(|c| c.is_ascii_digit() || c == '-' || c == '_' || c == '.')
    {
        return None;
    }
    Some(name.to_string())
}

/// Normalises a value that is not a name but is still shown to a human or
/// matched against a table: a vendor class, a model string, a service type.
///
/// Looser than [`clean_name`]: a value like `MSFT 5.0` or `1,15,3,6` is
/// meaningful even though it would fail the address-in-disguise test.
#[must_use]
pub fn clean_value(raw: &str) -> Option<String> {
    let value = raw.trim();
    if value.is_empty() || value.chars().count() > MAX_NAME_LEN {
        return None;
    }
    if value.chars().any(char::is_control) {
        return None;
    }
    Some(value.to_string())
}

/// Decodes a byte slice from a packet as a printable string.
///
/// Trailing NUL padding is stripped before decoding, because several protocols
/// pad a fixed-width field with zeroes and a NUL is a control character that
/// would otherwise reject the whole value.
#[must_use]
pub fn text(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .rposition(|b| *b != 0)
        .map_or(0, |last| last + 1);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_and_overlong_names_are_rejected() {
        assert_eq!(clean_name(""), None);
        assert_eq!(clean_name("   "), None);
        assert_eq!(clean_name("."), None);
        assert_eq!(clean_name(&"x".repeat(MAX_NAME_LEN + 1)), None);
        assert_eq!(
            clean_name(&"x".repeat(MAX_NAME_LEN)).map(|s| s.len()),
            Some(MAX_NAME_LEN)
        );
    }

    #[test]
    fn addresses_wearing_a_hostname_costume_are_rejected() {
        assert_eq!(clean_name("192-168-1-40"), None);
        assert_eq!(clean_name("10.0.0.5"), None);
        assert_eq!(clean_name("____"), None);
        assert_eq!(clean_name("pi4"), Some("pi4".into()));
    }

    #[test]
    fn control_characters_are_rejected_rather_than_stripped() {
        // Stripping would silently turn a corrupt name into a plausible one,
        // and a name Netgrasp invented is worse than no name.
        assert_eq!(clean_name("lap\u{0}top"), None);
        assert_eq!(clean_name("lap\ntop"), None);
        assert_eq!(clean_name("lap\u{7}top"), None);
    }

    #[test]
    fn trailing_dots_and_padding_are_trimmed() {
        assert_eq!(clean_name("printer.lan."), Some("printer.lan".into()));
        assert_eq!(clean_name("  nas.local.  "), Some("nas.local".into()));
    }

    #[test]
    fn values_may_be_things_a_name_may_not() {
        assert_eq!(clean_value("MSFT 5.0"), Some("MSFT 5.0".into()));
        assert_eq!(
            clean_value("1,15,3,6,44"),
            Some("1,15,3,6,44".into()),
            "a fingerprint is all digits and separators and is still meaningful"
        );
        assert_eq!(clean_value(""), None);
        assert_eq!(clean_value("a\u{0}b"), None);
    }

    #[test]
    fn nul_padding_is_stripped_before_decoding() {
        assert_eq!(text(b"laptop\0\0\0\0"), "laptop");
        assert_eq!(text(b"laptop"), "laptop");
        assert_eq!(text(b"\0\0\0"), "");
        assert_eq!(text(b""), "");
    }

    #[test]
    fn an_interior_nul_survives_decoding_and_is_caught_by_the_cleaner() {
        // Stripping only the tail is deliberate: an interior NUL means the field
        // is not what the parser thought it was, and clean_name must see it.
        assert_eq!(text(b"lap\0top\0\0"), "lap\u{0}top");
        assert_eq!(clean_name(&text(b"lap\0top\0\0")), None);
    }
}
