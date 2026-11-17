//! Points in time, as the daemon stores, prints and serializes them.
//!
//! [`Timestamp`] is a [`jiff::Timestamp`] with the daemon's formats attached.
//! It exists because the formats are part of the contract and the time crate
//! underneath is not: until 1.0.x the daemon used chrono, which was declared
//! unmaintained (RUSTSEC-2026-0543), and every timestamp it ever wrote to the
//! status file, an export bundle, `ng_events.details` or a log line has the
//! shape chrono gave it. jiff's own formats differ in two places, so they are
//! fixed here once rather than at every place a timestamp is written:
//!
//! - **Serialized** (serde, `Debug`): RFC 3339 in UTC with a `Z`, and the
//!   fractional second written with 0, 3, 6 or 9 digits, the fewest that hold
//!   it exactly. `2026-11-17T19:15:27.957148Z`, never `…27.957148000Z` and never
//!   `…27.9571Z`. jiff trims to the last non-zero digit instead.
//! - **Displayed**: `2026-11-17 19:15:27.957148 UTC`, the same fraction rule.
//!
//! Deserializing accepts any RFC 3339 timestamp with an offset, as before.
//! Postgres reads and writes it as `TIMESTAMPTZ` through tokio-postgres's
//! `with-jiff-0_2` support, at the column's microsecond precision.
//!
//! Durations are [`jiff::SignedDuration`] directly; nothing serializes one.

use std::fmt;
use std::ops::{Add, AddAssign, Sub, SubAssign};

use jiff::SignedDuration;
use jiff::tz::Offset;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A point in time, in UTC.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(jiff::Timestamp);

impl Timestamp {
    /// The Unix epoch.
    pub const UNIX_EPOCH: Timestamp = Timestamp(jiff::Timestamp::UNIX_EPOCH);

    /// Now, from the system clock.
    #[must_use]
    pub fn now() -> Self {
        Timestamp(jiff::Timestamp::now())
    }

    /// Seconds and nanoseconds since the Unix epoch, when they name a
    /// representable instant. `nanos` must be below one billion.
    #[must_use]
    pub fn from_unix(secs: i64, nanos: u32) -> Option<Self> {
        let nanos = i32::try_from(nanos).ok().filter(|n| *n < 1_000_000_000)?;
        jiff::Timestamp::new(secs, nanos).ok().map(Timestamp)
    }

    /// A calendar date and time of day in UTC, when it is a real one.
    #[must_use]
    pub fn from_utc(
        year: i16,
        month: i8,
        day: i8,
        hour: i8,
        minute: i8,
        second: i8,
    ) -> Option<Self> {
        jiff::civil::DateTime::new(year, month, day, hour, minute, second, 0)
            .ok()?
            .to_zoned(jiff::tz::TimeZone::UTC)
            .ok()
            .map(|zoned| Timestamp(zoned.timestamp()))
    }

    /// Whole seconds since the Unix epoch, rounded toward negative infinity
    /// for instants before it.
    #[must_use]
    pub fn unix_seconds(self) -> i64 {
        let secs = self.0.as_second();
        if self.0.subsec_nanosecond() < 0 {
            secs - 1
        } else {
            secs
        }
    }

    /// The nanoseconds past [`unix_seconds`](Self::unix_seconds), in
    /// `0..1_000_000_000`.
    #[must_use]
    pub fn subsec_nanos(self) -> u32 {
        let nanos = self.0.subsec_nanosecond();
        let nanos = if nanos < 0 {
            nanos + 1_000_000_000
        } else {
            nanos
        };
        u32::try_from(nanos).unwrap_or(0)
    }

    /// The microseconds past [`unix_seconds`](Self::unix_seconds).
    #[must_use]
    pub fn subsec_micros(self) -> u32 {
        self.subsec_nanos() / 1_000
    }

    /// The milliseconds past [`unix_seconds`](Self::unix_seconds).
    #[must_use]
    pub fn subsec_millis(self) -> u32 {
        self.subsec_nanos() / 1_000_000
    }

    /// How long after `earlier` this is; negative when it is before.
    #[must_use]
    pub fn since(self, earlier: Timestamp) -> SignedDuration {
        self.0.duration_since(earlier.0)
    }

    /// This instant plus a duration, unless that leaves the representable
    /// range.
    #[must_use]
    pub fn checked_add(self, duration: SignedDuration) -> Option<Self> {
        self.0.checked_add(duration).ok().map(Timestamp)
    }

    /// This instant minus a duration, unless that leaves the representable
    /// range.
    #[must_use]
    pub fn checked_sub(self, duration: SignedDuration) -> Option<Self> {
        self.0.checked_sub(duration).ok().map(Timestamp)
    }

    /// The civil date and time this instant is at a fixed UTC offset.
    #[must_use]
    pub fn at_offset(self, offset: Offset) -> jiff::civil::DateTime {
        offset.to_datetime(self.0)
    }

    /// Minutes past midnight at a fixed UTC offset, `0..1440`.
    #[must_use]
    pub fn minute_of_day_at(self, offset: Offset) -> u32 {
        let civil = self.at_offset(offset);
        u32::from(civil.hour().unsigned_abs()) * 60 + u32::from(civil.minute().unsigned_abs())
    }

    /// The calendar date at a fixed UTC offset.
    #[must_use]
    pub fn date_at(self, offset: Offset) -> jiff::civil::Date {
        self.at_offset(offset).date()
    }

    /// The UTC calendar date this instant falls on.
    #[must_use]
    pub fn utc_date(self) -> jiff::civil::Date {
        self.at_offset(Offset::UTC).date()
    }

    /// Midnight UTC at the start of this instant's UTC day.
    #[must_use]
    pub fn start_of_utc_day(self) -> Self {
        let midnight = self.utc_date().to_datetime(jiff::civil::Time::midnight());
        Offset::UTC.to_timestamp(midnight).map_or(self, Timestamp)
    }

    /// Formats in UTC with a `strftime` pattern.
    ///
    /// Only the conversions the daemon uses are relied on: `%Y`, `%m`, `%d`,
    /// `%H`, `%M`, `%S` and literal text. They agree with chrono's.
    #[must_use]
    pub fn strftime(self, pattern: &str) -> String {
        self.at_offset(Offset::UTC).strftime(pattern).to_string()
    }

    /// The jiff timestamp underneath.
    #[must_use]
    pub const fn as_jiff(self) -> jiff::Timestamp {
        self.0
    }

    /// Writes `YYYY-MM-DD{sep}HH:MM:SS` and the fraction, in UTC.
    fn write_utc(self, f: &mut fmt::Formatter<'_>, separator: char) -> fmt::Result {
        let civil = self.at_offset(Offset::UTC);
        write!(
            f,
            "{:04}-{:02}-{:02}{separator}{:02}:{:02}:{:02}",
            civil.year(),
            civil.month(),
            civil.day(),
            civil.hour(),
            civil.minute(),
            civil.second(),
        )?;
        write_fraction(f, self.subsec_nanos())
    }
}

/// Writes a fractional second the way chrono's `%.f` does: nothing for a whole
/// second, otherwise three, six or nine digits, the fewest that are exact.
fn write_fraction(f: &mut fmt::Formatter<'_>, nanos: u32) -> fmt::Result {
    if nanos == 0 {
        Ok(())
    } else if nanos.is_multiple_of(1_000_000) {
        write!(f, ".{:03}", nanos / 1_000_000)
    } else if nanos.is_multiple_of(1_000) {
        write!(f, ".{:06}", nanos / 1_000)
    } else {
        write!(f, ".{nanos:09}")
    }
}

impl Default for Timestamp {
    /// The Unix epoch.
    fn default() -> Self {
        Timestamp::UNIX_EPOCH
    }
}

impl fmt::Display for Timestamp {
    /// `2026-11-17 19:15:27.957148 UTC`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_utc(f, ' ')?;
        f.write_str(" UTC")
    }
}

impl fmt::Debug for Timestamp {
    /// `2026-11-17T19:15:27.957148Z`, the serialized form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_utc(f, 'T')?;
        f.write_str("Z")
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{self:?}"))
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        text.parse::<Timestamp>().map_err(serde::de::Error::custom)
    }
}

impl std::str::FromStr for Timestamp {
    type Err = jiff::Error;

    /// Any RFC 3339 timestamp with an offset.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        text.parse::<jiff::Timestamp>().map(Timestamp)
    }
}

impl Add<SignedDuration> for Timestamp {
    type Output = Timestamp;

    /// Panics if the result leaves the representable range, as chrono did.
    fn add(self, duration: SignedDuration) -> Timestamp {
        Timestamp(self.0 + duration)
    }
}

impl AddAssign<SignedDuration> for Timestamp {
    fn add_assign(&mut self, duration: SignedDuration) {
        *self = *self + duration;
    }
}

impl Sub<SignedDuration> for Timestamp {
    type Output = Timestamp;

    /// Panics if the result leaves the representable range, as chrono did.
    fn sub(self, duration: SignedDuration) -> Timestamp {
        Timestamp(self.0 - duration)
    }
}

impl SubAssign<SignedDuration> for Timestamp {
    fn sub_assign(&mut self, duration: SignedDuration) {
        *self = *self - duration;
    }
}

impl Sub for Timestamp {
    type Output = SignedDuration;

    fn sub(self, earlier: Timestamp) -> SignedDuration {
        self.since(earlier)
    }
}

impl From<jiff::Timestamp> for Timestamp {
    fn from(timestamp: jiff::Timestamp) -> Self {
        Timestamp(timestamp)
    }
}

impl From<Timestamp> for jiff::Timestamp {
    fn from(timestamp: Timestamp) -> Self {
        timestamp.0
    }
}

impl<'a> tokio_postgres::types::FromSql<'a> for Timestamp {
    fn from_sql(
        ty: &tokio_postgres::types::Type,
        raw: &'a [u8],
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        jiff::Timestamp::from_sql(ty, raw).map(Timestamp)
    }

    fn accepts(ty: &tokio_postgres::types::Type) -> bool {
        <jiff::Timestamp as tokio_postgres::types::FromSql>::accepts(ty)
    }
}

/// The Postgres epoch, 2000-01-01T00:00:00Z, which `TIMESTAMPTZ` counts
/// microseconds from.
const POSTGRES_EPOCH: jiff::Timestamp = jiff::Timestamp::constant(946_684_800, 0);

impl Timestamp {
    /// This instant cut to whole microseconds since the Postgres epoch, toward
    /// it, which is what chrono sent and so what every stored row holds.
    ///
    /// jiff's own encoding rounds to the nearest microsecond instead. On a
    /// clock with nanosecond resolution that would store some instants a
    /// microsecond later than the daemon had them, so the cut is made here
    /// and jiff is handed an instant it has nothing left to round.
    fn to_postgres_precision(self) -> jiff::Timestamp {
        let micros = self.0.duration_since(POSTGRES_EPOCH).as_micros();
        let micros = i64::try_from(micros).unwrap_or(if micros < 0 { i64::MIN } else { i64::MAX });
        POSTGRES_EPOCH
            .checked_add(SignedDuration::from_micros(micros))
            .unwrap_or(self.0)
    }
}

impl tokio_postgres::types::ToSql for Timestamp {
    fn to_sql(
        &self,
        ty: &tokio_postgres::types::Type,
        out: &mut bytes::BytesMut,
    ) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + Sync + Send>> {
        self.to_postgres_precision().to_sql(ty, out)
    }

    fn accepts(ty: &tokio_postgres::types::Type) -> bool {
        <jiff::Timestamp as tokio_postgres::types::ToSql>::accepts(ty)
    }

    tokio_postgres::types::to_sql_checked!();
}

/// The local UTC offset now, from the system time zone, the way the daemon
/// reads it once at startup for quiet hours and the nightly job.
#[must_use]
pub fn local_offset_now() -> Offset {
    jiff::tz::TimeZone::system().to_offset(jiff::Timestamp::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64, nanos: u32) -> Timestamp {
        Timestamp::from_unix(secs, nanos).expect("valid")
    }

    #[test]
    fn serialized_form_is_chronos_with_three_six_or_nine_fraction_digits() {
        // 2026-11-17T19:15:27Z
        let base = 1_794_942_927;
        let cases = [
            (0, "\"2026-11-17T19:15:27Z\""),
            (100_000_000, "\"2026-11-17T19:15:27.100Z\""),
            (957_148_000, "\"2026-11-17T19:15:27.957148Z\""),
            (957_100_000, "\"2026-11-17T19:15:27.957100Z\""),
            (1, "\"2026-11-17T19:15:27.000000001Z\""),
            (957_148_123, "\"2026-11-17T19:15:27.957148123Z\""),
        ];
        for (nanos, expected) in cases {
            let ts = at(base, nanos);
            assert_eq!(serde_json::to_string(&ts).expect("serializes"), expected);
            let back: Timestamp = serde_json::from_str(expected).expect("parses");
            assert_eq!(back, ts);
        }
    }

    #[test]
    fn display_is_chronos() {
        assert_eq!(
            at(1_794_942_927, 957_148_000).to_string(),
            "2026-11-17 19:15:27.957148 UTC"
        );
        assert_eq!(at(0, 0).to_string(), "1970-01-01 00:00:00 UTC");
        assert_eq!(format!("{:?}", at(0, 0)), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn an_offset_is_accepted_and_normalized_to_utc() {
        let ts: Timestamp = "2026-11-17T20:15:27.5+01:00".parse().expect("parses");
        assert_eq!(format!("{ts:?}"), "2026-11-17T19:15:27.500Z");
    }

    #[test]
    fn strftime_patterns_the_daemon_uses() {
        let ts = at(1_794_942_927, 957_148_000);
        assert_eq!(
            ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "2026-11-17 19:15:27 UTC"
        );
        assert_eq!(ts.strftime("%Y-%m-%d %H:%M"), "2026-11-17 19:15");
        assert_eq!(ts.strftime("%Y-%m-%d"), "2026-11-17");
    }

    #[test]
    fn unix_parts_and_construction_round_trip() {
        let ts = at(1_770_000_000, 500_000_000);
        assert_eq!(ts.unix_seconds(), 1_770_000_000);
        assert_eq!(ts.subsec_millis(), 500);
        assert_eq!(ts.subsec_micros(), 500_000);
        assert_eq!(Timestamp::from_unix(0, 1_000_000_000), None);
        assert_eq!(
            Timestamp::from_utc(2026, 2, 2, 9, 0, 0).expect("valid"),
            "2026-02-02T09:00:00Z".parse::<Timestamp>().expect("parses")
        );
        assert_eq!(Timestamp::from_utc(2026, 2, 30, 0, 0, 0), None);
        assert_eq!(
            at(1_794_942_927, 1).start_of_utc_day(),
            "2026-11-17T00:00:00Z".parse::<Timestamp>().expect("parses")
        );
    }

    #[test]
    fn postgres_receives_whole_microseconds_cut_toward_its_epoch_as_chrono_sent_them() {
        use tokio_postgres::types::{ToSql, Type};
        let encode = |ts: Timestamp| {
            let mut out = bytes::BytesMut::new();
            ts.to_sql(&Type::TIMESTAMPTZ, &mut out).expect("encodes");
            i64::from_be_bytes(out[..].try_into().expect("eight bytes"))
        };
        // 2026-11-17T19:15:27Z is this many microseconds after 2000-01-01.
        let whole = (1_794_942_927 - 946_684_800) * 1_000_000;
        assert_eq!(encode(at(1_794_942_927, 0)), whole);
        assert_eq!(encode(at(1_794_942_927, 957_148_000)), whole + 957_148);
        // 999 ns past a microsecond: chrono truncated, jiff alone would round up.
        assert_eq!(encode(at(1_794_942_927, 957_148_999)), whole + 957_148);
        assert_eq!(encode(at(1_794_942_927, 500)), whole);
        // Before the Postgres epoch the cut is still toward it, as chrono's
        // was: a nanosecond before is zero, not minus one.
        assert_eq!(encode(at(946_684_799, 999_999_999)), 0);
        assert_eq!(encode(at(946_684_799, 1)), -999_999);
    }

    #[test]
    fn arithmetic() {
        let a = at(100, 0);
        let b = a + SignedDuration::from_secs(90);
        assert_eq!(b - a, SignedDuration::from_secs(90));
        assert_eq!(a.since(b), SignedDuration::from_secs(-90));
        assert_eq!(b - SignedDuration::from_secs(90), a);
    }
}
