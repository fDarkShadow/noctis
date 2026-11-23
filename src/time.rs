//! UTC timestamps as they appear on the wire (REST API, webhooks, findings).
//!
//! [`UtcTime`] wraps [`jiff::Timestamp`] and pins the exact RFC 3339 shape API
//! clients have always received: `Z` suffix, and the fractional second printed
//! in groups of 0, 3, 6 or 9 digits (`…:40Z`, `…:40.120Z`, `…:40.123400Z`,
//! `…:40.123456700Z`). jiff's own serializer trims trailing zeros instead
//! (`…:40.12Z`) — valid RFC 3339, but a change for clients that compare or
//! parse timestamps strictly.

use std::fmt;

use jiff::fmt::temporal::DateTimePrinter;
use jiff::Timestamp;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A point in time, always rendered in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcTime(Timestamp);

impl UtcTime {
    pub fn now() -> Self {
        Self(Timestamp::now())
    }

    /// Milliseconds elapsed from `earlier` to `self`; negative if `earlier` is later.
    pub fn millis_since(self, earlier: UtcTime) -> i128 {
        self.0.duration_since(earlier.0).as_millis()
    }

    /// `self` shifted back by `ms` milliseconds (test helper).
    #[cfg(test)]
    pub fn minus_millis(self, ms: i64) -> Self {
        Self(
            self.0
                .checked_sub(jiff::SignedDuration::from_millis(ms))
                .expect("in range"),
        )
    }
}

impl fmt::Display for UtcTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let nanos = self.0.subsec_nanosecond().unsigned_abs();
        let digits = if nanos == 0 {
            0
        } else if nanos.is_multiple_of(1_000_000) {
            3
        } else if nanos.is_multiple_of(1_000) {
            6
        } else {
            9
        };
        let printer = DateTimePrinter::new().precision(Some(digits));
        f.write_str(&printer.timestamp_to_string(&self.0))
    }
}

impl Serialize for UtcTime {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for UtcTime {
    /// Accepts any RFC 3339 timestamp, whatever its offset, and normalises to UTC.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Timestamp::deserialize(deserializer).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(nanos: i32) -> UtcTime {
        UtcTime(Timestamp::new(1_795_000_000, nanos).unwrap())
    }

    /// Expected strings are what chrono 0.4 (`DateTime<Utc>` + serde) produced,
    /// i.e. the format API clients already depend on.
    #[test]
    fn wire_format_matches_previous_chrono_output() {
        let cases = [
            (0, "2026-11-18T11:06:40Z"),
            (120_000_000, "2026-11-18T11:06:40.120Z"),
            (123_000_000, "2026-11-18T11:06:40.123Z"),
            (123_400_000, "2026-11-18T11:06:40.123400Z"),
            (123_456_000, "2026-11-18T11:06:40.123456Z"),
            (123_456_700, "2026-11-18T11:06:40.123456700Z"),
            (123_456_789, "2026-11-18T11:06:40.123456789Z"),
            (5_000, "2026-11-18T11:06:40.000005Z"),
        ];
        for (nanos, want) in cases {
            let json = serde_json::to_string(&at(nanos)).unwrap();
            assert_eq!(json, format!("\"{want}\""), "nanos={nanos}");
        }
    }

    #[test]
    fn deserialize_normalises_offsets_to_utc() {
        let a: UtcTime = serde_json::from_str("\"2026-11-19T10:13:20+02:00\"").unwrap();
        let b: UtcTime = serde_json::from_str("\"2026-11-19T08:13:20Z\"").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.to_string(), "2026-11-19T08:13:20Z");
    }

    #[test]
    fn round_trips() {
        let t = at(123_400_000);
        let back: UtcTime = serde_json::from_str(&serde_json::to_string(&t).unwrap()).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn millis_since() {
        assert_eq!(at(500_000_000).millis_since(at(0)), 500);
        assert_eq!(at(0).millis_since(at(500_000_000)), -500);
    }
}
