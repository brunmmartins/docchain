use std::fmt;

use crate::DomainError;

/// A UTC instant with one-second resolution, as seconds since the Unix epoch.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Wraps seconds since the Unix epoch.
    #[must_use]
    pub const fn from_unix_seconds(seconds: i64) -> Self {
        Self(seconds)
    }

    /// Returns seconds since the Unix epoch.
    #[must_use]
    pub const fn unix_seconds(self) -> i64 {
        self.0
    }

    /// Parses exactly `YYYY-MM-DDTHH:MM:SSZ`, the canonical form key bindings use.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidTimestamp`] for any other spelling, including offsets,
    /// fractions, lowercase separators, and out-of-range fields.
    pub fn parse_rfc3339(value: &str) -> Result<Self, DomainError> {
        let bytes = value.as_bytes();
        if bytes.len() != 20
            || bytes[4] != b'-'
            || bytes[7] != b'-'
            || bytes[10] != b'T'
            || bytes[13] != b':'
            || bytes[16] != b':'
            || bytes[19] != b'Z'
        {
            return Err(DomainError::InvalidTimestamp);
        }
        let field = |start: usize, end: usize| digits(&bytes[start..end]);
        let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
            field(0, 4),
            field(5, 7),
            field(8, 10),
            field(11, 13),
            field(14, 16),
            field(17, 19),
        ) else {
            return Err(DomainError::InvalidTimestamp);
        };
        if !is_calendar_date(year, month, day) || hour > 23 || minute > 59 || second > 59 {
            return Err(DomainError::InvalidTimestamp);
        }
        let days = days_from_civil(i64::from(year), i64::from(month), i64::from(day));
        Ok(Self(
            days * 86_400 + i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second),
        ))
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Timestamp({})", self.0)
    }
}

fn digits(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0_u32, |number, byte| {
        byte.is_ascii_digit()
            .then(|| number * 10 + u32::from(*byte - b'0'))
    })
}

/// Reports whether the fields name a real proleptic Gregorian date in years 0 through 9999.
pub(crate) fn is_calendar_date(year: u32, month: u32, day: u32) -> bool {
    if year > 9_999 || !(1..=12).contains(&month) {
        return false;
    }
    let leap_year =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        2 if leap_year => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=days).contains(&day)
}

/// Days from 1970-01-01 to the given proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Parses an RFC 3339 `full-date`, `YYYY-MM-DD`.
pub(crate) fn is_full_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    match (
        digits(&bytes[0..4]),
        digits(&bytes[5..7]),
        digits(&bytes[8..10]),
    ) {
        (Some(year), Some(month), Some(day)) => is_calendar_date(year, month, day),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_utc_seconds() {
        assert_eq!(
            Timestamp::parse_rfc3339("1970-01-01T00:00:00Z").map(Timestamp::unix_seconds),
            Ok(0)
        );
        assert_eq!(
            Timestamp::parse_rfc3339("2026-09-19T00:00:00Z").map(Timestamp::unix_seconds),
            Ok(1_789_776_000)
        );
        assert_eq!(
            Timestamp::parse_rfc3339("1969-12-31T23:59:59Z").map(Timestamp::unix_seconds),
            Ok(-1)
        );
    }

    #[test]
    fn rejects_non_canonical_timestamps() {
        for value in [
            "2026-09-19T00:00:00+00:00",
            "2026-09-19t00:00:00Z",
            "2026-09-19T00:00:00.0Z",
            "2026-02-30T00:00:00Z",
            "2026-09-19T24:00:00Z",
        ] {
            assert_eq!(
                Timestamp::parse_rfc3339(value),
                Err(DomainError::InvalidTimestamp),
                "{value}"
            );
        }
    }

    #[test]
    fn full_dates_follow_the_gregorian_calendar_without_an_epoch_floor() {
        assert!(is_full_date("2024-02-29"));
        assert!(is_full_date("1969-07-20"));
        assert!(is_full_date("0001-01-01"));
        assert!(!is_full_date("2026-02-29"));
        assert!(!is_full_date("1900-02-29"));
        assert!(!is_full_date("2026-9-19"));
    }
}
