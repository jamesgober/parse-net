//! The proleptic Gregorian calendar and HTTP-date (RFC 9110 section 5.6.7).
//!
//! # Examples
//!
//! ```
//! use parse_net as pn;
//!
//! let d = pn::HttpDate::parse_imf_fixdate(b"Sun, 06 Nov 1994 08:49:37 GMT")?;
//! assert_eq!(d.unix(), 784_111_777);
//! assert_eq!(&d.format(), b"Sun, 06 Nov 1994 08:49:37 GMT");
//!
//! let now = 1_792_540_800; // 2026-10-21
//! assert_eq!(pn::http_date_at(b"Sun Nov  6 08:49:37 1994", now)?, d);
//! assert_eq!(pn::http_date_at(b"Wednesday, 01-Jan-76 00:00:00 GMT", now)?.civil().year, 2076);
//! assert_eq!(pn::http_date_at(b"Saturday, 01-Jan-77 00:00:00 GMT", now)?.civil().year, 1977);
//! # Ok::<(), pn::ParseError>(())
//! ```

use crate::{
    error::{ErrorKind, Result, WriteError, err},
    limits::Limits,
    text::trim_ows,
    write::Sink,
};

mod mail_date;

pub use mail_date::MailDate;

/// Whether `year` is a leap year in the proleptic Gregorian calendar.
///
/// # Examples
///
/// ```
/// use parse_net::date::is_leap_year;
///
/// assert!(is_leap_year(2000) && is_leap_year(2024) && !is_leap_year(1900) && !is_leap_year(2023));
/// ```
#[must_use]
pub const fn is_leap_year(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// The number of days in `month` (1 to 12) of `year`; 0 for any other month.
///
/// # Examples
///
/// ```
/// use parse_net::date::days_in_month;
///
/// assert_eq!(days_in_month(2024, 2), 29);
/// assert_eq!(days_in_month(2023, 2), 28);
/// assert_eq!(days_in_month(2023, 13), 0);
/// ```
#[must_use]
pub const fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 for a civil date, after Howard Hinnant's
/// `days_from_civil`.
///
/// The input is not validated: pair it with [`days_in_month`]. Any `i32`
/// year and `u8` month and day give a result without overflow.
///
/// # Examples
///
/// ```
/// use parse_net::date::days_from_civil;
///
/// assert_eq!(days_from_civil(1970, 1, 1), 0);
/// assert_eq!(days_from_civil(2000, 3, 1), 11_017);
/// assert_eq!(days_from_civil(1, 1, 1), -719_162);
/// ```
#[must_use]
pub const fn days_from_civil(year: i32, month: u8, day: u8) -> i64 {
    let m = month as i64;
    let y = if m <= 2 { year as i64 - 1 } else { year as i64 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The day count beyond which `civil_from_days` clamps, keeping every year
/// inside `i32`.
const DAYS_LIMIT: i64 = 784_352_296_671;

/// The civil date `(year, month, day)` for a day count since 1970-01-01,
/// after Howard Hinnant's `civil_from_days`.
///
/// Accepts any `i64`; day counts beyond the years an `i32` can hold are
/// clamped to them.
///
/// # Examples
///
/// ```
/// use parse_net::date::civil_from_days;
///
/// assert_eq!(civil_from_days(0), (1970, 1, 1));
/// assert_eq!(civil_from_days(-1), (1969, 12, 31));
/// assert_eq!(civil_from_days(19_782), (2024, 2, 29));
/// ```
#[must_use]
pub const fn civil_from_days(days: i64) -> (i32, u8, u8) {
    let days = if days > DAYS_LIMIT {
        DAYS_LIMIT
    } else if days < -DAYS_LIMIT {
        -DAYS_LIMIT
    } else {
        days
    };
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let y = if y > i32::MAX as i64 {
        i32::MAX
    } else if y < i32::MIN as i64 {
        i32::MIN
    } else {
        y as i32
    };
    // `m` is 1 to 12 and `d` is 1 to 31 by construction.
    (y, m as u8, d as u8)
}

/// The ISO 8601 weekday (1 = Monday ... 7 = Sunday) of a day count since
/// 1970-01-01.
///
/// # Examples
///
/// ```
/// assert_eq!(parse_net::date::weekday_from_days(0), 4); // a Thursday
/// ```
#[must_use]
pub const fn weekday_from_days(days: i64) -> u8 {
    // 1970-01-01 was a Thursday (4); the result is 1 to 7.
    ((days.rem_euclid(7) + 3) % 7 + 1) as u8
}

/// A broken-down UTC time.
///
/// # Examples
///
/// ```
/// let c = parse_net::HttpDate::from_unix(784_111_777)?.civil();
/// assert_eq!((c.year, c.month, c.day, c.hour, c.minute, c.second, c.weekday), (1994, 11, 6, 8, 49, 37, 7));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Civil {
    /// The year, 1 to 9999.
    pub year: u16,
    /// The month, 1 to 12.
    pub month: u8,
    /// The day of the month, 1 to 31.
    pub day: u8,
    /// The hour, 0 to 23.
    pub hour: u8,
    /// The minute, 0 to 59.
    pub minute: u8,
    /// The second, 0 to 59.
    pub second: u8,
    /// The ISO 8601 weekday: 1 = Monday ... 7 = Sunday.
    pub weekday: u8,
}

/// The HTTP-date format a value was written in.
///
/// # Examples
///
/// ```
/// use parse_net::{DateFormat, HttpDate};
///
/// let (_, fmt) = HttpDate::parse_detailed(b"Sun Nov  6 08:49:37 1994", 0)?;
/// assert_eq!(fmt, DateFormat::Asctime);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DateFormat {
    /// `Sun, 06 Nov 1994 08:49:37 GMT`, the only format senders may generate.
    ImfFixdate,
    /// `Sunday, 06-Nov-94 08:49:37 GMT` (obsolete).
    Rfc850,
    /// `Sun Nov  6 08:49:37 1994` (obsolete).
    Asctime,
}

const SECS_PER_DAY: i64 = 86_400;
const MIN_SECS: i64 = days_from_civil(1, 1, 1) * SECS_PER_DAY;
const MAX_SECS: i64 = days_from_civil(9999, 12, 31) * SECS_PER_DAY + SECS_PER_DAY - 1;

const DAY_NAMES: [&[u8; 3]; 7] = [b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat", b"Sun"];
const LONG_DAY_NAMES: [&[u8]; 7] = [
    b"Monday",
    b"Tuesday",
    b"Wednesday",
    b"Thursday",
    b"Friday",
    b"Saturday",
    b"Sunday",
];
const MONTH_NAMES: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

/// A point in time with one-second resolution, from year 1 to year 9999,
/// UTC; the value of HTTP-date fields (`Date`, `Last-Modified`, `Expires`).
///
/// # Examples
///
/// ```
/// use parse_net::HttpDate;
///
/// let d = HttpDate::from_unix(0)?;
/// assert_eq!(&d.format(), b"Thu, 01 Jan 1970 00:00:00 GMT");
/// assert!(HttpDate::from_unix(HttpDate::MAX.unix() + 1).is_err());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HttpDate {
    secs: i64,
}

impl HttpDate {
    /// 0001-01-01T00:00:00Z.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::HttpDate;
    ///
    /// assert_eq!(&HttpDate::MIN.format(), b"Mon, 01 Jan 0001 00:00:00 GMT");
    /// assert!(HttpDate::from_unix(HttpDate::MIN.unix() - 1).is_err());
    /// ```
    pub const MIN: Self = Self { secs: MIN_SECS };
    /// 9999-12-31T23:59:59Z.
    ///
    /// # Examples
    ///
    /// ```
    /// let c = parse_net::HttpDate::MAX.civil();
    /// assert_eq!((c.year, c.month, c.day, c.hour, c.minute, c.second), (9999, 12, 31, 23, 59, 59));
    /// ```
    pub const MAX: Self = Self { secs: MAX_SECS };

    /// The date `secs` seconds after the Unix epoch (negative before 1970).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::OutOfRange`] outside years 1 to 9999.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::HttpDate;
    ///
    /// assert_eq!(HttpDate::from_unix(1_792_540_800)?.civil().weekday, 3); // 2026-10-21, a Wednesday
    /// assert!(HttpDate::from_unix(i64::MAX).is_err());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub const fn from_unix(secs: i64) -> Result<Self> {
        if secs < MIN_SECS || secs > MAX_SECS {
            return err(ErrorKind::OutOfRange, 0);
        }
        Ok(Self { secs })
    }

    /// Seconds since the Unix epoch.
    ///
    /// # Examples
    ///
    /// ```
    /// let d = parse_net::HttpDate::parse_imf_fixdate(b"Thu, 01 Jan 1970 00:01:00 GMT")?;
    /// assert_eq!(d.unix(), 60);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn unix(self) -> i64 {
        self.secs
    }

    /// The broken-down UTC time.
    ///
    /// # Examples
    ///
    /// ```
    /// let c = parse_net::HttpDate::from_unix(946_684_800)?.civil();
    /// assert_eq!((c.year, c.month, c.day, c.weekday), (2000, 1, 1, 6)); // a Saturday
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn civil(self) -> Civil {
        let days = self.secs.div_euclid(SECS_PER_DAY);
        let rem = self.secs.rem_euclid(SECS_PER_DAY);
        let (year, month, day) = civil_from_days(days);
        Civil {
            // Years are 1 to 9999 by the type's invariant.
            year: u16::try_from(year).unwrap_or(0),
            month,
            day,
            hour: (rem / 3600) as u8,
            minute: (rem % 3600 / 60) as u8,
            second: (rem % 60) as u8,
            weekday: weekday_from_days(days),
        }
    }

    /// The IMF-fixdate text, `Sun, 06 Nov 1994 08:49:37 GMT`.
    ///
    /// # Examples
    ///
    /// ```
    /// let d = parse_net::HttpDate::from_unix(1_792_540_800)?;
    /// assert_eq!(&d.format(), b"Wed, 21 Oct 2026 00:00:00 GMT");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn format(self) -> [u8; 29] {
        let c = self.civil();
        let mut out = *b"Thu, 01 Jan 1970 00:00:00 GMT";
        let name = DAY_NAMES
            .get(usize::from(c.weekday).saturating_sub(1))
            .copied()
            .unwrap_or(b"Mon");
        let month = MONTH_NAMES
            .get(usize::from(c.month).saturating_sub(1))
            .copied()
            .unwrap_or(b"Jan");
        put(&mut out, 0, name);
        two(&mut out, 5, c.day);
        put(&mut out, 8, month);
        two(&mut out, 12, (c.year / 100) as u8);
        two(&mut out, 14, (c.year % 100) as u8);
        two(&mut out, 17, c.hour);
        two(&mut out, 20, c.minute);
        two(&mut out, 23, c.second);
        out
    }

    /// Writes [`format`](Self::format) into `out`.
    ///
    /// # Errors
    ///
    /// [`WriteError::Full`].
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{HttpDate, SliceSink};
    ///
    /// let mut buf = [0u8; 32];
    /// let mut out = SliceSink::new(&mut buf);
    /// HttpDate::MIN.write_to(&mut out)?;
    /// assert_eq!(out.written(), b"Mon, 01 Jan 0001 00:00:00 GMT");
    /// assert!(HttpDate::MAX.write_to(&mut SliceSink::new(&mut [0u8; 8])).is_err());
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn write_to(self, out: &mut impl Sink) -> core::result::Result<(), WriteError> {
        out.put(&self.format())?;
        Ok(())
    }

    /// Parses exactly an IMF-fixdate (29 bytes after OWS), the only format
    /// senders may generate. Needs no clock.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidDate`], [`ErrorKind::WeekdayMismatch`],
    /// [`ErrorKind::OutOfRange`] (year 0000), [`ErrorKind::TrailingData`].
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::HttpDate;
    ///
    /// assert_eq!(HttpDate::parse_imf_fixdate(b" Wed, 21 Oct 2026 07:28:00 GMT ")?.civil().hour, 7);
    /// assert!(HttpDate::parse_imf_fixdate(b"Thu, 21 Oct 2026 07:28:00 GMT").is_err()); // wrong weekday
    /// assert!(HttpDate::parse_imf_fixdate(b"Wednesday, 21-Oct-26 07:28:00 GMT").is_err());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn parse_imf_fixdate(value: &[u8]) -> Result<Self> {
        let (lead, v) = trimmed(value);
        imf_fixdate(v, &Limits::DEFAULT).map_err(|e| e.shifted(lead))
    }

    /// Parses an HTTP-date in any of its three formats.
    ///
    /// The RFC 850 two-digit year is resolved against `now` (Unix seconds):
    /// a date more than 50 years after `now` is taken as the most recent past
    /// year with the same last two digits, and a date 50 years or more before
    /// `now` moves forward a century, so the year lands in the hundred years
    /// around `now`. Names are case-sensitive, only `GMT` is accepted, and
    /// the weekday must agree with the date.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidDate`], [`ErrorKind::WeekdayMismatch`],
    /// [`ErrorKind::OutOfRange`], [`ErrorKind::TrailingData`].
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::HttpDate;
    ///
    /// let now = 1_792_540_800; // 2026-10-21
    /// let d = HttpDate::parse_at(b"Sunday, 06-Nov-94 08:49:37 GMT", now)?;
    /// assert_eq!(d.civil().year, 1994);
    /// assert_eq!(d, HttpDate::parse_at(b"Sun Nov  6 08:49:37 1994", now)?);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn parse_at(value: &[u8], now: i64) -> Result<Self> {
        Self::parse_detailed_with(value, now, &Limits::DEFAULT).map(|(d, _)| d)
    }

    /// As [`parse_at`](Self::parse_at), with [`Limits::allow_leap_second`]
    /// taken from `limits`.
    ///
    /// # Errors
    ///
    /// As [`parse_at`](Self::parse_at).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{HttpDate, Limits};
    ///
    /// let leap = b"Sat, 31 Dec 2016 23:59:60 GMT";
    /// assert!(HttpDate::parse_at(leap, 0).is_err());
    /// assert!(HttpDate::parse_at_with(leap, 0, &Limits::DEFAULT.allow_leap_second(true)).is_ok());
    /// ```
    pub fn parse_at_with(value: &[u8], now: i64, limits: &Limits) -> Result<Self> {
        Self::parse_detailed_with(value, now, limits).map(|(d, _)| d)
    }

    /// As [`parse_at`](Self::parse_at), also reporting the format seen.
    ///
    /// # Errors
    ///
    /// As [`parse_at`](Self::parse_at).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{DateFormat, HttpDate};
    ///
    /// let (_, fmt) = HttpDate::parse_detailed(b"Sunday, 06-Nov-94 08:49:37 GMT", 1_792_540_800)?;
    /// assert_eq!(fmt, DateFormat::Rfc850);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn parse_detailed(value: &[u8], now: i64) -> Result<(Self, DateFormat)> {
        Self::parse_detailed_with(value, now, &Limits::DEFAULT)
    }

    fn parse_detailed_with(value: &[u8], now: i64, limits: &Limits) -> Result<(Self, DateFormat)> {
        let (lead, v) = trimmed(value);
        let result = match (v.get(3), v.iter().position(|&b| b == b',')) {
            (Some(b','), _) => imf_fixdate(v, limits).map(|d| (d, DateFormat::ImfFixdate)),
            (Some(b' '), _) => asctime(v, limits).map(|d| (d, DateFormat::Asctime)),
            (_, Some(_)) => rfc850(v, now, limits).map(|d| (d, DateFormat::Rfc850)),
            _ => err(ErrorKind::InvalidDate, 0),
        };
        result.map_err(|e| e.shifted(lead))
    }

    /// The current time from the system clock, clamped to the supported
    /// range.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::HttpDate;
    ///
    /// assert!(HttpDate::now() > HttpDate::from_unix(1_700_000_000)?); // later than 2023-11-14
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    #[must_use]
    pub fn now() -> Self {
        match Self::from_system_time(std::time::SystemTime::now()) {
            Ok(d) => d,
            Err(_) => Self::MAX,
        }
    }

    /// The date of a `SystemTime`, truncated to whole seconds toward the
    /// past.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::OutOfRange`] outside years 1 to 9999.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::{Duration, UNIX_EPOCH};
    ///
    /// let t = UNIX_EPOCH + Duration::from_millis(1_500);
    /// assert_eq!(parse_net::HttpDate::from_system_time(t)?.unix(), 1);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn from_system_time(t: std::time::SystemTime) -> Result<Self> {
        let secs = match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            Err(before) => {
                let d = before.duration();
                let whole = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
                let extra = i64::from(d.subsec_nanos() > 0);
                0i64.saturating_sub(whole).saturating_sub(extra)
            }
        };
        Self::from_unix(secs)
    }

    /// The date as a `SystemTime`, or `None` when the platform's clock type
    /// cannot represent it (Windows cannot go before the year 1601).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::{Duration, UNIX_EPOCH};
    ///
    /// let d = parse_net::HttpDate::from_unix(86_400)?;
    /// assert_eq!(d.to_system_time(), Some(UNIX_EPOCH + Duration::from_secs(86_400)));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    #[must_use]
    pub fn to_system_time(self) -> Option<std::time::SystemTime> {
        let d = std::time::Duration::from_secs(self.secs.unsigned_abs());
        if self.secs >= 0 {
            std::time::UNIX_EPOCH.checked_add(d)
        } else {
            std::time::UNIX_EPOCH.checked_sub(d)
        }
    }
}

/// Parses an HTTP-date in any format, resolving RFC 850 years against `now`.
///
/// The Tier 1 form for `no_std` callers, who pass the clock in.
///
/// # Errors
///
/// As [`HttpDate::parse_at`].
///
/// # Examples
///
/// ```
/// let d = parse_net::http_date_at(b"Sun, 06 Nov 1994 08:49:37 GMT", 1_792_540_800)?;
/// assert_eq!(d.unix(), 784_111_777);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn http_date_at(value: &[u8], now: i64) -> Result<HttpDate> {
    HttpDate::parse_at(value, now)
}

/// Parses an HTTP-date in any format, resolving RFC 850 years against the
/// system clock.
///
/// # Errors
///
/// As [`HttpDate::parse_at`].
///
/// # Examples
///
/// ```
/// let d = parse_net::http_date(b"Sun, 06 Nov 1994 08:49:37 GMT")?;
/// assert_eq!(d.unix(), 784_111_777);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub fn http_date(value: &[u8]) -> Result<HttpDate> {
    HttpDate::parse_at(value, HttpDate::now().unix())
}

fn trimmed(value: &[u8]) -> (usize, &[u8]) {
    let lead = crate::text::skip_ows(value);
    (lead, trim_ows(value))
}

fn put(out: &mut [u8], at: usize, bytes: &[u8]) {
    if let Some(dst) = out.get_mut(at..at + bytes.len()) {
        dst.copy_from_slice(bytes);
    }
}

fn two(out: &mut [u8], at: usize, v: u8) {
    put(out, at, &[b'0' + v / 10 % 10, b'0' + v % 10]);
}

/// The value of `n` ASCII digits at `v[at..]`.
fn digits(v: &[u8], at: usize, n: usize) -> Result<u32> {
    let Some(ds) = v.get(at..at + n) else {
        return err(ErrorKind::InvalidDate, v.len().min(at));
    };
    let mut x = 0u32;
    for (i, &d) in ds.iter().enumerate() {
        if !d.is_ascii_digit() {
            return err(ErrorKind::InvalidDate, at + i);
        }
        x = x * 10 + u32::from(d - b'0');
    }
    Ok(x)
}

fn expect(v: &[u8], at: usize, lit: &[u8]) -> Result<()> {
    match v.get(at..at + lit.len()) {
        Some(s) if s == lit => Ok(()),
        _ => err(ErrorKind::InvalidDate, at),
    }
}

/// The index (0 to 11) of the case-sensitive month name at `v[at..at + 3]`.
fn month(v: &[u8], at: usize) -> Result<u8> {
    let name = v.get(at..at + 3).unwrap_or(&[]);
    match MONTH_NAMES.iter().position(|m| m.as_slice() == name) {
        // There are 12 months.
        Some(i) => Ok(i as u8 + 1),
        None => err(ErrorKind::InvalidDate, at),
    }
}

/// The ISO weekday of a short day name at `v[0..3]`.
fn short_day(v: &[u8]) -> Result<u8> {
    let name = v.get(..3).unwrap_or(&[]);
    match DAY_NAMES.iter().position(|d| d.as_slice() == name) {
        Some(i) => Ok(i as u8 + 1),
        None => err(ErrorKind::InvalidDate, 0),
    }
}

/// `hh:mm:ss` at `v[at..at + 8]`.
fn time(v: &[u8], at: usize, limits: &Limits) -> Result<i64> {
    let h = digits(v, at, 2)?;
    expect(v, at + 2, b":")?;
    let m = digits(v, at + 3, 2)?;
    expect(v, at + 5, b":")?;
    let mut s = digits(v, at + 6, 2)?;
    if h > 23 {
        return err(ErrorKind::InvalidDate, at);
    }
    if m > 59 {
        return err(ErrorKind::InvalidDate, at + 3);
    }
    if s == 60 && limits.allow_leap_second {
        s = 59;
    }
    if s > 59 {
        return err(ErrorKind::InvalidDate, at + 6);
    }
    Ok(i64::from(h * 3600 + m * 60 + s))
}

/// Builds the date and checks it exists and matches `weekday`.
fn assemble(
    year: u32,
    month: u8,
    day: u32,
    secs: i64,
    weekday: u8,
    year_at: usize,
    day_at: usize,
) -> Result<HttpDate> {
    if year == 0 || year > 9999 {
        return err(ErrorKind::OutOfRange, year_at);
    }
    // `year` is 1 to 9999, which fits an i32.
    let y = year as i32;
    if day == 0 || day > u32::from(days_in_month(y, month)) {
        return err(ErrorKind::InvalidDate, day_at);
    }
    let days = days_from_civil(y, month, day as u8);
    if weekday_from_days(days) != weekday {
        return err(ErrorKind::WeekdayMismatch, 0);
    }
    HttpDate::from_unix(days * SECS_PER_DAY + secs)
}

fn trailing(v: &[u8], len: usize) -> Result<()> {
    if v.len() > len {
        return err(ErrorKind::TrailingData, len);
    }
    Ok(())
}

/// `Sun, 06 Nov 1994 08:49:37 GMT`.
fn imf_fixdate(v: &[u8], limits: &Limits) -> Result<HttpDate> {
    let weekday = short_day(v)?;
    expect(v, 3, b", ")?;
    let day = digits(v, 5, 2)?;
    expect(v, 7, b" ")?;
    let m = month(v, 8)?;
    expect(v, 11, b" ")?;
    let year = digits(v, 12, 4)?;
    expect(v, 16, b" ")?;
    let secs = time(v, 17, limits)?;
    expect(v, 25, b" GMT")?;
    trailing(v, 29)?;
    assemble(year, m, day, secs, weekday, 12, 5)
}

/// `Sun Nov  6 08:49:37 1994`.
fn asctime(v: &[u8], limits: &Limits) -> Result<HttpDate> {
    let weekday = short_day(v)?;
    expect(v, 3, b" ")?;
    let m = month(v, 4)?;
    expect(v, 7, b" ")?;
    let day = if v.get(8) == Some(&b' ') {
        digits(v, 9, 1)?
    } else {
        digits(v, 8, 2)?
    };
    expect(v, 10, b" ")?;
    let secs = time(v, 11, limits)?;
    expect(v, 19, b" ")?;
    let year = digits(v, 20, 4)?;
    trailing(v, 24)?;
    assemble(year, m, day, secs, weekday, 20, 8)
}

/// `Sunday, 06-Nov-94 08:49:37 GMT`.
fn rfc850(v: &[u8], now: i64, limits: &Limits) -> Result<HttpDate> {
    let comma = v.iter().position(|&b| b == b',').unwrap_or(0);
    let name = v.get(..comma).unwrap_or(&[]);
    let Some(day_index) = LONG_DAY_NAMES.iter().position(|d| *d == name) else {
        return err(ErrorKind::InvalidDate, 0);
    };
    let weekday = day_index as u8 + 1;
    let at = comma + 2;
    expect(v, comma, b", ")?;
    let day = digits(v, at, 2)?;
    expect(v, at + 2, b"-")?;
    let m = month(v, at + 3)?;
    expect(v, at + 6, b"-")?;
    let yy = digits(v, at + 7, 2)?;
    expect(v, at + 9, b" ")?;
    let secs = time(v, at + 10, limits)?;
    expect(v, at + 18, b" GMT")?;
    trailing(v, at + 22)?;
    let year = resolve_two_digit_year(yy, m, day, secs, now);
    assemble(year, m, day, secs, weekday, at + 7, at)
}

/// RFC 9110 section 5.6.7: a two-digit year more than 50 years in the future
/// is the most recent past year with the same last two digits. The year is
/// first taken in `now`'s century, then moved so it lies after `now` minus
/// 50 years and no later than `now` plus 50 years (D-037).
fn resolve_two_digit_year(yy: u32, month: u8, day: u32, secs: i64, now: i64) -> u32 {
    let now = HttpDate::from_unix(now.clamp(MIN_SECS, MAX_SECS))
        .unwrap_or(HttpDate::MIN)
        .civil();
    let now_key = (
        u32::from(now.month),
        u32::from(now.day),
        i64::from(now.hour) * 3600 + i64::from(now.minute) * 60 + i64::from(now.second),
    );
    let key = (u32::from(month), day, secs);
    let now_year = u32::from(now.year);
    let mut year = now_year - now_year % 100 + yy;
    // More than 50 years ahead of now: a century back.
    if (year, key) > (now_year + 50, now_key) {
        year = year.saturating_sub(100);
    } else if (year, key) <= (now_year.saturating_sub(50), now_key) {
        year += 100;
    }
    year
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW_2026: i64 = 1_792_540_800; // 2026-10-21T00:00:00Z

    fn at(v: &[u8]) -> Result<HttpDate> {
        HttpDate::parse_at(v, NOW_2026)
    }

    #[test]
    fn test_calendar_round_trips_every_day_of_four_centuries() {
        let start = days_from_civil(1600, 1, 1);
        for days in start..start + 146_097 {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
            assert!(d >= 1 && d <= days_in_month(y, m));
        }
        assert_eq!(civil_from_days(i64::MAX).0, civil_from_days(DAYS_LIMIT).0);
        assert_eq!(civil_from_days(i64::MIN).0, civil_from_days(-DAYS_LIMIT).0);
    }

    #[test]
    fn test_weekday_known_dates() {
        assert_eq!(weekday_from_days(days_from_civil(1994, 11, 6)), 7);
        assert_eq!(weekday_from_days(days_from_civil(2000, 1, 1)), 6);
        assert_eq!(weekday_from_days(days_from_civil(1, 1, 1)), 1);
        assert_eq!(weekday_from_days(-1), 3);
    }

    #[test]
    fn test_http_date_rfc_examples_all_formats() {
        let d = HttpDate::from_unix(784_111_777).unwrap();
        assert_eq!(at(b"Sun, 06 Nov 1994 08:49:37 GMT").unwrap(), d);
        assert_eq!(at(b"Sunday, 06-Nov-94 08:49:37 GMT").unwrap(), d);
        assert_eq!(at(b"Sun Nov  6 08:49:37 1994").unwrap(), d);
        assert_eq!(at(b"  Sun, 06 Nov 1994 08:49:37 GMT \t").unwrap(), d);
    }

    #[test]
    fn test_http_date_rejections_table() {
        use ErrorKind::*;
        let cases: &[(&[u8], ErrorKind)] = &[
            (b"Mon, 06 Nov 1994 08:49:37 GMT", WeekdayMismatch),
            (b"sun, 06 Nov 1994 08:49:37 GMT", InvalidDate),
            (b"Sun, 06 nov 1994 08:49:37 GMT", InvalidDate),
            (b"Sun, 06 Nov 1994 08:49:37 UTC", InvalidDate),
            (b"Sun, 06 Nov 1994 08:49:37 +0000", InvalidDate),
            (b"Fri, 29 Feb 2023 00:00:00 GMT", InvalidDate),
            (b"Thu, 31 Apr 2025 00:00:00 GMT", InvalidDate),
            (b"Sun, 06 Nov 1994 24:00:00 GMT", InvalidDate),
            (b"Sun, 06 Nov 1994 23:60:00 GMT", InvalidDate),
            (b"Sun, 06 Nov 1994 23:59:60 GMT", InvalidDate),
            (b"Sat, 01 Jan 0000 00:00:00 GMT", OutOfRange),
            (b"Sun, 06 Nov 1994 08:49:37 GMTx", TrailingData),
            (b"Sun, 06 Nov 1994 08:49:37 GM", InvalidDate),
            (b"Sun, 6 Nov 1994 08:49:37 GMT", InvalidDate),
            (b"Sun Nov 6 08:49:37 1994", InvalidDate),
            (b"Sunday, 06-Nov-1994 08:49:37 GMT", InvalidDate),
            (b"Sun, 00 Nov 1994 08:49:37 GMT", InvalidDate),
            (b"", InvalidDate),
            (b"garbage", InvalidDate),
            (b"Sun, 06 Nov 1994 08:49:37 GMT, x", TrailingData),
        ];
        for (v, kind) in cases {
            assert_eq!(
                at(v).unwrap_err().kind(),
                *kind,
                "{}",
                std::string::String::from_utf8_lossy(v)
            );
        }
    }

    #[test]
    fn test_http_date_leap_year_and_leap_second() {
        assert!(at(b"Thu, 29 Feb 2024 00:00:00 GMT").is_ok());
        let v = b"Sun, 06 Nov 1994 08:49:60 GMT";
        assert!(at(v).is_err());
        let l = Limits::DEFAULT.allow_leap_second(true);
        let d = HttpDate::parse_at_with(v, NOW_2026, &l).unwrap();
        assert_eq!(d.civil().second, 59);
    }

    #[test]
    fn test_http_date_range_ends() {
        assert_eq!(&HttpDate::MAX.format(), b"Fri, 31 Dec 9999 23:59:59 GMT");
        assert_eq!(&HttpDate::MIN.format(), b"Mon, 01 Jan 0001 00:00:00 GMT");
        assert_eq!(at(b"Fri, 31 Dec 9999 23:59:59 GMT").unwrap(), HttpDate::MAX);
        assert_eq!(at(b"Mon, 01 Jan 0001 00:00:00 GMT").unwrap(), HttpDate::MIN);
        assert!(HttpDate::from_unix(MIN_SECS - 1).is_err());
        assert!(HttpDate::from_unix(MAX_SECS + 1).is_err());
        assert_eq!(MIN_SECS, -62_135_596_800);
        assert_eq!(MAX_SECS, 253_402_300_799);
    }

    #[test]
    fn test_rfc850_fifty_year_rule() {
        let y = |v: &[u8]| at(v).unwrap().civil().year;
        assert_eq!(y(b"Wednesday, 01-Jan-76 00:00:00 GMT"), 2076);
        assert_eq!(y(b"Saturday, 01-Jan-77 00:00:00 GMT"), 1977);
        assert_eq!(y(b"Wednesday, 21-Oct-76 00:00:00 GMT"), 2076);
        assert_eq!(y(b"Wednesday, 21-Oct-26 00:00:00 GMT"), 2026);
        assert_eq!(y(b"Tuesday, 01-Jan-80 00:00:00 GMT"), 1980);
        // At the turn of a century the window still centres on now.
        let now_2099 = HttpDate::parse_imf_fixdate(b"Thu, 01 Jan 2099 00:00:00 GMT")
            .unwrap()
            .unix();
        let d = HttpDate::parse_at(b"Friday, 01-Jan-00 00:00:00 GMT", now_2099).unwrap();
        assert_eq!(d.civil().year, 2100);
        let d = HttpDate::parse_at(b"Saturday, 01-Jan-50 00:00:00 GMT", now_2099).unwrap();
        assert_eq!(d.civil().year, 2050);
    }

    #[test]
    fn test_asctime_day_forms() {
        assert!(at(b"Wed Nov 16 08:49:37 1994").is_ok());
        assert_eq!(
            at(b"Sun Nov  6 08:49:37 1994 ").unwrap().unix(),
            784_111_777
        );
        assert_eq!(
            at(b"Sun Nov  6 08:49:37 1994x").unwrap_err().kind(),
            ErrorKind::TrailingData
        );
    }

    #[test]
    fn test_format_parse_round_trip_sampled() {
        let mut secs = MIN_SECS;
        while secs < MAX_SECS {
            let d = HttpDate::from_unix(secs).unwrap();
            assert_eq!(HttpDate::parse_imf_fixdate(&d.format()).unwrap(), d);
            secs += 7_919_993; // a prime step covers every weekday and time of day
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_system_time_conversions() {
        use std::time::{Duration, UNIX_EPOCH};
        let t = UNIX_EPOCH + Duration::from_millis(1500);
        assert_eq!(HttpDate::from_system_time(t).unwrap().unix(), 1);
        let before = UNIX_EPOCH - Duration::from_millis(1500);
        assert_eq!(HttpDate::from_system_time(before).unwrap().unix(), -2);
        let d = HttpDate::from_unix(784_111_777).unwrap();
        assert_eq!(
            HttpDate::from_system_time(d.to_system_time().unwrap()).unwrap(),
            d
        );
        assert!(HttpDate::now() > d);
        assert_eq!(http_date(b"Sun, 06 Nov 1994 08:49:37 GMT").unwrap(), d);
    }
}
