//! RFC 5322 section 3.3 `date-time`, with the obsolete forms of section 4.3
//! on request.

use super::{
    DAY_NAMES, MAX_SECS, MIN_SECS, MONTH_NAMES, SECS_PER_DAY, civil_from_days, days_from_civil,
    days_in_month, weekday_from_days,
};
use crate::{
    error::{ErrorKind, ParseError, Result, WriteError, err},
    limits::Limits,
    scan::control_kind,
    text::comment_end,
    write::{Sink, reserve},
};

/// The largest zone offset, `+9959`, in minutes.
const MAX_OFFSET: i16 = 99 * 60 + 59;

/// A point in time with a zone offset, from an email `Date` or `Received`
/// field (RFC 5322 section 3.3).
///
/// # Examples
///
/// ```
/// use parse_net::MailDate;
///
/// let d = MailDate::parse(b"Wed, 21 Oct 2026 17:38:00 +0200", false)?;
/// assert_eq!(d.offset_minutes(), 120);
/// let mut buf = [0u8; 64];
/// let mut out = parse_net::SliceSink::new(&mut buf);
/// d.write_to(&mut out).expect("room");
/// assert_eq!(out.written(), b"Wed, 21 Oct 2026 17:38:00 +0200");
/// assert!(MailDate::parse(b"21 Oct 26 17:38 EDT", false).is_err());
/// assert_eq!(MailDate::parse(b"21 Oct 26 17:38 EDT", true)?.offset_minutes(), -240);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MailDate {
    utc: i64,
    offset: i16,
    offset_unknown: bool,
    leap_second: bool,
}

impl MailDate {
    /// The time `utc_secs` (seconds since the Unix epoch) shown in the zone
    /// `offset_minutes` east of UTC.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::OutOfRange`] for an offset beyond plus or minus 99:59 or
    /// a local time outside years 1 to 9999.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::MailDate;
    ///
    /// let d = MailDate::new(0, -300)?;
    /// assert_eq!(&d.format().0[..d.format().1], b"Wed, 31 Dec 1969 19:00:00 -0500");
    /// assert!(MailDate::new(0, 6000).is_err());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn new(utc_secs: i64, offset_minutes: i16) -> Result<Self> {
        if offset_minutes.unsigned_abs() > MAX_OFFSET.unsigned_abs() {
            return err(ErrorKind::OutOfRange, 0);
        }
        let local = utc_secs.saturating_add(i64::from(offset_minutes) * 60);
        if !(MIN_SECS..=MAX_SECS).contains(&local) {
            return err(ErrorKind::OutOfRange, 0);
        }
        Ok(Self {
            utc: utc_secs,
            offset: offset_minutes,
            offset_unknown: false,
            leap_second: false,
        })
    }

    /// Seconds since the Unix epoch, UTC.
    #[must_use]
    pub const fn utc(self) -> i64 {
        self.utc
    }

    /// The zone offset in minutes east of UTC (`0` when unknown).
    #[must_use]
    pub const fn offset_minutes(self) -> i16 {
        self.offset
    }

    /// Whether the zone was `-0000`: the time is UTC and the local zone is
    /// unknown (RFC 5322 section 3.3), or an obsolete military zone, which
    /// the RFC says to read the same way.
    #[must_use]
    pub const fn offset_unknown(self) -> bool {
        self.offset_unknown
    }

    /// Whether the seconds were `60` (read as `59`).
    #[must_use]
    pub const fn leap_second(self) -> bool {
        self.leap_second
    }

    /// The value as `Wed, 21 Oct 2026 17:38:00 +0200`: weekday, two-digit
    /// day, four-digit year, seconds, and a numeric zone (`-0000` when the
    /// offset is unknown). Returns the bytes and their length (always 31).
    #[must_use]
    pub fn format(self) -> ([u8; 31], usize) {
        let local = self.utc + i64::from(self.offset) * 60;
        let days = local.div_euclid(SECS_PER_DAY);
        let secs = local.rem_euclid(SECS_PER_DAY);
        let (year, month, day) = civil_from_days(days);
        let mut out = [b' '; 31];
        let wd = usize::from(weekday_from_days(days)).saturating_sub(1);
        put(
            &mut out,
            0,
            DAY_NAMES
                .get(wd)
                .map_or(b"???".as_slice(), |d| d.as_slice()),
        );
        put(&mut out, 3, b",");
        two(&mut out, 5, day);
        let mon = MONTH_NAMES
            .get(usize::from(month).saturating_sub(1))
            .map_or(b"???".as_slice(), |m| m.as_slice());
        put(&mut out, 8, mon);
        // Years 1 to 9999 by construction.
        let y = u32::try_from(year).unwrap_or(0);
        two(&mut out, 12, (y / 100) as u8);
        two(&mut out, 14, (y % 100) as u8);
        two(&mut out, 17, (secs / 3600) as u8);
        put(&mut out, 19, b":");
        two(&mut out, 20, (secs / 60 % 60) as u8);
        put(&mut out, 22, b":");
        two(&mut out, 23, (secs % 60) as u8);
        let (sign, abs) = if self.offset < 0 || self.offset_unknown {
            (b"-", self.offset.unsigned_abs())
        } else {
            (b"+", self.offset.unsigned_abs())
        };
        put(&mut out, 26, sign);
        two(&mut out, 27, (abs / 60) as u8);
        two(&mut out, 29, (abs % 60) as u8);
        (out, 31)
    }

    /// Writes [`format`](Self::format)'s text.
    ///
    /// # Errors
    ///
    /// [`WriteError::Full`]; nothing is written when the sink reports its
    /// room.
    pub fn write_to(self, out: &mut impl Sink) -> core::result::Result<(), WriteError> {
        let (bytes, len) = self.format();
        reserve(out, len)?;
        out.put(bytes.get(..len).unwrap_or(&bytes))?;
        Ok(())
    }

    /// Parses an RFC 5322 `date-time`. Names are case-insensitive (RFC 5234
    /// quoted strings); comments and folding whitespace may separate the
    /// tokens. With `obsolete`, also the section 4.3 forms: two- and
    /// three-digit years (below 50 are 20xx, others 19xx; three digits add
    /// 1900, D-036), `UT`, `GMT`, the North American zones, and the military
    /// zones (read as `-0000`).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidDate`] (a field out of range, a missing token, an
    /// obsolete form without `obsolete`); [`ErrorKind::WeekdayMismatch`];
    /// [`ErrorKind::OutOfRange`] (a year outside 1 to 9999);
    /// [`ErrorKind::TrailingData`]; [`ErrorKind::UnbalancedComment`];
    /// [`ErrorKind::CommentTooDeep`]; [`ErrorKind::BareCr`] and
    /// [`ErrorKind::LineFeed`] for a line break that is not folding.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{ErrorKind, MailDate};
    ///
    /// let d = MailDate::parse(b"1 jan 2026 00:00 (morning) -0000", false)?;
    /// assert!(d.offset_unknown());
    /// assert_eq!(MailDate::parse(b"Mon, 21 Oct 2026 17:38:00 +0200", false).unwrap_err().kind(), ErrorKind::WeekdayMismatch);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn parse(value: &[u8], obsolete: bool) -> Result<Self> {
        let mut c = Cur {
            v: value,
            i: 0,
            limits: Limits::DEFAULT,
        };
        let _ = c.cfws()?;
        let weekday = if c.peek().is_some_and(|b| b.is_ascii_alphabetic()) {
            let wd = c.name(&DAY_NAMES)?;
            let _ = c.cfws()?;
            if c.peek() != Some(b',') {
                return Err(c.fail(ErrorKind::InvalidDate));
            }
            c.i += 1;
            let _ = c.cfws()?;
            Some(wd + 1)
        } else {
            None
        };
        let (day, n) = c.digits()?;
        if !(1..=2).contains(&n) {
            return Err(c.fail_at(ErrorKind::InvalidDate, c.i - n));
        }
        c.space()?;
        let month = c.name(&MONTH_NAMES)? + 1;
        c.space()?;
        let at = c.i;
        let (y, n) = c.digits()?;
        let year = match n {
            4.. => y,
            2 if obsolete => {
                if y < 50 {
                    2000 + y
                } else {
                    1900 + y
                }
            }
            3 if obsolete => 1900 + y,
            _ => return Err(c.fail_at(ErrorKind::InvalidDate, at)),
        };
        if !(1..=9999).contains(&year) {
            return err(ErrorKind::OutOfRange, at);
        }
        c.space()?;
        let (hour, minute, second) = c.time(obsolete)?;
        c.space()?;
        let (offset, unknown) = c.zone(obsolete)?;
        let _ = c.cfws()?;
        if c.i < value.len() {
            return Err(c.fail(ErrorKind::TrailingData));
        }
        let (year, month, day) = (year as i32, month as u8, day as u8);
        if day == 0 || day > days_in_month(year, month) {
            return err(ErrorKind::InvalidDate, 0);
        }
        let days = days_from_civil(year, month, day);
        if weekday.is_some_and(|w| w as u8 != weekday_from_days(days)) {
            return err(ErrorKind::WeekdayMismatch, 0);
        }
        let leap_second = second == 60;
        let second = if leap_second { 59 } else { second };
        let local = days * SECS_PER_DAY + hour * 3600 + minute * 60 + second;
        Ok(Self {
            utc: local - i64::from(offset) * 60,
            offset,
            offset_unknown: unknown,
            leap_second,
        })
    }
}

fn put(out: &mut [u8], at: usize, bytes: &[u8]) {
    if let Some(dst) = out.get_mut(at..at + bytes.len()) {
        dst.copy_from_slice(bytes);
    }
}

fn two(out: &mut [u8], at: usize, v: u8) {
    put(out, at, &[b'0' + v / 10, b'0' + v % 10]);
}

/// A position in a `date-time`.
struct Cur<'a> {
    v: &'a [u8],
    i: usize,
    limits: Limits,
}

impl Cur<'_> {
    fn peek(&self) -> Option<u8> {
        self.v.get(self.i).copied()
    }

    fn fail_at(&self, kind: ErrorKind, at: usize) -> ParseError {
        match self.v.get(at) {
            Some(&b) if crate::scan::is_control(b) => ParseError::new(control_kind(b), at),
            _ => ParseError::new(kind, at),
        }
    }

    fn fail(&self, kind: ErrorKind) -> ParseError {
        self.fail_at(kind, self.i)
    }

    /// Skips CFWS: WSP, `CRLF WSP`, and comments. Returns whether anything
    /// was skipped.
    fn cfws(&mut self) -> Result<bool> {
        let start = self.i;
        loop {
            match self.peek() {
                Some(b' ' | b'\t') => self.i += 1,
                Some(b'\r') => {
                    if self.v.get(self.i + 1) == Some(&b'\n')
                        && matches!(self.v.get(self.i + 2), Some(b' ' | b'\t'))
                    {
                        self.i += 3;
                    } else {
                        return Err(self.fail(ErrorKind::BareCr));
                    }
                }
                Some(b'(') => self.i = comment_end(self.v, self.i, &self.limits)?.0,
                _ => return Ok(self.i > start),
            }
        }
    }

    /// CFWS that must be present (the grammar's `FWS`).
    fn space(&mut self) -> Result<()> {
        if self.cfws()? {
            Ok(())
        } else {
            Err(self.fail(ErrorKind::InvalidDate))
        }
    }

    /// A run of digits: its value (saturating) and length.
    fn digits(&mut self) -> Result<(u32, usize)> {
        let start = self.i;
        let mut v: u32 = 0;
        while let Some(d) = self.peek().filter(u8::is_ascii_digit) {
            v = v.saturating_mul(10).saturating_add(u32::from(d - b'0'));
            self.i += 1;
        }
        if self.i == start {
            return Err(self.fail(ErrorKind::InvalidDate));
        }
        Ok((v, self.i - start))
    }

    /// Exactly two digits.
    fn two(&mut self) -> Result<i64> {
        let at = self.i;
        let (v, n) = self.digits()?;
        if n != 2 {
            return Err(self.fail_at(ErrorKind::InvalidDate, at));
        }
        Ok(i64::from(v))
    }

    /// A three-letter name from `names`, ASCII case-insensitive; its index.
    fn name(&mut self, names: &[&[u8; 3]]) -> Result<u32> {
        let word = self.v.get(self.i..self.i + 3).unwrap_or(&[]);
        let found = names
            .iter()
            .position(|n| n.eq_ignore_ascii_case(word))
            .filter(|_| !self.v.get(self.i + 3).is_some_and(u8::is_ascii_alphabetic));
        match found {
            Some(idx) => {
                self.i += 3;
                Ok(idx as u32)
            }
            None => Err(self.fail(ErrorKind::InvalidDate)),
        }
    }

    /// `hour ":" minute [ ":" second ]`; with `obsolete`, CFWS around the
    /// colons.
    fn time(&mut self, obsolete: bool) -> Result<(i64, i64, i64)> {
        let at = self.i;
        let hour = self.two()?;
        let minute = {
            self.colon(obsolete)?;
            self.two()?
        };
        let mark = self.i;
        let second = if obsolete {
            let _ = self.cfws()?;
            if self.peek() == Some(b':') {
                self.colon(obsolete)?;
                self.two()?
            } else {
                self.i = mark;
                0
            }
        } else if self.peek() == Some(b':') {
            self.i += 1;
            self.two()?
        } else {
            0
        };
        if hour > 23 || minute > 59 || second > 60 {
            return err(ErrorKind::InvalidDate, at);
        }
        Ok((hour, minute, second))
    }

    fn colon(&mut self, obsolete: bool) -> Result<()> {
        if obsolete {
            let _ = self.cfws()?;
        }
        if self.peek() != Some(b':') {
            return Err(self.fail(ErrorKind::InvalidDate));
        }
        self.i += 1;
        if obsolete {
            let _ = self.cfws()?;
        }
        Ok(())
    }

    /// `( "+" / "-" ) 4DIGIT`, or with `obsolete` the section 4.3 names.
    /// Returns the offset and whether it is unknown.
    fn zone(&mut self, obsolete: bool) -> Result<(i16, bool)> {
        let at = self.i;
        match self.peek() {
            Some(sign @ (b'+' | b'-')) => {
                self.i += 1;
                let (v, n) = self.digits()?;
                if n != 4 || v % 100 > 59 {
                    return err(ErrorKind::InvalidDate, at);
                }
                let minutes = (v / 100 * 60 + v % 100) as i16;
                if sign == b'-' {
                    Ok((-minutes, minutes == 0))
                } else {
                    Ok((minutes, false))
                }
            }
            Some(b) if obsolete && b.is_ascii_alphabetic() => {
                let n = self
                    .v
                    .get(self.i..)
                    .unwrap_or(&[])
                    .iter()
                    .take_while(|b| b.is_ascii_alphabetic())
                    .count();
                let name = self.v.get(self.i..self.i + n).unwrap_or(&[]);
                const ZONES: [(&[u8], i16); 10] = [
                    (b"UT", 0),
                    (b"GMT", 0),
                    (b"EST", -300),
                    (b"EDT", -240),
                    (b"CST", -360),
                    (b"CDT", -300),
                    (b"MST", -420),
                    (b"MDT", -360),
                    (b"PST", -480),
                    (b"PDT", -420),
                ];
                let found = ZONES.iter().find(|(z, _)| z.eq_ignore_ascii_case(name));
                self.i += n;
                match found {
                    Some(&(_, off)) => Ok((off, false)),
                    // A military zone (any letter except J) is read as
                    // "-0000" (RFC 5322 section 4.3).
                    None if n == 1 && !name.eq_ignore_ascii_case(b"j") => Ok((0, true)),
                    None => err(ErrorKind::InvalidDate, at),
                }
            }
            _ => Err(self.fail(ErrorKind::InvalidDate)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(v: &[u8]) -> MailDate {
        MailDate::parse(v, false).unwrap()
    }

    fn k(v: &[u8], obsolete: bool) -> ErrorKind {
        MailDate::parse(v, obsolete).unwrap_err().kind()
    }

    fn text(d: MailDate) -> std::string::String {
        let (b, n) = d.format();
        std::string::String::from_utf8(b[..n].to_vec()).unwrap()
    }

    #[test]
    fn test_mail_date_edge_cases() {
        let d = p(b"Wed, 21 Oct 2026 17:38:00 +0200");
        assert_eq!(d.utc(), p(b"21 Oct 2026 15:38:00 +0000").utc());
        assert_eq!(
            text(p(b"21 Oct 2026 17:38 +0200")),
            "Wed, 21 Oct 2026 17:38:00 +0200"
        );
        assert_eq!(
            text(p(b"1 Jan 2026 00:00:00 +0000")),
            "Thu, 01 Jan 2026 00:00:00 +0000"
        );
        assert_eq!(
            k(b"Mon, 21 Oct 2026 17:38:00 +0200", false),
            ErrorKind::WeekdayMismatch
        );
        assert_eq!(p(b"21 Oct 2026 17:38 +2400").offset_minutes(), 1440);
        assert_eq!(k(b"21 Oct 2026 17:38 +0060", false), ErrorKind::InvalidDate);
        let u = p(b"21 Oct 2026 17:38 -0000");
        assert!(u.offset_unknown() && u.offset_minutes() == 0);
        assert_eq!(text(u), "Wed, 21 Oct 2026 17:38:00 -0000");
        assert!(!p(b"21 Oct 2026 17:38 +0000").offset_unknown());
        let c = p(b" (a (b)) Wed , 21 (x) oct 2026 17:38:00 (y)\r\n +0200 (z) ");
        assert_eq!(c.utc(), d.utc());
        let l = p(b"31 Dec 2016 23:59:60 +0000");
        assert!(l.leap_second());
        assert_eq!(l.utc(), p(b"31 Dec 2016 23:59:59 +0000").utc());
        assert_eq!(k(b"30 Feb 2026 00:00 +0000", false), ErrorKind::InvalidDate);
        assert_eq!(k(b"21 Oct 2026 24:00 +0000", false), ErrorKind::InvalidDate);
        assert_eq!(
            k(b"21 Oct 2026 17:38 +0000 x", false),
            ErrorKind::TrailingData
        );
        assert_eq!(
            k(b"21 Oct 2026 17:38 +0000 (", false),
            ErrorKind::UnbalancedComment
        );
        assert_eq!(k(b"21 Oct 2026 17:38\r\n+0000", false), ErrorKind::BareCr);
        assert_eq!(
            k(b"21 Octo 2026 17:38 +0000", false),
            ErrorKind::InvalidDate
        );
        assert_eq!(k(b"21 Oct 0000 17:38 +0000", false), ErrorKind::OutOfRange);
        assert_eq!(k(b"21 Oct 10000 17:38 +0000", false), ErrorKind::OutOfRange);
        assert_eq!(k(b"21Oct 2026 17:38 +0000", false), ErrorKind::InvalidDate);
        assert_eq!(k(b"", false), ErrorKind::InvalidDate);
        let deep = b"21 Oct 2026 17:38 +0000 (((((((((x)))))))))";
        assert_eq!(k(deep, false), ErrorKind::CommentTooDeep);
    }

    #[test]
    fn test_mail_date_obsolete_forms() {
        assert_eq!(k(b"21 Oct 26 17:38 EDT", false), ErrorKind::InvalidDate);
        let d = MailDate::parse(b"21 Oct 26 17:38 EDT", true).unwrap();
        assert_eq!(
            (d.offset_minutes(), text(d).as_str()),
            (-240, "Wed, 21 Oct 2026 17:38:00 -0400")
        );
        assert_eq!(
            text(MailDate::parse(b"1 Jan 70 00:00 GMT", true).unwrap()),
            "Thu, 01 Jan 1970 00:00:00 +0000"
        );
        assert_eq!(
            text(MailDate::parse(b"1 Jan 49 00:00 UT", true).unwrap()),
            "Fri, 01 Jan 2049 00:00:00 +0000"
        );
        assert_eq!(
            text(MailDate::parse(b"1 Jan 100 00:00 PST", true).unwrap()),
            "Sat, 01 Jan 2000 00:00:00 -0800"
        );
        assert!(
            MailDate::parse(b"1 Jan 2026 00:00 Z", true)
                .unwrap()
                .offset_unknown()
        );
        assert_eq!(k(b"1 Jan 2026 00:00 J", true), ErrorKind::InvalidDate);
        assert_eq!(k(b"1 Jan 2026 00:00 XYZ", true), ErrorKind::InvalidDate);
        assert_eq!(
            MailDate::parse(b"1 Jan 2026 00 : 00 : 30 +0000", true)
                .unwrap()
                .utc()
                % 60,
            30
        );
        assert_eq!(
            k(b"1 Jan 2026 00 : 00 +0000", false),
            ErrorKind::InvalidDate
        );
    }

    #[test]
    fn test_mail_date_new_and_write() {
        assert_eq!(
            MailDate::new(0, 6000).unwrap_err().kind(),
            ErrorKind::OutOfRange
        );
        assert_eq!(
            MailDate::new(0, -6000).unwrap_err().kind(),
            ErrorKind::OutOfRange
        );
        assert!(MailDate::new(0, 5999).is_ok() && MailDate::new(0, -5999).is_ok());
        assert_eq!(
            MailDate::new(MIN_SECS, -1).unwrap_err().kind(),
            ErrorKind::OutOfRange
        );
        assert_eq!(
            MailDate::new(MAX_SECS, 1).unwrap_err().kind(),
            ErrorKind::OutOfRange
        );
        assert_eq!(
            text(MailDate::new(MIN_SECS, 0).unwrap()),
            "Mon, 01 Jan 0001 00:00:00 +0000"
        );
        let mut buf = [0u8; 30];
        let mut out = crate::SliceSink::new(&mut buf);
        assert_eq!(
            MailDate::new(0, 0).unwrap().write_to(&mut out),
            Err(WriteError::Full)
        );
        assert!(out.is_empty());
        for secs in [-62_135_596_800i64, -1, 0, 1_792_540_800, 253_402_300_799] {
            for off in [-5999i16, -300, 0, 330, 5999] {
                if let Ok(d) = MailDate::new(secs, off) {
                    let (b, n) = d.format();
                    let back = MailDate::parse(&b[..n], false).unwrap();
                    assert_eq!((back.utc(), back.offset_minutes()), (secs, off));
                }
            }
        }
    }
}
