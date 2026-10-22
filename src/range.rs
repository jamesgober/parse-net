//! `Range`, `Content-Range`, and `If-Range` (RFC 9110 section 14), with
//! resolution against a representation length and budgets against abusive
//! range sets.
//!
//! # Examples
//!
//! ```
//! use parse_net::{self as pn, ByteRange, RangeOutcome, range};
//!
//! let mut out = [ByteRange { start: 0, end: 0 }; 8];
//! assert_eq!(pn::byte_ranges(b"bytes=0-99, -100", 1000, &mut out)?, RangeOutcome::Ranges(2));
//! assert_eq!(out[1], ByteRange { start: 900, end: 999 });
//! assert_eq!(pn::byte_ranges(b"bytes=2000-", 1000, &mut out)?, RangeOutcome::Unsatisfiable);
//! assert_eq!(pn::byte_ranges(b"items=0-5", 1000, &mut out)?, RangeOutcome::NotBytes);
//!
//! let mut buf = [0u8; 32];
//! let mut sink = pn::SliceSink::new(&mut buf);
//! range::write_content_range(out[0], Some(1000), &mut sink).expect("room");
//! assert_eq!(sink.written(), b"bytes 0-99/1000");
//! # Ok::<(), pn::ParseError>(())
//! ```

use crate::{
    class,
    date::HttpDate,
    error::{ErrorKind, Result, WriteError, err},
    etag::EntityTag,
    limits::Limits,
    list,
    num::parse_u64,
    text::{skip_ows, trim_ows},
    write::{CountSink, Sink, reserve, write_decimal_u64},
};

/// One `range-spec` of a `bytes` range set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RangeSpec {
    /// `first-` : from `first` to the end.
    From(u64),
    /// `first-last`, both inclusive.
    FromTo(u64, u64),
    /// `-length`: the last `length` bytes.
    Suffix(u64),
}

/// A resolved byte range, both ends inclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ByteRange {
    /// The first byte.
    pub start: u64,
    /// The last byte (inclusive).
    pub end: u64,
}

impl ByteRange {
    /// The number of bytes, `end - start + 1`, saturating at `u64::MAX`; zero
    /// when `end < start`.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(parse_net::ByteRange { start: 0, end: 499 }.len(), 500);
    /// ```
    #[must_use]
    pub const fn len(&self) -> u64 {
        if self.end < self.start {
            0
        } else {
            (self.end - self.start).saturating_add(1)
        }
    }

    /// Whether the range holds no bytes (only possible when `end < start`).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.end < self.start
    }
}

/// What to do with a `Range` request.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RangeOutcome {
    /// Serve these ranges (206): the first `n` entries of the output.
    Ranges(usize),
    /// No range is satisfiable: answer 416 with `Content-Range: bytes */length`.
    Unsatisfiable,
    /// Ignore the field and serve the whole representation (200): the set is
    /// abusive (too many ranges, too many overlapping, too much out of order)
    /// or does not fit the output.
    Ignore,
    /// Another range unit: ignore the field and serve the whole
    /// representation.
    NotBytes,
}

/// A validated `Range` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RangeHeader<'a> {
    unit: &'a [u8],
    set: list::List<'a>,
}

impl<'a> RangeHeader<'a> {
    /// Whether the unit is `bytes` (case-insensitive).
    #[must_use]
    pub fn is_bytes(&self) -> bool {
        self.unit.eq_ignore_ascii_case(b"bytes")
    }

    /// The range unit, as sent.
    #[must_use]
    pub const fn unit(&self) -> &'a [u8] {
        self.unit
    }

    /// The range specs, in request order; empty unless the unit is `bytes`.
    pub fn specs(&self) -> impl Iterator<Item = RangeSpec> + use<'a> {
        let bytes = self.is_bytes();
        self.set
            .iter()
            .filter(move |_| bytes)
            .filter_map(|e| spec(e).ok())
    }

    /// The number of range specs.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.set.len()
    }

    /// Whether the set is empty (never true for a parsed value).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

/// Parses one `int-range / suffix-range`.
fn spec(e: &[u8]) -> Result<RangeSpec> {
    let Some(dash) = e.iter().position(|&b| b == b'-') else {
        return err(ErrorKind::InvalidRange, e.len());
    };
    let (first, last) = (
        e.get(..dash).unwrap_or(&[]),
        e.get(dash + 1..).unwrap_or(&[]),
    );
    match (first.is_empty(), last.is_empty()) {
        (true, true) => err(ErrorKind::InvalidRange, 0),
        (true, false) => Ok(RangeSpec::Suffix(
            parse_u64(last).map_err(|x| x.shifted(dash + 1))?,
        )),
        (false, true) => Ok(RangeSpec::From(parse_u64(first)?)),
        (false, false) => {
            let f = parse_u64(first)?;
            let l = parse_u64(last).map_err(|x| x.shifted(dash + 1))?;
            if f > l {
                return err(ErrorKind::InvalidRange, 0);
            }
            Ok(RangeSpec::FromTo(f, l))
        }
    }
}

/// Parses `range-unit "=" range-set` (RFC 9110 section 14.1.2).
///
/// The unit compares case-insensitively. A `bytes` set must hold only
/// `first-last`, `first-`, and `-length` specs; another unit's set is
/// checked as `other-range` bytes and not interpreted.
///
/// # Errors
///
/// [`ErrorKind::NotToken`] for the unit; [`ErrorKind::InvalidRange`] for a
/// missing `=`, whitespace around it, an empty set, `first > last`, or a
/// malformed spec; [`ErrorKind::InvalidNumber`], [`ErrorKind::NumberOverflow`];
/// the list errors.
///
/// # Examples
///
/// ```
/// use parse_net::{range, Limits, RangeSpec};
///
/// let h = range::parse(b"bytes=0-0, -5, 10-", &Limits::DEFAULT)?;
/// assert_eq!(h.specs().collect::<Vec<_>>(), [RangeSpec::FromTo(0, 0), RangeSpec::Suffix(5), RangeSpec::From(10)]);
/// assert!(range::parse(b"bytes=5-4", &Limits::DEFAULT).is_err());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse<'a>(value: &'a [u8], limits: &Limits) -> Result<RangeHeader<'a>> {
    let lead = skip_ows(value);
    let v = trim_ows(value);
    let unit_len = v.iter().take_while(|&&b| class::is_tchar(b)).count();
    if unit_len == 0 {
        return err(ErrorKind::NotToken, lead);
    }
    if v.get(unit_len) != Some(&b'=') {
        return err(ErrorKind::InvalidRange, lead + unit_len);
    }
    let unit = v.get(..unit_len).unwrap_or(&[]);
    let set_at = unit_len + 1;
    let set_text = v.get(set_at..).unwrap_or(&[]);
    if set_text.first().is_some_and(|&b| crate::text::is_ows(b)) {
        return err(ErrorKind::InvalidRange, lead + set_at);
    }
    let set = list::parse(set_text, limits).map_err(|e| e.shifted(lead + set_at))?;
    if set.is_empty() {
        return err(ErrorKind::InvalidRange, lead + set_at);
    }
    let bytes = unit.eq_ignore_ascii_case(b"bytes");
    for e in set.iter() {
        let at = lead + (e.as_ptr() as usize).saturating_sub(v.as_ptr() as usize);
        if bytes {
            spec(e).map(|_| ()).map_err(|x| x.shifted(at))?;
        } else if let Some(i) = e.iter().position(|&b| b == b',' || !class::is_vchar(b)) {
            return err(ErrorKind::InvalidRange, at + i);
        }
    }
    Ok(RangeHeader { unit, set })
}

/// Resolves a parsed `Range` against a representation of `length` bytes.
///
/// Suffix ranges become absolute; a last position beyond the end is clamped;
/// a range starting at or after the end, and a zero-length suffix, are
/// dropped. More than [`Limits::max_ranges`] ranges, more than two ranges
/// that overlap another, or more than two ranges that start before the one
/// before them give [`RangeOutcome::Ignore`] (RFC 9110 section 14.2 allows
/// ignoring abusive sets). With `coalesce`, overlapping and adjacent ranges
/// are merged into ascending order (this changes the shape of a multipart
/// response, so it is the caller's choice). An `out` too small for the
/// ranges gives `Ignore`: the set is never silently truncated.
///
/// # Examples
///
/// ```
/// use parse_net::{range, ByteRange, Limits, RangeOutcome};
///
/// let h = range::parse(b"bytes=0-10, 5-20, 40-49", &Limits::DEFAULT)?;
/// let mut out = [ByteRange { start: 0, end: 0 }; 4];
/// assert_eq!(range::resolve(&h, 100, true, &Limits::DEFAULT, &mut out), RangeOutcome::Ranges(2));
/// assert_eq!(out[..2], [ByteRange { start: 0, end: 20 }, ByteRange { start: 40, end: 49 }]);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[must_use]
pub fn resolve(
    h: &RangeHeader<'_>,
    length: u64,
    coalesce: bool,
    limits: &Limits,
    out: &mut [ByteRange],
) -> RangeOutcome {
    if !h.is_bytes() {
        return RangeOutcome::NotBytes;
    }
    if h.len() > usize::from(limits.ranges) {
        return RangeOutcome::Ignore;
    }
    let mut n = 0usize;
    let mut descents = 0usize;
    let mut previous_start: Option<u64> = None;
    for s in h.specs() {
        let Some(r) = absolute(s, length) else {
            continue;
        };
        if previous_start.is_some_and(|p| r.start < p) {
            descents += 1;
        }
        previous_start = Some(r.start);
        match out.get_mut(n) {
            Some(slot) => *slot = r,
            None => return RangeOutcome::Ignore,
        }
        n += 1;
    }
    if n == 0 {
        return RangeOutcome::Unsatisfiable;
    }
    let resolved = out.get_mut(..n).unwrap_or(&mut []);
    let overlapping = resolved
        .iter()
        .enumerate()
        .filter(|&(i, a)| {
            resolved
                .iter()
                .enumerate()
                .any(|(j, b)| i != j && a.start <= b.end && b.start <= a.end)
        })
        .count();
    if overlapping > 2 || descents > 2 {
        return RangeOutcome::Ignore;
    }
    if coalesce {
        // Insertion sort: at most `max_ranges` entries.
        for i in 1..resolved.len() {
            let mut j = i;
            while j > 0 {
                let (Some(&a), Some(&b)) = (resolved.get(j - 1), resolved.get(j)) else {
                    break;
                };
                if a.start <= b.start {
                    break;
                }
                resolved.swap(j - 1, j);
                j -= 1;
            }
        }
        let mut merged = 0usize;
        for i in 0..resolved.len() {
            let Some(&r) = resolved.get(i) else { break };
            match merged.checked_sub(1).and_then(|m| resolved.get_mut(m)) {
                Some(last) if r.start <= last.end.saturating_add(1) => {
                    last.end = last.end.max(r.end);
                }
                _ => {
                    if let Some(slot) = resolved.get_mut(merged) {
                        *slot = r;
                    }
                    merged += 1;
                }
            }
        }
        n = merged;
    }
    RangeOutcome::Ranges(n)
}

/// The absolute range of `s` in a representation of `length` bytes, or
/// `None` when it is unsatisfiable.
fn absolute(s: RangeSpec, length: u64) -> Option<ByteRange> {
    let last = length.checked_sub(1)?;
    match s {
        RangeSpec::From(f) if f <= last => Some(ByteRange {
            start: f,
            end: last,
        }),
        RangeSpec::FromTo(f, l) if f <= last => Some(ByteRange {
            start: f,
            end: l.min(last),
        }),
        RangeSpec::Suffix(n) if n > 0 => Some(ByteRange {
            start: length - n.min(length),
            end: last,
        }),
        _ => None,
    }
}

/// Parses and resolves `Range` against `length` with the default limits and
/// no coalescing.
///
/// # Errors
///
/// As [`parse`]. RFC 9110 lets a server ignore a `Range` it cannot read:
/// treat an error as [`RangeOutcome::Ignore`] unless the request should be
/// refused.
///
/// # Examples
///
/// ```
/// use parse_net::{byte_ranges, ByteRange, RangeOutcome};
///
/// let mut out = [ByteRange { start: 0, end: 0 }; 1];
/// assert_eq!(byte_ranges(b"bytes=0-0, 2-2", 10, &mut out)?, RangeOutcome::Ignore); // `out` too small
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn byte_ranges(value: &[u8], length: u64, out: &mut [ByteRange]) -> Result<RangeOutcome> {
    let h = parse(value, &Limits::DEFAULT)?;
    Ok(resolve(&h, length, false, &Limits::DEFAULT, out))
}

/// A parsed `Content-Range` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ContentRange {
    /// `bytes first-last/complete` or `bytes first-last/*`.
    Satisfied {
        /// The range sent.
        range: ByteRange,
        /// The complete length, when known.
        complete: Option<u64>,
    },
    /// `bytes */complete`, sent with 416.
    Unsatisfied {
        /// The complete length.
        complete: u64,
    },
}

/// Parses `Content-Range` (RFC 9110 section 14.4) for the `bytes` unit.
///
/// # Errors
///
/// [`ErrorKind::InvalidRange`] (another unit, a missing space, `last < first`,
/// `last >= complete`, a malformed shape); [`ErrorKind::InvalidNumber`],
/// [`ErrorKind::NumberOverflow`].
///
/// # Examples
///
/// ```
/// use parse_net::{range::parse_content_range, ByteRange, ContentRange};
///
/// assert_eq!(parse_content_range(b"bytes 0-499/1234")?,
///            ContentRange::Satisfied { range: ByteRange { start: 0, end: 499 }, complete: Some(1234) });
/// assert_eq!(parse_content_range(b"bytes */0")?, ContentRange::Unsatisfied { complete: 0 });
/// assert!(parse_content_range(b"bytes 0-5/5").is_err());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_content_range(value: &[u8]) -> Result<ContentRange> {
    let lead = skip_ows(value);
    let v = trim_ows(value);
    inner_content_range(v).map_err(|e| e.shifted(lead))
}

fn inner_content_range(v: &[u8]) -> Result<ContentRange> {
    let unit = v.get(..5).unwrap_or(&[]);
    if !unit.eq_ignore_ascii_case(b"bytes") || v.get(5) != Some(&b' ') {
        return err(ErrorKind::InvalidRange, 0);
    }
    let rest = v.get(6..).unwrap_or(&[]);
    let Some(slash) = rest.iter().position(|&b| b == b'/') else {
        return err(ErrorKind::InvalidRange, v.len());
    };
    let (range_text, complete_text) = (
        rest.get(..slash).unwrap_or(&[]),
        rest.get(slash + 1..).unwrap_or(&[]),
    );
    let complete_at = 6 + slash + 1;
    if range_text == b"*" {
        let complete = parse_u64(complete_text).map_err(|e| e.shifted(complete_at))?;
        return Ok(ContentRange::Unsatisfied { complete });
    }
    let complete = if complete_text == b"*" {
        None
    } else {
        Some(parse_u64(complete_text).map_err(|e| e.shifted(complete_at))?)
    };
    let Some(dash) = range_text.iter().position(|&b| b == b'-') else {
        return err(ErrorKind::InvalidRange, 6);
    };
    let first = parse_u64(range_text.get(..dash).unwrap_or(&[])).map_err(|e| e.shifted(6))?;
    let last = parse_u64(range_text.get(dash + 1..).unwrap_or(&[]))
        .map_err(|e| e.shifted(6 + dash + 1))?;
    if last < first || complete.is_some_and(|c| last >= c) {
        return err(ErrorKind::InvalidRange, 6);
    }
    Ok(ContentRange::Satisfied {
        range: ByteRange {
            start: first,
            end: last,
        },
        complete,
    })
}

fn put_content_range(
    r: ByteRange,
    complete: Option<u64>,
    out: &mut impl Sink,
) -> core::result::Result<(), WriteError> {
    out.put(b"bytes ")?;
    write_decimal_u64(r.start, out)?;
    out.put(b"-")?;
    write_decimal_u64(r.end, out)?;
    out.put(b"/")?;
    match complete {
        Some(c) => write_decimal_u64(c, out)?,
        None => out.put(b"*")?,
    }
    Ok(())
}

/// Writes `bytes first-last/complete`, or `bytes first-last/*` when the
/// complete length is unknown.
///
/// # Errors
///
/// [`WriteError::OutOfRange`] when `end < start` or `end >= complete`;
/// [`WriteError::Full`] (nothing written when the sink reports its room).
pub fn write_content_range(
    r: ByteRange,
    complete: Option<u64>,
    out: &mut impl Sink,
) -> core::result::Result<(), WriteError> {
    if r.end < r.start || complete.is_some_and(|c| r.end >= c) {
        return Err(WriteError::OutOfRange);
    }
    let mut count = CountSink::new();
    put_content_range(r, complete, &mut count)?;
    reserve(out, count.count())?;
    put_content_range(r, complete, out)
}

/// Writes `bytes */complete`, for a 416 response.
///
/// # Errors
///
/// [`WriteError::Full`] (nothing written when the sink reports its room).
///
/// # Examples
///
/// ```
/// use parse_net::{range::write_unsatisfied, SliceSink};
///
/// let mut buf = [0u8; 32];
/// let mut out = SliceSink::new(&mut buf);
/// write_unsatisfied(1234, &mut out).expect("room");
/// assert_eq!(out.written(), b"bytes */1234");
/// ```
pub fn write_unsatisfied(
    complete: u64,
    out: &mut impl Sink,
) -> core::result::Result<(), WriteError> {
    let mut count = CountSink::new();
    count.put(b"bytes */")?;
    write_decimal_u64(complete, &mut count)?;
    reserve(out, count.count())?;
    out.put(b"bytes */")?;
    write_decimal_u64(complete, out)
}

/// A parsed `If-Range` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IfRange<'a> {
    /// An HTTP-date.
    Date(HttpDate),
    /// An entity tag.
    Tag(EntityTag<'a>),
}

impl IfRange<'_> {
    /// Whether the condition holds, so the ranges may be served (RFC 9110
    /// section 13.1.5): a tag matches by strong comparison (a weak tag never
    /// matches); a date matches when it equals `last_modified` exactly. When
    /// it does not hold, send the whole representation.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{range::parse_if_range, EntityTag};
    ///
    /// let current = EntityTag::strong(b"v1")?;
    /// assert!(parse_if_range(b"\"v1\"")?.matches(Some(&current), None));
    /// assert!(!parse_if_range(b"W/\"v1\"")?.matches(Some(&current), None));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn matches(
        &self,
        current_tag: Option<&EntityTag<'_>>,
        last_modified: Option<HttpDate>,
    ) -> bool {
        match self {
            IfRange::Tag(t) => current_tag.is_some_and(|c| t.strong_eq(c)),
            IfRange::Date(d) => last_modified == Some(*d),
        }
    }
}

/// Parses `If-Range`: an entity tag when the value starts with `W/` or `"`,
/// an IMF-fixdate otherwise.
///
/// # Errors
///
/// The errors of [`EntityTag::parse`] or [`HttpDate::parse_imf_fixdate`].
pub fn parse_if_range(value: &[u8]) -> Result<IfRange<'_>> {
    let v = trim_ows(value);
    if v.starts_with(b"W/") || v.starts_with(b"\"") {
        EntityTag::parse(value).map(IfRange::Tag)
    } else {
        HttpDate::parse_imf_fixdate(value).map(IfRange::Date)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve_str(
        v: &[u8],
        length: u64,
        coalesce: bool,
    ) -> (RangeOutcome, std::vec::Vec<ByteRange>) {
        let mut out = [ByteRange { start: 0, end: 0 }; 32];
        let h = parse(v, &Limits::DEFAULT).unwrap();
        let o = resolve(&h, length, coalesce, &Limits::DEFAULT, &mut out);
        let n = if let RangeOutcome::Ranges(n) = o {
            n
        } else {
            0
        };
        (o, out[..n].to_vec())
    }

    #[test]
    fn test_range_parse_edge_cases() {
        let l = Limits::DEFAULT;
        let k = |v: &[u8]| parse(v, &l).unwrap_err().kind();
        assert!(parse(b"bytes=0-0", &l).is_ok());
        assert!(parse(b"BYTES=0-1", &l).unwrap().is_bytes());
        assert_eq!(k(b"bytes=5-4"), ErrorKind::InvalidRange);
        assert_eq!(k(b"bytes = 0-1"), ErrorKind::InvalidRange);
        assert_eq!(k(b"bytes= 0-1"), ErrorKind::InvalidRange);
        assert_eq!(k(b"bytes=0 -1"), ErrorKind::InvalidNumber);
        assert_eq!(k(b"bytes="), ErrorKind::InvalidRange);
        assert_eq!(k(b"bytes=-"), ErrorKind::InvalidRange);
        assert_eq!(
            k(b"bytes=0-18446744073709551616"),
            ErrorKind::NumberOverflow
        );
        assert!(parse(b"bytes=0-18446744073709551615", &l).is_ok());
        assert!(parse(b"bytes=0-1,", &l).is_ok());
        assert_eq!(k(b"=0-1"), ErrorKind::NotToken);
        assert_eq!(k(b"bytes"), ErrorKind::InvalidRange);
        assert!(parse(b"items=0-5", &l).is_ok());
        assert_eq!(k(b"items=a b"), ErrorKind::InvalidRange);
        assert_eq!(parse(b"items=0-5", &l).unwrap().specs().count(), 0);
    }

    #[test]
    fn test_range_resolution() {
        assert_eq!(
            resolve_str(b"bytes=0-", 10, false).1,
            [ByteRange { start: 0, end: 9 }]
        );
        assert_eq!(
            resolve_str(b"bytes=-0", 10, false).0,
            RangeOutcome::Unsatisfiable
        );
        assert_eq!(
            resolve_str(b"bytes=-1", 0, false).0,
            RangeOutcome::Unsatisfiable
        );
        assert_eq!(
            resolve_str(b"bytes=-20", 10, false).1,
            [ByteRange { start: 0, end: 9 }]
        );
        assert_eq!(
            resolve_str(b"bytes=5-100", 10, false).1,
            [ByteRange { start: 5, end: 9 }]
        );
        assert_eq!(
            resolve_str(b"bytes=10-", 10, false).0,
            RangeOutcome::Unsatisfiable
        );
        assert_eq!(
            resolve_str(b"bytes=10-, 0-0", 10, false).1,
            [ByteRange { start: 0, end: 0 }]
        );
        assert_eq!(
            resolve_str(b"bytes=0-18446744073709551615", u64::MAX, false).1[0].len(),
            u64::MAX
        );
    }

    #[test]
    fn test_range_17_ranges_ignored() {
        let mut sixteen = b"bytes=".to_vec();
        sixteen.extend(
            (0..16)
                .map(|i| std::format!("{}-{},", i * 10, i * 10 + 1))
                .collect::<std::string::String>()
                .into_bytes(),
        );
        assert_eq!(
            resolve_str(&sixteen, 1000, false).0,
            RangeOutcome::Ranges(16)
        );
        let seventeen: std::vec::Vec<u8> = (0..17)
            .map(|i| std::format!("{}-{},", i * 10, i * 10 + 1))
            .collect::<std::string::String>()
            .into_bytes();
        let mut v = b"bytes=".to_vec();
        v.extend(seventeen);
        assert_eq!(resolve_str(&v, 1000, false).0, RangeOutcome::Ignore);
    }

    #[test]
    fn test_range_three_overlapping_ignored() {
        assert_eq!(
            resolve_str(b"bytes=0-10, 5-15", 100, false).0,
            RangeOutcome::Ranges(2)
        );
        assert_eq!(
            resolve_str(b"bytes=0-10, 5-15, 8-20", 100, false).0,
            RangeOutcome::Ignore
        );
        assert_eq!(
            resolve_str(b"bytes=50-60, 40-45, 30-35, 20-25", 100, false).0,
            RangeOutcome::Ignore
        );
        assert_eq!(
            resolve_str(b"bytes=50-60, 40-45, 30-35", 100, false).0,
            RangeOutcome::Ranges(3)
        );
    }

    #[test]
    fn test_range_coalesce() {
        let (o, r) = resolve_str(b"bytes=40-49, 0-10, 11-20, 5-6", 100, true);
        assert_eq!(o, RangeOutcome::Ranges(2));
        assert_eq!(
            r,
            [
                ByteRange { start: 0, end: 20 },
                ByteRange { start: 40, end: 49 }
            ]
        );
    }

    #[test]
    fn test_content_range_cases() {
        assert!(parse_content_range(b"bytes 0-0/1").is_ok());
        assert_eq!(
            parse_content_range(b"bytes 0-0/*").unwrap(),
            ContentRange::Satisfied {
                range: ByteRange { start: 0, end: 0 },
                complete: None
            }
        );
        assert_eq!(
            parse_content_range(b"bytes */0").unwrap(),
            ContentRange::Unsatisfied { complete: 0 }
        );
        for bad in [
            &b"bytes 1-0/5"[..],
            b"bytes 0-5/5",
            b"bytes0-1/2",
            b"items 0-1/2",
            b"bytes 0-1",
            b"bytes -1/2",
            b"bytes */*",
        ] {
            assert!(
                parse_content_range(bad).is_err(),
                "{}",
                std::string::String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn test_content_range_writers() {
        let mut buf = [0u8; 64];
        let mut out = crate::SliceSink::new(&mut buf);
        assert_eq!(
            write_content_range(ByteRange { start: 5, end: 4 }, None, &mut out),
            Err(WriteError::OutOfRange)
        );
        assert_eq!(
            write_content_range(ByteRange { start: 0, end: 5 }, Some(5), &mut out),
            Err(WriteError::OutOfRange)
        );
        write_content_range(ByteRange { start: 0, end: 4 }, None, &mut out).unwrap();
        assert_eq!(out.written(), b"bytes 0-4/*");
        assert_eq!(
            parse_content_range(out.written()).unwrap(),
            ContentRange::Satisfied {
                range: ByteRange { start: 0, end: 4 },
                complete: None
            }
        );
        let mut small = [0u8; 8];
        let mut out = crate::SliceSink::new(&mut small);
        assert_eq!(write_unsatisfied(1, &mut out), Err(WriteError::Full));
        assert!(out.is_empty());
    }

    #[test]
    fn test_if_range() {
        let d = HttpDate::from_unix(784_111_777).unwrap();
        let date = parse_if_range(b"Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        assert!(date.matches(None, Some(d)));
        assert!(!date.matches(None, None));
        assert!(parse_if_range(b"Sunday, 06-Nov-94 08:49:37 GMT").is_err());
        let t = EntityTag::strong(b"a").unwrap();
        assert!(!parse_if_range(b"\"b\"").unwrap().matches(Some(&t), Some(d)));
    }
}
