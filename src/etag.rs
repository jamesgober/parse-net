//! Entity tags and the `If-Match` / `If-None-Match` conditions (RFC 9110
//! sections 8.8.3 and 13.1).
//!
//! # Examples
//!
//! ```
//! use parse_net::{self as pn, EntityTag};
//!
//! let v2 = EntityTag::strong(b"v2")?;
//! assert!(pn::if_none_match(b"\"v1\", W/\"v2\"", &v2)?);         // weak comparison: 304
//! assert!(!pn::if_match(b"W/\"v2\"", Some(&v2))?);               // strong comparison: 412
//! assert!(pn::if_match(b"*", Some(&v2))? && !pn::if_match(b"*", None)?);
//! # Ok::<(), pn::ParseError>(())
//! ```

use crate::{
    class,
    error::{ErrorKind, ParseError, Result, WriteError, err},
    limits::Limits,
    text::{skip_ows, trim_ows},
    write::{Sink, reserve},
};

/// An entity tag: a weak flag and the opaque bytes between the quotes.
///
/// # Examples
///
/// ```
/// use parse_net::EntityTag;
///
/// let t = EntityTag::parse(b"W/\"abc\"")?;
/// assert!(t.is_weak());
/// assert_eq!(t.opaque(), b"abc");
/// assert!(t.weak_eq(&EntityTag::strong(b"abc")?));
/// assert!(!t.strong_eq(&EntityTag::strong(b"abc")?));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EntityTag<'a> {
    pub(crate) weak: bool,
    pub(crate) opaque: &'a [u8],
}

/// The offset of the first byte of `opaque` that is not an `etagc`.
const fn first_bad(opaque: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < opaque.len() {
        // `i < opaque.len()` was just checked.
        #[allow(clippy::indexing_slicing)]
        let b = opaque[i];
        if !class::is_etagc(b) {
            return Some(i);
        }
        i += 1;
    }
    None
}

impl<'a> EntityTag<'a> {
    /// Parses `[ "W/" ] DQUOTE *etagc DQUOTE` (OWS around it stripped).
    /// `W/` is case-sensitive.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidEntityTag`] (a lowercase `w/`, no quotes, a byte
    /// outside `etagc`, `W/ "a"`); [`ErrorKind::TrailingData`].
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::EntityTag;
    ///
    /// let t = EntityTag::parse(b" \"xyzzy\" ")?;
    /// assert!(!t.is_weak() && t.opaque() == b"xyzzy");
    /// assert!(EntityTag::parse(b"w/\"xyzzy\"").is_err());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn parse(value: &'a [u8]) -> Result<Self> {
        let lead = crate::text::skip_ows(value);
        let (tag, used) = parse_prefix(trim_ows(value)).map_err(|e| e.shifted(lead))?;
        if used != trim_ows(value).len() {
            return err(ErrorKind::TrailingData, lead + used);
        }
        Ok(tag)
    }

    /// A strong tag with the given opaque bytes.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidEntityTag`] at the first byte that is not an
    /// `etagc`.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::EntityTag;
    ///
    /// assert!(!EntityTag::strong(b"v1")?.is_weak());
    /// assert!(EntityTag::strong(b"a\"b").is_err());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub const fn strong(opaque: &'a [u8]) -> Result<Self> {
        match first_bad(opaque) {
            Some(at) => Err(ParseError::new(ErrorKind::InvalidEntityTag, at)),
            None => Ok(Self {
                weak: false,
                opaque,
            }),
        }
    }

    /// A weak tag with the given opaque bytes.
    ///
    /// # Errors
    ///
    /// As [`strong`](Self::strong).
    ///
    /// # Examples
    ///
    /// ```
    /// let t = parse_net::EntityTag::weak(b"v1")?;
    /// assert!(t.is_weak() && t.opaque() == b"v1");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub const fn weak(opaque: &'a [u8]) -> Result<Self> {
        match first_bad(opaque) {
            Some(at) => Err(ParseError::new(ErrorKind::InvalidEntityTag, at)),
            None => Ok(Self { weak: true, opaque }),
        }
    }

    /// Whether the tag is weak (`W/`).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::EntityTag;
    ///
    /// assert!(EntityTag::parse(b"W/\"1\"")?.is_weak());
    /// assert!(!EntityTag::parse(b"\"1\"")?.is_weak());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn is_weak(&self) -> bool {
        self.weak
    }

    /// The opaque bytes, without the quotes.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::EntityTag;
    ///
    /// assert_eq!(EntityTag::parse(b"W/\"abc\"")?.opaque(), b"abc");
    /// assert_eq!(EntityTag::parse(b"\"\"")?.opaque(), b"");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn opaque(&self) -> &'a [u8] {
        self.opaque
    }

    /// Strong comparison (RFC 9110 section 8.8.3.2): both strong and equal.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::EntityTag;
    ///
    /// let a = EntityTag::strong(b"1")?;
    /// assert!(a.strong_eq(&EntityTag::parse(b"\"1\"")?));
    /// assert!(!a.strong_eq(&EntityTag::weak(b"1")?));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn strong_eq(&self, other: &EntityTag<'_>) -> bool {
        !self.weak && !other.weak && self.opaque == other.opaque
    }

    /// Weak comparison: equal opaque bytes, either may be weak.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::EntityTag;
    ///
    /// let (w, s) = (EntityTag::weak(b"1")?, EntityTag::strong(b"1")?);
    /// assert!(w.weak_eq(&s) && !w.weak_eq(&EntityTag::strong(b"2")?));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn weak_eq(&self, other: &EntityTag<'_>) -> bool {
        self.opaque == other.opaque
    }

    /// Writes `W/"..."` or `"..."`.
    ///
    /// # Errors
    ///
    /// [`WriteError::Full`]; nothing is written when the sink reports its
    /// room.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{EntityTag, SliceSink};
    ///
    /// let mut buf = [0u8; 16];
    /// let mut out = SliceSink::new(&mut buf);
    /// EntityTag::weak(b"v1")?.write_to(&mut out).expect("room");
    /// assert_eq!(out.written(), b"W/\"v1\"");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn write_to(&self, out: &mut impl Sink) -> core::result::Result<(), WriteError> {
        let prefix: &[u8] = if self.weak { b"W/\"" } else { b"\"" };
        reserve(out, prefix.len() + self.opaque.len() + 1)?;
        out.put(prefix)?;
        out.put(self.opaque)?;
        out.put(b"\"")?;
        Ok(())
    }
}

/// Parses one entity tag at the start of `s`; returns it and the bytes used.
fn parse_prefix(s: &[u8]) -> Result<(EntityTag<'_>, usize)> {
    let (weak, start) = match s {
        [b'W', b'/', ..] => (true, 2),
        _ => (false, 0),
    };
    if s.get(start) != Some(&b'"') {
        return err(ErrorKind::InvalidEntityTag, start);
    }
    let body = s.get(start + 1..).unwrap_or(&[]);
    let close = body.iter().position(|&b| !class::is_etagc(b));
    match close {
        Some(i) if body.get(i) == Some(&b'"') => {
            let opaque = body.get(..i).unwrap_or(&[]);
            Ok((EntityTag { weak, opaque }, start + i + 2))
        }
        Some(i) => {
            let b = body.get(i).copied().unwrap_or(0);
            let kind = if crate::scan::is_control(b) {
                crate::scan::control_kind(b)
            } else {
                ErrorKind::InvalidEntityTag
            };
            err(kind, start + 1 + i)
        }
        None => err(ErrorKind::InvalidEntityTag, s.len()),
    }
}

/// An `If-Match` or `If-None-Match` value: `*` or a list of entity tags.
///
/// # Examples
///
/// ```
/// use parse_net::{etag::parse_condition, Condition, Limits};
///
/// assert_eq!(parse_condition(b"*", &Limits::DEFAULT)?, Condition::Any);
/// assert!(matches!(parse_condition(b"\"a\"", &Limits::DEFAULT)?, Condition::Tags(t) if t.len() == 1));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Condition<'a> {
    /// `*`: any current representation.
    Any,
    /// The listed tags.
    Tags(TagList<'a>),
}

/// The tags of a validated condition.
///
/// # Examples
///
/// ```
/// use parse_net::{etag::parse_condition, Condition, Limits};
///
/// let Condition::Tags(tags) = parse_condition(b"\"a\", W/\"b\"", &Limits::DEFAULT)? else { unreachable!() };
/// assert_eq!(tags.iter().filter(|t| t.is_weak()).count(), 1);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TagList<'a> {
    /// The validated value, OWS trimmed.
    text: &'a [u8],
    count: usize,
}

impl<'a> TagList<'a> {
    /// The tags, in order.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{etag::parse_condition, Condition, Limits};
    ///
    /// let Condition::Tags(tags) = parse_condition(b"\"a\", W/\"b\"", &Limits::DEFAULT)? else { unreachable!() };
    /// let opaque: Vec<_> = tags.iter().map(|t| t.opaque()).collect();
    /// assert_eq!(opaque, [&b"a"[..], &b"b"[..]]);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = EntityTag<'a>> + use<'a> {
        TagIter { s: self.text, i: 0 }
    }

    /// The number of tags.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{etag::parse_condition, Condition, Limits};
    ///
    /// let Condition::Tags(tags) = parse_condition(b"\"a\", , \"b\"", &Limits::DEFAULT)? else { unreachable!() };
    /// assert_eq!(tags.len(), 2);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether there are no tags.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{etag::parse_condition, Condition, Limits};
    ///
    /// let Condition::Tags(tags) = parse_condition(b"\"a\"", &Limits::DEFAULT)? else { unreachable!() };
    /// assert!(!tags.is_empty());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// The tags of a validated [`TagList`].
struct TagIter<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Iterator for TagIter<'a> {
    type Item = EntityTag<'a>;

    fn next(&mut self) -> Option<EntityTag<'a>> {
        while matches!(self.s.get(self.i), Some(b' ' | b'\t' | b',')) {
            self.i += 1;
        }
        let (tag, used) = parse_prefix(self.s.get(self.i..)?).ok()?;
        self.i += used;
        Some(tag)
    }
}

/// What a condition value holds after [`walk`].
enum Walked {
    Any,
    Tags(usize),
}

/// Validates `"*" / #entity-tag` in one pass over `v` (OWS already trimmed),
/// calling `f` for every tag. Empty list elements are skipped up to
/// `max_empty_elements`; `*` must stand alone.
fn walk<'a>(v: &'a [u8], limits: &Limits, mut f: impl FnMut(EntityTag<'a>)) -> Result<Walked> {
    let (mut i, mut count, mut empty, mut star) = (0usize, 0usize, 0usize, false);
    loop {
        while matches!(v.get(i), Some(b' ' | b'\t')) {
            i += 1;
        }
        match v.get(i) {
            None => break,
            Some(b',') => {
                empty += 1;
                if empty > usize::from(limits.empty_elements) {
                    return err(ErrorKind::TooManyEmptyElements, i);
                }
                i += 1;
                continue;
            }
            Some(b'*') if !star && count == 0 => {
                star = true;
                i += 1;
            }
            Some(_) if star => return err(ErrorKind::Malformed, i),
            Some(_) => {
                let (tag, used) =
                    parse_prefix(v.get(i..).unwrap_or(&[])).map_err(|e| match e.kind() {
                        ErrorKind::InvalidEntityTag
                            if e.offset() + i >= v.len() && v.get(i) == Some(&b'"') =>
                        {
                            ParseError::new(ErrorKind::UnterminatedQuote, v.len())
                        }
                        _ => e.shifted(i),
                    })?;
                count += 1;
                if count > usize::from(limits.list_members) {
                    return err(ErrorKind::TooManyMembers, i);
                }
                f(tag);
                i += used;
            }
        }
        while matches!(v.get(i), Some(b' ' | b'\t')) {
            i += 1;
        }
        match v.get(i) {
            None => break,
            // The separator after a member is consumed here, so the next
            // pass counts only commas with nothing before them as empty.
            Some(b',') => i += 1,
            Some(&b) if crate::scan::is_control(b) => return err(crate::scan::control_kind(b), i),
            Some(_) if star => return err(ErrorKind::Malformed, i),
            Some(_) => return err(ErrorKind::InvalidEntityTag, i),
        }
    }
    Ok(if star {
        Walked::Any
    } else {
        Walked::Tags(count)
    })
}

/// Parses `"*" / #entity-tag`.
///
/// # Errors
///
/// [`ErrorKind::Malformed`] for `*` mixed with tags; [`ErrorKind::InvalidEntityTag`];
/// the list errors.
///
/// # Examples
///
/// ```
/// use parse_net::{etag::{parse_condition, Condition}, Limits};
///
/// let Condition::Tags(tags) = parse_condition(b"\"a\", , W/\"b\"", &Limits::DEFAULT)? else { unreachable!() };
/// assert_eq!(tags.len(), 2);
/// assert!(matches!(parse_condition(b"*", &Limits::DEFAULT)?, Condition::Any));
/// assert!(parse_condition(b"*, \"a\"", &Limits::DEFAULT).is_err());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_condition<'a>(value: &'a [u8], limits: &Limits) -> Result<Condition<'a>> {
    let lead = skip_ows(value);
    let v = trim_ows(value);
    Ok(
        match walk(v, limits, |_| {}).map_err(|e| e.shifted(lead))? {
            Walked::Any => Condition::Any,
            Walked::Tags(count) => Condition::Tags(TagList { text: v, count }),
        },
    )
}

/// Evaluates `If-None-Match` against the current representation's tag by
/// weak comparison (RFC 9110 section 13.1.2).
///
/// `true` means the condition is false for the request: answer 304 (GET,
/// HEAD) or 412 (other methods). `*` matches any current representation.
///
/// # Errors
///
/// As [`parse_condition`].
///
/// # Examples
///
/// ```
/// use parse_net::{if_none_match, EntityTag};
///
/// assert!(if_none_match(b"W/\"x\"", &EntityTag::strong(b"x")?)?);
/// assert!(!if_none_match(b"\"y\"", &EntityTag::strong(b"x")?)?);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn if_none_match(value: &[u8], current: &EntityTag<'_>) -> Result<bool> {
    // One pass: the whole field is validated, and the comparison runs as each
    // tag is read.
    let lead = skip_ows(value);
    let mut matched = false;
    let walked = walk(trim_ows(value), &Limits::DEFAULT, |t| {
        matched |= t.weak_eq(current)
    })
    .map_err(|e| e.shifted(lead))?;
    Ok(matches!(walked, Walked::Any) || matched)
}

/// Evaluates `If-Match` by strong comparison (RFC 9110 section 13.1.1).
///
/// `true` means the precondition holds; `false` means answer 412. `*` holds
/// when a current representation exists (`current` is `Some`).
///
/// # Errors
///
/// As [`parse_condition`].
///
/// # Examples
///
/// ```
/// use parse_net::{if_match, EntityTag};
///
/// let current = EntityTag::strong(b"x")?;
/// assert!(if_match(b"\"x\"", Some(&current))?);
/// assert!(!if_match(b"W/\"x\"", Some(&current))?);
/// assert!(!if_match(b"\"x\"", None)?);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn if_match(value: &[u8], current: Option<&EntityTag<'_>>) -> Result<bool> {
    let lead = skip_ows(value);
    let mut matched = false;
    let walked = walk(trim_ows(value), &Limits::DEFAULT, |t| {
        matched |= current.is_some_and(|c| t.strong_eq(c));
    })
    .map_err(|e| e.shifted(lead))?;
    Ok(match walked {
        Walked::Any => current.is_some(),
        Walked::Tags(_) => matched,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entity_tag_edge_cases() {
        assert_eq!(EntityTag::parse(b"\"\"").unwrap().opaque(), b"");
        assert!(EntityTag::parse(b"W/\"\"").unwrap().is_weak());
        let k = |v: &[u8]| EntityTag::parse(v).unwrap_err().kind();
        assert_eq!(k(b"w/\"a\""), ErrorKind::InvalidEntityTag);
        assert_eq!(k(b"\"a\"b"), ErrorKind::TrailingData);
        assert_eq!(k(b"\"a"), ErrorKind::InvalidEntityTag);
        assert_eq!(k(b"W/ \"a\""), ErrorKind::InvalidEntityTag);
        assert_eq!(k(b"\"a\x7f\""), ErrorKind::Control);
        assert_eq!(k(b"\"a b\""), ErrorKind::InvalidEntityTag);
        assert_eq!(k(b"abc"), ErrorKind::InvalidEntityTag);
        assert_eq!(k(b""), ErrorKind::InvalidEntityTag);
        assert!(EntityTag::parse(b"\"\x80\xff!\"").is_ok());
        assert!(EntityTag::strong(b"a b").is_err());
        assert!(EntityTag::weak(b"\"").is_err());
    }

    #[test]
    fn test_comparison_table_rfc_9110() {
        // RFC 9110 section 8.8.3.2.
        let w1 = EntityTag::weak(b"1").unwrap();
        let w2 = EntityTag::weak(b"2").unwrap();
        let s1 = EntityTag::strong(b"1").unwrap();
        assert!(!w1.strong_eq(&w1) && w1.weak_eq(&w1));
        assert!(!w1.strong_eq(&w2) && !w1.weak_eq(&w2));
        assert!(!w1.strong_eq(&s1) && w1.weak_eq(&s1));
        assert!(s1.strong_eq(&s1) && s1.weak_eq(&s1));
    }

    #[test]
    fn test_conditions() {
        let l = Limits::DEFAULT;
        assert_eq!(
            parse_condition(b"*, \"a\"", &l).unwrap_err().kind(),
            ErrorKind::Malformed
        );
        assert_eq!(
            parse_condition(b"\"a\" \"b\"", &l).unwrap_err().kind(),
            ErrorKind::InvalidEntityTag
        );
        let e = parse_condition(b"\"a\", w/\"b\"", &l).unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::InvalidEntityTag, 5));
        let s = EntityTag::strong(b"b").unwrap();
        assert!(if_none_match(b"\"a\", , \"b\"", &s).unwrap());
        assert!(if_none_match(b"*", &s).unwrap());
        assert!(!if_match(b"*", None).unwrap());
        assert!(if_match(b"\"a\", \"b\"", Some(&s)).unwrap());
        assert!(if_none_match(b"\"a", &s).is_err());
    }

    #[test]
    fn test_condition_separators_are_not_empty_elements() {
        // 0.6.0 counted the separator after each tag as an empty element, so
        // a list of more than 16 tags was refused.
        let l = Limits::DEFAULT;
        let tags = |n: usize| {
            (0..n)
                .map(|i| std::format!("W/\"t{i}\""))
                .collect::<std::vec::Vec<_>>()
                .join(", ")
        };
        let count = |v: &str| match parse_condition(v.as_bytes(), &l) {
            Ok(Condition::Tags(t)) => Ok(t.len()),
            Ok(Condition::Any) => Ok(usize::MAX),
            Err(e) => Err(e.kind()),
        };
        for n in [1, 16, 17, 100, 1024] {
            assert_eq!(count(&tags(n)), Ok(n), "{n}");
        }
        assert_eq!(count(&tags(1025)), Err(ErrorKind::TooManyMembers));
        let s = EntityTag::strong(b"t1023").unwrap();
        assert!(if_none_match(tags(1024).as_bytes(), &s).unwrap());
        assert!(if_match(tags(1024).replace("W/", "").as_bytes(), Some(&s)).unwrap());
        // Empty elements are still counted, before, between, and after.
        let empties = |n: usize| std::format!("\"a\",{}\"b\"", ", ".repeat(n));
        assert_eq!(count(&empties(16)), Ok(2));
        assert_eq!(count(&empties(17)), Err(ErrorKind::TooManyEmptyElements));
        assert_eq!(count(&std::format!("{}\"a\"", ",".repeat(16))), Ok(1));
        // After a tag the first comma is its separator; 16 more are empty.
        assert_eq!(count(&std::format!("\"a\"{}", ",".repeat(17))), Ok(1));
        assert_eq!(
            count(&std::format!("\"a\"{}", ",".repeat(18))),
            Err(ErrorKind::TooManyEmptyElements)
        );
        assert_eq!(count("\"a\",,\"b\","), Ok(2));
    }

    #[test]
    fn test_write_round_trip() {
        let mut buf = [0u8; 8];
        let mut out = crate::SliceSink::new(&mut buf);
        let t = EntityTag::strong(b"xyz").unwrap();
        t.write_to(&mut out).unwrap();
        assert_eq!(EntityTag::parse(out.written()).unwrap(), t);
        let mut small = [0u8; 3];
        let mut out = crate::SliceSink::new(&mut small);
        assert_eq!(t.write_to(&mut out), Err(WriteError::Full));
    }
}
