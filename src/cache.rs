//! `Cache-Control` (RFC 9111 section 5.2, with `immutable` from RFC 8246 and
//! `stale-while-revalidate` and `stale-if-error` from RFC 5861).
//!
//! # Examples
//!
//! ```
//! use parse_net::{self as pn, cache::Writer};
//!
//! let cc = pn::response_cache_control(b"public, max-age=\"60\", MAX-AGE=5, x-ext=1")?;
//! assert_eq!((cc.public, cc.max_age, cc.duplicates, cc.unknown), (true, Some(60), true, 1));
//!
//! let mut buf = [0u8; 64];
//! let mut out = pn::SliceSink::new(&mut buf);
//! Writer::new(&mut out).flag("public").and_then(|w| w.seconds("max-age", 60)).expect("room");
//! assert_eq!(out.written(), b"public, max-age=60");
//! # Ok::<(), pn::ParseError>(())
//! ```

use crate::{
    class,
    error::{ErrorKind, ParseError, Result, WriteError},
    limits::Limits,
    num::parse_u32_saturating,
    scan::control_kind,
    text::{Word, is_token, parse_word, skip_ows, trim_ows},
    write::{Sink, reserve, write_decimal_u64},
};

/// One directive: a name and an optional argument.
///
/// # Examples
///
/// ```
/// use parse_net::{cache, Limits};
///
/// let d = cache::parse(b"max-age=60", &Limits::DEFAULT)?.iter().next().expect("one directive");
/// assert_eq!(d.name, b"max-age");
/// assert!(d.value.is_some_and(|v| v.eq_bytes(b"60")));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Directive<'a> {
    /// The name as sent (compare it ASCII case-insensitively).
    pub name: &'a [u8],
    /// The argument, token or quoted.
    pub value: Option<Word<'a>>,
}

/// Skips SP and HTAB.
#[inline]
fn skip_ws(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    s
}

/// One directive at the front of `s`: `token [ "=" ( token / quoted-string ) ]`.
/// Returns it and what follows; error offsets are relative to `s`.
fn directive(s: &[u8]) -> Result<(Directive<'_>, &[u8])> {
    let n = s
        .iter()
        .position(|&b| !class::is_tchar(b))
        .unwrap_or(s.len());
    if n == 0 {
        return Err(bad(s, 0));
    }
    let (name, after) = s.split_at(n);
    let [b'=', value @ ..] = after else {
        return Ok((Directive { name, value: None }, after));
    };
    let (w, used) = parse_word(value).map_err(|x| match x.kind() {
        ErrorKind::Empty => bad(s, n + 1),
        _ => x.shifted(n + 1),
    })?;
    Ok((
        Directive {
            name,
            value: Some(w),
        },
        value.get(used..).unwrap_or(&[]),
    ))
}

/// Validates a `Cache-Control` value in one pass over `v` (OWS already
/// trimmed), calling `f` for each directive; returns the count. Empty list
/// elements are skipped up to `max_empty_elements`. The cursor is a
/// shrinking slice; offsets are computed only for an error.
fn walk<'a>(v: &'a [u8], limits: &Limits, mut f: impl FnMut(Directive<'a>)) -> Result<usize> {
    let at = |rest: &[u8]| v.len() - rest.len();
    let (mut rest, mut count, mut empty) = (v, 0usize, 0usize);
    loop {
        rest = skip_ws(rest);
        match rest {
            [] => return Ok(count),
            [b',', tail @ ..] => {
                empty += 1;
                if empty > usize::from(limits.empty_elements) {
                    return Err(ParseError::new(ErrorKind::TooManyEmptyElements, at(rest)));
                }
                rest = tail;
                continue;
            }
            _ => {}
        }
        let (d, tail) = directive(rest).map_err(|e| e.shifted(at(rest)))?;
        count += 1;
        if count > usize::from(limits.list_members) {
            return Err(ParseError::new(ErrorKind::TooManyMembers, at(rest)));
        }
        f(d);
        rest = skip_ws(tail);
        match rest {
            [] => return Ok(count),
            [b',', tail @ ..] => rest = tail,
            _ => return Err(bad(rest, 0).shifted(at(rest))),
        }
    }
}

/// Runs [`walk`] over a whole field value, offsets relative to it.
fn walk_value<'a>(
    value: &'a [u8],
    limits: &Limits,
    f: impl FnMut(Directive<'a>),
) -> Result<(&'a [u8], usize)> {
    let lead = skip_ows(value);
    let v = trim_ows(value);
    let count = walk(v, limits, f).map_err(|e| e.shifted(lead))?;
    Ok((v, count))
}

fn bad(e: &[u8], at: usize) -> ParseError {
    match e.get(at) {
        Some(&b) if crate::scan::is_control(b) => ParseError::new(control_kind(b), at),
        _ => ParseError::new(ErrorKind::NotToken, at),
    }
}

/// Validated directives.
///
/// # Examples
///
/// ```
/// use parse_net::{cache, Limits};
///
/// let d = cache::parse(b"no-store, max-age=0", &Limits::DEFAULT)?;
/// assert_eq!(d.len(), 2);
/// assert!(d.iter().any(|x| x.name.eq_ignore_ascii_case(b"NO-STORE")));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Directives<'a> {
    /// The validated value, OWS trimmed.
    text: &'a [u8],
    count: usize,
}

impl<'a> Directives<'a> {
    /// The directives, in order.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{cache, Limits};
    ///
    /// let d = cache::parse(b"public, max-age=60", &Limits::DEFAULT)?;
    /// let has_value: Vec<bool> = d.iter().map(|x| x.value.is_some()).collect();
    /// assert_eq!(has_value, [false, true]);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = Directive<'a>> + use<'a> {
        DirectiveIter { s: self.text }
    }

    /// The number of directives.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{cache, Limits};
    ///
    /// assert_eq!(cache::parse(b"no-cache, no-store, x-ext=1", &Limits::DEFAULT)?.len(), 3);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether there are no directives.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{cache, Limits};
    ///
    /// assert!(cache::parse(b"", &Limits::DEFAULT)?.is_empty());
    /// assert!(!cache::parse(b"no-store", &Limits::DEFAULT)?.is_empty());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// The directives of a validated [`Directives`].
struct DirectiveIter<'a> {
    s: &'a [u8],
}

impl<'a> Iterator for DirectiveIter<'a> {
    type Item = Directive<'a>;

    fn next(&mut self) -> Option<Directive<'a>> {
        let mut rest = self.s;
        while let [b' ' | b'\t' | b',', tail @ ..] = rest {
            rest = tail;
        }
        let (d, tail) = directive(rest).ok()?;
        self.s = tail;
        Some(d)
    }
}

/// Parses `#( token [ "=" ( token / quoted-string ) ] )`, keeping every
/// directive raw.
///
/// # Errors
///
/// The list errors; [`ErrorKind::NotToken`] for a malformed directive; the
/// quoted-string errors.
///
/// # Examples
///
/// ```
/// use parse_net::{cache, Limits};
///
/// let d = cache::parse(b"no-cache=\"Set-Cookie\", x-y", &Limits::DEFAULT)?;
/// let names: Vec<&[u8]> = d.iter().map(|x| x.name).collect();
/// assert_eq!(names, [&b"no-cache"[..], b"x-y"]);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse<'a>(value: &'a [u8], limits: &Limits) -> Result<Directives<'a>> {
    let (text, count) = walk_value(value, limits, |_| {})?;
    Ok(Directives { text, count })
}

/// The response directives (RFC 9111 section 5.2.2 and the extensions).
///
/// Unknown directives are counted in `unknown` and available raw through
/// [`parse`]. A directive given twice keeps its first value and sets
/// `duplicates` (RFC 9111 section 4.2.1); an argument that does not fit
/// (`max-age=60s`) leaves the field `None` and sets `invalid_values`: treat
/// such a response as stale. Conflicting directives (`private, public`) are
/// both reported.
///
/// # Examples
///
/// ```
/// let cc = parse_net::response_cache_control(b"max-age=60, s-maxage=60s, immutable")?;
/// assert_eq!(cc.max_age, Some(60));
/// assert!(cc.immutable);
/// assert!(cc.s_maxage.is_none() && cc.invalid_values);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ResponseDirectives {
    /// `max-age`, saturating at 2147483648.
    pub max_age: Option<u32>,
    /// `s-maxage`.
    pub s_maxage: Option<u32>,
    /// `no-cache` (with or without a field list).
    pub no_cache: bool,
    /// `no-store`.
    pub no_store: bool,
    /// `private` (with or without a field list).
    pub private: bool,
    /// `public`.
    pub public: bool,
    /// `must-revalidate`.
    pub must_revalidate: bool,
    /// `proxy-revalidate`.
    pub proxy_revalidate: bool,
    /// `must-understand`.
    pub must_understand: bool,
    /// `no-transform`.
    pub no_transform: bool,
    /// `immutable` (RFC 8246).
    pub immutable: bool,
    /// `stale-while-revalidate` (RFC 5861).
    pub stale_while_revalidate: Option<u32>,
    /// `stale-if-error` (RFC 5861).
    pub stale_if_error: Option<u32>,
    /// A known directive appeared more than once.
    pub duplicates: bool,
    /// A known directive had an argument that does not fit its grammar.
    pub invalid_values: bool,
    /// The number of extension directives (saturating).
    pub unknown: u16,
}

/// The request directives (RFC 9111 section 5.2.1).
///
/// # Examples
///
/// ```
/// let req = parse_net::request_cache_control(b"no-store, min-fresh=30, max-age=1, max-age=2")?;
/// assert!(req.no_store);
/// assert_eq!((req.min_fresh, req.max_age, req.duplicates), (Some(30), Some(1), true));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RequestDirectives {
    /// `max-age`.
    pub max_age: Option<u32>,
    /// `max-stale`: `Some(None)` without a value (any staleness).
    pub max_stale: Option<Option<u32>>,
    /// `min-fresh`.
    pub min_fresh: Option<u32>,
    /// `no-cache`.
    pub no_cache: bool,
    /// `no-store`.
    pub no_store: bool,
    /// `no-transform`.
    pub no_transform: bool,
    /// `only-if-cached`.
    pub only_if_cached: bool,
    /// `stale-if-error` (RFC 5861).
    pub stale_if_error: Option<u32>,
    /// A known directive appeared more than once.
    pub duplicates: bool,
    /// A known directive had an argument that does not fit its grammar.
    pub invalid_values: bool,
    /// The number of extension directives (saturating).
    pub unknown: u16,
}

/// Reads a `delta-seconds` argument, token or quoted (RFC 9111 section 5.2:
/// recipients accept both forms).
fn seconds(value: Option<Word<'_>>, invalid: &mut bool) -> Option<u32> {
    // Senders must not quote delta-seconds (RFC 9111 section 5.2), but
    // recipients read both forms; a quoted pair is read through the
    // unescaping iterator, so no buffer is needed.
    let n = match value {
        Some(Word::Token(t)) => parse_u32_saturating(t).ok(),
        Some(Word::Quoted(q)) => match q.as_plain() {
            Some(p) => parse_u32_saturating(p).ok(),
            None => {
                let mut n: Option<u32> = None;
                for b in q.bytes() {
                    if !b.is_ascii_digit() {
                        n = None;
                        break;
                    }
                    n = Some(
                        n.unwrap_or(0)
                            .saturating_mul(10)
                            .saturating_add(u32::from(b - b'0'))
                            .min(crate::num::DELTA_SECONDS_MAX),
                    );
                }
                n
            }
        },
        None => None,
    };
    if n.is_none() {
        *invalid = true;
    }
    n
}

/// A flag directive: no argument expected; one (other than a field list for
/// `no-cache` and `private`) marks the value invalid.
fn flag(
    slot: &mut bool,
    seen: &mut bool,
    dup: &mut bool,
    value: Option<Word<'_>>,
    invalid: &mut bool,
    list_ok: bool,
) {
    if *seen {
        *dup = true;
        return;
    }
    *seen = true;
    *slot = true;
    if value.is_some() && !list_ok {
        *invalid = true;
    }
}

/// The first value of a numeric directive; a repeat sets `dup`.
fn number(
    slot: &mut Option<u32>,
    seen: &mut bool,
    dup: &mut bool,
    value: Option<Word<'_>>,
    invalid: &mut bool,
) {
    if *seen {
        *dup = true;
        return;
    }
    *seen = true;
    *slot = seconds(value, invalid);
}

/// Whether the token `n` equals `lower`, a lowercase name of letters and
/// `-`, ignoring ASCII case. Among token bytes, `b | 0x20` maps exactly `A-Z`
/// onto `a-z` and leaves `-` alone (the only other byte it maps onto `-` is
/// CR, which is not a token byte), so one OR per byte suffices.
fn is_name(n: &[u8], lower: &[u8]) -> bool {
    n.len() == lower.len() && n.iter().zip(lower).all(|(&b, &p)| b | 0x20 == p)
}

/// The index of a response directive name, dispatched on length first.
fn response_slot(n: &[u8]) -> Option<usize> {
    let is = |s: &[u8]| is_name(n, s);
    match n.len() {
        6 if is(b"public") => Some(5),
        7 if is(b"max-age") => Some(0),
        7 if is(b"private") => Some(4),
        8 if is(b"s-maxage") => Some(1),
        8 if is(b"no-cache") => Some(2),
        8 if is(b"no-store") => Some(3),
        9 if is(b"immutable") => Some(10),
        12 if is(b"no-transform") => Some(9),
        14 if is(b"stale-if-error") => Some(12),
        15 if is(b"must-revalidate") => Some(6),
        15 if is(b"must-understand") => Some(8),
        16 if is(b"proxy-revalidate") => Some(7),
        22 if is(b"stale-while-revalidate") => Some(11),
        _ => None,
    }
}

/// Builds [`ResponseDirectives`] one directive at a time.
#[derive(Default)]
struct ResponseBuilder {
    r: ResponseDirectives,
    seen: [bool; 13],
}

impl ResponseBuilder {
    fn push(&mut self, d: Directive<'_>) {
        let r = &mut self.r;
        let Some(slot) = response_slot(d.name) else {
            r.unknown = r.unknown.saturating_add(1);
            return;
        };
        let Some(seen) = self.seen.get_mut(slot) else {
            return;
        };
        let (dup, inv) = (&mut r.duplicates, &mut r.invalid_values);
        match slot {
            0 => number(&mut r.max_age, seen, dup, d.value, inv),
            1 => number(&mut r.s_maxage, seen, dup, d.value, inv),
            2 => flag(&mut r.no_cache, seen, dup, d.value, inv, true),
            3 => flag(&mut r.no_store, seen, dup, d.value, inv, false),
            4 => flag(&mut r.private, seen, dup, d.value, inv, true),
            5 => flag(&mut r.public, seen, dup, d.value, inv, false),
            6 => flag(&mut r.must_revalidate, seen, dup, d.value, inv, false),
            7 => flag(&mut r.proxy_revalidate, seen, dup, d.value, inv, false),
            8 => flag(&mut r.must_understand, seen, dup, d.value, inv, false),
            9 => flag(&mut r.no_transform, seen, dup, d.value, inv, false),
            10 => flag(&mut r.immutable, seen, dup, d.value, inv, false),
            11 => number(&mut r.stale_while_revalidate, seen, dup, d.value, inv),
            _ => number(&mut r.stale_if_error, seen, dup, d.value, inv),
        }
    }
}

/// The index of a request directive name, dispatched on length first.
fn request_slot(n: &[u8]) -> Option<usize> {
    let is = |s: &[u8]| is_name(n, s);
    match n.len() {
        7 if is(b"max-age") => Some(0),
        8 if is(b"no-cache") => Some(3),
        8 if is(b"no-store") => Some(4),
        9 if is(b"max-stale") => Some(1),
        9 if is(b"min-fresh") => Some(2),
        12 if is(b"no-transform") => Some(5),
        14 if is(b"only-if-cached") => Some(6),
        14 if is(b"stale-if-error") => Some(7),
        _ => None,
    }
}

/// Builds [`RequestDirectives`] one directive at a time.
#[derive(Default)]
struct RequestBuilder {
    r: RequestDirectives,
    seen: [bool; 8],
}

impl RequestBuilder {
    fn push(&mut self, d: Directive<'_>) {
        let r = &mut self.r;
        let Some(slot) = request_slot(d.name) else {
            r.unknown = r.unknown.saturating_add(1);
            return;
        };
        let Some(seen) = self.seen.get_mut(slot) else {
            return;
        };
        let (dup, inv) = (&mut r.duplicates, &mut r.invalid_values);
        match slot {
            0 => number(&mut r.max_age, seen, dup, d.value, inv),
            1 => {
                if *seen {
                    *dup = true;
                } else {
                    *seen = true;
                    r.max_stale = Some(match d.value {
                        None => None,
                        v => seconds(v, inv),
                    });
                }
            }
            2 => number(&mut r.min_fresh, seen, dup, d.value, inv),
            3 => flag(&mut r.no_cache, seen, dup, d.value, inv, false),
            4 => flag(&mut r.no_store, seen, dup, d.value, inv, false),
            5 => flag(&mut r.no_transform, seen, dup, d.value, inv, false),
            6 => flag(&mut r.only_if_cached, seen, dup, d.value, inv, false),
            _ => number(&mut r.stale_if_error, seen, dup, d.value, inv),
        }
    }
}

/// Reads a response `Cache-Control` value.
///
/// # Errors
///
/// As [`parse`]: only structural errors; unknown directives and bad
/// arguments are reported in the struct.
///
/// # Examples
///
/// ```
/// let cc = parse_net::response_cache_control(b"max-age=99999999999999999999, private, public")?;
/// assert_eq!(cc.max_age, Some(2_147_483_648));
/// assert!(cc.private && cc.public);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn response_cache_control(value: &[u8]) -> Result<ResponseDirectives> {
    let mut b = ResponseBuilder::default();
    let _ = walk_value(value, &Limits::DEFAULT, |d| b.push(d))?;
    Ok(b.r)
}

/// Reads a request `Cache-Control` value.
///
/// # Errors
///
/// As [`parse`].
///
/// # Examples
///
/// ```
/// let req = parse_net::request_cache_control(b"max-stale, no-cache")?;
/// assert_eq!(req.max_stale, Some(None));
/// assert!(req.no_cache);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn request_cache_control(value: &[u8]) -> Result<RequestDirectives> {
    let mut b = RequestBuilder::default();
    let _ = walk_value(value, &Limits::DEFAULT, |d| b.push(d))?;
    Ok(b.r)
}

/// Reads several response `Cache-Control` field lines as one.
///
/// # Errors
///
/// As [`parse`], with [`ParseError::line`] set.
///
/// # Examples
///
/// ```
/// use parse_net::cache;
///
/// let lines: [&[u8]; 2] = [b"public", b"max-age=300"];
/// let cc = cache::response_lines(lines)?;
/// assert!(cc.public);
/// assert_eq!(cc.max_age, Some(300));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn response_lines<'a, I>(lines: I) -> Result<ResponseDirectives>
where
    I: IntoIterator<Item = &'a [u8]>,
    I::IntoIter: Clone,
{
    let mut b = ResponseBuilder::default();
    for (n, line) in lines.into_iter().enumerate() {
        let _ = walk_value(line, &Limits::DEFAULT, |d| b.push(d)).map_err(|e| e.on_line(n))?;
    }
    Ok(b.r)
}

/// Reads several request `Cache-Control` field lines as one.
///
/// # Errors
///
/// As [`parse`], with [`ParseError::line`] set.
///
/// # Examples
///
/// ```
/// use parse_net::cache;
///
/// let lines: [&[u8]; 2] = [b"no-cache", b"max-stale=60"];
/// let req = cache::request_lines(lines)?;
/// assert!(req.no_cache);
/// assert_eq!(req.max_stale, Some(Some(60)));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn request_lines<'a, I>(lines: I) -> Result<RequestDirectives>
where
    I: IntoIterator<Item = &'a [u8]>,
    I::IntoIter: Clone,
{
    let mut b = RequestBuilder::default();
    for (n, line) in lines.into_iter().enumerate() {
        let _ = walk_value(line, &Limits::DEFAULT, |d| b.push(d)).map_err(|e| e.on_line(n))?;
    }
    Ok(b.r)
}

/// Writes `Cache-Control` directives, separated by `, `.
///
/// Delta-seconds are always written as tokens (senders must not quote
/// them); field lists are always quoted.
///
/// # Examples
///
/// ```
/// use parse_net::{cache::Writer, SliceSink};
///
/// let mut buf = [0u8; 64];
/// let mut out = SliceSink::new(&mut buf);
/// Writer::new(&mut out).flag("no-store")?.seconds("max-age", 0)?;
/// assert_eq!(out.written(), b"no-store, max-age=0");
/// # Ok::<(), parse_net::WriteError>(())
/// ```
pub struct Writer<'s, S: Sink> {
    out: &'s mut S,
    first: bool,
}

impl<'s, S: Sink> Writer<'s, S> {
    /// A writer over `out`.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{cache::Writer, SliceSink};
    ///
    /// let mut buf = [0u8; 16];
    /// let mut out = SliceSink::new(&mut buf);
    /// let mut w = Writer::new(&mut out);
    /// w.flag("public")?;
    /// assert_eq!(out.written(), b"public");
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn new(out: &'s mut S) -> Self {
        Self { out, first: true }
    }

    fn separator(&self) -> &'static [u8] {
        if self.first { b"" } else { b", " }
    }

    /// Writes a directive with no argument (`no-store`).
    ///
    /// # Errors
    ///
    /// [`WriteError::NotToken`]; [`WriteError::Full`] (nothing written for
    /// this directive when the sink reports its room).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{cache::Writer, SliceSink, WriteError};
    ///
    /// let mut buf = [0u8; 64];
    /// let mut out = SliceSink::new(&mut buf);
    /// Writer::new(&mut out).flag("no-store")?.flag("no-transform")?;
    /// assert_eq!(out.written(), b"no-store, no-transform");
    /// assert!(matches!(Writer::new(&mut out).flag("no store"), Err(WriteError::NotToken)));
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn flag(&mut self, name: &str) -> core::result::Result<&mut Self, WriteError> {
        if !is_token(name.as_bytes()) {
            return Err(WriteError::NotToken);
        }
        let sep = self.separator();
        reserve(self.out, sep.len() + name.len())?;
        self.out.put(sep)?;
        self.out.put(name.as_bytes())?;
        self.first = false;
        Ok(self)
    }

    /// Writes `name=secs` (`max-age=60`).
    ///
    /// # Errors
    ///
    /// As [`flag`](Self::flag).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{cache::Writer, SliceSink};
    ///
    /// let mut buf = [0u8; 64];
    /// let mut out = SliceSink::new(&mut buf);
    /// Writer::new(&mut out).seconds("max-age", 3600)?.seconds("stale-while-revalidate", 30)?;
    /// assert_eq!(out.written(), b"max-age=3600, stale-while-revalidate=30");
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn seconds(
        &mut self,
        name: &str,
        secs: u32,
    ) -> core::result::Result<&mut Self, WriteError> {
        if !is_token(name.as_bytes()) {
            return Err(WriteError::NotToken);
        }
        let mut digits = crate::write::CountSink::new();
        write_decimal_u64(u64::from(secs), &mut digits)?;
        let sep = self.separator();
        reserve(self.out, sep.len() + name.len() + 1 + digits.count())?;
        self.out.put(sep)?;
        self.out.put(name.as_bytes())?;
        self.out.put(b"=")?;
        write_decimal_u64(u64::from(secs), self.out)?;
        self.first = false;
        Ok(self)
    }

    /// Writes `name="field, field"` (`no-cache="Set-Cookie"`).
    ///
    /// # Errors
    ///
    /// [`WriteError::NotToken`] for the name or a field name, and as
    /// [`flag`](Self::flag).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{cache::Writer, SliceSink};
    ///
    /// let mut buf = [0u8; 64];
    /// let mut out = SliceSink::new(&mut buf);
    /// Writer::new(&mut out).fields("no-cache", &["Set-Cookie", "Authorization"]).expect("room");
    /// assert_eq!(out.written(), b"no-cache=\"Set-Cookie, Authorization\"");
    /// ```
    pub fn fields(
        &mut self,
        name: &str,
        fields: &[&str],
    ) -> core::result::Result<&mut Self, WriteError> {
        if !is_token(name.as_bytes()) || fields.iter().any(|f| !is_token(f.as_bytes())) {
            return Err(WriteError::NotToken);
        }
        let sep = self.separator();
        let list_len: usize =
            fields.iter().map(|f| f.len()).sum::<usize>() + fields.len().saturating_sub(1) * 2;
        reserve(self.out, sep.len() + name.len() + 3 + list_len)?;
        self.out.put(sep)?;
        self.out.put(name.as_bytes())?;
        self.out.put(b"=\"")?;
        for (i, f) in fields.iter().enumerate() {
            if i > 0 {
                self.out.put(b", ")?;
            }
            self.out.put(f.as_bytes())?;
        }
        self.out.put(b"\"")?;
        self.first = false;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_directives_cases() {
        let r = |v: &[u8]| response_cache_control(v).unwrap();
        assert_eq!(r(b"max-age=0").max_age, Some(0));
        assert_eq!(r(b"max-age=\"60\"").max_age, Some(60));
        let bad = r(b"max-age=60s");
        assert_eq!((bad.max_age, bad.invalid_values), (None, true));
        assert_eq!(
            r(b"max-age=99999999999999999999").max_age,
            Some(2_147_483_648)
        );
        let dup = r(b"max-age=1, max-age=2");
        assert_eq!((dup.max_age, dup.duplicates), (Some(1), true));
        let nc = r(b"no-cache=\"Set-Cookie\"");
        assert!(nc.no_cache && !nc.invalid_values);
        let both = r(b"private, public");
        assert!(both.private && both.public);
        assert_eq!(r(b"x-unknown, y=1").unknown, 2);
        assert!(r(b"no-store, , NO-TRANSFORM, immutable").no_transform);
        assert_eq!(
            r(b"stale-while-revalidate=30, stale-if-error=60").stale_if_error,
            Some(60)
        );
        assert!(r(b"no-store=1").invalid_values);
        assert!(r(b"max-age").invalid_values);
        assert_eq!(r(b"").unknown, 0);
    }

    #[test]
    fn test_request_directives_cases() {
        let q = |v: &[u8]| request_cache_control(v).unwrap();
        assert_eq!(q(b"max-stale").max_stale, Some(None));
        assert_eq!(q(b"max-stale=10").max_stale, Some(Some(10)));
        assert!(q(b"only-if-cached").only_if_cached);
        assert_eq!(q(b"min-fresh=5, min-fresh=6").min_fresh, Some(5));
        assert!(q(b"min-fresh=5, min-fresh=6").duplicates);
    }

    #[test]
    fn test_cache_structure_errors() {
        let k = |v: &[u8]| response_cache_control(v).unwrap_err().kind();
        assert_eq!(k(b"max-age = 5"), ErrorKind::NotToken);
        assert_eq!(k(b"max-age=\"5"), ErrorKind::UnterminatedQuote);
        assert_eq!(k(b"=5"), ErrorKind::NotToken);
        assert_eq!(k(b"a=b c"), ErrorKind::NotToken);
        assert_eq!(k(b"a=\x01"), ErrorKind::Control);
    }

    #[test]
    fn test_lines() {
        let lines: [&[u8]; 2] = [b"public", b"max-age=5"];
        let r = response_lines(lines).unwrap();
        assert!(r.public && r.max_age == Some(5));
        let bad: [&[u8]; 2] = [b"public", b"max-age=\"5"];
        assert_eq!(response_lines(bad).unwrap_err().line(), 1);
        let req: [&[u8]; 2] = [b"no-cache", b"max-stale"];
        assert_eq!(request_lines(req).unwrap().max_stale, Some(None));
    }

    #[test]
    fn test_writer_round_trip_and_refusals() {
        let mut buf = [0u8; 128];
        let mut out = crate::SliceSink::new(&mut buf);
        Writer::new(&mut out)
            .flag("public")
            .and_then(|w| w.seconds("max-age", u32::MAX))
            .and_then(|w| w.fields("private", &["X-A"]))
            .map(|_| ())
            .unwrap();
        let r = response_cache_control(out.written()).unwrap();
        assert!(r.public && r.private);
        assert_eq!(r.max_age, Some(2_147_483_648));
        let mut w = Writer::new(&mut out);
        assert!(matches!(w.flag("a b"), Err(WriteError::NotToken)));
        assert!(matches!(
            w.fields("no-cache", &["a b"]),
            Err(WriteError::NotToken)
        ));
        let mut small = [0u8; 3];
        let mut out = crate::SliceSink::new(&mut small);
        assert!(matches!(
            Writer::new(&mut out).flag("public"),
            Err(WriteError::Full)
        ));
        assert!(out.is_empty());
    }
}
