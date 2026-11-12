//! `Cache-Control` (RFC 9111 section 5.2, with `immutable` from RFC 8246 and
//! `stale-while-revalidate` and `stale-if-error` from RFC 5861).
//!
//! # Examples
//!
//! ```
//! use parse_net::{self as pn, cache::Writer};
//!
//! let cc = pn::parse_response_cache_control(b"public, max-age=\"60\", MAX-AGE=5, x-ext=1")?;
//! assert_eq!((cc.public, cc.max_age, cc.duplicates, cc.unknown), (true, Some(60), true, 1));
//!
//! let mut buf = [0u8; 64];
//! let mut out = pn::SliceSink::new(&mut buf);
//! Writer::new(&mut out).flag("public").and_then(|w| w.seconds("max-age", 60)).expect("room");
//! assert_eq!(out.written(), b"public, max-age=60");
//! # Ok::<(), pn::ParseError>(())
//! ```

use crate::{
    error::{ErrorKind, ParseError, Result, WriteError},
    limits::Limits,
    num::parse_u32_saturating,
    scan::control_kind,
    text::{Word, is_token, parse_word, skip_ows, token_len, trim_ows},
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
    let n = token_len(s);
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

/// How much of the list limits a field has used, over all of its lines.
#[derive(Default)]
struct Budget {
    count: usize,
    empty: usize,
}

/// What a walk does with each directive.
trait Visit<'a> {
    /// Whether a member that does not parse is skipped (and reported to
    /// [`skipped`](Self::skipped)) instead of refusing the field.
    const LENIENT: bool;
    fn directive(&mut self, d: Directive<'a>);
    fn skipped(&mut self) {}
}

/// The validating walk of [`parse`]: nothing to record, nothing skipped.
struct Validate;

impl Visit<'_> for Validate {
    const LENIENT: bool = false;
    fn directive(&mut self, _: Directive<'_>) {}
}

/// Validates a `Cache-Control` value in one pass over `v` (OWS already
/// trimmed), handing each directive to `visit` and adding to `budget`. Empty
/// list elements are skipped up to `max_empty_elements`. The cursor is a
/// shrinking slice; offsets are computed only for an error.
///
/// When the visitor is lenient, a member that does not parse is skipped up
/// to the next comma outside a quoted string, so one bad extension cannot
/// hide a `no-store` beside it. Control bytes and the list limits stay
/// errors either way.
fn walk<'a, V: Visit<'a>>(
    v: &'a [u8],
    limits: &Limits,
    budget: &mut Budget,
    visit: &mut V,
) -> Result<()> {
    let at = |rest: &[u8]| v.len() - rest.len();
    let mut rest = v;
    let mut after_comma = false;
    loop {
        rest = skip_ws(rest);
        match rest {
            [] if !after_comma => return Ok(()),
            [] | [b',', ..] => {
                budget.empty += 1;
                if budget.empty > usize::from(limits.empty_elements) {
                    return Err(ParseError::new(ErrorKind::TooManyEmptyElements, at(rest)));
                }
                let [_, tail @ ..] = rest else {
                    return Ok(());
                };
                rest = tail;
                after_comma = true;
                continue;
            }
            _ => {}
        }
        let member = rest;
        let tail = match directive(member) {
            Ok((d, tail)) => match skip_ws(tail) {
                tail @ ([] | [b',', ..]) => {
                    budget.count += 1;
                    if budget.count > usize::from(limits.list_members) {
                        return Err(ParseError::new(ErrorKind::TooManyMembers, at(member)));
                    }
                    visit.directive(d);
                    tail
                }
                tail => {
                    let e = bad(tail, 0).shifted(at(tail));
                    skip_bad(e, member, at(member), limits, budget, visit)?
                }
            },
            Err(e) => skip_bad(
                e.shifted(at(member)),
                member,
                at(member),
                limits,
                budget,
                visit,
            )?,
        };
        let [_, next @ ..] = tail else {
            return Ok(());
        };
        rest = next;
        after_comma = true;
    }
}

/// A member that did not parse, with `e` its error relative to the value:
/// refused, or for a lenient visitor skipped up to the next comma outside a
/// quoted string, which is returned.
#[cold]
#[inline(never)]
fn skip_bad<'a, V: Visit<'a>>(
    e: ParseError,
    member: &'a [u8],
    at: usize,
    limits: &Limits,
    budget: &mut Budget,
    visit: &mut V,
) -> Result<&'a [u8]> {
    if !V::LENIENT || is_control_error(e.kind()) {
        return Err(e);
    }
    let tail = skip_member(member).map_err(|x| x.shifted(at))?;
    budget.count += 1;
    if budget.count > usize::from(limits.list_members) {
        return Err(ParseError::new(ErrorKind::TooManyMembers, at));
    }
    visit.skipped();
    Ok(tail)
}

/// Whether `kind` names a control byte, which no field value holds.
const fn is_control_error(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::BareCr | ErrorKind::LineFeed | ErrorKind::Nul | ErrorKind::Control
    )
}

/// The rest of `s` from the first comma outside a quoted string (empty when
/// there is none; an unclosed quote runs to the end). Control bytes are
/// refused; offsets are relative to `s`.
fn skip_member(s: &[u8]) -> Result<&[u8]> {
    let (mut quoted, mut escaped) = (false, false);
    for (i, &b) in s.iter().enumerate() {
        if crate::scan::is_control(b) {
            return Err(ParseError::new(control_kind(b), i));
        }
        if escaped {
            escaped = false;
        } else if quoted && b == b'\\' {
            escaped = true;
        } else if b == b'"' {
            quoted = !quoted;
        } else if b == b',' && !quoted {
            return Ok(s.get(i..).unwrap_or(&[]));
        }
    }
    Ok(&[])
}

/// Runs [`walk`] over a whole field value, offsets relative to it.
fn walk_value<'a, V: Visit<'a>>(
    value: &'a [u8],
    limits: &Limits,
    budget: &mut Budget,
    visit: &mut V,
) -> Result<&'a [u8]> {
    let lead = skip_ows(value);
    let v = trim_ows(value);
    walk(v, limits, budget, visit).map_err(|e| e.shifted(lead))?;
    Ok(v)
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
    let mut budget = Budget::default();
    let text = walk_value(value, limits, &mut budget, &mut Validate)?;
    let count = budget.count;
    Ok(Directives { text, count })
}

/// The response directives (RFC 9111 section 5.2.2 and the extensions).
///
/// Unknown directives are counted in `unknown` and available raw through
/// [`parse`]. A directive given twice keeps its first value and sets
/// `duplicates` (RFC 9111 section 4.2.1); an argument that does not fit
/// (`max-age=60s`) leaves the field `None` and sets `invalid_values`, and so
/// does a directive that does not parse at all (`ext=a b`), which is skipped
/// up to the next comma while every other directive is still read. Treat
/// such a response as stale; a cache that must fail closed does not store
/// it. Conflicting directives (`private, public`) are both reported.
///
/// # Examples
///
/// ```
/// let cc = parse_net::parse_response_cache_control(b"max-age=60, s-maxage=60s, immutable")?;
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
    /// A known directive had an argument that does not fit its grammar, or
    /// a directive did not parse and was skipped.
    pub invalid_values: bool,
    /// The number of extension directives (saturating).
    pub unknown: u16,
}

/// The request directives (RFC 9111 section 5.2.1), read as
/// [`ResponseDirectives`] are.
///
/// # Examples
///
/// ```
/// let req = parse_net::parse_request_cache_control(b"no-store, min-fresh=30, max-age=1, max-age=2")?;
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
    /// A known directive had an argument that does not fit its grammar, or
    /// a directive did not parse and was skipped.
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
/// CR, which is not a token byte), so one OR per byte suffices. The length
/// is a constant, so the bytes are compared as two to three overlapping
/// words, OR-ing `0x20` into each byte of a word at once.
#[inline]
fn is_name<const N: usize>(n: &[u8], lower: &[u8; N]) -> bool {
    let Ok(a) = <&[u8; N]>::try_from(n) else {
        return false;
    };
    if N < 4 {
        return a.iter().zip(lower).all(|(&b, &p)| b | 0x20 == p);
    }
    if N < 8 {
        let w = |s: &[u8; N], at: usize| {
            s.get(at..at + 4)
                .and_then(|c| <[u8; 4]>::try_from(c).ok())
                .map_or(0, u32::from_le_bytes)
        };
        return w(a, 0) | 0x2020_2020 == w(lower, 0)
            && w(a, N - 4) | 0x2020_2020 == w(lower, N - 4);
    }
    let w = |s: &[u8; N], at: usize| {
        s.get(at..at + 8)
            .and_then(|c| <[u8; 8]>::try_from(c).ok())
            .map_or(0, u64::from_le_bytes)
    };
    let mut at = 0;
    loop {
        let i = at.min(N - 8);
        if w(a, i) | 0x2020_2020_2020_2020 != w(lower, i) {
            return false;
        }
        at += 8;
        if at >= N {
            return true;
        }
    }
}

/// The index of a response directive name, dispatched on length first.
fn response_slot(n: &[u8]) -> Option<usize> {
    match n.len() {
        6 if is_name(n, b"public") => Some(5),
        7 if is_name(n, b"max-age") => Some(0),
        7 if is_name(n, b"private") => Some(4),
        8 if is_name(n, b"s-maxage") => Some(1),
        8 if is_name(n, b"no-cache") => Some(2),
        8 if is_name(n, b"no-store") => Some(3),
        9 if is_name(n, b"immutable") => Some(10),
        12 if is_name(n, b"no-transform") => Some(9),
        14 if is_name(n, b"stale-if-error") => Some(12),
        15 if is_name(n, b"must-revalidate") => Some(6),
        15 if is_name(n, b"must-understand") => Some(8),
        16 if is_name(n, b"proxy-revalidate") => Some(7),
        22 if is_name(n, b"stale-while-revalidate") => Some(11),
        _ => None,
    }
}

/// Builds [`ResponseDirectives`] one directive at a time.
#[derive(Default)]
struct ResponseBuilder {
    r: ResponseDirectives,
    seen: [bool; 13],
}

impl Visit<'_> for ResponseBuilder {
    const LENIENT: bool = true;

    fn skipped(&mut self) {
        self.r.invalid_values = true;
    }

    fn directive(&mut self, d: Directive<'_>) {
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
    match n.len() {
        7 if is_name(n, b"max-age") => Some(0),
        8 if is_name(n, b"no-cache") => Some(3),
        8 if is_name(n, b"no-store") => Some(4),
        9 if is_name(n, b"max-stale") => Some(1),
        9 if is_name(n, b"min-fresh") => Some(2),
        12 if is_name(n, b"no-transform") => Some(5),
        14 if is_name(n, b"only-if-cached") => Some(6),
        14 if is_name(n, b"stale-if-error") => Some(7),
        _ => None,
    }
}

/// Builds [`RequestDirectives`] one directive at a time.
#[derive(Default)]
struct RequestBuilder {
    r: RequestDirectives,
    seen: [bool; 8],
}

impl Visit<'_> for RequestBuilder {
    const LENIENT: bool = true;

    fn skipped(&mut self) {
        self.r.invalid_values = true;
    }

    fn directive(&mut self, d: Directive<'_>) {
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
                    // A bare `max-stale` means any staleness; an argument that
                    // cannot be read must not widen to that.
                    r.max_stale = match d.value {
                        None => Some(None),
                        v => seconds(v, inv).map(Some),
                    };
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
/// Only a control byte ([`ErrorKind::BareCr`], [`ErrorKind::LineFeed`],
/// [`ErrorKind::Nul`], [`ErrorKind::Control`]) and the list limits
/// ([`ErrorKind::TooManyMembers`], [`ErrorKind::TooManyEmptyElements`]):
/// unknown directives, bad arguments, and directives that do not parse are
/// reported in the struct.
///
/// # Examples
///
/// ```
/// let cc = parse_net::parse_response_cache_control(b"max-age=99999999999999999999, private, public")?;
/// assert_eq!(cc.max_age, Some(2_147_483_648));
/// assert!(cc.private && cc.public);
/// let cc = parse_net::parse_response_cache_control(b"private, no-store, ext=a b")?;
/// assert!(cc.private && cc.no_store && cc.invalid_values);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_response_cache_control(value: &[u8]) -> Result<ResponseDirectives> {
    let mut b = ResponseBuilder::default();
    let _ = walk_value(value, &Limits::DEFAULT, &mut Budget::default(), &mut b)?;
    Ok(b.r)
}

/// Reads a request `Cache-Control` value.
///
/// # Errors
///
/// As [`parse_response_cache_control`].
///
/// # Examples
///
/// ```
/// let req = parse_net::parse_request_cache_control(b"max-stale, no-cache")?;
/// assert_eq!(req.max_stale, Some(None));
/// assert!(req.no_cache);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_request_cache_control(value: &[u8]) -> Result<RequestDirectives> {
    let mut b = RequestBuilder::default();
    let _ = walk_value(value, &Limits::DEFAULT, &mut Budget::default(), &mut b)?;
    Ok(b.r)
}

/// Reads several response `Cache-Control` field lines as one.
///
/// # Errors
///
/// As [`parse_response_cache_control`], with [`ParseError::line`] set.
///
/// # Examples
///
/// ```
/// use parse_net::cache;
///
/// let lines: [&[u8]; 2] = [b"public", b"max-age=300"];
/// let cc = cache::parse_response_lines(lines)?;
/// assert!(cc.public);
/// assert_eq!(cc.max_age, Some(300));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_response_lines<'a, I>(lines: I) -> Result<ResponseDirectives>
where
    I: IntoIterator<Item = &'a [u8]>,
    I::IntoIter: Clone,
{
    let (mut b, mut budget) = (ResponseBuilder::default(), Budget::default());
    for (n, line) in lines.into_iter().enumerate() {
        let _ =
            walk_value(line, &Limits::DEFAULT, &mut budget, &mut b).map_err(|e| e.on_line(n))?;
    }
    Ok(b.r)
}

/// Reads several request `Cache-Control` field lines as one.
///
/// # Errors
///
/// As [`parse_response_cache_control`], with [`ParseError::line`] set.
///
/// # Examples
///
/// ```
/// use parse_net::cache;
///
/// let lines: [&[u8]; 2] = [b"no-cache", b"max-stale=60"];
/// let req = cache::parse_request_lines(lines)?;
/// assert!(req.no_cache);
/// assert_eq!(req.max_stale, Some(Some(60)));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_request_lines<'a, I>(lines: I) -> Result<RequestDirectives>
where
    I: IntoIterator<Item = &'a [u8]>,
    I::IntoIter: Clone,
{
    let (mut b, mut budget) = (RequestBuilder::default(), Budget::default());
    for (n, line) in lines.into_iter().enumerate() {
        let _ =
            walk_value(line, &Limits::DEFAULT, &mut budget, &mut b).map_err(|e| e.on_line(n))?;
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
        let r = |v: &[u8]| parse_response_cache_control(v).unwrap();
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
        let q = |v: &[u8]| parse_request_cache_control(v).unwrap();
        assert_eq!(q(b"max-stale").max_stale, Some(None));
        assert_eq!(q(b"max-stale=10").max_stale, Some(Some(10)));
        assert!(q(b"only-if-cached").only_if_cached);
        assert_eq!(q(b"min-fresh=5, min-fresh=6").min_fresh, Some(5));
        assert!(q(b"min-fresh=5, min-fresh=6").duplicates);
    }

    #[test]
    fn test_cache_structure_errors() {
        let k = |v: &[u8]| parse(v, &Limits::DEFAULT).unwrap_err().kind();
        assert_eq!(k(b"max-age = 5"), ErrorKind::NotToken);
        assert_eq!(k(b"max-age=\"5"), ErrorKind::UnterminatedQuote);
        assert_eq!(k(b"=5"), ErrorKind::NotToken);
        assert_eq!(k(b"a=b c"), ErrorKind::NotToken);
        assert_eq!(k(b"a=\x01"), ErrorKind::Control);
        let r = |v: &[u8]| parse_response_cache_control(v).map_err(|e| (e.kind(), e.offset()));
        assert_eq!(r(b"no-store, a=\x01"), Err((ErrorKind::Control, 12)));
        assert_eq!(r(b"no-store, a=b \x7f"), Err((ErrorKind::Control, 14)));
        assert_eq!(r(b"no-store, a=\"x\ny\""), Err((ErrorKind::LineFeed, 14)));
    }

    /// One directive that does not parse is skipped, and every
    /// other directive is still read.
    #[test]
    fn test_malformed_directive_skipped() {
        let r = |v: &[u8]| parse_response_cache_control(v).unwrap();
        for v in [
            &b"no-store, x="[..],
            b"no-store, ext=a b",
            b"no-store, ext=\"unterminated",
            b"no-store, ext=caf\xc3\xa9",
            b"no-store, max-age=",
            b"no-store, max-age=60 s",
            b"no-store, max-age = 60",
            b"x=, no-store",
            b"\"q,\", no-store",
            b"=, no-store,=",
        ] {
            let cc = r(v);
            assert!(cc.no_store && cc.invalid_values, "{v:?}");
            assert_eq!(cc.max_age, None, "{v:?}");
        }
        let cc = r(b"private, ext=\"a, b\" c, max-age=5, public");
        assert!(cc.private && cc.public && cc.invalid_values);
        assert_eq!(cc.max_age, Some(5));
        assert!(!r(b"private, ext=\"a, b\"").invalid_values);
        let q = parse_request_cache_control(b"no-cache, a b, max-stale=5").unwrap();
        assert!(q.no_cache && q.invalid_values);
        assert_eq!(q.max_stale, Some(Some(5)));
        let lines: [&[u8]; 2] = [b"public, x=", b"max-age=5"];
        let cc = parse_response_lines(lines).unwrap();
        assert!(cc.public && cc.invalid_values && cc.max_age == Some(5));
        // The validating parser still refuses it.
        assert!(parse(b"no-store, x=", &Limits::DEFAULT).is_err());
    }

    #[test]
    fn test_lines() {
        let lines: [&[u8]; 2] = [b"public", b"max-age=5"];
        let r = parse_response_lines(lines).unwrap();
        assert!(r.public && r.max_age == Some(5));
        let bad: [&[u8]; 2] = [b"public", b"max-age=\x00"];
        assert_eq!(parse_response_lines(bad).unwrap_err().line(), 1);
        let req: [&[u8]; 2] = [b"no-cache", b"max-stale"];
        assert_eq!(parse_request_lines(req).unwrap().max_stale, Some(None));
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
        let r = parse_response_cache_control(out.written()).unwrap();
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

    /// The word compare of `is_name` against the per-byte rule it replaces,
    /// for every directive name with each byte set to every value in turn,
    /// and for names one byte short or long.
    #[test]
    fn test_is_name_matches_bytewise() {
        fn check<const N: usize>(lower: &[u8; N]) {
            let reference =
                |n: &[u8]| n.len() == N && n.iter().zip(lower).all(|(&b, &p)| b | 0x20 == p);
            let mut n = *lower;
            for i in 0..N {
                for b in 0..=255u8 {
                    n[i] = b;
                    assert_eq!(is_name(&n, lower), reference(&n), "{lower:?} at {i} = {b}");
                }
                n[i] = lower[i].to_ascii_uppercase();
                assert!(is_name(&n, lower));
            }
            assert!(!is_name(&lower[..N - 1], lower));
            let mut long = lower.to_vec();
            long.push(b'a');
            assert!(!is_name(&long, lower));
        }
        check(b"abc");
        check(b"public");
        check(b"max-age");
        check(b"private");
        check(b"s-maxage");
        check(b"no-cache");
        check(b"no-store");
        check(b"immutable");
        check(b"max-stale");
        check(b"min-fresh");
        check(b"no-transform");
        check(b"only-if-cached");
        check(b"stale-if-error");
        check(b"must-revalidate");
        check(b"must-understand");
        check(b"proxy-revalidate");
        check(b"stale-while-revalidate");
    }
}
