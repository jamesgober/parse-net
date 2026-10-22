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
    list,
    num::parse_u32_saturating,
    scan::control_kind,
    text::{Word, is_token, parse_word},
    write::{Sink, reserve, write_decimal_u64},
};

/// One directive: a name and an optional argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Directive<'a> {
    /// The name as sent (compare it ASCII case-insensitively).
    pub name: &'a [u8],
    /// The argument, token or quoted.
    pub value: Option<Word<'a>>,
}

/// Parses one `token [ "=" ( token / quoted-string ) ]`.
fn directive(e: &[u8]) -> Result<Directive<'_>> {
    let n = e.iter().take_while(|&&b| class::is_tchar(b)).count();
    if n == 0 {
        return Err(bad(e, 0));
    }
    let name = e.get(..n).unwrap_or(&[]);
    match e.get(n) {
        None => Ok(Directive { name, value: None }),
        Some(b'=') => {
            let rest = e.get(n + 1..).unwrap_or(&[]);
            let (w, used) = parse_word(rest).map_err(|x| match x.kind() {
                ErrorKind::Empty => bad(e, n + 1),
                _ => x.shifted(n + 1),
            })?;
            if n + 1 + used != e.len() {
                return Err(bad(e, n + 1 + used));
            }
            Ok(Directive {
                name,
                value: Some(w),
            })
        }
        Some(_) => Err(bad(e, n)),
    }
}

fn bad(e: &[u8], at: usize) -> ParseError {
    match e.get(at) {
        Some(&b) if crate::scan::is_control(b) => ParseError::new(control_kind(b), at),
        _ => ParseError::new(ErrorKind::NotToken, at),
    }
}

/// Validated directives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Directives<'a> {
    list: list::List<'a>,
}

impl<'a> Directives<'a> {
    /// The directives, in order.
    pub fn iter(&self) -> impl Iterator<Item = Directive<'a>> + use<'a> {
        self.list.iter().filter_map(|e| directive(e).ok())
    }

    /// The number of directives.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.list.len()
    }

    /// Whether there are no directives.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.list.is_empty()
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
    let l = list::parse(value, limits)?;
    for e in l.iter() {
        let at = (e.as_ptr() as usize).saturating_sub(value.as_ptr() as usize);
        directive(e).map(|_| ()).map_err(|x| x.shifted(at))?;
    }
    Ok(Directives { list: l })
}

/// The response directives (RFC 9111 section 5.2.2 and the extensions).
///
/// Unknown directives are counted in `unknown` and available raw through
/// [`parse`]. A directive given twice keeps its first value and sets
/// `duplicates` (RFC 9111 section 4.2.1); an argument that does not fit
/// (`max-age=60s`) leaves the field `None` and sets `invalid_values`: treat
/// such a response as stale. Conflicting directives (`private, public`) are
/// both reported.
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
    let mut buf = [0u8; 32];
    let digits = match value {
        Some(Word::Token(t)) => t,
        Some(q @ Word::Quoted(_)) => match q.unescape_into(&mut buf) {
            Ok(d) => d,
            Err(_) => {
                *invalid = true;
                return None;
            }
        },
        None => {
            *invalid = true;
            return None;
        }
    };
    match parse_u32_saturating(digits) {
        Ok(n) => Some(n),
        Err(_) => {
            *invalid = true;
            None
        }
    }
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

fn response_from<'a>(directives: impl Iterator<Item = Directive<'a>>) -> ResponseDirectives {
    let mut r = ResponseDirectives::default();
    let mut seen = [false; 13];
    for d in directives {
        let n = d.name;
        let is = |s: &[u8]| n.eq_ignore_ascii_case(s);
        let (dup, inv) = (&mut r.duplicates, &mut r.invalid_values);
        match () {
            () if is(b"max-age") => number(&mut r.max_age, &mut seen[0], dup, d.value, inv),
            () if is(b"s-maxage") => number(&mut r.s_maxage, &mut seen[1], dup, d.value, inv),
            () if is(b"no-cache") => flag(&mut r.no_cache, &mut seen[2], dup, d.value, inv, true),
            () if is(b"no-store") => flag(&mut r.no_store, &mut seen[3], dup, d.value, inv, false),
            () if is(b"private") => flag(&mut r.private, &mut seen[4], dup, d.value, inv, true),
            () if is(b"public") => flag(&mut r.public, &mut seen[5], dup, d.value, inv, false),
            () if is(b"must-revalidate") => flag(
                &mut r.must_revalidate,
                &mut seen[6],
                dup,
                d.value,
                inv,
                false,
            ),
            () if is(b"proxy-revalidate") => flag(
                &mut r.proxy_revalidate,
                &mut seen[7],
                dup,
                d.value,
                inv,
                false,
            ),
            () if is(b"must-understand") => flag(
                &mut r.must_understand,
                &mut seen[8],
                dup,
                d.value,
                inv,
                false,
            ),
            () if is(b"no-transform") => {
                flag(&mut r.no_transform, &mut seen[9], dup, d.value, inv, false)
            }
            () if is(b"immutable") => {
                flag(&mut r.immutable, &mut seen[10], dup, d.value, inv, false)
            }
            () if is(b"stale-while-revalidate") => {
                number(
                    &mut r.stale_while_revalidate,
                    &mut seen[11],
                    dup,
                    d.value,
                    inv,
                );
            }
            () if is(b"stale-if-error") => {
                number(&mut r.stale_if_error, &mut seen[12], dup, d.value, inv)
            }
            () => r.unknown = r.unknown.saturating_add(1),
        }
    }
    r
}

fn request_from<'a>(directives: impl Iterator<Item = Directive<'a>>) -> RequestDirectives {
    let mut r = RequestDirectives::default();
    let mut seen = [false; 8];
    for d in directives {
        let n = d.name;
        let is = |s: &[u8]| n.eq_ignore_ascii_case(s);
        let (dup, inv) = (&mut r.duplicates, &mut r.invalid_values);
        match () {
            () if is(b"max-age") => number(&mut r.max_age, &mut seen[0], dup, d.value, inv),
            () if is(b"max-stale") => {
                if seen[1] {
                    *dup = true;
                } else {
                    seen[1] = true;
                    r.max_stale = Some(match d.value {
                        None => None,
                        v => seconds(v, inv),
                    });
                }
            }
            () if is(b"min-fresh") => number(&mut r.min_fresh, &mut seen[2], dup, d.value, inv),
            () if is(b"no-cache") => flag(&mut r.no_cache, &mut seen[3], dup, d.value, inv, false),
            () if is(b"no-store") => flag(&mut r.no_store, &mut seen[4], dup, d.value, inv, false),
            () if is(b"no-transform") => {
                flag(&mut r.no_transform, &mut seen[5], dup, d.value, inv, false)
            }
            () if is(b"only-if-cached") => flag(
                &mut r.only_if_cached,
                &mut seen[6],
                dup,
                d.value,
                inv,
                false,
            ),
            () if is(b"stale-if-error") => {
                number(&mut r.stale_if_error, &mut seen[7], dup, d.value, inv)
            }
            () => r.unknown = r.unknown.saturating_add(1),
        }
    }
    r
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
    Ok(response_from(parse(value, &Limits::DEFAULT)?.iter()))
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
    Ok(request_from(parse(value, &Limits::DEFAULT)?.iter()))
}

/// Reads several response `Cache-Control` field lines as one.
///
/// # Errors
///
/// As [`parse`], with [`ParseError::line`] set.
pub fn response_lines<'a, I>(lines: I) -> Result<ResponseDirectives>
where
    I: IntoIterator<Item = &'a [u8]>,
    I::IntoIter: Clone,
{
    let lines = lines.into_iter();
    for (n, line) in lines.clone().enumerate() {
        parse(line, &Limits::DEFAULT)
            .map(|_| ())
            .map_err(|e| e.on_line(n))?;
    }
    Ok(response_from(lines.flat_map(|l| {
        list::parse(l, &Limits::DEFAULT)
            .into_iter()
            .flat_map(|x| x.iter())
            .filter_map(|e| directive(e).ok())
    })))
}

/// Reads several request `Cache-Control` field lines as one.
///
/// # Errors
///
/// As [`parse`], with [`ParseError::line`] set.
pub fn request_lines<'a, I>(lines: I) -> Result<RequestDirectives>
where
    I: IntoIterator<Item = &'a [u8]>,
    I::IntoIter: Clone,
{
    let lines = lines.into_iter();
    for (n, line) in lines.clone().enumerate() {
        parse(line, &Limits::DEFAULT)
            .map(|_| ())
            .map_err(|e| e.on_line(n))?;
    }
    Ok(request_from(lines.flat_map(|l| {
        list::parse(l, &Limits::DEFAULT)
            .into_iter()
            .flat_map(|x| x.iter())
            .filter_map(|e| directive(e).ok())
    })))
}

/// Writes `Cache-Control` directives, separated by `, `.
///
/// Delta-seconds are always written as tokens (senders must not quote
/// them); field lists are always quoted.
pub struct Writer<'s, S: Sink> {
    out: &'s mut S,
    first: bool,
}

impl<'s, S: Sink> Writer<'s, S> {
    /// A writer over `out`.
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
