//! `Link` (RFC 8288 section 3): `#link-value`, where
//! `link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )` and
//! `link-param = token BWS [ "=" BWS ( token / quoted-string ) ]`.
//!
//! The target is validated as RFC 3986 characters with well-formed `%XX`
//! triples and returned unresolved (url-lib resolves). Commas inside `<...>`
//! do not split. A `title*` is decoded at parse time, as `filename*` is, so a
//! view never holds an undecodable title.
//!
//! # Examples
//!
//! ```
//! use parse_net::{parse_link, Limits};
//!
//! let links = parse_link(b"<https://x.test/p?page=2,3>; rel=\"next last\", </a>; rel=prev; crossorigin", &Limits::DEFAULT)?;
//! let all: Vec<_> = links.iter().collect();
//! assert_eq!(all[0].target(), b"https://x.test/p?page=2,3");
//! assert!(all[0].has_rel("last") && all[1].has_rel("prev"));
//! # Ok::<(), parse_net::ParseError>(())
//! ```

use crate::{
    class,
    disposition::Filename,
    error::{ErrorKind, ParseError, Result, WriteError, err},
    ext_value::ExtValue,
    limits::Limits,
    scan::control_kind,
    text::{Word, is_token, parse_word, skip_ows, trim_ows},
    write::{CountSink, Sink, reserve, write_word},
};

/// Limits for walking text that was already validated.
const RELAXED: Limits = Limits::DEFAULT
    .max_params(u16::MAX)
    .max_list_members(u16::MAX)
    .max_empty_elements(u16::MAX);

/// Whether `b` may appear in a URI-reference outside a `%XX` triple
/// (RFC 3986 sections 2.2 and 2.3).
const fn is_uri_char(b: u8) -> bool {
    class::is_unreserved(b)
        || class::is_sub_delim(b)
        || matches!(b, b':' | b'/' | b'?' | b'#' | b'[' | b']' | b'@')
}

fn refused(v: &[u8], at: usize, kind: ErrorKind) -> ParseError {
    match v.get(at) {
        Some(&b) if crate::scan::is_control(b) => ParseError::new(control_kind(b), at),
        _ => ParseError::new(kind, at),
    }
}

/// Validates the target after the `<` at `v[at - 1]`; returns the index of
/// the closing `>`.
fn target_end(v: &[u8], at: usize) -> Result<usize> {
    let mut i = at;
    loop {
        match v.get(i) {
            None => return err(ErrorKind::UnterminatedQuote, at - 1),
            Some(b'>') => return Ok(i),
            Some(b'%') => match (v.get(i + 1), v.get(i + 2)) {
                (Some(&h), Some(&l)) if class::is_hexdig(h) && class::is_hexdig(l) => i += 3,
                _ => return err(ErrorKind::InvalidPercentEncoding, i),
            },
            Some(&b) if is_uri_char(b) => i += 1,
            Some(_) => return Err(refused(v, i, ErrorKind::InvalidByte)),
        }
    }
}

/// One `link-value` starting at `v[i]`; returns the index after its last
/// parameter (before any OWS) and its parameter count.
fn link_value(v: &[u8], i: usize, limits: &Limits) -> Result<(usize, usize)> {
    if v.get(i) != Some(&b'<') {
        return Err(refused(v, i, ErrorKind::InvalidByte));
    }
    let mut i = target_end(v, i + 1)? + 1;
    let mut count = 0usize;
    loop {
        let mut j = i + skip_ows(v.get(i..).unwrap_or(&[]));
        if v.get(j) != Some(&b';') {
            return Ok((i, count));
        }
        j += 1;
        j += skip_ows(v.get(j..).unwrap_or(&[]));
        let n = v
            .get(j..)
            .unwrap_or(&[])
            .iter()
            .take_while(|&&b| class::is_tchar(b))
            .count();
        if n == 0 {
            return Err(refused(v, j, ErrorKind::NotToken));
        }
        let name = v.get(j..j + n).unwrap_or(&[]);
        let k = j + n;
        let mut eq = k + skip_ows(v.get(k..).unwrap_or(&[]));
        if v.get(eq) == Some(&b'=') {
            eq += 1;
            eq += skip_ows(v.get(eq..).unwrap_or(&[]));
            let (w, used) = parse_word(v.get(eq..).unwrap_or(&[])).map_err(|e| match e.kind() {
                ErrorKind::Empty => refused(v, eq, ErrorKind::MissingValue),
                _ => e.shifted(eq),
            })?;
            if name.eq_ignore_ascii_case(b"title*") {
                let Word::Token(t) = w else {
                    return err(ErrorKind::InvalidCharset, eq);
                };
                let ext = ExtValue::parse(t).map_err(|e| e.shifted(eq))?;
                ext.check_text()
                    .map_err(|e| ParseError::new(e.kind(), eq))?;
            }
            i = eq + used;
        } else {
            i = k;
        }
        count += 1;
        if count > usize::from(limits.params) {
            return err(ErrorKind::TooManyMembers, j);
        }
    }
}

/// Parses a `Link` field value.
///
/// # Errors
///
/// [`ErrorKind::InvalidByte`] (a target byte outside RFC 3986, a space in the
/// target, a member that does not start with `<`);
/// [`ErrorKind::UnterminatedQuote`] (no closing `>` or `"`);
/// [`ErrorKind::InvalidPercentEncoding`]; [`ErrorKind::NotToken`] and
/// [`ErrorKind::MissingValue`] for a parameter; the [`ExtValue::parse`]
/// errors for `title*`; [`ErrorKind::TooManyMembers`] beyond
/// `max_list_members` links or `max_params` parameters;
/// [`ErrorKind::TooManyEmptyElements`]; [`ErrorKind::TrailingData`].
///
/// # Examples
///
/// ```
/// use parse_net::{parse_link, ErrorKind, Limits};
///
/// let l = parse_link(b"<a>; rel=next; rel=prev", &Limits::DEFAULT)?;
/// assert!(l.iter().next().is_some_and(|v| v.has_rel("next") && !v.has_rel("prev")));
/// assert_eq!(parse_link(b"<a b>", &Limits::DEFAULT).unwrap_err().kind(), ErrorKind::InvalidByte);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_link<'a>(value: &'a [u8], limits: &Limits) -> Result<Links<'a>> {
    let lead = skip_ows(value);
    let v = trim_ows(value);
    let (mut i, mut count, mut empty) = (0usize, 0usize, 0usize);
    loop {
        i += skip_ows(v.get(i..).unwrap_or(&[]));
        match v.get(i) {
            None => break,
            Some(b',') => {
                empty += 1;
                if empty > usize::from(limits.empty_elements) {
                    return err(ErrorKind::TooManyEmptyElements, lead + i);
                }
                i += 1;
                continue;
            }
            Some(_) => {}
        }
        let at = i;
        let (end, _) = link_value(v, i, limits).map_err(|e| e.shifted(lead))?;
        count += 1;
        if count > usize::from(limits.list_members) {
            return err(ErrorKind::TooManyMembers, lead + at);
        }
        i = end + skip_ows(v.get(end..).unwrap_or(&[]));
        match v.get(i) {
            None => break,
            Some(b',') => i += 1,
            Some(_) => return Err(refused(v, i, ErrorKind::TrailingData).shifted(lead)),
        }
    }
    Ok(Links { text: v, count })
}

/// A validated `Link` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Links<'a> {
    text: &'a [u8],
    count: usize,
}

impl<'a> Links<'a> {
    /// The link values, in order.
    #[must_use]
    pub fn iter(&self) -> LinkIter<'a> {
        LinkIter { v: self.text, i: 0 }
    }

    /// The number of link values.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether the field holds no link value.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// The link values of a validated [`Links`].
#[derive(Clone, Debug)]
pub struct LinkIter<'a> {
    v: &'a [u8],
    i: usize,
}

impl<'a> Iterator for LinkIter<'a> {
    type Item = LinkValue<'a>;

    fn next(&mut self) -> Option<LinkValue<'a>> {
        let v = self.v;
        while matches!(v.get(self.i), Some(b' ' | b'\t' | b',')) {
            self.i += 1;
        }
        let start = self.i;
        if start >= v.len() {
            return None;
        }
        let (end, count) = link_value(v, start, &RELAXED).ok()?;
        let close = target_end(v, start + 1).ok()?;
        self.i = end;
        Some(LinkValue {
            target: v.get(start + 1..close).unwrap_or(&[]),
            params: LinkParams {
                text: v.get(close + 1..end).unwrap_or(&[]),
                count,
            },
        })
    }
}

/// One link value: a target and its parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LinkValue<'a> {
    target: &'a [u8],
    params: LinkParams<'a>,
}

impl<'a> LinkValue<'a> {
    /// The URI-reference between `<` and `>`, as sent (not resolved).
    #[must_use]
    pub const fn target(&self) -> &'a [u8] {
        self.target
    }

    /// The parameters, in order.
    #[must_use]
    pub const fn params(&self) -> LinkParams<'a> {
        self.params
    }

    /// The value of the first parameter named `name` (case-insensitive):
    /// `None` when absent, `Some(None)` when it has no value.
    fn first(&self, name: &str) -> Option<Option<Word<'a>>> {
        self.params
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, w)| w)
    }

    /// The first `rel` value; later `rel` parameters are ignored (RFC 8288
    /// section 3.3).
    #[must_use]
    pub fn rel(&self) -> Option<Word<'a>> {
        self.first("rel").flatten()
    }

    /// The relation types of the first `rel`, split on spaces. A relation
    /// type is a token or a URI, so it never needs a quoted pair; one that
    /// has one is yielded as sent.
    #[must_use]
    pub fn rels(&self) -> RelIter<'a> {
        let text = match self.rel() {
            Some(Word::Token(t)) => t,
            Some(Word::Quoted(q)) => q.raw(),
            None => &[],
        };
        RelIter { rest: text }
    }

    /// Whether the first `rel` lists `rel` (ASCII case-insensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{parse_link, Limits};
    ///
    /// let l = parse_link(b"</style.css>; rel=\"Preload stylesheet\"", &Limits::DEFAULT)?;
    /// let v = l.iter().next().expect("one link");
    /// assert!(v.has_rel("preload") && v.has_rel("STYLESHEET") && !v.has_rel("style"));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn has_rel(&self, rel: &str) -> bool {
        self.rels().any(|r| r.eq_ignore_ascii_case(rel.as_bytes()))
    }

    /// The first `anchor`.
    #[must_use]
    pub fn anchor(&self) -> Option<Word<'a>> {
        self.first("anchor").flatten()
    }

    /// Every `hreflang`, in order (the one parameter RFC 8288 lets repeat).
    #[must_use]
    pub fn hreflang(&self) -> HreflangIter<'a> {
        HreflangIter {
            params: self.params.iter(),
        }
    }

    /// The title: the first `title*` (RFC 8187, decoded like `filename*`)
    /// when present, else the first `title`.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{parse_link, Limits};
    ///
    /// let l = parse_link(b"<a>; title=\"EUR\"; title*=UTF-8''%E2%82%AC", &Limits::DEFAULT)?;
    /// let mut buf = [0u8; 8];
    /// let t = l.iter().next().and_then(|v| v.title()).expect("a title");
    /// assert_eq!(t.decode_into(&mut buf)?, "\u{20ac}");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn title(&self) -> Option<Filename<'a>> {
        let ext = self.first("title*").flatten().and_then(|w| match w {
            Word::Token(t) => ExtValue::parse(t).ok(),
            Word::Quoted(_) => None,
        });
        ext.map(Filename::Ext)
            .or_else(|| self.first("title").flatten().map(Filename::Plain))
    }

    /// The first `media`.
    #[must_use]
    pub fn media(&self) -> Option<Word<'a>> {
        self.first("media").flatten()
    }

    /// The first `type`.
    #[must_use]
    pub fn type_(&self) -> Option<Word<'a>> {
        self.first("type").flatten()
    }
}

/// The parameters of a link value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LinkParams<'a> {
    text: &'a [u8],
    count: usize,
}

impl<'a> LinkParams<'a> {
    /// The parameters, in order: the name as sent and the value, if any.
    #[must_use]
    pub fn iter(&self) -> LinkParamIter<'a> {
        LinkParamIter { s: self.text, i: 0 }
    }

    /// The number of parameters.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether there are no parameters.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// The parameters of a validated [`LinkParams`].
#[derive(Clone, Debug)]
pub struct LinkParamIter<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Iterator for LinkParamIter<'a> {
    type Item = (&'a [u8], Option<Word<'a>>);

    fn next(&mut self) -> Option<Self::Item> {
        let s = self.s;
        let mut j = self.i + skip_ows(s.get(self.i..)?);
        if s.get(j) != Some(&b';') {
            return None;
        }
        j += 1;
        j += skip_ows(s.get(j..)?);
        let n = s
            .get(j..)?
            .iter()
            .take_while(|&&b| class::is_tchar(b))
            .count();
        let name = s.get(j..j + n)?;
        let k = j + n;
        let eq = k + skip_ows(s.get(k..)?);
        if s.get(eq) == Some(&b'=') {
            let at = eq + 1 + skip_ows(s.get(eq + 1..)?);
            let (w, used) = parse_word(s.get(at..)?).ok()?;
            self.i = at + used;
            Some((name, Some(w)))
        } else {
            self.i = k;
            Some((name, None))
        }
    }
}

/// The relation types of a `rel` value.
#[derive(Clone, Debug)]
pub struct RelIter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for RelIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let start = self.rest.iter().position(|&b| b != b' ')?;
        let rest = self.rest.get(start..)?;
        let n = rest.iter().position(|&b| b == b' ').unwrap_or(rest.len());
        let (r, tail) = rest.split_at(n);
        self.rest = tail;
        Some(r)
    }
}

/// The `hreflang` values of a link value.
#[derive(Clone, Debug)]
pub struct HreflangIter<'a> {
    params: LinkParamIter<'a>,
}

impl<'a> Iterator for HreflangIter<'a> {
    type Item = Word<'a>;

    fn next(&mut self) -> Option<Word<'a>> {
        self.params.by_ref().find_map(|(n, w)| {
            if n.eq_ignore_ascii_case(b"hreflang") {
                w
            } else {
                None
            }
        })
    }
}

/// Writes one link value: `<target>; name=value` for each parameter, values
/// through [`write_word`](crate::write::write_word). An empty value writes
/// the name alone (`; crossorigin`), which parses back as a parameter with no
/// value.
///
/// # Errors
///
/// [`WriteError::Forbidden`] for a target byte that is not an RFC 3986
/// character (`<`, `>`, SP, a control, a non-ASCII byte) or a `%` not
/// followed by two hex digits, and for a control byte in a value;
/// [`WriteError::NotToken`] for a name; [`WriteError::Full`] (nothing written
/// when the sink reports its room).
///
/// # Examples
///
/// ```
/// use parse_net::{link, SliceSink};
///
/// let mut buf = [0u8; 64];
/// let mut out = SliceSink::new(&mut buf);
/// link::write_link(b"/page/2", &[("rel", "next"), ("title", "Page 2"), ("crossorigin", "")], &mut out)?;
/// assert_eq!(out.written(), b"</page/2>; rel=next; title=\"Page 2\"; crossorigin");
/// # Ok::<(), parse_net::WriteError>(())
/// ```
pub fn write_link(
    target: &[u8],
    params: &[(&str, &str)],
    out: &mut impl Sink,
) -> core::result::Result<(), WriteError> {
    let mut i = 0usize;
    while let Some(&b) = target.get(i) {
        if b == b'%' {
            match (target.get(i + 1), target.get(i + 2)) {
                (Some(&h), Some(&l)) if class::is_hexdig(h) && class::is_hexdig(l) => i += 3,
                _ => return Err(WriteError::forbidden(i)),
            }
        } else if is_uri_char(b) {
            i += 1;
        } else {
            return Err(WriteError::forbidden(i));
        }
    }
    if params.iter().any(|(name, _)| !is_token(name.as_bytes())) {
        return Err(WriteError::NotToken);
    }
    let mut count = CountSink::new();
    put_link(target, params, &mut count)?;
    reserve(out, count.count())?;
    put_link(target, params, out)
}

fn put_link(
    target: &[u8],
    params: &[(&str, &str)],
    out: &mut impl Sink,
) -> core::result::Result<(), WriteError> {
    out.put(b"<")?;
    out.put(target)?;
    out.put(b">")?;
    for (name, value) in params {
        out.put(b"; ")?;
        out.put(name.as_bytes())?;
        if !value.is_empty() {
            out.put(b"=")?;
            write_word(value.as_bytes(), out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{vec, vec::Vec};

    fn one(v: &[u8]) -> LinkValue<'_> {
        let l = parse_link(v, &Limits::DEFAULT).unwrap();
        assert_eq!(l.len(), 1);
        l.iter().next().unwrap()
    }

    fn k(v: &[u8]) -> ErrorKind {
        parse_link(v, &Limits::DEFAULT).unwrap_err().kind()
    }

    #[test]
    fn test_link_edge_cases() {
        assert_eq!(one(b"<a>; rel=next").target(), b"a");
        assert_eq!(one(b"<a,b>; rel=next").target(), b"a,b");
        let v = one(b"<a>; rel=\"next prev\"");
        assert_eq!(v.rels().collect::<Vec<_>>(), vec![&b"next"[..], b"prev"]);
        assert!(
            one(b"<a>;rel=next;rel=prev")
                .rel()
                .unwrap()
                .eq_bytes(b"next")
        );
        assert_eq!(k(b"<a"), ErrorKind::UnterminatedQuote);
        assert_eq!(k(b"<a b>"), ErrorKind::InvalidByte);
        assert_eq!(k(b"<a%2>"), ErrorKind::InvalidPercentEncoding);
        assert_eq!(k(b"a"), ErrorKind::InvalidByte);
        assert_eq!(k(b"<a>; rel=\"x"), ErrorKind::UnterminatedQuote);
        assert_eq!(k(b"<a>; =x"), ErrorKind::NotToken);
        assert_eq!(k(b"<a>; rel="), ErrorKind::MissingValue);
        assert_eq!(k(b"<a> x"), ErrorKind::TrailingData);
        assert_eq!(k(b"<a>\r\n"), ErrorKind::BareCr);
        let v = one(b"<a>; crossorigin");
        assert_eq!(v.params().iter().next(), Some((&b"crossorigin"[..], None)));
        assert!(v.rel().is_none() && v.rels().next().is_none());
        assert_eq!(
            one(b"<a>; rel = next").rel().unwrap().as_plain(),
            Some(&b"next"[..])
        );
        assert!(parse_link(b"", &Limits::DEFAULT).unwrap().is_empty());
        assert_eq!(
            parse_link(b" , <a>,, <b> ,", &Limits::DEFAULT)
                .unwrap()
                .iter()
                .count(),
            2
        );
        assert_eq!(
            one(b"<http://[::1]:8080/a?b#c>").target(),
            b"http://[::1]:8080/a?b#c"
        );
    }

    #[test]
    fn test_link_params() {
        let v = one(
            b"<a>; anchor=\"#x\"; hreflang=en; hreflang=\"de\"; media=screen; type=\"text/html\"",
        );
        assert!(v.anchor().unwrap().eq_bytes(b"#x"));
        let langs: Vec<_> = v.hreflang().map(|w| w.as_plain().unwrap()).collect();
        assert_eq!(langs, vec![&b"en"[..], b"de"]);
        assert!(v.media().unwrap().eq_bytes(b"screen"));
        assert!(v.type_().unwrap().eq_bytes(b"text/html"));
        assert_eq!(v.params().len(), 5);
        assert_eq!(v.params().iter().count(), 5);
    }

    #[test]
    fn test_link_title_ext_preferred_and_checked() {
        let mut buf = [0u8; 16];
        let v = one(b"<a>; title*=UTF-8''%E2%82%AC; title=x");
        assert_eq!(
            v.title().unwrap().decode_into(&mut buf).unwrap(),
            "\u{20ac}"
        );
        assert!(matches!(
            one(b"<a>; title=x").title(),
            Some(Filename::Plain(_))
        ));
        assert_eq!(k(b"<a>; title*=\"UTF-8''x\""), ErrorKind::InvalidCharset);
        assert_eq!(k(b"<a>; title*=UTF-8''%0a"), ErrorKind::ControlInDecoded);
        assert_eq!(k(b"<a>; title*=x"), ErrorKind::InvalidCharset);
    }

    #[test]
    fn test_link_limits_plus_one_refused() {
        let l = Limits::DEFAULT.max_list_members(2).max_params(2);
        assert!(parse_link(b"<a>, <b>", &l).is_ok());
        assert_eq!(
            parse_link(b"<a>, <b>, <c>", &l).unwrap_err().kind(),
            ErrorKind::TooManyMembers
        );
        assert!(parse_link(b"<a>;x;y", &l).is_ok());
        assert_eq!(
            parse_link(b"<a>;x;y;z", &l).unwrap_err().kind(),
            ErrorKind::TooManyMembers
        );
        let e = Limits::DEFAULT.max_empty_elements(1);
        assert!(parse_link(b"<a>,,<b>", &e).is_ok());
        assert_eq!(
            parse_link(b"<a>,,,<b>", &e).unwrap_err().kind(),
            ErrorKind::TooManyEmptyElements
        );
    }

    #[test]
    fn test_write_link_refusals_and_round_trip() {
        let mut buf = [0u8; 64];
        let mut out = crate::SliceSink::new(&mut buf);
        assert_eq!(
            write_link(b"a b", &[], &mut out),
            Err(WriteError::Forbidden { at: 1 })
        );
        assert_eq!(
            write_link(b"<a", &[], &mut out),
            Err(WriteError::Forbidden { at: 0 })
        );
        assert_eq!(
            write_link(b"a%2", &[], &mut out),
            Err(WriteError::Forbidden { at: 1 })
        );
        assert_eq!(
            write_link(b"a", &[("x y", "1")], &mut out),
            Err(WriteError::NotToken)
        );
        assert_eq!(
            write_link(b"a", &[("x", "\r")], &mut out),
            Err(WriteError::Forbidden { at: 0 })
        );
        assert!(out.is_empty());
        let mut small = [0u8; 4];
        let mut s = crate::SliceSink::new(&mut small);
        assert_eq!(write_link(b"abcd", &[], &mut s), Err(WriteError::Full));
        assert!(s.is_empty());
        write_link(
            b"/x?a=1,2",
            &[("rel", "next prev"), ("crossorigin", "")],
            &mut out,
        )
        .unwrap();
        let v = one(out.written());
        assert_eq!(v.target(), b"/x?a=1,2");
        assert!(v.has_rel("prev"));
        assert_eq!(v.params().iter().nth(1), Some((&b"crossorigin"[..], None)));
    }

    #[test]
    fn test_link_long_input_linear() {
        let mut v = Vec::new();
        for _ in 0..1000 {
            v.extend_from_slice(b"<a,b>; rel=x, ");
        }
        let l = Limits::DEFAULT.max_list_members(u16::MAX);
        assert_eq!(parse_link(&v, &l).unwrap().iter().count(), 1000);
    }
}
