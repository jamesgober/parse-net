//! RFC 2045 section 5.1 parameters with RFC 2231 continuations and
//! extended values.

use super::cfws;
use crate::{
    class,
    error::{ErrorKind, ParseError, Result, WriteError, err},
    ext_value::{Charset, ExtValue},
    limits::{Limits, MAX_RFC2231_SECTIONS},
    param::{MAX_CHECKED_PARAMS, Names},
    scan::control_kind,
    text::{Word, parse_quoted},
    write::{CountSink, Sink, reserve},
};

/// Limits for walking text that was already validated.
const RELAXED: Limits = Limits::DEFAULT
    .max_params(u16::MAX)
    .max_comment_depth(u8::MAX);

/// How a parameter name takes part in RFC 2231.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Section {
    /// `name`.
    Plain,
    /// `name*`: one extended value.
    Ext,
    /// `name*N` or `name*N*`.
    Part { n: usize, ext: bool },
}

/// Splits `name*N*` into the base name and its section.
fn split_name(name: &[u8]) -> (&[u8], Section) {
    let (body, ext) = match name.split_last() {
        Some((b'*', body)) => (body, true),
        _ => (name, false),
    };
    if let Some(star) = body.iter().rposition(|&b| b == b'*') {
        let digits = body.get(star + 1..).unwrap_or(&[]);
        let canonical = !digits.is_empty()
            && digits.len() <= 3
            && digits.iter().all(u8::is_ascii_digit)
            && (digits.len() == 1 || digits.first() != Some(&b'0'));
        if canonical {
            let n = digits
                .iter()
                .fold(0usize, |a, &d| a * 10 + usize::from(d - b'0'));
            return (body.get(..star).unwrap_or(&[]), Section::Part { n, ext });
        }
    }
    if ext {
        (body, Section::Ext)
    } else {
        (name, Section::Plain)
    }
}

fn refused(v: &[u8], at: usize, kind: ErrorKind) -> ParseError {
    match v.get(at) {
        Some(&b) if crate::scan::is_control(b) => ParseError::new(control_kind(b), at),
        _ => ParseError::new(kind, at),
    }
}

/// One `; attribute = value` at `v[i]` (the `;`); returns the name, value,
/// where the value starts, and the index after it.
fn param_at<'a>(
    v: &'a [u8],
    i: usize,
    limits: &Limits,
) -> Result<(&'a [u8], Word<'a>, usize, usize)> {
    let j = cfws(v, i + 1, limits)?;
    let n = v
        .get(j..)
        .unwrap_or(&[])
        .iter()
        .take_while(|&&b| class::is_mime_token_char(b))
        .count();
    if n == 0 {
        return Err(refused(v, j, ErrorKind::NotToken));
    }
    let name = v.get(j..j + n).unwrap_or(&[]);
    let k = cfws(v, j + n, limits)?;
    if v.get(k) != Some(&b'=') {
        return Err(refused(v, k, ErrorKind::MissingValue));
    }
    let at = cfws(v, k + 1, limits)?;
    let rest = v.get(at..).unwrap_or(&[]);
    if rest.first() == Some(&b'"') {
        let (q, used) = parse_quoted(rest).map_err(|e| e.shifted(at))?;
        return Ok((name, Word::Quoted(q), at, at + used));
    }
    let t = rest
        .iter()
        .take_while(|&&b| class::is_mime_token_char(b))
        .count();
    if t == 0 {
        return Err(refused(v, at, ErrorKind::MissingValue));
    }
    Ok((name, Word::Token(rest.get(..t).unwrap_or(&[])), at, at + t))
}

/// Whether `t` is RFC 2231 `extended-other-values`: attr-chars and `%XX`.
fn pct_chars(t: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    while let Some(&b) = t.get(i) {
        if b == b'%' {
            match (t.get(i + 1), t.get(i + 2)) {
                (Some(&h), Some(&l)) if class::is_hexdig(h) && class::is_hexdig(l) => i += 3,
                _ => return Some(i),
            }
        } else if class::is_attr_char(b) {
            i += 1;
        } else {
            return Some(i);
        }
    }
    None
}

/// Parses `*( ";" attribute "=" value )` (RFC 2045 section 5.1) with the MIME
/// token class, CFWS between the parts, and case-insensitive names, and
/// validates every RFC 2231 extended value and continuation. Returns the
/// parameters and the bytes used (parsing stops at the first byte that does
/// not start another parameter).
///
/// # Errors
///
/// [`ErrorKind::NotToken`], [`ErrorKind::MissingValue`],
/// [`ErrorKind::DuplicateParameter`], [`ErrorKind::UnterminatedQuote`],
/// [`ErrorKind::TooManyMembers`] beyond `max_params` or
/// [`MAX_CHECKED_PARAMS`](crate::param::MAX_CHECKED_PARAMS); for RFC 2231:
/// [`ErrorKind::SectionGap`], [`ErrorKind::TooManySections`] beyond
/// `max_rfc2231_sections`, the [`ExtValue::parse`] errors (a charset outside
/// section 0 is [`ErrorKind::InvalidPercentEncoding`] at its `'`),
/// [`ErrorKind::InvalidUtf8`], [`ErrorKind::ControlInDecoded`];
/// [`ErrorKind::UnbalancedComment`], [`ErrorKind::CommentTooDeep`].
///
/// # Examples
///
/// ```
/// use parse_net::{mail, Limits};
///
/// let (p, used) = mail::parse_mime_params(b"; charset=\"utf-8\" (comment); format=flowed rest", &Limits::DEFAULT)?;
/// assert_eq!((p.len(), used), (2, 42));
/// let mut buf = [0u8; 8];
/// assert_eq!(p.decode_into("CHARSET", &mut buf)?, Some("utf-8"));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_mime_params<'a>(s: &'a [u8], limits: &Limits) -> Result<(MimeParams<'a>, usize)> {
    let (mut i, mut count) = (0usize, 0usize);
    let max = usize::from(limits.params).min(MAX_CHECKED_PARAMS);
    let mut names = Names::new();
    loop {
        let j = cfws(s, i, limits)?;
        if s.get(j) != Some(&b';') {
            break;
        }
        let (name, value, at, end) = param_at(s, j, limits)?;
        count += 1;
        if count > max {
            return err(ErrorKind::TooManyMembers, j);
        }
        let name_at = (name.as_ptr() as usize).saturating_sub(s.as_ptr() as usize);
        if names.repeats(s, name_at, name, class::is_mime_token_char) {
            return err(ErrorKind::DuplicateParameter, j);
        }
        match (split_name(name).1, value) {
            (Section::Ext | Section::Part { n: 0, ext: true }, Word::Token(t)) => {
                let ext = ExtValue::parse(t).map_err(|e| e.shifted(at))?;
                if split_name(name).1 == Section::Ext {
                    ext.check_text()
                        .map_err(|e| ParseError::new(e.kind(), at))?;
                }
            }
            (Section::Part { ext: true, .. }, Word::Token(t)) => {
                if let Some(bad) = pct_chars(t) {
                    return err(ErrorKind::InvalidPercentEncoding, at + bad);
                }
            }
            (Section::Ext | Section::Part { ext: true, .. }, Word::Quoted(_)) => {
                // Extended values are tokens (RFC 2231 section 7).
                return err(ErrorKind::InvalidCharset, at);
            }
            _ => {}
        }
        i = end;
    }
    let params = MimeParams {
        text: s.get(..i).unwrap_or(&[]),
        count,
    };
    // Every continuation must be whole and decodable.
    for (name, _) in params.iter() {
        if let (base, Section::Part { n: 0, .. }) = split_name(name) {
            let c = Continuation { params, name: base };
            let _ = c.walk(limits, &mut |_| {})?;
        } else if let (base, Section::Part { .. }) = split_name(name) {
            let has_zero = params
                .iter()
                .any(|(n, _)| matches!(split_name(n), (b, Section::Part { n: 0, .. }) if b.eq_ignore_ascii_case(base)));
            if !has_zero {
                return err(ErrorKind::SectionGap, 0);
            }
        }
    }
    Ok((params, i))
}

/// Validated MIME parameters.
///
/// # Examples
///
/// ```
/// use parse_net::{mail, Limits};
///
/// let (p, _) = mail::parse_mime_params(b"; charset=us-ascii", &Limits::DEFAULT)?;
/// let mut buf = [0u8; 16];
/// assert_eq!(p.decode_into("charset", &mut buf)?, Some("us-ascii"));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MimeParams<'a> {
    text: &'a [u8],
    count: usize,
}

impl<'a> MimeParams<'a> {
    /// The value of `name` (case-insensitive): a continuation when
    /// `name*0` or `name*0*` is present, else the extended `name*`, else the
    /// plain `name`.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{mail::{self, MimeValue}, Limits};
    ///
    /// let (p, _) = mail::parse_mime_params(b"; name=plain.txt; name*=UTF-8''ext.txt", &Limits::DEFAULT)?;
    /// assert!(matches!(p.get("NAME"), Some(MimeValue::Extended(e)) if e.encoded() == b"ext.txt"));
    /// assert!(p.get("other").is_none());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn get(&self, name: &str) -> Option<MimeValue<'a>> {
        let want = name.as_bytes();
        let mut ext = None;
        let mut plain = None;
        for (n, w) in self.iter() {
            match split_name(n) {
                (b, Section::Part { n: 0, .. }) if b.eq_ignore_ascii_case(want) => {
                    return Some(MimeValue::Continued(Continuation {
                        params: *self,
                        name: b,
                    }));
                }
                (b, Section::Ext) if b.eq_ignore_ascii_case(want) => {
                    if let Word::Token(t) = w {
                        ext = ExtValue::parse(t).ok();
                    }
                }
                (b, Section::Plain) if b.eq_ignore_ascii_case(want) => plain = Some(w),
                _ => {}
            }
        }
        ext.map(MimeValue::Extended).or(plain.map(MimeValue::Plain))
    }

    /// Decodes the value of `name` into `out` (as [`get`](Self::get)
    /// chooses it); `Ok(None)` when absent.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::BufferTooSmall`]; [`ErrorKind::InvalidUtf8`] for a plain
    /// value that is not UTF-8. Nothing is written on error.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{mail, ErrorKind, Limits};
    ///
    /// let (p, _) = mail::parse_mime_params(b"; boundary=\"simple boundary\"", &Limits::DEFAULT)?;
    /// let mut buf = [0u8; 32];
    /// assert_eq!(p.decode_into("boundary", &mut buf)?, Some("simple boundary"));
    /// assert_eq!(p.decode_into("charset", &mut buf)?, None);
    /// assert_eq!(p.decode_into("boundary", &mut [0u8; 4]).unwrap_err().kind(), ErrorKind::BufferTooSmall);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn decode_into<'b>(&self, name: &str, out: &'b mut [u8]) -> Result<Option<&'b str>> {
        match self.get(name) {
            None => Ok(None),
            Some(MimeValue::Continued(c)) => c.decode_into(out).map(Some),
            Some(MimeValue::Extended(e)) => e.decode_into(out).map(Some),
            Some(MimeValue::Plain(w)) => {
                let len = w.len();
                let Some(dst) = out.get_mut(..len) else {
                    return err(ErrorKind::BufferTooSmall, 0);
                };
                let utf8 = core::str::from_utf8(w.unescape_into(dst)?).is_ok();
                if !utf8 {
                    dst.fill(0);
                    return err(ErrorKind::InvalidUtf8, 0);
                }
                core::str::from_utf8(dst)
                    .map(Some)
                    .map_err(|e| ParseError::new(ErrorKind::InvalidUtf8, e.valid_up_to()))
            }
        }
    }

    /// The parameters as sent, sections included, in order.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{mail, Limits};
    ///
    /// let (p, _) = mail::parse_mime_params(b"; a*0=x; a*1=y", &Limits::DEFAULT)?;
    /// let names: Vec<&[u8]> = p.iter().map(|(name, _)| name).collect();
    /// assert_eq!(names, [&b"a*0"[..], b"a*1"]);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn iter(&self) -> MimeParamIter<'a> {
        MimeParamIter { s: self.text, i: 0 }
    }

    /// The number of parameters, sections counted one by one.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{mail, Limits};
    ///
    /// let (p, _) = mail::parse_mime_params(b"; a*0=x; a*1=y; b=z", &Limits::DEFAULT)?;
    /// assert_eq!(p.len(), 3);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether there are no parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{mail, Limits};
    ///
    /// let (p, used) = mail::parse_mime_params(b" no params", &Limits::DEFAULT)?;
    /// assert!(p.is_empty() && used == 0);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// The parameters of a validated [`MimeParams`].
///
/// # Examples
///
/// ```
/// use parse_net::{mail, Limits};
///
/// let (p, _) = mail::parse_mime_params(b"; format=flowed", &Limits::DEFAULT)?;
/// let mut it = p.iter();
/// let (name, value) = it.next().expect("one parameter");
/// assert!(name == b"format" && value.eq_bytes(b"flowed"));
/// assert!(it.next().is_none());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Debug)]
pub struct MimeParamIter<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Iterator for MimeParamIter<'a> {
    type Item = (&'a [u8], Word<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        let j = cfws(self.s, self.i, &RELAXED).ok()?;
        if self.s.get(j) != Some(&b';') {
            return None;
        }
        let (name, value, _, end) = param_at(self.s, j, &RELAXED).ok()?;
        self.i = end;
        Some((name, value))
    }
}

/// A MIME parameter value.
///
/// # Examples
///
/// ```
/// use parse_net::{mail::{self, MimeValue}, Limits};
///
/// let (p, _) = mail::parse_mime_params(b"; size=10; t*0=a; t*1=b", &Limits::DEFAULT)?;
/// assert!(matches!(p.get("size"), Some(MimeValue::Plain(w)) if w.eq_bytes(b"10")));
/// assert!(matches!(p.get("t"), Some(MimeValue::Continued(_))));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MimeValue<'a> {
    /// `name=value`.
    Plain(Word<'a>),
    /// `name*=charset'lang'value`.
    Extended(ExtValue<'a>),
    /// `name*0`, `name*1*`, ...: RFC 2231 continuations.
    Continued(Continuation<'a>),
}

/// The sections of an RFC 2231 continued value, validated at parse.
///
/// # Examples
///
/// ```
/// use parse_net::{mail::{self, MimeValue}, Limits};
///
/// let (p, _) = mail::parse_mime_params(b"; url*0=\"http://a.example/\"; url*1=\"b\"", &Limits::DEFAULT)?;
/// let Some(MimeValue::Continued(c)) = p.get("url") else { unreachable!() };
/// let mut buf = [0u8; 32];
/// assert_eq!(c.decode_into(&mut buf)?, "http://a.example/b");
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Continuation<'a> {
    params: MimeParams<'a>,
    name: &'a [u8],
}

impl Continuation<'_> {
    /// The number of sections.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{mail::{self, MimeValue}, Limits};
    ///
    /// let (p, _) = mail::parse_mime_params(b"; n*0=a; n*1=b; n*2=c", &Limits::DEFAULT)?;
    /// let Some(MimeValue::Continued(c)) = p.get("n") else { unreachable!() };
    /// assert_eq!(c.sections(), 3);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn sections(&self) -> usize {
        self.params
            .iter()
            .filter(|(n, _)| matches!(split_name(n), (b, Section::Part { .. }) if b.eq_ignore_ascii_case(self.name)))
            .count()
    }

    /// An upper bound on the decoded length (twice the raw length, for
    /// ISO-8859-1 transcoded to UTF-8).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{mail::{self, MimeValue}, Limits};
    ///
    /// let (p, _) = mail::parse_mime_params(b"; t*0=abc; t*1=de", &Limits::DEFAULT)?;
    /// let Some(MimeValue::Continued(c)) = p.get("t") else { unreachable!() };
    /// assert_eq!(c.max_decoded_len(), 10);
    /// let mut buf = [0u8; 10];
    /// assert_eq!(c.decode_into(&mut buf)?, "abcde");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn max_decoded_len(&self) -> usize {
        self.params
            .iter()
            .filter(|(n, _)| matches!(split_name(n), (b, Section::Part { .. }) if b.eq_ignore_ascii_case(self.name)))
            .map(|(_, w)| w.len().saturating_mul(2))
            .sum()
    }

    /// Decodes the sections in order into `out`: `%XX` in extended sections,
    /// the charset of section 0 (UTF-8 or ISO-8859-1, transcoded).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::BufferTooSmall`]; nothing is written on error.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{mail::{self, MimeValue}, Limits};
    ///
    /// let (p, _) = mail::parse_mime_params(b"; title*0*=iso-8859-1'en'%A3; title*1=\" rates\"", &Limits::DEFAULT)?;
    /// let Some(MimeValue::Continued(c)) = p.get("title") else { unreachable!() };
    /// let mut buf = [0u8; 16];
    /// assert_eq!((c.sections(), c.decode_into(&mut buf)?), (2, "\u{a3} rates"));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn decode_into<'b>(&self, out: &'b mut [u8]) -> Result<&'b str> {
        let len = self.walk(&RELAXED, &mut |_| {})?;
        let Some(dst) = out.get_mut(..len) else {
            return err(ErrorKind::BufferTooSmall, 0);
        };
        let mut n = 0usize;
        let _ = self.walk(&RELAXED, &mut |b: u8| {
            if let Some(d) = dst.get_mut(n) {
                *d = b;
            }
            n += 1;
        })?;
        core::str::from_utf8(dst)
            .map_err(|e| ParseError::new(ErrorKind::InvalidUtf8, e.valid_up_to()))
    }

    /// Orders the sections, checks them, and emits the decoded UTF-8 bytes;
    /// returns their count.
    fn walk(&self, limits: &Limits, emit: &mut impl FnMut(u8)) -> Result<usize> {
        let mut slots: [Option<(bool, Word<'_>)>; MAX_RFC2231_SECTIONS as usize] =
            [None; MAX_RFC2231_SECTIONS as usize];
        let max = usize::from(limits.rfc2231_sections.min(MAX_RFC2231_SECTIONS));
        let mut highest = 0usize;
        for (name, w) in self.params.iter() {
            if let (b, Section::Part { n, ext }) = split_name(name) {
                if !b.eq_ignore_ascii_case(self.name) {
                    continue;
                }
                if n >= max {
                    return err(ErrorKind::TooManySections, 0);
                }
                if let Some(slot) = slots.get_mut(n) {
                    *slot = Some((ext, w));
                }
                highest = highest.max(n);
            }
        }
        let used = slots.get(..=highest).unwrap_or(&[]);
        if used.iter().any(Option::is_none) {
            return err(ErrorKind::SectionGap, 0);
        }
        let mut charset = Charset::Utf8;
        let mut utf8 = crate::utf8::Utf8::new();
        let mut count = 0usize;
        let mut put = |b: u8, charset: Charset, count: &mut usize| -> Result<()> {
            let decoded = [0xc0 | (b >> 6), 0x80 | (b & 0x3f)];
            let bytes: &[u8] = if charset == Charset::Iso8859_1 && b >= 0x80 {
                &decoded
            } else {
                core::slice::from_ref(&b)
            };
            for &x in bytes {
                if !utf8.push(x) {
                    return err(ErrorKind::InvalidUtf8, 0);
                }
                emit(x);
                *count += 1;
            }
            Ok(())
        };
        for (k, slot) in used.iter().enumerate() {
            let Some((ext, w)) = *slot else { continue };
            let raw: &[u8] = match (k, ext, w) {
                (0, true, Word::Token(t)) => {
                    let e = ExtValue::parse(t)?;
                    charset = e.charset();
                    e.encoded()
                }
                (_, true, Word::Token(t)) => t,
                _ => &[],
            };
            if ext {
                let mut i = 0usize;
                while let Some(&b) = raw.get(i) {
                    let byte = if b == b'%' {
                        let hi = raw
                            .get(i + 1)
                            .copied()
                            .and_then(class::hex_value)
                            .unwrap_or(0);
                        let lo = raw
                            .get(i + 2)
                            .copied()
                            .and_then(class::hex_value)
                            .unwrap_or(0);
                        i += 3;
                        (hi << 4) | lo
                    } else {
                        i += 1;
                        b
                    };
                    if byte < 0x20 || byte == 0x7f {
                        return err(ErrorKind::ControlInDecoded, 0);
                    }
                    if charset == Charset::UsAscii && byte >= 0x80 {
                        return err(ErrorKind::InvalidByte, 0);
                    }
                    put(byte, charset, &mut count)?;
                }
            } else {
                match w {
                    Word::Token(t) => {
                        for &byte in t {
                            put(byte, charset, &mut count)?;
                        }
                    }
                    Word::Quoted(q) => {
                        for byte in q.bytes() {
                            put(byte, charset, &mut count)?;
                        }
                    }
                }
            }
        }
        if !utf8.is_complete() {
            return err(ErrorKind::InvalidUtf8, 0);
        }
        Ok(count)
    }
}

/// The bytes a parameter name may hold: MIME token characters except `*`,
/// `'`, and `%`, which RFC 2231 gives meaning to.
fn is_attribute(name: &[u8]) -> bool {
    !name.is_empty()
        && name
            .iter()
            .all(|&b| class::is_mime_token_char(b) && !matches!(b, b'*' | b'\'' | b'%'))
}

/// The line length writers keep to.
const LINE: usize = 78;

/// The length of `b` in an extended value: 1 for an attr-char, else 3.
const fn unit_len(b: u8) -> usize {
    if class::is_attr_char(b) { 1 } else { 3 }
}

/// Writes `b` in an extended value: itself or `%XX`.
fn put_unit(b: u8, out: &mut impl Sink) -> core::result::Result<(), WriteError> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    if class::is_attr_char(b) {
        out.put(&[b])?;
    } else {
        let hi = HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0');
        let lo = HEX.get(usize::from(b & 0xf)).copied().unwrap_or(b'0');
        out.put(&[b'%', hi, lo])?;
    }
    Ok(())
}

fn put_param(name: &str, value: &str, out: &mut impl Sink) -> core::result::Result<(), WriteError> {
    let (n, v) = (name.as_bytes(), value.as_bytes());
    if !v.is_empty()
        && v.iter().all(|&b| class::is_mime_token_char(b))
        && 3 + n.len() + v.len() <= LINE
    {
        out.put(b"; ")?;
        out.put(n)?;
        out.put(b"=")?;
        out.put(v)?;
        return Ok(());
    }
    let escaped = v.iter().filter(|&&b| b == b'"' || b == b'\\').count();
    if v.iter().all(|&b| (0x20..=0x7e).contains(&b)) && 5 + n.len() + v.len() + escaped <= LINE {
        out.put(b"; ")?;
        out.put(n)?;
        out.put(b"=\"")?;
        for &b in v {
            if b == b'"' || b == b'\\' {
                out.put(b"\\")?;
            }
            out.put(&[b])?;
        }
        out.put(b"\"")?;
        return Ok(());
    }
    let encoded: usize = v.iter().map(|&b| unit_len(b)).sum();
    if 4 + n.len() + 7 + encoded <= LINE {
        out.put(b"; ")?;
        out.put(n)?;
        out.put(b"*=UTF-8''")?;
        for &b in v {
            put_unit(b, out)?;
        }
        return Ok(());
    }
    // Sections, one per line: `;CRLF name*k*=...`, each line within 78
    // columns with its trailing `;`.
    out.put(b";")?;
    let mut rest = v;
    let mut k = 0usize;
    while !rest.is_empty() || k == 0 {
        if k >= usize::from(MAX_RFC2231_SECTIONS) {
            return Err(WriteError::OutOfRange);
        }
        let mut digits = [0u8; 2];
        let dl = if k < 10 {
            digits[0] = b'0' + k as u8;
            1
        } else {
            digits[0] = b'0' + (k / 10) as u8;
            digits[1] = b'0' + (k % 10) as u8;
            2
        };
        if k > 0 {
            out.put(b";")?;
        }
        out.put(b"\r\n ")?;
        out.put(n)?;
        out.put(b"*")?;
        out.put(digits.get(..dl).unwrap_or(&[]))?;
        out.put(b"*=")?;
        let mut col = 1 + n.len() + 1 + dl + 2;
        if k == 0 {
            out.put(b"UTF-8''")?;
            col += 7;
        }
        let mut took = 0usize;
        for &b in rest {
            let u = unit_len(b);
            // One column stays for the `;` that may follow.
            if col + u + 1 > LINE && took > 0 {
                break;
            }
            put_unit(b, out)?;
            col += u;
            took += 1;
        }
        rest = rest.get(took..).unwrap_or(&[]);
        k += 1;
    }
    Ok(())
}

/// Writes `; name=value`: as a token, as a quoted string, or, for non-ASCII
/// or long values, as `; name*=UTF-8''...`, split into `name*0*`,
/// `name*1*` sections on folded lines when one line would pass 78 columns.
/// The output parses back with [`parse_mime_params`] to the same value.
///
/// # Errors
///
/// [`WriteError::NotToken`] for a name that is not a MIME token or holds `*`,
/// `'`, or `%`; [`WriteError::Forbidden`] for a control character in
/// `value`; [`WriteError::OutOfRange`] for a value needing more than 32
/// sections; [`WriteError::Full`] (nothing written when the sink reports its
/// room).
///
/// # Examples
///
/// ```
/// use parse_net::{mail, SliceSink};
///
/// let mut buf = [0u8; 64];
/// let mut out = SliceSink::new(&mut buf);
/// mail::write_mime_param("filename", "caf\u{e9}.txt", &mut out)?;
/// assert_eq!(out.written(), b"; filename*=UTF-8''caf%C3%A9.txt");
/// # Ok::<(), parse_net::WriteError>(())
/// ```
pub fn write_mime_param(
    name: &str,
    value: &str,
    out: &mut impl Sink,
) -> core::result::Result<(), WriteError> {
    if !is_attribute(name.as_bytes()) {
        return Err(WriteError::NotToken);
    }
    if let Some((at, _)) = value.char_indices().find(|&(_, c)| c.is_control()) {
        return Err(WriteError::forbidden(at));
    }
    let mut count = CountSink::new();
    put_param(name, value, &mut count)?;
    reserve(out, count.count())?;
    put_param(name, value, out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{format, string::String, vec, vec::Vec};

    fn p(v: &[u8]) -> MimeParams<'_> {
        parse_mime_params(v, &Limits::DEFAULT).unwrap().0
    }

    fn k(v: &[u8]) -> ErrorKind {
        parse_mime_params(v, &Limits::DEFAULT).unwrap_err().kind()
    }

    fn get(v: &[u8], name: &str) -> String {
        let mut buf = vec![0u8; 512];
        String::from(p(v).decode_into(name, &mut buf).unwrap().unwrap())
    }

    #[test]
    fn test_mime_params_basic() {
        assert_eq!(get(b"; a=b; c=\"d e\"", "C"), "d e");
        assert_eq!(get(b"; boundary={x}", "boundary"), "{x}");
        assert_eq!(get(b" ; a = (c) b (d)", "a"), "b");
        assert_eq!(get(b";\r\n a=b", "a"), "b");
        assert!(
            p(b"; a=b")
                .decode_into("z", &mut [0u8; 4])
                .unwrap()
                .is_none()
        );
        assert_eq!(parse_mime_params(b"", &Limits::DEFAULT).unwrap().1, 0);
        assert_eq!(
            parse_mime_params(b"; a=b x", &Limits::DEFAULT).unwrap().1,
            5
        );
        assert_eq!(k(b"; =b"), ErrorKind::NotToken);
        assert_eq!(k(b"; a"), ErrorKind::MissingValue);
        assert_eq!(k(b"; a="), ErrorKind::MissingValue);
        assert_eq!(k(b"; a=\"b"), ErrorKind::UnterminatedQuote);
        assert_eq!(k(b"; a=1; A=2"), ErrorKind::DuplicateParameter);
        assert_eq!(k(b"; a=1 (x"), ErrorKind::UnbalancedComment);
        let l = Limits::DEFAULT.max_params(2);
        assert!(parse_mime_params(b"; a=1; b=2", &l).is_ok());
        assert_eq!(
            parse_mime_params(b"; a=1; b=2; c=3", &l)
                .unwrap_err()
                .kind(),
            ErrorKind::TooManyMembers
        );
    }

    #[test]
    fn test_mime_params_rfc2231() {
        assert_eq!(
            get(
                b"; t*=us-ascii'en-us'This%20is%20%2A%2A%2Afun%2A%2A%2A",
                "t"
            ),
            "This is ***fun***"
        );
        assert_eq!(get(b"; t*0=\"foo\"; t*1=bar", "t"), "foobar");
        assert_eq!(get(b"; t*1=bar; t*0=\"foo\"", "t"), "foobar");
        assert_eq!(get(b"; t*0*=UTF-8''%E2%82; t*1*=%AC", "t"), "\u{20ac}");
        assert_eq!(get(b"; t=plain; t*=UTF-8''ext", "t"), "ext");
        assert_eq!(get(b"; t=plain; t*0=cont", "t"), "cont");
        assert_eq!(get(b"; t*00=x; t=plain", "t"), "plain");
        assert_eq!(k(b"; t*0=a; t*2=c"), ErrorKind::SectionGap);
        assert_eq!(k(b"; t*1=a"), ErrorKind::SectionGap);
        assert_eq!(k(b"; t*0=a; t*0=b"), ErrorKind::DuplicateParameter);
        assert_eq!(
            k(b"; t*0*=UTF-8''a; t*1*=UTF-8''b"),
            ErrorKind::InvalidPercentEncoding
        );
        assert_eq!(k(b"; t*0*=UTF-8''%C3"), ErrorKind::InvalidUtf8);
        assert_eq!(k(b"; t*0*=UTF-8''%0D"), ErrorKind::ControlInDecoded);
        assert_eq!(k(b"; t*=\"UTF-8''x\""), ErrorKind::InvalidCharset);
        let mut v = Vec::new();
        for i in 0..32 {
            v.extend_from_slice(format!("; t*{i}=x").as_bytes());
        }
        assert_eq!(
            p(&v)
                .get("t")
                .map(|m| matches!(m, MimeValue::Continued(c) if c.sections() == 32)),
            Some(true)
        );
        v.extend_from_slice(b"; t*32=x");
        assert_eq!(k(&v), ErrorKind::TooManySections);
        let l = Limits::DEFAULT.max_rfc2231_sections(2);
        assert!(parse_mime_params(b"; t*0=a; t*1=b", &l).is_ok());
        assert_eq!(
            parse_mime_params(b"; t*0=a; t*1=b; t*2=c", &l)
                .unwrap_err()
                .kind(),
            ErrorKind::TooManySections
        );
    }

    fn written(name: &str, value: &str) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        let mut out = crate::SliceSink::new(&mut buf);
        write_mime_param(name, value, &mut out).unwrap();
        out.written().to_vec()
    }

    #[test]
    fn test_write_mime_param_forms_and_round_trip() {
        assert_eq!(written("charset", "utf-8"), b"; charset=utf-8");
        assert_eq!(written("name", "a \"b\""), b"; name=\"a \\\"b\\\"\"");
        assert_eq!(written("name", ""), b"; name=\"\"");
        let long = "x".repeat(200);
        let nonascii = "\u{e9}".repeat(60);
        for value in [
            String::from("plain"),
            long,
            nonascii,
            String::from("caf\u{e9} au lait.txt"),
        ] {
            let w = written("filename", &value);
            for line in w.split(|&b| b == b'\n') {
                assert!(line.len() <= 79, "{}", String::from_utf8_lossy(line));
            }
            let (params, used) = parse_mime_params(&w, &Limits::DEFAULT).unwrap();
            assert_eq!(used, w.len());
            let mut buf = vec![0u8; 1024];
            assert_eq!(
                params.decode_into("filename", &mut buf).unwrap(),
                Some(value.as_str())
            );
        }
        let mut buf = [0u8; 8];
        let mut out = crate::SliceSink::new(&mut buf);
        assert_eq!(
            write_mime_param("a*b", "x", &mut out),
            Err(WriteError::NotToken)
        );
        assert_eq!(
            write_mime_param("a", "x\ny", &mut out),
            Err(WriteError::Forbidden { at: 1 })
        );
        assert_eq!(
            write_mime_param("a", "toolongvalue", &mut out),
            Err(WriteError::Full)
        );
        assert!(out.is_empty());
        let mut big = vec![0u8; 1 << 16];
        let mut out = crate::SliceSink::new(&mut big);
        assert_eq!(
            write_mime_param("f", &"\u{e9}".repeat(1000), &mut out),
            Err(WriteError::OutOfRange)
        );
    }
}
