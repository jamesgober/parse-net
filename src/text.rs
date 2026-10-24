//! The lexical forms of RFC 9110 section 5.6: tokens, optional whitespace,
//! quoted strings, words (`token / quoted-string`), and comments.
//!
//! # Examples
//!
//! ```
//! use parse_net::text;
//!
//! assert!(text::is_token(b"no-cache") && !text::is_token(b"no cache"));
//! assert_eq!(text::trim_ows(b" \t gzip \t"), b"gzip");
//! let (q, used) = text::parse_quoted(b"\"a \\\"b\\\" c\"; x")?;
//! assert_eq!(used, 11);
//! assert!(q.eq_bytes(b"a \"b\" c"));
//! # Ok::<(), parse_net::ParseError>(())
//! ```

use core::fmt;

use crate::{
    class,
    error::{ErrorKind, Result, err},
    limits::Limits,
    scan::control_kind,
};

/// Whether `s` is a token: non-empty, every byte `tchar` (RFC 9110 section
/// 5.6.2).
///
/// # Examples
///
/// ```
/// use parse_net::text::is_token;
///
/// assert!(is_token(b"GET") && !is_token(b"GE T") && !is_token(b""));
/// ```
#[inline]
#[must_use]
pub fn is_token(s: &[u8]) -> bool {
    !s.is_empty() && class::all(s, class::Class::TCHAR)
}

/// Whether `b` is optional whitespace: SP or HTAB only.
///
/// # Examples
///
/// ```
/// use parse_net::text::is_ows;
///
/// assert!(is_ows(b' ') && is_ows(b'\t') && !is_ows(0x0b));
/// ```
#[inline]
#[must_use]
pub const fn is_ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// `s` without leading and trailing SP and HTAB.
///
/// `<[u8]>::trim_ascii` is deliberately not used: it also strips vertical tab
/// and form feed, which are invalid in a field value and must be refused, not
/// silently removed. NBSP and every other byte stay too.
///
/// # Examples
///
/// ```
/// use parse_net::text::trim_ows;
///
/// assert_eq!(trim_ows(b" \t a b \t"), b"a b");
/// assert_eq!(trim_ows(b"\x0ba\x0c"), b"\x0ba\x0c");
/// assert_eq!(trim_ows(b"   "), b"");
/// ```
#[inline]
#[must_use]
pub fn trim_ows(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if is_ows(*first) {
            s = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = s {
        if is_ows(*last) {
            s = rest;
        } else {
            break;
        }
    }
    s
}

/// The number of leading SP and HTAB bytes in `s`.
///
/// # Examples
///
/// ```
/// assert_eq!(parse_net::text::skip_ows(b" \t x"), 3);
/// ```
#[inline]
#[must_use]
pub fn skip_ows(s: &[u8]) -> usize {
    s.iter().take_while(|&&b| is_ows(b)).count()
}

/// The length of the longest token prefix of `s` (0 when `s` does not start
/// with a `tchar`).
#[inline]
pub(crate) fn token_len(s: &[u8]) -> usize {
    s.iter()
        .position(|&b| !class::is_tchar(b))
        .unwrap_or(s.len())
}

/// The word at the front of text a parser has already validated: the view
/// and the bytes used. Nothing is checked again; quoted strings are only
/// scanned for their closing quote.
#[inline]
pub(crate) fn validated_word(s: &[u8]) -> (Word<'_>, usize) {
    let Some((&b'"', body)) = s.split_first() else {
        let n = token_len(s);
        return (Word::Token(s.get(..n).unwrap_or(&[])), n);
    };
    let mut has_escapes = false;
    let mut rest = body;
    loop {
        match rest {
            [b'"', ..] | [] => break,
            [b'\\', _, tail @ ..] => {
                has_escapes = true;
                rest = tail;
            }
            [_, tail @ ..] => rest = tail,
        }
    }
    let len = body.len() - rest.len();
    let raw = body.get(..len).unwrap_or(&[]);
    (Word::Quoted(Quoted { raw, has_escapes }), len + 2)
}

/// The longest token prefix of `s`, and its length.
///
/// The rest of `s` is the caller's to check.
///
/// # Errors
///
/// [`ErrorKind::Empty`] when `s` does not start with a `tchar`.
///
/// # Examples
///
/// ```
/// use parse_net::text::parse_token;
///
/// assert_eq!(parse_token(b"charset=utf-8")?, (&b"charset"[..], 7));
/// assert!(parse_token(b"=x").is_err());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_token(s: &[u8]) -> Result<(&[u8], usize)> {
    let n = token_len(s);
    if n == 0 {
        return err(ErrorKind::Empty, 0);
    }
    Ok((s.get(..n).unwrap_or(&[]), n))
}

/// The error for a byte refused inside a quoted string or comment.
#[inline]
const fn refused(b: u8) -> ErrorKind {
    if crate::scan::is_control(b) {
        control_kind(b)
    } else {
        ErrorKind::InvalidByte
    }
}

/// Parses the quoted string at the start of `s` (RFC 9110 section 5.6.4).
///
/// Returns the view and the length used, both quotes included.
///
/// # Errors
///
/// [`ErrorKind::InvalidByte`] at offset 0 when `s` does not start with `"`;
/// [`ErrorKind::BareCr`], [`ErrorKind::LineFeed`], [`ErrorKind::Nul`], or
/// [`ErrorKind::Control`] for a control byte inside; [`ErrorKind::InvalidQuotedPair`]
/// when the byte after `\` is not `HTAB / SP / VCHAR / obs-text`;
/// [`ErrorKind::UnterminatedQuote`] at the end of input.
///
/// # Examples
///
/// ```
/// use parse_net::text::parse_quoted;
///
/// let (q, used) = parse_quoted(b"\"say \\\"hi\\\"\" rest")?;
/// assert_eq!(used, 12);
/// assert_eq!(q.raw(), b"say \\\"hi\\\"");
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_quoted(s: &[u8]) -> Result<(Quoted<'_>, usize)> {
    let Some((&b'"', body)) = s.split_first() else {
        return err(ErrorKind::InvalidByte, 0);
    };
    let mut has_escapes = false;
    let mut i = 0usize;
    let mut bytes = body.iter();
    while let Some(&b) = bytes.next() {
        match b {
            b'"' => {
                let raw = body.get(..i).unwrap_or(&[]);
                return Ok((Quoted { raw, has_escapes }, i + 2));
            }
            b'\\' => {
                has_escapes = true;
                match bytes.next() {
                    None => return err(ErrorKind::UnterminatedQuote, s.len()),
                    Some(&e) if class::is_quoted_pair_char(e) => i += 2,
                    Some(_) => return err(ErrorKind::InvalidQuotedPair, i + 2),
                }
            }
            _ if class::is_qdtext(b) => i += 1,
            _ => return err(refused(b), i + 1),
        }
    }
    err(ErrorKind::UnterminatedQuote, s.len())
}

/// Parses a word at the start of `s`: a quoted string when `s` starts with
/// `"`, a token otherwise.
///
/// # Errors
///
/// As [`parse_token`] and [`parse_quoted`].
///
/// # Examples
///
/// ```
/// use parse_net::text::parse_word;
///
/// let (a, _) = parse_word(b"utf-8")?;
/// let (b, _) = parse_word(b"\"UTF-8\"")?;
/// assert!(a.eq_ignore_ascii_case(b"UTF-8") && b.eq_ignore_ascii_case(b"utf-8"));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_word(s: &[u8]) -> Result<(Word<'_>, usize)> {
    if s.first() == Some(&b'"') {
        let (q, n) = parse_quoted(s)?;
        Ok((Word::Quoted(q), n))
    } else {
        let (t, n) = parse_token(s)?;
        Ok((Word::Token(t), n))
    }
}

/// Parses the comment at the start of `s` (RFC 9110 section 5.6.5), nested
/// comments included, counted and never recursed.
///
/// Returns the view and the length used, both outer parentheses included.
///
/// # Errors
///
/// [`ErrorKind::InvalidByte`] at offset 0 when `s` does not start with `(`;
/// a control kind for a control byte; [`ErrorKind::InvalidQuotedPair`];
/// [`ErrorKind::UnbalancedComment`] when the comment never closes;
/// [`ErrorKind::CommentTooDeep`] at the `(` that exceeded
/// [`Limits::max_comment_depth`].
///
/// # Examples
///
/// ```
/// use parse_net::{text::parse_comment, Limits};
///
/// let (c, used) = parse_comment(b"(compatible; (nested)) rest", &Limits::DEFAULT)?;
/// assert_eq!((c.raw(), c.max_depth(), used), (&b"compatible; (nested)"[..], 2, 22));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_comment<'a>(s: &'a [u8], limits: &Limits) -> Result<(Comment<'a>, usize)> {
    if s.first() != Some(&b'(') {
        return err(ErrorKind::InvalidByte, 0);
    }
    let end = comment_end(s, 0, limits)?;
    let (end, max_depth) = end;
    let raw = s.get(1..end - 1).unwrap_or(&[]);
    Ok((Comment { raw, max_depth }, end))
}

/// Scans the comment that starts at `s[start]` (an opening `(`). Returns the
/// offset just past its closing `)` and the deepest nesting seen.
pub(crate) fn comment_end(s: &[u8], start: usize, limits: &Limits) -> Result<(usize, u8)> {
    let limit = u16::from(limits.comment_depth);
    let mut depth: u16 = 0;
    let mut max: u16 = 0;
    let mut i = start;
    let mut bytes = s.get(start..).unwrap_or(&[]).iter();
    while let Some(&b) = bytes.next() {
        match b {
            b'(' => {
                depth += 1;
                if depth > limit {
                    return err(ErrorKind::CommentTooDeep, i);
                }
                max = max.max(depth);
                i += 1;
            }
            b')' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    // The limit is a u8, so `max` fits.
                    return Ok((i, u8::try_from(max).unwrap_or(u8::MAX)));
                }
            }
            b'\\' => match bytes.next() {
                None => return err(ErrorKind::UnbalancedComment, s.len()),
                Some(&e) if class::is_quoted_pair_char(e) => i += 2,
                Some(_) => return err(ErrorKind::InvalidQuotedPair, i + 1),
            },
            _ if class::is_ctext(b) => i += 1,
            _ => return err(refused(b), i),
        }
    }
    err(ErrorKind::UnbalancedComment, s.len())
}

/// A validated quoted string: the bytes between the quotes, and whether any
/// quoted pair occurs.
///
/// `Debug` prints the raw bytes as an escaped byte string.
///
/// # Examples
///
/// ```
/// use parse_net::text;
///
/// let (q, _) = text::parse_quoted(b"\"say \\\"hi\\\"\"")?;
/// assert!(q.has_escapes() && q.as_plain().is_none());
/// assert_eq!(q.unescaped_len(), 8);
/// let mut buf = [0u8; 8];
/// assert_eq!(q.unescape_into(&mut buf)?, b"say \"hi\"");
/// assert!(q.eq_bytes(b"say \"hi\""));
/// let mut short = [0u8; 7];
/// assert_eq!(q.unescape_into(&mut short).unwrap_err().kind(), parse_net::ErrorKind::BufferTooSmall);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Quoted<'a> {
    raw: &'a [u8],
    has_escapes: bool,
}

impl<'a> Quoted<'a> {
    /// A view over content already validated by another grammar whose
    /// escapes are `\x` pairs (RFC 9651 strings).
    pub(crate) const fn from_raw(raw: &'a [u8], has_escapes: bool) -> Self {
        Self { raw, has_escapes }
    }

    /// The content between the quotes exactly as sent, quoted pairs included.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::text::parse_quoted;
    ///
    /// let (q, _) = parse_quoted(b"\"a\\\"b\"")?;
    /// assert_eq!(q.raw(), b"a\\\"b");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// Whether the content contains a quoted pair (`\x`).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::text::parse_quoted;
    ///
    /// assert!(parse_quoted(b"\"a\\\"b\"")?.0.has_escapes());
    /// assert!(!parse_quoted(b"\"ab\"")?.0.has_escapes());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn has_escapes(&self) -> bool {
        self.has_escapes
    }

    /// The content when it contains no quoted pair: the value, with no copy.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::text::parse_quoted;
    ///
    /// assert_eq!(parse_quoted(b"\"gzip\"")?.0.as_plain(), Some(&b"gzip"[..]));
    /// assert_eq!(parse_quoted(b"\"a\\\"b\"")?.0.as_plain(), None);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn as_plain(&self) -> Option<&'a [u8]> {
        if self.has_escapes {
            None
        } else {
            Some(self.raw)
        }
    }

    /// The length of the value with quoted pairs replaced.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::text::parse_quoted;
    ///
    /// let (q, _) = parse_quoted(b"\"a\\\"b\"")?;
    /// assert_eq!((q.raw().len(), q.unescaped_len()), (4, 3));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn unescaped_len(&self) -> usize {
        if self.has_escapes {
            self.bytes().count()
        } else {
            self.raw.len()
        }
    }

    /// The bytes of the value with quoted pairs replaced.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::text::parse_quoted;
    ///
    /// let (q, _) = parse_quoted(b"\"a\\\"b\"")?;
    /// assert_eq!(q.bytes().collect::<Vec<u8>>(), b"a\"b");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn bytes(&self) -> Unescape<'a> {
        Unescape {
            rest: self.raw.iter(),
        }
    }

    /// Writes the value into `out`, every quoted pair replaced by the byte
    /// after the backslash, and returns the written part.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::BufferTooSmall`] when `out` is shorter than
    /// [`unescaped_len`](Self::unescaped_len); nothing is written.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::text::parse_quoted;
    ///
    /// let (q, _) = parse_quoted(b"\"a\\\"b\"")?;
    /// let mut buf = [0u8; 8];
    /// assert_eq!(q.unescape_into(&mut buf)?, b"a\"b");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn unescape_into<'b>(&self, out: &'b mut [u8]) -> Result<&'b [u8]> {
        let len = self.unescaped_len();
        let Some(dst) = out.get_mut(..len) else {
            return err(ErrorKind::BufferTooSmall, 0);
        };
        for (d, b) in dst.iter_mut().zip(self.bytes()) {
            *d = b;
        }
        Ok(dst)
    }

    /// Whether the value equals `other`, compared without a buffer.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::text::parse_quoted;
    ///
    /// let (q, _) = parse_quoted(b"\"a\\\"b\"")?;
    /// assert!(q.eq_bytes(b"a\"b") && !q.eq_bytes(b"a\\\"b"));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn eq_bytes(&self, other: &[u8]) -> bool {
        match self.as_plain() {
            Some(p) => p == other,
            None => self.bytes().eq(other.iter().copied()),
        }
    }

    /// Whether the value equals `other` ignoring ASCII case, compared without
    /// a buffer.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::text::parse_quoted;
    ///
    /// let (q, _) = parse_quoted(b"\"UTF\\-8\"")?;
    /// assert!(q.eq_ignore_ascii_case(b"utf-8") && !q.eq_ignore_ascii_case(b"utf8"));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn eq_ignore_ascii_case(&self, other: &[u8]) -> bool {
        match self.as_plain() {
            Some(p) => p.eq_ignore_ascii_case(other),
            None => {
                let mut theirs = other.iter();
                self.bytes()
                    .all(|b| theirs.next().is_some_and(|o| o.eq_ignore_ascii_case(&b)))
                    && theirs.next().is_none()
            }
        }
    }
}

impl fmt::Debug for Quoted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Quoted(\"")?;
        for &b in self.raw {
            for c in core::ascii::escape_default(b) {
                f.write_str(core::str::from_utf8(&[c]).unwrap_or("?"))?;
            }
        }
        f.write_str("\")")
    }
}

/// The unescaped bytes of a [`Quoted`] value.
///
/// # Examples
///
/// ```
/// use parse_net::text::parse_quoted;
///
/// let (q, _) = parse_quoted(b"\"a\\\"b\"")?;
/// let mut it = q.bytes();
/// assert_eq!((it.next(), it.next(), it.next(), it.next()), (Some(b'a'), Some(b'"'), Some(b'b'), None));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Debug)]
pub struct Unescape<'a> {
    rest: core::slice::Iter<'a, u8>,
}

impl Iterator for Unescape<'_> {
    type Item = u8;

    #[inline]
    fn next(&mut self) -> Option<u8> {
        match self.rest.next() {
            Some(&b'\\') => self.rest.next().copied(),
            other => other.copied(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.rest.len();
        (n.div_ceil(2), Some(n))
    }
}

/// `token / quoted-string`: the value form of parameters and directives.
///
/// A token and a quoted string with the same content compare equal, as
/// RFC 9110 section 5.6.6 requires: [`eq_bytes`](Self::eq_bytes) and
/// [`eq_ignore_ascii_case`](Self::eq_ignore_ascii_case) compare unescaped
/// content. The derived `PartialEq` compares the forms structurally.
///
/// # Examples
///
/// ```
/// use parse_net::text;
///
/// let (a, _) = text::parse_word(b"utf-8")?;
/// let (b, _) = text::parse_word(b"\"UTF-8\"")?;
/// assert!(a.eq_ignore_ascii_case(b"UTF-8") && b.eq_ignore_ascii_case(b"utf-8"));
/// assert_eq!(b.as_str(), Some("UTF-8"));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Word<'a> {
    /// A token.
    Token(&'a [u8]),
    /// A quoted string.
    Quoted(Quoted<'a>),
}

impl<'a> Word<'a> {
    /// The token, or the quoted content when it has no quoted pair.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::text::parse_word;
    ///
    /// assert_eq!(parse_word(b"gzip")?.0.as_plain(), Some(&b"gzip"[..]));
    /// assert_eq!(parse_word(b"\"a\\\"b\"")?.0.as_plain(), None);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn as_plain(&self) -> Option<&'a [u8]> {
        match self {
            Self::Token(t) => Some(t),
            Self::Quoted(q) => q.as_plain(),
        }
    }

    /// [`as_plain`](Self::as_plain) when it is valid UTF-8.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::text::parse_word;
    ///
    /// assert_eq!(parse_word(b"\"caf\xc3\xa9\"")?.0.as_str(), Some("caf\u{e9}"));
    /// assert_eq!(parse_word(b"\"\xff\"")?.0.as_str(), None);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn as_str(&self) -> Option<&'a str> {
        self.as_plain().and_then(|p| core::str::from_utf8(p).ok())
    }

    /// Whether the unescaped value equals `other`.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::text::parse_word;
    ///
    /// assert!(parse_word(b"\"a b\"")?.0.eq_bytes(b"a b"));
    /// assert!(parse_word(b"gzip")?.0.eq_bytes(b"gzip") && !parse_word(b"gzip")?.0.eq_bytes(b"GZIP"));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn eq_bytes(&self, other: &[u8]) -> bool {
        match self {
            Self::Token(t) => *t == other,
            Self::Quoted(q) => q.eq_bytes(other),
        }
    }

    /// Whether the unescaped value equals `other` ignoring ASCII case.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::text::parse_word;
    ///
    /// assert!(parse_word(b"GZIP")?.0.eq_ignore_ascii_case(b"gzip"));
    /// assert!(parse_word(b"\"Br\"")?.0.eq_ignore_ascii_case(b"br"));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn eq_ignore_ascii_case(&self, other: &[u8]) -> bool {
        match self {
            Self::Token(t) => t.eq_ignore_ascii_case(other),
            Self::Quoted(q) => q.eq_ignore_ascii_case(other),
        }
    }

    /// Writes the unescaped value into `out` and returns the written part.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::BufferTooSmall`]; nothing is written.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{text::parse_word, ErrorKind};
    ///
    /// let (w, _) = parse_word(b"\"a\\\"b\"")?;
    /// let mut buf = [0u8; 8];
    /// assert_eq!(w.unescape_into(&mut buf)?, b"a\"b");
    /// assert_eq!(w.unescape_into(&mut [0u8; 2]).unwrap_err().kind(), ErrorKind::BufferTooSmall);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn unescape_into<'b>(&self, out: &'b mut [u8]) -> Result<&'b [u8]> {
        match self {
            Self::Token(t) => {
                let Some(dst) = out.get_mut(..t.len()) else {
                    return err(ErrorKind::BufferTooSmall, 0);
                };
                dst.copy_from_slice(t);
                Ok(dst)
            }
            Self::Quoted(q) => q.unescape_into(out),
        }
    }

    /// The length of the unescaped value.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::text::parse_word;
    ///
    /// assert_eq!(parse_word(b"\"a\\\"b\"")?.0.len(), 3);
    /// assert_eq!(parse_word(b"gzip")?.0.len(), 4);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Token(t) => t.len(),
            Self::Quoted(q) => q.unescaped_len(),
        }
    }

    /// Whether two words have equal unescaped values, optionally ignoring
    /// ASCII case (RFC 9110 section 5.6.6: the token and quoted forms of the
    /// same value are equal).
    pub(crate) fn same_value(&self, other: &Word<'_>, ignore_case: bool) -> bool {
        match other {
            Word::Token(t) if ignore_case => self.eq_ignore_ascii_case(t),
            Word::Token(t) => self.eq_bytes(t),
            Word::Quoted(q) => {
                let mut theirs = q.bytes();
                let eq = |a: u8, b: u8| {
                    if ignore_case {
                        a.eq_ignore_ascii_case(&b)
                    } else {
                        a == b
                    }
                };
                let all = match self {
                    Word::Token(t) => t.iter().all(|&a| theirs.next().is_some_and(|b| eq(a, b))),
                    Word::Quoted(mine) => mine
                        .bytes()
                        .all(|a| theirs.next().is_some_and(|b| eq(a, b))),
                };
                all && theirs.next().is_none()
            }
        }
    }

    /// Whether the unescaped value is empty (only a quoted string can be).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::text::parse_word;
    ///
    /// assert!(parse_word(b"\"\"")?.0.is_empty());
    /// assert!(!parse_word(b"x")?.0.is_empty());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Token(t) => t.is_empty(),
            Self::Quoted(q) => q.raw.is_empty(),
        }
    }
}

/// A validated comment: the text without the outer parentheses, and the
/// deepest nesting reached.
///
/// # Examples
///
/// ```
/// use parse_net::{text::parse_comment, Limits};
///
/// let (c, _) = parse_comment(b"(a(b))", &Limits::DEFAULT)?;
/// assert_eq!((c.raw(), c.max_depth()), (&b"a(b)"[..], 2));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Comment<'a> {
    raw: &'a [u8],
    max_depth: u8,
}

impl<'a> Comment<'a> {
    /// The text between the outer parentheses, as sent.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{text::parse_comment, Limits};
    ///
    /// let (c, _) = parse_comment(b"(gzip; level 9) x", &Limits::DEFAULT)?;
    /// assert_eq!(c.raw(), b"gzip; level 9");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// The deepest nesting reached: 1 for `(a)`, 2 for `(a(b))`.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{text::parse_comment, Limits};
    ///
    /// assert_eq!(parse_comment(b"(a)", &Limits::DEFAULT)?.0.max_depth(), 1);
    /// assert_eq!(parse_comment(b"(a(b(c)) d)", &Limits::DEFAULT)?.0.max_depth(), 3);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn max_depth(&self) -> u8 {
        self.max_depth
    }
}

#[cfg(test)]
mod tests {
    use std::{format, vec, vec::Vec};

    use super::*;

    fn q(s: &[u8]) -> Result<(Quoted<'_>, usize)> {
        parse_quoted(s)
    }

    #[test]
    fn test_quoted_edge_cases() {
        assert_eq!(q(b"\"\"").unwrap().0.raw(), b"");
        assert!(q(b"\"\\\"\"").unwrap().0.eq_bytes(b"\""));
        assert!(q(b"\"\\\\\"").unwrap().0.eq_bytes(b"\\"));
        assert_eq!(q(b"\"\\").unwrap_err().kind(), ErrorKind::UnterminatedQuote);
        assert_eq!(q(b"\"a").unwrap_err().kind(), ErrorKind::UnterminatedQuote);
        let e = q(b"\"a\x00\"").unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::Nul, 2));
        let e = q(b"\"\\\x7f\"").unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::InvalidQuotedPair, 2));
        assert!(q(b"\"\x80\xff\"").is_ok());
        assert!(q(b"\"\\\t\"").unwrap().0.eq_bytes(b"\t"));
        assert_eq!(q(b"x").unwrap_err().kind(), ErrorKind::InvalidByte);
        assert_eq!(q(b"").unwrap_err().kind(), ErrorKind::InvalidByte);
        assert_eq!(q(b"\"a\rb\"").unwrap_err().kind(), ErrorKind::BareCr);
        assert_eq!(q(b"\"a\nb\"").unwrap_err().kind(), ErrorKind::LineFeed);
    }

    #[test]
    fn test_quoted_unescape_buffer_one_short_writes_nothing() {
        let (v, _) = q(b"\"a\\\"b\"").unwrap();
        let mut buf = [0xaau8; 2];
        assert_eq!(
            v.unescape_into(&mut buf).unwrap_err().kind(),
            ErrorKind::BufferTooSmall
        );
        assert_eq!(buf, [0xaa, 0xaa]);
        let mut buf = [0u8; 3];
        assert_eq!(v.unescape_into(&mut buf).unwrap(), b"a\"b");
    }

    #[test]
    fn test_quoted_many_backslashes_linear() {
        let mut v = vec![b'"'];
        v.extend(core::iter::repeat_n(b'\\', 64 * 1024));
        v.push(b'"');
        let (quoted, used) = q(&v).unwrap();
        assert_eq!(used, v.len());
        assert_eq!(quoted.unescaped_len(), 32 * 1024);
    }

    #[test]
    fn test_quoted_case_insensitive_compare() {
        let (v, _) = q(b"\"A\\Bc\"").unwrap();
        assert!(v.eq_ignore_ascii_case(b"abc"));
        assert!(!v.eq_ignore_ascii_case(b"ab"));
        assert!(!v.eq_ignore_ascii_case(b"abcd"));
        assert!(!v.eq_bytes(b"abc"));
        assert_eq!(v.bytes().collect::<Vec<u8>>(), b"ABc");
    }

    #[test]
    fn test_word_token_and_quoted_compare_equal() {
        let (a, _) = parse_word(b"abc").unwrap();
        let (b, _) = parse_word(b"\"a\\bc\"").unwrap();
        assert!(a.eq_bytes(b"abc") && b.eq_bytes(b"abc"));
        assert_ne!(a, b);
        assert_eq!((a.len(), b.len()), (3, 3));
        assert_eq!(b.as_str(), None);
        let (e, _) = parse_word(b"\"\"").unwrap();
        assert!(e.is_empty() && !a.is_empty());
        let mut buf = [0u8; 3];
        assert_eq!(a.unescape_into(&mut buf).unwrap(), b"abc");
        assert_eq!(
            a.unescape_into(&mut buf[..2]).unwrap_err().kind(),
            ErrorKind::BufferTooSmall
        );
        assert_eq!(parse_word(b";").unwrap_err().kind(), ErrorKind::Empty);
    }

    #[test]
    fn test_trim_ows_never_strips_vt_ff_nbsp() {
        assert_eq!(trim_ows(b"\x0b a"), b"\x0b a");
        assert_eq!(trim_ows(b"a\x0c"), b"a\x0c");
        assert_eq!(trim_ows(b"\xc2\xa0a"), b"\xc2\xa0a");
        assert_eq!(trim_ows(b""), b"");
        assert_eq!(skip_ows(b""), 0);
    }

    #[test]
    fn test_comment_edge_cases() {
        let l = Limits::DEFAULT;
        assert_eq!(parse_comment(b"()", &l).unwrap().0.raw(), b"");
        assert_eq!(parse_comment(b"(a(b)c)", &l).unwrap().0.max_depth(), 2);
        assert_eq!(parse_comment(b"(\\))", &l).unwrap().1, 4);
        assert_eq!(
            parse_comment(b"((a)", &l).unwrap_err().kind(),
            ErrorKind::UnbalancedComment
        );
        assert_eq!(parse_comment(b"(a))", &l).unwrap().1, 3);
        assert_eq!(
            parse_comment(b"x", &l).unwrap_err().kind(),
            ErrorKind::InvalidByte
        );
        assert_eq!(
            parse_comment(b"(\\", &l).unwrap_err().kind(),
            ErrorKind::UnbalancedComment
        );
        assert_eq!(
            parse_comment(b"(\\\x00)", &l).unwrap_err().kind(),
            ErrorKind::InvalidQuotedPair
        );
        assert_eq!(
            parse_comment(b"(a\rb)", &l).unwrap_err().kind(),
            ErrorKind::BareCr
        );
    }

    #[test]
    fn test_comment_depth_limit_plus_one_refused() {
        let l = Limits::DEFAULT.max_comment_depth(3);
        assert!(parse_comment(b"(((x)))", &l).is_ok());
        let e = parse_comment(b"((((x))))", &l).unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::CommentTooDeep, 3));
        let deep: Vec<u8> = core::iter::repeat_n(b'(', 10_000)
            .chain(core::iter::repeat_n(b')', 10_000))
            .collect();
        assert_eq!(
            parse_comment(&deep, &Limits::DEFAULT).unwrap_err().kind(),
            ErrorKind::CommentTooDeep
        );
    }

    #[test]
    fn test_quoted_debug_escapes() {
        let (v, _) = q(b"\"a\\\"\x80\"").unwrap();
        assert_eq!(format!("{v:?}"), "Quoted(\"a\\\\\\\"\\x80\")");
    }
}
