//! The RFC 9651 section 4.2 parsing algorithms over a cursor.
//!
//! Every function takes the cursor at the position the RFC describes and
//! leaves it after what it consumed. Inner lists cannot nest (the grammar
//! allows one level), so there is no recursion anywhere: depth is at most 2.

use super::{BareItem, ByteSeq, Decimal, DisplayString, SfString};
use crate::{
    class,
    error::{ErrorKind, ParseError, Result},
    limits::Limits,
    scan::control_kind,
    utf8::Utf8,
};

/// The most digits an Integer may have.
const INTEGER_DIGITS: usize = 15;
/// The largest Integer magnitude.
pub(crate) const INTEGER_MAX: i64 = 999_999_999_999_999;

/// A position in a field value.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Cursor<'a> {
    pub(crate) s: &'a [u8],
    pub(crate) i: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) const fn new(s: &'a [u8]) -> Self {
        Self { s, i: 0 }
    }

    pub(crate) fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.i >= self.s.len()
    }

    pub(crate) fn bump(&mut self) {
        self.i += 1;
    }

    pub(crate) fn fail(&self, kind: ErrorKind) -> ParseError {
        match self.peek() {
            Some(b) if crate::scan::is_control(b) => ParseError::new(control_kind(b), self.i),
            _ => ParseError::new(kind, self.i),
        }
    }

    /// Discards leading SP (section 4.2: only SP around the whole value and
    /// inside inner lists).
    pub(crate) fn skip_sp(&mut self) {
        while self.peek() == Some(b' ') {
            self.i += 1;
        }
    }

    /// Discards leading OWS (SP and HTAB, around list and dictionary
    /// separators).
    pub(crate) fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.i += 1;
        }
    }

    fn slice(&self, from: usize) -> &'a [u8] {
        self.s.get(from..self.i).unwrap_or(&[])
    }
}

/// Section 4.2.3.3: a key.
pub(crate) fn key<'a>(c: &mut Cursor<'a>, limits: &Limits) -> Result<&'a str> {
    let start = c.i;
    match c.peek() {
        Some(b) if class::is_sf_key_start(b) => c.bump(),
        _ => return Err(c.fail(ErrorKind::InvalidKey)),
    }
    while c.peek().is_some_and(class::is_sf_key_char) {
        c.bump();
    }
    if c.i - start > usize::from(limits.key_len) {
        return Err(ParseError::new(ErrorKind::TooLong, start));
    }
    // Keys are ASCII by construction.
    Ok(core::str::from_utf8(c.slice(start)).unwrap_or(""))
}

/// Section 4.2.4: an Integer or a Decimal.
fn number(c: &mut Cursor<'_>) -> Result<BareItem<'static>> {
    let start = c.i;
    let negative = c.peek() == Some(b'-');
    if negative {
        c.bump();
    }
    if !c.peek().is_some_and(|b| b.is_ascii_digit()) {
        return Err(c.fail(ErrorKind::InvalidNumber));
    }
    let mut int: i64 = 0;
    let mut int_digits = 0usize;
    while let Some(d) = c.peek().filter(u8::is_ascii_digit) {
        int_digits += 1;
        if int_digits > INTEGER_DIGITS {
            return Err(ParseError::new(ErrorKind::NumberOverflow, c.i));
        }
        int = int * 10 + i64::from(d - b'0');
        c.bump();
    }
    if c.peek() != Some(b'.') {
        return Ok(BareItem::Integer(if negative { -int } else { int }));
    }
    // A Decimal: at most 12 integer digits and 1 to 3 fractional digits.
    if int_digits > 12 {
        return Err(ParseError::new(ErrorKind::NumberOverflow, c.i));
    }
    c.bump();
    let mut frac: i64 = 0;
    let mut frac_digits = 0u32;
    while let Some(d) = c.peek().filter(u8::is_ascii_digit) {
        frac_digits += 1;
        if frac_digits > 3 {
            return Err(ParseError::new(ErrorKind::NumberOverflow, c.i));
        }
        frac = frac * 10 + i64::from(d - b'0');
        c.bump();
    }
    if frac_digits == 0 {
        return Err(ParseError::new(ErrorKind::InvalidNumber, start));
    }
    let thousandths = int * 1000 + frac * 10_i64.pow(3 - frac_digits);
    Ok(BareItem::Decimal(Decimal(if negative {
        -thousandths
    } else {
        thousandths
    })))
}

/// Section 4.2.5: a String. Returns the raw content (escapes kept).
fn string<'a>(c: &mut Cursor<'a>, limits: &Limits) -> Result<SfString<'a>> {
    c.bump(); // the opening DQUOTE
    let start = c.i;
    let mut decoded = 0usize;
    let mut escapes = false;
    loop {
        match c.peek() {
            None => return Err(ParseError::new(ErrorKind::UnterminatedQuote, c.i)),
            Some(b'"') => break,
            Some(b'\\') => {
                c.bump();
                match c.peek() {
                    Some(b'"' | b'\\') => {
                        escapes = true;
                        c.bump();
                    }
                    None => return Err(ParseError::new(ErrorKind::UnterminatedQuote, c.i)),
                    Some(_) => return Err(c.fail(ErrorKind::InvalidQuotedPair)),
                }
            }
            Some(b) if class::is_sf_string_char(b) => c.bump(),
            Some(_) => return Err(c.fail(ErrorKind::InvalidByte)),
        }
        decoded += 1;
        if decoded > usize::from(limits.string_len) {
            return Err(ParseError::new(ErrorKind::TooLong, start));
        }
    }
    let raw = c.slice(start);
    c.bump(); // the closing DQUOTE
    Ok(SfString {
        // ASCII by construction.
        raw: core::str::from_utf8(raw).unwrap_or(""),
        escapes,
    })
}

/// Section 4.2.6: a Token.
fn token<'a>(c: &mut Cursor<'a>, limits: &Limits) -> Result<&'a str> {
    let start = c.i;
    c.bump(); // ALPHA or "*", checked by the caller
    while c.peek().is_some_and(class::is_sf_token_char) {
        c.bump();
    }
    if c.i - start > usize::from(limits.token_len) {
        return Err(ParseError::new(ErrorKind::TooLong, start));
    }
    Ok(core::str::from_utf8(c.slice(start)).unwrap_or(""))
}

/// Section 4.2.7: a Byte Sequence. Padding is optional and non-zero pad bits
/// are accepted, as the section says recipients should.
fn byte_seq<'a>(c: &mut Cursor<'a>, limits: &Limits) -> Result<ByteSeq<'a>> {
    c.bump(); // ":"
    let start = c.i;
    while c.peek().is_some_and(class::is_base64_char) {
        c.bump();
    }
    let body = c.i - start;
    let mut pad = 0usize;
    while c.peek() == Some(b'=') {
        pad += 1;
        c.bump();
    }
    match c.peek() {
        Some(b':') => {}
        None => return Err(ParseError::new(ErrorKind::UnterminatedQuote, c.i)),
        Some(_) => return Err(c.fail(ErrorKind::InvalidBase64)),
    }
    // A base64 text of `body` symbols decodes when `body % 4 != 1`; padding,
    // when present, completes the last quantum and nothing else.
    let valid = body % 4 != 1 && (pad == 0 || ((body + pad) % 4 == 0 && pad <= 2));
    if !valid {
        return Err(ParseError::new(ErrorKind::InvalidBase64, start + body));
    }
    let raw = c.slice(start);
    c.bump(); // ":"
    let seq = ByteSeq { raw };
    if seq.decoded_len() > limits.byte_seq_len as usize {
        return Err(ParseError::new(ErrorKind::TooLong, start));
    }
    Ok(seq)
}

/// Section 4.2.8: a Boolean.
fn boolean(c: &mut Cursor<'_>) -> Result<bool> {
    c.bump(); // "?"
    let v = match c.peek() {
        Some(b'1') => true,
        Some(b'0') => false,
        _ => return Err(c.fail(ErrorKind::InvalidByte)),
    };
    c.bump();
    Ok(v)
}

/// Section 4.2.9: a Date: `@` and an Integer, within years 1 to 9999 (D-030).
fn date(c: &mut Cursor<'_>) -> Result<i64> {
    c.bump(); // "@"
    let at = c.i;
    match number(c)? {
        BareItem::Integer(secs) => {
            if secs < crate::HttpDate::MIN.unix() || secs > crate::HttpDate::MAX.unix() {
                return Err(ParseError::new(ErrorKind::OutOfRange, at));
            }
            Ok(secs)
        }
        _ => Err(ParseError::new(ErrorKind::InvalidNumber, at)),
    }
}

/// Section 4.2.10: a Display String: lowercase `%xx` only, the decoded bytes
/// UTF-8 validated as they are read (no buffer).
fn display_string<'a>(c: &mut Cursor<'a>, limits: &Limits) -> Result<DisplayString<'a>> {
    c.bump(); // "%"
    if c.peek() != Some(b'"') {
        return Err(c.fail(ErrorKind::InvalidByte));
    }
    c.bump();
    let start = c.i;
    let mut utf8 = Utf8::new();
    let mut decoded = 0usize;
    loop {
        let b = match c.peek() {
            None => return Err(ParseError::new(ErrorKind::UnterminatedQuote, c.i)),
            Some(b'"') => break,
            Some(b'%') => {
                let at = c.i;
                let hex = |x: Option<u8>| {
                    x.filter(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                        .and_then(class::hex_value)
                };
                let hi = hex(c.s.get(c.i + 1).copied());
                let lo = hex(c.s.get(c.i + 2).copied());
                let (Some(hi), Some(lo)) = (hi, lo) else {
                    return Err(ParseError::new(ErrorKind::InvalidPercentEncoding, at));
                };
                c.i += 3;
                if !utf8.push((hi << 4) | lo) {
                    return Err(ParseError::new(ErrorKind::InvalidUtf8, at));
                }
                decoded += 1;
                continue;
            }
            Some(b) if (0x20..=0x7e).contains(&b) => b,
            Some(_) => return Err(c.fail(ErrorKind::InvalidByte)),
        };
        // A literal byte is ASCII: it must not interrupt a multi-byte
        // character decoded from triples.
        if !utf8.is_complete() || !utf8.push(b) {
            return Err(ParseError::new(ErrorKind::InvalidUtf8, c.i));
        }
        c.bump();
        decoded += 1;
        if decoded > usize::from(limits.string_len) {
            return Err(ParseError::new(ErrorKind::TooLong, start));
        }
    }
    if !utf8.is_complete() {
        return Err(ParseError::new(ErrorKind::InvalidUtf8, c.i));
    }
    let raw = c.slice(start);
    c.bump(); // the closing DQUOTE
    Ok(DisplayString { raw })
}

/// Section 4.2.3.1: a bare item.
pub(crate) fn bare_item<'a>(c: &mut Cursor<'a>, limits: &Limits) -> Result<BareItem<'a>> {
    match c.peek() {
        Some(b'-' | b'0'..=b'9') => number(c),
        Some(b'"') => string(c, limits).map(BareItem::String),
        Some(b) if b == b'*' || b.is_ascii_alphabetic() => token(c, limits).map(BareItem::Token),
        Some(b':') => byte_seq(c, limits).map(BareItem::ByteSeq),
        Some(b'?') => boolean(c).map(BareItem::Boolean),
        Some(b'@') => date(c).map(BareItem::Date),
        Some(b'%') => display_string(c, limits).map(BareItem::DisplayString),
        _ => Err(c.fail(ErrorKind::InvalidByte)),
    }
}

/// Section 4.2.3.2: parameters. Calls `f` for each, in order; returns the
/// count.
pub(crate) fn params<'a>(
    c: &mut Cursor<'a>,
    limits: &Limits,
    mut f: impl FnMut(&'a str, BareItem<'a>) -> Result<()>,
) -> Result<usize> {
    let mut count = 0usize;
    while c.peek() == Some(b';') {
        let at = c.i;
        c.bump();
        c.skip_sp();
        let k = key(c, limits)?;
        let v = if c.peek() == Some(b'=') {
            c.bump();
            bare_item(c, limits)?
        } else {
            BareItem::Boolean(true)
        };
        count += 1;
        if count > usize::from(limits.params) {
            return Err(ParseError::new(ErrorKind::TooManyMembers, at));
        }
        f(k, v)?;
    }
    Ok(count)
}

/// The events a parse produces, for views and visitors alike.
pub(crate) trait Events<'a> {
    fn item(&mut self, bare: BareItem<'a>) -> Result<()>;
    fn param(&mut self, key: &'a str, value: BareItem<'a>) -> Result<()>;
    fn inner_start(&mut self) -> Result<()>;
    fn inner_end(&mut self) -> Result<()>;
    fn key(&mut self, key: &'a str) -> Result<()>;
}

/// Events that are discarded: validation only.
pub(crate) struct Nothing;

impl<'a> Events<'a> for Nothing {
    fn item(&mut self, _: BareItem<'a>) -> Result<()> {
        Ok(())
    }
    fn param(&mut self, _: &'a str, _: BareItem<'a>) -> Result<()> {
        Ok(())
    }
    fn inner_start(&mut self) -> Result<()> {
        Ok(())
    }
    fn inner_end(&mut self) -> Result<()> {
        Ok(())
    }
    fn key(&mut self, _: &'a str) -> Result<()> {
        Ok(())
    }
}

/// Section 4.2.1.2: an inner list, the cursor at `(`.
fn inner_list<'a>(c: &mut Cursor<'a>, limits: &Limits, ev: &mut impl Events<'a>) -> Result<()> {
    ev.inner_start()?;
    c.bump(); // "("
    let mut count = 0usize;
    loop {
        c.skip_sp();
        if c.peek() == Some(b')') {
            c.bump();
            ev.inner_end()?;
            let _ = params(c, limits, |k, v| ev.param(k, v))?;
            return Ok(());
        }
        if c.is_empty() {
            return Err(ParseError::new(ErrorKind::UnterminatedQuote, c.i));
        }
        let at = c.i;
        let bare = bare_item(c, limits)?;
        count += 1;
        if count > usize::from(limits.inner_list_members) {
            return Err(ParseError::new(ErrorKind::TooManyMembers, at));
        }
        ev.item(bare)?;
        let _ = params(c, limits, |k, v| ev.param(k, v))?;
        match c.peek() {
            Some(b' ' | b')') => {}
            None => return Err(ParseError::new(ErrorKind::UnterminatedQuote, c.i)),
            Some(_) => return Err(c.fail(ErrorKind::ExpectedSeparator)),
        }
    }
}

/// Section 4.2.1.1: an item or an inner list.
pub(crate) fn member<'a>(
    c: &mut Cursor<'a>,
    limits: &Limits,
    ev: &mut impl Events<'a>,
) -> Result<()> {
    if c.peek() == Some(b'(') {
        inner_list(c, limits, ev)
    } else {
        let bare = bare_item(c, limits)?;
        ev.item(bare)?;
        params(c, limits, |k, v| ev.param(k, v)).map(|_| ())
    }
}

/// After a list or dictionary member: OWS, then the end or `,` and OWS and
/// another member. Returns whether another member follows.
fn separator(c: &mut Cursor<'_>) -> Result<bool> {
    c.skip_ows();
    if c.is_empty() {
        return Ok(false);
    }
    if c.peek() != Some(b',') {
        return Err(c.fail(ErrorKind::ExpectedSeparator));
    }
    c.bump();
    c.skip_ows();
    if c.is_empty() {
        return Err(ParseError::new(ErrorKind::TrailingSeparator, c.i));
    }
    Ok(true)
}

/// Section 4.2.1: a list; returns the member count.
pub(crate) fn list<'a>(
    c: &mut Cursor<'a>,
    limits: &Limits,
    ev: &mut impl Events<'a>,
) -> Result<usize> {
    let mut count = 0usize;
    if c.is_empty() {
        return Ok(0);
    }
    loop {
        let at = c.i;
        count += 1;
        if count > usize::from(limits.list_members) {
            return Err(ParseError::new(ErrorKind::TooManyMembers, at));
        }
        member(c, limits, ev)?;
        if !separator(c)? {
            return Ok(count);
        }
    }
}

/// Section 4.2.2: a dictionary; returns the member count (duplicates
/// included: views keep every member, and lookups take the last).
pub(crate) fn dictionary<'a>(
    c: &mut Cursor<'a>,
    limits: &Limits,
    ev: &mut impl Events<'a>,
) -> Result<usize> {
    let mut count = 0usize;
    if c.is_empty() {
        return Ok(0);
    }
    loop {
        let at = c.i;
        count += 1;
        if count > usize::from(limits.dictionary_members) {
            return Err(ParseError::new(ErrorKind::TooManyMembers, at));
        }
        let k = key(c, limits)?;
        ev.key(k)?;
        if c.peek() == Some(b'=') {
            c.bump();
            member(c, limits, ev)?;
        } else {
            ev.item(BareItem::Boolean(true))?;
            let _ = params(c, limits, |k, v| ev.param(k, v))?;
        }
        if !separator(c)? {
            return Ok(count);
        }
    }
}

/// Section 4.2: the top level. Leading and trailing SP are discarded (SP
/// only); `body` parses the rest; anything left is an error.
pub(crate) fn field<'a, T>(
    value: &'a [u8],
    body: impl FnOnce(&mut Cursor<'a>) -> Result<T>,
) -> Result<(T, usize, usize)> {
    let mut c = Cursor::new(value);
    c.skip_sp();
    let start = c.i;
    // Trailing SP is discarded before parsing, so a list or dictionary does
    // not see it as a separator.
    let mut end = value.len();
    while end > start && value.get(end - 1) == Some(&b' ') {
        end -= 1;
    }
    let mut inner = Cursor {
        s: value.get(..end).unwrap_or(&[]),
        i: start,
    };
    let out = body(&mut inner)?;
    if !inner.is_empty() {
        return Err(inner.fail(ErrorKind::TrailingData));
    }
    Ok((out, start, end))
}
