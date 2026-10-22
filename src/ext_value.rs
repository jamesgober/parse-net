//! RFC 8187 extended parameter values: `charset "'" [ language ] "'"
//! value-chars`, as in `filename*` and `title*`.
//!
//! # Examples
//!
//! ```
//! use parse_net::{ExtValue, Charset};
//!
//! let v = ExtValue::parse(b"UTF-8'en'%E2%82%AC%20rates.txt")?;
//! assert_eq!((v.charset(), v.language()), (Charset::Utf8, &b"en"[..]));
//! let mut buf = [0u8; 32];
//! assert_eq!(v.decode_into(&mut buf)?, "\u{20ac} rates.txt");
//! # Ok::<(), parse_net::ParseError>(())
//! ```

use crate::{
    class,
    error::{ErrorKind, Result, WriteError, err},
    pct::{EncodeSet, HexCase},
    scan::control_kind,
    utf8::Utf8,
    write::{Sink, reserve},
};

/// The charsets RFC 8187 values are decoded from.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Charset {
    /// UTF-8, the charset producers must use (RFC 8187 section 3.2.1).
    Utf8,
    /// ISO-8859-1, decoded only (D-010).
    Iso8859_1,
    /// US-ASCII, decoded only: a decoded byte above 0x7F is refused (D-058).
    UsAscii,
}

/// A validated extended value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExtValue<'a> {
    charset: Charset,
    language: &'a [u8],
    encoded: &'a [u8],
}

/// Whether `b` may appear in a `mime-charset` (RFC 8187 section 3.2.1).
const fn is_mime_charset_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'+'
                | b'-'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'}'
                | b'~'
        )
}

/// Whether a decoded code point is a control: C0, DEL, or C1.
const fn is_control_point(c: u32) -> bool {
    c < 0x20 || (c >= 0x7f && c <= 0x9f)
}

impl<'a> ExtValue<'a> {
    /// Parses an extended value.
    ///
    /// The charset is `UTF-8` or `ISO-8859-1` (case-insensitive); the
    /// language is empty or letters, digits, and `-`; the value is
    /// `attr-char` bytes and `%XX` triples.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidCharset`] (no `'`, an empty or malformed charset,
    /// a malformed language); [`ErrorKind::UnsupportedCharset`];
    /// [`ErrorKind::InvalidPercentEncoding`]; [`ErrorKind::InvalidByte`], or a
    /// control kind, for a byte outside the value grammar.
    pub fn parse(value: &'a [u8]) -> Result<Self> {
        let Some(q1) = value.iter().position(|&b| b == b'\'') else {
            return err(ErrorKind::InvalidCharset, value.len());
        };
        let charset_text = value.get(..q1).unwrap_or(&[]);
        if charset_text.is_empty() || !charset_text.iter().all(|&b| is_mime_charset_char(b)) {
            return err(ErrorKind::InvalidCharset, 0);
        }
        let charset = if charset_text.eq_ignore_ascii_case(b"UTF-8") {
            Charset::Utf8
        } else if charset_text.eq_ignore_ascii_case(b"ISO-8859-1") {
            Charset::Iso8859_1
        } else if charset_text.eq_ignore_ascii_case(b"US-ASCII") {
            Charset::UsAscii
        } else {
            return err(ErrorKind::UnsupportedCharset, 0);
        };
        let after = value.get(q1 + 1..).unwrap_or(&[]);
        let Some(q2) = after.iter().position(|&b| b == b'\'') else {
            return err(ErrorKind::InvalidCharset, value.len());
        };
        let language = after.get(..q2).unwrap_or(&[]);
        if let Some(i) = language
            .iter()
            .position(|&b| !(b.is_ascii_alphanumeric() || b == b'-'))
        {
            return err(ErrorKind::InvalidCharset, q1 + 1 + i);
        }
        let encoded_at = q1 + 1 + q2 + 1;
        let encoded = after.get(q2 + 1..).unwrap_or(&[]);
        let mut i = 0usize;
        while let Some(&b) = encoded.get(i) {
            if b == b'%' {
                match (encoded.get(i + 1), encoded.get(i + 2)) {
                    (Some(&h), Some(&l)) if class::is_hexdig(h) && class::is_hexdig(l) => i += 3,
                    _ => return err(ErrorKind::InvalidPercentEncoding, encoded_at + i),
                }
            } else if class::is_attr_char(b) {
                i += 1;
            } else if crate::scan::is_control(b) {
                return err(control_kind(b), encoded_at + i);
            } else {
                return err(ErrorKind::InvalidByte, encoded_at + i);
            }
        }
        Ok(Self {
            charset,
            language,
            encoded,
        })
    }

    /// The declared charset.
    #[must_use]
    pub const fn charset(&self) -> Charset {
        self.charset
    }

    /// The language tag, possibly empty, as sent.
    #[must_use]
    pub const fn language(&self) -> &'a [u8] {
        self.language
    }

    /// The `value-chars`, still percent-encoded.
    #[must_use]
    pub const fn encoded(&self) -> &'a [u8] {
        self.encoded
    }

    /// The decoded bytes, before charset handling.
    pub(crate) fn raw_bytes(&self) -> PctBytes<'a> {
        PctBytes {
            rest: self.encoded.iter(),
        }
    }

    /// An upper bound on the length [`decode_into`](Self::decode_into)
    /// writes: exact for UTF-8, doubled for ISO-8859-1.
    #[must_use]
    pub fn max_decoded_len(&self) -> usize {
        let n = self.raw_bytes().count();
        match self.charset {
            Charset::Utf8 | Charset::UsAscii => n,
            Charset::Iso8859_1 => n.saturating_mul(2),
        }
    }

    /// Checks that the value decodes: valid UTF-8 (for UTF-8) and no
    /// control character.
    pub(crate) fn check_text(&self) -> Result<()> {
        decoded_text_len(self.raw_bytes(), self.charset).map(|_| ())
    }

    /// Decodes into `out` and returns the text: UTF-8 is validated
    /// (overlong forms and surrogates refused), ISO-8859-1 is transcoded.
    /// A decoded control character (C0, DEL, or C1, such as `%0D%0A` or
    /// `%00`) is refused: never copy such a value into another header or a
    /// log.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidUtf8`], [`ErrorKind::ControlInDecoded`],
    /// [`ErrorKind::BufferTooSmall`]. Nothing is written on error.
    pub fn decode_into<'b>(&self, out: &'b mut [u8]) -> Result<&'b str> {
        decode_checked(self.raw_bytes(), self.charset, out)
    }
}

/// Decodes `bytes` in `charset` into `out`, refusing controls, after a first
/// pass that validates and sizes the output so nothing is written on error.
pub(crate) fn decode_checked(
    bytes: impl Iterator<Item = u8> + Clone,
    charset: Charset,
    out: &mut [u8],
) -> Result<&str> {
    let len = decoded_text_len(bytes.clone(), charset)?;
    let Some(dst) = out.get_mut(..len) else {
        return err(ErrorKind::BufferTooSmall, 0);
    };
    let mut slots = dst.iter_mut();
    for b in bytes {
        match charset {
            Charset::Utf8 | Charset::UsAscii => {
                if let Some(s) = slots.next() {
                    *s = b;
                }
            }
            Charset::Iso8859_1 => {
                if b < 0x80 {
                    if let Some(s) = slots.next() {
                        *s = b;
                    }
                } else {
                    // U+0080 to U+00FF in UTF-8: 0xC2 or 0xC3, then 0x80 | low six bits.
                    if let Some(s) = slots.next() {
                        *s = 0xc0 | (b >> 6);
                    }
                    if let Some(s) = slots.next() {
                        *s = 0x80 | (b & 0x3f);
                    }
                }
            }
        }
    }
    core::str::from_utf8(dst)
        .map_err(|e| crate::ParseError::new(ErrorKind::InvalidUtf8, e.valid_up_to()))
}

/// Validates `bytes` as text in `charset` with no control character, and
/// returns its UTF-8 length.
pub(crate) fn decoded_text_len(bytes: impl Iterator<Item = u8>, charset: Charset) -> Result<usize> {
    let mut len = 0usize;
    match charset {
        Charset::Utf8 => {
            let mut v = Utf8::new();
            let mut point = 0u32;
            for (i, b) in bytes.enumerate() {
                if !v.push(b) {
                    return err(ErrorKind::InvalidUtf8, i);
                }
                // Accumulate the code point; `v` has already refused any
                // byte out of place, so the masks below see valid UTF-8.
                point = match b {
                    0x00..=0x7f => u32::from(b),
                    0x80..=0xbf => (point << 6) | u32::from(b & 0x3f),
                    0xc0..=0xdf => u32::from(b & 0x1f),
                    0xe0..=0xef => u32::from(b & 0x0f),
                    _ => u32::from(b & 0x07),
                };
                if v.is_complete() && is_control_point(point) {
                    return err(ErrorKind::ControlInDecoded, i);
                }
                len += 1;
            }
            if !v.is_complete() {
                return err(ErrorKind::InvalidUtf8, len);
            }
        }
        Charset::Iso8859_1 => {
            for (i, b) in bytes.enumerate() {
                if is_control_point(u32::from(b)) {
                    return err(ErrorKind::ControlInDecoded, i);
                }
                len += if b < 0x80 { 1 } else { 2 };
            }
        }
        Charset::UsAscii => {
            for (i, b) in bytes.enumerate() {
                if b >= 0x80 {
                    return err(ErrorKind::InvalidByte, i);
                }
                if is_control_point(u32::from(b)) {
                    return err(ErrorKind::ControlInDecoded, i);
                }
                len += 1;
            }
        }
    }
    Ok(len)
}

/// Percent-decoded bytes of already validated text.
#[derive(Clone)]
pub(crate) struct PctBytes<'a> {
    pub(crate) rest: core::slice::Iter<'a, u8>,
}

impl Iterator for PctBytes<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        let b = *self.rest.next()?;
        if b != b'%' {
            return Some(b);
        }
        let hi = self.rest.next().copied().and_then(class::hex_value);
        let lo = self.rest.next().copied().and_then(class::hex_value);
        match (hi, lo) {
            (Some(h), Some(l)) => Some((h << 4) | l),
            _ => Some(b),
        }
    }
}

/// Writes `UTF-8''` and `text` with every byte that is not an `attr-char`
/// as `%XX` (uppercase hex). ISO-8859-1 is never written (D-010).
///
/// # Errors
///
/// [`WriteError::Forbidden`] for a control character (C0, DEL, or C1);
/// [`WriteError::Full`] (nothing written when the sink reports its room).
///
/// # Examples
///
/// ```
/// use parse_net::{ext_value::write_ext_value, SliceSink};
///
/// let mut buf = [0u8; 64];
/// let mut out = SliceSink::new(&mut buf);
/// write_ext_value("\u{20ac} rates.txt", &mut out).expect("room");
/// assert_eq!(out.written(), b"UTF-8''%E2%82%AC%20rates.txt");
/// ```
pub fn write_ext_value(text: &str, out: &mut impl Sink) -> core::result::Result<(), WriteError> {
    for (i, c) in text.char_indices() {
        if is_control_point(u32::from(c)) {
            return Err(WriteError::forbidden(i));
        }
    }
    let set = EncodeSet::ATTR_CHAR_COMPLEMENT;
    reserve(
        out,
        7usize.saturating_add(crate::pct::encoded_len(text.as_bytes(), &set)),
    )?;
    out.put(b"UTF-8''")?;
    crate::pct::encode(text.as_bytes(), &set, HexCase::Upper, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(v: &[u8]) -> Result<std::string::String> {
        let e = ExtValue::parse(v)?;
        let mut buf = [0u8; 64];
        e.decode_into(&mut buf).map(std::string::String::from)
    }

    #[test]
    fn test_ext_value_charset_matrix() {
        assert_eq!(decode(b"UTF-8''").unwrap(), "");
        assert_eq!(decode(b"utf-8''a").unwrap(), "a");
        assert_eq!(decode(b"UTF-8'en'a").unwrap(), "a");
        assert_eq!(decode(b"ISO-8859-1''%E9").unwrap(), "\u{e9}");
        assert_eq!(decode(b"iso-8859-1''caf%e9").unwrap(), "caf\u{e9}");
        assert_eq!(decode(b"us-ascii'en'a%20b").unwrap(), "a b");
        assert_eq!(
            decode(b"US-ASCII''caf%e9").unwrap_err().kind(),
            ErrorKind::InvalidByte
        );
        assert_eq!(decode(b"UTF-8''%C3%A9").unwrap(), "\u{e9}");
        // The same bytes read under the other charset are refused or differ.
        assert_eq!(
            decode(b"UTF-8''%E9").unwrap_err().kind(),
            ErrorKind::InvalidUtf8
        );
        assert_eq!(decode(b"ISO-8859-1''%C3%A9").unwrap(), "\u{c3}\u{a9}");
        assert_eq!(
            ExtValue::parse(b"UTF-16''a").unwrap_err().kind(),
            ErrorKind::UnsupportedCharset
        );
        assert_eq!(
            ExtValue::parse(b"''a").unwrap_err().kind(),
            ErrorKind::InvalidCharset
        );
        assert_eq!(
            ExtValue::parse(b"UTF-8'a").unwrap_err().kind(),
            ErrorKind::InvalidCharset
        );
        assert_eq!(
            ExtValue::parse(b"UTF 8''a").unwrap_err().kind(),
            ErrorKind::InvalidCharset
        );
        assert_eq!(
            ExtValue::parse(b"UTF-8'e n'a").unwrap_err().kind(),
            ErrorKind::InvalidCharset
        );
    }

    #[test]
    fn test_ext_value_percent_crlf_refused() {
        assert_eq!(
            ExtValue::parse(b"UTF-8''%").unwrap_err().kind(),
            ErrorKind::InvalidPercentEncoding
        );
        assert_eq!(
            ExtValue::parse(b"UTF-8''%G0").unwrap_err().kind(),
            ErrorKind::InvalidPercentEncoding
        );
        assert_eq!(
            decode(b"UTF-8''%C3").unwrap_err().kind(),
            ErrorKind::InvalidUtf8
        );
        assert_eq!(
            decode(b"UTF-8''%C0%AF").unwrap_err().kind(),
            ErrorKind::InvalidUtf8
        );
        assert_eq!(
            decode(b"UTF-8''%00").unwrap_err().kind(),
            ErrorKind::ControlInDecoded
        );
        assert_eq!(
            decode(b"UTF-8''a%0D%0Ab").unwrap_err().kind(),
            ErrorKind::ControlInDecoded
        );
        assert_eq!(
            decode(b"UTF-8''%C2%85").unwrap_err().kind(),
            ErrorKind::ControlInDecoded
        );
        assert_eq!(
            decode(b"ISO-8859-1''%85").unwrap_err().kind(),
            ErrorKind::ControlInDecoded
        );
        assert_eq!(decode(b"UTF-8''a%2Fb").unwrap(), "a/b");
        assert_eq!(
            ExtValue::parse(b"UTF-8''a b").unwrap_err().kind(),
            ErrorKind::InvalidByte
        );
        assert_eq!(
            ExtValue::parse(b"UTF-8''a\rb").unwrap_err().kind(),
            ErrorKind::BareCr
        );
    }

    #[test]
    fn test_ext_value_buffer_and_lengths() {
        let e = ExtValue::parse(b"ISO-8859-1''%E9%E9").unwrap();
        assert_eq!(e.max_decoded_len(), 4);
        let mut short = [0xaau8; 3];
        assert_eq!(
            e.decode_into(&mut short).unwrap_err().kind(),
            ErrorKind::BufferTooSmall
        );
        assert_eq!(short, [0xaa; 3]);
        let u = ExtValue::parse(b"UTF-8''%E2%82%AC").unwrap();
        assert_eq!(u.max_decoded_len(), 3);
    }

    #[test]
    fn test_write_ext_value_round_trip_and_refusals() {
        let mut buf = [0u8; 128];
        let mut out = crate::SliceSink::new(&mut buf);
        assert_eq!(
            write_ext_value("a\r\nb", &mut out),
            Err(WriteError::Forbidden { at: 1 })
        );
        assert_eq!(
            write_ext_value("x\u{85}", &mut out),
            Err(WriteError::Forbidden { at: 1 })
        );
        write_ext_value("caf\u{e9} \u{1f600}/", &mut out).unwrap();
        let back = ExtValue::parse(out.written()).unwrap();
        let mut dec = [0u8; 64];
        assert_eq!(back.decode_into(&mut dec).unwrap(), "caf\u{e9} \u{1f600}/");
    }
}
