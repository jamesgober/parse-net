//! RFC 2047 encoded words in unstructured header text.

use crate::{
    class,
    error::{ErrorKind, ParseError, Result, WriteError, err},
    limits::Limits,
    utf8::Utf8,
    write::{CountSink, Sink, reserve},
};

/// The longest encoded word (RFC 2047 section 2).
const WORD_LIMIT: usize = 75;
/// `=?UTF-8?Q?` and `?=`.
const OVERHEAD: usize = 12;

/// Whether `b` is written as itself inside a Q-encoded word in a header
/// (RFC 2047 section 5, rule 3).
const fn q_plain(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'!' | b'*' | b'+' | b'-' | b'/')
}

/// The Q-encoded length of every byte: 1 for a byte written as itself or
/// as `_` (a space), 3 for `=XX`. One lookup instead of the class tests.
// Built at compile time; `b` runs over 0..256, the array's own bounds.
#[allow(clippy::indexing_slicing)]
const Q_LEN: [u8; 256] = {
    let mut t = [3u8; 256];
    let mut b = 0usize;
    while b < 256 {
        if q_plain(b as u8) || b == b' ' as usize {
            t[b] = 1;
        }
        b += 1;
    }
    t
};

/// The Q-encoded length of one byte.
#[inline]
fn q_byte_len(b: u8) -> usize {
    usize::from(Q_LEN.get(usize::from(b)).copied().unwrap_or(3))
}

/// The length in bytes of the UTF-8 character that starts with `b`.
const fn utf8_width(b: u8) -> usize {
    match b {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

/// The payload of one encoded word, built on the stack: at most 75 bytes
/// less the 12 of `=?UTF-8?Q?` and `?=`.
struct Payload {
    buf: [u8; WORD_LIMIT - OVERHEAD],
    len: usize,
}

impl Payload {
    /// Appends the Q encoding of `ch` (one UTF-8 character); the caller has
    /// checked that it fits.
    fn push(&mut self, ch: &[u8]) {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        for &b in ch {
            let len = self.len;
            if q_byte_len(b) == 1 {
                if let Some(d) = self.buf.get_mut(len) {
                    *d = if b == b' ' { b'_' } else { b };
                }
                self.len = len + 1;
            } else {
                let hi = HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0');
                let lo = HEX.get(usize::from(b & 0xf)).copied().unwrap_or(b'0');
                if let Some([x, y, z]) = self.buf.get_mut(len..len + 3) {
                    (*x, *y, *z) = (b'=', hi, lo);
                }
                self.len = len + 3;
            }
        }
    }

    fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }
}

fn put_words(
    text: &str,
    room_first_line: usize,
    out: &mut impl Sink,
) -> core::result::Result<(), WriteError> {
    let bytes = text.as_bytes();
    if bytes.iter().all(|b| (0x20..=0x7e).contains(b)) && !text.contains("=?") {
        out.put(bytes)?;
        return Ok(());
    }
    let mut limit = room_first_line.min(WORD_LIMIT);
    let mut word = Payload {
        buf: [0; WORD_LIMIT - OVERHEAD],
        len: 0,
    };
    let mut open = false;
    let mut i = 0usize;
    while let Some(&lead) = bytes.get(i) {
        let ch = bytes.get(i..i + utf8_width(lead)).unwrap_or(&[]);
        i += ch.len().max(1);
        let mut n = 0usize;
        for &b in ch {
            n += q_byte_len(b);
        }
        if open && OVERHEAD + word.len + n > limit {
            out.put(word.as_bytes())?;
            out.put(b"?=\r\n ")?;
            open = false;
            limit = WORD_LIMIT;
        }
        if !open {
            if OVERHEAD + n > limit {
                // Not even one character fits in the room left on the first
                // line: start on a new one.
                out.put(b"\r\n ")?;
                limit = WORD_LIMIT;
            }
            out.put(b"=?UTF-8?Q?")?;
            open = true;
            word.len = 0;
        }
        word.push(ch);
    }
    if open {
        out.put(word.as_bytes())?;
        out.put(b"?=")?;
    }
    Ok(())
}

/// Writes `text` for an unstructured header field: as it is when it is
/// printable ASCII without `=?`, otherwise as RFC 2047 `=?UTF-8?Q?...?=`
/// words of at most 75 bytes, split only between characters, separated by
/// CRLF SP. The first word fits in `room_first_line` (the columns left after
/// `Name: `); when not even one character fits there, the words start on a
/// new line.
///
/// # Errors
///
/// [`WriteError::Forbidden`] for a control character (C0, DEL, or C1);
/// [`WriteError::Full`] (nothing written when the sink reports its room).
///
/// # Examples
///
/// ```
/// use parse_net::{mail, SliceSink};
///
/// let mut buf = [0u8; 256];
/// let mut out = SliceSink::new(&mut buf);
/// mail::encode_words("Caf\u{e9} au lait", 64, &mut out).expect("room");
/// assert_eq!(out.written(), b"=?UTF-8?Q?Caf=C3=A9_au_lait?=");
/// ```
pub fn encode_words(
    text: &str,
    room_first_line: usize,
    out: &mut impl Sink,
) -> core::result::Result<(), WriteError> {
    if let Some((at, _)) = text.char_indices().find(|&(_, c)| c.is_control()) {
        return Err(WriteError::forbidden(at));
    }
    let mut count = CountSink::new();
    put_words(text, room_first_line, &mut count)?;
    reserve(out, count.count())?;
    put_words(text, room_first_line, out)
}

/// The charsets decoded.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Charset {
    Utf8,
    Ascii,
    Latin1,
}

/// The parts of an encoded word.
struct Encoded<'a> {
    charset: Charset,
    /// The `B` encoding.
    base64: bool,
    text: &'a [u8],
    /// The index after the closing `?=`.
    end: usize,
}

/// An encoded word at `v[i..]`: `=?charset?enc?text?=`. `Ok(None)` when the
/// bytes do not have that shape (they are then ordinary text).
fn shape(v: &[u8], i: usize) -> Result<Option<Encoded<'_>>> {
    let rest = v.get(i + 2..).unwrap_or(&[]);
    let Some(q1) = rest.iter().position(|&b| b == b'?') else {
        return Ok(None);
    };
    let charset = rest.get(..q1).unwrap_or(&[]);
    if charset.is_empty()
        || !charset
            .iter()
            .all(|&b| class::is_mime_token_char(b) && b != b'?')
    {
        return Ok(None);
    }
    let after = rest.get(q1 + 1..).unwrap_or(&[]);
    let (Some(&enc), Some(b'?')) = (after.first(), after.get(1)) else {
        return Ok(None);
    };
    let text_start = i + 2 + q1 + 3;
    let text_rest = v.get(text_start..).unwrap_or(&[]);
    let Some(end) = text_rest.windows(2).position(|w| w == b"?=") else {
        return Ok(None);
    };
    let text = text_rest.get(..end).unwrap_or(&[]);
    if text.iter().any(|&b| b == b' ' || b == b'\t' || b == b'?') {
        return Ok(None);
    }
    // RFC 2231 section 5: `charset*language`.
    let name = charset.split(|&b| b == b'*').next().unwrap_or(&[]);
    let cs = if name.eq_ignore_ascii_case(b"utf-8") {
        Charset::Utf8
    } else if name.eq_ignore_ascii_case(b"us-ascii") {
        Charset::Ascii
    } else if name.eq_ignore_ascii_case(b"iso-8859-1") {
        Charset::Latin1
    } else {
        return err(ErrorKind::UnsupportedCharset, i + 2);
    };
    let b = match enc {
        b'Q' | b'q' => false,
        b'B' | b'b' => true,
        _ => return err(ErrorKind::InvalidEncodedWord, i + 2 + q1 + 1),
    };
    Ok(Some(Encoded {
        charset: cs,
        base64: b,
        text,
        end: text_start + end + 2,
    }))
}

/// Decodes one Q word's text, emitting UTF-8.
fn decode_q(cs: Charset, text: &[u8], at: usize, emit: &mut impl FnMut(&[u8])) -> Result<()> {
    let mut utf8 = Utf8::new();
    let mut i = 0usize;
    while let Some(&b) = text.get(i) {
        let byte = match b {
            b'_' => b' ',
            b'=' => {
                let hi = text.get(i + 1).copied().and_then(class::hex_value);
                let lo = text.get(i + 2).copied().and_then(class::hex_value);
                let (Some(hi), Some(lo)) = (hi, lo) else {
                    return err(ErrorKind::InvalidEncodedWord, at + i);
                };
                i += 2;
                (hi << 4) | lo
            }
            0x21..=0x7e => b,
            _ => return err(ErrorKind::InvalidEncodedWord, at + i),
        };
        i += 1;
        if matches!(byte, b'\r' | b'\n' | 0) {
            return err(ErrorKind::ControlInDecoded, at + i - 1);
        }
        match cs {
            Charset::Utf8 => {
                if !utf8.push(byte) {
                    return err(ErrorKind::InvalidUtf8, at + i - 1);
                }
                emit(&[byte]);
            }
            Charset::Ascii if byte >= 0x80 => {
                return err(ErrorKind::InvalidEncodedWord, at + i - 1);
            }
            Charset::Ascii => emit(&[byte]),
            Charset::Latin1 if byte >= 0x80 => emit(&[0xc0 | (byte >> 6), 0x80 | (byte & 0x3f)]),
            Charset::Latin1 => emit(&[byte]),
        }
    }
    if !utf8.is_complete() {
        // Each encoded word holds whole characters (RFC 2047 section 5).
        return err(ErrorKind::InvalidUtf8, at + text.len());
    }
    Ok(())
}

/// Walks `v`, emitting the decoded text.
fn walk(v: &[u8], limits: &Limits, emit: &mut impl FnMut(&[u8])) -> Result<()> {
    let (mut i, mut words) = (0usize, 0usize);
    let (mut boundary, mut quoted, mut after_word) = (true, false, false);
    let mut held: Option<(usize, usize)> = None;
    while let Some(&b) = v.get(i) {
        if quoted {
            emit(&[b]);
            if b == b'\\' {
                if let Some(&n) = v.get(i + 1) {
                    emit(&[n]);
                    i += 1;
                }
            } else if b == b'"' {
                quoted = false;
            }
            i += 1;
            continue;
        }
        if b == b' ' || b == b'\t' {
            let start = i;
            while matches!(v.get(i), Some(b' ' | b'\t')) {
                i += 1;
            }
            if after_word {
                held = Some((start, i));
            } else {
                emit(v.get(start..i).unwrap_or(&[]));
            }
            boundary = true;
            continue;
        }
        if boundary && v.get(i..i + 2) == Some(b"=?") {
            if let Some(Encoded {
                charset: cs,
                base64: b64,
                text,
                end,
            }) = shape(v, i)?
            {
                if end == v.len() || matches!(v.get(end), Some(b' ' | b'\t')) {
                    words += 1;
                    if words > usize::from(limits.encoded_words) {
                        return err(ErrorKind::TooManyMembers, i);
                    }
                    if b64 {
                        // Base64 decoding comes with encode-lib (D-002).
                        return err(ErrorKind::InvalidEncodedWord, i);
                    }
                    // Whitespace between two encoded words is dropped
                    // (RFC 2047 section 6.2).
                    held = None;
                    let text_at = end - 2 - text.len();
                    decode_q(cs, text, text_at, emit)?;
                    after_word = true;
                    boundary = false;
                    i = end;
                    continue;
                }
            }
        }
        if let Some((s, e)) = held.take() {
            emit(v.get(s..e).unwrap_or(&[]));
        }
        after_word = false;
        boundary = false;
        if b == b'"' {
            quoted = true;
        }
        emit(&[b]);
        i += 1;
    }
    if let Some((s, e)) = held {
        emit(v.get(s..e).unwrap_or(&[]));
    }
    Ok(())
}

/// Decodes the RFC 2047 encoded words in unstructured header text into
/// `out` and returns the text. Text outside encoded words is copied;
/// whitespace between two adjacent encoded words is dropped (section 6.2);
/// `_` is a space in Q; an encoded word must stand alone between whitespace,
/// and words inside a quoted string are not decoded (section 5). Charsets:
/// UTF-8, US-ASCII, ISO-8859-1 (transcoded), with an optional RFC 2231
/// `*language`. `B` words need the `encode-lib` feature, which is not yet
/// available (D-002).
///
/// # Errors
///
/// [`ErrorKind::UnsupportedCharset`]; [`ErrorKind::InvalidEncodedWord`] (a
/// bad encoding letter, a broken `=XX`, a byte not allowed in a Q word, a
/// `B` word); [`ErrorKind::ControlInDecoded`] for a decoded CR, LF, or NUL;
/// [`ErrorKind::InvalidUtf8`] (a UTF-8 word that is not whole characters, or
/// text outside the words that is not UTF-8); [`ErrorKind::TooManyMembers`]
/// beyond `max_encoded_words`; [`ErrorKind::BufferTooSmall`]. Nothing is
/// written on error.
///
/// # Examples
///
/// ```
/// use parse_net::{mail, Limits};
///
/// let mut buf = [0u8; 64];
/// let s = mail::decode_words(b"=?utf-8?q?Caf=C3=A9?= =?ISO-8859-1?Q?_cr=E8me?= now", &Limits::DEFAULT, &mut buf)?;
/// assert_eq!(s, "Caf\u{e9} cr\u{e8}me now");
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn decode_words<'b>(value: &[u8], limits: &Limits, out: &'b mut [u8]) -> Result<&'b str> {
    let mut len = 0usize;
    walk(value, limits, &mut |b: &[u8]| len += b.len())?;
    let Some(dst) = out.get_mut(..len) else {
        return err(ErrorKind::BufferTooSmall, 0);
    };
    let mut n = 0usize;
    walk(value, limits, &mut |b: &[u8]| {
        if let Some(d) = dst.get_mut(n..n + b.len()) {
            d.copy_from_slice(b);
        }
        n += b.len();
    })?;
    if let Err(e) = core::str::from_utf8(dst) {
        let at = e.valid_up_to();
        // Nothing is left behind on error.
        dst.fill(0);
        return Err(ParseError::new(ErrorKind::InvalidUtf8, at));
    }
    core::str::from_utf8(dst).map_err(|e| ParseError::new(ErrorKind::InvalidUtf8, e.valid_up_to()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{string::String, vec};

    fn enc(text: &str, room: usize) -> String {
        let mut buf = vec![0u8; 2048];
        let mut out = crate::SliceSink::new(&mut buf);
        encode_words(text, room, &mut out).unwrap();
        String::from_utf8(out.written().to_vec()).unwrap()
    }

    fn dec(v: &[u8]) -> Result<String> {
        let mut buf = vec![0u8; 2048];
        decode_words(v, &Limits::DEFAULT, &mut buf).map(String::from)
    }

    #[test]
    fn test_encode_words_edge_cases() {
        assert_eq!(enc("plain ascii", 10), "plain ascii");
        assert_eq!(enc("a =?b", 70), "=?UTF-8?Q?a_=3D=3Fb?=");
        let long = "\u{e9}".repeat(40);
        let e = enc(&long, 75);
        for word in e.split("\r\n ") {
            assert!(word.len() <= 75 && word.starts_with("=?UTF-8?Q?") && word.ends_with("?="));
            // Each word holds whole characters, so it decodes on its own.
            assert!(dec(word.as_bytes()).is_ok());
        }
        assert_eq!(dec(e.replace("\r\n", "").as_bytes()).unwrap(), long);
        // An encoded word of exactly 75 bytes: 63 bytes of payload.
        let e = enc(&"\u{20ac}".repeat(7), 75);
        assert_eq!(e.len(), 12 + 63);
        assert!(!e.starts_with("\r\n "));
        assert!(enc("\u{e9}", 5).starts_with("\r\n =?UTF-8?Q?"));
        let mut buf = [0u8; 8];
        let mut out = crate::SliceSink::new(&mut buf);
        assert_eq!(
            encode_words("a\nb", 70, &mut out),
            Err(WriteError::Forbidden { at: 1 })
        );
        assert_eq!(
            encode_words("a\u{85}", 70, &mut out),
            Err(WriteError::Forbidden { at: 1 })
        );
        assert_eq!(
            encode_words("\u{e9}\u{e9}", 70, &mut out),
            Err(WriteError::Full)
        );
        assert!(out.is_empty());
    }

    #[test]
    fn test_decode_words_edge_cases() {
        assert_eq!(dec(b"=?utf-8?q?a_b?=").unwrap(), "a b");
        assert_eq!(dec(b"=?UTF-8?Q?a?=  \t =?UTF-8?Q?b?=").unwrap(), "ab");
        assert_eq!(dec(b"=?UTF-8?Q?a?= x =?UTF-8?Q?b?= ").unwrap(), "a x b ");
        assert_eq!(dec(b"\"=?UTF-8?Q?a?=\"").unwrap(), "\"=?UTF-8?Q?a?=\"");
        assert_eq!(dec(b"x=?UTF-8?Q?a?=").unwrap(), "x=?UTF-8?Q?a?=");
        assert_eq!(dec(b"=?UTF-8?Q?a?=x").unwrap(), "=?UTF-8?Q?a?=x");
        assert_eq!(dec(b"=?UTF-8*en?Q?a?=").unwrap(), "a");
        assert_eq!(dec(b"=? not a word").unwrap(), "=? not a word");
        assert_eq!(dec(b"=?US-ASCII?Q?ok?=").unwrap(), "ok");
        assert_eq!(
            dec(b"=?KOI8-R?Q?a?=").unwrap_err().kind(),
            ErrorKind::UnsupportedCharset
        );
        assert_eq!(
            dec(b"=?UTF-8?X?a?=").unwrap_err().kind(),
            ErrorKind::InvalidEncodedWord
        );
        assert_eq!(
            dec(b"=?UTF-8?Q?=4?=").unwrap_err().kind(),
            ErrorKind::InvalidEncodedWord
        );
        assert_eq!(
            dec(b"=?UTF-8?B?YQ==?=").unwrap_err().kind(),
            ErrorKind::InvalidEncodedWord
        );
        assert_eq!(
            dec(b"=?UTF-8?Q?=0D=0A?=").unwrap_err().kind(),
            ErrorKind::ControlInDecoded
        );
        assert_eq!(
            dec(b"=?UTF-8?Q?=C3?=").unwrap_err().kind(),
            ErrorKind::InvalidUtf8
        );
        assert_eq!(
            dec(b"=?US-ASCII?Q?=E9?=").unwrap_err().kind(),
            ErrorKind::InvalidEncodedWord
        );
        assert_eq!(dec(b"raw \xe9").unwrap_err().kind(), ErrorKind::InvalidUtf8);
        let l = Limits::DEFAULT.max_encoded_words(2);
        let mut buf = [0u8; 64];
        assert!(decode_words(b"=?UTF-8?Q?a?= =?UTF-8?Q?b?=", &l, &mut buf).is_ok());
        assert_eq!(
            decode_words(b"=?UTF-8?Q?a?= =?UTF-8?Q?b?= =?UTF-8?Q?c?=", &l, &mut buf)
                .unwrap_err()
                .kind(),
            ErrorKind::TooManyMembers
        );
        let mut small = [0u8; 2];
        assert_eq!(
            decode_words(b"abc", &Limits::DEFAULT, &mut small)
                .unwrap_err()
                .kind(),
            ErrorKind::BufferTooSmall
        );
        assert_eq!(small, [0, 0]);
    }
}
