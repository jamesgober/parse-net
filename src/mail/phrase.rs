//! The text of a `phrase` (RFC 5322 section 3.2.5), such as a display name,
//! with its RFC 2047 encoded words decoded (section 5).

use super::words::{self, Text};
use crate::{
    class,
    error::{ErrorKind, ParseError, Result, err},
    limits::Limits,
    scan::{control_kind, is_control},
    text::{comment_end_folded, parse_quoted},
};

/// Whether `b` belongs to an atom of a phrase: `atext`, the `.` of
/// `obs-phrase`, or RFC 6532 UTF-8.
fn is_word_byte(b: u8) -> bool {
    WORD.get(usize::from(b)).copied().unwrap_or(false)
}

/// [`is_word_byte`] for every byte: one lookup instead of the class tests.
// Built at compile time; `b` runs over 0..256, the array's own bounds.
#[allow(clippy::indexing_slicing)]
const WORD: [bool; 256] = {
    let mut t = [false; 256];
    let mut b = 0usize;
    while b < 256 {
        t[b] = class::is_atext(b as u8) || b == b'.' as usize || b >= 0x80;
        b += 1;
    }
    t
};

/// The last word written.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Last {
    None,
    Text,
    Encoded,
}

/// Walks the phrase `v`, emitting its text.
fn walk(v: &[u8], limits: &Limits, emit: &mut impl FnMut(&[u8])) -> Result<()> {
    let mut text = Text::new();
    let (mut i, mut words) = (0usize, 0usize);
    let mut last = Last::None;
    // A comment since the last word: two encoded words with a comment between
    // them are not adjacent (RFC 2047 section 6.2), so a space separates them.
    let mut commented = false;
    while let Some(&b) = v.get(i) {
        let n = words::ws_len(v, i);
        if n > 0 {
            i += n;
            continue;
        }
        if b == b'(' {
            i = comment_end_folded(v, i, limits)?.0;
            commented = true;
            continue;
        }
        if b == b'"' {
            let (q, used) = parse_quoted(v.get(i..).unwrap_or(&[])).map_err(|e| e.shifted(i))?;
            if last != Last::None {
                emit(b" ");
            }
            // The content with its quoted pairs unescaped; a word inside a
            // quoted string is not decoded (RFC 2047 section 5).
            let raw = q.raw();
            if raw.is_ascii() {
                // `qdtext` and `quoted-pair` hold no control but HTAB in
                // ASCII, so the runs between escapes go out as they are.
                let mut rest = raw;
                while let Some(p) = rest.iter().position(|&c| c == b'\\') {
                    emit(rest.get(..p).unwrap_or(&[]));
                    emit(rest.get(p + 1..p + 2).unwrap_or(&[]));
                    rest = rest.get(p + 2..).unwrap_or(&[]);
                }
                emit(rest);
            } else {
                let mut k = 0usize;
                while let Some(&c) = raw.get(k) {
                    if c == b'\\' {
                        k += 1;
                    }
                    let c = raw.get(k).copied().unwrap_or(c);
                    text.check(c, i + 1 + k)?;
                    emit(&[c]);
                    k += 1;
                }
                if !text.is_complete() {
                    return err(ErrorKind::InvalidUtf8, i + used - 1);
                }
            }
            last = Last::Text;
            commented = false;
            i += used;
            continue;
        }
        if !is_word_byte(b) {
            let kind = if is_control(b) {
                control_kind(b)
            } else {
                ErrorKind::InvalidByte
            };
            return Err(ParseError::new(kind, i));
        }
        let rest = v.get(i..).unwrap_or(&[]);
        let end = i + rest
            .iter()
            .position(|&c| !is_word_byte(c))
            .unwrap_or(rest.len());
        // An encoded word is a whole atom between whitespace; next to a
        // special or a comment it is text.
        let alone = end == v.len() || words::ws_len(v, end) > 0;
        let encoded = if alone && rest.starts_with(b"=?") {
            words::shape(v.get(..end).unwrap_or(&[]), i)?
        } else {
            None
        };
        if let Some(e) = encoded {
            words += 1;
            if words > usize::from(limits.encoded_words) {
                return err(ErrorKind::TooManyMembers, i);
            }
            if last == Last::Text || (last == Last::Encoded && commented) {
                emit(b" ");
            }
            words::decode_word(&e, i, emit)?;
            last = Last::Encoded;
        } else {
            if last != Last::None {
                emit(b" ");
            }
            let atom = v.get(i..end).unwrap_or(&[]);
            // An ASCII atom is `atext` and dots, all printable.
            if !atom.is_ascii() {
                for (k, &c) in atom.iter().enumerate() {
                    text.check(c, i + k)?;
                }
                if !text.is_complete() {
                    return err(ErrorKind::InvalidUtf8, end);
                }
            }
            emit(atom);
            last = Last::Text;
        }
        commented = false;
        i = end;
    }
    if last == Last::None {
        return err(ErrorKind::Empty, 0);
    }
    Ok(())
}

/// Decodes a `phrase` (RFC 5322 section 3.2.5), such as the display name
/// [`parse_mailbox`](super::parse_mailbox) returns raw, into `out` and returns
/// its text: comments are dropped, quoted strings lose their quotes and
/// their quoted pairs are unescaped, and the words are joined by one space.
/// RFC 2047 encoded words are decoded where section 5 allows them in a
/// phrase: a whole atom between whitespace, never inside a quoted string;
/// two encoded words with only whitespace between them are joined with none
/// (section 6.2). Encoded words are read as
/// [`decode_words`](super::decode_words) reads them, and every byte of the
/// text meets its rules: UTF-8, no control character but HTAB.
///
/// # Errors
///
/// [`ErrorKind::Empty`] for a phrase with no word (empty, or only comments
/// and whitespace); [`ErrorKind::InvalidByte`] for a special such as `,` or
/// `<` outside a quoted string or comment; a control kind for a control
/// byte, other than HTAB and the CRLF of a fold; [`ErrorKind::Control`] for
/// a C1 character; [`ErrorKind::InvalidUtf8`];
/// [`ErrorKind::UnterminatedQuote`]; [`ErrorKind::UnbalancedComment`],
/// [`ErrorKind::CommentTooDeep`]; the encoded-word errors of
/// [`decode_words`](super::decode_words), [`ErrorKind::TooManyMembers`]
/// beyond `max_encoded_words` among them; [`ErrorKind::BufferTooSmall`].
/// Nothing is written on error.
///
/// # Examples
///
/// ```
/// use parse_net::{mail, Limits};
///
/// let m = mail::parse_mailbox(b"\"Doe, Jane\" (Sales) <jane@example.com>", &Limits::DEFAULT)?;
/// let mut buf = [0u8; 64];
/// let name = mail::decode_phrase(m.display_name.unwrap_or_default(), &Limits::DEFAULT, &mut buf)?;
/// assert_eq!(name, "Doe, Jane");
///
/// let name = mail::decode_phrase(b"=?UTF-8?Q?Ren=C3=A9e?= \"O'Neil\"", &Limits::DEFAULT, &mut buf)?;
/// assert_eq!(name, "Ren\u{e9}e O'Neil");
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn decode_phrase<'b>(value: &[u8], limits: &Limits, out: &'b mut [u8]) -> Result<&'b str> {
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
    // The first walk checked the text; this is the safe conversion.
    core::str::from_utf8(dst).map_err(|e| ParseError::new(ErrorKind::InvalidUtf8, e.valid_up_to()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{string::String, vec, vec::Vec};

    fn dec(v: &[u8]) -> Result<String> {
        let mut buf = vec![0u8; 1024];
        decode_phrase(v, &Limits::DEFAULT, &mut buf).map(String::from)
    }

    fn fails(v: &[u8]) -> (ErrorKind, usize) {
        let e = dec(v).unwrap_err();
        (e.kind(), e.offset())
    }

    #[test]
    fn test_decode_phrase_words() {
        assert_eq!(dec(b"Jane Doe").unwrap(), "Jane Doe");
        assert_eq!(dec(b"  Jane \t  Doe  ").unwrap(), "Jane Doe");
        assert_eq!(dec(b"Jane\r\n Doe").unwrap(), "Jane Doe");
        assert_eq!(dec(b"John Q. Public").unwrap(), "John Q. Public");
        assert_eq!(dec(b"\"Doe, John\"").unwrap(), "Doe, John");
        assert_eq!(dec(b"\"a \\\"q\\\" \\\\ b\"").unwrap(), "a \"q\" \\ b");
        assert_eq!(dec(b"Jane\"Q\"Doe").unwrap(), "Jane Q Doe");
        assert_eq!(dec(b"\"  spaced  \" x").unwrap(), "  spaced   x");
        assert_eq!(dec(b"\"\"").unwrap(), "");
        assert_eq!(dec(b"John (the (nested) one) Doe").unwrap(), "John Doe");
        assert_eq!(dec(b"(lead)John(trail)").unwrap(), "John");
        assert_eq!(
            dec("J\u{f6}rg M\u{fc}ller".as_bytes()).unwrap(),
            "J\u{f6}rg M\u{fc}ller"
        );
        assert_eq!(
            dec("\"\u{e9}t\u{e9}\"".as_bytes()).unwrap(),
            "\u{e9}t\u{e9}"
        );
        assert_eq!(dec(b"\"tab\there\"").unwrap(), "tab\there");
    }

    #[test]
    fn test_decode_phrase_encoded_words() {
        assert_eq!(
            dec(b"=?UTF-8?Q?Caf=C3=A9?= Owner").unwrap(),
            "Caf\u{e9} Owner"
        );
        assert_eq!(
            dec(b"Owner =?utf-8?q?Caf=C3=A9?=").unwrap(),
            "Owner Caf\u{e9}"
        );
        assert_eq!(dec(b"=?UTF-8?Q?a?= =?UTF-8?Q?b?=").unwrap(), "ab");
        assert_eq!(dec(b"=?UTF-8?Q?a?=\r\n =?UTF-8?Q?b?=").unwrap(), "ab");
        assert_eq!(dec(b"=?UTF-8?Q?a?= (c) =?UTF-8?Q?b?=").unwrap(), "a b");
        assert_eq!(dec(b"=?UTF-8?Q?a_b?=").unwrap(), "a b");
        assert_eq!(
            dec(b"=?ISO-8859-1?Q?Andr=E9?= Pirard").unwrap(),
            "Andr\u{e9} Pirard"
        );
        assert_eq!(
            dec(b"=?UTF-8?B?5Lya6K2w44Gu44GK55+l44KJ44Gb?=").unwrap(),
            "\u{4f1a}\u{8b70}\u{306e}\u{304a}\u{77e5}\u{3089}\u{305b}"
        );
        // Inside a quoted string, or next to a special, it is text.
        assert_eq!(dec(b"\"=?UTF-8?Q?a?=\"").unwrap(), "=?UTF-8?Q?a?=");
        assert_eq!(dec(b"=?UTF-8?Q?a?=(c)").unwrap(), "=?UTF-8?Q?a?=");
        assert_eq!(dec(b"=?UTF-8?Q?a?=\"b\"").unwrap(), "=?UTF-8?Q?a?= b");
        // Not the shape of an encoded word: text.
        assert_eq!(dec(b"=?x").unwrap(), "=?x");
        assert_eq!(dec(b"a=?UTF-8?Q?b?=").unwrap(), "a=?UTF-8?Q?b?=");
    }

    #[test]
    fn test_decode_phrase_errors() {
        assert_eq!(fails(b""), (ErrorKind::Empty, 0));
        assert_eq!(fails(b"   "), (ErrorKind::Empty, 0));
        assert_eq!(fails(b"(only a comment)"), (ErrorKind::Empty, 0));
        assert_eq!(fails(b"Doe, John"), (ErrorKind::InvalidByte, 3));
        assert_eq!(fails(b"a <b>"), (ErrorKind::InvalidByte, 2));
        assert_eq!(fails(b"a@b"), (ErrorKind::InvalidByte, 1));
        assert_eq!(fails(b"a\x01b").0, ErrorKind::Control);
        assert_eq!(fails(b"a\rb").0, ErrorKind::BareCr);
        assert_eq!(fails(b"a\nb").0, ErrorKind::LineFeed);
        assert_eq!(fails(b"a\0b").0, ErrorKind::Nul);
        assert_eq!(fails(b"\"open"), (ErrorKind::UnterminatedQuote, 5));
        assert_eq!(fails(b"a (open").0, ErrorKind::UnbalancedComment);
        assert_eq!(fails(b"a \xff"), (ErrorKind::InvalidUtf8, 2));
        assert_eq!(fails(b"a \xc3 b"), (ErrorKind::InvalidUtf8, 3));
        assert_eq!(fails(b"\"\xc3\" b"), (ErrorKind::InvalidUtf8, 2));
        assert_eq!(fails(b"a\xc2\x85b"), (ErrorKind::Control, 2));
        assert_eq!(fails(b"\"\\\xc2\\\x85\"").0, ErrorKind::Control);
        assert_eq!(fails(b"=?KOI8-R?Q?a?=").0, ErrorKind::UnsupportedCharset);
        assert_eq!(fails(b"x =?UTF-8?Q?=0D?=").0, ErrorKind::ControlInDecoded);
        assert_eq!(fails(b"=?UTF-8?B?YQ=?=").0, ErrorKind::InvalidEncodedWord);
        let l = Limits::DEFAULT.max_encoded_words(1);
        let mut buf = [0u8; 16];
        assert_eq!(
            decode_phrase(b"=?UTF-8?Q?a?= =?UTF-8?Q?b?=", &l, &mut buf)
                .unwrap_err()
                .kind(),
            ErrorKind::TooManyMembers
        );
        // Nothing is written when the buffer is short.
        let mut small = [b'#'; 4];
        assert_eq!(
            decode_phrase(b"Jane Doe", &Limits::DEFAULT, &mut small)
                .unwrap_err()
                .kind(),
            ErrorKind::BufferTooSmall
        );
        assert_eq!(small, [b'#'; 4]);
    }

    /// A reader with no shortcuts: words made only of atoms, quoted
    /// strings, whitespace, and comments without nesting, so the expected
    /// text is the words joined by one space.
    fn reference(words: &[(bool, String)]) -> String {
        let mut out = String::new();
        for (k, (_, w)) in words.iter().enumerate() {
            if k > 0 {
                out.push(' ');
            }
            out.push_str(w);
        }
        out
    }

    proptest::proptest! {
        #[test]
        fn decode_phrase_matches_reference(
            words in proptest::collection::vec(
                (proptest::bool::ANY, "[ -~\u{e9}\u{4f1a}]{0,8}", "[a-zA-Z0-9!#$%&'*+/=?^_`{|}~.\u{e9}-]{1,8}"),
                1..6,
            ),
            gaps in proptest::collection::vec(0usize..4, 6),
        ) {
            let mut raw = Vec::new();
            let mut expect = Vec::new();
            for (k, (quoted, q, atom)) in words.iter().enumerate() {
                if k > 0 {
                    match gaps.get(k).copied().unwrap_or(0) {
                        0 => raw.push(b' '),
                        1 => raw.extend_from_slice(b"\t "),
                        2 => raw.extend_from_slice(b" (note) "),
                        _ => raw.extend_from_slice(b"\r\n "),
                    }
                }
                if *quoted {
                    raw.push(b'"');
                    for c in q.bytes() {
                        if c == b'"' || c == b'\\' {
                            raw.push(b'\\');
                        }
                        raw.push(c);
                    }
                    raw.push(b'"');
                    expect.push((true, q.clone()));
                } else {
                    raw.extend_from_slice(atom.as_bytes());
                    expect.push((false, atom.clone()));
                }
            }
            // Atoms that happen to look like encoded words decode: keep
            // to the plain case here.
            proptest::prop_assume!(!expect.iter().any(|(q, w)| !q && w.starts_with("=?")));
            proptest::prop_assert_eq!(dec(&raw).unwrap(), reference(&expect));
        }

        #[test]
        fn decode_phrase_never_panics(v in proptest::collection::vec(proptest::num::u8::ANY, 0..64)) {
            let mut buf = [0u8; 256];
            if let Ok(s) = decode_phrase(&v, &Limits::DEFAULT, &mut buf) {
                proptest::prop_assert!(!s.chars().any(|c| c.is_control() && c != '\t'));
            }
        }
    }
}
