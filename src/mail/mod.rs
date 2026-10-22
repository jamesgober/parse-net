//! The email lexical layer (RFC 5322, RFC 2045, RFC 2047, RFC 2231): header
//! lines and folding, encoded words, MIME parameters with continuations,
//! addresses, and message identifiers. The grammar smtp-net needs to write
//! mail and gate-net needs to validate login addresses (D-008); not a mail
//! parser. Charsets decoded: UTF-8, US-ASCII, ISO-8859-1.
//!
//! # Examples
//!
//! ```
//! use parse_net::{mail, SliceSink, Limits};
//!
//! let mut buf = [0u8; 256];
//! let mut out = SliceSink::new(&mut buf);
//! mail::encode_words("Caf\u{e9} au lait", 64, &mut out).expect("room");
//! assert_eq!(out.written(), b"=?UTF-8?Q?Caf=C3=A9_au_lait?=");
//!
//! let a = mail::parse_addr_spec(b"\"john doe\"@example.com")?;
//! assert!(a.is_ascii());
//! assert!(mail::parse_addr_spec(b"john..doe@example.com").is_err());
//!
//! let (p, _) = mail::parse_mime_params(b"; filename*0*=UTF-8''caf%C3%A9; filename*1=\".txt\"", &Limits::DEFAULT)?;
//! let mut name = [0u8; 32];
//! assert_eq!(p.decode_into("filename", &mut name)?, Some("caf\u{e9}.txt"));
//! # Ok::<(), parse_net::ParseError>(())
//! ```

mod addr;
mod params;
mod words;

pub use addr::{
    AddrSpec, Domain, LocalPart, Mailbox, MsgId, parse_addr_spec, parse_mailbox, parse_msg_id,
    write_msg_id,
};
pub use params::{
    Continuation, MimeParamIter, MimeParams, MimeValue, parse_mime_params, write_mime_param,
};
pub use words::{decode_words, encode_words};

pub use crate::MailDate;

use crate::{
    error::{ErrorKind, Result, WriteError, err},
    scan::control_kind,
    write::{CountSink, Sink, reserve},
};

/// The longest physical line, CRLF excluded (RFC 5322 section 2.1.1).
const HARD_LIMIT: usize = 998;
/// The line length writers keep to where they can (RFC 5322 section 2.1.1).
const SOFT_LIMIT: usize = 78;

/// Skips CFWS at `v[i..]` (WSP, `CRLF WSP`, and comments, depth-limited);
/// returns the index after it.
pub(super) fn cfws(v: &[u8], mut i: usize, limits: &crate::Limits) -> Result<usize> {
    loop {
        match v.get(i) {
            Some(b' ' | b'\t') => i += 1,
            Some(b'\r') => {
                if v.get(i + 1) == Some(&b'\n') && matches!(v.get(i + 2), Some(b' ' | b'\t')) {
                    i += 3;
                } else {
                    return err(ErrorKind::BareCr, i);
                }
            }
            Some(b'\n') => return err(ErrorKind::LineFeed, i),
            Some(b'(') => i = crate::text::comment_end(v, i, limits)?.0,
            _ => return Ok(i),
        }
    }
}

/// Checks a header field value for writing: no CR, LF, or NUL, and at most
/// 998 bytes (the physical line limit of RFC 5322 section 2.1.1, which the
/// caller's `Name: ` also counts toward).
///
/// # Errors
///
/// [`ErrorKind::BareCr`], [`ErrorKind::LineFeed`], [`ErrorKind::Nul`];
/// [`ErrorKind::LineTooLong`].
///
/// # Examples
///
/// ```
/// use parse_net::{mail, ErrorKind};
///
/// assert!(mail::check_header_value(b"Hello there").is_ok());
/// assert_eq!(mail::check_header_value(b"a\r\nBcc: x").unwrap_err().kind(), ErrorKind::BareCr);
/// assert_eq!(mail::check_header_value(&[b'a'; 999]).unwrap_err().kind(), ErrorKind::LineTooLong);
/// ```
pub fn check_header_value(value: &[u8]) -> Result<()> {
    if let Some(at) = value.iter().position(|&b| matches!(b, b'\r' | b'\n' | 0)) {
        return err(control_kind(value.get(at).copied().unwrap_or(0)), at);
    }
    if value.len() > HARD_LIMIT {
        return err(ErrorKind::LineTooLong, HARD_LIMIT);
    }
    Ok(())
}

/// Whether `name` is an email header field name: one or more `ftext`
/// (`%d33-57 / %d59-126`, RFC 5322 section 3.6.8).
///
/// # Examples
///
/// ```
/// assert!(parse_net::mail::is_field_name(b"X-Mailer"));
/// assert!(!parse_net::mail::is_field_name(b"Bad:Name") && !parse_net::mail::is_field_name(b""));
/// ```
#[must_use]
pub fn is_field_name(name: &[u8]) -> bool {
    !name.is_empty() && name.iter().all(|&b| matches!(b, 33..=57 | 59..=126))
}

/// Validates a folded header field body and returns its pieces: the text
/// between `CRLF WSP` folds, each CRLF removed and the WSP kept (RFC 5322
/// section 2.2.3). Concatenated, the pieces are the unfolded value.
///
/// # Errors
///
/// [`ErrorKind::BareCr`] (a CR not followed by LF and WSP),
/// [`ErrorKind::LineFeed`] (an LF without CR), [`ErrorKind::Nul`].
///
/// # Examples
///
/// ```
/// use parse_net::mail;
///
/// let u = mail::unfold(b"a long\r\n subject")?;
/// assert_eq!(u.iter().collect::<Vec<_>>(), [&b"a long"[..], b" subject"]);
/// assert!(mail::unfold(b"a\r\nb").is_err());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn unfold(value: &[u8]) -> Result<Unfolded<'_>> {
    let mut i = 0usize;
    while let Some(&b) = value.get(i) {
        match b {
            b'\r' => {
                if value.get(i + 1) == Some(&b'\n')
                    && matches!(value.get(i + 2), Some(b' ' | b'\t'))
                {
                    i += 3;
                    continue;
                }
                return err(ErrorKind::BareCr, i);
            }
            b'\n' => return err(ErrorKind::LineFeed, i),
            0 => return err(ErrorKind::Nul, i),
            _ => i += 1,
        }
    }
    Ok(Unfolded { value })
}

/// A validated folded field body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Unfolded<'a> {
    value: &'a [u8],
}

impl<'a> Unfolded<'a> {
    /// The pieces between folds, in order.
    #[must_use]
    pub fn iter(&self) -> UnfoldIter<'a> {
        UnfoldIter {
            rest: Some(self.value),
        }
    }
}

/// The pieces of an [`Unfolded`] value.
#[derive(Clone, Debug)]
pub struct UnfoldIter<'a> {
    rest: Option<&'a [u8]>,
}

impl<'a> Iterator for UnfoldIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let rest = self.rest?;
        match rest.iter().position(|&b| b == b'\r') {
            Some(at) => {
                self.rest = rest.get(at + 2..);
                rest.get(..at)
            }
            None => {
                self.rest = None;
                Some(rest)
            }
        }
    }
}

/// Writes `Name: value` with CRLF folds before whitespace so lines stay
/// within 78 columns where the words allow, never creating a line of only
/// whitespace and never one over 998 bytes. A space is added after the colon
/// when `value` does not start with whitespace. No CRLF is written at the
/// end.
///
/// # Errors
///
/// [`WriteError::NotToken`] for a name outside `ftext`;
/// [`WriteError::Forbidden`] for CR, LF, or NUL in `value`;
/// [`WriteError::OutOfRange`] for a word that cannot fit in 998 bytes;
/// [`WriteError::Full`] (nothing written when the sink reports its room).
///
/// # Examples
///
/// ```
/// use parse_net::{mail, SliceSink};
///
/// let mut buf = [0u8; 256];
/// let mut out = SliceSink::new(&mut buf);
/// let words = "word ".repeat(20);
/// mail::fold("Subject", words.trim_end().as_bytes(), &mut out)?;
/// let lines: Vec<&[u8]> = out.written().split(|&b| b == b'\n').collect();
/// assert_eq!(lines.len(), 2);
/// assert!(lines.iter().all(|l| l.len() <= 79));
/// # Ok::<(), parse_net::WriteError>(())
/// ```
pub fn fold(name: &str, value: &[u8], out: &mut impl Sink) -> core::result::Result<(), WriteError> {
    if !is_field_name(name.as_bytes()) {
        return Err(WriteError::NotToken);
    }
    if let Some(at) = value.iter().position(|&b| matches!(b, b'\r' | b'\n' | 0)) {
        return Err(WriteError::forbidden(at));
    }
    let mut count = CountSink::new();
    put_fold(name.as_bytes(), value, &mut count)?;
    reserve(out, count.count())?;
    put_fold(name.as_bytes(), value, out)
}

fn put_fold(
    name: &[u8],
    value: &[u8],
    out: &mut impl Sink,
) -> core::result::Result<(), WriteError> {
    out.put(name)?;
    out.put(b":")?;
    let mut col = name.len() + 1;
    if value.first().is_some_and(|&b| b != b' ' && b != b'\t') {
        out.put(b" ")?;
        col += 1;
    }
    let mut words_on_line = 0usize;
    let mut rest = value;
    loop {
        let ws_len = rest
            .iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count();
        let (ws, tail) = rest.split_at(ws_len);
        let word_len = tail
            .iter()
            .take_while(|&&b| b != b' ' && b != b'\t')
            .count();
        let (word, tail) = tail.split_at(word_len);
        if word.is_empty() {
            // Trailing whitespace stays on the line it ends.
            out.put(ws)?;
            return Ok(());
        }
        if words_on_line > 0 && col + ws.len() + word.len() > SOFT_LIMIT {
            out.put(b"\r\n")?;
            col = 0;
            words_on_line = 0;
        }
        if col + ws.len() + word.len() > HARD_LIMIT {
            return Err(WriteError::OutOfRange);
        }
        out.put(ws)?;
        out.put(word)?;
        col += ws.len() + word.len();
        words_on_line += 1;
        rest = tail;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{vec, vec::Vec};

    #[test]
    fn test_check_header_value_limits() {
        assert!(check_header_value(&[b'a'; 998]).is_ok());
        assert_eq!(
            check_header_value(&[b'a'; 999]).unwrap_err().kind(),
            ErrorKind::LineTooLong
        );
        assert_eq!(
            check_header_value(b"a\nb").unwrap_err().kind(),
            ErrorKind::LineFeed
        );
        assert_eq!(
            check_header_value(b"a\x00b").unwrap_err().kind(),
            ErrorKind::Nul
        );
        assert!(check_header_value(b"").is_ok());
    }

    #[test]
    fn test_field_names() {
        assert!(is_field_name(b"Subject") && is_field_name(b"!#$%&'*+-.^_`|~9"));
        assert!(!is_field_name(b"A B") && !is_field_name(b"A:") && !is_field_name(b"\x7f"));
    }

    #[test]
    fn test_unfold_edge_cases() {
        let u = unfold(b"a\r\n\tb\r\n c").unwrap();
        assert_eq!(u.iter().collect::<Vec<_>>(), vec![&b"a"[..], b"\tb", b" c"]);
        assert_eq!(
            unfold(b"").unwrap().iter().collect::<Vec<_>>(),
            vec![&b""[..]]
        );
        assert_eq!(unfold(b"a\r").unwrap_err().kind(), ErrorKind::BareCr);
        assert_eq!(unfold(b"a\r\n").unwrap_err().kind(), ErrorKind::BareCr);
        assert_eq!(unfold(b"a\nb").unwrap_err().kind(), ErrorKind::LineFeed);
    }

    fn folded(name: &str, value: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        let mut out = crate::SliceSink::new(&mut buf);
        fold(name, value, &mut out).unwrap();
        out.written().to_vec()
    }

    #[test]
    fn test_fold_lines_and_round_trip() {
        let value = "the quick brown fox jumps over the lazy dog ".repeat(5);
        let value = value.trim_end().as_bytes();
        let f = folded("Subject", value);
        for line in f.split(|&b| b == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            assert!(line.len() <= 78, "{}", line.len());
            assert!(!line.iter().all(|&b| b == b' '));
        }
        let body = f.strip_prefix(b"Subject: ").unwrap();
        let back: Vec<u8> = unfold(body).unwrap().iter().flatten().copied().collect();
        assert_eq!(back, value);
        assert_eq!(folded("X", b" lead"), b"X: lead");
        assert_eq!(folded("X", b"tab\tsep"), b"X: tab\tsep");
        assert_eq!(folded("X", b""), b"X:");
        assert_eq!(folded("X", b"a  "), b"X: a  ");
    }

    #[test]
    fn test_fold_long_words() {
        let word = vec![b'w'; 989];
        let f = folded("Subject", &word);
        assert_eq!(f.len(), 998);
        let mut buf = vec![0u8; 4096];
        let mut out = crate::SliceSink::new(&mut buf);
        assert_eq!(
            fold("Subject", &[b'w'; 1000], &mut out),
            Err(WriteError::OutOfRange)
        );
        let mut two = vec![b'a'; 10];
        two.push(b' ');
        two.extend_from_slice(&[b'w'; 997]);
        assert_eq!(fold("S", &two, &mut out), Ok(()));
        let mut two = vec![b'a'; 10];
        two.push(b' ');
        two.extend_from_slice(&[b'w'; 998]);
        assert_eq!(fold("S", &two, &mut out), Err(WriteError::OutOfRange));
    }

    #[test]
    fn test_fold_refusals_write_nothing() {
        let mut buf = [0u8; 8];
        let mut out = crate::SliceSink::new(&mut buf);
        assert_eq!(fold("A B", b"x", &mut out), Err(WriteError::NotToken));
        assert_eq!(
            fold("A", b"x\r\nBcc: y", &mut out),
            Err(WriteError::Forbidden { at: 1 })
        );
        assert_eq!(
            fold("A", b"too long for eight", &mut out),
            Err(WriteError::Full)
        );
        assert!(out.is_empty());
    }
}
