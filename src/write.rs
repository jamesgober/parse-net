//! Output: the [`Sink`] trait, [`SliceSink`], [`CountSink`], and the writers
//! for numbers, tokens, quoted strings, parameters, and field values.
//!
//! Every writer validates all of its input before the first
//! [`put`](Sink::put), and checks [`remaining`](Sink::remaining) when its
//! output takes several `put` calls, so after any error a [`SliceSink`] holds
//! exactly what it held before. No writer can emit CR, LF, or NUL, and no
//! writer produces a value its own parser would refuse.
//!
//! # Examples
//!
//! ```
//! use parse_net::{self as pn, write};
//!
//! let mut buf = [0u8; 64];
//! let mut out = pn::SliceSink::new(&mut buf);
//! write::write_word(b"gzip", &mut out)?;
//! write::write_param(b"title", b"say \"hi\"", &mut out)?;
//! assert_eq!(out.written(), b"gzip; title=\"say \\\"hi\\\"\"");
//! assert_eq!(write::write_quoted(b"a\nb", &mut out), Err(pn::WriteError::Forbidden { at: 1 }));
//! # Ok::<(), pn::WriteError>(())
//! ```

use core::fmt;

pub use crate::error::Full;
use crate::{class, error::WriteError, text};

/// The output abstraction every writer takes.
///
/// `put` appends all of `bytes` or fails with [`Full`]. `remaining` reports
/// how many more bytes fit, when the sink knows; writers that produce a value
/// in several `put` calls check it first, so a sink that knows its room never
/// holds half a value after an error.
///
/// # Examples
///
/// ```
/// use parse_net::{Full, Sink};
///
/// /// A sink that keeps only the last byte it was given.
/// struct Last(Option<u8>);
/// impl Sink for Last {
///     fn put(&mut self, bytes: &[u8]) -> Result<(), Full> {
///         if let Some(&b) = bytes.last() {
///             self.0 = Some(b);
///         }
///         Ok(())
///     }
/// }
///
/// let mut last = Last(None);
/// parse_net::write::write_token(b"gzip", &mut last)?;
/// assert_eq!(last.0, Some(b'p'));
/// # Ok::<(), parse_net::WriteError>(())
/// ```
pub trait Sink {
    /// Appends all of `bytes`, or fails with [`Full`] and appends nothing.
    ///
    /// # Errors
    ///
    /// [`Full`] when the sink has no room for `bytes`.
    fn put(&mut self, bytes: &[u8]) -> Result<(), Full>;

    /// How many more bytes fit, when the sink knows; `None` otherwise.
    fn remaining(&self) -> Option<usize> {
        None
    }
}

impl<S: Sink + ?Sized> Sink for &mut S {
    #[inline]
    fn put(&mut self, bytes: &[u8]) -> Result<(), Full> {
        (**self).put(bytes)
    }

    #[inline]
    fn remaining(&self) -> Option<usize> {
        (**self).remaining()
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl Sink for alloc::vec::Vec<u8> {
    #[inline]
    fn put(&mut self, bytes: &[u8]) -> Result<(), Full> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

/// A cursor over a caller buffer.
///
/// No allocation; reports [`remaining`](Sink::remaining); a `put` that does
/// not fit writes nothing. `Debug` prints the lengths only, never the bytes.
///
/// # Examples
///
/// ```
/// use parse_net::{Sink, SliceSink};
///
/// let mut buf = [0u8; 8];
/// let mut out = SliceSink::new(&mut buf);
/// out.put(b"gzip")?;
/// assert_eq!(out.written(), b"gzip");
/// assert_eq!(out.remaining(), Some(4));
/// out.clear();
/// assert!(out.is_empty());
/// # Ok::<(), parse_net::Full>(())
/// ```
pub struct SliceSink<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> SliceSink<'a> {
    /// A sink that writes into `buf`, starting at its first byte.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{Sink, SliceSink};
    ///
    /// let mut buf = [0u8; 4];
    /// let out = SliceSink::new(&mut buf);
    /// assert_eq!((out.len(), out.remaining()), (0, Some(4)));
    /// ```
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    /// The bytes written so far.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{write, SliceSink};
    ///
    /// let mut buf = [0u8; 16];
    /// let mut out = SliceSink::new(&mut buf);
    /// write::write_token(b"br", &mut out)?;
    /// assert_eq!(out.written(), b"br");
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    #[must_use]
    pub fn written(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }

    /// The number of bytes written so far.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{write, SliceSink};
    ///
    /// let mut buf = [0u8; 16];
    /// let mut out = SliceSink::new(&mut buf);
    /// write::write_quoted(b"a b", &mut out)?;
    /// assert_eq!(out.len(), 5);
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether nothing has been written.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{write, SliceSink};
    ///
    /// let mut buf = [0u8; 16];
    /// let mut out = SliceSink::new(&mut buf);
    /// assert!(out.is_empty());
    /// write::write_token(b"gzip", &mut out)?;
    /// assert!(!out.is_empty());
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Forgets what was written; the buffer is reused from its start.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{write, SliceSink};
    ///
    /// let mut buf = [0u8; 8];
    /// let mut out = SliceSink::new(&mut buf);
    /// write::write_token(b"gzip", &mut out)?;
    /// out.clear();
    /// write::write_token(b"br", &mut out)?;
    /// assert_eq!(out.written(), b"br");
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl Sink for SliceSink<'_> {
    #[inline]
    fn put(&mut self, bytes: &[u8]) -> Result<(), Full> {
        let end = self.len.checked_add(bytes.len()).ok_or(Full)?;
        let dst = self.buf.get_mut(self.len..end).ok_or(Full)?;
        dst.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    #[inline]
    fn remaining(&self) -> Option<usize> {
        Some(self.buf.len().saturating_sub(self.len))
    }
}

impl fmt::Debug for SliceSink<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SliceSink")
            .field("len", &self.len)
            .field("capacity", &self.buf.len())
            .finish()
    }
}

/// A sink that counts bytes and writes nothing.
///
/// Run a writer into it to learn the exact output length, then size a buffer
/// once. Saturates at `usize::MAX`.
///
/// # Examples
///
/// ```
/// use parse_net::{self as pn, write};
///
/// let mut count = pn::CountSink::new();
/// write::write_param(b"filename", b"my report.pdf", &mut count)?;
/// let mut buf = [0u8; 64];
/// let mut out = pn::SliceSink::new(&mut buf[..count.count()]);
/// write::write_param(b"filename", b"my report.pdf", &mut out)?;
/// assert_eq!(out.written(), b"; filename=\"my report.pdf\"");
/// # Ok::<(), pn::WriteError>(())
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CountSink {
    n: usize,
}

impl CountSink {
    /// A counter at zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::CountSink;
    ///
    /// const ZERO: CountSink = CountSink::new();
    /// assert_eq!((ZERO.count(), ZERO), (0, CountSink::default()));
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self { n: 0 }
    }

    /// The number of bytes put so far.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{write, CountSink};
    ///
    /// let mut count = CountSink::new();
    /// write::write_quoted(b"a b", &mut count)?;
    /// assert_eq!(count.count(), 5);
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    #[must_use]
    pub const fn count(&self) -> usize {
        self.n
    }
}

impl Sink for CountSink {
    #[inline]
    fn put(&mut self, bytes: &[u8]) -> Result<(), Full> {
        self.n = self.n.saturating_add(bytes.len());
        Ok(())
    }
}

/// Fails with `Full` before anything is written when the sink knows it has
/// less than `len` bytes of room.
#[inline]
pub(crate) fn reserve(out: &impl Sink, len: usize) -> Result<(), WriteError> {
    match out.remaining() {
        Some(room) if room < len => Err(WriteError::Full),
        _ => Ok(()),
    }
}

/// Fails with `DuplicateName` when two parameter names are equal ignoring
/// ASCII case: the output would be refused by every parser of the field.
pub(crate) fn unique_names(params: &[(&str, &str)]) -> Result<(), WriteError> {
    for (i, (a, _)) in params.iter().enumerate() {
        let later = params.get(i + 1..).unwrap_or(&[]);
        if later.iter().any(|(b, _)| a.eq_ignore_ascii_case(b)) {
            return Err(WriteError::DuplicateName);
        }
    }
    Ok(())
}

/// Writes `n` in decimal, with no sign and no padding.
///
/// # Errors
///
/// [`WriteError::Full`].
///
/// # Examples
///
/// ```
/// use parse_net::{write::write_decimal_u64, SliceSink};
///
/// let mut buf = [0u8; 20];
/// let mut out = SliceSink::new(&mut buf);
/// write_decimal_u64(u64::MAX, &mut out)?;
/// assert_eq!(out.written(), b"18446744073709551615");
/// # Ok::<(), parse_net::WriteError>(())
/// ```
pub fn write_decimal_u64(n: u64, out: &mut impl Sink) -> Result<(), WriteError> {
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    let mut v = n;
    loop {
        i -= 1;
        if let Some(d) = digits.get_mut(i) {
            // `v % 10` is below 10, so the cast cannot truncate.
            *d = b'0' + (v % 10) as u8;
        }
        v /= 10;
        if v == 0 || i == 0 {
            break;
        }
    }
    out.put(digits.get(i..).unwrap_or(&[]))?;
    Ok(())
}

/// Writes `n` in lowercase hexadecimal, with no prefix and no padding.
///
/// # Errors
///
/// [`WriteError::Full`].
///
/// # Examples
///
/// ```
/// use parse_net::{write::write_hex_u64, SliceSink};
///
/// let mut buf = [0u8; 16];
/// let mut out = SliceSink::new(&mut buf);
/// write_hex_u64(0xdead_beef, &mut out)?;
/// assert_eq!(out.written(), b"deadbeef");
/// # Ok::<(), parse_net::WriteError>(())
/// ```
pub fn write_hex_u64(n: u64, out: &mut impl Sink) -> Result<(), WriteError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut digits = [0u8; 16];
    let mut i = digits.len();
    let mut v = n;
    loop {
        i -= 1;
        if let (Some(d), Some(&h)) = (digits.get_mut(i), HEX.get((v & 0xf) as usize)) {
            *d = h;
        }
        v >>= 4;
        if v == 0 || i == 0 {
            break;
        }
    }
    out.put(digits.get(i..).unwrap_or(&[]))?;
    Ok(())
}

/// Writes `s` as a token, after checking it is one.
///
/// # Errors
///
/// [`WriteError::NotToken`] (also for empty input), [`WriteError::Full`].
///
/// # Examples
///
/// ```
/// use parse_net::{write::write_token, SliceSink, WriteError};
///
/// let mut buf = [0u8; 16];
/// let mut out = SliceSink::new(&mut buf);
/// write_token(b"no-cache", &mut out)?;
/// assert_eq!(write_token(b"no cache", &mut out), Err(WriteError::NotToken));
/// assert_eq!(out.written(), b"no-cache");
/// # Ok::<(), WriteError>(())
/// ```
pub fn write_token(s: &[u8], out: &mut impl Sink) -> Result<(), WriteError> {
    if !text::is_token(s) {
        return Err(WriteError::NotToken);
    }
    out.put(s)?;
    Ok(())
}

/// The length of `s` written as a quoted string, after checking every byte
/// may be written.
pub(crate) fn quoted_len(s: &[u8]) -> Result<usize, WriteError> {
    let mut len = s.len().saturating_add(2);
    for (i, &b) in s.iter().enumerate() {
        match b {
            b'"' | b'\\' => len = len.saturating_add(1),
            b'\t' => {}
            _ if class::is_quoted_pair_char(b) => {}
            _ => return Err(WriteError::forbidden(i)),
        }
    }
    Ok(len)
}

/// Writes `s` as a quoted string.
///
/// Only `"` and `\` are escaped (RFC 9110 section 5.6.4: senders SHOULD NOT
/// generate other quoted pairs); HTAB, SP, VCHAR, and obs-text are written as
/// they are.
///
/// # Errors
///
/// [`WriteError::Forbidden`] for CR, LF, NUL, another control byte, or DEL;
/// [`WriteError::Full`].
///
/// # Examples
///
/// ```
/// use parse_net::{write::write_quoted, SliceSink};
///
/// let mut buf = [0u8; 16];
/// let mut out = SliceSink::new(&mut buf);
/// write_quoted(b"a \"b\"", &mut out)?;
/// assert_eq!(out.written(), b"\"a \\\"b\\\"\"");
/// # Ok::<(), parse_net::WriteError>(())
/// ```
pub fn write_quoted(s: &[u8], out: &mut impl Sink) -> Result<(), WriteError> {
    let len = quoted_len(s)?;
    reserve(out, len)?;
    put_quoted(s, out)
}

/// Writes an already validated quoted string.
fn put_quoted(s: &[u8], out: &mut impl Sink) -> Result<(), WriteError> {
    out.put(b"\"")?;
    let mut rest = s;
    while let Some(i) = rest.iter().position(|&b| b == b'"' || b == b'\\') {
        let (plain, tail) = rest.split_at(i);
        out.put(plain)?;
        if let Some((escaped, after)) = tail.split_first() {
            out.put(&[b'\\', *escaped])?;
            rest = after;
        } else {
            rest = &[];
        }
    }
    out.put(rest)?;
    out.put(b"\"")?;
    Ok(())
}

/// The length of `s` written by [`write_word`].
pub(crate) fn word_len(s: &[u8]) -> Result<usize, WriteError> {
    if text::is_token(s) {
        Ok(s.len())
    } else {
        quoted_len(s)
    }
}

/// Writes `s` as a token when it is a non-empty token, and as a quoted string
/// otherwise (`token / quoted-string`, RFC 9110 section 5.6.6).
///
/// # Errors
///
/// As [`write_quoted`].
///
/// # Examples
///
/// ```
/// use parse_net::{write::write_word, SliceSink};
///
/// let mut buf = [0u8; 32];
/// let mut out = SliceSink::new(&mut buf);
/// write_word(b"utf-8", &mut out)?;
/// write_word(b" ", &mut out)?;
/// write_word(b"", &mut out)?;
/// assert_eq!(out.written(), b"utf-8\" \"\"\"");
/// # Ok::<(), parse_net::WriteError>(())
/// ```
pub fn write_word(s: &[u8], out: &mut impl Sink) -> Result<(), WriteError> {
    if text::is_token(s) {
        out.put(s)?;
        Ok(())
    } else {
        write_quoted(s, out)
    }
}

/// Writes `s` as a field value, after checking every byte is `field-vchar`,
/// SP, HTAB, or `obs-text`.
///
/// This is the header-injection guard: a value containing CR, LF, or NUL can
/// never reach the wire through it.
///
/// # Errors
///
/// [`WriteError::Forbidden`] at the first refused byte; [`WriteError::Full`].
///
/// # Examples
///
/// ```
/// use parse_net::{write::write_field_value, SliceSink, WriteError};
///
/// let mut buf = [0u8; 32];
/// let mut out = SliceSink::new(&mut buf);
/// write_field_value(b"text/html; charset=utf-8", &mut out)?;
/// assert_eq!(write_field_value(b"a\r\nb", &mut out), Err(WriteError::Forbidden { at: 1 }));
/// # Ok::<(), WriteError>(())
/// ```
pub fn write_field_value(s: &[u8], out: &mut impl Sink) -> Result<(), WriteError> {
    if let Err(e) = crate::scan::check_field_value(s) {
        return Err(WriteError::forbidden(e.offset()));
    }
    out.put(s)?;
    Ok(())
}

/// Writes `; name=value`, the value through [`write_word`].
///
/// # Errors
///
/// [`WriteError::NotToken`] for a name that is not a token, then as
/// [`write_word`].
///
/// # Examples
///
/// ```
/// use parse_net::{write::write_param, SliceSink};
///
/// let mut buf = [0u8; 32];
/// let mut out = SliceSink::new(&mut buf);
/// write_param(b"charset", b"utf-8", &mut out)?;
/// assert_eq!(out.written(), b"; charset=utf-8");
/// # Ok::<(), parse_net::WriteError>(())
/// ```
pub fn write_param(name: &[u8], value: &[u8], out: &mut impl Sink) -> Result<(), WriteError> {
    if !text::is_token(name) {
        return Err(WriteError::NotToken);
    }
    let value_len = word_len(value)?;
    reserve(out, name.len().saturating_add(3).saturating_add(value_len))?;
    out.put(b"; ")?;
    out.put(name)?;
    out.put(b"=")?;
    if text::is_token(value) {
        out.put(value)?;
        Ok(())
    } else {
        put_quoted(value, out)
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;

    fn written(f: impl Fn(&mut SliceSink<'_>) -> Result<(), WriteError>) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let mut out = SliceSink::new(&mut buf);
        f(&mut out).unwrap();
        out.written().to_vec()
    }

    #[test]
    fn test_number_writers_known_values() {
        assert_eq!(written(|o| write_decimal_u64(0, o)), b"0");
        assert_eq!(written(|o| write_decimal_u64(10, o)), b"10");
        assert_eq!(
            written(|o| write_decimal_u64(u64::MAX, o)),
            b"18446744073709551615"
        );
        assert_eq!(written(|o| write_hex_u64(0, o)), b"0");
        assert_eq!(written(|o| write_hex_u64(u64::MAX, o)), b"ffffffffffffffff");
        assert_eq!(written(|o| write_hex_u64(0x10, o)), b"10");
    }

    #[test]
    fn test_writers_refuse_crlf_in_every_position() {
        let bad: Vec<u8> = (0u8..0x20).filter(|&b| b != b'\t').chain([0x7f]).collect();
        for &b in &bad {
            for pos in 0..3 {
                let mut input = *b"abc";
                input[pos] = b;
                let mut buf = [0u8; 64];
                let mut out = SliceSink::new(&mut buf);
                let at = pos as u32;
                assert_eq!(
                    write_quoted(&input, &mut out),
                    Err(WriteError::Forbidden { at })
                );
                assert_eq!(
                    write_word(&input, &mut out),
                    Err(WriteError::Forbidden { at })
                );
                assert_eq!(
                    write_field_value(&input, &mut out),
                    Err(WriteError::Forbidden { at })
                );
                assert_eq!(
                    write_param(b"n", &input, &mut out),
                    Err(WriteError::Forbidden { at })
                );
                assert_eq!(write_token(&input, &mut out), Err(WriteError::NotToken));
                assert!(out.is_empty());
            }
        }
    }

    #[test]
    fn test_quoted_escapes_only_quote_and_backslash() {
        assert_eq!(written(|o| write_quoted(b"", o)), b"\"\"");
        assert_eq!(
            written(|o| write_quoted(b"a\\b\"c\td\x80", o)),
            b"\"a\\\\b\\\"c\td\x80\""
        );
    }

    #[test]
    fn test_slice_sink_one_byte_short_writes_nothing() {
        for (input, needed) in [(&b"a\"b"[..], 6usize), (b"x y", 5)] {
            let mut buf = [0u8; 16];
            let mut out = SliceSink::new(&mut buf[..needed - 1]);
            assert_eq!(write_quoted(input, &mut out), Err(WriteError::Full));
            assert!(out.is_empty());
            let mut out = SliceSink::new(&mut buf[..needed]);
            assert_eq!(write_quoted(input, &mut out), Ok(()));
        }
        let mut buf = [0u8; 9];
        let mut out = SliceSink::new(&mut buf);
        assert_eq!(
            write_param(b"name", b"a b", &mut out),
            Err(WriteError::Full)
        );
        assert!(out.is_empty());
        let mut buf = [0u8; 3];
        let mut out = SliceSink::new(&mut buf);
        assert_eq!(write_decimal_u64(1234, &mut out), Err(WriteError::Full));
        assert!(out.is_empty());
    }

    #[test]
    fn test_count_sink_matches_slice_output() {
        let mut count = CountSink::new();
        write_param(b"a", b"x\"y", &mut count).unwrap();
        assert_eq!(
            count.count(),
            written(|o| write_param(b"a", b"x\"y", o)).len()
        );
        let mut c = CountSink { n: usize::MAX };
        c.put(b"x").unwrap();
        assert_eq!(c.count(), usize::MAX);
    }

    #[test]
    fn test_param_name_must_be_token() {
        let mut buf = [0u8; 16];
        let mut out = SliceSink::new(&mut buf);
        assert_eq!(
            write_param(b"a b", b"x", &mut out),
            Err(WriteError::NotToken)
        );
        assert_eq!(write_param(b"", b"x", &mut out), Err(WriteError::NotToken));
    }

    #[test]
    fn test_sink_for_mut_reference_and_debug() {
        let mut buf = [0u8; 4];
        let mut out = SliceSink::new(&mut buf);
        {
            let r = &mut out;
            write_token(b"ab", &mut &mut *r).unwrap();
            assert_eq!(Sink::remaining(&r), Some(2));
        }
        assert_eq!(std::format!("{out:?}"), "SliceSink { len: 2, capacity: 4 }");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_vec_sink_grows() {
        let mut v = Vec::new();
        write_quoted(b"a b", &mut v).unwrap();
        assert_eq!(v, b"\"a b\"");
        assert_eq!(Sink::remaining(&v), None);
    }
}
