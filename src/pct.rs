//! The percent-encoding primitive: validate, decode into a caller buffer, and
//! encode with a named set and hex case.
//!
//! These are the operations parse-net's own grammars need (RFC 8187 values,
//! RFC 9651 Display Strings, RFC 7578 file names). Everything URL-specific
//! (component encode sets, `+` as space, normalization) belongs to url-lib,
//! which builds its sets with [`EncodeSet::add`] and [`EncodeSet::remove`].
//!
//! # Examples
//!
//! ```
//! use parse_net::{self as pn, pct::{self, EncodeSet, HexCase}, class::Class};
//!
//! let mut buf = [0u8; 16];
//! assert_eq!(pct::decode_utf8_into(b"caf%C3%A9", &mut buf)?, "caf\u{e9}");
//! assert_eq!(pct::validate(b"%4").unwrap_err().kind(), pn::ErrorKind::InvalidPercentEncoding);
//! assert!(pct::validate_with(b"/a/b?c=%20", Class::URI_TARGET).is_ok());
//!
//! let mut out = pn::SliceSink::new(&mut buf);
//! pct::encode(b"a b/c", &EncodeSet::ATTR_CHAR_COMPLEMENT, HexCase::Upper, &mut out).expect("room");
//! assert_eq!(out.written(), b"a%20b%2Fc");
//! # Ok::<(), pn::ParseError>(())
//! ```

use crate::{
    class::{self, Class},
    error::{ErrorKind, Result, WriteError, err},
    scan::control_kind,
    utf8::Utf8,
    write::{Sink, reserve},
};

/// A set of bytes that must be percent-encoded: a 256-bit bitmap.
///
/// [`encode`] always encodes bytes above 0x7F, whatever the set says.
///
/// # Examples
///
/// ```
/// use parse_net::pct::EncodeSet;
///
/// let path = EncodeSet::CONTROLS_AND_NON_ASCII.add(b' ').add(b'#').add(b'?');
/// assert!(path.contains(b'#') && !path.contains(b'/'));
/// assert!(!path.remove(b'#').contains(b'#'));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EncodeSet([u64; 4]);

/// Which named set [`set_of`] builds.
#[derive(Clone, Copy)]
enum Named {
    ControlsAndNonAscii,
    AttrCharComplement,
    SfDisplay,
}

const fn in_named(b: u8, which: Named) -> bool {
    match which {
        Named::ControlsAndNonAscii => b < 0x20 || b >= 0x7f,
        Named::AttrCharComplement => !class::is_attr_char(b),
        Named::SfDisplay => b == b'%' || b == b'"' || b < 0x20 || b > 0x7e,
    }
}

const fn set_of(which: Named) -> [u64; 4] {
    let mut bits = [0u64; 4];
    let mut b: u8 = 0;
    loop {
        if in_named(b, which) {
            let word = (b >> 6) as usize;
            // `word` is 0 to 3.
            #[allow(clippy::indexing_slicing)]
            {
                bits[word] |= 1 << (b & 63);
            }
        }
        if b == u8::MAX {
            break;
        }
        b += 1;
    }
    bits
}

impl EncodeSet {
    /// C0 controls, DEL, and 0x80 to 0xFF.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::pct::EncodeSet;
    ///
    /// let s = EncodeSet::CONTROLS_AND_NON_ASCII;
    /// assert!(s.contains(b'\n') && s.contains(0x7f) && s.contains(0xe9));
    /// assert!(!s.contains(b' ') && !s.contains(b'%'));
    /// ```
    pub const CONTROLS_AND_NON_ASCII: Self = Self(set_of(Named::ControlsAndNonAscii));
    /// Every byte that is not an `attr-char` (RFC 8187 section 3.2.1).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::pct::EncodeSet;
    ///
    /// let s = EncodeSet::ATTR_CHAR_COMPLEMENT;
    /// assert!(s.contains(b' ') && s.contains(b'%') && s.contains(b'\''));
    /// assert!(!s.contains(b'a') && !s.contains(b'~'));
    /// ```
    pub const ATTR_CHAR_COMPLEMENT: Self = Self(set_of(Named::AttrCharComplement));
    /// `%`, `"`, and every byte outside 0x20 to 0x7E (RFC 9651 section 4.1.11).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::pct::EncodeSet;
    ///
    /// let s = EncodeSet::SF_DISPLAY;
    /// assert!(s.contains(b'%') && s.contains(b'"') && s.contains(0x7f));
    /// assert!(!s.contains(b' ') && !s.contains(b'~'));
    /// ```
    pub const SF_DISPLAY: Self = Self(set_of(Named::SfDisplay));

    /// The empty set (only bytes above 0x7F are then encoded).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::pct::{encoded_len, EncodeSet};
    ///
    /// let none = EncodeSet::empty();
    /// assert!(!none.contains(b'%'));
    /// assert_eq!(encoded_len(b"a b", &none), 3);
    /// assert_eq!(encoded_len(&[0xff], &none), 3);
    /// ```
    #[must_use]
    pub const fn empty() -> Self {
        Self([0; 4])
    }

    /// The set with `b` added.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::pct::EncodeSet;
    ///
    /// let s = EncodeSet::empty().add(b'/');
    /// assert!(s.contains(b'/') && !s.contains(b'?'));
    /// ```
    #[must_use]
    pub const fn add(self, b: u8) -> Self {
        let mut bits = self.0;
        let word = (b >> 6) as usize;
        // `word` is 0 to 3.
        #[allow(clippy::indexing_slicing)]
        {
            bits[word] |= 1 << (b & 63);
        }
        Self(bits)
    }

    /// The set with `b` removed.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::pct::EncodeSet;
    ///
    /// let s = EncodeSet::ATTR_CHAR_COMPLEMENT.remove(b'%');
    /// assert!(!s.contains(b'%') && s.contains(b' '));
    /// ```
    #[must_use]
    pub const fn remove(self, b: u8) -> Self {
        let mut bits = self.0;
        let word = (b >> 6) as usize;
        // `word` is 0 to 3.
        #[allow(clippy::indexing_slicing)]
        {
            bits[word] &= !(1 << (b & 63));
        }
        Self(bits)
    }

    /// Whether `b` is in the set.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::pct::EncodeSet;
    ///
    /// assert!(EncodeSet::SF_DISPLAY.contains(b'"'));
    /// assert!(!EncodeSet::SF_DISPLAY.contains(b'a'));
    /// ```
    #[must_use]
    pub const fn contains(&self, b: u8) -> bool {
        let word = (b >> 6) as usize;
        // `word` is 0 to 3.
        #[allow(clippy::indexing_slicing)]
        let w = self.0[word];
        w & (1 << (b & 63)) != 0
    }
}

/// The hex case [`encode`] writes.
///
/// # Examples
///
/// ```
/// use parse_net::{pct::{encode, EncodeSet, HexCase}, SliceSink};
///
/// let mut buf = [0u8; 8];
/// let mut out = SliceSink::new(&mut buf);
/// encode(b"/", &EncodeSet::ATTR_CHAR_COMPLEMENT, HexCase::Lower, &mut out)?;
/// assert_eq!(out.written(), b"%2f");
/// # Ok::<(), parse_net::WriteError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HexCase {
    /// `%2F` (RFC 3986 section 2.1 recommends uppercase).
    Upper,
    /// `%2f` (required by RFC 9651 Display Strings).
    Lower,
}

/// How the hex digits of a triple may be written.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Accept {
    AnyCase,
    LowerOnly,
}

/// Walks `input`, calling `f` with each decoded byte and its offset.
#[inline]
fn walk(input: &[u8], accept: Accept, mut f: impl FnMut(u8, usize) -> Result<()>) -> Result<()> {
    let mut i = 0usize;
    while let Some(&b) = input.get(i) {
        if b == b'%' {
            let hi = input.get(i + 1).copied().and_then(|h| hex(h, accept));
            let lo = input.get(i + 2).copied().and_then(|h| hex(h, accept));
            let (Some(hi), Some(lo)) = (hi, lo) else {
                return err(ErrorKind::InvalidPercentEncoding, i);
            };
            f((hi << 4) | lo, i)?;
            i += 3;
        } else {
            f(b, i)?;
            i += 1;
        }
    }
    Ok(())
}

#[inline]
const fn hex(b: u8, accept: Accept) -> Option<u8> {
    match (b, accept) {
        (b'A'..=b'F', Accept::LowerOnly) => None,
        _ => class::hex_value(b),
    }
}

/// Checks that every `%` is followed by two hex digits (either case).
///
/// # Errors
///
/// [`ErrorKind::InvalidPercentEncoding`] at the `%`.
///
/// # Examples
///
/// ```
/// use parse_net::pct::validate;
///
/// assert!(validate(b"a%20b").is_ok());
/// assert_eq!(validate(b"a%2").unwrap_err().offset(), 1);
/// ```
pub fn validate(input: &[u8]) -> Result<()> {
    walk(input, Accept::AnyCase, |_, _| Ok(()))
}

/// As [`validate`], and every byte other than a `%XX` triple is in `allowed`.
///
/// `validate_with(target, Class::URI_TARGET)` checks the characters of a
/// request target.
///
/// # Errors
///
/// [`ErrorKind::InvalidPercentEncoding`]; a control kind for a control byte;
/// [`ErrorKind::InvalidByte`] for another byte outside `allowed`.
///
/// # Examples
///
/// ```
/// use parse_net::{pct::validate_with, class::Class, ErrorKind};
///
/// assert!(validate_with(b"/a/b?c=d&e=%20", Class::URI_TARGET).is_ok());
/// assert_eq!(validate_with(b"/a#frag", Class::URI_TARGET).unwrap_err().kind(), ErrorKind::InvalidByte);
/// ```
pub fn validate_with(input: &[u8], allowed: Class) -> Result<()> {
    let mut i = 0usize;
    while let Some(&b) = input.get(i) {
        if b == b'%' {
            match (input.get(i + 1), input.get(i + 2)) {
                (Some(&h), Some(&l)) if class::is_hexdig(h) && class::is_hexdig(l) => i += 3,
                _ => return err(ErrorKind::InvalidPercentEncoding, i),
            }
        } else if allowed.contains(b) {
            i += 1;
        } else if crate::scan::is_control(b) {
            return err(control_kind(b), i);
        } else {
            return err(ErrorKind::InvalidByte, i);
        }
    }
    Ok(())
}

/// Validates `input` and returns its decoded length.
///
/// # Errors
///
/// [`ErrorKind::InvalidPercentEncoding`].
///
/// # Examples
///
/// ```
/// assert_eq!(parse_net::pct::decoded_len(b"a%20b")?, 3);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn decoded_len(input: &[u8]) -> Result<usize> {
    let mut n = 0usize;
    walk(input, Accept::AnyCase, |_, _| {
        n += 1;
        Ok(())
    })?;
    Ok(n)
}

fn decode_with<'b>(
    input: &[u8],
    out: &'b mut [u8],
    accept: Accept,
    utf8: bool,
) -> Result<&'b [u8]> {
    // First pass: validate everything and size the output, writing nothing.
    let mut n = 0usize;
    let mut v = Utf8::new();
    walk(input, accept, |b, at| {
        if utf8 && !v.push(b) {
            return err(ErrorKind::InvalidUtf8, at);
        }
        n += 1;
        Ok(())
    })?;
    if utf8 && !v.is_complete() {
        return err(ErrorKind::InvalidUtf8, input.len());
    }
    let Some(dst) = out.get_mut(..n) else {
        return err(ErrorKind::BufferTooSmall, 0);
    };
    let mut slots = dst.iter_mut();
    walk(input, accept, |b, _| {
        if let Some(slot) = slots.next() {
            *slot = b;
        }
        Ok(())
    })?;
    Ok(dst)
}

/// Decodes `%XX` triples (either case) into `out`, copying every other byte,
/// and returns the written part.
///
/// # Errors
///
/// [`ErrorKind::InvalidPercentEncoding`]; [`ErrorKind::BufferTooSmall`].
/// Nothing is written on error.
///
/// # Examples
///
/// ```
/// let mut buf = [0u8; 8];
/// assert_eq!(parse_net::pct::decode_into(b"a%2Fb", &mut buf)?, b"a/b");
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn decode_into<'b>(input: &[u8], out: &'b mut [u8]) -> Result<&'b [u8]> {
    decode_with(input, out, Accept::AnyCase, false)
}

/// As [`decode_into`], and the decoded bytes must be UTF-8 (overlong forms
/// and surrogates refused).
///
/// # Errors
///
/// [`ErrorKind::InvalidUtf8`], and as [`decode_into`]. Nothing is written on
/// error.
///
/// # Examples
///
/// ```
/// use parse_net::{pct::decode_utf8_into, ErrorKind};
///
/// let mut buf = [0u8; 8];
/// assert_eq!(decode_utf8_into(b"%E2%82%AC", &mut buf)?, "\u{20ac}");
/// assert_eq!(decode_utf8_into(b"%C0%AF", &mut buf).unwrap_err().kind(), ErrorKind::InvalidUtf8);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn decode_utf8_into<'b>(input: &[u8], out: &'b mut [u8]) -> Result<&'b str> {
    let bytes = decode_with(input, out, Accept::AnyCase, true)?;
    core::str::from_utf8(bytes)
        .map_err(|e| crate::ParseError::new(ErrorKind::InvalidUtf8, e.valid_up_to()))
}

/// As [`decode_into`], refusing uppercase hex (RFC 9651 section 4.2.10).
///
/// # Errors
///
/// [`ErrorKind::InvalidPercentEncoding`] for uppercase hex or a broken
/// triple; [`ErrorKind::BufferTooSmall`]. Nothing is written on error.
///
/// # Examples
///
/// ```
/// use parse_net::pct::decode_lower_only_into;
///
/// let mut buf = [0u8; 4];
/// assert_eq!(decode_lower_only_into(b"%c3%a9", &mut buf)?, b"\xc3\xa9");
/// assert!(decode_lower_only_into(b"%C3%A9", &mut buf).is_err());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn decode_lower_only_into<'b>(input: &[u8], out: &'b mut [u8]) -> Result<&'b [u8]> {
    decode_with(input, out, Accept::LowerOnly, false)
}

#[inline]
fn must_encode(b: u8, set: &EncodeSet) -> bool {
    b >= 0x80 || set.contains(b)
}

/// The length of `input` once encoded with `set`.
///
/// # Examples
///
/// ```
/// use parse_net::pct::{encoded_len, EncodeSet};
///
/// assert_eq!(encoded_len(b"a b", &EncodeSet::empty().add(b' ')), 5);
/// ```
#[must_use]
pub fn encoded_len(input: &[u8], set: &EncodeSet) -> usize {
    input
        .iter()
        .map(|&b| if must_encode(b, set) { 3 } else { 1 })
        .fold(0usize, usize::saturating_add)
}

/// Writes `input` with every byte in `set`, and every byte above 0x7F, as
/// `%XX`.
///
/// # Errors
///
/// [`WriteError::Full`]; nothing is written when the sink reports its room.
///
/// # Examples
///
/// ```
/// use parse_net::{pct::{encode, EncodeSet, HexCase}, SliceSink};
///
/// let mut buf = [0u8; 16];
/// let mut out = SliceSink::new(&mut buf);
/// encode("caf\u{e9}".as_bytes(), &EncodeSet::SF_DISPLAY, HexCase::Lower, &mut out).expect("room");
/// assert_eq!(out.written(), b"caf%c3%a9");
/// ```
pub fn encode(
    input: &[u8],
    set: &EncodeSet,
    case: HexCase,
    out: &mut impl Sink,
) -> core::result::Result<(), WriteError> {
    reserve(out, encoded_len(input, set))?;
    let digits: &[u8; 16] = match case {
        HexCase::Upper => b"0123456789ABCDEF",
        HexCase::Lower => b"0123456789abcdef",
    };
    let mut rest = input;
    while !rest.is_empty() {
        let plain = rest.iter().take_while(|&&b| !must_encode(b, set)).count();
        let (literal, tail) = rest.split_at(plain);
        out.put(literal)?;
        if let Some((&b, after)) = tail.split_first() {
            let hi = digits.get(usize::from(b >> 4)).copied().unwrap_or(b'0');
            let lo = digits.get(usize::from(b & 15)).copied().unwrap_or(b'0');
            out.put(&[b'%', hi, lo])?;
            rest = after;
        } else {
            rest = &[];
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::write::SliceSink;

    #[test]
    fn test_pct_edge_cases() {
        let mut buf = [0u8; 8];
        for bad in [&b"%"[..], b"%4", b"%4g", b"a%", b"%g4"] {
            assert_eq!(
                validate(bad).unwrap_err().kind(),
                ErrorKind::InvalidPercentEncoding
            );
            assert_eq!(
                decode_into(bad, &mut buf).unwrap_err().kind(),
                ErrorKind::InvalidPercentEncoding
            );
        }
        assert_eq!(decode_into(b"%41", &mut buf).unwrap(), b"A");
        assert_eq!(decode_into(b"%c3%a9", &mut buf).unwrap(), b"\xc3\xa9");
        assert_eq!(decode_into(b"%C3%A9", &mut buf).unwrap(), b"\xc3\xa9");
        assert_eq!(decode_into(b"%00", &mut buf).unwrap(), b"\x00");
        assert_eq!(
            decode_utf8_into(b"%c3", &mut buf).unwrap_err().kind(),
            ErrorKind::InvalidUtf8
        );
        assert_eq!(
            decode_utf8_into(b"%ed%a0%80", &mut buf).unwrap_err().kind(),
            ErrorKind::InvalidUtf8
        );
        let e = decode_lower_only_into(b"ab%2F", &mut buf).unwrap_err();
        assert_eq!(
            (e.kind(), e.offset()),
            (ErrorKind::InvalidPercentEncoding, 2)
        );
    }

    #[test]
    fn test_pct_decode_buffer_one_short_writes_nothing() {
        let mut buf = [0xaau8; 2];
        assert_eq!(
            decode_into(b"a%20b", &mut buf).unwrap_err().kind(),
            ErrorKind::BufferTooSmall
        );
        assert_eq!(buf, [0xaa, 0xaa]);
        let mut buf = [0xaau8; 3];
        assert_eq!(
            decode_utf8_into(b"a%c3", &mut buf).unwrap_err().kind(),
            ErrorKind::InvalidUtf8
        );
        assert_eq!(buf, [0xaa; 3]);
    }

    #[test]
    fn test_validate_with_target_matches_http_net() {
        assert!(validate_with(b"/a/b?c=d&e=%20", Class::URI_TARGET).is_ok());
        assert!(validate_with(b"/a%2", Class::URI_TARGET).is_err());
        assert!(validate_with(b"/a%zz", Class::URI_TARGET).is_err());
        assert!(validate_with(b"/a b", Class::URI_TARGET).is_err());
        assert!(validate_with(b"/a#frag", Class::URI_TARGET).is_err());
        assert_eq!(
            validate_with(b"/a\x7f", Class::URI_TARGET)
                .unwrap_err()
                .kind(),
            ErrorKind::Control
        );
    }

    #[test]
    fn test_encode_sets_and_round_trip() {
        for b in 0u8..=255 {
            assert_eq!(
                EncodeSet::ATTR_CHAR_COMPLEMENT.contains(b),
                !class::is_attr_char(b)
            );
            assert_eq!(
                EncodeSet::CONTROLS_AND_NON_ASCII.contains(b),
                !(0x20..0x7f).contains(&b)
            );
            assert!(EncodeSet::empty().add(b).contains(b));
            assert!(!EncodeSet::SF_DISPLAY.remove(b).contains(b));
        }
        let all: std::vec::Vec<u8> = (0u8..=255).collect();
        let mut buf = [0u8; 1024];
        let mut out = SliceSink::new(&mut buf);
        encode(
            &all,
            &EncodeSet::ATTR_CHAR_COMPLEMENT,
            HexCase::Upper,
            &mut out,
        )
        .unwrap();
        assert_eq!(
            out.len(),
            encoded_len(&all, &EncodeSet::ATTR_CHAR_COMPLEMENT)
        );
        let mut back = [0u8; 256];
        assert_eq!(decode_into(out.written(), &mut back).unwrap(), &all[..]);
    }

    #[test]
    fn test_encode_full_writes_nothing() {
        let mut buf = [0u8; 4];
        let mut out = SliceSink::new(&mut buf);
        assert_eq!(
            encode(
                b"a b",
                &EncodeSet::empty().add(b' '),
                HexCase::Upper,
                &mut out
            ),
            Err(WriteError::Full)
        );
        assert!(out.is_empty());
    }
}
