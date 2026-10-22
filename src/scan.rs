//! Byte search and field-value validation, eight bytes per step.
//!
//! The fast paths read the input as little-endian `u64` words and use the
//! classic "has zero byte" bit trick (SWAR: SIMD within a register), with no
//! `unsafe`. Each one agrees with the bytewise definition for every byte at
//! every position; the tests and property tests check exactly that.

use crate::{
    class::{self, Class},
    error::{ErrorKind, Result, err},
};

const LO: u64 = 0x0101_0101_0101_0101;
const HI: u64 = 0x8080_8080_8080_8080;

/// The high bit of each byte of `x` that is zero is set; bits above the first
/// zero byte may be set falsely, so only the lowest set marker is exact.
#[inline]
const fn zero_markers(x: u64) -> u64 {
    x.wrapping_sub(LO) & !x & HI
}

#[inline]
fn word(chunk: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    if let Ok(exact) = <[u8; 8]>::try_from(chunk) {
        bytes = exact;
    }
    u64::from_le_bytes(bytes)
}

#[inline]
fn first_marker(markers: u64) -> usize {
    (markers.trailing_zeros() / 8) as usize
}

/// The index of the first `needle` in `hay`.
///
/// Identical to `hay.iter().position(|&b| b == needle)`, eight bytes per
/// step.
///
/// # Examples
///
/// ```
/// use parse_net::scan::find_byte;
///
/// assert_eq!(find_byte(b';', b"text/html; charset=utf-8"), Some(9));
/// assert_eq!(find_byte(b',', b"gzip"), None);
/// ```
#[inline]
#[must_use]
pub fn find_byte(needle: u8, hay: &[u8]) -> Option<usize> {
    let pattern = u64::from_le_bytes([needle; 8]);
    let mut chunks = hay.chunks_exact(8);
    let mut base = 0usize;
    for chunk in &mut chunks {
        let found = zero_markers(word(chunk) ^ pattern);
        if found != 0 {
            return Some(base + first_marker(found));
        }
        base += 8;
    }
    chunks
        .remainder()
        .iter()
        .position(|&b| b == needle)
        .map(|i| base + i)
}

/// The index of the first byte in `hay` that equals `a` or `b`.
///
/// # Examples
///
/// ```
/// use parse_net::scan::find_either;
///
/// assert_eq!(find_either(b',', b'"', b"a=\"x,y\", b"), Some(2));
/// ```
#[inline]
#[must_use]
pub fn find_either(a: u8, b: u8, hay: &[u8]) -> Option<usize> {
    let pa = u64::from_le_bytes([a; 8]);
    let pb = u64::from_le_bytes([b; 8]);
    let mut chunks = hay.chunks_exact(8);
    let mut base = 0usize;
    for chunk in &mut chunks {
        let w = word(chunk);
        let found = zero_markers(w ^ pa) | zero_markers(w ^ pb);
        if found != 0 {
            // The lowest marker of the union is exact: a false marker in one
            // half can only sit above a true one in that half.
            return Some(base + first_marker(found));
        }
        base += 8;
    }
    chunks
        .remainder()
        .iter()
        .position(|&x| x == a || x == b)
        .map(|i| base + i)
}

/// The index of the first byte of `s` outside `class`.
///
/// # Examples
///
/// ```
/// use parse_net::{scan::first_not_in, class::Class};
///
/// assert_eq!(first_not_in(b"gzip, br", Class::TCHAR), Some(4));
/// assert_eq!(first_not_in(b"gzip", Class::TCHAR), None);
/// ```
#[inline]
#[must_use]
pub fn first_not_in(s: &[u8], class: Class) -> Option<usize> {
    s.iter().position(|&b| !class.contains(b))
}

/// Validates a field value per RFC 9110 section 5.5: every byte is
/// `field-vchar`, SP, HTAB, or `obs-text`.
///
/// This is the guard every engine runs on every field value. It does not
/// strip OWS; an empty value is valid.
///
/// # Errors
///
/// [`ErrorKind::BareCr`] for CR, [`ErrorKind::LineFeed`] for LF,
/// [`ErrorKind::Nul`] for NUL, and [`ErrorKind::Control`] for any other
/// control byte or DEL, each at the offending offset.
///
/// # Examples
///
/// ```
/// use parse_net::{scan::check_field_value, ErrorKind};
///
/// assert!(check_field_value(b"caf\xc3\xa9 \tok").is_ok());
/// assert_eq!(check_field_value(b"abcdefgh\x00").unwrap_err().kind(), ErrorKind::Nul);
/// assert_eq!(check_field_value(b"a\nb").unwrap_err().offset(), 1);
/// ```
#[inline]
pub fn check_field_value(value: &[u8]) -> Result<()> {
    let mut chunks = value.chunks_exact(8);
    let mut base = 0usize;
    for chunk in &mut chunks {
        let w = word(chunk);
        // A byte is suspicious when it is below 0x20, equal to 0x7F, or has
        // the high bit set (obs-text is valid, but rare enough to check
        // bytewise). Suspicious words drop to the exact per-byte check.
        let low = w.wrapping_sub(0x2020_2020_2020_2020) & !w & HI;
        let del = zero_markers(w ^ 0x7f7f_7f7f_7f7f_7f7f);
        if (low | del | (w & HI)) != 0 {
            check_field_bytes(chunk, base)?;
        }
        base += 8;
    }
    check_field_bytes(chunks.remainder(), base)
}

#[inline]
fn check_field_bytes(bytes: &[u8], base: usize) -> Result<()> {
    match bytes.iter().position(|&b| !class::is_field_text(b)) {
        None => Ok(()),
        Some(i) => err(control_kind(bytes.get(i).copied().unwrap_or(0)), base + i),
    }
}

/// Whether `b` is a control byte that no field value may hold: C0 other than
/// HTAB, or DEL. HTAB is field text, so a misplaced tab is a grammar error,
/// not a control (D-037).
#[inline]
pub(crate) const fn is_control(b: u8) -> bool {
    (b < 0x20 && b != 0x09) || b == 0x7f
}

/// The error kind for a byte that is not allowed in a field value.
#[inline]
pub(crate) const fn control_kind(b: u8) -> ErrorKind {
    match b {
        b'\r' => ErrorKind::BareCr,
        b'\n' => ErrorKind::LineFeed,
        0 => ErrorKind::Nul,
        _ => ErrorKind::Control,
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;

    #[test]
    fn test_find_byte_matches_position() {
        let hay: std::vec::Vec<u8> = (0..64u8).collect();
        for needle in 0..70u8 {
            assert_eq!(
                find_byte(needle, &hay),
                hay.iter().position(|&b| b == needle)
            );
        }
        assert_eq!(find_byte(b'\n', b"\x0b\x0a"), Some(1));
        assert_eq!(find_byte(1, &[0x81, 0x01]), Some(1));
        assert_eq!(find_byte(b'a', b""), None);
    }

    #[test]
    fn test_find_byte_false_marker_above_true_one() {
        // 0x01 after 0x00 can raise a false marker; the first match must win.
        let hay = [2u8, 2, 1, 0, 1, 2, 2, 2, 2];
        assert_eq!(find_byte(1, &hay), Some(2));
        assert_eq!(find_byte(0, &hay), Some(3));
    }

    #[test]
    fn test_find_either_every_position() {
        for len in 0..20usize {
            for pos_a in 0..len {
                let mut v = vec![b'x'; len];
                v[pos_a] = b',';
                for pos_b in 0..len {
                    let mut w = v.clone();
                    w[pos_b] = b'"';
                    let expected = w.iter().position(|&b| b == b',' || b == b'"');
                    assert_eq!(find_either(b',', b'"', &w), expected);
                }
            }
        }
    }

    #[test]
    fn test_field_value_rejects_controls_with_kinds() {
        assert!(check_field_value(b"").is_ok());
        assert!(check_field_value(b"text/html; q=0.9\tx").is_ok());
        assert!(check_field_value(b"caf\xc3\xa9 \x80\xff").is_ok());
        let e = check_field_value(b"a\rb").unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::BareCr, 1));
        let e = check_field_value(b"abcdefgh\x00ijk").unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::Nul, 8));
        let e = check_field_value(b"abcdefghijklmno\x7f").unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::Control, 15));
        let e = check_field_value(b"abcdefg\nhij").unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::LineFeed, 7));
        assert_eq!(
            check_field_value(b"\x0b").unwrap_err().kind(),
            ErrorKind::Control
        );
        assert_eq!(
            check_field_value(b"\x0c").unwrap_err().kind(),
            ErrorKind::Control
        );
    }

    #[test]
    fn test_field_value_fast_path_agrees_with_bytewise() {
        for b in 0u8..=255 {
            for pos in 0..17 {
                let mut v = vec![b'a'; 17];
                v[pos] = b;
                let fast = check_field_value(&v);
                let slow = check_field_bytes(&v, 0);
                assert_eq!(fast, slow, "byte {b:#04x} at {pos}");
            }
        }
    }

    #[test]
    fn test_field_value_one_mebibyte() {
        let v = vec![b'a'; 1 << 20];
        assert!(check_field_value(&v).is_ok());
    }

    #[test]
    fn test_first_not_in_positions() {
        assert_eq!(first_not_in(b"", Class::TCHAR), None);
        assert_eq!(first_not_in(b" a", Class::TCHAR), Some(0));
    }
}
