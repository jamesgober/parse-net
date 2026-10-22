//! Decimal digits with overflow checks.

use crate::error::{ErrorKind, Result, err};

/// Parses `1*DIGIT` into a `u64`.
///
/// No sign, no whitespace, no trimming; leading zeros are allowed.
///
/// # Errors
///
/// [`ErrorKind::Empty`] for an empty input, [`ErrorKind::InvalidNumber`] at
/// the first byte that is not a digit, [`ErrorKind::NumberOverflow`] at the
/// digit that overflows.
///
/// # Examples
///
/// ```
/// use parse_net::{num::parse_u64, ErrorKind};
///
/// assert_eq!(parse_u64(b"18446744073709551615")?, u64::MAX);
/// assert_eq!(parse_u64(b"18446744073709551616").unwrap_err().kind(), ErrorKind::NumberOverflow);
/// assert_eq!(parse_u64(b"+1").unwrap_err().kind(), ErrorKind::InvalidNumber);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_u64(digits: &[u8]) -> Result<u64> {
    if digits.is_empty() {
        return err(ErrorKind::Empty, 0);
    }
    let mut n: u64 = 0;
    for (i, &b) in digits.iter().enumerate() {
        if !b.is_ascii_digit() {
            return err(ErrorKind::InvalidNumber, i);
        }
        n = match n
            .checked_mul(10)
            .and_then(|m| m.checked_add(u64::from(b - b'0')))
        {
            Some(v) => v,
            None => return err(ErrorKind::NumberOverflow, i),
        };
    }
    Ok(n)
}

/// The value `delta-seconds` saturate at (RFC 9111 section 1.2.2).
pub(crate) const DELTA_SECONDS_MAX: u32 = 2_147_483_648;

/// Parses `1*DIGIT` by the `delta-seconds` rule of RFC 9111 section 1.2.2:
/// any number of digits, values above 2147483648 give 2147483648.
///
/// # Errors
///
/// [`ErrorKind::Empty`], [`ErrorKind::InvalidNumber`].
///
/// # Examples
///
/// ```
/// use parse_net::num::parse_u32_saturating;
///
/// assert_eq!(parse_u32_saturating(b"60")?, 60);
/// assert_eq!(parse_u32_saturating(b"99999999999999999999")?, 2_147_483_648);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_u32_saturating(digits: &[u8]) -> Result<u32> {
    if digits.is_empty() {
        return err(ErrorKind::Empty, 0);
    }
    // Nine digits cannot overflow a u32 (999,999,999 < 2^32), so the usual
    // lengths take a loop without saturating steps.
    if digits.len() <= 9 {
        let mut n: u32 = 0;
        for (i, &b) in digits.iter().enumerate() {
            let d = b.wrapping_sub(b'0');
            if d > 9 {
                return err(ErrorKind::InvalidNumber, i);
            }
            n = n * 10 + u32::from(d);
        }
        return Ok(n.min(DELTA_SECONDS_MAX));
    }
    let mut n: u32 = 0;
    for (i, &b) in digits.iter().enumerate() {
        if !b.is_ascii_digit() {
            return err(ErrorKind::InvalidNumber, i);
        }
        n = n
            .saturating_mul(10)
            .saturating_add(u32::from(b - b'0'))
            .min(DELTA_SECONDS_MAX);
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_u64_rejects_signs_and_overflow() {
        assert_eq!(parse_u64(b"0"), Ok(0));
        assert_eq!(parse_u64(b"007"), Ok(7));
        assert_eq!(parse_u64(b"18446744073709551615"), Ok(u64::MAX));
        let e = parse_u64(b"18446744073709551616").unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::NumberOverflow, 19));
        assert_eq!(
            parse_u64(b"+1").unwrap_err().kind(),
            ErrorKind::InvalidNumber
        );
        assert_eq!(
            parse_u64(b"-1").unwrap_err().kind(),
            ErrorKind::InvalidNumber
        );
        assert_eq!(parse_u64(b"").unwrap_err().kind(), ErrorKind::Empty);
        let e = parse_u64(b"1 ").unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::InvalidNumber, 1));
    }

    #[test]
    fn test_parse_u32_saturating_boundaries() {
        assert_eq!(parse_u32_saturating(b"2147483647"), Ok(2_147_483_647));
        assert_eq!(parse_u32_saturating(b"2147483648"), Ok(2_147_483_648));
        assert_eq!(parse_u32_saturating(b"2147483649"), Ok(2_147_483_648));
        assert_eq!(parse_u32_saturating(b"4294967296"), Ok(2_147_483_648));
        assert_eq!(
            parse_u32_saturating(b"").unwrap_err().kind(),
            ErrorKind::Empty
        );
        assert_eq!(
            parse_u32_saturating(b"6s").unwrap_err().kind(),
            ErrorKind::InvalidNumber
        );
    }

    /// The definition the fast path must agree with: exact value, clamped.
    fn reference_u32(d: &[u8]) -> Result<u32> {
        if d.is_empty() {
            return err(ErrorKind::Empty, 0);
        }
        let mut n: u128 = 0;
        for (i, &b) in d.iter().enumerate() {
            if !b.is_ascii_digit() {
                return err(ErrorKind::InvalidNumber, i);
            }
            n = (n * 10 + u128::from(b - b'0')).min(u128::from(u32::MAX) + 1);
        }
        Ok(u32::try_from(n.min(u128::from(DELTA_SECONDS_MAX))).unwrap_or(DELTA_SECONDS_MAX))
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(8192))]

        #[test]
        fn test_parse_u32_saturating_agrees_with_reference(d in "[0-9]{0,22}|[0-9]{0,10}[^0-9][0-9]{0,4}") {
            proptest::prop_assert_eq!(parse_u32_saturating(d.as_bytes()), reference_u32(d.as_bytes()));
        }
    }

    #[test]
    fn test_parse_u32_saturating_length_boundaries() {
        assert_eq!(parse_u32_saturating(b"999999999"), Ok(999_999_999));
        assert_eq!(parse_u32_saturating(b"000000000"), Ok(0));
        assert_eq!(parse_u32_saturating(b"2147483647"), Ok(2_147_483_647));
        assert_eq!(parse_u32_saturating(b"2147483648"), Ok(DELTA_SECONDS_MAX));
        assert_eq!(parse_u32_saturating(b"2147483649"), Ok(DELTA_SECONDS_MAX));
        assert_eq!(
            parse_u32_saturating(b"99999999999999999999"),
            Ok(DELTA_SECONDS_MAX)
        );
        let e = parse_u32_saturating(b"12345678/").unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::InvalidNumber, 8));
        let e = parse_u32_saturating(b"1234567890:").unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::InvalidNumber, 10));
    }
}
