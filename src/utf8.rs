//! An incremental UTF-8 validator, fed one byte at a time, so decoded text
//! (percent-encoded values, Display Strings) is validated during the parse
//! with no buffer.
//!
//! It accepts exactly the well-formed sequences of RFC 3629 section 4 and the
//! Unicode standard's table 3-7: no overlong forms, no surrogates
//! (U+D800 to U+DFFF), nothing above U+10FFFF.

/// The validator state: how many continuation bytes are still expected, and
/// the allowed range of the next one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Utf8 {
    needed: u8,
    low: u8,
    high: u8,
}

impl Utf8 {
    /// A validator at a character boundary.
    pub(crate) const fn new() -> Self {
        Self {
            needed: 0,
            low: 0x80,
            high: 0xbf,
        }
    }

    /// Feeds one byte; `false` when the input can no longer be UTF-8.
    #[inline]
    pub(crate) fn push(&mut self, b: u8) -> bool {
        if self.needed == 0 {
            match b {
                0x00..=0x7f => true,
                0xc2..=0xdf => self.expect(1, 0x80, 0xbf),
                0xe0 => self.expect(2, 0xa0, 0xbf),
                0xe1..=0xec | 0xee..=0xef => self.expect(2, 0x80, 0xbf),
                0xed => self.expect(2, 0x80, 0x9f),
                0xf0 => self.expect(3, 0x90, 0xbf),
                0xf1..=0xf3 => self.expect(3, 0x80, 0xbf),
                0xf4 => self.expect(3, 0x80, 0x8f),
                _ => false,
            }
        } else {
            if b < self.low || b > self.high {
                return false;
            }
            self.needed -= 1;
            self.low = 0x80;
            self.high = 0xbf;
            true
        }
    }

    fn expect(&mut self, needed: u8, low: u8, high: u8) -> bool {
        self.needed = needed;
        self.low = low;
        self.high = high;
        true
    }

    /// Whether the input so far ends at a character boundary.
    pub(crate) const fn is_complete(&self) -> bool {
        self.needed == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid(bytes: &[u8]) -> bool {
        let mut v = Utf8::new();
        bytes.iter().all(|&b| v.push(b)) && v.is_complete()
    }

    #[test]
    fn test_utf8_matches_core_for_every_short_sequence() {
        for a in 0u8..=255 {
            assert_eq!(valid(&[a]), core::str::from_utf8(&[a]).is_ok(), "{a:#x}");
            for b in 0u8..=255 {
                let s = [a, b];
                assert_eq!(valid(&s), core::str::from_utf8(&s).is_ok(), "{s:x?}");
            }
        }
        // Three- and four-byte sequences around every boundary of table 3-7.
        for lead in [
            0xe0u8, 0xe1, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf3, 0xf4, 0xf5,
        ] {
            for second in [0x7fu8, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0] {
                for third in [0x7fu8, 0x80, 0xbf, 0xc0] {
                    let s3 = [lead, second, third];
                    assert_eq!(valid(&s3), core::str::from_utf8(&s3).is_ok(), "{s3:x?}");
                    let s4 = [lead, second, third, 0x80];
                    assert_eq!(valid(&s4), core::str::from_utf8(&s4).is_ok(), "{s4:x?}");
                }
            }
        }
    }

    #[test]
    fn test_utf8_refuses_surrogates_and_overlong() {
        assert!(!valid(&[0xed, 0xa0, 0x80]));
        assert!(!valid(&[0xc0, 0xaf]));
        assert!(!valid(&[0xe0, 0x80, 0xaf]));
        assert!(!valid(&[0xf4, 0x90, 0x80, 0x80]));
        assert!(!valid(&[0xc3]));
        assert!(valid("caf\u{e9} \u{20ac} \u{10ffff}".as_bytes()));
    }
}
