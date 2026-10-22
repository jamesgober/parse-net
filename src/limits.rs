//! [`Limits`], the work and size bounds every parser enforces, and
//! [`DuplicatePolicy`].

/// The work and size bounds every parser enforces.
///
/// Every bound is checked before the work it governs, and none allocates:
/// they bound loops. The defaults meet every minimum RFC 9651 section 3 sets
/// for parsers, so a conforming sender is never refused by default.
///
/// | Bound | Default | Source |
/// |---|---|---|
/// | list members | 1024 | RFC 9651 section 3.1 minimum |
/// | inner list members | 256 | RFC 9651 section 3.1.1 minimum |
/// | parameters per item or field | 256 | RFC 9651 section 3.1.2 minimum |
/// | dictionary members | 1024 | RFC 9651 section 3.2 minimum |
/// | key length | 256 | RFC 9651 minimum is 64 |
/// | string length (decoded) | 1024 | RFC 9651 section 3.3.3 minimum |
/// | token length | 512 | RFC 9651 section 3.3.4 minimum |
/// | byte sequence length (decoded) | 16384 | RFC 9651 section 3.3.5 minimum |
/// | empty list elements | 16 | RFC 9110 section 5.6.1.2: "a reasonable number" |
/// | comment depth | 8 | none in the RFC |
/// | ranges | 16 | RFC 9110 section 14.2 permits refusal |
/// | RFC 2231 sections | 32 | none in the RFC |
/// | encoded words per field | 64 | none in the RFC |
/// | forwarded hops | 16 | none in the RFC |
///
/// A setter may set a bound below the RFC minimum: that is the caller
/// tightening deliberately, and it makes the parser non-conforming for that
/// field.
///
/// # Examples
///
/// ```
/// use parse_net::{list, ErrorKind, Limits};
///
/// const STRICT: Limits = Limits::DEFAULT.max_list_members(64).max_params(16);
/// let err = list::parse(b"a, b, c", &Limits::DEFAULT.max_list_members(2)).unwrap_err();
/// assert_eq!((err.kind(), err.offset()), (ErrorKind::TooManyMembers, 6));
/// # let _ = STRICT;
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Limits {
    pub(crate) list_members: u16,
    pub(crate) inner_list_members: u16,
    pub(crate) params: u16,
    pub(crate) dictionary_members: u16,
    pub(crate) key_len: u16,
    pub(crate) string_len: u16,
    pub(crate) token_len: u16,
    pub(crate) byte_seq_len: u32,
    pub(crate) empty_elements: u16,
    pub(crate) comment_depth: u8,
    pub(crate) ranges: u16,
    pub(crate) rfc2231_sections: u8,
    pub(crate) encoded_words: u16,
    pub(crate) hops: u8,
    pub(crate) allow_leap_second: bool,
    pub(crate) duplicate_params: DuplicatePolicy,
}

/// The size of the stack array that reassembles RFC 2231 sections.
pub(crate) const MAX_RFC2231_SECTIONS: u8 = 32;

impl Limits {
    /// The defaults in the table above.
    pub const DEFAULT: Self = Self {
        list_members: 1024,
        inner_list_members: 256,
        params: 256,
        dictionary_members: 1024,
        key_len: 256,
        string_len: 1024,
        token_len: 512,
        byte_seq_len: 16384,
        empty_elements: 16,
        comment_depth: 8,
        ranges: 16,
        rfc2231_sections: MAX_RFC2231_SECTIONS,
        encoded_words: 64,
        hops: 16,
        allow_leap_second: false,
        duplicate_params: DuplicatePolicy::Refuse,
    };

    /// The defaults; the same as [`Limits::DEFAULT`].
    #[must_use]
    pub const fn new() -> Self {
        Self::DEFAULT
    }

    /// The most members a list may have (default 1024).
    #[must_use]
    pub const fn max_list_members(self, n: u16) -> Self {
        Self {
            list_members: n,
            ..self
        }
    }

    /// The most members a Structured Field inner list may have (default 256).
    #[must_use]
    pub const fn max_inner_list_members(self, n: u16) -> Self {
        Self {
            inner_list_members: n,
            ..self
        }
    }

    /// The most parameters an item or a field may have (default 256).
    #[must_use]
    pub const fn max_params(self, n: u16) -> Self {
        Self { params: n, ..self }
    }

    /// The most members a Structured Field dictionary may have (default 1024).
    #[must_use]
    pub const fn max_dictionary_members(self, n: u16) -> Self {
        Self {
            dictionary_members: n,
            ..self
        }
    }

    /// The longest Structured Field key (default 256).
    #[must_use]
    pub const fn max_key_len(self, n: u16) -> Self {
        Self { key_len: n, ..self }
    }

    /// The longest Structured Field string, decoded (default 1024).
    #[must_use]
    pub const fn max_string_len(self, n: u16) -> Self {
        Self {
            string_len: n,
            ..self
        }
    }

    /// The longest Structured Field token (default 512).
    #[must_use]
    pub const fn max_token_len(self, n: u16) -> Self {
        Self {
            token_len: n,
            ..self
        }
    }

    /// The longest Structured Field byte sequence, decoded (default 16384).
    #[must_use]
    pub const fn max_byte_seq_len(self, n: u32) -> Self {
        Self {
            byte_seq_len: n,
            ..self
        }
    }

    /// The most empty list elements accepted in one field (default 16).
    #[must_use]
    pub const fn max_empty_elements(self, n: u16) -> Self {
        Self {
            empty_elements: n,
            ..self
        }
    }

    /// The deepest comment nesting accepted (default 8).
    #[must_use]
    pub const fn max_comment_depth(self, n: u8) -> Self {
        Self {
            comment_depth: n,
            ..self
        }
    }

    /// The most ranges a `Range` field may request (default 16).
    #[must_use]
    pub const fn max_ranges(self, n: u16) -> Self {
        Self { ranges: n, ..self }
    }

    /// The most RFC 2231 sections in one parameter (default 32). Values above
    /// 32, the size of the reassembly array, are stored as 32.
    #[must_use]
    pub const fn max_rfc2231_sections(self, n: u8) -> Self {
        let n = if n > MAX_RFC2231_SECTIONS {
            MAX_RFC2231_SECTIONS
        } else {
            n
        };
        Self {
            rfc2231_sections: n,
            ..self
        }
    }

    /// The most RFC 2047 encoded words in one field (default 64).
    #[must_use]
    pub const fn max_encoded_words(self, n: u16) -> Self {
        Self {
            encoded_words: n,
            ..self
        }
    }

    /// The most hops in a forwarded chain (default 16).
    #[must_use]
    pub const fn max_hops(self, n: u8) -> Self {
        Self { hops: n, ..self }
    }

    /// Whether HTTP-date accepts second `60` (read as 59). Off by default.
    #[must_use]
    pub const fn allow_leap_second(self, yes: bool) -> Self {
        Self {
            allow_leap_second: yes,
            ..self
        }
    }

    /// What parameter parsers do with a repeated name (default
    /// [`DuplicatePolicy::Refuse`]).
    #[must_use]
    pub const fn duplicate_params(self, p: DuplicatePolicy) -> Self {
        Self {
            duplicate_params: p,
            ..self
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What a parameter parser does when a name repeats.
///
/// Names compare ASCII case-insensitively. [`Refuse`](Self::Refuse), the
/// default, fails with [`ErrorKind::DuplicateParameter`](crate::ErrorKind::DuplicateParameter)
/// at the repeated name: a field one component reads first-wins and another
/// last-wins is a known attack. [`First`](Self::First) and
/// [`Last`](Self::Last) exist for fields whose RFC states the rule.
/// Structured Fields always use last-wins, as RFC 9651 requires.
///
/// # Examples
///
/// ```
/// use parse_net::{param, DuplicatePolicy, Limits};
///
/// let limits = Limits::DEFAULT.duplicate_params(DuplicatePolicy::Last);
/// let (p, _) = param::parse(b";a=1;a=2", &limits)?;
/// assert!(p.get("a").is_some_and(|v| v.eq_bytes(b"2")));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum DuplicatePolicy {
    /// Refuse a repeated name.
    #[default]
    Refuse,
    /// Keep the first occurrence for lookups.
    First,
    /// Keep the last occurrence for lookups.
    Last,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_limits_defaults_meet_rfc_minimums() {
        let l = Limits::new();
        assert_eq!(l, Limits::default());
        assert!(l.list_members >= 1024);
        assert!(l.inner_list_members >= 256);
        assert!(l.params >= 256);
        assert!(l.dictionary_members >= 1024);
        assert!(l.key_len >= 64);
        assert!(l.string_len >= 1024);
        assert!(l.token_len >= 512);
        assert!(l.byte_seq_len >= 16384);
        assert!(!l.allow_leap_second);
        assert_eq!(l.duplicate_params, DuplicatePolicy::Refuse);
    }

    #[test]
    fn test_limits_setters_set_one_field() {
        let l = Limits::DEFAULT
            .max_list_members(1)
            .max_inner_list_members(2)
            .max_params(3)
            .max_dictionary_members(4)
            .max_key_len(5)
            .max_string_len(6)
            .max_token_len(7)
            .max_byte_seq_len(8)
            .max_empty_elements(9)
            .max_comment_depth(10)
            .max_ranges(11)
            .max_rfc2231_sections(12)
            .max_encoded_words(13)
            .max_hops(14)
            .allow_leap_second(true)
            .duplicate_params(DuplicatePolicy::First);
        assert_eq!(
            (
                l.list_members,
                l.inner_list_members,
                l.params,
                l.dictionary_members
            ),
            (1, 2, 3, 4)
        );
        assert_eq!(
            (l.key_len, l.string_len, l.token_len, l.byte_seq_len),
            (5, 6, 7, 8)
        );
        assert_eq!((l.empty_elements, l.comment_depth, l.ranges), (9, 10, 11));
        assert_eq!((l.rfc2231_sections, l.encoded_words, l.hops), (12, 13, 14));
        assert!(l.allow_leap_second);
        assert_eq!(l.duplicate_params, DuplicatePolicy::First);
    }

    #[test]
    fn test_limits_rfc2231_sections_capped_at_32() {
        assert_eq!(
            Limits::DEFAULT.max_rfc2231_sections(200).rfc2231_sections,
            32
        );
    }
}
