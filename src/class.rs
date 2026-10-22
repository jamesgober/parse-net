//! The byte classes of the ABNF, in one table.
//!
//! One `static` table of 256 `u32` entries (1 KiB), built at compile time from
//! the ABNF, holds one bit per class, so classifying a byte is one load and
//! one mask. The table is the single reviewable source of every class; the
//! tests compare it, for all 256 bytes, with slow functions written straight
//! from the RFC text.
//!
//! Every class is ASCII-only except `OBS_TEXT`, `FIELD_TEXT`, `QDTEXT`,
//! `CTEXT`, `QUOTED_PAIR`, and `ETAGC`, which include 0x80 to 0xFF as
//! `obs-text`. DEL (0x7F) is in no class.
//!
//! # Examples
//!
//! ```
//! use parse_net::class::{self, Class};
//!
//! assert!(class::is_tchar(b'!') && !class::is_tchar(b'('));
//! assert!(class::is_mime_token_char(b'{') && !class::is_tchar(b'{'));
//! assert_eq!(class::hex_value(b'f'), Some(15));
//! assert!(class::all(b"no-cache", Class::TCHAR));
//! assert!(Class::UNRESERVED.union(Class::SUB_DELIM).contains(b'~'));
//! ```

const TCHAR: u32 = 1 << 0;
const VCHAR: u32 = 1 << 1;
const OBS_TEXT: u32 = 1 << 2;
const FIELD_TEXT: u32 = 1 << 3;
const QDTEXT: u32 = 1 << 4;
const CTEXT: u32 = 1 << 5;
const QUOTED_PAIR: u32 = 1 << 6;
const ETAGC: u32 = 1 << 7;
const ATTR_CHAR: u32 = 1 << 8;
const MIME_TOKEN: u32 = 1 << 9;
const UNRESERVED: u32 = 1 << 10;
const SUB_DELIM: u32 = 1 << 11;
const PCHAR_NO_PCT: u32 = 1 << 12;
const URI_TARGET: u32 = 1 << 13;
const HEXDIG: u32 = 1 << 14;
const SF_KEY_START: u32 = 1 << 15;
const SF_KEY: u32 = 1 << 16;
const SF_TOKEN: u32 = 1 << 17;
const SF_STRING: u32 = 1 << 18;
const TOKEN68: u32 = 1 << 19;
const BASE64: u32 = 1 << 20;
const ATEXT: u32 = 1 << 21;
const BCHAR_NOSPACE: u32 = 1 << 22;
const COOKIE_OCTET: u32 = 1 << 23;
const AV_OCTET: u32 = 1 << 24;
/// Internal: field text that is not a list delimiter (`,` `"` `(` `)`), so
/// the list walker can skip it with one lookup per byte.
const LIST_PLAIN: u32 = 1 << 26;

/// Whether `c` is one of the bytes in `set`.
const fn one_of(c: u8, set: &[u8]) -> bool {
    let mut rest = set;
    while let [first, tail @ ..] = rest {
        if *first == c {
            return true;
        }
        rest = tail;
    }
    false
}

const fn classify(c: u8) -> u32 {
    let alpha = c.is_ascii_alphabetic();
    let digit = c.is_ascii_digit();
    let alnum = alpha || digit;
    let vchar = c >= 0x21 && c <= 0x7e;
    let obs = c >= 0x80;
    let sp_ht = c == b' ' || c == b'\t';
    let mut class = 0u32;

    // RFC 9110 section 5.6.2.
    if alnum || one_of(c, b"!#$%&'*+-.^_`|~") {
        class |= TCHAR;
    }
    if vchar {
        class |= VCHAR;
    }
    if obs {
        class |= OBS_TEXT;
    }
    // RFC 9110 section 5.5: field-vchar / SP / HTAB.
    if vchar || obs || sp_ht {
        class |= FIELD_TEXT;
    }
    // RFC 9110 section 5.6.4: HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text.
    if sp_ht || c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e) || obs {
        class |= QDTEXT;
    }
    // RFC 9110 section 5.6.5: HTAB / SP / %x21-27 / %x2A-5B / %x5D-7E / obs-text.
    if sp_ht
        || (c >= 0x21 && c <= 0x27)
        || (c >= 0x2a && c <= 0x5b)
        || (c >= 0x5d && c <= 0x7e)
        || obs
    {
        class |= CTEXT;
    }
    // The byte after "\": HTAB / SP / VCHAR / obs-text.
    if sp_ht || vchar || obs {
        class |= QUOTED_PAIR;
    }
    // RFC 9110 section 8.8.3: "!" / %x23-7E / obs-text.
    if c == 0x21 || (c >= 0x23 && c <= 0x7e) || obs {
        class |= ETAGC;
    }
    // RFC 8187 section 3.2.1.
    if alnum || one_of(c, b"!#$&+-.^_`|~") {
        class |= ATTR_CHAR;
    }
    // RFC 2045 section 5.1: any CHAR except SP, CTLs, and tspecials.
    if vchar && !one_of(c, b"()<>@,;:\\\"/[]?=") {
        class |= MIME_TOKEN;
    }
    // RFC 3986 sections 2.2 and 2.3.
    let unreserved = alnum || one_of(c, b"-._~");
    let sub_delim = one_of(c, b"!$&'()*+,;=");
    if unreserved {
        class |= UNRESERVED;
    }
    if sub_delim {
        class |= SUB_DELIM;
    }
    let pchar = unreserved || sub_delim || c == b':' || c == b'@';
    if pchar {
        class |= PCHAR_NO_PCT;
    }
    // pchar / "/" / "?", plus the "%" that introduces a pct-encoded triple.
    if pchar || c == b'/' || c == b'?' || c == b'%' {
        class |= URI_TARGET;
    }
    if c.is_ascii_hexdigit() {
        class |= HEXDIG;
    }
    // RFC 9651 section 3.1.2: key = ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" ).
    let lcalpha = c.is_ascii_lowercase();
    if lcalpha || c == b'*' {
        class |= SF_KEY_START;
    }
    if lcalpha || digit || one_of(c, b"_-.*") {
        class |= SF_KEY;
    }
    // RFC 9651 section 3.3.4: the characters after the first in a token.
    if alnum || one_of(c, b"!#$%&'*+-.^_`|~") || c == b':' || c == b'/' {
        class |= SF_TOKEN;
    }
    // RFC 9651 section 3.3.3: unescaped = %x20-21 / %x23-5B / %x5D-7E.
    if c == 0x20 || c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e) {
        class |= SF_STRING;
    }
    // RFC 9110 section 11.2 (the trailing "=" is handled apart).
    if alnum || one_of(c, b"-._~+/") {
        class |= TOKEN68;
    }
    // RFC 4648 section 4 (the "=" padding is handled apart).
    if alnum || c == b'+' || c == b'/' {
        class |= BASE64;
    }
    // RFC 5322 section 3.2.3.
    if alnum || one_of(c, b"!#$%&'*+-/=?^_`{|}~") {
        class |= ATEXT;
    }
    // RFC 2046 section 5.1.1: bcharsnospace.
    if alnum || one_of(c, b"'()+_,-./:=?") {
        class |= BCHAR_NOSPACE;
    }
    // draft-ietf-httpbis-rfc6265bis section 4.1.1.
    if c == 0x21
        || (c >= 0x23 && c <= 0x2b)
        || (c >= 0x2d && c <= 0x3a)
        || (c >= 0x3c && c <= 0x5b)
        || (c >= 0x5d && c <= 0x7e)
    {
        class |= COOKIE_OCTET;
    }
    if (c >= 0x20 && c <= 0x3a) || (c >= 0x3c && c <= 0x7e) {
        class |= AV_OCTET;
    }
    if (vchar || obs || sp_ht) && !one_of(c, b",\"()") {
        class |= LIST_PLAIN;
    }
    class
}

const fn build() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut b: u8 = 0;
    loop {
        // `b` is a u8, so the index is always below 256.
        #[allow(clippy::indexing_slicing)]
        {
            table[b as usize] = classify(b);
        }
        if b == u8::MAX {
            break;
        }
        b += 1;
    }
    table
}

static CLASSES: [u32; 256] = build();

#[inline]
const fn has(b: u8, bit: u32) -> bool {
    // A u8 index into a 256-entry table cannot be out of bounds.
    #[allow(clippy::indexing_slicing)]
    let entry = CLASSES[b as usize];
    entry & bit != 0
}

/// A set of byte classes, for [`all`] and the scanning functions.
///
/// The named constants are the classes of [`dev/PLAN.md` section 7.1](https://github.com/jamesgober/parse-net/blob/main/dev/PLAN.md#71-the-byte-class-table).
///
/// # Examples
///
/// ```
/// use parse_net::class::Class;
///
/// let host_chars = Class::UNRESERVED.union(Class::SUB_DELIM);
/// assert!(host_chars.contains(b'!') && !host_chars.contains(b'/'));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Class(u32);

impl Class {
    /// `tchar` (RFC 9110 section 5.6.2).
    pub const TCHAR: Self = Self(TCHAR);
    /// `VCHAR`: 0x21 to 0x7E (RFC 5234).
    pub const VCHAR: Self = Self(VCHAR);
    /// `obs-text`: 0x80 to 0xFF (RFC 9110 section 5.5).
    pub const OBS_TEXT: Self = Self(OBS_TEXT);
    /// `field-vchar / SP / HTAB` (RFC 9110 section 5.5).
    pub const FIELD_TEXT: Self = Self(FIELD_TEXT);
    /// `qdtext` (RFC 9110 section 5.6.4).
    pub const QDTEXT: Self = Self(QDTEXT);
    /// `ctext` (RFC 9110 section 5.6.5).
    pub const CTEXT: Self = Self(CTEXT);
    /// The byte after `\` in a `quoted-pair`: `HTAB / SP / VCHAR / obs-text`.
    pub const QUOTED_PAIR: Self = Self(QUOTED_PAIR);
    /// `etagc` (RFC 9110 section 8.8.3).
    pub const ETAGC: Self = Self(ETAGC);
    /// `attr-char` (RFC 8187 section 3.2.1).
    pub const ATTR_CHAR: Self = Self(ATTR_CHAR);
    /// The MIME `token` characters (RFC 2045 section 5.1); unlike `tchar`,
    /// they include `{` and `}`.
    pub const MIME_TOKEN: Self = Self(MIME_TOKEN);
    /// `unreserved` (RFC 3986 section 2.3).
    pub const UNRESERVED: Self = Self(UNRESERVED);
    /// `sub-delims` (RFC 3986 section 2.2).
    pub const SUB_DELIM: Self = Self(SUB_DELIM);
    /// `unreserved / sub-delims / ":" / "@"`: `pchar` without `pct-encoded`.
    pub const PCHAR_NO_PCT: Self = Self(PCHAR_NO_PCT);
    /// `pchar / "/" / "?"` plus `%`: the characters of a request target.
    pub const URI_TARGET: Self = Self(URI_TARGET);
    /// `HEXDIG`, either case.
    pub const HEXDIG: Self = Self(HEXDIG);
    /// The first byte of a Structured Field key: `lcalpha / "*"`.
    pub const SF_KEY_START: Self = Self(SF_KEY_START);
    /// A Structured Field key byte: `lcalpha / DIGIT / "_" / "-" / "." / "*"`.
    pub const SF_KEY: Self = Self(SF_KEY);
    /// A Structured Field token byte after the first: `tchar / ":" / "/"`.
    pub const SF_TOKEN: Self = Self(SF_TOKEN);
    /// An unescaped Structured Field string byte: `%x20-21 / %x23-5B / %x5D-7E`.
    pub const SF_STRING: Self = Self(SF_STRING);
    /// A `token68` byte (RFC 9110 section 11.2), without the `=` padding.
    pub const TOKEN68: Self = Self(TOKEN68);
    /// The base64 alphabet (RFC 4648 section 4), without the `=` padding.
    pub const BASE64: Self = Self(BASE64);
    /// `atext` (RFC 5322 section 3.2.3).
    pub const ATEXT: Self = Self(ATEXT);
    /// `bcharsnospace` (RFC 2046 section 5.1.1).
    pub const BCHAR_NOSPACE: Self = Self(BCHAR_NOSPACE);
    /// `cookie-octet` (rfc6265bis section 4.1.1), for cookie-net.
    pub const COOKIE_OCTET: Self = Self(COOKIE_OCTET);
    /// Cookie attribute value bytes (rfc6265bis section 4.1.1), for cookie-net.
    pub const AV_OCTET: Self = Self(AV_OCTET);

    /// Whether `b` is in this class.
    #[inline]
    #[must_use]
    pub const fn contains(self, b: u8) -> bool {
        has(b, self.0)
    }

    /// A class holding the bytes of both.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Whether every byte of `s` is in `class` (true for an empty `s`). Stops at
/// the first byte outside.
///
/// # Examples
///
/// ```
/// use parse_net::class::{all, Class};
///
/// assert!(all(b"gzip", Class::TCHAR));
/// assert!(!all(b"gzip, br", Class::TCHAR));
/// assert!(all(b"", Class::TCHAR));
/// ```
#[inline]
#[must_use]
pub const fn all(s: &[u8], class: Class) -> bool {
    // An indexed loop: the compiler drops the bounds check for `i < len`,
    // which the slice-pattern form does not get as reliably.
    let mut i = 0;
    while i < s.len() {
        // `i < s.len()` was just checked.
        #[allow(clippy::indexing_slicing)]
        let b = s[i];
        if !has(b, class.0) {
            return false;
        }
        i += 1;
    }
    true
}

macro_rules! predicate {
    ($(#[$doc:meta])* $name:ident, $bit:ident, $example_yes:literal, $example_no:literal) => {
        $(#[$doc])*
        ///
        /// # Examples
        ///
        /// ```
        #[doc = concat!("assert!(parse_net::class::", stringify!($name), "(", stringify!($example_yes), "));")]
        #[doc = concat!("assert!(!parse_net::class::", stringify!($name), "(", stringify!($example_no), "));")]
        /// ```
        #[inline]
        #[must_use]
        pub const fn $name(b: u8) -> bool {
            has(b, $bit)
        }
    };
}

predicate!(
    /// Whether `b` is a `tchar`, a byte allowed in a token (RFC 9110 section 5.6.2).
    is_tchar, TCHAR, b'~', b'('
);
predicate!(
    /// Whether `b` is a visible ASCII character, 0x21 to 0x7E.
    is_vchar, VCHAR, b'!', b' '
);
predicate!(
    /// Whether `b` is `obs-text`, 0x80 to 0xFF.
    is_obs_text, OBS_TEXT, 0x80, 0x7f
);
predicate!(
    /// Whether `b` may appear in a field value: `field-vchar / SP / HTAB`
    /// (RFC 9110 section 5.5).
    is_field_text, FIELD_TEXT, b'\t', b'\r'
);
predicate!(
    /// Whether `b` may appear unescaped in a quoted string (RFC 9110 section 5.6.4).
    is_qdtext, QDTEXT, b' ', b'"'
);
predicate!(
    /// Whether `b` may appear unescaped in a comment (RFC 9110 section 5.6.5).
    is_ctext, CTEXT, b'a', b'('
);
predicate!(
    /// Whether `b` may follow `\` in a `quoted-pair`: `HTAB / SP / VCHAR / obs-text`.
    is_quoted_pair_char, QUOTED_PAIR, b'"', 0x7f
);
predicate!(
    /// Whether `b` is an `etagc` (RFC 9110 section 8.8.3).
    is_etagc, ETAGC, b'!', b'"'
);
predicate!(
    /// Whether `b` is an `attr-char` (RFC 8187 section 3.2.1).
    is_attr_char, ATTR_CHAR, b'|', b'%'
);
predicate!(
    /// Whether `b` may appear in a MIME `token` (RFC 2045 section 5.1).
    is_mime_token_char, MIME_TOKEN, b'{', b'/'
);
predicate!(
    /// Whether `b` is `unreserved` (RFC 3986 section 2.3).
    is_unreserved, UNRESERVED, b'~', b'!'
);
predicate!(
    /// Whether `b` is a `sub-delims` byte (RFC 3986 section 2.2).
    is_sub_delim, SUB_DELIM, b'!', b'/'
);
predicate!(
    /// Whether `b` is a `pchar` other than the `%` of `pct-encoded`
    /// (RFC 3986 section 3.3).
    is_pchar_no_pct, PCHAR_NO_PCT, b'@', b'/'
);
predicate!(
    /// Whether `b` may appear in a request target: `pchar / "/" / "?"` or the
    /// `%` of a `pct-encoded` triple (whose digits are checked apart).
    is_uri_target, URI_TARGET, b'?', b'#'
);
predicate!(
    /// Whether `b` is a hex digit, either case.
    is_hexdig, HEXDIG, b'F', b'g'
);
predicate!(
    /// Whether `b` may start a Structured Field key: `lcalpha / "*"`.
    is_sf_key_start, SF_KEY_START, b'*', b'A'
);
predicate!(
    /// Whether `b` may appear in a Structured Field key.
    is_sf_key_char, SF_KEY, b'_', b'A'
);
predicate!(
    /// Whether `b` may appear in a Structured Field token after its first byte.
    is_sf_token_char, SF_TOKEN, b':', b'"'
);
predicate!(
    /// Whether `b` may appear unescaped in a Structured Field string.
    is_sf_string_char, SF_STRING, b' ', b'\\'
);
predicate!(
    /// Whether `b` is a `token68` byte other than the `=` padding.
    is_token68_char, TOKEN68, b'~', b'='
);
predicate!(
    /// Whether `b` is in the base64 alphabet (RFC 4648 section 4), padding aside.
    is_base64_char, BASE64, b'+', b'-'
);
predicate!(
    /// Whether `b` is an `atext` byte (RFC 5322 section 3.2.3).
    is_atext, ATEXT, b'{', b'@'
);
predicate!(
    /// Whether `b` is a `bcharsnospace` byte (RFC 2046 section 5.1.1).
    is_bchar_nospace, BCHAR_NOSPACE, b'?', b' '
);
predicate!(
    /// Whether `b` is a `cookie-octet` (rfc6265bis section 4.1.1).
    is_cookie_octet, COOKIE_OCTET, b'!', b';'
);
predicate!(
    /// Whether `b` may appear in a cookie attribute value (rfc6265bis section 4.1.1).
    is_av_octet, AV_OCTET, b' ', b';'
);

/// Whether `b` is field text other than a list delimiter (`,` `"` `(` `)`).
#[inline]
pub(crate) const fn is_list_plain(b: u8) -> bool {
    has(b, LIST_PLAIN)
}

/// The value of one hex digit (either case), or `None`.
///
/// # Examples
///
/// ```
/// use parse_net::class::hex_value;
///
/// assert_eq!(hex_value(b'A'), Some(10));
/// assert_eq!(hex_value(b'g'), None);
/// ```
#[inline]
#[must_use]
pub const fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Slow references written straight from the ABNF, one per class.
    fn r_alnum(b: u8) -> bool {
        b.is_ascii_alphanumeric()
    }
    fn r_vchar(b: u8) -> bool {
        (0x21..=0x7e).contains(&b)
    }
    fn r_obs(b: u8) -> bool {
        b >= 0x80
    }
    fn r_tchar(b: u8) -> bool {
        r_alnum(b) || b"!#$%&'*+-.^_`|~".contains(&b)
    }

    fn check(name: &str, fast: fn(u8) -> bool, slow: impl Fn(u8) -> bool) {
        for b in 0u8..=255 {
            assert_eq!(fast(b), slow(b), "{name}: byte {b:#04x}");
        }
    }

    #[test]
    fn test_tchar_table_exhaustive() {
        check("tchar", is_tchar, r_tchar);
        check("vchar", is_vchar, r_vchar);
        check("obs-text", is_obs_text, r_obs);
        check("field-text", is_field_text, |b| {
            r_vchar(b) || r_obs(b) || b == b' ' || b == b'\t'
        });
    }

    #[test]
    fn test_quoting_classes_exhaustive() {
        check("qdtext", is_qdtext, |b| {
            b == b'\t'
                || b == b' '
                || b == 0x21
                || (0x23..=0x5b).contains(&b)
                || (0x5d..=0x7e).contains(&b)
                || r_obs(b)
        });
        check("ctext", is_ctext, |b| {
            b == b'\t'
                || b == b' '
                || (0x21..=0x27).contains(&b)
                || (0x2a..=0x5b).contains(&b)
                || (0x5d..=0x7e).contains(&b)
                || r_obs(b)
        });
        check("quoted-pair", is_quoted_pair_char, |b| {
            b == b'\t' || b == b' ' || r_vchar(b) || r_obs(b)
        });
        check("etagc", is_etagc, |b| {
            b == 0x21 || (0x23..=0x7e).contains(&b) || r_obs(b)
        });
    }

    #[test]
    fn test_mime_and_attr_classes_exhaustive() {
        check("attr-char", is_attr_char, |b| {
            r_alnum(b) || b"!#$&+-.^_`|~".contains(&b)
        });
        check("mime token", is_mime_token_char, |b| {
            (0x21..=0x7e).contains(&b) && !b"()<>@,;:\\\"/[]?=".contains(&b)
        });
        check("bcharsnospace", is_bchar_nospace, |b| {
            r_alnum(b) || b"'()+_,-./:=?".contains(&b)
        });
        check("atext", is_atext, |b| {
            r_alnum(b) || b"!#$%&'*+-/=?^_`{|}~".contains(&b)
        });
    }

    #[test]
    fn test_uri_classes_exhaustive() {
        let unreserved = |b: u8| r_alnum(b) || b"-._~".contains(&b);
        let sub = |b: u8| b"!$&'()*+,;=".contains(&b);
        check("unreserved", is_unreserved, unreserved);
        check("sub-delims", is_sub_delim, sub);
        check("pchar", is_pchar_no_pct, |b| {
            unreserved(b) || sub(b) || b == b':' || b == b'@'
        });
        check("target", is_uri_target, |b| {
            unreserved(b) || sub(b) || b":@/?%".contains(&b)
        });
        check("hexdig", is_hexdig, |b| b.is_ascii_hexdigit());
    }

    #[test]
    fn test_structured_field_classes_exhaustive() {
        check("sf key start", is_sf_key_start, |b| {
            b.is_ascii_lowercase() || b == b'*'
        });
        check("sf key", is_sf_key_char, |b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-.*".contains(&b)
        });
        check("sf token", is_sf_token_char, |b| {
            r_tchar(b) || b == b':' || b == b'/'
        });
        check("sf string", is_sf_string_char, |b| {
            b == 0x20 || b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b)
        });
    }

    #[test]
    fn test_base64_and_cookie_classes_exhaustive() {
        check("token68", is_token68_char, |b| {
            r_alnum(b) || b"-._~+/".contains(&b)
        });
        check("base64", is_base64_char, |b| {
            r_alnum(b) || b == b'+' || b == b'/'
        });
        check("cookie-octet", is_cookie_octet, |b| {
            b == 0x21
                || (0x23..=0x2b).contains(&b)
                || (0x2d..=0x3a).contains(&b)
                || (0x3c..=0x5b).contains(&b)
                || (0x5d..=0x7e).contains(&b)
        });
        check("av-octet", is_av_octet, |b| {
            (0x20..=0x3a).contains(&b) || (0x3c..=0x7e).contains(&b)
        });
    }

    #[test]
    fn test_list_plain_is_field_text_without_delimiters() {
        for b in 0u8..=255 {
            let expected = is_field_text(b) && !b",\"()".contains(&b);
            assert_eq!(is_list_plain(b), expected, "byte {b:#04x}");
        }
    }

    #[test]
    fn test_del_is_in_no_class() {
        assert_eq!(CLASSES[0x7f], 0);
    }

    #[test]
    fn test_unicode_bytes_never_in_ascii_classes() {
        let ascii_only = TCHAR
            | VCHAR
            | ATTR_CHAR
            | MIME_TOKEN
            | UNRESERVED
            | SUB_DELIM
            | PCHAR_NO_PCT
            | URI_TARGET
            | HEXDIG
            | SF_KEY_START
            | SF_KEY
            | SF_TOKEN
            | SF_STRING
            | TOKEN68
            | BASE64
            | ATEXT
            | BCHAR_NOSPACE
            | COOKIE_OCTET
            | AV_OCTET;
        for b in 0x80u8..=0xff {
            assert_eq!(CLASSES[b as usize] & ascii_only, 0, "byte {b:#04x}");
        }
    }

    #[test]
    fn test_hex_value_all_bytes() {
        for b in 0u8..=255 {
            let expected = (b as char).to_digit(16).map(|d| d as u8);
            assert_eq!(hex_value(b), expected, "byte {b:#04x}");
        }
    }

    #[test]
    fn test_class_all_and_union() {
        assert!(all(b"", Class::TCHAR));
        assert!(all(b"abc", Class::TCHAR));
        assert!(!all(b"a c", Class::TCHAR));
        let c = Class::TCHAR.union(Class::SF_KEY);
        assert!(c.contains(b'a') && c.contains(b'*') && !c.contains(b' '));
        for b in 0u8..=255 {
            assert_eq!(Class::QDTEXT.contains(b), is_qdtext(b));
        }
    }
}
