//! Parameters: `*( OWS ";" OWS [ parameter ] )` (RFC 9110 section 5.6.6).
//!
//! # Examples
//!
//! ```
//! use parse_net::{param, Limits};
//!
//! let (p, used) = param::parse(b"; charset=utf-8;format=\"flowed\" , next", &Limits::DEFAULT)?;
//! assert_eq!(used, 31);
//! assert!(p.get("Charset").is_some_and(|v| v.eq_bytes(b"utf-8")));
//! assert_eq!(format!("{p:?}"), "Params([\"charset\", \"format\"])");
//! # Ok::<(), parse_net::ParseError>(())
//! ```

use core::fmt;

use crate::{
    class,
    error::{ErrorKind, Result, err},
    limits::{DuplicatePolicy, Limits},
    scan::control_kind,
    text::{Word, is_ows, parse_quoted, token_len, validated_word},
};

/// One parameter: a name and a value.
///
/// # Examples
///
/// ```
/// use parse_net::{param, Limits, Param, Word};
///
/// let (p, _) = param::parse(b";charset=utf-8", &Limits::DEFAULT)?;
/// assert_eq!(p.iter().next(), Some(Param { name: b"charset", value: Word::Token(b"utf-8") }));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Param<'a> {
    /// The name as sent (compare it ASCII case-insensitively).
    pub name: &'a [u8],
    /// The value.
    pub value: Word<'a>,
}

/// The most parameters one element may have when repeated names are
/// refused: RFC 9110 parameters under [`DuplicatePolicy::Refuse`],
/// authentication parameters, and MIME parameters. Their name offsets are
/// kept on the stack, so a repeat is found by comparing names in place,
/// never by reading the parameters again (D-072). Without it, the check for
/// a repeat reads every earlier parameter, values included, and a field of
/// many parameters costs the square of its length.
pub const MAX_CHECKED_PARAMS: usize = 64;

/// The names already seen in one parameter list, for the repeat check: their
/// offsets in the list's text, compared in place (D-072). The caller keeps
/// at most [`MAX_CHECKED_PARAMS`] names.
pub(crate) struct Names {
    at: [usize; MAX_CHECKED_PARAMS],
    len: usize,
    seen: u64,
}

impl Names {
    pub(crate) const fn new() -> Self {
        Self {
            at: [0; MAX_CHECKED_PARAMS],
            len: 0,
            seen: 0,
        }
    }

    /// Whether `name`, at `off` in `text`, repeats a recorded name (ASCII
    /// case-insensitive); records it when it does not. `in_name` is the
    /// names' byte class: a recorded name ends at the first byte outside it.
    pub(crate) fn repeats(
        &mut self,
        text: &[u8],
        off: usize,
        name: &[u8],
        in_name: fn(u8) -> bool,
    ) -> bool {
        let bit = name_bit(name);
        let l = name.len();
        let earlier = self.at.get(..self.len).unwrap_or(&[]);
        if self.seen & bit != 0
            && earlier.iter().any(|&o| {
                text.get(o + l).is_none_or(|&b| !in_name(b))
                    && text
                        .get(o..o + l)
                        .is_some_and(|e| e.eq_ignore_ascii_case(name))
            })
        {
            return true;
        }
        self.seen |= bit;
        if let Some(slot) = self.at.get_mut(self.len) {
            *slot = off;
            self.len += 1;
        }
        false
    }
}

/// A small filter over parameter names, so the table of earlier names is
/// searched only when a repeat could exist.
#[inline]
fn name_bit(name: &[u8]) -> u64 {
    let first = name.first().map_or(0, u8::to_ascii_lowercase);
    let last = name.last().map_or(0, u8::to_ascii_lowercase);
    let h = (name.len() as u64)
        .wrapping_mul(31)
        .wrapping_add(u64::from(first))
        .wrapping_mul(31)
        .wrapping_add(u64::from(last));
    1u64 << (h & 63)
}

/// Parses parameters at the start of `s`.
///
/// `s` starts at the first `;` (optionally preceded by OWS) or is empty.
/// Parsing continues as long as the grammar does; the view and the number of
/// bytes used are returned (OWS after the last parameter is not used), and
/// whatever follows is the caller's to check. Empty parameters (`;;`, a
/// trailing `;`) are allowed, as the grammar says. Whitespace around `=` is
/// not (BWS is not part of this grammar).
///
/// # Errors
///
/// [`ErrorKind::NotToken`] for a bad name; [`ErrorKind::MissingValue`] for a
/// name with no `=` or no value; [`ErrorKind::InvalidByte`] for whitespace
/// around `=`; the quoted-string errors; [`ErrorKind::DuplicateParameter`]
/// under [`DuplicatePolicy::Refuse`]; [`ErrorKind::TooManyMembers`] beyond [`Limits::max_params`], and under
/// [`DuplicatePolicy::Refuse`] beyond [`MAX_CHECKED_PARAMS`] as well.
///
/// # Examples
///
/// ```
/// use parse_net::{param, ErrorKind, Limits};
///
/// let dup = param::parse(b";a=1;A=2", &Limits::DEFAULT).unwrap_err();
/// assert_eq!((dup.kind(), dup.offset()), (ErrorKind::DuplicateParameter, 5));
/// assert_eq!(param::parse(b";a =1", &Limits::DEFAULT).unwrap_err().kind(), ErrorKind::InvalidByte);
/// ```
pub fn parse<'a>(s: &'a [u8], limits: &Limits) -> Result<(Params<'a>, usize)> {
    let policy = limits.duplicate_params;
    let refuse = policy == DuplicatePolicy::Refuse;
    let max = if refuse {
        usize::from(limits.params).min(MAX_CHECKED_PARAMS)
    } else {
        usize::from(limits.params)
    };
    // The cursor is a shrinking slice; an offset is computed only for an
    // error or the result. `done` follows the last complete parameter.
    let at = |rest: &[u8]| s.len() - rest.len();
    let (mut done, mut count) = (s, 0usize);
    let mut names = Names::new();
    while let [b';', after @ ..] = skip_ws(done) {
        let r = skip_ws(after);
        let n = token_len(r);
        if n == 0 {
            match r.first() {
                None | Some(b';') => {
                    done = r;
                    continue;
                }
                // OWS after an empty parameter followed by a list separator
                // belongs to the caller.
                Some(b',') => {
                    done = after;
                    break;
                }
                Some(&b) => {
                    let kind = if crate::scan::is_control(b) {
                        control_kind(b)
                    } else {
                        ErrorKind::NotToken
                    };
                    return err(kind, at(r));
                }
            }
        }
        let name_at = at(r);
        let (name, r) = r.split_at(n);
        let value = match r {
            [b'=', value @ ..] => value,
            [b, ..] if is_ows(*b) => {
                let kind = if skip_ws(r).first() == Some(&b'=') {
                    ErrorKind::InvalidByte
                } else {
                    ErrorKind::MissingValue
                };
                return err(kind, at(r));
            }
            [b'"', ..] => return err(ErrorKind::MissingValue, at(r)),
            [b, ..] if *b != b';' && *b != b',' && class::is_field_text(*b) => {
                return err(ErrorKind::NotToken, at(r));
            }
            [b, ..] if !class::is_field_text(*b) => return err(control_kind(*b), at(r)),
            _ => return err(ErrorKind::MissingValue, at(r)),
        };
        let used = match value {
            [b, ..] if is_ows(*b) => return err(ErrorKind::InvalidByte, at(value)),
            [] | [b';' | b',', ..] => return err(ErrorKind::MissingValue, at(value)),
            [b'"', ..] => parse_quoted(value).map_err(|e| e.shifted(at(value)))?.1,
            [b, ..] => match token_len(value) {
                0 => return err(control_or_invalid(*b), at(value)),
                n => n,
            },
        };
        count += 1;
        if count > max {
            return err(ErrorKind::TooManyMembers, name_at);
        }
        if refuse && names.repeats(s, name_at, name, class::is_tchar) {
            return err(ErrorKind::DuplicateParameter, name_at);
        }
        done = value.get(used..).unwrap_or(&[]);
    }
    let used = at(done);
    Ok((
        Params {
            text: s.get(..used).unwrap_or(&[]),
            count: u32::try_from(count).unwrap_or(u32::MAX),
            policy,
        },
        used,
    ))
}

/// Skips SP and HTAB.
#[inline]
fn skip_ws(s: &[u8]) -> &[u8] {
    match s {
        [b' ' | b'\t', ..] => {
            let n = s
                .iter()
                .position(|&b| b != b' ' && b != b'\t')
                .unwrap_or(s.len());
            s.get(n..).unwrap_or(&[])
        }
        _ => s,
    }
}

#[inline]
const fn control_or_invalid(b: u8) -> ErrorKind {
    if crate::scan::is_control(b) {
        control_kind(b)
    } else {
        ErrorKind::InvalidByte
    }
}

/// Validated parameters. Iterating them cannot fail.
///
/// `Debug` prints the parameter names only: values can be secrets.
///
/// # Examples
///
/// ```
/// use parse_net::{param, Limits};
///
/// let (p, used) = param::parse(b";q=1;level=\"2\"", &Limits::DEFAULT)?;
/// assert_eq!((p.len(), used), (2, 14));
/// assert!(p.get("level").is_some_and(|v| v.eq_bytes(b"2")));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Params<'a> {
    pub(crate) text: &'a [u8],
    pub(crate) count: u32,
    pub(crate) policy: DuplicatePolicy,
}

impl<'a> Params<'a> {
    /// Every parameter, in order (with `First` or `Last`, duplicates
    /// included).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{param, Limits};
    ///
    /// let (p, _) = param::parse(b";a=1; B=2", &Limits::DEFAULT)?;
    /// let names: Vec<&[u8]> = p.iter().map(|p| p.name).collect();
    /// assert_eq!(names, [&b"a"[..], b"B"]);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn iter(&self) -> ParamIter<'a> {
        ParamIter { rest: self.text }
    }

    /// The value of the parameter named `name` (ASCII case-insensitive): the
    /// first match, or the last under [`DuplicatePolicy::Last`].
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{param, Limits};
    ///
    /// let (p, _) = param::parse(b";charset=UTF-8", &Limits::DEFAULT)?;
    /// assert!(p.get("CHARSET").is_some_and(|v| v.eq_bytes(b"UTF-8")));
    /// assert!(p.get("q").is_none());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Word<'a>> {
        let name = name.as_bytes();
        let last = self.policy == DuplicatePolicy::Last;
        let mut found = None;
        // Validated text: OWS ";" OWS [ name "=" word ] ... When `tail` starts
        // with a token byte it starts a parameter name, which ends at its
        // first `=`; so `name` followed by `=` there is that whole name when
        // `name` holds no `=`. (An empty parameter starts `tail` with `;`.)
        // No other byte is checked again.
        let mut rest = self.text;
        while let [b';', after @ ..] = skip_ws(rest) {
            let tail = skip_ws(after);
            let value = match tail.split_at_checked(name.len()) {
                // An exact compare first: names are usually sent in the case
                // asked for.
                Some((head, [b'=', value @ ..]))
                    if (head == name || head.eq_ignore_ascii_case(name))
                        && head.first().is_some_and(|&b| class::is_tchar(b))
                        && !name.contains(&b'=') =>
                {
                    let (word, used) = validated_word(value);
                    if !last {
                        return Some(word);
                    }
                    found = Some(word);
                    rest = value.get(used..).unwrap_or(&[]);
                    continue;
                }
                _ => match token_len(tail) {
                    0 => {
                        rest = tail;
                        continue;
                    }
                    n => tail.get(n + 1..).unwrap_or(&[]),
                },
            };
            rest = value.get(validated_word(value).1..).unwrap_or(&[]);
        }
        found
    }

    /// The parameters before the first one named `name` (ASCII
    /// case-insensitive), and that parameter; all of them and `None` when no
    /// parameter has the name. Used to split media-type parameters from
    /// `q` and the `accept-ext` after it.
    pub(crate) fn split_at_name(&self, name: &[u8]) -> (Params<'a>, Option<Param<'a>>) {
        for (index, p) in self.iter().enumerate() {
            if p.name.eq_ignore_ascii_case(name) {
                // `p.name` points into `self.text`; the distance is its offset.
                let off = (p.name.as_ptr() as usize).saturating_sub(self.text.as_ptr() as usize);
                let head = self.text.get(..off).unwrap_or(&[]);
                let semi = head.iter().rposition(|&b| b == b';').unwrap_or(0);
                let before = Params {
                    text: self.text.get(..semi).unwrap_or(&[]),
                    count: u32::try_from(index).unwrap_or(u32::MAX),
                    policy: self.policy,
                };
                return (before, Some(p));
            }
        }
        (*self, None)
    }

    /// The number of parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{param, Limits};
    ///
    /// assert_eq!(param::parse(b";a=1;;b=2;", &Limits::DEFAULT)?.0.len(), 2);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count as usize
    }

    /// Whether there are no parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{param, Limits};
    ///
    /// assert!(param::parse(b"", &Limits::DEFAULT)?.0.is_empty());
    /// assert!(!param::parse(b";a=1", &Limits::DEFAULT)?.0.is_empty());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The validated text, from the first `;` to the end of the last
    /// parameter.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{param, Limits};
    ///
    /// let (p, _) = param::parse(b";a=1 ;b=2 , next", &Limits::DEFAULT)?;
    /// assert_eq!(p.raw(), b";a=1 ;b=2");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn raw(&self) -> &'a [u8] {
        self.text
    }
}

impl fmt::Debug for Params<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Params(")?;
        f.debug_list()
            .entries(
                self.iter()
                    .map(|p| core::str::from_utf8(p.name).unwrap_or("?")),
            )
            .finish()?;
        f.write_str(")")
    }
}

/// The parameters of a validated [`Params`].
///
/// # Examples
///
/// ```
/// use parse_net::{param, Limits};
///
/// let (p, _) = param::parse(b";a=1;b=2", &Limits::DEFAULT)?;
/// let mut it = p.iter();
/// assert_eq!(it.next().map(|p| p.name), Some(&b"a"[..]));
/// assert_eq!(it.next().map(|p| p.name), Some(&b"b"[..]));
/// assert!(it.next().is_none());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Debug)]
pub struct ParamIter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for ParamIter<'a> {
    type Item = Param<'a>;

    fn next(&mut self) -> Option<Param<'a>> {
        loop {
            // Validated text: OWS ";" OWS [ name "=" word ] ...
            let [b';', after @ ..] = skip_ws(self.rest) else {
                self.rest = &[];
                return None;
            };
            let tail = skip_ws(after);
            let n = token_len(tail);
            let Some((name, [_, value_text @ ..])) = (n > 0).then(|| tail.split_at(n)) else {
                self.rest = tail;
                continue;
            };
            let (value, used) = validated_word(value_text);
            self.rest = value_text.get(used..).unwrap_or(&[]);
            return Some(Param { name, value });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{format, string::String, vec, vec::Vec};

    use proptest::prelude::{Just, Strategy, prop, prop_assert_eq, prop_oneof};

    use super::*;

    fn p(s: &[u8]) -> Result<(Params<'_>, usize)> {
        parse(s, &Limits::DEFAULT)
    }

    fn names<'a>(ps: &Params<'a>) -> Vec<&'a [u8]> {
        ps.iter().map(|x| x.name).collect()
    }

    #[test]
    fn test_params_edge_cases() {
        assert_eq!(p(b"").unwrap().1, 0);
        assert!(p(b";").unwrap().0.is_empty());
        assert_eq!(p(b";").unwrap().1, 1);
        assert_eq!(p(b";;").unwrap().1, 2);
        let (ps, used) = p(b"; a=b").unwrap();
        assert_eq!((used, names(&ps)), (5, [&b"a"[..]].to_vec()));
        assert_eq!(p(b";a=").unwrap_err().kind(), ErrorKind::MissingValue);
        assert_eq!(p(b";a").unwrap_err().kind(), ErrorKind::MissingValue);
        assert_eq!(p(b";a;b=c").unwrap_err().kind(), ErrorKind::MissingValue);
        assert_eq!(p(b";a =b").unwrap_err().kind(), ErrorKind::InvalidByte);
        assert_eq!(p(b";a= b").unwrap_err().kind(), ErrorKind::InvalidByte);
        assert_eq!(p(b";@=b").unwrap_err().kind(), ErrorKind::NotToken);
        assert_eq!(p(b";a@=b").unwrap_err().kind(), ErrorKind::NotToken);
        assert_eq!(p(b";a=\"\"").unwrap().0.get("a").map(|w| w.len()), Some(0));
        assert!(
            p(b";a=\"x\\\"y\"")
                .unwrap()
                .0
                .get("a")
                .unwrap()
                .eq_bytes(b"x\"y")
        );
        assert_eq!(
            p(b";a=\"x").unwrap_err().kind(),
            ErrorKind::UnterminatedQuote
        );
        assert_eq!(p(b";a=b\rc").unwrap().1, 4);
        assert_eq!(p(b";a=\x01").unwrap_err().kind(), ErrorKind::Control);
    }

    #[test]
    fn test_params_stop_at_list_separator_and_trailing_ows() {
        let (ps, used) = p(b";a=1 , b").unwrap();
        assert_eq!((used, ps.len()), (4, 1));
        let (_, used) = p(b";a=1; ,b").unwrap();
        assert_eq!(used, 5);
        let (_, used) = p(b" ;a=1 x").unwrap();
        assert_eq!(used, 5);
    }

    #[test]
    fn test_params_duplicate_refused_case_insensitive() {
        let e = p(b";A=b;a=c").unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::DuplicateParameter, 5));
        assert!(p(b";ab=1;ba=2;aa=3;bb=4").is_ok());
    }

    #[test]
    fn test_params_first_and_last_policies() {
        let first = Limits::DEFAULT.duplicate_params(DuplicatePolicy::First);
        let last = Limits::DEFAULT.duplicate_params(DuplicatePolicy::Last);
        let (a, _) = parse(b";a=1;A=2", &first).unwrap();
        let (b, _) = parse(b";a=1;A=2", &last).unwrap();
        assert!(a.get("a").unwrap().eq_bytes(b"1"));
        assert!(b.get("a").unwrap().eq_bytes(b"2"));
        assert_eq!(a.len(), 2);
    }

    #[test]
    fn test_params_count_limit() {
        let mut v = Vec::new();
        for i in 0..257 {
            v.extend_from_slice(format!(";p{i}=v").as_bytes());
        }
        let cut = v.len() - format!(";p{}=v", 256).len();
        // `First` and `Last` read up to `max_params` (256 by default).
        for policy in [DuplicatePolicy::First, DuplicatePolicy::Last] {
            let l = Limits::DEFAULT.duplicate_params(policy);
            assert_eq!(parse(&v[..cut], &l).unwrap().0.len(), 256);
            assert_eq!(parse(&v, &l).unwrap_err().kind(), ErrorKind::TooManyMembers);
        }
        // `Refuse` stops at the size of its name table, whatever the limit.
        let upto = |n: usize| {
            (0..n)
                .map(|i| format!(";p{i}=v"))
                .collect::<Vec<_>>()
                .concat()
        };
        assert_eq!(p(upto(MAX_CHECKED_PARAMS).as_bytes()).unwrap().0.len(), 64);
        let over = upto(MAX_CHECKED_PARAMS + 1);
        let e = p(over.as_bytes()).unwrap_err();
        let last = over.rfind(';').unwrap() + 1;
        assert_eq!((e.kind(), e.offset()), (ErrorKind::TooManyMembers, last));
        let wide = Limits::DEFAULT.max_params(u16::MAX);
        assert_eq!(
            parse(over.as_bytes(), &wide).unwrap_err().kind(),
            ErrorKind::TooManyMembers
        );
        assert_eq!(
            parse(upto(3).as_bytes(), &Limits::DEFAULT.max_params(2))
                .unwrap_err()
                .kind(),
            ErrorKind::TooManyMembers
        );
    }

    #[test]
    fn test_params_duplicate_found_in_every_table_slot() {
        // A repeat of each of the 64 names is found, in either case, and a
        // name that is a prefix or an extension of an earlier one is not a
        // repeat.
        let base = (0..63)
            .map(|i| format!(";p{i}=\"v;p{i}=w\""))
            .collect::<Vec<_>>()
            .concat();
        for i in 0..63 {
            let dup = format!("{base};P{i}=x");
            let e = p(dup.as_bytes()).unwrap_err();
            assert_eq!(
                (e.kind(), e.offset()),
                (ErrorKind::DuplicateParameter, base.len() + 1),
                "{i}"
            );
        }
        for other in ["p", "p1x", "xp1", "p100"] {
            assert!(p(format!("{base};{other}=x").as_bytes()).is_ok(), "{other}");
        }
    }

    #[test]
    fn test_params_debug_prints_names_only() {
        let (ps, _) = p(b";user=alice;token=\"s3cr3t\"").unwrap();
        let d = format!("{ps:?}");
        assert_eq!(d, "Params([\"user\", \"token\"])");
        assert!(!d.contains("s3cr3t") && !d.contains("alice"));
    }

    #[test]
    fn test_params_iter_skips_empty_parameters() {
        let (ps, _) = p(b";; a=1 ;;b=\"x;y\";").unwrap();
        assert_eq!(names(&ps), [&b"a"[..], b"b"]);
        assert!(ps.get("b").unwrap().eq_bytes(b"x;y"));
        assert_eq!(ps.raw(), b";; a=1 ;;b=\"x;y\";");
    }

    #[test]
    fn test_params_get_matches_whole_names_only() {
        // Found by `test_iter_and_get_agree_with_checked_reads`: an empty
        // parameter must not let `;a` match across the second `;`.
        let (ps, _) = p(b";;a=\"\"").unwrap();
        assert!(ps.get(";a").is_none());
        assert!(ps.get("a").is_some_and(|v| v.eq_bytes(b"")));
        let (ps, _) = p(b";a=b;c=d").unwrap();
        for name in ["a=b", "a=b;c", "", ";", "=", "a;", " a"] {
            assert!(ps.get(name).is_none(), "{name}");
        }
        assert!(ps.get("C").is_some_and(|v| v.eq_bytes(b"d")));
    }

    /// The 0.6 walker, kept as the reference the slice-cursor walker is
    /// compared with (`test_parse_agrees_with_reference`).
    mod reference {
        use super::super::*;
        use crate::text::{parse_word, skip_ows};

        pub(super) fn parse<'a>(s: &'a [u8], limits: &Limits) -> Result<(Params<'a>, usize)> {
            let policy = limits.duplicate_params;
            let mut count: usize = 0;
            let mut used = 0usize;
            let mut seen: u64 = 0;
            loop {
                let ows = skip_ows(s.get(used..).unwrap_or(&[]));
                let semi = used + ows;
                if s.get(semi) != Some(&b';') {
                    break;
                }
                let mut i = semi + 1;
                i += skip_ows(s.get(i..).unwrap_or(&[]));
                match s.get(i) {
                    None | Some(b';') => {
                        used = i;
                        continue;
                    }
                    Some(&b) if !class::is_tchar(b) => {
                        // OWS after an empty parameter followed by a list separator
                        // or the end belongs to the caller.
                        if b == b',' {
                            used = semi + 1;
                            break;
                        }
                        return err(
                            if crate::scan::is_control(b) {
                                control_kind(b)
                            } else {
                                ErrorKind::NotToken
                            },
                            i,
                        );
                    }
                    Some(_) => {}
                }
                let name_start = i;
                let name_len = s
                    .get(i..)
                    .unwrap_or(&[])
                    .iter()
                    .take_while(|&&b| class::is_tchar(b))
                    .count();
                let name = s.get(name_start..name_start + name_len).unwrap_or(&[]);
                i += name_len;
                match s.get(i) {
                    Some(b'=') => i += 1,
                    Some(&b) if is_ows(b) => {
                        let after = i + skip_ows(s.get(i..).unwrap_or(&[]));
                        if s.get(after) == Some(&b'=') {
                            return err(ErrorKind::InvalidByte, i);
                        }
                        return err(ErrorKind::MissingValue, i);
                    }
                    Some(b'"') => return err(ErrorKind::MissingValue, i),
                    Some(&b) if b != b';' && b != b',' && class::is_field_text(b) => {
                        return err(ErrorKind::NotToken, i);
                    }
                    Some(&b) if !class::is_field_text(b) => return err(control_kind(b), i),
                    _ => return err(ErrorKind::MissingValue, i),
                }
                let value_start = i;
                match s.get(i) {
                    Some(&b) if is_ows(b) => return err(ErrorKind::InvalidByte, i),
                    None | Some(b';' | b',') => return err(ErrorKind::MissingValue, i),
                    _ => {}
                }
                let rest = s.get(i..).unwrap_or(&[]);
                let (_, n) = parse_word(rest).map_err(|e| match e.kind() {
                    ErrorKind::Empty => crate::error::ParseError::new(
                        control_or_invalid(rest.first().copied().unwrap_or(0)),
                        value_start,
                    ),
                    _ => e.shifted(value_start),
                })?;
                i += n;
                count += 1;
                if count > usize::from(limits.params) {
                    return err(ErrorKind::TooManyMembers, name_start);
                }
                if policy == DuplicatePolicy::Refuse {
                    let bit = name_bit(name);
                    if seen & bit != 0 {
                        let earlier = Params {
                            text: s.get(..used).unwrap_or(&[]),
                            count: 0,
                            policy,
                        };
                        if earlier.iter().any(|p| p.name.eq_ignore_ascii_case(name)) {
                            return err(ErrorKind::DuplicateParameter, name_start);
                        }
                    }
                    seen |= bit;
                }
                used = i;
            }
            Ok((
                Params {
                    text: s.get(..used).unwrap_or(&[]),
                    count: u32::try_from(count).unwrap_or(u32::MAX),
                    policy,
                },
                used,
            ))
        }
    }

    /// Parameter text built from the pieces the grammar turns on.
    fn param_text() -> impl Strategy<Value = Vec<u8>> {
        let piece = prop_oneof![
            Just(b";".to_vec()),
            Just(b" ".to_vec()),
            Just(b"\t".to_vec()),
            Just(b"=".to_vec()),
            Just(b",".to_vec()),
            Just(b"\"a\\\"b;c=d\"".to_vec()),
            Just(b"\"\\".to_vec()),
            Just(b"\r".to_vec()),
            Just(b"\x7f".to_vec()),
            "[a-cA-C]{1,3}".prop_map(String::into_bytes),
            "[0-9]{1,3}".prop_map(String::into_bytes),
            "[(){}@/]".prop_map(String::into_bytes),
            "; ?[a-cA-C]{1,2}=[0-9a-c]{1,2}".prop_map(String::into_bytes),
            "; ?[a-c]=\"[a-c;,= ]{0,3}\"".prop_map(String::into_bytes),
        ];
        prop::collection::vec(piece, 0..16).prop_map(|v| v.concat())
    }

    fn outcome(
        r: Result<(Params<'_>, usize)>,
    ) -> core::result::Result<(Vec<u8>, usize, usize), (ErrorKind, usize)> {
        r.map(|(p, used)| (p.raw().to_vec(), p.len(), used))
            .map_err(|e| (e.kind(), e.offset()))
    }

    /// Re-reads validated text with the checked public word parser.
    fn reference_iter(raw: &[u8]) -> Vec<Param<'_>> {
        let mut out = Vec::new();
        let mut i = 0;
        loop {
            i += crate::text::skip_ows(raw.get(i..).unwrap_or(&[]));
            if raw.get(i) != Some(&b';') {
                return out;
            }
            i += 1;
            i += crate::text::skip_ows(raw.get(i..).unwrap_or(&[]));
            let Ok((name, n)) = crate::text::parse_token(raw.get(i..).unwrap_or(&[])) else {
                continue;
            };
            i += n + 1;
            let (value, n) = crate::text::parse_word(raw.get(i..).unwrap_or(&[])).unwrap();
            i += n;
            out.push(Param { name, value });
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(4096))]

        #[test]
        fn test_parse_agrees_with_reference(v in param_text()) {
            for policy in [DuplicatePolicy::Refuse, DuplicatePolicy::First, DuplicatePolicy::Last] {
                let limits = Limits::DEFAULT.duplicate_params(policy);
                prop_assert_eq!(outcome(parse(&v, &limits)), outcome(reference::parse(&v, &limits)));
            }
        }

        #[test]
        fn test_iter_and_get_agree_with_checked_reads(v in param_text(), name in "[a-cA-C=; \"]{0,4}") {
            for policy in [DuplicatePolicy::Refuse, DuplicatePolicy::First, DuplicatePolicy::Last] {
                let limits = Limits::DEFAULT.duplicate_params(policy);
                let Ok((p, _)) = parse(&v, &limits) else { continue };
                let all: Vec<Param<'_>> = p.iter().collect();
                prop_assert_eq!(&all, &reference_iter(p.raw()));
                prop_assert_eq!(all.len(), p.len());
                let mut matching = all.iter().filter(|x| x.name.eq_ignore_ascii_case(name.as_bytes()));
                let expected = if policy == DuplicatePolicy::Last { matching.next_back() } else { matching.next() };
                prop_assert_eq!(p.get(&name), expected.map(|x| x.value));
                for x in &all {
                    let n = core::str::from_utf8(x.name).unwrap();
                    let mut same = all.iter().filter(|y| y.name.eq_ignore_ascii_case(x.name));
                    let expected = if policy == DuplicatePolicy::Last { same.next_back() } else { same.next() };
                    prop_assert_eq!(p.get(n), expected.map(|y| y.value));
                }
            }
        }
    }
}
