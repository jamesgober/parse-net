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
    text::{Word, is_ows, parse_word, skip_ows},
};

/// One parameter: a name and a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Param<'a> {
    /// The name as sent (compare it ASCII case-insensitively).
    pub name: &'a [u8],
    /// The value.
    pub value: Word<'a>,
}

/// A small filter over parameter names, so a repeated name is searched for
/// only when one could exist. Bounded: at most `max_params` names are seen.
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
/// under [`DuplicatePolicy::Refuse`]; [`ErrorKind::TooManyMembers`] beyond
/// [`Limits::max_params`].
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
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Params<'a> {
    text: &'a [u8],
    count: u32,
    policy: DuplicatePolicy,
}

impl<'a> Params<'a> {
    /// Every parameter, in order (with `First` or `Last`, duplicates
    /// included).
    #[must_use]
    pub fn iter(&self) -> ParamIter<'a> {
        ParamIter { rest: self.text }
    }

    /// The value of the parameter named `name` (ASCII case-insensitive): the
    /// first match, or the last under [`DuplicatePolicy::Last`].
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Word<'a>> {
        let name = name.as_bytes();
        let mut matches = self.iter().filter(|p| p.name.eq_ignore_ascii_case(name));
        let found = if self.policy == DuplicatePolicy::Last {
            matches.last()
        } else {
            matches.next()
        };
        found.map(|p| p.value)
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
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count as usize
    }

    /// Whether there are no parameters.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The validated text, from the first `;` to the end of the last
    /// parameter.
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
#[derive(Clone, Debug)]
pub struct ParamIter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for ParamIter<'a> {
    type Item = Param<'a>;

    fn next(&mut self) -> Option<Param<'a>> {
        loop {
            // Validated text: OWS ";" OWS [ name "=" word ] ...
            let s = self.rest;
            let semi = s.iter().position(|&b| b == b';')?;
            let after = semi + 1;
            let start = after + skip_ows(s.get(after..).unwrap_or(&[]));
            let tail = s.get(start..).unwrap_or(&[]);
            let name_len = tail.iter().take_while(|&&b| class::is_tchar(b)).count();
            if name_len == 0 {
                self.rest = tail;
                continue;
            }
            let name = tail.get(..name_len).unwrap_or(&[]);
            let value_text = tail.get(name_len + 1..).unwrap_or(&[]);
            let Ok((value, n)) = parse_word(value_text) else {
                self.rest = &[];
                return None;
            };
            self.rest = value_text.get(n..).unwrap_or(&[]);
            return Some(Param { name, value });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{format, vec::Vec};

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
        assert_eq!(p(&v[..cut]).unwrap().0.len(), 256);
        assert_eq!(p(&v).unwrap_err().kind(), ErrorKind::TooManyMembers);
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
}
