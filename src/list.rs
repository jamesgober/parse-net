//! The `#rule` lists of RFC 9110 section 5.6.1, including several field lines
//! read as one list (section 5.3).
//!
//! A comma ends an element only outside quoted strings and comments, so
//! `a="x,y", b` is two elements. Elements are yielded trimmed of OWS, as raw
//! bytes; the grammar of each element (a token, `token;params`, a media
//! range) is the caller's.
//!
//! # Examples
//!
//! ```
//! use parse_net::{self as pn, Limits};
//!
//! let l = pn::list(b"a, \"b,c\" , , (d, e) f,")?;
//! let all: Vec<&[u8]> = l.iter().collect();
//! assert_eq!(all, [&b"a"[..], b"\"b,c\"", b"(d, e) f"]);
//!
//! let lines: [&[u8]; 3] = [b"gzip", b"", b"br, zstd"];
//! let c = pn::list::combined(lines, &Limits::DEFAULT)?;
//! assert_eq!(c.iter().collect::<Vec<_>>(), [&b"gzip"[..], b"br", b"zstd"]);
//! # Ok::<(), pn::ParseError>(())
//! ```

use crate::{
    class,
    error::{ErrorKind, Result, err},
    limits::Limits,
    scan::control_kind,
    text::{self, comment_end, parse_quoted, trim_ows},
};

/// Counters carried across the lines of one field.
#[derive(Clone, Copy, Default)]
struct Budget {
    members: usize,
    empties: usize,
}

/// Whether `value` holds no quoted string and no comment, so a plain comma
/// search finds every element boundary.
#[inline]
fn is_simple(value: &[u8]) -> bool {
    !value.iter().any(|&b| matches!(b, b'"' | b'(' | b')'))
}

/// Accounts for the segment `value[start..end]` (an element or an empty
/// one) and calls `f` for a non-empty element.
#[inline]
fn segment<'a>(
    value: &'a [u8],
    start: usize,
    end: usize,
    limits: &Limits,
    budget: &mut Budget,
    f: &mut impl FnMut(&'a [u8]),
) -> Result<()> {
    let raw = value.get(start..end).unwrap_or(&[]);
    let element = trim_ows(raw);
    if element.is_empty() {
        // An empty value has no elements, not one empty element.
        if !(end == value.len() && start == 0) {
            budget.empties += 1;
            if budget.empties > usize::from(limits.empty_elements) {
                return err(ErrorKind::TooManyEmptyElements, end);
            }
        }
    } else {
        budget.members += 1;
        if budget.members > usize::from(limits.list_members) {
            return err(ErrorKind::TooManyMembers, start + text::skip_ows(raw));
        }
        f(element);
    }
    Ok(())
}

/// Validates `value` as a list and calls `f` for each non-empty element, in
/// one pass with one table lookup per ordinary byte. Returns whether the
/// value was simple (no quoted string, no comment).
fn walk<'a>(
    value: &'a [u8],
    limits: &Limits,
    budget: &mut Budget,
    mut f: impl FnMut(&'a [u8]),
) -> Result<bool> {
    let mut simple = true;
    let mut start = 0usize;
    let mut i = 0usize;
    loop {
        let rest = value.get(i..).unwrap_or(&[]);
        i += rest
            .iter()
            .position(|&b| !class::is_list_plain(b))
            .unwrap_or(rest.len());
        match value.get(i) {
            None => {
                segment(value, start, i, limits, budget, &mut f)?;
                return Ok(simple);
            }
            Some(b',') => {
                segment(value, start, i, limits, budget, &mut f)?;
                i += 1;
                start = i;
            }
            Some(b'"') => {
                simple = false;
                let rest = value.get(i..).unwrap_or(&[]);
                let (_, used) = parse_quoted(rest).map_err(|e| e.shifted(i))?;
                i += used;
            }
            Some(b'(') => {
                simple = false;
                let (end, _) = comment_end(value, i, limits)?;
                i = end;
            }
            Some(b')') => return err(ErrorKind::UnbalancedComment, i),
            // Every byte that is not plain and not a delimiter is a control.
            Some(&b) => return err(control_kind(b), i),
        }
    }
}

/// Parses `value` as a list with the default [`Limits`].
///
/// # Errors
///
/// As [`parse`].
///
/// # Examples
///
/// ```
/// let codings: Vec<&[u8]> = parse_net::list(b"gzip, deflate;q=0.5")?.iter().collect();
/// assert_eq!(codings, [&b"gzip"[..], b"deflate;q=0.5"]);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn list(value: &[u8]) -> Result<List<'_>> {
    parse(value, &Limits::DEFAULT)
}

/// Parses `value` as a list.
///
/// The whole value is validated: every byte as a field value (RFC 9110
/// section 5.5), quoted strings terminated with valid quoted pairs, comments
/// balanced within the depth limit. Empty elements are skipped, up to
/// [`Limits::max_empty_elements`] (RFC 9110 section 5.6.1.2).
///
/// # Errors
///
/// [`ErrorKind::BareCr`], [`ErrorKind::LineFeed`], [`ErrorKind::Nul`],
/// [`ErrorKind::Control`]; [`ErrorKind::UnterminatedQuote`],
/// [`ErrorKind::InvalidQuotedPair`]; [`ErrorKind::UnbalancedComment`],
/// [`ErrorKind::CommentTooDeep`]; [`ErrorKind::TooManyEmptyElements`] at the
/// separator that exceeded the budget; [`ErrorKind::TooManyMembers`] at the
/// element beyond [`Limits::max_list_members`].
///
/// # Examples
///
/// ```
/// use parse_net::{list, ErrorKind, Limits};
///
/// let l = list::parse(b"a, b", &Limits::DEFAULT)?;
/// assert_eq!(l.len(), 2);
/// assert_eq!(list::parse(b"a, \"b", &Limits::DEFAULT).unwrap_err().kind(), ErrorKind::UnterminatedQuote);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse<'a>(value: &'a [u8], limits: &Limits) -> Result<List<'a>> {
    let mut budget = Budget::default();
    let simple = walk(value, limits, &mut budget, |_| {})?;
    Ok(List {
        value,
        // The member limit is a u16, so the count fits.
        count: u32::try_from(budget.members).unwrap_or(u32::MAX),
        simple,
    })
}

/// Validates `value` and calls `f` for each element in the same pass, then
/// returns the element count.
///
/// On error, `f` has seen the elements before the failure.
///
/// # Errors
///
/// As [`parse`].
///
/// # Examples
///
/// ```
/// use parse_net::{list, Limits};
///
/// let mut longest = 0;
/// let n = list::for_each(b"gzip, br, zstd", &Limits::DEFAULT, |e| longest = longest.max(e.len()))?;
/// assert_eq!((n, longest), (3, 4));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn for_each<'a>(value: &'a [u8], limits: &Limits, f: impl FnMut(&'a [u8])) -> Result<usize> {
    let mut budget = Budget::default();
    let _simple = walk(value, limits, &mut budget, f)?;
    Ok(budget.members)
}

/// Validates several field lines of one name as one list (RFC 9110 section
/// 5.3), as if joined by `", "`, without joining them.
///
/// An empty line adds nothing. An element never spans two lines, so a quoted
/// string still open at the end of a line is refused. The empty-element and
/// member budgets count across all lines.
///
/// # Errors
///
/// As [`parse`], with [`ParseError::line`](crate::ParseError::line) set to the
/// failing line.
///
/// # Examples
///
/// ```
/// use parse_net::{list, Limits};
///
/// let lines: [&[u8]; 2] = [b"a, \"x", b"y\""];
/// assert!(list::combined(lines, &Limits::DEFAULT).is_err());
/// ```
pub fn combined<'a, I>(lines: I, limits: &Limits) -> Result<CombinedList<'a, I::IntoIter>>
where
    I: IntoIterator<Item = &'a [u8]>,
    I::IntoIter: Clone,
{
    let lines = lines.into_iter();
    let mut budget = Budget::default();
    for (n, line) in lines.clone().enumerate() {
        let _simple = walk(line, limits, &mut budget, |_| {}).map_err(|e| e.on_line(n))?;
    }
    Ok(CombinedList {
        lines,
        count: budget.members,
        _value: core::marker::PhantomData,
    })
}

/// Whether any element of any line equals `token`, ignoring ASCII case.
///
/// For `Connection: keep-alive, Upgrade` and `Upgrade: websocket`. A line
/// that fails to parse counts as not containing the token (fail closed).
///
/// # Examples
///
/// ```
/// use parse_net::list::contains_token;
///
/// assert!(contains_token([&b"keep-alive, Upgrade"[..]], b"upgrade"));
/// assert!(!contains_token([&b"keep-alive, \"upgrade"[..]], b"upgrade"));
/// ```
pub fn contains_token<'a, I>(lines: I, token: &[u8]) -> bool
where
    I: IntoIterator<Item = &'a [u8]>,
{
    lines.into_iter().any(|line| {
        parse(line, &Limits::DEFAULT).is_ok_and(|l| l.iter().any(|e| e.eq_ignore_ascii_case(token)))
    })
}

/// A validated list. Iterating it cannot fail.
///
/// # Examples
///
/// ```
/// let l = parse_net::list(b"gzip, , br")?;
/// assert_eq!(l.len(), 2);
/// assert_eq!(l.iter().collect::<Vec<_>>(), [&b"gzip"[..], b"br"]);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct List<'a> {
    value: &'a [u8],
    count: u32,
    simple: bool,
}

impl<'a> List<'a> {
    /// The elements, in order, each trimmed of OWS.
    ///
    /// # Examples
    ///
    /// ```
    /// let l = parse_net::list(b"a, \"b, c\"")?;
    /// let mut it = l.iter();
    /// assert_eq!(it.next(), Some(&b"a"[..]));
    /// assert_eq!(it.next(), Some(&b"\"b, c\""[..]));
    /// assert_eq!(it.next(), None);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn iter(&self) -> Elements<'a> {
        Elements {
            rest: self.value,
            remaining: self.count as usize,
            simple: self.simple,
        }
    }

    /// The number of elements.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(parse_net::list(b"a, , b,")?.len(), 2);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count as usize
    }

    /// Whether the list has no elements.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(parse_net::list(b" , ")?.is_empty());
    /// assert!(!parse_net::list(b"a")?.is_empty());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl<'a> IntoIterator for List<'a> {
    type Item = &'a [u8];
    type IntoIter = Elements<'a>;

    fn into_iter(self) -> Elements<'a> {
        self.iter()
    }
}

/// The index of the first comma of `s` outside quoted strings and comments.
/// `s` has been validated, so quotes and comments are well formed.
fn top_level_comma(s: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    let mut depth = 0u32;
    let mut quoted = false;
    while let Some(&b) = s.get(i) {
        match b {
            b'\\' if quoted || depth > 0 => i += 1,
            b'"' if depth == 0 => quoted = !quoted,
            b'(' if !quoted => depth += 1,
            b')' if !quoted => depth = depth.saturating_sub(1),
            b',' if !quoted && depth == 0 => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// The elements of a validated list.
///
/// # Examples
///
/// ```
/// let mut e = parse_net::list(b"gzip, br")?.iter();
/// assert_eq!(e.len(), 2);
/// assert_eq!(e.next(), Some(&b"gzip"[..]));
/// assert_eq!(e.len(), 1);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Debug)]
pub struct Elements<'a> {
    rest: &'a [u8],
    remaining: usize,
    simple: bool,
}

impl<'a> Iterator for Elements<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        while self.remaining > 0 && !self.rest.is_empty() {
            let end = if self.simple {
                self.rest.iter().position(|&b| b == b',')
            } else {
                top_level_comma(self.rest)
            }
            .unwrap_or(self.rest.len());
            let element = trim_ows(self.rest.get(..end).unwrap_or(&[]));
            self.rest = self.rest.get(end + 1..).unwrap_or(&[]);
            if !element.is_empty() {
                self.remaining -= 1;
                return Some(element);
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for Elements<'_> {}

/// Several validated field lines read as one list.
///
/// # Examples
///
/// ```
/// use parse_net::{list, Limits};
///
/// let lines: [&[u8]; 2] = [b"gzip", b"br, zstd"];
/// let c = list::combined(lines, &Limits::DEFAULT)?;
/// assert_eq!(c.len(), 3);
/// assert!(c.iter().any(|e| e == b"zstd"));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Debug)]
pub struct CombinedList<'a, I> {
    lines: I,
    count: usize,
    _value: core::marker::PhantomData<&'a [u8]>,
}

impl<'a, I: Iterator<Item = &'a [u8]> + Clone> CombinedList<'a, I> {
    /// The elements of every line, in order.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{list, Limits};
    ///
    /// let lines: [&[u8]; 2] = [b"gzip", b"br, zstd"];
    /// let c = list::combined(lines, &Limits::DEFAULT)?;
    /// assert_eq!(c.iter().collect::<Vec<_>>(), [&b"gzip"[..], b"br", b"zstd"]);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn iter(&self) -> CombinedElements<'a, I> {
        CombinedElements {
            lines: self.lines.clone(),
            current: Elements {
                rest: &[],
                remaining: 0,
                simple: true,
            },
            remaining: self.count,
        }
    }

    /// The number of elements across all lines.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{list, Limits};
    ///
    /// let lines: [&[u8]; 3] = [b"a, b", b"", b"c"];
    /// assert_eq!(list::combined(lines, &Limits::DEFAULT)?.len(), 3);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether no line has an element.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{list, Limits};
    ///
    /// let lines: [&[u8]; 2] = [b"", b" , "];
    /// assert!(list::combined(lines, &Limits::DEFAULT)?.is_empty());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// The elements of a [`CombinedList`].
///
/// # Examples
///
/// ```
/// use parse_net::{list, Limits};
///
/// let lines: [&[u8]; 2] = [b"gzip", b"br"];
/// let mut it = list::combined(lines, &Limits::DEFAULT)?.iter();
/// assert_eq!(it.next(), Some(&b"gzip"[..]));
/// assert_eq!(it.next(), Some(&b"br"[..]));
/// assert_eq!(it.next(), None);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Debug)]
pub struct CombinedElements<'a, I> {
    lines: I,
    current: Elements<'a>,
    remaining: usize,
}

impl<'a, I: Iterator<Item = &'a [u8]>> Iterator for CombinedElements<'a, I> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        while self.remaining > 0 {
            if let Some(e) = self.current.next() {
                self.remaining -= 1;
                return Some(e);
            }
            let line = self.lines.next()?;
            // The line was validated with the same rules; `usize::MAX` lets
            // the walker run to the line's end.
            self.current = Elements {
                rest: line,
                remaining: usize::MAX,
                simple: is_simple(line),
            };
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<'a, I: Iterator<Item = &'a [u8]>> ExactSizeIterator for CombinedElements<'a, I> {}

#[cfg(test)]
mod tests {
    use std::{vec, vec::Vec};

    use super::*;

    fn all(v: &[u8]) -> Vec<&[u8]> {
        list(v).unwrap().iter().collect()
    }

    #[test]
    fn test_list_edge_cases() {
        assert!(all(b"").is_empty());
        assert!(all(b"   ").is_empty());
        assert!(all(b",").is_empty());
        assert!(all(b", ,").is_empty());
        assert_eq!(all(b"a,"), [b"a"]);
        assert_eq!(all(b",a"), [b"a"]);
        assert_eq!(all(b"a,,b"), [&b"a"[..], b"b"]);
        assert_eq!(all(b"a, \"b,c\""), [&b"a"[..], b"\"b,c\""]);
        assert_eq!(all(b"a, (b,c)"), [&b"a"[..], b"(b,c)"]);
        assert_eq!(all(b"a;q=1 , b"), [&b"a;q=1"[..], b"b"]);
        assert_eq!(all(b"a=\"x\\\",y\", b"), [&b"a=\"x\\\",y\""[..], b"b"]);
        assert_eq!(all(b"(a\\)b,c), d"), [&b"(a\\)b,c)"[..], b"d"]);
    }

    #[test]
    fn test_list_comma_in_quotes_is_one_element() {
        assert_eq!(all(b"filename=\"a,b.txt\""), [&b"filename=\"a,b.txt\""[..]]);
    }

    #[test]
    fn test_list_empty_element_budget() {
        // "a" and "b" around 17 commas leave 16 empty elements; 18 leave 17.
        let mut sixteen = vec![b'a'];
        sixteen.extend([b','; 17]);
        sixteen.push(b'b');
        assert_eq!(all(&sixteen), [&b"a"[..], b"b"]);
        let mut seventeen = vec![b'a'];
        seventeen.extend([b','; 18]);
        seventeen.push(b'b');
        let e = list(&seventeen).unwrap_err();
        assert_eq!(
            (e.kind(), e.offset()),
            (ErrorKind::TooManyEmptyElements, 18)
        );
    }

    #[test]
    fn test_list_member_budget() {
        let mut v = Vec::new();
        for i in 0..1025 {
            if i > 0 {
                v.extend_from_slice(b", ");
            }
            v.push(b'a');
        }
        assert_eq!(list(&v[..v.len() - 3]).unwrap().len(), 1024);
        assert_eq!(list(&v).unwrap_err().kind(), ErrorKind::TooManyMembers);
        let e = parse(b"a, b, c", &Limits::DEFAULT.max_list_members(2)).unwrap_err();
        assert_eq!(e.offset(), 6);
    }

    #[test]
    fn test_list_refuses_bad_bytes_and_structure() {
        assert_eq!(list(b"a\rb").unwrap_err().kind(), ErrorKind::BareCr);
        assert_eq!(
            list(b"a, \"b").unwrap_err().kind(),
            ErrorKind::UnterminatedQuote
        );
        assert_eq!(
            list(b"a)").unwrap_err().kind(),
            ErrorKind::UnbalancedComment
        );
        assert_eq!(
            list(b"(a").unwrap_err().kind(),
            ErrorKind::UnbalancedComment
        );
        let e = list(b"ab, \"c\x01\"").unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::Control, 6));
    }

    #[test]
    fn test_combined_lines() {
        let lines: [&[u8]; 3] = [b"a, b", b"", b"c"];
        let c = combined(lines, &Limits::DEFAULT).unwrap();
        assert_eq!(c.len(), 3);
        assert_eq!(c.iter().collect::<Vec<_>>(), [&b"a"[..], b"b", b"c"]);
        assert_eq!(c.iter().len(), 3);
        let bad: [&[u8]; 2] = [b"a", b"\"open"];
        let e = combined(bad, &Limits::DEFAULT).unwrap_err();
        assert_eq!((e.kind(), e.line()), (ErrorKind::UnterminatedQuote, 1));
        let empty: [&[u8]; 0] = [];
        assert!(combined(empty, &Limits::DEFAULT).unwrap().is_empty());
    }

    #[test]
    fn test_combined_budgets_count_across_lines() {
        let l = Limits::DEFAULT.max_list_members(2);
        let lines: [&[u8]; 2] = [b"a", b"b, c"];
        let e = combined(lines, &l).unwrap_err();
        assert_eq!(
            (e.kind(), e.line(), e.offset()),
            (ErrorKind::TooManyMembers, 1, 3)
        );
    }

    #[test]
    fn test_combined_equals_joined_at_every_comma() {
        let value = b"a, \"b,c\", (d,e), f;g=\"h\", i";
        let whole = all(value);
        let mut commas = Vec::new();
        let mut from = 0;
        while let Some(i) = top_level_comma(&value[from..]) {
            commas.push(from + i);
            from += i + 1;
        }
        assert_eq!(commas.len(), 4);
        for &split in &commas {
            let lines: [&[u8]; 2] = [&value[..split], &value[split + 1..]];
            let c = combined(lines, &Limits::DEFAULT).unwrap();
            assert_eq!(c.iter().collect::<Vec<_>>(), whole, "split at {split}");
        }
    }

    #[test]
    fn test_contains_token_fails_closed() {
        assert!(contains_token(
            [&b"close"[..], b"keep-alive, Upgrade"],
            b"upgrade"
        ));
        assert!(!contains_token([&b"upgrade\r"[..]], b"upgrade"));
        let none: [&[u8]; 0] = [];
        assert!(!contains_token(none, b"x"));
    }

    #[test]
    fn test_for_each_sees_every_element() {
        let mut seen = vec![];
        let n = for_each(b"a, b ,c", &Limits::DEFAULT, |e| seen.push(e)).unwrap();
        assert_eq!((n, seen), (3, vec![&b"a"[..], b"b", b"c"]));
    }
}
