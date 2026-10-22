//! `addr-spec`, `mailbox`, and `msg-id` (RFC 5322 sections 3.4 and 3.6.4),
//! with UTF-8 per RFC 6532.

use crate::{
    class,
    error::{ErrorKind, ParseError, Result, WriteError, err},
    limits::Limits,
    scan::control_kind,
    text::{Quoted, comment_end, parse_quoted, skip_ows, trim_ows},
    write::{CountSink, Sink, reserve},
};

/// The longest local part (RFC 5321 section 4.5.3.1.1).
const LOCAL_LIMIT: usize = 64;
/// The longest address: the 256-octet path limit less the angle brackets
/// (RFC 5321 section 4.5.3.1.3).
const ADDRESS_LIMIT: usize = 254;

fn refused(v: &[u8], at: usize, kind: ErrorKind) -> ParseError {
    match v.get(at) {
        Some(&b) if crate::scan::is_control(b) => ParseError::new(control_kind(b), at),
        _ => ParseError::new(kind, at),
    }
}

/// Checks `seg` as a `dot-atom-text` with RFC 6532 UTF-8: atoms of `atext` or
/// non-ASCII UTF-8, joined by single dots. `base` offsets the errors.
fn check_dot_atom(seg: &[u8], base: usize) -> Result<()> {
    if seg.is_empty() {
        return err(ErrorKind::InvalidAddrSpec, base);
    }
    if let Err(e) = core::str::from_utf8(seg) {
        return err(ErrorKind::InvalidUtf8, base + e.valid_up_to());
    }
    let mut prev_dot = true;
    for (i, &b) in seg.iter().enumerate() {
        if b == b'.' {
            if prev_dot {
                return err(ErrorKind::InvalidAddrSpec, base + i);
            }
            prev_dot = true;
        } else if class::is_atext(b) || b >= 0x80 {
            prev_dot = false;
        } else {
            return Err(refused(seg, i, ErrorKind::InvalidAddrSpec).shifted(base));
        }
    }
    if prev_dot {
        return err(ErrorKind::InvalidAddrSpec, base + seg.len() - 1);
    }
    Ok(())
}

/// `dtext` with RFC 6532 UTF-8: `%d33-90 / %d94-126`, or non-ASCII.
fn check_dtext(seg: &[u8], base: usize) -> Result<()> {
    if let Err(e) = core::str::from_utf8(seg) {
        return err(ErrorKind::InvalidUtf8, base + e.valid_up_to());
    }
    match seg
        .iter()
        .position(|&b| !matches!(b, 33..=90 | 94..=126 | 0x80..))
    {
        Some(i) => Err(refused(seg, i, ErrorKind::InvalidAddrSpec).shifted(base)),
        None => Ok(()),
    }
}

/// An address: `local-part "@" domain`.
///
/// # Examples
///
/// ```
/// use parse_net::mail::{self, Domain, LocalPart};
///
/// let a = mail::parse_addr_spec(b"jane.doe@example.com")?;
/// assert_eq!(a.local, LocalPart::DotAtom(b"jane.doe"));
/// assert_eq!(a.domain, Domain::DotAtom(b"example.com"));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AddrSpec<'a> {
    /// The part before `@`.
    pub local: LocalPart<'a>,
    /// The part after `@`.
    pub domain: Domain<'a>,
}

impl AddrSpec<'_> {
    /// Whether the address is all ASCII; `false` means delivery needs
    /// SMTPUTF8 (RFC 6531).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::mail;
    ///
    /// assert!(mail::parse_addr_spec(b"info@example.com")?.is_ascii());
    /// assert!(!mail::parse_addr_spec("info@b\u{fc}cher.example".as_bytes())?.is_ascii());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn is_ascii(&self) -> bool {
        let local = match self.local {
            LocalPart::DotAtom(a) => a,
            LocalPart::Quoted(q) => q.raw(),
        };
        let domain = match self.domain {
            Domain::DotAtom(d) | Domain::Literal(d) => d,
        };
        local.is_ascii() && domain.is_ascii()
    }
}

/// A local part.
///
/// # Examples
///
/// ```
/// use parse_net::mail::{self, LocalPart};
///
/// let a = mail::parse_addr_spec(b"\"john doe\"@example.com")?;
/// assert!(matches!(a.local, LocalPart::Quoted(q) if q.eq_bytes(b"john doe")));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LocalPart<'a> {
    /// `dot-atom-text`, as sent.
    DotAtom(&'a [u8]),
    /// A quoted string.
    Quoted(Quoted<'a>),
}

/// A domain.
///
/// # Examples
///
/// ```
/// use parse_net::mail::{self, Domain};
///
/// assert_eq!(mail::parse_addr_spec(b"a@Example.COM")?.domain, Domain::DotAtom(b"Example.COM"));
/// assert_eq!(mail::parse_addr_spec(b"a@[IPv6:2001:db8::1]")?.domain, Domain::Literal(b"IPv6:2001:db8::1"));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Domain<'a> {
    /// `dot-atom-text`, as sent (compare it ASCII case-insensitively).
    DotAtom(&'a [u8]),
    /// A domain literal: the text inside `[` and `]`.
    Literal(&'a [u8]),
}

/// Parses an `addr-spec` (RFC 5322 section 3.4.1) without obsolete forms,
/// comments, or folding: a `dot-atom` or quoted local part, `@`, and a
/// `dot-atom` domain or `[domain-literal]`. The local part is at most 64
/// octets and the address at most 254; non-ASCII is accepted only as valid
/// UTF-8 (RFC 6532). Surrounding SP and HTAB are stripped.
///
/// # Errors
///
/// [`ErrorKind::InvalidAddrSpec`] (a leading, trailing, or doubled dot, a
/// missing `@`, a comment, a byte outside the grammar);
/// [`ErrorKind::TooLong`]; [`ErrorKind::InvalidUtf8`];
/// [`ErrorKind::UnterminatedQuote`].
///
/// # Examples
///
/// ```
/// use parse_net::mail::{self, Domain};
///
/// let a = mail::parse_addr_spec(b"user@[192.0.2.1]")?;
/// assert_eq!(a.domain, Domain::Literal(b"192.0.2.1"));
/// assert!(!mail::parse_addr_spec("j\u{f6}rg@example.de".as_bytes())?.is_ascii());
/// assert!(mail::parse_addr_spec(b"user(comment)@example.com").is_err());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_addr_spec(value: &[u8]) -> Result<AddrSpec<'_>> {
    let lead = skip_ows(value);
    let v = trim_ows(value);
    addr_spec(v).map_err(|e| e.shifted(lead))
}

fn addr_spec(v: &[u8]) -> Result<AddrSpec<'_>> {
    let (local, at) = if v.first() == Some(&b'"') {
        let (q, used) = parse_quoted(v)?;
        if let Err(e) = core::str::from_utf8(q.raw()) {
            return err(ErrorKind::InvalidUtf8, 1 + e.valid_up_to());
        }
        (LocalPart::Quoted(q), used)
    } else {
        let at = v.iter().position(|&b| b == b'@').unwrap_or(v.len());
        let seg = v.get(..at).unwrap_or(&[]);
        check_dot_atom(seg, 0)?;
        (LocalPart::DotAtom(seg), at)
    };
    if at > LOCAL_LIMIT {
        return err(ErrorKind::TooLong, LOCAL_LIMIT);
    }
    if v.get(at) != Some(&b'@') {
        return Err(refused(v, at, ErrorKind::InvalidAddrSpec));
    }
    let start = at + 1;
    let rest = v.get(start..).unwrap_or(&[]);
    let domain = if rest.first() == Some(&b'[') {
        let Some((&b']', inner)) = rest
            .split_last()
            .map(|(l, h)| (l, h.get(1..).unwrap_or(&[])))
        else {
            return err(ErrorKind::InvalidAddrSpec, v.len());
        };
        check_dtext(inner, start + 1)?;
        Domain::Literal(inner)
    } else {
        check_dot_atom(rest, start)?;
        Domain::DotAtom(rest)
    };
    if v.len() > ADDRESS_LIMIT {
        return err(ErrorKind::TooLong, ADDRESS_LIMIT);
    }
    Ok(AddrSpec { local, domain })
}

/// A mailbox: an optional display name and an address.
///
/// # Examples
///
/// ```
/// use parse_net::{mail::{self, Domain}, Limits};
///
/// let m = mail::parse_mailbox(b"Jane Doe <jane@example.com>", &Limits::DEFAULT)?;
/// assert_eq!(m.display_name, Some(&b"Jane Doe"[..]));
/// assert_eq!(m.addr.domain, Domain::DotAtom(b"example.com"));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Mailbox<'a> {
    /// The display name as sent (words, quoted strings, comments, possibly
    /// encoded words: decode with [`decode_words`](super::decode_words)).
    pub display_name: Option<&'a [u8]>,
    /// The address.
    pub addr: AddrSpec<'a>,
}

/// Parses a `mailbox` (RFC 5322 section 3.4): `[display-name] "<" addr-spec
/// ">"` or a bare `addr-spec`. The display name is checked as a phrase
/// (atoms, dots, quoted strings, comments, UTF-8) and returned raw.
///
/// # Errors
///
/// As [`parse_addr_spec`]; [`ErrorKind::UnbalancedComment`],
/// [`ErrorKind::CommentTooDeep`].
///
/// # Examples
///
/// ```
/// use parse_net::{mail, Limits};
///
/// let m = mail::parse_mailbox(b"\"Doe, John\" <john@example.com>", &Limits::DEFAULT)?;
/// assert_eq!(m.display_name, Some(&b"\"Doe, John\""[..]));
/// assert!(mail::parse_mailbox(b"john@example.com", &Limits::DEFAULT)?.display_name.is_none());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_mailbox<'a>(value: &'a [u8], limits: &Limits) -> Result<Mailbox<'a>> {
    let lead = skip_ows(value);
    let v = trim_ows(value);
    if v.last() != Some(&b'>') {
        let addr = addr_spec(v).map_err(|e| e.shifted(lead))?;
        return Ok(Mailbox {
            display_name: None,
            addr,
        });
    }
    // Find the `<` outside quoted strings and comments, checking the phrase.
    let mut i = 0usize;
    let lt = loop {
        match v.get(i) {
            None => return err(ErrorKind::InvalidAddrSpec, lead + i),
            Some(b'<') => break i,
            Some(b'"') => {
                let (q, used) =
                    parse_quoted(v.get(i..).unwrap_or(&[])).map_err(|e| e.shifted(lead + i))?;
                if let Err(e) = core::str::from_utf8(q.raw()) {
                    return err(ErrorKind::InvalidUtf8, lead + i + 1 + e.valid_up_to());
                }
                i += used;
            }
            Some(b'(') => i = comment_end(v, i, limits).map_err(|e| e.shifted(lead))?.0,
            Some(&b) if class::is_atext(b) || matches!(b, b'.' | b' ' | b'\t') || b >= 0x80 => {
                i += 1
            }
            Some(_) => return Err(refused(v, i, ErrorKind::InvalidAddrSpec).shifted(lead)),
        }
    };
    let display = trim_ows(v.get(..lt).unwrap_or(&[]));
    if let Err(e) = core::str::from_utf8(display) {
        return err(ErrorKind::InvalidUtf8, lead + e.valid_up_to());
    }
    let inner = v.get(lt + 1..v.len() - 1).unwrap_or(&[]);
    let addr = addr_spec(inner).map_err(|e| e.shifted(lead + lt + 1))?;
    Ok(Mailbox {
        display_name: (!display.is_empty()).then_some(display),
        addr,
    })
}

/// A message identifier: `"<" id-left "@" id-right ">"`.
///
/// # Examples
///
/// ```
/// let id = parse_net::mail::parse_msg_id(b"<abc.123@[192.0.2.1]>")?;
/// assert_eq!((id.left, id.right), (&b"abc.123"[..], &b"[192.0.2.1]"[..]));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MsgId<'a> {
    /// The part before `@`.
    pub left: &'a [u8],
    /// The part after `@` (a domain literal keeps its brackets).
    pub right: &'a [u8],
}

/// Parses a `msg-id` (RFC 5322 section 3.6.4): `dot-atom-text` on both
/// sides of `@`, or a `no-fold-literal` (`[...]`) on the right.
///
/// # Errors
///
/// [`ErrorKind::InvalidAddrSpec`]; [`ErrorKind::InvalidUtf8`].
///
/// # Examples
///
/// ```
/// let id = parse_net::mail::parse_msg_id(b"<1234.5678@mail.example.com>")?;
/// assert_eq!((id.left, id.right), (&b"1234.5678"[..], &b"mail.example.com"[..]));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_msg_id(value: &[u8]) -> Result<MsgId<'_>> {
    let lead = skip_ows(value);
    let v = trim_ows(value);
    let inner = match (v.first(), v.last()) {
        (Some(b'<'), Some(b'>')) if v.len() >= 2 => v.get(1..v.len() - 1).unwrap_or(&[]),
        _ => return err(ErrorKind::InvalidAddrSpec, lead),
    };
    let at = inner.iter().position(|&b| b == b'@').unwrap_or(inner.len());
    let left = inner.get(..at).unwrap_or(&[]);
    check_dot_atom(left, lead + 1)?;
    if inner.get(at) != Some(&b'@') {
        return err(ErrorKind::InvalidAddrSpec, lead + 1 + at);
    }
    let right = inner.get(at + 1..).unwrap_or(&[]);
    let base = lead + 2 + at;
    match (right.first(), right.last()) {
        (Some(b'['), Some(b']')) if right.len() >= 2 => {
            check_dtext(right.get(1..right.len() - 1).unwrap_or(&[]), base + 1)?
        }
        _ => check_dot_atom(right, base)?,
    }
    Ok(MsgId { left, right })
}

fn is_ascii_dot_atom(s: &[u8]) -> Option<usize> {
    let mut prev_dot = true;
    for (i, &b) in s.iter().enumerate() {
        if b == b'.' {
            if prev_dot {
                return Some(i);
            }
            prev_dot = true;
        } else if class::is_atext(b) {
            prev_dot = false;
        } else {
            return Some(i);
        }
    }
    prev_dot.then_some(s.len().saturating_sub(1))
}

/// Writes `<left@right>`. `left` must be ASCII `dot-atom-text`; `right` the
/// same or a domain literal in brackets.
///
/// # Errors
///
/// [`WriteError::Forbidden`] with `at` counting through `left` and then
/// `right` (a byte outside the grammar, a misplaced dot, an empty side);
/// [`WriteError::Full`] (nothing written when the sink reports its room).
///
/// # Examples
///
/// ```
/// use parse_net::{mail, SliceSink};
///
/// let mut buf = [0u8; 64];
/// let mut out = SliceSink::new(&mut buf);
/// mail::write_msg_id("1234.5678", "mail.example.com", &mut out)?;
/// assert_eq!(out.written(), b"<1234.5678@mail.example.com>");
/// # Ok::<(), parse_net::WriteError>(())
/// ```
pub fn write_msg_id(
    left: &str,
    right: &str,
    out: &mut impl Sink,
) -> core::result::Result<(), WriteError> {
    let (l, r) = (left.as_bytes(), right.as_bytes());
    if let Some(i) = is_ascii_dot_atom(l) {
        return Err(WriteError::forbidden(i));
    }
    let bad_right = match (r.first(), r.last()) {
        (Some(b'['), Some(b']')) if r.len() >= 2 => r
            .get(1..r.len() - 1)
            .unwrap_or(&[])
            .iter()
            .position(|&b| !matches!(b, 33..=90 | 94..=126))
            .map(|i| i + 1),
        _ => is_ascii_dot_atom(r),
    };
    if let Some(i) = bad_right {
        return Err(WriteError::forbidden(l.len() + i));
    }
    let mut count = CountSink::new();
    put_msg_id(l, r, &mut count)?;
    reserve(out, count.count())?;
    put_msg_id(l, r, out)
}

fn put_msg_id(l: &[u8], r: &[u8], out: &mut impl Sink) -> core::result::Result<(), WriteError> {
    out.put(b"<")?;
    out.put(l)?;
    out.put(b"@")?;
    out.put(r)?;
    out.put(b">")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn k(v: &[u8]) -> ErrorKind {
        parse_addr_spec(v).unwrap_err().kind()
    }

    #[test]
    fn test_addr_spec_edge_cases() {
        let a = parse_addr_spec(b"\"john doe\"@example.com").unwrap();
        assert!(matches!(a.local, LocalPart::Quoted(q) if q.eq_bytes(b"john doe")));
        assert_eq!(a.domain, Domain::DotAtom(b"example.com"));
        assert!(parse_addr_spec(b"a.b+tag@sub.example.co").is_ok());
        assert_eq!(k(b"john..doe@example.com"), ErrorKind::InvalidAddrSpec);
        assert_eq!(k(b".john@example.com"), ErrorKind::InvalidAddrSpec);
        assert_eq!(k(b"john.@example.com"), ErrorKind::InvalidAddrSpec);
        assert_eq!(k(b"john@example..com"), ErrorKind::InvalidAddrSpec);
        assert_eq!(k(b"john@"), ErrorKind::InvalidAddrSpec);
        assert_eq!(k(b"@example.com"), ErrorKind::InvalidAddrSpec);
        assert_eq!(k(b"john.example.com"), ErrorKind::InvalidAddrSpec);
        assert_eq!(k(b"john(c)@example.com"), ErrorKind::InvalidAddrSpec);
        assert_eq!(k(b"john@example.com (c)"), ErrorKind::InvalidAddrSpec);
        assert_eq!(k(b"a b@example.com"), ErrorKind::InvalidAddrSpec);
        assert_eq!(k(b"a@b@example.com"), ErrorKind::InvalidAddrSpec);
        assert_eq!(k(b"\"a@example.com"), ErrorKind::UnterminatedQuote);
        assert_eq!(k(b"a\r\n@example.com"), ErrorKind::BareCr);
        assert_eq!(k(b"j\xf6rg@example.de"), ErrorKind::InvalidUtf8);
        assert!(
            !parse_addr_spec("j\u{f6}rg@\u{e9}xample.de".as_bytes())
                .unwrap()
                .is_ascii()
        );
        let lit = parse_addr_spec(b"a@[IPv6:2001:db8::1]").unwrap();
        assert_eq!(lit.domain, Domain::Literal(b"IPv6:2001:db8::1"));
        assert_eq!(k(b"a@[1.2.3.4"), ErrorKind::InvalidAddrSpec);
        assert_eq!(k(b"a@[a[b]"), ErrorKind::InvalidAddrSpec);
    }

    #[test]
    fn test_addr_spec_lengths() {
        let local = [b'a'; 64];
        let ok = [&local[..], b"@example.com"].concat();
        assert!(parse_addr_spec(&ok).is_ok());
        let long = [&[b'a'; 65][..], b"@example.com"].concat();
        assert_eq!(k(&long), ErrorKind::TooLong);
        let mut domain = Vec::new();
        while domain.len() < 250 {
            domain.extend_from_slice(b"abcdefghi.");
        }
        domain.truncate(252);
        domain.push(b'x');
        let a = [b"a@".as_slice(), &domain[..251]].concat();
        assert_eq!(a.len(), 253);
        let a = [b"ab@".as_slice(), &domain[..251]].concat();
        assert_eq!((a.len(), parse_addr_spec(&a).is_ok()), (254, true));
        let a = [b"abc@".as_slice(), &domain[..251]].concat();
        assert_eq!(k(&a), ErrorKind::TooLong);
    }

    #[test]
    fn test_mailbox_forms() {
        let l = Limits::DEFAULT;
        let m = parse_mailbox(b"John Q. Public <jqp@example.com>", &l).unwrap();
        assert_eq!(m.display_name, Some(&b"John Q. Public"[..]));
        let m = parse_mailbox(b"=?UTF-8?Q?J=C3=B6rg?= (work) <j@example.de>", &l).unwrap();
        assert_eq!(m.display_name, Some(&b"=?UTF-8?Q?J=C3=B6rg?= (work)"[..]));
        let m = parse_mailbox(b"<a@b.c>", &l).unwrap();
        assert!(m.display_name.is_none());
        assert_eq!(
            parse_mailbox(b"\"a <b@c.d>", &l).unwrap_err().kind(),
            ErrorKind::UnterminatedQuote
        );
        assert_eq!(
            parse_mailbox(b"(x <a@b.c>", &l).unwrap_err().kind(),
            ErrorKind::UnbalancedComment
        );
        assert_eq!(
            parse_mailbox(b"a@b <a@b.c>", &l).unwrap_err().kind(),
            ErrorKind::InvalidAddrSpec
        );
        assert_eq!(
            parse_mailbox(b"x <a..b@c.d>", &l).unwrap_err().kind(),
            ErrorKind::InvalidAddrSpec
        );
        assert_eq!(
            parse_mailbox(b"x a@b.c>", &l).unwrap_err().kind(),
            ErrorKind::InvalidAddrSpec
        );
    }

    #[test]
    fn test_msg_id_parse_and_write() {
        assert!(parse_msg_id(b"<a@[127.0.0.1]>").is_ok());
        assert_eq!(
            parse_msg_id(b"a@b").unwrap_err().kind(),
            ErrorKind::InvalidAddrSpec
        );
        assert_eq!(
            parse_msg_id(b"<ab>").unwrap_err().kind(),
            ErrorKind::InvalidAddrSpec
        );
        assert_eq!(
            parse_msg_id(b"<a..b@c>").unwrap_err().kind(),
            ErrorKind::InvalidAddrSpec
        );
        assert_eq!(
            parse_msg_id(b"<>").unwrap_err().kind(),
            ErrorKind::InvalidAddrSpec
        );
        let mut buf = [0u8; 64];
        let mut out = crate::SliceSink::new(&mut buf);
        assert_eq!(
            write_msg_id("a b", "c", &mut out),
            Err(WriteError::Forbidden { at: 1 })
        );
        assert_eq!(
            write_msg_id("a", "c..d", &mut out),
            Err(WriteError::Forbidden { at: 3 })
        );
        assert_eq!(
            write_msg_id("", "c", &mut out),
            Err(WriteError::Forbidden { at: 0 })
        );
        assert_eq!(
            write_msg_id("a", "[x]y]", &mut out),
            Err(WriteError::Forbidden { at: 3 })
        );
        assert!(out.is_empty());
        write_msg_id("x.y", "[192.0.2.1]", &mut out).unwrap();
        let id = parse_msg_id(out.written()).unwrap();
        assert_eq!((id.left, id.right), (&b"x.y"[..], &b"[192.0.2.1]"[..]));
    }
}
