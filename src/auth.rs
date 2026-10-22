//! `Authorization`, `Proxy-Authorization`, `WWW-Authenticate`, and
//! `Proxy-Authenticate` (RFC 9110 section 11), with the `Bearer` (RFC 6750)
//! and `Basic` (RFC 7617) payloads.
//!
//! Credentials are secrets: `Debug` on [`Credentials`] and [`AuthPayload`]
//! prints the scheme and parameter names only.
//!
//! # Examples
//!
//! ```
//! use parse_net::{self as pn, auth, Limits};
//!
//! assert_eq!(pn::bearer(b"bearer  mF_9.B5f-4.1JqM==")?, Some(&b"mF_9.B5f-4.1JqM=="[..]));
//! assert_eq!(pn::bearer(b"Basic dXNlcjpwYXNz")?, None);
//! assert_eq!(pn::basic(b"Basic dXNlcjpwYXNz")?, Some(&b"dXNlcjpwYXNz"[..]));
//!
//! let c = auth::parse_credentials(b"Digest username=\"a\", realm=\"r\"", &Limits::DEFAULT)?;
//! assert!(c.scheme_is("digest"));
//! assert_eq!(format!("{c:?}"), "Credentials { scheme: \"Digest\", .. }");
//! # Ok::<(), pn::ParseError>(())
//! ```

use core::{fmt, iter::Peekable};

use crate::{
    class,
    error::{ErrorKind, ParseError, Result, WriteError, err},
    limits::Limits,
    list,
    param::{MAX_CHECKED_PARAMS, Names},
    scan::control_kind,
    text::{Word, is_token, parse_word, skip_ows, trim_ows},
    write::{CountSink, Sink, reserve, unique_names, write_quoted, write_word},
};

/// Whether `s` is a `token68`: `1*( ALPHA / DIGIT / "-" / "." / "_" / "~" /
/// "+" / "/" ) *"="`.
fn is_token68(s: &[u8]) -> bool {
    let body = s.iter().take_while(|&&b| class::is_token68_char(b)).count();
    body > 0
        && s.get(body..)
            .is_some_and(|pad| pad.iter().all(|&b| b == b'='))
}

/// One `auth-param`: `token BWS "=" BWS ( token / quoted-string )`.
fn auth_param(e: &[u8]) -> Result<(&[u8], Word<'_>)> {
    let n = e.iter().take_while(|&&b| class::is_tchar(b)).count();
    if n == 0 {
        return Err(refused(e, 0, ErrorKind::NotToken));
    }
    let name = e.get(..n).unwrap_or(&[]);
    let mut i = n + skip_ows(e.get(n..).unwrap_or(&[]));
    if e.get(i) != Some(&b'=') {
        return Err(refused(e, i, ErrorKind::MissingValue));
    }
    i += 1;
    i += skip_ows(e.get(i..).unwrap_or(&[]));
    let (w, used) = parse_word(e.get(i..).unwrap_or(&[])).map_err(|x| match x.kind() {
        ErrorKind::Empty => refused(e, i, ErrorKind::MissingValue),
        _ => x.shifted(i),
    })?;
    if i + used != e.len() {
        return Err(refused(e, i + used, ErrorKind::TrailingData));
    }
    Ok((name, w))
}

fn refused(e: &[u8], at: usize, kind: ErrorKind) -> ParseError {
    match e.get(at) {
        Some(&b) if crate::scan::is_control(b) => ParseError::new(control_kind(b), at),
        _ => ParseError::new(kind, at),
    }
}

/// Whether element `e` is an `auth-param` (a token, optional whitespace,
/// then `=`), as opposed to the start of a challenge.
fn is_param_start(e: &[u8]) -> bool {
    let n = e.iter().take_while(|&&b| class::is_tchar(b)).count();
    n > 0 && e.get(n + skip_ows(e.get(n..).unwrap_or(&[]))) == Some(&b'=')
}

/// Comma-separated `auth-param`s, validated.
///
/// `Debug` prints the parameter names only: values can be secrets.
///
/// # Examples
///
/// ```
/// use parse_net::{auth, AuthPayload, Limits};
///
/// let c = auth::parse_credentials(b"Digest username=\"a\", realm=\"r\"", &Limits::DEFAULT)?;
/// let AuthPayload::Params(p) = c.payload() else { unreachable!() };
/// assert_eq!(p.len(), 2);
/// assert!(p.get("realm").is_some_and(|v| v.eq_bytes(b"r")));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthParams<'a> {
    text: &'a [u8],
    count: usize,
}

impl<'a> AuthParams<'a> {
    /// The parameters, in order.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{auth, AuthPayload, Limits};
    ///
    /// let c = auth::parse_credentials(b"Digest username=\"a\", nc=1", &Limits::DEFAULT)?;
    /// let AuthPayload::Params(p) = c.payload() else { unreachable!() };
    /// let names: Vec<&[u8]> = p.iter().map(|(n, _)| n).collect();
    /// assert_eq!(names, [&b"username"[..], b"nc"]);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = (&'a [u8], Word<'a>)> + use<'a> {
        list::parse(self.text, &Limits::DEFAULT.max_list_members(u16::MAX))
            .into_iter()
            .flat_map(|l| l.into_iter())
            .filter_map(|e| auth_param(e).ok())
    }

    /// The value of the parameter `name` (ASCII case-insensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{auth, AuthPayload, Limits};
    ///
    /// let c = auth::parse_credentials(b"Digest Realm=\"api\"", &Limits::DEFAULT)?;
    /// let AuthPayload::Params(p) = c.payload() else { unreachable!() };
    /// assert!(p.get("realm").is_some_and(|v| v.eq_bytes(b"api")));
    /// assert!(p.get("nonce").is_none());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Word<'a>> {
        self.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, v)| v)
    }

    /// The number of parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{auth, AuthPayload, Limits};
    ///
    /// let c = auth::parse_credentials(b"Digest a=1, b=2, c=3", &Limits::DEFAULT)?;
    /// let AuthPayload::Params(p) = c.payload() else { unreachable!() };
    /// assert_eq!(p.len(), 3);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether there are no parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{auth, AuthPayload, Limits};
    ///
    /// let c = auth::parse_credentials(b"Digest a=1", &Limits::DEFAULT)?;
    /// let AuthPayload::Params(p) = c.payload() else { unreachable!() };
    /// assert!(!p.is_empty());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl fmt::Debug for AuthParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthParams(")?;
        f.debug_list()
            .entries(
                self.iter()
                    .map(|(n, _)| core::str::from_utf8(n).unwrap_or("?")),
            )
            .finish()?;
        f.write_str(")")
    }
}

/// What follows the scheme of a credential or a challenge.
///
/// # Examples
///
/// ```
/// use parse_net::{auth, AuthPayload, Limits};
///
/// let l = Limits::DEFAULT;
/// assert_eq!(auth::parse_credentials(b"Negotiate", &l)?.payload(), AuthPayload::None);
/// assert_eq!(auth::parse_credentials(b"Bearer abc123", &l)?.payload(), AuthPayload::Token68(b"abc123"));
/// assert!(matches!(auth::parse_credentials(b"Digest a=b", &l)?.payload(), AuthPayload::Params(_)));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthPayload<'a> {
    /// Nothing.
    None,
    /// A `token68`, such as a bearer token or `Basic` base64 text.
    Token68(&'a [u8]),
    /// `auth-param`s.
    Params(AuthParams<'a>),
}

impl fmt::Debug for AuthPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthPayload::None => f.write_str("None"),
            AuthPayload::Token68(_) => f.write_str("Token68(..)"),
            AuthPayload::Params(p) => fmt::Debug::fmt(p, f),
        }
    }
}

/// Validated credentials (`Authorization`, `Proxy-Authorization`).
///
/// `Debug` prints the scheme only.
///
/// # Examples
///
/// ```
/// use parse_net::{auth, AuthPayload, Limits};
///
/// let c = auth::parse_credentials(b"Bearer abc123", &Limits::DEFAULT)?;
/// assert!(c.scheme_is("bearer"));
/// assert_eq!(c.payload(), AuthPayload::Token68(b"abc123"));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Credentials<'a> {
    scheme: &'a [u8],
    payload: AuthPayload<'a>,
}

impl<'a> Credentials<'a> {
    /// The scheme, as sent.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{auth, Limits};
    ///
    /// let c = auth::parse_credentials(b"Bearer abc123", &Limits::DEFAULT)?;
    /// assert_eq!(c.scheme(), b"Bearer");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn scheme(&self) -> &'a [u8] {
        self.scheme
    }

    /// Whether the scheme is `s` (ASCII case-insensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{auth, Limits};
    ///
    /// let c = auth::parse_credentials(b"BASIC dXNlcjpwYXNz", &Limits::DEFAULT)?;
    /// assert!(c.scheme_is("basic") && !c.scheme_is("bearer"));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn scheme_is(&self, s: &str) -> bool {
        self.scheme.eq_ignore_ascii_case(s.as_bytes())
    }

    /// The payload.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{auth, AuthPayload, Limits};
    ///
    /// let c = auth::parse_credentials(b"Basic dXNlcjpwYXNz", &Limits::DEFAULT)?;
    /// assert_eq!(c.payload(), AuthPayload::Token68(b"dXNlcjpwYXNz"));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn payload(&self) -> AuthPayload<'a> {
        self.payload
    }
}

impl fmt::Debug for Credentials<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("scheme", &core::str::from_utf8(self.scheme).unwrap_or("?"))
            .finish_non_exhaustive()
    }
}

/// Validates the `auth-param` list `text` (from `at` in the field) with no
/// repeated name, and counts it.
fn check_params(text: &[u8], at: usize, limits: &Limits) -> Result<usize> {
    let l = list::parse(text, limits).map_err(|e| e.shifted(at))?;
    let max = usize::from(limits.params).min(MAX_CHECKED_PARAMS);
    let (mut count, mut names) = (0usize, Names::new());
    for e in l.iter() {
        let rel = (e.as_ptr() as usize).saturating_sub(text.as_ptr() as usize);
        let off = at + rel;
        let (name, _) = auth_param(e).map_err(|x| x.shifted(off))?;
        count += 1;
        if count > max {
            return err(ErrorKind::TooManyMembers, off);
        }
        // A repeated name within one credential or challenge is refused
        // (RFC 9110 section 11.2); the name starts the element.
        if names.repeats(text, rel, name, class::is_tchar) {
            return err(ErrorKind::DuplicateParameter, off);
        }
    }
    Ok(count)
}

/// Parses `credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`.
///
/// One credential per field; parameter names may not repeat; OWS around
/// `=` in a parameter is accepted (BWS).
///
/// # Errors
///
/// [`ErrorKind::NotToken`] for the scheme or a parameter name;
/// [`ErrorKind::DuplicateParameter`]; [`ErrorKind::MissingValue`];
/// [`ErrorKind::TrailingData`] (for example a second credential); the
/// quoted-string and list errors.
///
/// # Examples
///
/// ```
/// use parse_net::{auth, Limits};
///
/// assert!(auth::parse_credentials(b"Digest a=b, a=c", &Limits::DEFAULT).is_err());
/// ```
pub fn parse_credentials<'a>(value: &'a [u8], limits: &Limits) -> Result<Credentials<'a>> {
    let lead = skip_ows(value);
    let v = trim_ows(value);
    let n = v.iter().take_while(|&&b| class::is_tchar(b)).count();
    if n == 0 {
        return Err(refused(v, 0, ErrorKind::NotToken).shifted(lead));
    }
    let scheme = v.get(..n).unwrap_or(&[]);
    let rest = v.get(n..).unwrap_or(&[]);
    if rest.is_empty() {
        return Ok(Credentials {
            scheme,
            payload: AuthPayload::None,
        });
    }
    let spaces = rest.iter().take_while(|&&b| b == b' ').count();
    if spaces == 0 {
        return Err(refused(v, n, ErrorKind::NotToken).shifted(lead));
    }
    let at = n + spaces;
    let body = v.get(at..).unwrap_or(&[]);
    if is_token68(body) {
        return Ok(Credentials {
            scheme,
            payload: AuthPayload::Token68(body),
        });
    }
    if !is_param_start(body) {
        // A token68 followed by more, or a second scheme.
        let t68 = body
            .iter()
            .take_while(|&&b| class::is_token68_char(b) || b == b'=')
            .count();
        return Err(refused(v, at + t68, ErrorKind::TrailingData).shifted(lead));
    }
    let count = check_params(body, lead + at, limits)?;
    Ok(Credentials {
        scheme,
        payload: AuthPayload::Params(AuthParams { text: body, count }),
    })
}

/// The `Bearer` token of an `Authorization` value (RFC 6750 section 2.1):
/// `Some(token)` when the scheme is `Bearer` (case-insensitive), `None` for
/// another scheme.
///
/// # Errors
///
/// [`ErrorKind::Empty`] for `Bearer` alone; [`ErrorKind::InvalidByte`] when
/// the payload is not a `b64token`; [`ErrorKind::TrailingData`]; the scheme
/// errors.
///
/// # Examples
///
/// ```
/// assert_eq!(parse_net::bearer(b"Bearer abc123")?, Some(&b"abc123"[..]));
/// assert_eq!(parse_net::bearer(b"Basic dXNlcjpwYXNz")?, None);
/// assert!(parse_net::bearer(b"Bearer").is_err());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn bearer(value: &[u8]) -> Result<Option<&[u8]>> {
    let c = parse_credentials(value, &Limits::DEFAULT)?;
    if !c.scheme_is("bearer") {
        return Ok(None);
    }
    match c.payload {
        AuthPayload::Token68(t) => Ok(Some(t)),
        AuthPayload::None => err(ErrorKind::Empty, value.len()),
        AuthPayload::Params(p) => {
            let at = (p.text.as_ptr() as usize).saturating_sub(value.as_ptr() as usize);
            err(ErrorKind::InvalidByte, at)
        }
    }
}

/// The base64 text of a `Basic` `Authorization` value (RFC 7617): `Some`
/// when the scheme is `Basic`, `None` for another scheme. The text is
/// checked (the base64 alphabet, padding only at the end, a length that is a
/// multiple of four) and not decoded.
///
/// # Errors
///
/// [`ErrorKind::InvalidBase64`]; [`ErrorKind::Empty`] for `Basic` alone;
/// the scheme errors.
///
/// # Examples
///
/// ```
/// assert_eq!(parse_net::basic(b"Basic dXNlcjpwYXNz")?, Some(&b"dXNlcjpwYXNz"[..]));
/// assert_eq!(parse_net::basic(b"Bearer abc123")?, None);
/// assert!(parse_net::basic(b"Basic YQ").is_err());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn basic(value: &[u8]) -> Result<Option<&[u8]>> {
    let c = parse_credentials(value, &Limits::DEFAULT)?;
    if !c.scheme_is("basic") {
        return Ok(None);
    }
    let t = match c.payload {
        AuthPayload::Token68(t) => t,
        AuthPayload::None => return err(ErrorKind::Empty, value.len()),
        AuthPayload::Params(p) => {
            let at = (p.text.as_ptr() as usize).saturating_sub(value.as_ptr() as usize);
            return err(ErrorKind::InvalidBase64, at);
        }
    };
    let at = (t.as_ptr() as usize).saturating_sub(value.as_ptr() as usize);
    let body = t.iter().take_while(|&&b| class::is_base64_char(b)).count();
    let pad = t.len() - body;
    if body < t.len() && t.get(body) != Some(&b'=') || pad > 2 || t.len() % 4 != 0 {
        return err(ErrorKind::InvalidBase64, at + body);
    }
    Ok(Some(t))
}

/// One challenge.
///
/// # Examples
///
/// ```
/// use parse_net::{auth, Limits};
///
/// let c = auth::parse_challenges(b"Bearer realm=\"api\", error=invalid_token", &Limits::DEFAULT)?;
/// let first = c.iter().next().expect("one challenge");
/// assert!(first.scheme_is("bearer"));
/// assert!(first.param("error").is_some_and(|v| v.eq_bytes(b"invalid_token")));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Challenge<'a> {
    scheme: &'a [u8],
    payload: AuthPayload<'a>,
}

impl<'a> Challenge<'a> {
    /// The scheme, as sent.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{auth, Limits};
    ///
    /// let c = auth::parse_challenges(b"Basic realm=\"x\", Negotiate", &Limits::DEFAULT)?;
    /// let schemes: Vec<&[u8]> = c.iter().map(|x| x.scheme()).collect();
    /// assert_eq!(schemes, [&b"Basic"[..], b"Negotiate"]);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn scheme(&self) -> &'a [u8] {
        self.scheme
    }

    /// Whether the scheme is `s` (ASCII case-insensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{auth, Limits};
    ///
    /// let c = auth::parse_challenges(b"NEGOTIATE", &Limits::DEFAULT)?;
    /// assert!(c.iter().next().is_some_and(|x| x.scheme_is("negotiate")));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn scheme_is(&self, s: &str) -> bool {
        self.scheme.eq_ignore_ascii_case(s.as_bytes())
    }

    /// The payload.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{auth, AuthPayload, Limits};
    ///
    /// let c = auth::parse_challenges(b"Negotiate abc==", &Limits::DEFAULT)?;
    /// let first = c.iter().next().expect("one challenge");
    /// assert_eq!(first.payload(), AuthPayload::Token68(b"abc=="));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn payload(&self) -> AuthPayload<'a> {
        self.payload
    }

    /// The parameter `name` (`realm`, `error`, `scope`, ...).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{auth, Limits};
    ///
    /// let c = auth::parse_challenges(b"Basic realm=\"simple\", charset=UTF-8", &Limits::DEFAULT)?;
    /// let first = c.iter().next().expect("one challenge");
    /// assert!(first.param("Realm").is_some_and(|v| v.eq_bytes(b"simple")));
    /// assert!(first.param("scope").is_none());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn param(&self, name: &str) -> Option<Word<'a>> {
        match self.payload {
            AuthPayload::Params(p) => p.get(name),
            _ => None,
        }
    }
}

/// Validated challenges.
///
/// # Examples
///
/// ```
/// use parse_net::{auth, Limits};
///
/// let c = auth::parse_challenges(b"Basic realm=\"a\", Bearer", &Limits::DEFAULT)?;
/// assert_eq!(c.len(), 2);
/// assert!(c.iter().any(|x| x.scheme_is("bearer")));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Challenges<'a> {
    list: list::List<'a>,
    value: &'a [u8],
    count: usize,
}

impl<'a> Challenges<'a> {
    /// The challenges, in order.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{auth, Limits};
    ///
    /// let c = auth::parse_challenges(b"Basic realm=\"a\", Bearer", &Limits::DEFAULT)?;
    /// let mut it = c.iter();
    /// assert!(it.next().is_some_and(|x| x.scheme_is("basic")));
    /// assert!(it.next().is_some_and(|x| x.scheme_is("bearer")));
    /// assert!(it.next().is_none());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn iter(&self) -> ChallengeIter<'a> {
        ChallengeIter {
            value: self.value,
            elements: self.list.iter().peekable(),
        }
    }

    /// The number of challenges.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{auth, Limits};
    ///
    /// let c = auth::parse_challenges(b"A, B realm=x, C abc==", &Limits::DEFAULT)?;
    /// assert_eq!(c.len(), 3);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether there are no challenges.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{auth, Limits};
    ///
    /// assert!(auth::parse_challenges(b"", &Limits::DEFAULT)?.is_empty());
    /// assert!(!auth::parse_challenges(b"Basic", &Limits::DEFAULT)?.is_empty());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// The challenges of a validated value.
///
/// # Examples
///
/// ```
/// use parse_net::{auth::{self, ChallengeIter}, Limits};
///
/// let c = auth::parse_challenges(b"Negotiate, Basic realm=\"x\"", &Limits::DEFAULT)?;
/// let it: ChallengeIter<'_> = c.iter();
/// assert_eq!(it.count(), 2);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Debug)]
pub struct ChallengeIter<'a> {
    value: &'a [u8],
    elements: Peekable<list::Elements<'a>>,
}

/// The start of challenge element `e`: its scheme and what follows.
fn challenge_start(e: &[u8]) -> (&[u8], &[u8]) {
    let n = e.iter().take_while(|&&b| class::is_tchar(b)).count();
    let scheme = e.get(..n).unwrap_or(&[]);
    let rest = e.get(n..).unwrap_or(&[]);
    let rest = rest
        .get(rest.iter().take_while(|&&b| b == b' ').count()..)
        .unwrap_or(&[]);
    (scheme, rest)
}

impl<'a> Iterator for ChallengeIter<'a> {
    type Item = Challenge<'a>;

    fn next(&mut self) -> Option<Challenge<'a>> {
        let e = self.elements.next()?;
        let (scheme, rest) = challenge_start(e);
        if rest.is_empty() {
            return Some(Challenge {
                scheme,
                payload: AuthPayload::None,
            });
        }
        if is_token68(rest) {
            return Some(Challenge {
                scheme,
                payload: AuthPayload::Token68(rest),
            });
        }
        // The first parameter is in this element; the rest follow it as
        // separate elements until the next challenge starts.
        let start = (rest.as_ptr() as usize).saturating_sub(self.value.as_ptr() as usize);
        let mut end = start + rest.len();
        let mut count = 1usize;
        while let Some(next) = self.elements.peek() {
            if !is_param_start(next) {
                break;
            }
            end =
                (next.as_ptr() as usize).saturating_sub(self.value.as_ptr() as usize) + next.len();
            count += 1;
            let _skipped = self.elements.next();
        }
        let text = self.value.get(start..end).unwrap_or(&[]);
        Some(Challenge {
            scheme,
            payload: AuthPayload::Params(AuthParams { text, count }),
        })
    }
}

/// Parses `WWW-Authenticate` or `Proxy-Authenticate`: `#challenge`.
///
/// A challenge's own parameters are comma-separated too, so where one
/// challenge ends is decided element by element: a token followed by `=` is
/// a parameter of the current challenge; a token alone, or a token and
/// `1*SP` before a `token68` or a parameter, starts a new one. A parameter
/// name may not repeat within one challenge (RFC 9110 section 11.2).
///
/// # Errors
///
/// [`ErrorKind::DuplicateParameter`]; [`ErrorKind::NotToken`];
/// [`ErrorKind::ExpectedSeparator`] for a parameter before any challenge;
/// [`ErrorKind::TrailingData`]; the list and quoted-string errors.
///
/// # Examples
///
/// ```
/// use parse_net::{auth, Limits};
///
/// let c = auth::parse_challenges(
///     b"Newauth realm=\"apps\", type=1, title=\"Login to \\\"apps\\\"\", Basic realm=\"simple\"",
///     &Limits::DEFAULT)?;
/// let all: Vec<_> = c.iter().collect();
/// assert_eq!(all.len(), 2);
/// assert!(all[0].param("type").is_some_and(|v| v.eq_bytes(b"1")));
/// assert!(all[1].scheme_is("basic"));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_challenges<'a>(value: &'a [u8], limits: &Limits) -> Result<Challenges<'a>> {
    let l = list::parse(value, limits)?;
    let mut count = 0usize;
    let mut elements = l.iter().peekable();
    while let Some(e) = elements.next() {
        let at = (e.as_ptr() as usize).saturating_sub(value.as_ptr() as usize);
        if is_param_start(e) {
            return err(ErrorKind::ExpectedSeparator, at);
        }
        let n = e.iter().take_while(|&&b| class::is_tchar(b)).count();
        if n == 0 {
            return Err(refused(e, 0, ErrorKind::NotToken).shifted(at));
        }
        let (_, rest) = challenge_start(e);
        if e.get(n).is_some_and(|&b| b != b' ') {
            return Err(refused(e, n, ErrorKind::NotToken).shifted(at));
        }
        count += 1;
        if rest.is_empty() || is_token68(rest) {
            continue;
        }
        if !is_param_start(rest) {
            let off = e.len() - rest.len();
            return Err(refused(e, off, ErrorKind::TrailingData).shifted(at));
        }
        // This challenge's parameters: the rest of this element and every
        // following parameter element.
        let start = at + (e.len() - rest.len());
        let mut end = at + e.len();
        while let Some(next) = elements.peek() {
            if !is_param_start(next) {
                break;
            }
            end = (next.as_ptr() as usize).saturating_sub(value.as_ptr() as usize) + next.len();
            let _skipped = elements.next();
        }
        let _params = check_params(value.get(start..end).unwrap_or(&[]), start, limits)?;
    }
    Ok(Challenges {
        list: l,
        value,
        count,
    })
}

fn put_challenge(
    scheme: &str,
    params: &[(&str, &str)],
    out: &mut impl Sink,
) -> core::result::Result<(), WriteError> {
    out.put(scheme.as_bytes())?;
    for (i, (name, value)) in params.iter().enumerate() {
        out.put(if i == 0 { b" " } else { b", " })?;
        out.put(name.as_bytes())?;
        out.put(b"=")?;
        if name.eq_ignore_ascii_case("realm") {
            write_quoted(value.as_bytes(), out)?;
        } else {
            write_word(value.as_bytes(), out)?;
        }
    }
    Ok(())
}

/// Writes a challenge with parameters: `Bearer realm="api", error="invalid_token"`.
/// `realm` is always quoted (RFC 9110 section 11.5); other values are tokens
/// when they can be.
///
/// # Errors
///
/// [`WriteError::NotToken`] for the scheme or a name;
/// [`WriteError::DuplicateName`] for a name given twice (RFC 9110 section
/// 11.2 allows each once); [`WriteError::Forbidden`] for a control byte in a
/// value; [`WriteError::Full`] (nothing written when the sink reports its
/// room).
///
/// # Examples
///
/// ```
/// use parse_net::{auth, SliceSink};
///
/// let mut buf = [0u8; 64];
/// let mut out = SliceSink::new(&mut buf);
/// auth::write_challenge("Bearer", &[("realm", "api"), ("error", "invalid_token")], &mut out).expect("room");
/// assert_eq!(out.written(), b"Bearer realm=\"api\", error=invalid_token");
/// ```
pub fn write_challenge(
    scheme: &str,
    params: &[(&str, &str)],
    out: &mut impl Sink,
) -> core::result::Result<(), WriteError> {
    if !is_token(scheme.as_bytes()) || params.iter().any(|(n, _)| !is_token(n.as_bytes())) {
        return Err(WriteError::NotToken);
    }
    unique_names(params)?;
    let mut count = CountSink::new();
    put_challenge(scheme, params, &mut count)?;
    reserve(out, count.count())?;
    put_challenge(scheme, params, out)
}

/// Writes a challenge with a `token68`: `Negotiate <token68>`.
///
/// # Errors
///
/// [`WriteError::NotToken`] for the scheme; [`WriteError::Forbidden`] when
/// `token68` is not a `token68`; [`WriteError::Full`].
///
/// # Examples
///
/// ```
/// use parse_net::{auth, SliceSink};
///
/// let mut buf = [0u8; 32];
/// let mut out = SliceSink::new(&mut buf);
/// auth::write_challenge_token68("Negotiate", b"YIIB==", &mut out).expect("room");
/// assert_eq!(out.written(), b"Negotiate YIIB==");
/// ```
pub fn write_challenge_token68(
    scheme: &str,
    token68: &[u8],
    out: &mut impl Sink,
) -> core::result::Result<(), WriteError> {
    if !is_token(scheme.as_bytes()) {
        return Err(WriteError::NotToken);
    }
    if !is_token68(token68) {
        let at = token68
            .iter()
            .position(|&b| !(class::is_token68_char(b) || b == b'='))
            .unwrap_or(0);
        return Err(WriteError::forbidden(at));
    }
    reserve(out, scheme.len() + 1 + token68.len())?;
    out.put(scheme.as_bytes())?;
    out.put(b" ")?;
    out.put(token68)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{format, vec::Vec};

    use super::*;

    #[test]
    fn test_bearer_cases() {
        assert_eq!(bearer(b"Bearer abc").unwrap(), Some(&b"abc"[..]));
        assert_eq!(bearer(b"bearer abc").unwrap(), Some(&b"abc"[..]));
        assert_eq!(bearer(b"Bearer  abc").unwrap(), Some(&b"abc"[..]));
        assert_eq!(bearer(b"Bearer abc==").unwrap(), Some(&b"abc=="[..]));
        assert_eq!(bearer(b"Bearer").unwrap_err().kind(), ErrorKind::Empty);
        assert_eq!(
            bearer(b"Bearer abc def").unwrap_err().kind(),
            ErrorKind::TrailingData
        );
        assert_eq!(
            bearer(b"Bearer a=b").unwrap_err().kind(),
            ErrorKind::InvalidByte
        );
        assert_eq!(
            bearer(b"Bearer\tabc").unwrap_err().kind(),
            ErrorKind::NotToken
        );
        assert_eq!(bearer(b"").unwrap_err().kind(), ErrorKind::NotToken);
        assert_eq!(bearer(b"Digest a=b").unwrap(), None);
    }

    #[test]
    fn test_basic_cases() {
        assert_eq!(
            basic(b"Basic dXNlcjpwYXNz").unwrap(),
            Some(&b"dXNlcjpwYXNz"[..])
        );
        assert_eq!(basic(b"Basic YQ==").unwrap(), Some(&b"YQ=="[..]));
        assert_eq!(basic(b"Basic").unwrap_err().kind(), ErrorKind::Empty);
        assert_eq!(
            basic(b"Basic YQ").unwrap_err().kind(),
            ErrorKind::InvalidBase64
        );
        assert_eq!(
            basic(b"Basic a-b_").unwrap_err().kind(),
            ErrorKind::InvalidBase64
        );
        assert_eq!(
            basic(b"Basic YQ===").unwrap_err().kind(),
            ErrorKind::InvalidBase64
        );
        assert_eq!(basic(b"Bearer x").unwrap(), None);
    }

    #[test]
    fn test_credentials_params_and_duplicates() {
        let l = Limits::DEFAULT;
        let c = parse_credentials(b"Digest username = \"a\" , realm=r, ", &l).unwrap();
        let AuthPayload::Params(p) = c.payload() else {
            panic!("params")
        };
        assert_eq!(p.len(), 2);
        assert!(p.get("USERNAME").unwrap().eq_bytes(b"a"));
        assert_eq!(
            parse_credentials(b"Digest a=b, A=c", &l)
                .unwrap_err()
                .kind(),
            ErrorKind::DuplicateParameter
        );
        assert_eq!(
            parse_credentials(b"Negotiate token68===", &l)
                .unwrap()
                .payload(),
            AuthPayload::Token68(b"token68===")
        );
        assert_eq!(
            parse_credentials(b"Digest a", &l).unwrap().payload(),
            AuthPayload::Token68(b"a")
        );
        assert_eq!(
            parse_credentials(b"Digest a b", &l).unwrap_err().kind(),
            ErrorKind::TrailingData
        );
        // `a=` is a token68 with padding; `a=, b` is a parameter with no value.
        assert_eq!(
            parse_credentials(b"Digest a=", &l).unwrap().payload(),
            AuthPayload::Token68(b"a=")
        );
        assert_eq!(
            parse_credentials(b"Digest a=, b=1", &l).unwrap_err().kind(),
            ErrorKind::MissingValue
        );
        assert_eq!(
            parse_credentials(b"Digest a=\"x", &l).unwrap_err().kind(),
            ErrorKind::UnterminatedQuote
        );
    }

    #[test]
    fn test_credentials_debug_redacted() {
        let c = parse_credentials(b"Bearer s3cr3t-token", &Limits::DEFAULT).unwrap();
        let d = format!("{c:?} {:?}", c.payload());
        assert!(!d.contains("s3cr3t"));
        let p = parse_credentials(b"Digest response=\"s3cr3t\"", &Limits::DEFAULT).unwrap();
        let d = format!("{:?}", p.payload());
        assert_eq!(d, "AuthParams([\"response\"])");
    }

    #[test]
    fn test_challenges_rfc_examples() {
        let l = Limits::DEFAULT;
        let names = |v: &[u8]| -> Vec<Vec<u8>> {
            parse_challenges(v, &l)
                .unwrap()
                .iter()
                .map(|c| c.scheme().to_vec())
                .collect()
        };
        assert_eq!(
            names(b"Basic realm=\"a\", Bearer"),
            [b"Basic".to_vec(), b"Bearer".to_vec()]
        );
        let c = parse_challenges(b"Bearer realm=\"a\", error=\"invalid_token\"", &l).unwrap();
        let one: Vec<_> = c.iter().collect();
        assert_eq!(one.len(), 1);
        assert!(one[0].param("error").unwrap().eq_bytes(b"invalid_token"));
        assert_eq!(
            names(b"Negotiate abc==, Basic realm=x"),
            [b"Negotiate".to_vec(), b"Basic".to_vec()]
        );
        assert_eq!(
            names(b"A, , B, ,C"),
            [b"A".to_vec(), b"B".to_vec(), b"C".to_vec()]
        );
        let t68 = parse_challenges(b"Negotiate abc==", &l).unwrap();
        assert_eq!(
            t68.iter().next().unwrap().payload(),
            AuthPayload::Token68(b"abc==")
        );
    }

    #[test]
    fn test_challenge_refusals() {
        let l = Limits::DEFAULT;
        let k = |v: &[u8]| parse_challenges(v, &l).unwrap_err().kind();
        assert_eq!(k(b"Basic realm=a, realm=b"), ErrorKind::DuplicateParameter);
        assert_eq!(k(b"realm=a"), ErrorKind::ExpectedSeparator);
        assert_eq!(k(b"Basic\trealm=a"), ErrorKind::NotToken);
        assert_eq!(k(b"Basic abc def"), ErrorKind::TrailingData);
        assert!(parse_challenges(b"Basic realm=a, Digest realm=b", &l).is_ok());
    }

    #[test]
    fn test_challenge_writers_round_trip() {
        let mut buf = [0u8; 128];
        let mut out = crate::SliceSink::new(&mut buf);
        write_challenge(
            "Bearer",
            &[("realm", "api"), ("scope", "read write")],
            &mut out,
        )
        .unwrap();
        let c = parse_challenges(out.written(), &Limits::DEFAULT).unwrap();
        let first = c.iter().next().unwrap();
        assert!(first.param("realm").unwrap().eq_bytes(b"api"));
        assert!(first.param("scope").unwrap().eq_bytes(b"read write"));
        assert_eq!(
            write_challenge("Bad scheme", &[], &mut out),
            Err(WriteError::NotToken)
        );
        assert_eq!(
            write_challenge("Basic", &[("realm", "a"), ("Realm", "b")], &mut out),
            Err(WriteError::DuplicateName)
        );
        assert_eq!(
            write_challenge("Basic", &[("realm", "a\r\n")], &mut out),
            Err(WriteError::Forbidden { at: 1 })
        );
        assert_eq!(
            write_challenge_token68("Negotiate", b"a b", &mut out),
            Err(WriteError::Forbidden { at: 1 })
        );
    }
}
