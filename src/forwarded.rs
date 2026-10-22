//! `Forwarded` (RFC 7239) and the de facto `X-Forwarded-For`,
//! `X-Forwarded-Proto`, and `X-Forwarded-Host`, with client-address
//! resolution through trusted proxies.
//!
//! The leftmost `X-Forwarded-For` address is whatever the client typed; only
//! addresses appended by proxies you trust mean anything. [`client_address`]
//! ignores the header unless the connection's peer is trusted, walks the
//! chain from the right, and stops at the first address it cannot trust. A
//! malformed chain fails closed: use the peer address.
//!
//! # Examples
//!
//! ```
//! use core::net::IpAddr;
//! use parse_net::{self as pn, ClientAddress, ForwardedSource};
//!
//! let proxy: IpAddr = "10.0.0.2".parse()?;
//! let inner: IpAddr = "10.0.0.1".parse()?;
//! let trusted = |a: IpAddr| a == proxy || a == inner;
//! let xff: [&[u8]; 1] = [b"203.0.113.9, 198.51.100.7, 10.0.0.1"];
//! let ip = pn::client_address(proxy, ForwardedSource::XForwardedFor(&xff), &trusted, 16)?;
//! assert_eq!(ip, ClientAddress::Forwarded { addr: "198.51.100.7".parse()?, hops: 2 });
//!
//! // The same header from an untrusted peer is ignored entirely.
//! let stranger: IpAddr = "192.0.2.1".parse()?;
//! assert_eq!(pn::client_address(stranger, ForwardedSource::XForwardedFor(&xff), &trusted, 16)?,
//!            ClientAddress::Peer(stranger));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use core::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use crate::{
    class,
    error::{ErrorKind, ParseError, Result, err},
    host::{HostPort, host_port},
    limits::Limits,
    list,
    scan::control_kind,
    text::{Word, parse_word, skip_ows, trim_ows},
};

/// Decides whether an address belongs to a proxy you trust.
///
/// Implemented for every `Fn(IpAddr) -> bool`; a deployment's CIDR sets
/// (net-io, bouncer-io configuration) implement it directly.
pub trait Trust {
    /// Whether `addr` is a trusted proxy.
    fn is_trusted(&self, addr: IpAddr) -> bool;
}

impl<F: Fn(IpAddr) -> bool> Trust for F {
    fn is_trusted(&self, addr: IpAddr) -> bool {
        self(addr)
    }
}

/// Which header the deployment reads the chain from: every field line of
/// it, in order. The two are never merged (merging is a parser
/// differential: two proxies could disagree on the order).
#[derive(Clone, Copy, Debug)]
pub enum ForwardedSource<'a> {
    /// `Forwarded` field lines.
    Forwarded(&'a [&'a [u8]]),
    /// `X-Forwarded-For` field lines.
    XForwardedFor(&'a [&'a [u8]]),
}

/// The client address a request is attributed to.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClientAddress {
    /// The connection's peer: it is not a trusted proxy (its header was not
    /// read), or it is a trusted proxy that forwarded no chain.
    Peer(IpAddr),
    /// An address from the chain, found after walking `hops` elements from
    /// the right.
    Forwarded {
        /// The client address.
        addr: IpAddr,
        /// The elements walked, the returned one included.
        hops: u8,
    },
    /// The walk reached `unknown`, an obfuscated identifier, or an element
    /// without `for` after `hops` elements: nothing to its left can be
    /// trusted.
    Unknown {
        /// The elements walked, the unknown one included.
        hops: u8,
    },
}

/// A node port: a number or an obfuscated identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NodePort<'a> {
    /// A port number.
    Number(u16),
    /// An obfuscated port (`_` and letters, digits, `.`, `_`, `-`).
    Obfuscated(&'a [u8]),
}

/// A `for` or `by` node (RFC 7239 section 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Node<'a> {
    /// An IP address.
    Addr(IpAddr, Option<NodePort<'a>>),
    /// `unknown`.
    Unknown(Option<NodePort<'a>>),
    /// An obfuscated identifier.
    Obfuscated(&'a [u8], Option<NodePort<'a>>),
}

/// The protocol a request arrived over at the proxy.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Proto {
    /// `http`.
    Http,
    /// `https`.
    Https,
}

/// One `Forwarded` element.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Element<'a> {
    /// `for=`: the client of this hop.
    pub for_: Option<Node<'a>>,
    /// `by=`: the proxy's receiving interface.
    pub by: Option<Node<'a>>,
    /// `host=`: the `Host` the proxy received.
    pub host: Option<HostPort<'a>>,
    /// `proto=`.
    pub proto: Option<Proto>,
}

/// `"_" 1*( ALPHA / DIGIT / "." / "_" / "-" )`.
fn is_obfuscated(s: &[u8]) -> bool {
    matches!(s, [b'_', rest @ ..] if !rest.is_empty()
        && rest.iter().all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
}

fn node_port(s: &[u8]) -> Option<NodePort<'_>> {
    if is_obfuscated(s) {
        return Some(NodePort::Obfuscated(s));
    }
    if s.is_empty() || s.len() > 5 || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let n = s.iter().fold(0u32, |n, &d| n * 10 + u32::from(d - b'0'));
    u16::try_from(n).ok().map(NodePort::Number)
}

/// An IP literal: dotted-decimal IPv4 (no leading zeros) or IPv6.
fn ip(text: &[u8], v6: bool) -> Option<IpAddr> {
    let t = core::str::from_utf8(text).ok()?;
    if v6 {
        Ipv6Addr::from_str(t).ok().map(IpAddr::V6)
    } else {
        // `core` refuses leading zeros, so `01.2.3.4` cannot pass.
        Ipv4Addr::from_str(t).ok().map(IpAddr::V4)
    }
}

/// Parses a node value (already unquoted).
fn node(v: &[u8]) -> Result<Node<'_>> {
    let (name, rest) = if v.first() == Some(&b'[') {
        match v.iter().position(|&b| b == b']') {
            Some(close) => (
                v.get(..=close).unwrap_or(&[]),
                v.get(close + 1..).unwrap_or(&[]),
            ),
            None => return err(ErrorKind::InvalidAddress, 0),
        }
    } else {
        match v.iter().position(|&b| b == b':') {
            Some(c) => (v.get(..c).unwrap_or(&[]), v.get(c..).unwrap_or(&[])),
            None => (v, &[][..]),
        }
    };
    let port = match rest.split_first() {
        None => None,
        Some((b':', p)) => match node_port(p) {
            Some(p) => Some(p),
            None => return err(ErrorKind::InvalidPort, name.len() + 1),
        },
        Some(_) => return err(ErrorKind::InvalidAddress, name.len()),
    };
    if name == b"unknown" {
        return Ok(Node::Unknown(port));
    }
    if is_obfuscated(name) {
        return Ok(Node::Obfuscated(name, port));
    }
    let addr = match name {
        [b'[', inner @ .., b']'] => ip(inner, true),
        _ => ip(name, false),
    };
    match addr {
        Some(a) => Ok(Node::Addr(a, port)),
        None => err(ErrorKind::InvalidAddress, 0),
    }
}

/// Parses one `forwarded-element`: `[ pair ] *( ";" [ pair ] )`, OWS around
/// `;` accepted, names case-insensitive, a known name at most once.
fn element(e: &[u8]) -> Result<Element<'_>> {
    let mut out = Element {
        for_: None,
        by: None,
        host: None,
        proto: None,
    };
    let mut seen = [false; 4];
    let mut i = 0usize;
    loop {
        i += skip_ows(e.get(i..).unwrap_or(&[]));
        match e.get(i) {
            None => return Ok(out),
            Some(b';') => {
                i += 1;
                continue;
            }
            Some(_) => {}
        }
        let name_len = e
            .get(i..)
            .unwrap_or(&[])
            .iter()
            .take_while(|&&b| class::is_tchar(b))
            .count();
        if name_len == 0 {
            return Err(refused(e, i, ErrorKind::NotToken));
        }
        let name_at = i;
        let name = e.get(i..i + name_len).unwrap_or(&[]);
        i += name_len;
        if e.get(i) != Some(&b'=') {
            return Err(refused(e, i, ErrorKind::MissingValue));
        }
        i += 1;
        let (w, used) = parse_word(e.get(i..).unwrap_or(&[])).map_err(|x| match x.kind() {
            ErrorKind::Empty => refused(e, i, ErrorKind::InvalidByte),
            _ => x.shifted(i),
        })?;
        // Node, host, and proto values never need quoted pairs; refusing them
        // keeps every view borrowed from the input.
        let Some(v) = w.as_plain() else {
            return err(ErrorKind::InvalidQuotedPair, i);
        };
        let value_at = i + usize::from(matches!(w, Word::Quoted(_)));
        i += used;
        let slot = [&b"for"[..], b"by", b"host", b"proto"]
            .iter()
            .position(|k| name.eq_ignore_ascii_case(k));
        if let Some(s) = slot {
            if seen.get(s).copied().unwrap_or(false) {
                return err(ErrorKind::DuplicateParameter, name_at);
            }
            if let Some(flag) = seen.get_mut(s) {
                *flag = true;
            }
        }
        match slot {
            Some(0) => out.for_ = Some(node(v).map_err(|x| x.shifted(value_at))?),
            Some(1) => out.by = Some(node(v).map_err(|x| x.shifted(value_at))?),
            Some(2) => out.host = Some(host_port(v).map_err(|x| x.shifted(value_at))?),
            Some(3) => {
                out.proto = Some(if v.eq_ignore_ascii_case(b"http") {
                    Proto::Http
                } else if v.eq_ignore_ascii_case(b"https") {
                    Proto::Https
                } else {
                    return err(ErrorKind::Malformed, value_at);
                });
            }
            _ => {}
        }
        i += skip_ows(e.get(i..).unwrap_or(&[]));
        match e.get(i) {
            None => return Ok(out),
            Some(b';') => i += 1,
            Some(_) => return Err(refused(e, i, ErrorKind::ExpectedSeparator)),
        }
    }
}

fn refused(e: &[u8], at: usize, kind: ErrorKind) -> ParseError {
    match e.get(at) {
        Some(&b) if crate::scan::is_control(b) => ParseError::new(control_kind(b), at),
        _ => ParseError::new(kind, at),
    }
}

/// Validated `Forwarded` field lines.
#[derive(Clone, Copy, Debug)]
pub struct ForwardedElements<'a> {
    lines: &'a [&'a [u8]],
    count: usize,
}

impl<'a> ForwardedElements<'a> {
    /// The elements, left to right across every line.
    pub fn iter(&self) -> impl Iterator<Item = Element<'a>> + use<'a> {
        let lines = self.lines;
        lines
            .iter()
            .filter_map(|line| list::parse(line, &Limits::DEFAULT).ok())
            .flat_map(|l| l.into_iter())
            .filter_map(|e| element(e).ok())
    }

    /// The number of elements.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether there are no elements.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// Parses every `Forwarded` field line (RFC 7239 section 4).
///
/// IPv6 must be quoted and bracketed (`for="[2001:db8::1]:4711"`); an
/// unquoted IPv6 is refused because `:` and `[` are not token characters.
/// Values containing quoted pairs are refused. `proto` must be `http` or
/// `https`.
///
/// # Errors
///
/// [`ErrorKind::DuplicateParameter`] (a known name twice in one element);
/// [`ErrorKind::InvalidAddress`], [`ErrorKind::InvalidPort`],
/// [`ErrorKind::InvalidHost`]; [`ErrorKind::Malformed`] for another `proto`;
/// [`ErrorKind::TooManyHops`] beyond [`Limits::max_hops`]; the list and
/// token errors, with [`ParseError::line`] set.
///
/// # Examples
///
/// ```
/// use parse_net::{forwarded, Limits};
///
/// let lines: [&[u8]; 1] = [b"for=192.0.2.60;proto=http;by=203.0.113.43, for=\"[2001:db8:cafe::17]:4711\""];
/// let elems: Vec<_> = forwarded::parse(&lines, &Limits::DEFAULT)?.iter().collect();
/// assert_eq!(elems.len(), 2);
/// assert!(forwarded::parse(&[&b"for=2001:db8::1"[..]], &Limits::DEFAULT).is_err());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse<'a>(lines: &'a [&'a [u8]], limits: &Limits) -> Result<ForwardedElements<'a>> {
    let mut count = 0usize;
    for (n, line) in lines.iter().enumerate() {
        let l = list::parse(line, limits).map_err(|e| e.on_line(n))?;
        for e in l.iter() {
            let at = (e.as_ptr() as usize).saturating_sub(line.as_ptr() as usize);
            element(e)
                .map(|_| ())
                .map_err(|x| x.shifted(at).on_line(n))?;
            count += 1;
            if count > usize::from(limits.hops) {
                return Err(ParseError::new(ErrorKind::TooManyHops, at).on_line(n));
            }
        }
    }
    Ok(ForwardedElements { lines, count })
}

/// One `X-Forwarded-For` member: an IPv4 or IPv6 address, IPv6 optionally
/// bracketed, with an optional port after IPv4 or bracketed IPv6.
fn xff_member(m: &[u8]) -> Option<(IpAddr, Option<u16>)> {
    let port = |p: &[u8]| -> Option<Option<u16>> {
        match node_port(p)? {
            NodePort::Number(n) => Some(Some(n)),
            NodePort::Obfuscated(_) => None,
        }
    };
    if let [b'[', ..] = m {
        let close = m.iter().position(|&b| b == b']')?;
        let a = ip(m.get(1..close)?, true)?;
        return match m.get(close + 1..)? {
            [] => Some((a, None)),
            [b':', p @ ..] => Some((a, port(p)?)),
            _ => None,
        };
    }
    if let Some(a) = ip(m, true) {
        return Some((a, None));
    }
    match m.iter().position(|&b| b == b':') {
        Some(c) => Some((ip(m.get(..c)?, false)?, port(m.get(c + 1..)?)?)),
        None => Some((ip(m, false)?, None)),
    }
}

/// The members of one `X-Forwarded-For` line, refusing empty members.
fn xff_line(line: &[u8]) -> impl Iterator<Item = &[u8]> {
    line.split(|&b| b == b',').map(trim_ows)
}

/// A validated `X-Forwarded-For` chain.
#[derive(Clone, Copy, Debug)]
pub struct XffChain<'a> {
    lines: &'a [&'a [u8]],
    count: usize,
}

impl<'a> XffChain<'a> {
    /// The addresses and ports, left to right across every line.
    pub fn iter(&self) -> impl Iterator<Item = (IpAddr, Option<u16>)> + use<'a> {
        self.lines
            .iter()
            .flat_map(|line| xff_line(line))
            .filter_map(xff_member)
    }

    /// The number of addresses.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether there are no addresses.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// Parses every `X-Forwarded-For` field line.
///
/// There is no RFC: the de facto grammar accepted is comma-separated IPv4
/// and IPv6 literals with OWS, brackets optional around IPv6, and an
/// optional `:port` after IPv4 or bracketed IPv6. Anything else, an empty
/// member included, is refused (D-016).
///
/// # Errors
///
/// [`ErrorKind::Malformed`]; [`ErrorKind::TooManyHops`] beyond
/// [`Limits::max_hops`]; each with [`ParseError::line`] set.
///
/// # Examples
///
/// ```
/// use parse_net::{forwarded::parse_x_forwarded_for, Limits};
///
/// let lines: [&[u8]; 2] = [b"203.0.113.9:4711, [2001:db8::1]:443", b"2001:db8::2"];
/// assert_eq!(parse_x_forwarded_for(&lines, &Limits::DEFAULT)?.len(), 3);
/// assert!(parse_x_forwarded_for(&[&b"1.2.3.4, , 5.6.7.8"[..]], &Limits::DEFAULT).is_err());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_x_forwarded_for<'a>(lines: &'a [&'a [u8]], limits: &Limits) -> Result<XffChain<'a>> {
    let mut count = 0usize;
    for (n, line) in lines.iter().enumerate() {
        crate::scan::check_field_value(line).map_err(|e| e.on_line(n))?;
        for m in xff_line(line) {
            let at = (m.as_ptr() as usize).saturating_sub(line.as_ptr() as usize);
            if xff_member(m).is_none() {
                return Err(ParseError::new(ErrorKind::Malformed, at).on_line(n));
            }
            count += 1;
            if count > usize::from(limits.hops) {
                return Err(ParseError::new(ErrorKind::TooManyHops, at).on_line(n));
            }
        }
    }
    Ok(XffChain { lines, count })
}

/// Parses `X-Forwarded-Proto`: `http` or `https`, case-insensitive; a
/// comma list only when every member is the same.
///
/// # Errors
///
/// [`ErrorKind::Malformed`].
///
/// # Examples
///
/// ```
/// use parse_net::forwarded::{parse_x_forwarded_proto, Proto};
///
/// assert_eq!(parse_x_forwarded_proto(b"HTTPS")?, Proto::Https);
/// assert!(parse_x_forwarded_proto(b"https, http").is_err());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_x_forwarded_proto(value: &[u8]) -> Result<Proto> {
    let mut found: Option<Proto> = None;
    for m in value.split(|&b| b == b',') {
        let at = (m.as_ptr() as usize).saturating_sub(value.as_ptr() as usize);
        let t = trim_ows(m);
        let p = if t.eq_ignore_ascii_case(b"http") {
            Proto::Http
        } else if t.eq_ignore_ascii_case(b"https") {
            Proto::Https
        } else {
            return err(ErrorKind::Malformed, at);
        };
        if found.is_some_and(|f| f != p) {
            return err(ErrorKind::Malformed, at);
        }
        found = Some(p);
    }
    found.ok_or(ParseError::new(ErrorKind::Malformed, 0))
}

/// Parses `X-Forwarded-Host`: one `Host` value; a list is refused.
///
/// # Errors
///
/// [`ErrorKind::Malformed`] for a list; the `Host` errors.
///
/// # Examples
///
/// ```
/// use parse_net::forwarded::parse_x_forwarded_host;
///
/// assert_eq!(parse_x_forwarded_host(b"example.com:8443")?.port, Some(8443));
/// assert!(parse_x_forwarded_host(b"a.example, b.example").is_err());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_x_forwarded_host(value: &[u8]) -> Result<HostPort<'_>> {
    if let Some(at) = crate::scan::find_byte(b',', value) {
        return err(ErrorKind::Malformed, at);
    }
    crate::host::parse_host_port(value)
}

/// What a walk step found.
enum Step {
    Addr(IpAddr),
    Unknown,
}

/// Walks a chain of `count` steps from the right; `step(i)` gives the
/// `i`-th step counted from the left.
fn walk(
    count: usize,
    trust: &impl Trust,
    mut step: impl FnMut(usize) -> Step,
) -> Option<ClientAddress> {
    let mut leftmost: Option<IpAddr> = None;
    for (walked, i) in (0..count).rev().enumerate() {
        let hops = u8::try_from(walked + 1).unwrap_or(u8::MAX);
        match step(i) {
            Step::Addr(a) if trust.is_trusted(a) => leftmost = Some(a),
            Step::Addr(addr) => return Some(ClientAddress::Forwarded { addr, hops }),
            Step::Unknown => return Some(ClientAddress::Unknown { hops }),
        }
    }
    leftmost.map(|addr| ClientAddress::Forwarded {
        addr,
        hops: u8::try_from(count).unwrap_or(u8::MAX),
    })
}

/// The `i`-th element (from the left) of validated lines, by index: the
/// chain is short (at most `max_hops`), so a walk by index stays cheap and
/// allocates nothing.
fn nth_member<'a, I: Iterator<Item = &'a [u8]>>(
    lines: &[&'a [u8]],
    i: usize,
    members: impl Fn(&'a [u8]) -> I,
) -> Option<&'a [u8]> {
    lines.iter().flat_map(|line| members(line)).nth(i)
}

/// Resolves the client address of a request that arrived from `peer`.
///
/// The algorithm: an untrusted `peer` gives [`ClientAddress::Peer`] and the
/// header is never read. Otherwise the whole chain is parsed; a malformed
/// chain anywhere is an error (fail closed: use the peer); more than
/// `max_hops` elements is an error. The chain is walked from the right:
/// trusted addresses are skipped; the first untrusted address is the client;
/// `unknown`, an obfuscated identifier, or a `Forwarded` element without
/// `for` stops the walk with [`ClientAddress::Unknown`]. When every element
/// is trusted, the leftmost is the client. A trusted peer that sent no chain
/// is itself the client.
///
/// # Errors
///
/// [`ErrorKind::Malformed`] (the error's offset and line point at the
/// problem); [`ErrorKind::TooManyHops`].
///
/// # Examples
///
/// ```
/// use core::net::IpAddr;
/// use parse_net::{client_address, ClientAddress, ForwardedSource};
///
/// let proxy: IpAddr = "203.0.113.43".parse()?;
/// let trusted = |a: IpAddr| a == proxy;
/// let lines: [&[u8]; 1] = [b"for=192.0.2.60;proto=http;by=203.0.113.43"];
/// assert_eq!(client_address(proxy, ForwardedSource::Forwarded(&lines), &trusted, 16)?,
///            ClientAddress::Forwarded { addr: "192.0.2.60".parse()?, hops: 1 });
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn client_address(
    peer: IpAddr,
    source: ForwardedSource<'_>,
    trust: &impl Trust,
    max_hops: u8,
) -> Result<ClientAddress> {
    if !trust.is_trusted(peer) {
        return Ok(ClientAddress::Peer(peer));
    }
    let limits = Limits::DEFAULT.max_hops(max_hops);
    let found = match source {
        ForwardedSource::XForwardedFor(lines) => {
            let chain = parse_x_forwarded_for(lines, &limits).map_err(as_malformed)?;
            walk(chain.len(), trust, |i| {
                match nth_member(lines, i, xff_line).and_then(xff_member) {
                    Some((a, _)) => Step::Addr(a),
                    None => Step::Unknown,
                }
            })
        }
        ForwardedSource::Forwarded(lines) => {
            let elements = parse(lines, &limits).map_err(as_malformed)?;
            walk(elements.len(), trust, |i| {
                let e = nth_member(lines, i, |line| {
                    list::parse(line, &Limits::DEFAULT)
                        .ok()
                        .into_iter()
                        .flat_map(|l| l.into_iter())
                })
                .and_then(|e| element(e).ok());
                match e.and_then(|e| e.for_) {
                    Some(Node::Addr(a, _)) => Step::Addr(a),
                    _ => Step::Unknown,
                }
            })
        }
    };
    Ok(found.unwrap_or(ClientAddress::Peer(peer)))
}

/// Every parse error of a chain becomes `Malformed` (or stays
/// `TooManyHops`), keeping its offset and line.
fn as_malformed(e: ParseError) -> ParseError {
    if e.kind() == ErrorKind::TooManyHops {
        e
    } else {
        ParseError::new(ErrorKind::Malformed, e.offset()).on_line(e.line())
    }
}

/// [`client_address`] and whether the other header kind was present too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Resolved {
    /// The client address.
    pub address: ClientAddress,
    /// Whether the header kind not configured had a non-empty line: worth
    /// logging as a likely spoofing attempt (the two are never merged).
    pub other_present: bool,
}

/// As [`client_address`], and reports whether `other_lines` (the field
/// lines of the header kind not configured) were present.
///
/// # Errors
///
/// As [`client_address`].
///
/// # Examples
///
/// ```
/// use core::net::IpAddr;
/// use parse_net::{forwarded::client_address_detailed, ForwardedSource};
///
/// let peer: IpAddr = "10.0.0.1".parse()?;
/// let xff: [&[u8]; 1] = [b"198.51.100.7"];
/// let fwd: [&[u8]; 1] = [b"for=192.0.2.1"];
/// let r = client_address_detailed(peer, ForwardedSource::XForwardedFor(&xff), &fwd, &|a: IpAddr| a == peer, 16)?;
/// assert!(r.other_present);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn client_address_detailed(
    peer: IpAddr,
    source: ForwardedSource<'_>,
    other_lines: &[&[u8]],
    trust: &impl Trust,
    max_hops: u8,
) -> Result<Resolved> {
    Ok(Resolved {
        address: client_address(peer, source, trust, max_hops)?,
        other_present: other_lines.iter().any(|l| !trim_ows(l).is_empty()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_forwarded_rfc_examples() {
        let l = Limits::DEFAULT;
        let one = |v: &'static [u8]| -> Element<'static> {
            let lines: &'static [&'static [u8]] = std::boxed::Box::leak(std::boxed::Box::new([v]));
            parse(lines, &l).unwrap().iter().next().unwrap()
        };
        let e = one(b"for=\"_gazonk\"");
        assert_eq!(e.for_, Some(Node::Obfuscated(b"_gazonk", None)));
        let e = one(b"For=\"[2001:db8:cafe::17]:4711\"");
        assert!(matches!(
            e.for_,
            Some(Node::Addr(IpAddr::V6(_), Some(NodePort::Number(4711))))
        ));
        let e = one(b"for=192.0.2.60;proto=http;by=203.0.113.43");
        assert_eq!(
            (e.proto, e.by),
            (
                Some(Proto::Http),
                Some(Node::Addr(ip4("203.0.113.43"), None))
            )
        );
        assert_eq!(one(b"for=unknown").for_, Some(Node::Unknown(None)));
        assert_eq!(
            one(b"for=\"10.0.0.1:_p1\"").for_,
            Some(Node::Addr(
                ip4("10.0.0.1"),
                Some(NodePort::Obfuscated(b"_p1"))
            ))
        );
        assert_eq!(
            one(b"host=example.com; proto=https").proto,
            Some(Proto::Https)
        );
        assert_eq!(
            one(b";;for=1.2.3.4;").for_,
            Some(Node::Addr(ip4("1.2.3.4"), None))
        );
    }

    #[test]
    fn test_forwarded_refusals() {
        let l = Limits::DEFAULT;
        let k = |v: &[u8]| parse(&[v], &l).unwrap_err().kind();
        assert_ne!(k(b"for=2001:db8::1"), ErrorKind::TooManyHops);
        assert_eq!(k(b"for=1.2.3.4;for=5.6.7.8"), ErrorKind::DuplicateParameter);
        assert_eq!(k(b"for=1.2.3"), ErrorKind::InvalidAddress);
        assert_eq!(k(b"for=01.2.3.4"), ErrorKind::InvalidAddress);
        assert_eq!(k(b"for=\"[::1]:99999\""), ErrorKind::InvalidPort);
        assert_eq!(k(b"proto=ftp"), ErrorKind::Malformed);
        assert_eq!(k(b"for"), ErrorKind::MissingValue);
        assert_eq!(k(b"for=\"a\\\"b\""), ErrorKind::InvalidQuotedPair);
        assert_eq!(k(b"for=1.2.3.4 x"), ErrorKind::ExpectedSeparator);
        let seventeen = [b"for=1.1.1.1,".repeat(17)].concat();
        assert_eq!(
            parse(&[&seventeen[..]], &l).unwrap_err().kind(),
            ErrorKind::TooManyHops
        );
        let sixteen = [b"for=1.1.1.1,".repeat(16)].concat();
        assert_eq!(parse(&[&sixteen[..]], &l).unwrap().len(), 16);
    }

    #[test]
    fn test_xff_shapes() {
        let l = Limits::DEFAULT;
        let ok = |v: &[u8]| parse_x_forwarded_for(&[v], &l).map(|c| c.len());
        assert_eq!(ok(b"1.2.3.4"), Ok(1));
        assert_eq!(ok(b" 1.2.3.4 , 5.6.7.8:80 "), Ok(2));
        assert_eq!(ok(b"2001:db8::1, [2001:db8::2]:443, [::1]"), Ok(3));
        for bad in [
            &b"1.2.3.4, , 5.6.7.8"[..],
            b"",
            b"garbage",
            b"1.2.3.4:x",
            b"2001:db8::1:80:",
            b"[::1",
            b"1.2.3.4\r",
        ] {
            assert!(
                ok(bad).is_err(),
                "{}",
                std::string::String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn test_xff_untrusted_peer_ignored() {
        let t = |a: IpAddr| a == ip4("10.0.0.1");
        let lines: [&[u8]; 1] = [b"garbage that would be refused"];
        assert_eq!(
            client_address(
                ip4("192.0.2.9"),
                ForwardedSource::XForwardedFor(&lines),
                &t,
                16
            ),
            Ok(ClientAddress::Peer(ip4("192.0.2.9")))
        );
    }

    #[test]
    fn test_xff_leftmost_spoof_ignored() {
        let t = |a: IpAddr| a == ip4("10.0.0.1") || a == ip4("10.0.0.2");
        let lines: [&[u8]; 1] = [b"1.1.1.1, 203.0.113.7, 10.0.0.2"];
        assert_eq!(
            client_address(
                ip4("10.0.0.1"),
                ForwardedSource::XForwardedFor(&lines),
                &t,
                16
            ),
            Ok(ClientAddress::Forwarded {
                addr: ip4("203.0.113.7"),
                hops: 2
            })
        );
    }

    #[test]
    fn test_xff_malformed_fails_closed() {
        let t = |_: IpAddr| true;
        let lines: [&[u8]; 2] = [b"1.1.1.1", b"10.0.0.2, nope"];
        let e = client_address(
            ip4("10.0.0.1"),
            ForwardedSource::XForwardedFor(&lines),
            &t,
            16,
        )
        .unwrap_err();
        assert_eq!((e.kind(), e.line()), (ErrorKind::Malformed, 1));
        let too_many: [&[u8]; 1] = [b"1.1.1.1, 1.1.1.2, 1.1.1.3"];
        assert_eq!(
            client_address(
                ip4("10.0.0.1"),
                ForwardedSource::XForwardedFor(&too_many),
                &t,
                2
            )
            .unwrap_err()
            .kind(),
            ErrorKind::TooManyHops
        );
    }

    #[test]
    fn test_client_address_walk_cases() {
        let t = |a: IpAddr| a.is_loopback() || a == ip4("10.0.0.1");
        let peer = ip4("10.0.0.1");
        let x = |v: &'static [u8]| {
            client_address(
                peer,
                ForwardedSource::XForwardedFor(std::boxed::Box::leak(std::boxed::Box::new([v]))),
                &t,
                16,
            )
        };
        assert_eq!(
            x(b"127.0.0.1, 10.0.0.1"),
            Ok(ClientAddress::Forwarded {
                addr: ip4("127.0.0.1"),
                hops: 2
            })
        );
        let none: [&[u8]; 0] = [];
        assert_eq!(
            client_address(peer, ForwardedSource::XForwardedFor(&none), &t, 16),
            Ok(ClientAddress::Peer(peer))
        );
        let f = |v: &'static [u8]| {
            client_address(
                peer,
                ForwardedSource::Forwarded(std::boxed::Box::leak(std::boxed::Box::new([v]))),
                &t,
                16,
            )
        };
        assert_eq!(
            f(b"for=192.0.2.1, for=unknown, for=127.0.0.1"),
            Ok(ClientAddress::Unknown { hops: 2 })
        );
        assert_eq!(
            f(b"for=192.0.2.1, for=_hidden"),
            Ok(ClientAddress::Unknown { hops: 1 })
        );
        assert_eq!(
            f(b"for=192.0.2.1, proto=https"),
            Ok(ClientAddress::Unknown { hops: 1 })
        );
        assert_eq!(
            f(b"for=\"[2001:db8::7]\""),
            Ok(ClientAddress::Forwarded {
                addr: "2001:db8::7".parse().unwrap(),
                hops: 1
            })
        );
        assert_eq!(
            f(b"for=2001:db8::7").unwrap_err().kind(),
            ErrorKind::Malformed
        );
    }

    #[test]
    fn test_both_forwarded_headers_reported() {
        let t = |_: IpAddr| true;
        let xff: [&[u8]; 1] = [b"192.0.2.1"];
        let fwd: [&[u8]; 1] = [b"for=198.51.100.1"];
        let r = client_address_detailed(
            ip4("10.0.0.1"),
            ForwardedSource::XForwardedFor(&xff),
            &fwd,
            &t,
            16,
        )
        .unwrap();
        assert!(r.other_present);
        assert_eq!(
            r.address,
            ClientAddress::Forwarded {
                addr: ip4("192.0.2.1"),
                hops: 1
            }
        );
        let empty: [&[u8]; 1] = [b"  "];
        assert!(
            !client_address_detailed(
                ip4("10.0.0.1"),
                ForwardedSource::XForwardedFor(&xff),
                &empty,
                &t,
                16
            )
            .unwrap()
            .other_present
        );
    }

    #[test]
    fn test_x_forwarded_proto_and_host() {
        assert_eq!(parse_x_forwarded_proto(b"http, HTTP"), Ok(Proto::Http));
        assert!(parse_x_forwarded_proto(b"").is_err());
        assert!(parse_x_forwarded_proto(b"wss").is_err());
        assert!(parse_x_forwarded_host(b"[::1]:8080").is_ok());
        assert_eq!(
            parse_x_forwarded_host(b"a,b").unwrap_err().kind(),
            ErrorKind::Malformed
        );
    }
}
