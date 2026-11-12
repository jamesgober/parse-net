//! `Forwarded` (RFC 7239) and the de facto `X-Forwarded-For`,
//! `X-Forwarded-Proto`, and `X-Forwarded-Host`, with client-address
//! resolution through trusted proxies.
//!
//! The leftmost `X-Forwarded-For` address is whatever the client typed; only
//! addresses appended by proxies you trust mean anything. [`client_address`]
//! ignores the header unless the connection's peer is trusted, walks the
//! chain from the right, and stops at the first address it cannot trust.
//! Nothing left of that address is read, so the client cannot make the walk
//! fail with text of its own. When the entry there gives no address,
//! the answer is [`ClientAddress::Unknown`]: never use the peer then, as it
//! is a trusted proxy.
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
//! let ip = pn::client_address(proxy, ForwardedSource::XForwardedFor(&xff), &trusted);
//! assert_eq!(ip, ClientAddress::Forwarded { addr: "198.51.100.7".parse()?, hops: 2 });
//!
//! // The same header from an untrusted peer is ignored entirely.
//! let stranger: IpAddr = "192.0.2.1".parse()?;
//! assert_eq!(pn::client_address(stranger, ForwardedSource::XForwardedFor(&xff), &trusted),
//!            ClientAddress::Peer(stranger));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use core::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use crate::{
    class,
    error::{ErrorKind, ParseError, Result, WriteError, err},
    host::{Host, HostPort, host_port},
    limits::Limits,
    list,
    param::{MAX_CHECKED_PARAMS, Names},
    scan::control_kind,
    text::{Word, is_token, parse_word, skip_ows, trim_ows},
    write::{CountSink, Sink, reserve},
};

/// Decides whether an address belongs to a proxy you trust.
///
/// Implemented for every `Fn(IpAddr) -> bool`; a deployment's CIDR sets
/// (net-io, bouncer-io configuration) implement it directly. Addresses
/// arrive as written: an IPv4-mapped IPv6 entry (`::ffff:10.0.0.2`) is an
/// [`IpAddr::V6`], so a set of IPv4 ranges does not trust it, which errs
/// toward untrusted.
///
/// # Examples
///
/// ```
/// use core::net::IpAddr;
/// use parse_net::Trust;
///
/// struct Loopback;
/// impl Trust for Loopback {
///     fn is_trusted(&self, addr: IpAddr) -> bool { addr.is_loopback() }
/// }
/// assert!(Loopback.is_trusted("127.0.0.1".parse()?));
/// let proxy: IpAddr = "10.0.0.2".parse()?;
/// assert!(!(|a: IpAddr| a == proxy).is_trusted("192.0.2.1".parse()?));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
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
///
/// # Examples
///
/// ```
/// use core::net::IpAddr;
/// use parse_net::{client_address, ClientAddress, ForwardedSource};
///
/// let peer: IpAddr = "10.0.0.1".parse()?;
/// let lines: [&[u8]; 1] = [b"for=192.0.2.60"];
/// let source = ForwardedSource::Forwarded(&lines);
/// assert_eq!(client_address(peer, source, &|a: IpAddr| a == peer),
///            ClientAddress::Forwarded { addr: "192.0.2.60".parse()?, hops: 1 });
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub enum ForwardedSource<'a> {
    /// `Forwarded` field lines.
    Forwarded(&'a [&'a [u8]]),
    /// `X-Forwarded-For` field lines.
    XForwardedFor(&'a [&'a [u8]]),
}

/// The client address a request is attributed to.
///
/// # Examples
///
/// ```
/// use core::net::IpAddr;
/// use parse_net::{client_address, ClientAddress, ForwardedSource};
///
/// let peer: IpAddr = "10.0.0.1".parse()?;
/// let trusted = |a: IpAddr| a == peer;
/// let hidden: [&[u8]; 1] = [b"for=unknown"];
/// assert_eq!(client_address(peer, ForwardedSource::Forwarded(&hidden), &trusted), ClientAddress::Unknown { hops: 1 });
/// let none: [&[u8]; 0] = [];
/// assert_eq!(client_address(peer, ForwardedSource::XForwardedFor(&none), &trusted), ClientAddress::Peer(peer));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
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
    /// No reliable client address: after `hops` elements the walk reached
    /// `unknown`, an obfuscated identifier, an element without `for`, text
    /// that is not an address, or the hop limit. Never use the peer in its
    /// place: it is a trusted proxy.
    Unknown {
        /// The elements walked, the unknown one included.
        hops: u8,
    },
}

/// A node port: a number or an obfuscated identifier.
///
/// # Examples
///
/// ```
/// use parse_net::{forwarded::{self, Node, NodePort}, Limits};
///
/// let lines: [&[u8]; 1] = [b"for=\"192.0.2.60:4711\";by=\"_proxy:_p1\""];
/// let e = forwarded::parse(&lines, &Limits::DEFAULT)?.iter().next().expect("one element");
/// assert!(matches!(e.for_, Some(Node::Addr(_, Some(NodePort::Number(4711))))));
/// assert_eq!(e.by, Some(Node::Obfuscated(b"_proxy", Some(NodePort::Obfuscated(b"_p1")))));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NodePort<'a> {
    /// A port number.
    Number(u16),
    /// An obfuscated port (`_` and letters, digits, `.`, `_`, `-`).
    Obfuscated(&'a [u8]),
}

/// A `for` or `by` node (RFC 7239 section 6).
///
/// # Examples
///
/// ```
/// use parse_net::{forwarded::{self, Node}, Limits};
///
/// let lines: [&[u8]; 1] = [b"for=unknown, for=\"[2001:db8::1]\", for=_hidden"];
/// let nodes: Vec<_> = forwarded::parse(&lines, &Limits::DEFAULT)?.iter().map(|e| e.for_).collect();
/// assert_eq!(nodes[0], Some(Node::Unknown(None)));
/// assert_eq!(nodes[1], Some(Node::Addr("2001:db8::1".parse()?, None)));
/// assert_eq!(nodes[2], Some(Node::Obfuscated(b"_hidden", None)));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[non_exhaustive]
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
///
/// # Examples
///
/// ```
/// use parse_net::forwarded::{parse_x_forwarded_proto, Proto};
///
/// assert_eq!(parse_x_forwarded_proto(b"http")?, Proto::Http);
/// assert_eq!(parse_x_forwarded_proto(b"https, HTTPS")?, Proto::Https);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Proto {
    /// `http`.
    Http,
    /// `https`.
    Https,
    /// `ws`.
    Ws,
    /// `wss`.
    Wss,
    /// Another URI scheme (RFC 7239 section 5.4 allows any). It cannot be
    /// written back: [`write_element`] refuses it.
    Other,
}

/// The scheme named by `v`; `None` when `v` is not a URI scheme.
fn proto(v: &[u8]) -> Option<Proto> {
    const NAMES: [(&[u8], Proto); 4] = [
        (b"http", Proto::Http),
        (b"https", Proto::Https),
        (b"ws", Proto::Ws),
        (b"wss", Proto::Wss),
    ];
    if let Some(&(_, p)) = NAMES.iter().find(|(n, _)| v.eq_ignore_ascii_case(n)) {
        return Some(p);
    }
    let (first, rest) = v.split_first()?;
    let scheme = first.is_ascii_alphabetic()
        && rest
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'));
    scheme.then_some(Proto::Other)
}

/// One `Forwarded` element.
///
/// # Examples
///
/// ```
/// use parse_net::{forwarded::{self, Proto}, Host, Limits};
///
/// let lines: [&[u8]; 1] = [b"for=192.0.2.60;proto=https;host=example.com"];
/// let e = forwarded::parse(&lines, &Limits::DEFAULT)?.iter().next().expect("one element");
/// assert_eq!(e.proto, Some(Proto::Https));
/// assert_eq!(e.host.map(|h| h.host), Some(Host::Name(b"example.com")));
/// assert!(e.by.is_none());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
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

impl Element<'_> {
    /// An element with no parameters, to fill in field by field before
    /// [`write_element`] (the struct is `#[non_exhaustive]`).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{forwarded::{write_element, Element, Node, Proto}, SliceSink};
    ///
    /// let mut e = Element::new();
    /// e.for_ = Some(Node::Addr("192.0.2.60".parse()?, None));
    /// e.proto = Some(Proto::Https);
    /// let mut buf = [0u8; 64];
    /// let mut out = SliceSink::new(&mut buf);
    /// write_element(&e, &mut out)?;
    /// assert_eq!(out.written(), b"for=192.0.2.60;proto=https");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            for_: None,
            by: None,
            host: None,
            proto: None,
        }
    }
}

/// Limits for walking text that was already validated.
const RELAXED: Limits = Limits::DEFAULT
    .max_list_members(u16::MAX)
    .max_empty_elements(u16::MAX)
    .max_comment_depth(u8::MAX);

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
    if v6 {
        let t = core::str::from_utf8(text).ok()?;
        Ipv6Addr::from_str(t).ok().map(IpAddr::V6)
    } else {
        ipv4(text).map(IpAddr::V4)
    }
}

/// The dotted-decimal IPv4 address at the front of `s`, with `core`'s rules
/// (four parts of one to three digits, each at most 255, no leading zeros, so
/// `01.2.3.4` cannot pass), and what follows it. One pass over the bytes,
/// with no UTF-8 check.
fn ipv4_prefix(mut s: &[u8]) -> Option<(Ipv4Addr, &[u8])> {
    let mut octets = [0u8; 4];
    for (i, o) in octets.iter_mut().enumerate() {
        if i > 0 {
            let [b'.', rest @ ..] = s else {
                return None;
            };
            s = rest;
        }
        let [first @ b'0'..=b'9', rest @ ..] = s else {
            return None;
        };
        let (mut n, mut len) = (u16::from(*first - b'0'), 1usize);
        s = rest;
        while let [d @ b'0'..=b'9', rest @ ..] = s {
            len += 1;
            if len > 3 || *first == b'0' {
                return None;
            }
            n = n * 10 + u16::from(*d - b'0');
            s = rest;
        }
        *o = u8::try_from(n).ok()?;
    }
    Some((Ipv4Addr::from(octets), s))
}

/// A whole dotted-decimal IPv4 address.
fn ipv4(text: &[u8]) -> Option<Ipv4Addr> {
    match ipv4_prefix(text)? {
        (a, []) => Some(a),
        _ => None,
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
    if name.eq_ignore_ascii_case(b"unknown") {
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
    let (mut names, mut pairs) = (Names::new(), 0usize);
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
        // RFC 7239 section 4: a pair occurs at most once in an element.
        pairs += 1;
        if pairs > MAX_CHECKED_PARAMS {
            return err(ErrorKind::TooManyMembers, name_at);
        }
        if names.repeats(e, name_at, name, class::is_tchar) {
            return err(ErrorKind::DuplicateParameter, name_at);
        }
        let slot = [&b"for"[..], b"by", b"host", b"proto"]
            .iter()
            .position(|k| name.eq_ignore_ascii_case(k));
        match slot {
            Some(0) => out.for_ = Some(node(v).map_err(|x| x.shifted(value_at))?),
            Some(1) => out.by = Some(node(v).map_err(|x| x.shifted(value_at))?),
            Some(2) => out.host = Some(host_port(v).map_err(|x| x.shifted(value_at))?),
            Some(3) => match proto(v) {
                Some(p) => out.proto = Some(p),
                None => return err(ErrorKind::Malformed, value_at),
            },
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
///
/// # Examples
///
/// ```
/// use parse_net::{forwarded, Limits};
///
/// let lines: [&[u8]; 2] = [b"for=192.0.2.60", b"for=198.51.100.7;proto=https"];
/// let elems = forwarded::parse(&lines, &Limits::DEFAULT)?;
/// assert_eq!(elems.len(), 2);
/// assert_eq!(elems.iter().filter(|e| e.proto.is_some()).count(), 1);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct ForwardedElements<'a> {
    lines: &'a [&'a [u8]],
    count: usize,
}

impl<'a> ForwardedElements<'a> {
    /// The elements, left to right across every line.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{forwarded::{self, Proto}, Limits};
    ///
    /// let lines: [&[u8]; 2] = [b"for=192.0.2.60", b"for=198.51.100.7;proto=https"];
    /// let protos: Vec<_> = forwarded::parse(&lines, &Limits::DEFAULT)?.iter().map(|e| e.proto).collect();
    /// assert_eq!(protos, [None, Some(Proto::Https)]);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = Element<'a>> + use<'a> {
        let lines = self.lines;
        lines
            .iter()
            .filter_map(|line| list::parse(line, &RELAXED).ok())
            .flat_map(|l| l.into_iter())
            .filter_map(|e| element(e).ok())
    }

    /// The number of elements.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{forwarded, Limits};
    ///
    /// let lines: [&[u8]; 2] = [b"for=192.0.2.60, for=192.0.2.61", b"for=unknown"];
    /// assert_eq!(forwarded::parse(&lines, &Limits::DEFAULT)?.len(), 3);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether there are no elements.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{forwarded, Limits};
    ///
    /// let none: [&[u8]; 0] = [];
    /// assert!(forwarded::parse(&none, &Limits::DEFAULT)?.is_empty());
    /// assert!(!forwarded::parse(&[&b"for=unknown"[..]], &Limits::DEFAULT)?.is_empty());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
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
    // A whole IPv4 address cannot start IPv6 text, so IPv4 is read first.
    match ipv4_prefix(m) {
        Some((a, [])) => Some((IpAddr::V4(a), None)),
        Some((a, [b':', p @ ..])) => Some((IpAddr::V4(a), port(p)?)),
        Some(_) => None,
        None => ip(m, true).map(|a| (a, None)),
    }
}

/// The members of one `X-Forwarded-For` line, refusing empty members.
fn xff_line(line: &[u8]) -> impl Iterator<Item = &[u8]> {
    line.split(|&b| b == b',').map(trim_ows)
}

/// A validated `X-Forwarded-For` chain.
///
/// # Examples
///
/// ```
/// use parse_net::{forwarded::parse_x_forwarded_for, Limits};
///
/// let lines: [&[u8]; 1] = [b"203.0.113.9, 10.0.0.1:8080"];
/// let chain = parse_x_forwarded_for(&lines, &Limits::DEFAULT)?;
/// assert_eq!(chain.len(), 2);
/// assert_eq!(chain.iter().last(), Some(("10.0.0.1".parse()?, Some(8080))));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct XForwardedFor<'a> {
    lines: &'a [&'a [u8]],
    count: usize,
}

impl<'a> XForwardedFor<'a> {
    /// The addresses and ports, left to right across every line.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{forwarded::parse_x_forwarded_for, Limits};
    ///
    /// let lines: [&[u8]; 1] = [b"203.0.113.9, [2001:db8::1]:443"];
    /// let mut it = parse_x_forwarded_for(&lines, &Limits::DEFAULT)?.iter();
    /// assert_eq!(it.next(), Some(("203.0.113.9".parse()?, None)));
    /// assert_eq!(it.next(), Some(("2001:db8::1".parse()?, Some(443))));
    /// assert_eq!(it.next(), None);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = (IpAddr, Option<u16>)> + use<'a> {
        self.lines
            .iter()
            .flat_map(|line| xff_line(line))
            .filter_map(xff_member)
    }

    /// The number of addresses.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{forwarded::parse_x_forwarded_for, Limits};
    ///
    /// let lines: [&[u8]; 2] = [b"203.0.113.9, 198.51.100.7", b"10.0.0.1"];
    /// assert_eq!(parse_x_forwarded_for(&lines, &Limits::DEFAULT)?.len(), 3);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether there are no addresses.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{forwarded::parse_x_forwarded_for, Limits};
    ///
    /// let none: [&[u8]; 0] = [];
    /// assert!(parse_x_forwarded_for(&none, &Limits::DEFAULT)?.is_empty());
    /// assert!(!parse_x_forwarded_for(&[&b"10.0.0.1"[..]], &Limits::DEFAULT)?.is_empty());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
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
pub fn parse_x_forwarded_for<'a>(
    lines: &'a [&'a [u8]],
    limits: &Limits,
) -> Result<XForwardedFor<'a>> {
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
    Ok(XForwardedFor { lines, count })
}

/// Parses `X-Forwarded-Proto`: a URI scheme, case-insensitive ([`Proto`]
/// names `http`, `https`, `ws`, and `wss`); a comma list only when every
/// member is the same.
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
    let mut found: Option<(Proto, &[u8])> = None;
    for m in value.split(|&b| b == b',') {
        let at = (m.as_ptr() as usize).saturating_sub(value.as_ptr() as usize);
        let t = trim_ows(m);
        let Some(p) = proto(t) else {
            return err(ErrorKind::Malformed, at);
        };
        if found.is_some_and(|(_, f)| !f.eq_ignore_ascii_case(t)) {
            return err(ErrorKind::Malformed, at);
        }
        found = Some((p, t));
    }
    found
        .map(|(p, _)| p)
        .ok_or(ParseError::new(ErrorKind::Malformed, 0))
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

/// The walk from the right shared by both header kinds. `entries` yields the
/// chain right to left, `None` for an entry that gives no reliable address;
/// it is lazy, so nothing left of the decision point is ever read. `None` is
/// an empty chain.
fn walk(
    entries: impl Iterator<Item = Option<IpAddr>>,
    trust: &impl Trust,
    limit: u8,
) -> Option<ClientAddress> {
    let (mut hops, mut leftmost) = (0u8, None);
    for entry in entries {
        if hops == limit {
            return Some(ClientAddress::Unknown { hops });
        }
        hops += 1;
        match entry {
            Some(a) if trust.is_trusted(a) => leftmost = Some(a),
            Some(addr) => return Some(ClientAddress::Forwarded { addr, hops }),
            None => return Some(ClientAddress::Unknown { hops }),
        }
    }
    leftmost.map(|addr| ClientAddress::Forwarded { addr, hops })
}

/// The `X-Forwarded-For` members right to left; a line of only OWS has
/// none.
fn xff_rev<'a>(lines: &'a [&'a [u8]]) -> impl Iterator<Item = Option<IpAddr>> + 'a {
    lines
        .iter()
        .rev()
        .filter(|line| !trim_ows(line).is_empty())
        .flat_map(|line| line.rsplit(|&b| b == b','))
        .map(|m| xff_member(trim_ows(m)).map(|(a, _)| a))
}

/// Whether every quoted string in `line` is closed, read left to right as
/// the list grammar reads it.
fn quotes_closed(line: &[u8]) -> bool {
    let (mut quoted, mut escaped) = (false, false);
    for &b in line {
        if escaped {
            escaped = false;
        } else if quoted && b == b'\\' {
            escaped = true;
        } else if b == b'"' {
            quoted = !quoted;
        }
    }
    !quoted
}

/// The elements of one `Forwarded` line right to left, split at commas
/// outside quoted strings. With every quote closed, a `"` met from the right
/// outside a string closes one, and inside a string it is escaped when an
/// odd run of `\` precedes it. A backslash outside a string can misread the
/// split, but only inside an element the walk refuses anyway.
fn forwarded_line_rev(line: &[u8]) -> impl Iterator<Item = &[u8]> {
    let (mut end, mut done) = (line.len(), false);
    core::iter::from_fn(move || {
        if done {
            return None;
        }
        let mut quoted = false;
        let mut i = end;
        while i > 0 {
            i -= 1;
            match line.get(i) {
                Some(b'"') if quoted => {
                    let before = line.get(..i).unwrap_or(&[]);
                    let run = before.iter().rev().take_while(|&&b| b == b'\\').count();
                    if run % 2 == 0 {
                        quoted = false;
                    }
                }
                Some(b'"') => quoted = true,
                Some(b',') if !quoted => {
                    let e = line.get(i + 1..end).unwrap_or(&[]);
                    end = i;
                    return Some(e);
                }
                _ => {}
            }
        }
        done = true;
        line.get(..end)
    })
}

/// The `Forwarded` elements right to left: the `for` address of each, or
/// `None` for an element without a usable one, or for a line whose quoted
/// strings are not closed. Empty elements are skipped, as the list grammar
/// allows them.
fn forwarded_rev<'a>(lines: &'a [&'a [u8]]) -> impl Iterator<Item = Option<IpAddr>> + 'a {
    lines.iter().rev().flat_map(|&line| {
        let closed = quotes_closed(line);
        let broken = (!closed).then_some(None);
        let elements = closed
            .then(|| forwarded_line_rev(line))
            .into_iter()
            .flatten()
            .map(trim_ows)
            .filter(|e| !e.is_empty())
            .map(|e| match element(e).map(|e| e.for_) {
                Ok(Some(Node::Addr(a, _))) => Some(a),
                _ => None,
            });
        broken.into_iter().chain(elements)
    })
}

/// Resolves the client address of a request that arrived from `peer`, with
/// at most 16 trusted hops ([`client_address_with_limits`] takes others).
///
/// Proxies append on the right, so only the right end of a chain was written
/// by hops you trust; everything left of the first untrusted address is
/// whatever the client sent, and it is never read. The walk:
///
/// - an untrusted `peer` gives [`ClientAddress::Peer`], and the header is
///   never read;
/// - otherwise the chain is read from the right: trusted addresses are
///   skipped, and the first untrusted address is the client
///   ([`ClientAddress::Forwarded`]);
/// - an entry that gives no reliable address there (`unknown`, an obfuscated
///   identifier, a `Forwarded` element without `for`, text that is not an
///   address, a `Forwarded` line with an unclosed quoted string), or more
///   trusted entries than the limit, gives [`ClientAddress::Unknown`];
/// - when every entry is trusted, the leftmost is the client, and a trusted
///   peer that sent no chain is itself the client.
///
/// [`ClientAddress::Unknown`] means there is no reliable client address.
/// Never use the peer in its place: the peer is a trusted proxy, and a
/// client attributed to it escapes its own rate limits and bans. Treat the
/// client as unknown (one shared bucket, no address-based allow) or refuse
/// the request.
///
/// # Examples
///
/// ```
/// use core::net::IpAddr;
/// use parse_net::{client_address, ClientAddress, ForwardedSource};
///
/// let proxy: IpAddr = "10.0.0.2".parse()?;
/// let trusted = |a: IpAddr| a == proxy;
/// // The proxy appended 198.51.100.7; the junk on the left is never read.
/// let lines: [&[u8]; 1] = [b"junk, 198.51.100.7"];
/// assert_eq!(client_address(proxy, ForwardedSource::XForwardedFor(&lines), &trusted),
///            ClientAddress::Forwarded { addr: "198.51.100.7".parse()?, hops: 1 });
/// let hidden: [&[u8]; 1] = [b"for=unknown"];
/// assert_eq!(client_address(proxy, ForwardedSource::Forwarded(&hidden), &trusted),
///            ClientAddress::Unknown { hops: 1 });
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[inline]
#[must_use]
pub fn client_address(
    peer: IpAddr,
    source: ForwardedSource<'_>,
    trust: &impl Trust,
) -> ClientAddress {
    client_address_with_limits(peer, source, trust, &Limits::DEFAULT)
}

/// As [`client_address`], with at most [`Limits::max_hops`] trusted hops
/// walked.
///
/// # Examples
///
/// ```
/// use core::net::IpAddr;
/// use parse_net::{forwarded::client_address_with_limits, ClientAddress, ForwardedSource, Limits};
///
/// let trusted = |a: IpAddr| matches!(a, IpAddr::V4(v) if v.is_private());
/// let peer: IpAddr = "10.0.0.2".parse()?;
/// let lines: [&[u8]; 1] = [b"198.51.100.7, 10.0.0.4, 10.0.0.3"];
/// let one = Limits::DEFAULT.max_hops(1);
/// assert_eq!(client_address_with_limits(peer, ForwardedSource::XForwardedFor(&lines), &trusted, &one),
///            ClientAddress::Unknown { hops: 1 });
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use]
pub fn client_address_with_limits(
    peer: IpAddr,
    source: ForwardedSource<'_>,
    trust: &impl Trust,
    limits: &Limits,
) -> ClientAddress {
    if !trust.is_trusted(peer) {
        return ClientAddress::Peer(peer);
    }
    let found = match source {
        ForwardedSource::XForwardedFor(lines) => walk(xff_rev(lines), trust, limits.hops),
        ForwardedSource::Forwarded(lines) => walk(forwarded_rev(lines), trust, limits.hops),
    };
    found.unwrap_or(ClientAddress::Peer(peer))
}

/// [`client_address`] and whether the other header kind was present too.
///
/// # Examples
///
/// ```
/// use core::net::IpAddr;
/// use parse_net::{forwarded::client_address_detailed, ClientAddress, ForwardedSource, Limits};
///
/// let peer: IpAddr = "10.0.0.1".parse()?;
/// let xff: [&[u8]; 1] = [b"198.51.100.7"];
/// let r = client_address_detailed(peer, ForwardedSource::XForwardedFor(&xff), &[], &|a: IpAddr| a == peer, &Limits::DEFAULT);
/// assert_eq!(r.address, ClientAddress::Forwarded { addr: "198.51.100.7".parse()?, hops: 1 });
/// assert!(!r.other_present);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
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
/// # Examples
///
/// ```
/// use core::net::IpAddr;
/// use parse_net::{forwarded::client_address_detailed, ForwardedSource, Limits};
///
/// let peer: IpAddr = "10.0.0.1".parse()?;
/// let xff: [&[u8]; 1] = [b"198.51.100.7"];
/// let fwd: [&[u8]; 1] = [b"for=192.0.2.1"];
/// let r = client_address_detailed(peer, ForwardedSource::XForwardedFor(&xff), &fwd, &|a: IpAddr| a == peer, &Limits::DEFAULT);
/// assert!(r.other_present);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use]
pub fn client_address_detailed(
    peer: IpAddr,
    source: ForwardedSource<'_>,
    other_lines: &[&[u8]],
    trust: &impl Trust,
    limits: &Limits,
) -> Resolved {
    Resolved {
        address: client_address_with_limits(peer, source, trust, limits),
        other_present: other_lines.iter().any(|l| !trim_ows(l).is_empty()),
    }
}

/// Writes a node's text: the address (IPv6 in brackets), `unknown`, or the
/// obfuscated name, then `:` and the port.
fn put_node(n: &Node<'_>, out: &mut impl Sink) -> core::result::Result<(), WriteError> {
    let port = match *n {
        Node::Addr(ip, port) => {
            let host = match ip {
                IpAddr::V4(a) => Host::V4(a),
                IpAddr::V6(a) => Host::V6(a),
            };
            HostPort {
                host,
                port: None,
                empty_port: false,
            }
            .write_to(out)?;
            port
        }
        Node::Unknown(port) => {
            out.put(b"unknown")?;
            port
        }
        Node::Obfuscated(name, port) => {
            if !is_obfuscated(name) {
                return Err(WriteError::NotToken);
            }
            out.put(name)?;
            port
        }
    };
    match port {
        None => {}
        Some(NodePort::Number(p)) => {
            out.put(b":")?;
            crate::write::write_decimal_u64(u64::from(p), out)?;
        }
        Some(NodePort::Obfuscated(p)) => {
            if !is_obfuscated(p) {
                return Err(WriteError::NotToken);
            }
            out.put(b":")?;
            out.put(p)?;
        }
    }
    Ok(())
}

/// Writes `name=` and the node, quoted when it holds an IPv6 address or a
/// port (`:` is not a token character, RFC 7239 section 6).
fn put_pair(
    name: &[u8],
    n: &Node<'_>,
    first: &mut bool,
    out: &mut impl Sink,
) -> core::result::Result<(), WriteError> {
    let quote = matches!(n, Node::Addr(IpAddr::V6(_), _))
        || matches!(
            n,
            Node::Addr(_, Some(_)) | Node::Unknown(Some(_)) | Node::Obfuscated(_, Some(_))
        );
    if !*first {
        out.put(b";")?;
    }
    *first = false;
    out.put(name)?;
    out.put(b"=")?;
    if quote {
        out.put(b"\"")?;
    }
    put_node(n, out)?;
    if quote {
        out.put(b"\"")?;
    }
    Ok(())
}

fn put_element(e: &Element<'_>, out: &mut impl Sink) -> core::result::Result<(), WriteError> {
    let mut first = true;
    if let Some(n) = &e.for_ {
        put_pair(b"for", n, &mut first, out)?;
    }
    if let Some(p) = e.proto {
        if !first {
            out.put(b";")?;
        }
        first = false;
        out.put(match p {
            Proto::Http => b"proto=http",
            Proto::Https => b"proto=https",
            Proto::Ws => b"proto=ws",
            Proto::Wss => b"proto=wss",
            Proto::Other => return Err(WriteError::NotToken),
        })?;
    }
    if let Some(n) = &e.by {
        put_pair(b"by", n, &mut first, out)?;
    }
    if let Some(h) = &e.host {
        if !first {
            out.put(b";")?;
        }
        out.put(b"host=")?;
        // A value that is not a token needs quotes: a port, an IPv6 literal,
        // an empty name, or a name with `,`, `;`, `=`, `(`, or `)`, all legal
        // in a reg-name and all able to end the pair or forge another. The
        // quoted bytes need no escapes: no host holds `"` or `\`.
        let quote = h.port.is_some()
            || match h.host {
                Host::V4(_) => false,
                Host::V6(_) | Host::Future(_) => true,
                Host::Name(n) => !is_token(n),
            };
        if quote {
            out.put(b"\"")?;
        }
        h.write_to(out)?;
        if quote {
            out.put(b"\"")?;
        }
    }
    Ok(())
}

/// Writes one `Forwarded` element: `for`, `proto`, `by`, and `host`, in that
/// order, each when present, with IPv6 addresses and nodes with ports
/// quoted. For proxies that append their hop.
///
/// # Errors
///
/// [`WriteError::NotToken`] for an obfuscated name or port that is not `_`
/// followed by `ALPHA / DIGIT / "." / "_" / "-"`, or for [`Proto::Other`];
/// [`WriteError::Forbidden`] for a host name with a byte no name holds;
/// [`WriteError::Full`]
/// (nothing written when the sink reports its room).
///
/// # Examples
///
/// ```
/// use core::net::IpAddr;
/// use parse_net::{forwarded::{self, Element, Node, NodePort, Proto}, SliceSink};
///
/// let mut e = Element::new();
/// e.for_ = Some(Node::Addr("192.0.2.60".parse::<IpAddr>()?, None));
/// e.by = Some(Node::Addr("2001:db8::17".parse::<IpAddr>()?, Some(NodePort::Number(4711))));
/// e.proto = Some(Proto::Https);
/// let mut buf = [0u8; 96];
/// let mut out = SliceSink::new(&mut buf);
/// forwarded::write_element(&e, &mut out)?;
/// assert_eq!(out.written(), b"for=192.0.2.60;proto=https;by=\"[2001:db8::17]:4711\"");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn write_element(e: &Element<'_>, out: &mut impl Sink) -> core::result::Result<(), WriteError> {
    let mut count = CountSink::new();
    put_element(e, &mut count)?;
    reserve(out, count.count())?;
    put_element(e, out)
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;

    #[test]
    fn test_write_element_round_trip() {
        let v6: IpAddr = "2001:db8:cafe::17".parse().unwrap();
        let cases = [
            Element {
                for_: Some(Node::Addr(ip4("192.0.2.43"), None)),
                by: None,
                host: None,
                proto: None,
            },
            Element {
                for_: Some(Node::Addr(v6, Some(NodePort::Number(4711)))),
                by: Some(Node::Obfuscated(
                    b"_hidden",
                    Some(NodePort::Obfuscated(b"_p1")),
                )),
                host: Some(crate::parse_host_port(b"example.com:8080").unwrap()),
                proto: Some(Proto::Http),
            },
            Element {
                for_: Some(Node::Unknown(Some(NodePort::Number(80)))),
                by: Some(Node::Addr(v6, None)),
                host: Some(crate::parse_host_port(b"[::1]").unwrap()),
                proto: Some(Proto::Https),
            },
        ];
        for e in cases {
            let mut buf = [0u8; 128];
            let mut out = crate::SliceSink::new(&mut buf);
            write_element(&e, &mut out).unwrap();
            let lines = [out.written()];
            let parsed = parse(&lines, &Limits::DEFAULT).unwrap();
            assert_eq!(
                parsed.iter().next(),
                Some(e),
                "{:?}",
                core::str::from_utf8(out.written())
            );
        }
        let bad = Element {
            for_: Some(Node::Obfuscated(b"hidden", None)),
            by: None,
            host: None,
            proto: None,
        };
        let mut buf = [0u8; 8];
        let mut out = crate::SliceSink::new(&mut buf);
        assert_eq!(write_element(&bad, &mut out), Err(WriteError::NotToken));
        let big = Element {
            for_: Some(Node::Addr(v6, None)),
            by: None,
            host: None,
            proto: None,
        };
        assert_eq!(write_element(&big, &mut out), Err(WriteError::Full));
        assert!(out.is_empty());
    }

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
        assert_eq!(k(b"proto=1x"), ErrorKind::Malformed);
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
            client_address(ip4("192.0.2.9"), ForwardedSource::XForwardedFor(&lines), &t),
            ClientAddress::Peer(ip4("192.0.2.9"))
        );
    }

    #[test]
    fn test_xff_leftmost_spoof_ignored() {
        let t = |a: IpAddr| a == ip4("10.0.0.1") || a == ip4("10.0.0.2");
        let lines: [&[u8]; 1] = [b"1.1.1.1, 203.0.113.7, 10.0.0.2"];
        assert_eq!(
            client_address(ip4("10.0.0.1"), ForwardedSource::XForwardedFor(&lines), &t),
            ClientAddress::Forwarded {
                addr: ip4("203.0.113.7"),
                hops: 2
            }
        );
    }

    /// Text left of the client address is the client's own and
    /// is never read, so it cannot turn the answer into an error (which the
    /// 0.9 docs told callers to answer with the peer, a trusted proxy).
    #[test]
    fn test_client_text_left_of_the_client_is_never_read() {
        let lb = ip4("10.0.0.2");
        let t = |a: IpAddr| a == lb;
        let real = ClientAddress::Forwarded {
            addr: ip4("198.51.100.7"),
            hops: 1,
        };
        let xff = |lines: &[&[u8]]| client_address(lb, ForwardedSource::XForwardedFor(lines), &t);
        let fwd = |lines: &[&[u8]]| client_address(lb, ForwardedSource::Forwarded(lines), &t);
        assert_eq!(xff(&[b"x, 198.51.100.7"]), real);
        assert_eq!(xff(&[b"x", b"198.51.100.7"]), real);
        assert_eq!(xff(&[b"unknown, 198.51.100.7"]), real);
        assert_eq!(xff(&[b"unknown", b"198.51.100.7"]), real);
        assert_eq!(xff(&[b"\x00\x7f, , 198.51.100.7"]), real);
        let mut padded = std::string::String::new();
        for i in 0..40 {
            padded.push_str(&std::format!("192.0.2.{i}, "));
        }
        padded.push_str("198.51.100.7");
        assert_eq!(xff(&[padded.as_bytes()]), real);
        assert_eq!(fwd(&[b"for=nonsense, for=198.51.100.7"]), real);
        assert_eq!(fwd(&[b"for=nonsense", b"for=198.51.100.7"]), real);
        assert_eq!(fwd(&[b"for=\"x", b"for=198.51.100.7"]), real);
        assert_eq!(
            fwd(&[b"(, for=\"a,b\";by=\"\\\"\", for=198.51.100.7"]),
            real
        );
        // An unclosed quote on the proxy's own line swallows its element:
        // nothing reliable is left.
        assert_eq!(
            fwd(&[b"for=\"x, for=198.51.100.7"]),
            ClientAddress::Unknown { hops: 1 }
        );
    }

    #[test]
    fn test_unreliable_entry_at_the_decision_point() {
        let t = |_: IpAddr| true;
        let peer = ip4("10.0.0.1");
        let lines: [&[u8]; 2] = [b"1.1.1.1", b"10.0.0.2, nope"];
        assert_eq!(
            client_address(peer, ForwardedSource::XForwardedFor(&lines), &t),
            ClientAddress::Unknown { hops: 1 }
        );
        let lines: [&[u8]; 1] = [b"1.1.1.1, 1.1.1.2, 1.1.1.3"];
        let two = Limits::DEFAULT.max_hops(2);
        assert_eq!(
            client_address_with_limits(peer, ForwardedSource::XForwardedFor(&lines), &t, &two),
            ClientAddress::Unknown { hops: 2 }
        );
        let three = Limits::DEFAULT.max_hops(3);
        assert_eq!(
            client_address_with_limits(peer, ForwardedSource::XForwardedFor(&lines), &t, &three),
            ClientAddress::Forwarded {
                addr: ip4("1.1.1.1"),
                hops: 3
            }
        );
        let blank: [&[u8]; 2] = [b"1.1.1.1", b"  "];
        assert_eq!(
            client_address(peer, ForwardedSource::XForwardedFor(&blank), &t),
            ClientAddress::Forwarded {
                addr: ip4("1.1.1.1"),
                hops: 1
            }
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
            )
        };
        assert_eq!(
            x(b"127.0.0.1, 10.0.0.1"),
            ClientAddress::Forwarded {
                addr: ip4("127.0.0.1"),
                hops: 2
            }
        );
        let none: [&[u8]; 0] = [];
        assert_eq!(
            client_address(peer, ForwardedSource::XForwardedFor(&none), &t),
            ClientAddress::Peer(peer)
        );
        let f = |v: &'static [u8]| {
            client_address(
                peer,
                ForwardedSource::Forwarded(std::boxed::Box::leak(std::boxed::Box::new([v]))),
                &t,
            )
        };
        assert_eq!(
            f(b"for=192.0.2.1, for=unknown, for=127.0.0.1"),
            ClientAddress::Unknown { hops: 2 }
        );
        assert_eq!(
            f(b"for=192.0.2.1, for=_hidden"),
            ClientAddress::Unknown { hops: 1 }
        );
        assert_eq!(
            f(b"for=192.0.2.1, proto=https"),
            ClientAddress::Unknown { hops: 1 }
        );
        assert_eq!(
            f(b"for=\"[2001:db8::7]\""),
            ClientAddress::Forwarded {
                addr: "2001:db8::7".parse().unwrap(),
                hops: 1
            }
        );
        assert_eq!(f(b"for=2001:db8::7"), ClientAddress::Unknown { hops: 1 });
        assert_eq!(
            f(b"for=192.0.2.1,, for=127.0.0.1 ,"),
            ClientAddress::Forwarded {
                addr: ip4("192.0.2.1"),
                hops: 2
            }
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
            &Limits::DEFAULT,
        );
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
                &Limits::DEFAULT
            )
            .other_present
        );
    }

    #[test]
    fn test_x_forwarded_proto_and_host() {
        assert_eq!(parse_x_forwarded_proto(b"http, HTTP"), Ok(Proto::Http));
        assert!(parse_x_forwarded_proto(b"").is_err());
        assert_eq!(parse_x_forwarded_proto(b"wss"), Ok(Proto::Wss));
        assert_eq!(parse_x_forwarded_proto(b"ftp"), Ok(Proto::Other));
        assert!(parse_x_forwarded_proto(b"ftp, sftp").is_err());
        assert!(parse_x_forwarded_proto(b"1x").is_err());
        assert!(parse_x_forwarded_host(b"[::1]:8080").is_ok());
        assert_eq!(
            parse_x_forwarded_host(b"a,b").unwrap_err().kind(),
            ErrorKind::Malformed
        );
    }

    /// The 0.8 member reader and a collect-then-walk resolver, kept as the
    /// references the one-pass versions are compared with.
    mod reference {
        use super::super::*;
        use std::vec::Vec;

        pub(super) fn xff_member(m: &[u8]) -> Option<(IpAddr, Option<u16>)> {
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
            let v4 = |t: &[u8]| {
                core::str::from_utf8(t)
                    .ok()?
                    .parse::<Ipv4Addr>()
                    .ok()
                    .map(IpAddr::V4)
            };
            let mut colons = m.iter().enumerate().filter(|&(_, &b)| b == b':');
            match (colons.next(), colons.next()) {
                (None, _) => Some((v4(m)?, None)),
                (Some((c, _)), None) => Some((v4(m.get(..c)?)?, port(m.get(c + 1..)?)?)),
                (Some(_), Some(_)) => Some((ip(m, true)?, None)),
            }
        }

        /// Every entry, left to right; `None` has no usable address.
        fn xff_entries(lines: &[&[u8]]) -> Vec<Option<IpAddr>> {
            let mut out = Vec::new();
            for line in lines.iter().filter(|l| !trim_ows(l).is_empty()) {
                for m in line.split(|&b| b == b',') {
                    out.push(super::super::xff_member(trim_ows(m)).map(|(a, _)| a));
                }
            }
            out
        }

        /// One line split left to right at commas outside quoted strings;
        /// `None` when a quoted string is not closed.
        fn split(line: &[u8]) -> Option<Vec<&[u8]>> {
            let (mut out, mut start) = (Vec::new(), 0);
            let (mut quoted, mut escaped) = (false, false);
            for (i, &b) in line.iter().enumerate() {
                if escaped {
                    escaped = false;
                } else if quoted && b == b'\\' {
                    escaped = true;
                } else if b == b'"' {
                    quoted = !quoted;
                } else if b == b',' && !quoted {
                    out.push(&line[start..i]);
                    start = i + 1;
                }
            }
            if quoted {
                return None;
            }
            out.push(&line[start..]);
            Some(out)
        }

        fn forwarded_entries(lines: &[&[u8]]) -> Vec<Option<IpAddr>> {
            let mut out = Vec::new();
            for line in lines {
                let Some(elements) = split(line) else {
                    out.push(None);
                    continue;
                };
                for e in elements.into_iter().map(trim_ows).filter(|e| !e.is_empty()) {
                    out.push(match element(e).map(|e| e.for_) {
                        Ok(Some(Node::Addr(a, _))) => Some(a),
                        _ => None,
                    });
                }
            }
            out
        }

        pub(super) fn client_address(
            peer: IpAddr,
            source: ForwardedSource<'_>,
            trust: &impl Trust,
            limit: u8,
        ) -> ClientAddress {
            if !trust.is_trusted(peer) {
                return ClientAddress::Peer(peer);
            }
            let entries = match source {
                ForwardedSource::XForwardedFor(lines) => xff_entries(lines),
                ForwardedSource::Forwarded(lines) => forwarded_entries(lines),
            };
            let mut leftmost = None;
            for (walked, e) in entries.iter().rev().enumerate() {
                if walked == usize::from(limit) {
                    return ClientAddress::Unknown { hops: limit };
                }
                let hops = u8::try_from(walked + 1).unwrap();
                match *e {
                    Some(a) if trust.is_trusted(a) => leftmost = Some(a),
                    Some(addr) => return ClientAddress::Forwarded { addr, hops },
                    None => return ClientAddress::Unknown { hops },
                }
            }
            match leftmost {
                Some(addr) => ClientAddress::Forwarded {
                    addr,
                    hops: u8::try_from(entries.len()).unwrap(),
                },
                None => ClientAddress::Peer(peer),
            }
        }
    }

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(4096))]

        #[test]
        fn test_xff_member_agrees_with_reference(
            text in "[0-9a-f.:\\[\\]]{0,28}",
            shaped in "(25[0-9]|1?[0-9]{1,2})\\.(0|[0-9]{1,3})\\.[0-9]{1,3}\\.[0-9]{1,3}(:[0-9_a]{0,6})?",
        ) {
            proptest::prop_assert_eq!(xff_member(text.as_bytes()), reference::xff_member(text.as_bytes()));
            proptest::prop_assert_eq!(xff_member(shaped.as_bytes()), reference::xff_member(shaped.as_bytes()));
        }

        #[test]
        fn test_client_address_agrees_with_reference(
            xff in proptest::collection::vec(proptest::sample::select(&[
                "10.0.0.1", "10.0.0.2", "1.2.3.4", "198.51.100.7:80", "[2001:db8::1]:443",
                "2001:db8::2", "::1", "", "  ", "bad", "unknown", "01.2.3.4", "1.2.3", "1.2.3.4:99999", "[::1",
            ][..]), 0..12),
            fwd in proptest::collection::vec(proptest::sample::select(&[
                "for=10.0.0.1", "for=10.0.0.2;proto=http", "for=1.2.3.4", "for=unknown",
                "for=_hidden", "proto=https", "for=\"[2001:db8::1]:80\"", "for=\"::1\"",
                "by=10.0.0.1;for=198.51.100.7", "bad", "for=", "", " ",
                r#"for="a,b""#, r#"for="x"#, r#"by="\",";for=10.0.0.2"#, r#"x\"y"#,
                r#"for="10.0.0.1\\""#, "(c, d)",
            ][..]), 0..12),
            cuts in proptest::collection::vec(proptest::bool::ANY, 12),
            max_hops in 0u8..10,
            trusted_peer in proptest::bool::ANY,
        ) {
            // Joined with commas, some of them line breaks, so a chain spans
            // several field lines.
            fn lines<'a>(members: &[&str], cuts: &[bool], store: &'a mut Vec<std::string::String>) -> Vec<&'a [u8]> {
                let mut cur = std::string::String::new();
                for (i, m) in members.iter().enumerate() {
                    if i > 0 && cuts[i] {
                        store.push(core::mem::take(&mut cur));
                    } else if i > 0 {
                        cur.push_str(", ");
                    }
                    cur.push_str(m);
                }
                if !members.is_empty() {
                    store.push(cur);
                }
                store.iter().map(|s| s.as_bytes()).collect()
            }
            let peer = if trusted_peer { v4("10.0.0.1") } else { v4("203.0.113.1") };
            let trust = |a: IpAddr| a == v4("10.0.0.1") || a == v4("10.0.0.2") || a == v4("::1");
            let limits = Limits::DEFAULT.max_hops(max_hops);
            let mut store = Vec::new();
            let ls = lines(&xff, &cuts, &mut store);
            proptest::prop_assert_eq!(
                client_address_with_limits(peer, ForwardedSource::XForwardedFor(&ls), &trust, &limits),
                reference::client_address(peer, ForwardedSource::XForwardedFor(&ls), &trust, max_hops)
            );
            let mut store = Vec::new();
            let ls = lines(&fwd, &cuts, &mut store);
            proptest::prop_assert_eq!(
                client_address_with_limits(peer, ForwardedSource::Forwarded(&ls), &trust, &limits),
                reference::client_address(peer, ForwardedSource::Forwarded(&ls), &trust, max_hops)
            );
        }
    }
}
