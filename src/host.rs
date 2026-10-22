//! `Host = uri-host [ ":" port ]` (RFC 9110 section 7.2, citing RFC 3986
//! section 3.2.2), with real IPv4 and IPv6 validation.
//!
//! # Examples
//!
//! ```
//! use core::net::Ipv6Addr;
//! use parse_net::{self as pn, Host, HostPort};
//!
//! assert_eq!(pn::parse_host_port(b"[::1]:8080")?,
//!            HostPort { host: Host::V6(Ipv6Addr::LOCALHOST), port: Some(8080), empty_port: false });
//! assert_eq!(pn::parse_host_port(b"Example.COM.")?.host, Host::Name(b"Example.COM."));
//! assert_eq!(pn::parse_host_port(b"127.1").unwrap_err().kind(), pn::ErrorKind::InvalidAddress);
//! assert_eq!(pn::parse_host_port(b"a.com:80@b.com").unwrap_err().kind(), pn::ErrorKind::InvalidHost);
//! # Ok::<(), pn::ParseError>(())
//! ```

use core::{
    fmt::{self, Write as _},
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use crate::{
    class,
    error::{ErrorKind, Result, WriteError, err},
    scan::{control_kind, find_byte},
    text::{skip_ows, trim_ows},
    write::{CountSink, Sink, reserve},
};

/// A host: a registered name, an IP address, or a future IP literal.
///
/// # Examples
///
/// ```
/// use core::net::Ipv4Addr;
/// use parse_net::{parse_host_port, Host};
///
/// assert_eq!(parse_host_port(b"192.0.2.1")?.host, Host::V4(Ipv4Addr::new(192, 0, 2, 1)));
/// assert_eq!(parse_host_port(b"example.com")?.host, Host::Name(b"example.com"));
/// assert_eq!(parse_host_port(b"[v1.fe]")?.host, Host::Future(b"v1.fe"));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Host<'a> {
    /// A registered name (`reg-name`), as sent: case and a trailing dot are
    /// kept, `%XX` triples are not decoded. Empty when the field was empty.
    Name(&'a [u8]),
    /// A dotted-decimal IPv4 address.
    V4(Ipv4Addr),
    /// A bracketed IPv6 address.
    V6(Ipv6Addr),
    /// A bracketed `IPvFuture` literal (`vX.yyy`), without the brackets.
    Future(&'a [u8]),
}

impl Host<'_> {
    /// Whether two hosts are the same: names compared ASCII
    /// case-insensitively, IP literals by value.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::host::parse_host;
    ///
    /// assert!(parse_host(b"Example.com")?.eq_ignore_ascii_case(&parse_host(b"example.COM")?));
    /// assert!(parse_host(b"[::1]")?.eq_ignore_ascii_case(&parse_host(b"[0:0::1]")?));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn eq_ignore_ascii_case(&self, other: &Host<'_>) -> bool {
        match (self, other) {
            (Host::Name(a), Host::Name(b)) | (Host::Future(a), Host::Future(b)) => {
                a.eq_ignore_ascii_case(b)
            }
            (Host::V4(a), Host::V4(b)) => a == b,
            (Host::V6(a), Host::V6(b)) => a == b,
            _ => false,
        }
    }

    /// Whether this is the empty name of an empty `Host` field.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::parse_host_port;
    ///
    /// assert!(parse_host_port(b"")?.host.is_empty());
    /// assert!(!parse_host_port(b"example.com")?.host.is_empty());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self, Host::Name(n) if n.is_empty())
    }

    /// Writes the host: names as given, IPv6 bracketed in its RFC 5952 form.
    ///
    /// # Errors
    ///
    /// [`WriteError::Full`]; nothing is written when the sink reports its
    /// room.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{host::parse_host, SliceSink};
    ///
    /// let mut buf = [0u8; 64];
    /// let mut out = SliceSink::new(&mut buf);
    /// parse_host(b"[2001:DB8:0:0:0:0:0:1]")?.write_to(&mut out).expect("room");
    /// assert_eq!(out.written(), b"[2001:db8::1]");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn write_to(&self, out: &mut impl Sink) -> core::result::Result<(), WriteError> {
        let mut count = CountSink::new();
        self.put(&mut count)?;
        reserve(out, count.count())?;
        self.put(out)
    }

    fn put(&self, out: &mut impl Sink) -> core::result::Result<(), WriteError> {
        match self {
            Host::Name(n) => out.put(n)?,
            Host::V4(a) => write!(SinkWriter(out), "{a}").map_err(|_| WriteError::Full)?,
            Host::V6(a) => write!(SinkWriter(out), "[{a}]").map_err(|_| WriteError::Full)?,
            Host::Future(f) => {
                out.put(b"[")?;
                out.put(f)?;
                out.put(b"]")?;
            }
        }
        Ok(())
    }
}

/// Lets `core::fmt` write into a [`Sink`].
pub(crate) struct SinkWriter<'s, S: Sink>(pub(crate) &'s mut S);

impl<S: Sink> fmt::Write for SinkWriter<'_, S> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.put(s.as_bytes()).map_err(|_| fmt::Error)
    }
}

/// A host and an optional port.
///
/// # Examples
///
/// ```
/// use parse_net::{parse_host_port, Host};
///
/// let hp = parse_host_port(b"example.com:")?;
/// assert_eq!((hp.host, hp.port, hp.empty_port), (Host::Name(b"example.com"), None, true));
/// assert_eq!(parse_host_port(b"example.com:8080")?.port, Some(8080));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HostPort<'a> {
    /// The host.
    pub host: Host<'a>,
    /// The port, when digits followed the `:`.
    pub port: Option<u16>,
    /// Whether a `:` with no digits followed the host (`example.com:`),
    /// which RFC 3986 allows (`port = *DIGIT`).
    pub empty_port: bool,
}

impl HostPort<'_> {
    /// Writes the host, then `:port` when there is a port.
    ///
    /// # Errors
    ///
    /// [`WriteError::Full`]; nothing is written when the sink reports its
    /// room.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{parse_host_port, SliceSink};
    ///
    /// let mut buf = [0u8; 64];
    /// let mut out = SliceSink::new(&mut buf);
    /// parse_host_port(b"[::1]:8080")?.write_to(&mut out).expect("room");
    /// assert_eq!(out.written(), b"[::1]:8080");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn write_to(&self, out: &mut impl Sink) -> core::result::Result<(), WriteError> {
        let mut count = CountSink::new();
        self.put(&mut count)?;
        reserve(out, count.count())?;
        self.put(out)
    }

    fn put(&self, out: &mut impl Sink) -> core::result::Result<(), WriteError> {
        self.host.put(out)?;
        if let Some(port) = self.port {
            out.put(b":")?;
            crate::write::write_decimal_u64(u64::from(port), out)?;
        }
        Ok(())
    }
}

/// Parses a `Host` value: `uri-host [ ":" port ]`.
///
/// A registered name (`unreserved / pct-encoded / sub-delims`), a
/// dotted-decimal IPv4 address with no leading zeros, a bracketed IPv6
/// address in any RFC 4291 text form, or a bracketed IPvFuture literal,
/// optionally followed by `:` and a port up to 65535. An empty port is
/// accepted with `empty_port` set. An empty value is accepted as an empty
/// name (RFC 9112 section 3.2: the target has no authority); the caller
/// decides what that means.
///
/// A name made only of digits and dots, or whose last label is a number
/// (`127.1`, `0x7f.1`, `example.123`), must be a canonical IPv4 address:
/// RFC 3986 reads such hosts as names and the WHATWG URL standard as IPv4
/// addresses, and refusing them removes the disagreement.
///
/// # Errors
///
/// [`ErrorKind::InvalidHost`] for userinfo (any `@`, checked first), a byte
/// outside the name class, a port with no host, or unbracketed IPv6;
/// [`ErrorKind::InvalidAddress`] for a malformed IP literal or a numeric
/// name that is not canonical IPv4; [`ErrorKind::InvalidPort`];
/// [`ErrorKind::InvalidPercentEncoding`]; a control kind for a control byte.
///
/// # Examples
///
/// ```
/// use parse_net::{parse_host_port, ErrorKind};
///
/// let hp = parse_host_port(b"example.com:8443")?;
/// assert_eq!(hp.port, Some(8443));
/// assert_eq!(parse_host_port(b"a:65536").unwrap_err().kind(), ErrorKind::InvalidPort);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_host_port(value: &[u8]) -> Result<HostPort<'_>> {
    let lead = skip_ows(value);
    host_port(trim_ows(value)).map_err(|e| e.shifted(lead))
}

/// Parses `host [ ":" port ]` exactly as given, for a URI authority or a
/// request target: unlike [`parse_host_port`], no OWS is stripped, so any
/// whitespace is refused.
///
/// Use this wherever the bytes are not a field value: an authority-form or
/// absolute-form request target, a URL, a `Forwarded` node. Stripping
/// whitespace there would accept `CONNECT  example.com:443` (two spaces),
/// which other parsers refuse.
///
/// # Errors
///
/// As [`parse_host_port`]; whitespace is refused like any other byte outside
/// the grammar ([`ErrorKind::InvalidHost`] in the host, [`ErrorKind::InvalidPort`]
/// after a port).
///
/// # Examples
///
/// ```
/// use parse_net::{host::parse_uri_host_port, parse_host_port};
///
/// assert!(parse_host_port(b" example.com:443").is_ok());
/// assert!(parse_uri_host_port(b" example.com:443").is_err());
/// assert_eq!(parse_uri_host_port(b"example.com:443")?.port, Some(443));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_uri_host_port(value: &[u8]) -> Result<HostPort<'_>> {
    host_port(value)
}

/// Parses a host with no port.
///
/// # Errors
///
/// As [`parse_host_port`], and [`ErrorKind::InvalidHost`] for a port.
///
/// # Examples
///
/// ```
/// use parse_net::{host::parse_host, Host};
///
/// assert_eq!(parse_host(b"192.0.2.1")?, Host::V4([192, 0, 2, 1].into()));
/// assert!(parse_host(b"a.example:80").is_err());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_host(value: &[u8]) -> Result<Host<'_>> {
    let hp = parse_host_port(value)?;
    if hp.port.is_some() || hp.empty_port {
        let at = skip_ows(value) + value.iter().rposition(|&b| b == b':').unwrap_or(0);
        return err(ErrorKind::InvalidHost, at.min(value.len()));
    }
    Ok(hp.host)
}

pub(crate) fn host_port(v: &[u8]) -> Result<HostPort<'_>> {
    host_port_inner(v).map_err(|e| userinfo_first(v, e))
}

/// Userinfo is the attack (`a.com:80@b.com`): whatever else is wrong with the
/// value, an `@` anywhere is reported as `InvalidHost` at the `@`.
#[cold]
fn userinfo_first(v: &[u8], e: crate::ParseError) -> crate::ParseError {
    match find_byte(b'@', v) {
        Some(at) => crate::ParseError::new(ErrorKind::InvalidHost, at),
        None => e,
    }
}

fn host_port_inner(v: &[u8]) -> Result<HostPort<'_>> {
    let (host, rest, rest_at) = if v.first() == Some(&b'[') {
        let Some(close) = find_byte(b']', v) else {
            return err(ErrorKind::InvalidAddress, v.len());
        };
        let inner = v.get(1..close).unwrap_or(&[]);
        (
            ip_literal(inner)?,
            v.get(close + 1..).unwrap_or(&[]),
            close + 1,
        )
    } else {
        let (host, colon) = reg_name_or_ipv4(v)?;
        let rest = v.get(colon..).unwrap_or(&[]);
        if colon == 0 && !rest.is_empty() {
            return err(ErrorKind::InvalidHost, 0);
        }
        (host, rest, colon)
    };
    let (port, empty_port) = match rest.split_first() {
        None => (None, false),
        Some((b':', digits)) => port(digits).map_err(|e| e.shifted(rest_at + 1))?,
        Some(_) => return err(ErrorKind::InvalidHost, rest_at),
    };
    Ok(HostPort {
        host,
        port,
        empty_port,
    })
}

fn port(digits: &[u8]) -> Result<(Option<u16>, bool)> {
    if digits.is_empty() {
        return Ok((None, true));
    }
    let mut n: u32 = 0;
    for (i, &d) in digits.iter().enumerate() {
        if !d.is_ascii_digit() {
            // A second ":" means unbracketed IPv6.
            let kind = if d == b':' {
                ErrorKind::InvalidHost
            } else {
                ErrorKind::InvalidPort
            };
            return err(kind, i);
        }
        n = n * 10 + u32::from(d - b'0');
        if n > 65_535 {
            return err(ErrorKind::InvalidPort, i);
        }
    }
    // `n` is at most 65535.
    Ok((u16::try_from(n).ok(), false))
}

fn ip_literal(inner: &[u8]) -> Result<Host<'_>> {
    // Offsets inside the brackets are reported from the "[".
    match inner.first() {
        Some(b'v' | b'V') => {
            // IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
            let rest = inner.get(1..).unwrap_or(&[]);
            let hex = rest.iter().take_while(|&&b| class::is_hexdig(b)).count();
            let after = rest.get(hex..).unwrap_or(&[]);
            let tail_ok = match after.split_first() {
                Some((b'.', tail)) => {
                    !tail.is_empty()
                        && tail.iter().all(|&b| {
                            class::is_unreserved(b) || class::is_sub_delim(b) || b == b':'
                        })
                }
                _ => false,
            };
            if hex == 0 || !tail_ok {
                return err(ErrorKind::InvalidAddress, 1);
            }
            Ok(Host::Future(inner))
        }
        _ => {
            let text = core::str::from_utf8(inner)
                .map_err(|_| crate::ParseError::new(ErrorKind::InvalidAddress, 1))?;
            match Ipv6Addr::from_str(text) {
                Ok(a) => Ok(Host::V6(a)),
                Err(_) => err(ErrorKind::InvalidAddress, 1),
            }
        }
    }
}

/// Whether `label` is a number in the WHATWG sense: decimal digits, or `0x`
/// followed by hex digits.
fn is_numeric_label(label: &[u8]) -> bool {
    match label {
        [] => false,
        [b'0', b'x' | b'X', hex @ ..] => hex.iter().all(|&b| class::is_hexdig(b)),
        _ => label.iter().all(u8::is_ascii_digit),
    }
}

/// `unreserved / sub-delims`: the reg-name bytes other than `pct-encoded`.
const REG_NAME: class::Class = class::Class::UNRESERVED.union(class::Class::SUB_DELIM);

/// Reads the name at the start of `v` up to a `:` or the end, in one pass:
/// validates it as a reg-name and notes whether it could be read as IPv4.
/// Returns the host and the offset where the name ended.
fn reg_name_or_ipv4(v: &[u8]) -> Result<(Host<'_>, usize)> {
    let mut i = 0usize;
    let mut digits_dots = true;
    let mut label_start = 0usize;
    let mut prev_label_start = 0usize;
    while let Some(&b) = v.get(i) {
        if REG_NAME.contains(b) {
            if b == b'.' {
                prev_label_start = label_start;
                label_start = i + 1;
            } else if !b.is_ascii_digit() {
                digits_dots = false;
            }
            i += 1;
        } else if b == b':' {
            break;
        } else if b == b'%' {
            match (v.get(i + 1), v.get(i + 2)) {
                (Some(&h), Some(&l)) if class::is_hexdig(h) && class::is_hexdig(l) => i += 3,
                _ => return err(ErrorKind::InvalidPercentEncoding, i),
            }
            digits_dots = false;
        } else if crate::scan::is_control(b) {
            return err(control_kind(b), i);
        } else {
            return err(ErrorKind::InvalidHost, i);
        }
    }
    let name = v.get(..i).unwrap_or(&[]);
    // The last label, ignoring one trailing dot.
    let last = if name.last() == Some(&b'.') {
        name.get(prev_label_start..i - 1).unwrap_or(&[])
    } else {
        name.get(label_start..).unwrap_or(&[])
    };
    if (digits_dots && !name.is_empty()) || is_numeric_label(last) {
        return match ipv4(name) {
            Some(a) => Ok((Host::V4(a), i)),
            None => err(ErrorKind::InvalidAddress, 0),
        };
    }
    Ok((Host::Name(name), i))
}

/// Canonical dotted decimal: four parts, 0 to 255, no leading zeros.
fn ipv4(s: &[u8]) -> Option<Ipv4Addr> {
    let mut octets = [0u8; 4];
    let mut parts = s.split(|&b| b == b'.');
    for slot in &mut octets {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 3 || (part.len() > 1 && part.first() == Some(&b'0')) {
            return None;
        }
        let mut n: u16 = 0;
        for &d in part {
            if !d.is_ascii_digit() {
                return None;
            }
            n = n * 10 + u16::from(d - b'0');
        }
        *slot = u8::try_from(n).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(Ipv4Addr::from(octets))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hp(v: &[u8]) -> Result<HostPort<'_>> {
        parse_host_port(v)
    }

    #[test]
    fn test_host_edge_cases() {
        use ErrorKind::*;
        assert!(hp(b"").unwrap().host.is_empty());
        assert_eq!(hp(b"a").unwrap().host, Host::Name(b"a"));
        let e = hp(b"a:").unwrap();
        assert_eq!((e.port, e.empty_port), (None, true));
        assert_eq!(hp(b"a:0").unwrap().port, Some(0));
        assert_eq!(hp(b"a:65535").unwrap().port, Some(65535));
        assert_eq!(hp(b"a:65536").unwrap_err().kind(), InvalidPort);
        assert_eq!(hp(b"a:-1").unwrap_err().kind(), InvalidPort);
        assert_eq!(hp(b"a:8x").unwrap_err().kind(), InvalidPort);
        assert_eq!(hp(b"[::1]").unwrap().host, Host::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(hp(b"[::1]:80").unwrap().port, Some(80));
        assert_eq!(hp(b"[::1").unwrap_err().kind(), InvalidAddress);
        assert_eq!(hp(b"[zz]").unwrap_err().kind(), InvalidAddress);
        assert_eq!(hp(b"[]").unwrap_err().kind(), InvalidAddress);
        assert_eq!(hp(b"::1").unwrap_err().kind(), InvalidHost);
        assert_eq!(hp(b"a:1:2").unwrap_err().kind(), InvalidHost);
        assert_eq!(hp(b"[v1.x]").unwrap().host, Host::Future(b"v1.x"));
        assert_eq!(hp(b"[v.x]").unwrap_err().kind(), InvalidAddress);
        assert_eq!(hp(b"[v1.]").unwrap_err().kind(), InvalidAddress);
        assert_eq!(
            hp(b"1.2.3.4").unwrap().host,
            Host::V4(Ipv4Addr::new(1, 2, 3, 4))
        );
        assert_eq!(hp(b"[::1]x").unwrap_err().kind(), InvalidHost);
        assert_eq!(hp(b"%41.com").unwrap().host, Host::Name(b"%41.com"));
        assert_eq!(hp(b"%4.com").unwrap_err().kind(), InvalidPercentEncoding);
        assert_eq!(hp(b"a b").unwrap_err().kind(), InvalidHost);
        assert_eq!(hp(b"a/b").unwrap_err().kind(), InvalidHost);
        assert_eq!(
            hp(b"example.com.").unwrap().host,
            Host::Name(b"example.com.")
        );
        assert_eq!(hp(b":80").unwrap_err().kind(), InvalidHost);
        assert_eq!(hp(b"a\rb").unwrap_err().kind(), BareCr);
    }

    #[test]
    fn test_host_partial_ipv4_refused() {
        for v in [
            &b"1.2.3"[..],
            b"01.2.3.4",
            b"256.0.0.1",
            b"127.1",
            b"0x7f.0.0.1",
            b"1.2.3.4.",
            b"example.123",
            b"a.0x10",
            b"1..2.3",
        ] {
            assert_eq!(
                hp(v).unwrap_err().kind(),
                ErrorKind::InvalidAddress,
                "{}",
                std::string::String::from_utf8_lossy(v)
            );
        }
        assert_eq!(hp(b"123.example").unwrap().host, Host::Name(b"123.example"));
        assert_eq!(
            hp(b"0.0.0.0").unwrap().host,
            Host::V4(Ipv4Addr::UNSPECIFIED)
        );
    }

    #[test]
    fn test_host_userinfo_refused() {
        let e = hp(b"a.com:80@b.com").unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::InvalidHost, 8));
        assert_eq!(
            hp(b"user@b.com").unwrap_err().kind(),
            ErrorKind::InvalidHost
        );
        assert_eq!(hp(b"[::1]@x").unwrap_err().kind(), ErrorKind::InvalidHost);
    }

    #[test]
    fn test_ipv6_text_forms() {
        for v in [
            &b"[::]"[..],
            b"[::1]",
            b"[2001:db8::1]",
            b"[2001:DB8:0:0:8:800:200C:417A]",
            b"[::ffff:192.0.2.1]",
            b"[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]",
            b"[1::]",
        ] {
            assert!(
                matches!(hp(v).unwrap().host, Host::V6(_)),
                "{}",
                std::string::String::from_utf8_lossy(v)
            );
        }
        for v in [
            &b"[1:2:3:4:5:6:7:8:9]"[..],
            b"[12345::]",
            b"[::1%25eth0]",
            b"[:::]",
            b"[1::2::3]",
        ] {
            assert_eq!(hp(v).unwrap_err().kind(), ErrorKind::InvalidAddress);
        }
    }

    #[test]
    fn test_host_compare_and_write() {
        assert!(Host::V6(Ipv6Addr::LOCALHOST).eq_ignore_ascii_case(&hp(b"[0:0::1]").unwrap().host));
        assert!(!Host::Name(b"a").eq_ignore_ascii_case(&Host::V4(Ipv4Addr::LOCALHOST)));
        let mut buf = [0u8; 64];
        let mut out = crate::SliceSink::new(&mut buf);
        hp(b"1.2.3.4:5").unwrap().write_to(&mut out).unwrap();
        assert_eq!(out.written(), b"1.2.3.4:5");
        let mut small = [0u8; 3];
        let mut out = crate::SliceSink::new(&mut small);
        assert_eq!(
            hp(b"[::1]").unwrap().write_to(&mut out),
            Err(WriteError::Full)
        );
        assert!(out.is_empty());
        assert_eq!(
            parse_host(b"a:").unwrap_err().kind(),
            ErrorKind::InvalidHost
        );
    }
}
