//! `Origin` (RFC 6454 section 7): `null` or `scheme "://" host [ ":" port ]`.
//!
//! # Examples
//!
//! ```
//! use parse_net::{self as pn, OriginValue};
//!
//! let OriginValue::Origin(a) = pn::parse_origin(b"https://app.example.com")? else { unreachable!() };
//! let OriginValue::Origin(b) = pn::parse_origin(b"HTTPS://APP.example.com:443")? else { unreachable!() };
//! assert!(a.same_origin(&b));
//! let OriginValue::Origin(evil) = pn::parse_origin(b"https://app.example.com.evil.test")? else { unreachable!() };
//! assert!(!a.same_origin(&evil));
//! assert_eq!(pn::parse_origin(b"https://app.example.com/").unwrap_err().kind(), pn::ErrorKind::InvalidOrigin);
//! # Ok::<(), pn::ParseError>(())
//! ```

use crate::{
    error::{ErrorKind, ParseError, Result, WriteError, err},
    host::{Host, HostPort, host_port},
    text::{skip_ows, trim_ows},
    write::{CountSink, Sink, reserve, write_decimal_u64},
};

/// An `Origin` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OriginValue<'a> {
    /// `null` (an opaque origin: a sandboxed frame, a `data:` URL, a
    /// privacy-sensitive redirect).
    Null,
    /// A serialized origin.
    Origin(Origin<'a>),
}

/// A serialized origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Origin<'a> {
    /// The scheme as sent (compare it ASCII case-insensitively).
    pub scheme: &'a [u8],
    /// The host.
    pub host: Host<'a>,
    /// The port, when one was given.
    pub port: Option<u16>,
}

impl Origin<'_> {
    /// The port, or the scheme's default: 80 for `http` and `ws`, 443 for
    /// `https` and `wss`; `None` for another scheme without a port.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{parse_origin, OriginValue};
    ///
    /// let OriginValue::Origin(o) = parse_origin(b"wss://chat.example")? else { unreachable!() };
    /// assert_eq!(o.effective_port(), Some(443));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn effective_port(&self) -> Option<u16> {
        self.port.or_else(|| {
            let s = self.scheme;
            if s.eq_ignore_ascii_case(b"http") || s.eq_ignore_ascii_case(b"ws") {
                Some(80)
            } else if s.eq_ignore_ascii_case(b"https") || s.eq_ignore_ascii_case(b"wss") {
                Some(443)
            } else {
                None
            }
        })
    }

    /// Whether two origins are the same: schemes and hosts equal as whole
    /// values (ASCII case-insensitive, IP literals by value), effective ports
    /// equal. Never a prefix or suffix comparison.
    #[must_use]
    pub fn same_origin(&self, other: &Origin<'_>) -> bool {
        self.scheme.eq_ignore_ascii_case(other.scheme)
            && self.host.eq_ignore_ascii_case(&other.host)
            && self.effective_port() == other.effective_port()
    }

    /// Writes the origin with a lowercase scheme and without a default port.
    ///
    /// # Errors
    ///
    /// [`WriteError::Full`]; nothing is written when the sink reports its
    /// room.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{parse_origin, OriginValue, SliceSink};
    ///
    /// let OriginValue::Origin(o) = parse_origin(b"HTTPS://a.example:443")? else { unreachable!() };
    /// let mut buf = [0u8; 64];
    /// let mut out = SliceSink::new(&mut buf);
    /// o.write_to(&mut out).expect("room");
    /// assert_eq!(out.written(), b"https://a.example");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn write_to(&self, out: &mut impl Sink) -> core::result::Result<(), WriteError> {
        let mut count = CountSink::new();
        self.put(&mut count)?;
        reserve(out, count.count())?;
        self.put(out)
    }

    fn put(&self, out: &mut impl Sink) -> core::result::Result<(), WriteError> {
        let mut scheme = [0u8; 32];
        for chunk in self.scheme.chunks(scheme.len()) {
            let dst = scheme.get_mut(..chunk.len()).unwrap_or(&mut []);
            for (d, &c) in dst.iter_mut().zip(chunk) {
                *d = c.to_ascii_lowercase();
            }
            out.put(dst)?;
        }
        out.put(b"://")?;
        HostPort {
            host: self.host,
            port: None,
            empty_port: false,
        }
        .write_to(out)?;
        let default = Origin {
            port: None,
            ..*self
        }
        .effective_port();
        if let Some(p) = self.port.filter(|&p| Some(p) != default) {
            out.put(b":")?;
            write_decimal_u64(u64::from(p), out)?;
        }
        Ok(())
    }
}

/// Parses an `Origin` value.
///
/// `null` is case-sensitive. The scheme is a letter followed by letters,
/// digits, `+`, `-`, or `.`; the host follows the `Host` rules and may not
/// be empty; a path, query, fragment, trailing `/`, userinfo, or empty port
/// is refused.
///
/// # Errors
///
/// [`ErrorKind::InvalidOrigin`]; the `Host` errors for the host part.
///
/// # Examples
///
/// ```
/// use parse_net::{parse_origin, OriginValue};
///
/// assert_eq!(parse_origin(b"null")?, OriginValue::Null);
/// assert!(parse_origin(b"Null").is_err());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_origin(value: &[u8]) -> Result<OriginValue<'_>> {
    let lead = skip_ows(value);
    let v = trim_ows(value);
    if v == b"null" {
        return Ok(OriginValue::Null);
    }
    let scheme_len = v
        .iter()
        .take_while(|&&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        .count();
    if scheme_len == 0 || !v.first().is_some_and(u8::is_ascii_alphabetic) {
        return err(ErrorKind::InvalidOrigin, lead);
    }
    let scheme = v.get(..scheme_len).unwrap_or(&[]);
    if v.get(scheme_len..scheme_len + 3) != Some(b"://") {
        return err(ErrorKind::InvalidOrigin, lead + scheme_len);
    }
    let authority_at = scheme_len + 3;
    let authority = v.get(authority_at..).unwrap_or(&[]);
    if let Some(i) = authority
        .iter()
        .position(|&b| matches!(b, b'/' | b'?' | b'#'))
    {
        return err(ErrorKind::InvalidOrigin, lead + authority_at + i);
    }
    let hp = host_port(authority).map_err(|e: ParseError| e.shifted(lead + authority_at))?;
    if hp.host.is_empty() || hp.empty_port {
        return err(ErrorKind::InvalidOrigin, lead + authority_at);
    }
    Ok(OriginValue::Origin(Origin {
        scheme,
        host: hp.host,
        port: hp.port,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn o(v: &[u8]) -> Origin<'_> {
        match parse_origin(v).unwrap() {
            OriginValue::Origin(o) => o,
            OriginValue::Null => panic!("null"),
        }
    }

    #[test]
    fn test_origin_edge_cases() {
        let k = |v: &[u8]| parse_origin(v).unwrap_err().kind();
        assert_eq!(k(b"Null"), ErrorKind::InvalidOrigin);
        assert_eq!(o(b"https://a.com").port, None);
        assert_eq!(o(b"https://a.com:443").port, Some(443));
        assert_eq!(k(b"https://a.com/"), ErrorKind::InvalidOrigin);
        assert_eq!(k(b"https://a.com:"), ErrorKind::InvalidOrigin);
        assert_eq!(k(b"https://user@a.com"), ErrorKind::InvalidHost);
        assert_eq!(o(b"HTTPS://A.COM").scheme, b"HTTPS");
        assert_eq!(k(b"file://"), ErrorKind::InvalidOrigin);
        assert_eq!(k(b"https:a.com"), ErrorKind::InvalidOrigin);
        assert_eq!(k(b"1https://a.com"), ErrorKind::InvalidOrigin);
        assert_eq!(k(b"https://a.com?x"), ErrorKind::InvalidOrigin);
        assert_eq!(k(b""), ErrorKind::InvalidOrigin);
        assert!(matches!(o(b"http://[::1]:8080").host, Host::V6(_)));
        let long = [b"https://".as_slice(), &[b'a'; 4096]].concat();
        assert!(parse_origin(&long).is_ok());
    }

    #[test]
    fn test_origin_suffix_attack_not_same() {
        let a = o(b"https://example.com");
        assert!(!a.same_origin(&o(b"https://example.com.evil.test")));
        assert!(!a.same_origin(&o(b"https://evilexample.com")));
        assert!(!a.same_origin(&o(b"http://example.com")));
        assert!(!a.same_origin(&o(b"https://example.com:8443")));
        assert!(a.same_origin(&o(b"https://EXAMPLE.com:443")));
    }

    #[test]
    fn test_origin_trailing_slash_refused() {
        assert_eq!(
            parse_origin(b"https://example.com/").unwrap_err().kind(),
            ErrorKind::InvalidOrigin
        );
    }

    #[test]
    fn test_origin_write() {
        let mut buf = [0u8; 64];
        let mut out = crate::SliceSink::new(&mut buf);
        o(b"HTTP://[::1]:8080").write_to(&mut out).unwrap();
        assert_eq!(out.written(), b"http://[::1]:8080");
        assert_eq!(o(b"x-app://a").effective_port(), None);
    }
}
