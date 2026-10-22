//! Owned forms (`alloc`): for callers that keep a parsed value beyond the
//! input buffer. Each copies the view's bytes into one buffer (`to_owned`)
//! and gives the same view back (`as_view`), so every accessor works on
//! both. parse-net never uses them itself.
//!
//! # Examples
//!
//! ```
//! use parse_net::{parse_media_type, OwnedMediaType};
//!
//! let owned: OwnedMediaType = {
//!     let input = b"text/html; charset=utf-8".to_vec();
//!     parse_media_type(&input)?.to_owned()
//! };
//! assert!(owned.as_view().is("text", "html"));
//! assert!(owned.as_view().charset().is_some_and(|c| c.eq_bytes(b"utf-8")));
//! # Ok::<(), parse_net::ParseError>(())
//! ```

use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::{
    etag::EntityTag,
    host::{Host, HostPort},
    limits::DuplicatePolicy,
    media::MediaType,
    param::Params,
};

/// An owned [`MediaType`].
///
/// # Examples
///
/// ```
/// let owned: parse_net::OwnedMediaType = parse_net::parse_media_type(b"image/png")?.to_owned();
/// assert!(owned.as_view().is("image", "png"));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OwnedMediaType {
    /// The type, the subtype, then the parameter text.
    buf: Vec<u8>,
    type_len: usize,
    subtype_len: usize,
    count: u32,
    policy: DuplicatePolicy,
}

impl MediaType<'_> {
    /// Copies the media type into an [`OwnedMediaType`] (one allocation).
    ///
    /// # Examples
    ///
    /// ```
    /// let input = b"application/json; charset=utf-8".to_vec();
    /// let owned = parse_net::parse_media_type(&input)?.to_owned();
    /// drop(input);
    /// assert!(owned.as_view().is("application", "json"));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn to_owned(&self) -> OwnedMediaType {
        let mut buf =
            Vec::with_capacity(self.type_.len() + self.subtype.len() + self.params.text.len());
        buf.extend_from_slice(self.type_);
        buf.extend_from_slice(self.subtype);
        buf.extend_from_slice(self.params.text);
        OwnedMediaType {
            buf,
            type_len: self.type_.len(),
            subtype_len: self.subtype.len(),
            count: self.params.count,
            policy: self.params.policy,
        }
    }
}

impl OwnedMediaType {
    /// The view over the owned bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let m = parse_net::parse_media_type(b"text/plain; format=flowed")?;
    /// assert_eq!(m.to_owned().as_view(), m);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn as_view(&self) -> MediaType<'_> {
        let (type_, rest) = self.buf.split_at(self.type_len.min(self.buf.len()));
        let (subtype, text) = rest.split_at(self.subtype_len.min(rest.len()));
        MediaType {
            type_,
            subtype,
            params: Params {
                text,
                count: self.count,
                policy: self.policy,
            },
        }
    }
}

/// An owned [`EntityTag`].
///
/// # Examples
///
/// ```
/// use parse_net::EntityTag;
///
/// let owned = EntityTag::parse(b"W/\"v1\"")?.to_owned();
/// assert!(owned.as_view().is_weak() && owned.as_view().opaque() == b"v1");
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OwnedEntityTag {
    weak: bool,
    opaque: Vec<u8>,
}

impl EntityTag<'_> {
    /// Copies the tag into an [`OwnedEntityTag`] (one allocation).
    ///
    /// # Examples
    ///
    /// ```
    /// let input = b"\"abc\"".to_vec();
    /// let owned = parse_net::EntityTag::parse(&input)?.to_owned();
    /// drop(input);
    /// assert!(!owned.as_view().is_weak() && owned.as_view().opaque() == b"abc");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn to_owned(&self) -> OwnedEntityTag {
        OwnedEntityTag {
            weak: self.weak,
            opaque: self.opaque.to_vec(),
        }
    }
}

impl OwnedEntityTag {
    /// The view over the owned bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let tag = parse_net::EntityTag::parse(b"W/\"x\"")?;
    /// assert_eq!(tag.to_owned().as_view(), tag);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn as_view(&self) -> EntityTag<'_> {
        EntityTag {
            weak: self.weak,
            opaque: &self.opaque,
        }
    }
}

/// The host of an [`OwnedHostPort`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Kind {
    Name,
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Future,
}

/// An owned [`HostPort`].
///
/// # Examples
///
/// ```
/// use parse_net::parse_host_port;
///
/// let owned = parse_host_port(b"Example.COM:8080")?.to_owned();
/// assert_eq!(owned.as_view().port, Some(8080));
/// assert!(owned.as_view().host.eq_ignore_ascii_case(&parse_host_port(b"example.com")?.host));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OwnedHostPort {
    kind: Kind,
    /// The name or IPvFuture text; empty for an address.
    text: Vec<u8>,
    port: Option<u16>,
    empty_port: bool,
}

impl HostPort<'_> {
    /// Copies the value into an [`OwnedHostPort`] (one allocation for a name,
    /// none for an address).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{parse_host_port, Host};
    /// use std::net::Ipv4Addr;
    ///
    /// let owned = parse_host_port(b"192.0.2.1:443")?.to_owned();
    /// assert_eq!(owned.as_view().port, Some(443));
    /// assert_eq!(owned.as_view().host, Host::V4(Ipv4Addr::new(192, 0, 2, 1)));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn to_owned(&self) -> OwnedHostPort {
        let (kind, text) = match self.host {
            Host::Name(n) => (Kind::Name, n.to_vec()),
            Host::V4(a) => (Kind::V4(a), Vec::new()),
            Host::V6(a) => (Kind::V6(a), Vec::new()),
            Host::Future(f) => (Kind::Future, f.to_vec()),
        };
        OwnedHostPort {
            kind,
            text,
            port: self.port,
            empty_port: self.empty_port,
        }
    }
}

impl OwnedHostPort {
    /// The view over the owned bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let hp = parse_net::parse_host_port(b"[::1]:8080")?;
    /// assert_eq!(hp.to_owned().as_view(), hp);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn as_view(&self) -> HostPort<'_> {
        let host = match self.kind {
            Kind::Name => Host::Name(&self.text),
            Kind::V4(a) => Host::V4(a),
            Kind::V6(a) => Host::V6(a),
            Kind::Future => Host::Future(&self.text),
        };
        HostPort {
            host,
            port: self.port,
            empty_port: self.empty_port,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_owned_forms_give_the_same_view() {
        for v in [
            &b"text/html"[..],
            b"multipart/form-data; boundary=\"a b\"; x=1",
            b"a/b;",
        ] {
            let m = crate::parse_media_type(v).unwrap();
            assert_eq!(m.to_owned().as_view(), m);
        }
        for v in [&b"\"x\""[..], b"W/\"\"", b"\"\xff\""] {
            let t = EntityTag::parse(v).unwrap();
            assert_eq!(t.to_owned().as_view(), t);
        }
        for v in [
            &b"a.example:1"[..],
            b"[::1]",
            b"192.0.2.1",
            b"[v1.x]",
            b"h:",
        ] {
            let h = crate::parse_host_port(v).unwrap();
            assert_eq!(h.to_owned().as_view(), h);
        }
    }

    #[test]
    fn test_owned_outlives_the_input() {
        let owned = {
            let input = b"Text/Plain; Charset=\"UTF-8\"".to_vec();
            crate::parse_media_type(&input).unwrap().to_owned()
        };
        let v = owned.as_view();
        assert!(v.is("text", "plain") && v.charset().unwrap().eq_ignore_ascii_case(b"utf-8"));
        assert_eq!(v.params().len(), 1);
    }
}
