//! # parse_net
//!
//! The grammar layer for Internet message fields: RFC 9110 field syntax,
//! media types, RFC 9651 Structured Field Values, HTTP and RFC 5322 dates,
//! content negotiation, entity tags, ranges, `Content-Disposition` with
//! RFC 8187, `Cache-Control`, `Link`, `Forwarded`, authentication challenges,
//! `Host`, `Origin`, and the email lexical layer, with safe writers for each.
//!
//! Protocol engines (http-net, ws-net, h2-net) frame messages; parse-net reads
//! what is inside a field value and writes field values back out without ever
//! emitting CR, LF, or NUL. It is `no_std`, needs no allocator for any parse,
//! does no I/O, and has no dependencies.
//!
//! ## Tier 1
//!
//! The convention in every example is `use parse_net as pn;`. One plain call
//! per field:
//!
//! ```rust
//! use parse_net as pn;
//!
//! // Media types: one strict view, no copy.
//! let mt = pn::parse_media_type(b"text/html; charset=UTF-8")?;
//! assert!(mt.essence_is("text/html"));
//! assert!(mt.charset().is_some_and(|c| c.eq_ignore_ascii_case(b"utf-8")));
//!
//! // Lists: commas inside quoted strings and comments do not split.
//! let codings: Vec<&[u8]> = pn::parse_list(b"gzip, deflate;q=0.5, x=\"a,b\"")?.iter().collect();
//! assert_eq!(codings, [&b"gzip"[..], b"deflate;q=0.5", b"x=\"a,b\""]);
//!
//! // HTTP-date: all three formats in, IMF-fixdate out.
//! let now = 1_792_540_800; // the caller's clock, Unix seconds
//! let d = pn::parse_http_date_at(b"Sunday, 06-Nov-94 08:49:37 GMT", now)?;
//! assert_eq!(&d.format(), b"Sun, 06 Nov 1994 08:49:37 GMT");
//!
//! // Host: real IPv4 and IPv6 validation, ports up to 65535.
//! let hp = pn::parse_host_port(b"[2001:db8::1]:8443")?;
//! assert_eq!(hp.port, Some(8443));
//! assert!(pn::parse_host_port(b"127.1").is_err()); // read as IPv4 by browsers: refused
//!
//! // Writers cannot emit CR, LF, or NUL.
//! let mut buf = [0u8; 64];
//! let mut out = pn::SliceSink::new(&mut buf);
//! pn::media::write("text", "plain", &[("charset", "utf-8")], &mut out)?;
//! assert_eq!(out.written(), b"text/plain; charset=utf-8");
//! assert!(pn::write::write_field_value(b"x\r\nSet-Cookie: y", &mut out).is_err());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Errors carry a kind and an offset, never input bytes:
//!
//! ```rust
//! use parse_net as pn;
//!
//! let err = pn::parse_media_type(b"text/ html").unwrap_err();
//! assert_eq!(err.kind(), pn::ErrorKind::InvalidMediaType);
//! assert_eq!(err.to_string(), "invalid media type at offset 5");
//! ```
//!
//! The rest of Tier 1, one call per question a server or a mail client asks:
//!
//! ```rust
//! use parse_net as pn;
//! use core::net::IpAddr;
//!
//! // Content negotiation: the index of the best offer.
//! let accept = Some(&b"text/html;q=0.9, application/json"[..]);
//! assert_eq!(pn::best_media(accept, &["text/html", "application/json"]), Some(1));
//!
//! // Conditional requests: answer 304 when the tag matches.
//! let current = pn::Representation::Tagged(pn::EntityTag::strong(b"v2")?);
//! assert!(pn::if_none_match(b"\"v1\", W/\"v2\"", current)?);
//!
//! // Ranges: resolved against the length, written into the caller's array.
//! let mut ranges = [pn::ByteRange { start: 0, end: 0 }; 4];
//! assert_eq!(pn::byte_ranges(b"bytes=0-499", 10_000, &mut ranges)?, pn::RangeOutcome::Ranges(1));
//!
//! // Downloads and caching.
//! let cd = pn::parse_content_disposition(b"attachment; filename=\"report.pdf\"")?;
//! assert!(cd.filename().is_some());
//! let cc = pn::parse_response_cache_control(b"public, max-age=31536000, immutable")?;
//! assert_eq!(cc.max_age, Some(31_536_000));
//!
//! // Proxies: the client address behind the trusted ones.
//! let peer: IpAddr = "10.0.0.2".parse()?;
//! let lines: [&[u8]; 1] = [b"203.0.113.7, 10.0.0.2"];
//! let client = pn::client_address(peer, pn::ForwardedSource::XForwardedFor(&lines), &|a: IpAddr| a == peer);
//! assert_eq!(client, pn::ClientAddress::Forwarded { addr: "203.0.113.7".parse()?, hops: 2 });
//!
//! // Authorization and Structured Fields.
//! assert_eq!(pn::bearer(b"Bearer mF_9.B5f-4.1JqM")?, Some(&b"mF_9.B5f-4.1JqM"[..]));
//! let site = pn::structured::parse_item(b"same-origin")?;
//!
//! // Email: an address, a display name, and a subject as text.
//! let m = pn::mail::parse_mailbox(b"=?UTF-8?Q?Ren=C3=A9e?= <renee@example.com>")?;
//! let mut name = [0u8; 64];
//! assert_eq!(pn::mail::decode_phrase(m.display_name.unwrap_or_default(), &mut name)?, "Ren\u{e9}e");
//! let mut subject = [0u8; 64];
//! assert_eq!(pn::mail::decode_words(b"=?UTF-8?Q?Caf=C3=A9?= menu", &mut subject)?, "Caf\u{e9} menu");
//! # let _ = site;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Every Tier 1 call uses [`Limits::DEFAULT`]. The same parser with other
//! limits is the module's `parse(value, &limits)` (`media::parse`,
//! `link::parse`), or the call's `_with_limits` form where a module has several
//! (`mail::parse_mailbox_with_limits`).
//!
//! ## Status
//!
//! Beta, `0.10.0`: every planned field, measured against the Rust crates that
//! do the same work (`docs/PERFORMANCE.md`), hardened
//! (`docs/SECURITY.md`), and in use by published consumers (http-net,
//! cookie-net, form-net). The public API is written down in `docs/API.md`,
//! each field's grammar in `docs/GRAMMAR.md`, the design in `dev/PLAN.md`,
//! and the milestone schedule in `dev/ROADMAP.md`
//! (all in the [repository](https://github.com/jamesgober/parse-net)).

#![doc(html_root_url = "https://docs.rs/parse-net")]
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(unused_must_use, unused_results)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::dbg_macro,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::indexing_slicing
    )
)]

#[cfg(any(feature = "std", test))]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod auth;
pub mod cache;
pub mod class;
pub mod date;
pub mod disposition;
mod error;
pub mod etag;
pub mod extended_value;
pub mod forwarded;
pub mod host;
mod limits;
pub mod link;
pub mod list;
pub mod mail;
pub mod media;
pub mod negotiate;
pub mod num;
pub mod origin;
#[cfg(feature = "alloc")]
mod owned;
pub mod param;
pub mod percent;
pub mod range;
pub mod scan;
pub mod structured;
pub mod text;
mod utf8;
pub mod write;

pub use auth::{AuthPayload, Challenge, Credentials, basic, bearer};
pub use cache::{
    Directive, RequestDirectives, ResponseDirectives, parse_request_cache_control,
    parse_response_cache_control,
};
#[cfg(feature = "std")]
pub use date::parse_http_date;
pub use date::{Civil, DateFormat, HttpDate, MailDate, parse_http_date_at};
pub use disposition::{
    ContentDisposition, DispositionType, Filename, parse_content_disposition, write_attachment,
};
pub use error::{ErrorKind, Full, ParseError, WriteError};
pub use etag::{Condition, EntityTag, Representation, TagList, if_match, if_none_match};
pub use extended_value::{Charset, ExtendedValue, write_extended_value};
pub use forwarded::{ClientAddress, ForwardedSource, Trust, client_address};
pub use host::{Host, HostPort, parse_host_port};
pub use limits::{DuplicatePolicy, Limits};
pub use link::{LinkValue, Links, parse_link};
pub use list::{List, parse_list};
pub use media::{Boundary, MediaRange, MediaType, parse_media_type};
pub use negotiate::{QValue, best_charset, best_encoding, best_language, best_media};
pub use origin::{Origin, OriginValue, parse_origin};
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub use owned::{OwnedEntityTag, OwnedHostPort, OwnedMediaType};
pub use param::{Param, Params};
pub use range::{
    ByteRange, ContentRange, IfRange, RangeHeader, RangeOutcome, RangeSpec, byte_ranges,
};
pub use text::{Comment, Quoted, Word};
pub use write::{CountSink, Sink, SliceSink};

/// Crate version string, populated by Cargo at build time.
///
/// # Examples
///
/// ```
/// assert_eq!(parse_net::VERSION.split('.').count(), 3);
/// ```
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn test_version_matches_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(VERSION.split('.').count(), 3, "expected MAJOR.MINOR.PATCH");
    }
}
