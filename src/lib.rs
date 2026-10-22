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
//! let codings: Vec<&[u8]> = pn::list(b"gzip, deflate;q=0.5, x=\"a,b\"")?.iter().collect();
//! assert_eq!(codings, [&b"gzip"[..], b"deflate;q=0.5", b"x=\"a,b\""]);
//!
//! // HTTP-date: all three formats in, IMF-fixdate out.
//! let now = 1_792_540_800; // the caller's clock, Unix seconds
//! let d = pn::http_date_at(b"Sunday, 06-Nov-94 08:49:37 GMT", now)?;
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
//! The rest of Tier 1 arrives with `0.4.0` and `0.5.0` (see the
//! [roadmap](https://github.com/jamesgober/parse-net/blob/main/dev/ROADMAP.md)):
//!
//! ```text
//! pn::best_media(accept, &["text/html", "application/json"])    // Option<usize>
//! pn::if_none_match(if_none_match, &current_etag)?              // bool: answer 304
//! pn::byte_ranges(range, file_len, &mut buf)?                   // RangeOutcome
//! pn::parse_content_disposition(value)?.filename()              // prefers filename*
//! pn::response_cache_control(value)?                            // ResponseDirectives
//! pn::client_address(peer, pn::ForwardedSource::XForwardedFor(&lines), &trusted, 16)?
//! pn::sfv::parse_item(b"same-origin")?                          // Sec-Fetch-Site
//! pn::bearer(authorization)?                                    // Option<&[u8]>
//! ```
//!
//! ## Status
//!
//! The core, `0.3.0`. The public API is written down in `docs/API.md`, the
//! design in `dev/PLAN.md`, and the milestone schedule in `dev/ROADMAP.md`
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
pub mod ext_value;
pub mod forwarded;
pub mod host;
mod limits;
pub mod list;
pub mod media;
pub mod negotiate;
pub mod num;
pub mod origin;
pub mod param;
pub mod pct;
pub mod range;
pub mod scan;
pub mod text;
mod utf8;
pub mod write;

pub use auth::{AuthPayload, Challenge, Credentials, basic, bearer};
pub use cache::{
    Directive, RequestDirectives, ResponseDirectives, request_cache_control, response_cache_control,
};
#[cfg(feature = "std")]
pub use date::http_date;
pub use date::{Civil, DateFormat, HttpDate, http_date_at};
pub use disposition::{
    ContentDisposition, DispositionType, Filename, parse_content_disposition, write_attachment,
};
pub use error::{ErrorKind, Full, ParseError, WriteError};
pub use etag::{Condition, EntityTag, TagList, if_match, if_none_match, parse_condition};
pub use ext_value::{Charset, ExtValue, write_ext_value};
pub use forwarded::{ClientAddress, ForwardedSource, Trust, client_address};
pub use host::{Host, HostPort, parse_host_port};
pub use limits::{DuplicatePolicy, Limits};
pub use list::{List, list};
pub use media::{Boundary, MediaRange, MediaType, parse_media_type};
pub use negotiate::{QValue, best_charset, best_encoding, best_language, best_media};
pub use origin::{Origin, OriginValue, parse_origin};
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
