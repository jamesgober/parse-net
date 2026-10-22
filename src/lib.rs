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
//! The convention in every example is `use parse_net as pn;`:
//!
//! ```
//! use parse_net as pn;
//!
//! assert!(!pn::VERSION.is_empty());
//! ```
//!
//! The Tier 1 functions arrive from `0.3.0` on, one plain call per field:
//!
//! ```text
//! pn::parse_media_type(b"text/html; charset=UTF-8")?   // MediaType view
//! pn::best_media(accept, &["text/html", "application/json"])  // Option<usize>
//! pn::http_date_at(b"Sun, 06 Nov 1994 08:49:37 GMT", now)?    // HttpDate
//! pn::if_none_match(if_none_match, &current_etag)?     // bool: answer 304
//! pn::byte_ranges(range, file_len, &mut buf)?           // RangeOutcome
//! pn::parse_content_disposition(value)?.filename()      // prefers filename*
//! pn::sfv::parse_item(b"same-origin")?                  // Sec-Fetch-Site
//! pn::parse_host_port(b"example.com:8443")?             // HostPort
//! ```
//!
//! ## Status
//!
//! Scaffold. The design is written down in `dev/PLAN.md` and the milestone
//! schedule in `dev/ROADMAP.md` (both in the
//! [repository](https://github.com/jamesgober/parse-net)); the public API is
//! locked in `0.2.0` and the core ships in `0.3.0`.

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
