<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>parse-net</b>
    <br>
    <sub>
        <sup>INTERNET MESSAGE FIELD GRAMMAR</sup>
    </sub>
</h1>

<p align="center">
    <a href="https://crates.io/crates/parse-net"><img src="https://img.shields.io/crates/v/parse-net.svg" alt="Crates.io"></a>
    <a href="https://crates.io/crates/parse-net" alt="Download"><img alt="Crates.io Downloads" src="https://img.shields.io/crates/d/parse-net?color=%230099ff"></a>
    <a href="https://docs.rs/parse-net"><img src="https://docs.rs/parse-net/badge.svg" alt="Documentation"></a>
    <a href="https://github.com/jamesgober/parse-net/actions"><img alt="GitHub CI" src="https://github.com/jamesgober/parse-net/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
    <a href="#license"><img src="https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg" alt="License"></a>
</p>

<p align="center">
    <b>The grammar under the stack's protocol crates.</b>
    <br>
    <i>No dependencies, no allocation, no I/O.</i>
</p>

<br>

<p>
    <strong>parse-net</strong> reads and writes the values inside Internet message fields: RFC 9110 field syntax (tokens, quoted strings, comments, lists, parameters), media types, RFC 9651 Structured Field Values, HTTP and RFC 5322 dates, content negotiation, entity tags, ranges, <code>Content-Disposition</code> with RFC 8187 <code>filename*</code>, <code>Cache-Control</code>, <code>Link</code>, <code>Forwarded</code> and <code>X-Forwarded-For</code> with trusted-proxy resolution, <code>Authorization</code> and <code>WWW-Authenticate</code>, <code>Host</code>, <code>Origin</code>, and the email lexical layer (folding, encoded words, MIME parameters with RFC 2231, <code>addr-spec</code>).
</p>

<p>
    Protocol engines such as http-net and ws-net frame messages; parse-net reads what is inside a field value, so every engine shares one strict implementation instead of carrying its own copy. Every parse checks the whole value in one forward pass and returns a small <code>Copy</code> view into the caller's bytes. Decoded forms go into a buffer the caller provides. Errors carry a kind and a byte offset, never input bytes.
</p>

<p>
    The core is <code>no_std</code> without <code>alloc</code>, has zero runtime dependencies, and contains no <code>unsafe</code>. Every writer refuses CR, LF, and NUL, and no writer can produce a value its own parser would refuse. Anything two conforming implementations could read differently is refused, unless the RFC tells recipients to accept it.
</p>

---

## Features

The list below is the plan for 1.0. What ships in the current version is under [Status](#status-feature-complete).

### **Field grammar**
- **Byte classes** - every ABNF class (`tchar`, `qdtext`, `ctext`, `etagc`, `attr-char`, MIME `token`, RFC 3986, Structured Field keys and tokens) in one 1 KiB table, one load and one mask per byte.
- **Lexical forms** - tokens, OWS (space and tab only), quoted strings with zero-copy access and buffer-free comparison, nested comments without recursion.
- **Lists and parameters** - quote- and comment-aware comma lists, several field lines read as one list without copying, parameters that refuse duplicates by default.

### **Field values**
- **Media types and negotiation** - media types, RFC 2046 boundaries, exact q-values, `Accept`, `Accept-Language` (RFC 4647), `Accept-Encoding`, `Accept-Charset`.
- **Dates** - HTTP-date in all three formats with the RFC 9110 50-year rule, IMF-fixdate formatting, RFC 5322 date-time; years 1 to 9999.
- **Caching and conditions** - entity tags, `If-Match`, `If-None-Match`, `Range`, `Content-Range`, `If-Range`, `Cache-Control`.
- **Downloads and links** - `Content-Disposition` with RFC 8187 decoding, `Link` with `title*`.
- **Proxies and auth** - `Forwarded`, `X-Forwarded-*` with a trust predicate that fails closed, `Authorization`, `WWW-Authenticate`.
- **Hosts and origins** - `Host` with real IPv4 and IPv6 validation, `Origin` with same-origin comparison.
- **Structured Fields** - RFC 9651 Items, Lists, Dictionaries, every bare item type, parse and serialize.
- **Email** - folding, RFC 2047 encoded words, MIME parameters with RFC 2231 continuations, `addr-spec`, `msg-id`.

### **Reliability and safety**
- **No unsafe code** - `#![forbid(unsafe_code)]`; the SWAR scanners are plain safe Rust.
- **No allocation, no recursion** - proved by a counting allocator and depth tests.
- **Bounded work** - every limit checked before the work it governs; linear time on every input.
- **Tested to the byte** - unit tests on every path, property tests, fuzz targets for every parser, RFC vectors and the httpwg Structured Field suite.

> **Note on performance:** the target is at least 20% faster than the best Rust competitor for each comparable operation, at equal or stronger strictness. The measurements, the method, and the commands to reproduce them are in [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

---

<br>

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
parse-net = "0.8.0"

# Optional features:
parse-net = { version = "0.8.0", features = [
    "alloc",        # owned forms and Sink for Vec<u8>
    "std",          # SystemTime conversions and http_date() with the system clock
] }
```

**Feature recommendations**:
- **Minimal (embedded, engines)**: no features; `no_std`, no allocator.
- **Servers**: `std`.
- **Owned values**: `alloc`.

---

<br>

## Quick Start

The convention is `use parse_net as pn;`.

```rust
use parse_net as pn;

// Media types: one strict view, no copy.
let mt = pn::parse_media_type(b"text/html; charset=UTF-8")?;
assert!(mt.essence_is("text/html"));
assert!(mt.charset().is_some_and(|c| c.eq_ignore_ascii_case(b"utf-8")));

// Lists: commas inside quoted strings and comments do not split.
let codings: Vec<&[u8]> = pn::list(b"gzip, deflate;q=0.5, x=\"a,b\"")?.iter().collect();
assert_eq!(codings, [&b"gzip"[..], b"deflate;q=0.5", b"x=\"a,b\""]);

// HTTP-date: all three formats in, IMF-fixdate out.
let now = 1_792_540_800; // the caller's clock, Unix seconds
let d = pn::http_date_at(b"Sunday, 06-Nov-94 08:49:37 GMT", now)?;
assert_eq!(&d.format(), b"Sun, 06 Nov 1994 08:49:37 GMT");

// Host: real IPv4 and IPv6 validation, ports up to 65535.
let hp = pn::parse_host_port(b"[2001:db8::1]:8443")?;
assert_eq!(hp.port, Some(8443));
assert!(pn::parse_host_port(b"127.1").is_err()); // read as IPv4 by browsers: refused

// Writers cannot emit CR, LF, or NUL.
let mut buf = [0u8; 64];
let mut out = pn::SliceSink::new(&mut buf);
pn::media::write("text", "plain", &[("charset", "utf-8")], &mut out)?;
assert_eq!(out.written(), b"text/plain; charset=utf-8");
assert!(pn::write::write_field_value(b"x\r\nSet-Cookie: y", &mut out).is_err());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Errors carry a kind and an offset, never input bytes:

```rust
use parse_net as pn;

let err = pn::parse_media_type(b"text/ html").unwrap_err();
assert_eq!(err.kind(), pn::ErrorKind::InvalidMediaType);
assert_eq!(err.to_string(), "invalid media type at offset 5");
```

The rest of Tier 1 arrives with `0.4.0` and `0.5.0` (see the [roadmap](./dev/ROADMAP.md)):

```text
pn::best_media(accept, &["text/html", "application/json"])    // Option<usize>
pn::if_none_match(if_none_match, &current_etag)?              // bool: answer 304
pn::byte_ranges(range, file_len, &mut buf)?                   // RangeOutcome
pn::parse_content_disposition(value)?.filename()              // prefers filename*
pn::response_cache_control(value)?                            // ResponseDirectives
pn::client_address(peer, pn::ForwardedSource::XForwardedFor(&lines), &trusted, 16)?
pn::sfv::parse_item(b"same-origin")?                          // Sec-Fetch-Site
pn::bearer(authorization)?                                    // Option<&[u8]>
```

---

## **What it is not**

- Not a protocol engine: message framing, start lines, and chunked bodies belong to http-net, h2-net, fcgi-net, and ws-net.
- Not a header map: the engine owns field storage.
- Not a URL parser (url-lib) or a base64 codec (encode-lib).
- Not cookie grammar (cookie-net) or a full email parser.
- Not a policy engine: it reports facts strictly; what to accept is the caller's call.

---

## **Status: feature complete**

**Current Version:** `0.8.0` - every planned field, for HTTP and for mail, benchmarked, hardened, and in use by published consumers: http-net, cookie-net, and form-net.
**Target:** `1.0.0` stable, per the roadmap in [`dev/ROADMAP.md`](./dev/ROADMAP.md).

**What's complete**:
- **Errors and limits** - `ParseError` (8 bytes: kind and offset, never input bytes), `ErrorKind`, `WriteError`, `Limits` with RFC-sourced defaults, `DuplicatePolicy`.
- **Byte classes and scanning** - every ABNF class in one 1 KiB table; SWAR byte search and field-value validation, eight bytes per step.
- **Writers** - `Sink`, `SliceSink`, `CountSink`, `Vec<u8>` (with `alloc`); tokens, quoted strings, words, parameters, field values, numbers; nothing half-written after an error.
- **Lexical forms** - tokens, OWS, quoted strings (zero-copy, buffer-free comparison), words, comments (nested, counted, never recursed).
- **Lists and parameters** - quote- and comment-aware lists, several field lines as one list without copying, parameters that refuse duplicates by default.
- **Media types** - parsing, RFC 2046 boundaries, `charset`, suffixes, writing, canonical form.
- **HTTP-date** - all three formats, the RFC 9110 50-year rule with an explicit clock, IMF-fixdate formatting, years 1 to 9999, the calendar functions; `SystemTime` conversions with `std`.
- **Host** - reg-names, IPv4, IPv6, IPvFuture, ports; numeric names that browsers read as IPv4 refused.
- **Percent-encoding** - validation, decoding into a caller buffer (UTF-8 checked, lowercase-only for Structured Fields), encoding with named sets.
- **Content negotiation** - `Accept`, `Accept-Language` (RFC 4647 lookup or filtering), `Accept-Encoding`, `Accept-Charset`, with q-values and an explicit outcome when a header is ignored.
- **Conditional and range requests** - entity tags with strong and weak comparison, `If-Match`, `If-None-Match`, `Range` resolution that refuses abusive sets, `Content-Range`, `If-Range`.
- **File names** - RFC 8187 values and `Content-Disposition` with `filename*` preferred, decoded controls refused, path separators and bidi controls reported; every tc2231 case has a verdict.
- **Caching, proxies, auth, origins** - `Cache-Control`, `Forwarded` and `X-Forwarded-*` with client-address resolution through trusted proxies only, `Authorization` and `WWW-Authenticate` with redacted `Debug`, `Origin` with exact same-origin comparison.
- **Structured Fields** - RFC 9651 Items, Lists, and Dictionaries with every bare item type: views, a single-pass visitor, and a canonical writer, passing the httpwg parsing and serialisation suites in full.
- **Links** - RFC 8288 `Link` values, with the first `rel` winning and `title*` decoded.
- **Email** - RFC 5322 dates, header folding and unfolding, RFC 2047 encoded words, MIME parameters with RFC 2231 continuations, `addr-spec`, mailboxes, and message identifiers, for smtp-net and login validation.
- **Owned forms** - with `alloc`, owned media types, entity tags, host-ports, and Structured Field values that give the same views back.
- **Proof** - unit tests on every path, property tests (no panic, round trips, writer-parser closure, combined lines), counting-allocator tests for every parse and write, RFC and tc2231 vectors, 34 fuzz targets including three differential oracles against `httpdate`, `mime`, and `sfv`, and an example for every public item.

- **Performance** - at least 20% faster than the competing Rust crates on every compared operation (21% to 81%), without allocating: see [docs/PERFORMANCE.md](docs/PERFORMANCE.md).
- **Hardening** - an attack test for every threat in the model, every walker checked for linear time at 1 KiB, 64 KiB, and 1 MiB, and every fuzz target run for 24 hours: see [docs/SECURITY.md](docs/SECURITY.md).

**What's planned next**:
- `0.9.0`: beta: ws-net, smtp-net, and web-net on parse-net, then a pre-1.0 polish pass (every accepted gap and missed target revisited, a fresh performance and security pass) before the release candidates.
- `1.0.0`: the full audit in `docs/STABILITY-1.0.md`, released on James's go.

**Note on API stability**: the API was locked at `0.2.0` ([`docs/API.md`](./docs/API.md)); names and signatures change only with a recorded decision until `1.0.0` freezes them, with the contract recorded in `docs/STABILITY-1.0.md`.

---

## **Documentation & Resources**

- **[API Reference](docs/API.md)** - every public item with examples
- **[Grammar](docs/GRAMMAR.md)** - each field's ABNF, case rules, and leniencies
- **[Architecture](docs/ARCHITECTURE.md)** - modules, the byte-class table, views, and algorithms
- **[Performance](docs/PERFORMANCE.md)** - benchmarks against the competing crates, and the method
- **[Security](docs/SECURITY.md)** - the threat model, its tests, and how to report a vulnerability
- **[Platform notes](docs/PLATFORM-NOTES.md)** - features, `no_std` and bare-metal builds, stack use
- **[Migration](docs/MIGRATION.md)** - moving http-net and ws-net onto parse-net
- **[Plan](dev/PLAN.md)** - design, threats, and decisions
- **[Roadmap](dev/ROADMAP.md)** - versions and exit criteria
- **[Changelog](CHANGELOG.md)** - every change
- **[docs.rs](https://docs.rs/parse-net)** - rendered API documentation
- **[crates.io](https://crates.io/crates/parse-net)** - the crate

### **Version Compatibility**
- **Rust**: 1.85+ (edition 2024)
- **MSRV Policy**: after `1.0.0`, an MSRV raise is a major change
- **API Stability**: pre-1.0; the API may change at each minor version until `1.0.0`
- **Targets**: anything with `core`; `thumbv7em-none-eabi` is checked in CI

### **Development Setup**
```bash
git clone https://github.com/jamesgober/parse-net.git
cd parse-net
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

## **Contributing**

See [`dev/DIRECTIVES.md`](./dev/DIRECTIVES.md) for engineering standards and the definition of done. Before a PR: `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features` must be clean.

<hr>

<div id="license">
    <h2>License</h2>
    <p><b>parse-net</b> is dual-licensed under either of:</p>
    <ul>
        <li><b>Apache License, Version 2.0</b>: see <a href="./LICENSE-APACHE" title="Apache-2.0 License">LICENSE-APACHE</a> or <a href="http://www.apache.org/licenses/LICENSE-2.0" title="Apache-2.0 License" target="_blank">apache.org/licenses/LICENSE-2.0</a></li>
        <li><b>MIT License</b>: see <a href="./LICENSE-MIT" title="MIT License">LICENSE-MIT</a> or <a href="https://opensource.org/licenses/MIT" title="MIT License" target="_blank">opensource.org/licenses/MIT</a></li>
    </ul>
    <p>at your option.</p>
    <h3>Contribution</h3>
    <p>Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in <b>parse-net</b> by you, as defined in the Apache-2.0 license, shall be dual-licensed as above, without any additional terms or conditions.</p>
    <p>Unless required by applicable law or agreed to in writing, software distributed under the Licenses is distributed on an <b>"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND</b>, either express or implied.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>JAMES GOBER.</strong></sup>
</div>
