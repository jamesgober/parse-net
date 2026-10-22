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

The list below is the plan for 1.0. What ships in the current version is under [Status](#status-design-lock).

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

> **Note on performance:** the target is at least 20% faster than the best Rust competitor for each comparable operation, at equal or stronger strictness. Numbers are published in `docs/PERFORMANCE.md` from `0.6.0`; until then they are targets, not measurements.

---

<br>

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
parse-net = "0.2.0"

# Optional features:
parse-net = { version = "0.2.0", features = [
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

println!("parse-net {}", pn::VERSION);
```

The Tier 1 functions arrive from `0.3.0`, one plain call per field:

```text
pn::parse_media_type(b"text/html; charset=UTF-8")?           // MediaType view
pn::best_media(accept, &["text/html", "application/json"])    // Option<usize>
pn::http_date_at(b"Sun, 06 Nov 1994 08:49:37 GMT", now)?      // HttpDate
pn::if_none_match(if_none_match, &current_etag)?              // bool: answer 304
pn::byte_ranges(range, file_len, &mut buf)?                   // RangeOutcome
pn::parse_content_disposition(value)?.filename()              // prefers filename*
pn::sfv::parse_item(b"same-origin")?                          // Sec-Fetch-Site
pn::parse_host_port(b"example.com:8443")?                     // HostPort
```

---

## **What it is not**

- Not a protocol engine: message framing, start lines, and chunked bodies belong to http-net, h2-net, fcgi-net, and ws-net.
- Not a header map: the engine owns field storage.
- Not a URL parser (url-lib) or a base64 codec (encode-lib).
- Not cookie grammar (cookie-net) or a full email parser.
- Not a policy engine: it reports facts strictly; what to accept is the caller's call.

---

## **Status: design lock**

**Current Version:** `0.2.0` - the public API locked in [`docs/API.md`](./docs/API.md). No parsing code yet.
**Target:** `1.0.0` stable, per the roadmap in [`dev/ROADMAP.md`](./dev/ROADMAP.md).

**What's complete**:
- **Manifest and crate root** - edition 2024, MSRV 1.85, zero dependencies, `no_std`, `forbid(unsafe_code)`, `VERSION`.
- **CI** - Linux, macOS, and Windows on stable and 1.85; a bare-metal `thumbv7em-none-eabi` build; a zero-dependency check; package, audit, and deny.
- **Plan** - [`dev/PLAN.md`](./dev/PLAN.md): scope, requirements, design, threats, performance targets, testing, and the decision log.
- **API** - [`docs/API.md`](./docs/API.md): every public item through 1.0 with its signature, behaviour, errors, examples, and edge cases, and one coverage checklist per consumer (http-net, ws-net, cookie-net, form-net, smtp-net).

**What's planned next**:
- `0.3.0` ships the core http-net, ws-net, and cookie-net need: errors, limits, byte classes, scanning, writers, tokens, quoted strings, lists, parameters, media types, HTTP dates, `Host`, and percent-encoding.

**Note on API stability**: nothing is public yet beyond `VERSION`. The API was locked at `0.2.0`; names and signatures change only with a recorded decision until `1.0.0` freezes them, with the contract recorded in `docs/STABILITY-1.0.md`.

---

## **Documentation & Resources**

- **[API Reference](docs/API.md)** - every public item with examples
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
