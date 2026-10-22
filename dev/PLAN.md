# parse-net - Project Plan

> The design, strategy, and decision record for `parse-net`. A living document: every design decision, idea, or open question about parse-net is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Read order:** [`../REPS.md`](../REPS.md) -> [`DIRECTIVES.md`](./DIRECTIVES.md) -> **this file** -> [`ROADMAP.md`](./ROADMAP.md) -> [`../docs/API.md`](../docs/API.md).
>
> **Status:** scaffold, `0.1.0`. Design lock is `0.2.0`.

---

## Contents

1. [Purpose](#1-purpose)
2. [Where it sits](#2-where-it-sits)
3. [Scope](#3-scope)
4. [Requirements](#4-requirements)
5. [Design principles](#5-design-principles)
6. [Architecture](#6-architecture)
7. [Grammar notes and algorithms](#7-grammar-notes-and-algorithms)
8. [API outline](#8-api-outline)
9. [Threats](#9-threats)
10. [Performance](#10-performance)
11. [Testing](#11-testing)
12. [Ecosystem and dependencies](#12-ecosystem-and-dependencies)
13. [Competitors](#13-competitors)
14. [Open decisions](#14-open-decisions)
15. [Ideas](#15-ideas)
16. [Decision log](#16-decision-log)

---

## 1. Purpose

parse-net is the grammar layer for Internet message fields. It gives every protocol crate in the stack one correct, strict, fast, allocation-free implementation of:

- the byte classes of the ABNF (`tchar`, `field-vchar`, `qdtext`, `ctext`, `etagc`, `attr-char`, the MIME `token`, RFC 3986 classes, Structured Field key and token characters, and more);
- the shared lexical forms: tokens, optional whitespace, quoted strings with quoted pairs, comments, comma lists, parameters;
- the field values more than one crate reads or writes: media types, HTTP dates, quality values and content negotiation, entity tags, ranges, `Content-Disposition` with RFC 8187 `filename*`, `Cache-Control`, `Link`, `Forwarded` and `X-Forwarded-For`, `Authorization` and `WWW-Authenticate`, `Host`, `Origin`, Structured Field Values;
- the email lexical layer: header folding, RFC 5322 dates, RFC 2047 encoded words, MIME parameters with RFC 2231 continuations, `addr-spec`, `msg-id`;
- safe writers for all of the above, which cannot emit CR, LF, or NUL into a field value.

Every parse returns borrowed views into the caller's bytes. Nothing is copied unless the caller asks for a decoded form, and then it is written into a buffer the caller provides.

### 1.1 What it is not

| Not | Where that lives |
|---|---|
| a protocol engine (start lines, field-line splitting, chunked bodies, state machines) | http-net, h2-net, fcgi-net, ws-net |
| a header map or typed-header registry | the engine owns field storage; web-net may build typed accessors on top |
| a URL parser, URL normalizer, query-string parser, or urlencoded codec | url-lib (planned); form-net for bodies |
| a base64, base32, hex, or quoted-printable codec | encode-lib (planned) |
| cookie grammar and cookie semantics | cookie-net (it uses parse-net for tokens, dates, and host syntax) |
| a full email parser (bodies, multipart trees, charsets beyond UTF-8, US-ASCII, ISO-8859-1) | out of scope |
| a policy engine (which media types a route accepts, which proxies are trusted, which file names are safe) | customs-sec, bouncer-io, net-io, path-lib, service configuration |
| content sniffing, charset tables, IDNA, public suffix data | out of scope |

---

## 2. Where it sits

parse-net stands alone and depends on nothing. The protocol crates depend on it, so none of them carries its own copy of `token`, `quoted-string`, parameters, media types, dates, or Structured Field Values.

```
   http-net   ws-net   h2-net   fcgi-net   cookie-net   form-net   smtp-net   url-lib   fetch-net   web-net
      │         │        │         │           │           │          │          │          │         │
      └─────────┴────────┴─────────┴───────────┴───────────┴──────────┴──────────┴──────────┴─────────┘
                                                   │
                                              parse-net   (no dependencies; no_std; sans-IO; no allocation)
```

Engines frame messages (start lines, field lines, chunks, frames); parse-net reads what is inside a field value. The protocol parser slot of the service gateway still hosts a protocol engine; parse-net sits underneath every engine.

### 2.1 Consumers and what they take

| Consumer | Uses | Today |
|---|---|---|
| http-net | byte classes, field-value validation, tokens, OWS, comma lists (`Connection`, `Transfer-Encoding`, `Expect`, `Upgrade`), decimal parsing, `Host` syntax, IMF-fixdate formatting, number writers | own copies in `src/syntax.rs` and `src/blocking.rs` (section 6.3) |
| ws-net | tokens, OWS, comma lists with parameters (`Sec-WebSocket-Extensions`), field-value checks | own copies in `src/head.rs` and `src/handshake.rs` |
| cookie-net | `token`, OWS, IMF-fixdate (`Expires`), `Host` and domain syntax, safe writers, cookie byte classes | scaffold |
| form-net | media type and `boundary`, `Content-Disposition` (`name`, `filename`), RFC 2046 boundary validation, percent decoding | scaffold |
| smtp-net | folding, RFC 5322 date-time, encoded words, MIME parameters with RFC 2231, `addr-spec`, `msg-id`, media types | scaffold |
| web-net and the service layer | negotiation, entity tags and conditions, `Range`, `Cache-Control`, `Link`, `Content-Disposition`, `Forwarded` behind trusted proxies, `Origin`, Structured Fields (`Sec-Fetch-*`, `Priority`) | not started |
| url-lib (planned) | percent-encoding primitive, RFC 3986 byte classes, `Host` syntax | not started |
| fetch-net (planned) | `WWW-Authenticate`, `Retry-After`, `Content-Range`, `Link`, media types, dates | not started |
| csrf-sec adapters | `Origin`, `Sec-Fetch-Site` as a Structured Field token (csrf-sec itself stays protocol-free, D-017) | not started |
| customs-sec | media type checks on `Content-Type`, header value rules | plan only |

---

## 3. Scope

### 3.1 The rule that decides scope

A grammar goes into parse-net when **two or more crates** need it, or when it is the **lexical base** such grammars are built from. A grammar exactly one crate needs stays in that crate.

| Candidate | Decision | Reason |
|---|---|---|
| RFC 9110 field syntax: token, quoted-string, comments, OWS, BWS, lists, parameters | in (P0) | every HTTP crate; duplicated today in http-net and ws-net |
| media types and parameters | in (P0) | http-net callers, form-net, smtp-net, web-net, customs-sec, fetch-net |
| RFC 9651 Structured Field Values, every bare item type | in (P1) | `Sec-Fetch-*`, `Priority`, `Cache-Status`, `Proxy-Status`, `Content-Digest`, message signatures |
| HTTP-date: IMF-fixdate, RFC 850, asctime | in (P0) | http-net, cookie-net, web-net, fetch-net |
| RFC 5322 date-time and header grammar | in (P1 write, P2 read) | smtp-net; shares the calendar code with HTTP-date |
| RFC 2045 parameters, RFC 2047 encoded words, RFC 2231 continuations | in (P1) | smtp-net writes them; form-net may meet legacy encoded words |
| RFC 8187 `ext-value` and `filename*` | in (P0 decode, P1 encode) | web-net downloads, fetch-net, `Link` `title*` |
| negotiation: q-values, `Accept`, `Accept-Language`, `Accept-Encoding`, `Accept-Charset` | in (P1) | web-net, locale selection, static files, fetch-net |
| entity tags and lists | in (P1) | web-net, static files, cache-net, fetch-net |
| `Range`, `Content-Range`, `If-Range` | in (P1) | static files, fetch-net, resumable uploads later |
| `Content-Disposition` | in (P0) | form-net, web-net, fetch-net |
| `Cache-Control` | in (P1) | web-net, cache-net, fetch-net, proxy-net |
| `Link` (RFC 8288) | in (P2) | web-net, fetch-net, webhook-net |
| `Forwarded` and `X-Forwarded-*` with trusted-proxy resolution | in (P1) | service site step, web-net, serve-net, bouncer-io |
| `Authorization` and `WWW-Authenticate` | in (P1) | gateway credential locator, gate-net, fetch-net, oauth-net |
| percent-encoding | in, primitive only (P0) | RFC 8187 and RFC 9651 Display Strings need it here; url-lib builds URL encode sets on top (D-004) |
| base64 | out (encode-lib); parse-net validates the alphabet only | no second codec in the portfolio (D-002) |
| `Host` and `Origin` | in (P0 `Host`, P1 `Origin`) | http-net, `Forwarded`, csrf adapters, ws-net, url-lib |
| RFC 6265 cookie-date algorithm | out, cookie-net | one consumer (D-020) |
| cookie grammar | out, cookie-net | one consumer |
| RFC 9112 message syntax | out, http-net | HTTP/1.1 only |
| multipart body framing | out, form-net | body framing, not field grammar |
| quoted-printable | out, encode-lib | a codec (D-009) |
| `Content-Security-Policy`, `Strict-Transport-Security`, `Permissions-Policy` | out today (P3) | one consumer (D-021) |

### 3.2 Out of scope, also named

HPACK and QPACK (h2-net, h3-net); `Sec-WebSocket-Accept` computation (ws-net); trusted-proxy address sets (net-io and bouncer-io configuration; parse-net receives a predicate).

---

## 4. Requirements

### 4.1 Functional

| Id | Requirement | API items |
|---|---|---|
| FR-1 | Classify any byte against every ABNF class in 7.1 with one table lookup | CLS-1 to CLS-22 |
| FR-2 | Validate a field value per RFC 9110 section 5.5, reporting CR, LF, NUL, and other controls as distinct error kinds | SCN-3 |
| FR-3 | Recognise tokens, strip OWS (SP and HTAB only, never VT or FF), parse BWS | TXT-1 to TXT-4 |
| FR-4 | Parse quoted strings with quoted pairs; raw content zero-copy; unescape into a caller buffer; compare without unescaping | TXT-5 to TXT-12 |
| FR-5 | Parse comments with nesting, bounded by a depth limit, never by recursion | TXT-13, TXT-14 |
| FR-6 | Iterate list elements, never splitting inside a quoted string or comment, skipping empty elements up to a budget | LST-1 to LST-4 |
| FR-7 | Treat several field lines of one name as one combined list without copying | LST-3 |
| FR-8 | Parse parameters with case-insensitive names, token or quoted values, a duplicate policy whose default is refusal | PRM-1 to PRM-6 |
| FR-9 | Parse media types and media ranges; compare essence case-insensitively; expose `charset` and `boundary`; validate RFC 2046 boundaries | MED-1 to MED-12 |
| FR-10 | Parse q-values exactly (thousandths, no floating point) and select the best offer for `Accept`, `Accept-Language` (RFC 4647 lookup and basic filtering), `Accept-Encoding` (with the `identity` rules), `Accept-Charset` | NEG-1 to NEG-9 |
| FR-11 | Parse HTTP-date in all three forms, validating weekday, day of month, leap years; resolve RFC 850 years by the RFC 9110 50-year rule; format IMF-fixdate | DAT-1 to DAT-10 |
| FR-12 | Parse and format RFC 5322 date-time with numeric zones, comments, and (on request) obsolete zones | DAT-11 to DAT-13 |
| FR-13 | Parse entity tags and `If-Match` / `If-None-Match`; strong and weak comparison per RFC 9110 section 8.8.3.2 | ETG-1 to ETG-7 |
| FR-14 | Parse `Range` and `Content-Range`, resolve byte ranges with budgets on count and overlap, write `Content-Range` | RNG-1 to RNG-8 |
| FR-15 | Parse `Content-Disposition`, decode RFC 8187 (UTF-8, ISO-8859-1 transcoded), prefer `filename*`, refuse decoded control bytes; write attachment headers with an ASCII fallback | DSP-1 to DSP-7, EXT-1 to EXT-4 |
| FR-16 | Parse `Cache-Control` request and response directives, saturating delta-seconds at 2^31, recording duplicates and conflicts; write directives | CCH-1 to CCH-5 |
| FR-17 | Parse `Link` values with every target attribute, `rel` per RFC 8288, and `title*` | LNK-1 to LNK-4 |
| FR-18 | Parse `Forwarded` and `X-Forwarded-*`, resolve the client address from the right with a trust predicate, failing closed on malformed chains | FWD-1 to FWD-8 |
| FR-19 | Parse `Authorization` credentials and `WWW-Authenticate` challenges (token68 or auth-params) with the multiple-challenge comma ambiguity; extract `Bearer` and `Basic` payloads | ATH-1 to ATH-7 |
| FR-20 | Parse `Host` (reg-name, IPv4, IPv6, IPvFuture, port 0 to 65535) and `Origin` (`null` or a serialized origin) with same-origin comparison | HST-1 to HST-4, ORG-1 to ORG-4 |
| FR-21 | Percent-decode into a caller buffer (refusing malformed triples) and percent-encode with a named set and hex case | PCT-1 to PCT-6 |
| FR-22 | Parse RFC 9651 Items, Lists, Dictionaries with every bare item type, every limit and failure rule, zero-copy; serialize canonically | SFV-1 to SFV-16 |
| FR-23 | Unfold and fold email header fields within 78 and 998; encode and decode RFC 2047 words; parse and write MIME parameters with RFC 2231; parse `addr-spec` and `msg-id` | MAIL-1 to MAIL-14 |
| FR-24 | Every writer refuses CR, LF, NUL, and any byte its grammar forbids; no writer can produce a value its own parser rejects | WRT-1 to WRT-11, every `write_*` |
| FR-25 | One error type with a kind and a byte offset; errors never contain input bytes | ERR-1 to ERR-4 |
| FR-26 | One limits type with defaults that meet every RFC minimum and can be tightened | LIM-1 to LIM-3 |
| FR-27 | Optional owned forms (`alloc`) for values kept beyond the input buffer | OWN |

### 4.2 Non-functional

| Id | Requirement | How it is checked |
|---|---|---|
| NFR-1 | No allocation in any parse, compare, or write-into-slice path | counting-allocator tests over every public parse function and the fuzz corpora |
| NFR-2 | Linear time in the input length; no backtracking that revisits a byte more than a constant number of times | complexity tests at 1 KiB, 64 KiB, 1 MiB adversarial inputs; fuzzing with time budgets |
| NFR-3 | No recursion; nesting tracked by counters with a depth limit | review rule, plus tests at the limit and the limit plus one |
| NFR-4 | No panics on any input: no `unwrap`, `expect`, fallible indexing, or overflowing arithmetic on untrusted values | clippy denies (`indexing_slicing`, `arithmetic_side_effects` included), fuzzing, "never panics" property |
| NFR-5 | `no_std` without `alloc` builds and passes its tests; `alloc` and `std` only add | CI `--no-default-features` jobs and a `thumbv7em-none-eabi` build |
| NFR-6 | Deterministic: the same bytes (and the same `now`) give the same result everywhere | cross-platform CI on the same vector files |
| NFR-7 | At least 20% faster than the best Rust competitor for each comparable operation, at equal or stronger strictness | criterion benchmarks in `docs/PERFORMANCE.md` |
| NFR-8 | No regression for consumers: http-net and ws-net benchmarks after migration within 5% of before | benchmarks in those repositories |
| NFR-9 | Every public function taking untrusted input has a fuzz target and a property test | `fuzz/` target list (11.4) |
| NFR-10 | Every parser with a writer round-trips (`parse(write(x)) == x`) | property tests |
| NFR-11 | Error values are 8 bytes, `Copy`, and carry no input data | size assertion; `Debug` and `Display` tests |
| NFR-12 | Every public item documented with a runnable example; `#![deny(missing_docs)]` | `cargo doc` and doctests in CI |
| NFR-13 | MSRV 1.85; Linux, macOS, Windows on stable and MSRV | CI matrix |
| NFR-14 | Zero runtime dependencies in the default build; `cargo tree -e normal` shows only the crate | CI job `zero-deps` |
| NFR-15 | Public types are `Send + Sync + Unpin`, and `Copy` where they are views | compile-time assertions |
| NFR-16 | Strict by default: anything two conforming implementations could read differently is refused, unless the RFC tells recipients to accept it (then it is accepted and documented) | differential tests |

---

## 5. Design principles

1. **Validate, then view.** Every `parse_*` checks the whole value in one forward pass and returns a small `Copy` view over the input. Iterators on a view walk text already proven valid, so they yield items, never `Result`s, and cannot fail. A field is accepted or refused as a whole (RFC 9651 section 4.2 requires this for Structured Fields; strictness requires it everywhere else).
2. **Zero-copy.** Views hold `&'a [u8]` slices of the caller's bytes. Decoded forms go into a caller buffer through `*_into` functions, or are compared in place.
3. **No allocation, no recursion, no floating point.** Nesting is counted. Quality values are thousandths in a `u16`; Structured Field decimals are thousandths in an `i64`.
4. **Strict by default, lenient only where the RFC tells recipients to be.** Each leniency is documented and tested: empty list elements (RFC 9110 section 5.6.1.2), all three HTTP-date formats (section 5.6.7), token and quoted `Cache-Control` arguments (RFC 9111 section 5.2), missing base64 padding in Structured Field byte sequences (RFC 9651 section 4.2.7).
5. **Bytes, not strings.** Field values may contain `obs-text`, so inputs and views are `&[u8]`. Views offer `as_str()` returning `Option<&str>` for valid UTF-8, never a lossy conversion.
6. **Writers cannot produce what parsers refuse.** Every `write_*` validates as it writes; property tests prove `parse(write(x)) == x`.
7. **Errors carry a position, never content.** An error is a kind plus a byte offset, so logging an error cannot inject attacker bytes into a log line.
8. **One table.** Every byte class lives in one 256-entry `u32` table (1 KiB, built at compile time from the ABNF): classifying a byte is one load and one mask.

---

## 6. Architecture

### 6.1 Modules

```
src/
  lib.rs          crate docs, Tier 1 re-exports, VERSION, feature gates
  class.rs        the byte-class table and the is_* predicates (CLS)
  scan.rs         SWAR search and field-value validation (SCN)
  error.rs        ParseError, ErrorKind, WriteError (ERR)
  limits.rs       Limits (LIM)
  write.rs        Sink, SliceSink, CountSink, number and quoting writers (WRT)
  text.rs         token, OWS, BWS, quoted-string, comment, Word (TXT)
  list.rs         #rule lists, combined field lines (LST)
  param.rs        parameters (PRM)
  num.rs          decimal digits with overflow checks (NUM)
  media.rs        media types, media ranges, boundaries (MED)
  negotiate.rs    q-values and Accept-* selection (NEG)
  date.rs         civil calendar, HttpDate, MailDate (DAT)
  etag.rs         entity tags and conditions (ETG)
  range.rs        Range, Content-Range, If-Range (RNG)
  ext_value.rs    RFC 8187 (EXT)
  disposition.rs  Content-Disposition (DSP)
  cache.rs        Cache-Control (CCH)
  link.rs         Link (LNK)
  forwarded.rs    Forwarded, X-Forwarded-*, client address resolution (FWD)
  auth.rs         Authorization, WWW-Authenticate (ATH)
  host.rs         Host, authority host and port (HST)
  origin.rs       Origin (ORG)
  pct.rs          percent-encoding primitive (PCT)
  sfv/            mod.rs, parse.rs, item.rs, write.rs, visit.rs (SFV)
  mail/           mod.rs, fold.rs, words.rs, mime.rs, addr.rs (MAIL)
  owned.rs        owned forms, `alloc` feature (OWN)
```

Every module depends only on `class`, `scan`, `error`, `limits`, `write`, `text`, and `num`, except `disposition` and `link` (use `ext_value`), `negotiate` (uses `media`), `forwarded` and `origin` (use `host`), and `range` (uses `date` and `etag` for `If-Range`). The graph has no cycles.

### 6.2 Views and their sizes (64-bit)

| View | Holds | Size |
|---|---|---|
| `Quoted<'a>` | the bytes between the quotes, a "contains quoted pairs" flag | 24 bytes |
| `Word<'a>` | token or `Quoted` | 24 bytes |
| `Params<'a>` | the validated `;...` text, member count | 24 bytes |
| `MediaType<'a>` | type, subtype, `Params` | 56 bytes |
| `List<'a>` | the validated value, member count | 24 bytes |
| `HttpDate` | seconds since the Unix epoch as `i64` | 8 bytes |
| `EntityTag<'a>` | weak flag, opaque slice | 24 bytes |
| `sfv::Item<'a>` | bare item and `SfParams` | 64 bytes [est.] |
| `ParseError` | `ErrorKind` (`u8`) plus `u32` offset | 8 bytes |

Sizes are checked by tests so a change that grows them is noticed.

### 6.3 What moves out of http-net and ws-net

Read from the code on 2026-10-21. Each row is moved, not copied: the consumer deletes its copy in the release that adopts parse-net.

| Today | Goes to | Notes |
|---|---|---|
| http-net `syntax.rs` classes (`TCHAR`, `FIELD`, `TARGET`, `HEX`, `QDTEXT`) and `build_classes` | `class` | the table grows to `u32` to hold every class in 7.1 |
| http-net `is_tchar`, `is_token`, `is_ows`, `trim_ows` | `class::is_tchar`, `text::is_token`, `text::is_ows`, `text::trim_ows` | `trim_ows` keeps the deliberate refusal to strip VT and FF, with its explanation |
| http-net `check_field_value`, `check_field_bytes` (SWAR) | `scan::check_field_value` | returns `BareCr`, `LineFeed`, `Nul`, `Control`; http-net maps them to its own errors exactly as today |
| http-net `is_reason` | stays in http-net as a wrapper over `class::is_field_text` | reason-phrase is RFC 9112 grammar |
| http-net `is_target_chars` | `pct::validate_with(class::Class::URI_TARGET)` | url-lib later owns target parsing |
| http-net `is_host_value` | `host::parse_host_port` | adds real IPv4 and IPv6 validation (today `[zz]` passes the bracket check) |
| http-net `parse_decimal`, `hex_value` | `num::parse_u64`, `class::hex_value` | same behaviour: refuses signs, spaces, overflow |
| http-net `is_qdtext` | `class::is_qdtext` | used by chunk extensions |
| http-net `list_elements` | `list::elements` | quote-aware already; parse-net also skips commas inside comments and bounds empty elements (D-011) |
| http-net `find_byte` | `scan::find_byte` | same SWAR algorithm and tests |
| http-net `push_hex`, `push_decimal` | `write::write_hex_u64`, `write::write_decimal_u64` | any `Sink`, not only `Vec<u8>` |
| http-net `blocking.rs` `http_date`, `two_digits`, `civil_from_days` | `HttpDate::format`, `date::civil_from_days` | full range (years 1 to 9999) instead of clamping at the epoch |
| http-net `head.rs` header scanning, framing, target forms | stays in http-net | RFC 9112 message syntax |
| ws-net `head.rs` `is_token`, `trim_ows`, `is_control`, `is_visible` | `text::is_token`, `text::trim_ows`, `scan::check_field_value`, `class::is_vchar` | ws-net keeps its line framing |
| ws-net `handshake.rs` `list`, `list_has` | `list::elements`, `list::contains_token` | ws-net can then accept `Sec-WebSocket-Extensions` with parameters |
| ws-net `base64.rs` | encode-lib | not parse-net (D-002) |
| ws-net `sha1.rs` | crypt-io | hashing is crypt-io's |

Migration rule: http-net and ws-net adopt parse-net in their next minor release after parse-net 0.3.0, with benchmarks before and after (NFR-8); their manifests change from "no dependencies" to "no third-party dependencies".

### 6.4 Feature flags

| Feature | Default | Adds |
|---|---|---|
| (none) | yes | everything not marked otherwise; `no_std`, no `alloc` |
| `alloc` | no | owned forms, `Sink for Vec<u8>`, functions returning `String` |
| `std` | no | `HttpDate` to and from `SystemTime`; Tier 1 `http_date` reading the system clock; implies `alloc` |
| `encode-lib` | no | base64 helpers on Structured Field byte sequences, `Basic` credentials, RFC 2047 `B` words |

`core::error::Error` is implemented without `std` (stable since 1.81).

### 6.5 Memory and work bounds

| Bound | Source | Default |
|---|---|---|
| list members | RFC 9651 section 3.1 minimum 1024 | 1024 |
| inner list members | RFC 9651 section 3.1.1 minimum 256 | 256 |
| parameters per item or field | RFC 9651 section 3.1.2 minimum 256 | 256 |
| dictionary members | RFC 9651 section 3.2 minimum 1024 | 1024 |
| key length | RFC 9651 minimum 64 | 256 |
| string length (decoded) | RFC 9651 section 3.3.3 minimum 1024 | 1024 |
| token length | RFC 9651 section 3.3.4 minimum 512 | 512 |
| byte sequence length (decoded) | RFC 9651 section 3.3.5 minimum 16384 | 16384 |
| empty list elements | RFC 9110 section 5.6.1.2 "reasonable number" | 16 |
| comment depth | none in the RFC | 8 |
| ranges | RFC 9110 section 14.2 permits refusal | 16 |
| RFC 2231 sections | none in the RFC | 32 |
| encoded words per field | none in the RFC | 64 |
| forwarded hops | none in the RFC | 16 |

Every bound is checked before the work it governs. None allocates: they bound loops.

---

## 7. Grammar notes and algorithms

### 7.1 The byte-class table

One `static CLASSES: [u32; 256]`, built by a `const fn` from the ABNF, one bit per class. Every predicate is `CLASSES[b as usize] & BIT != 0`.

| Bit | Class | ABNF (source) |
|---|---|---|
| 0 | `TCHAR` | `"!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "\|" / "~" / DIGIT / ALPHA` (RFC 9110 section 5.6.2) |
| 1 | `VCHAR` | `%x21-7E` (RFC 5234) |
| 2 | `OBS_TEXT` | `%x80-FF` (RFC 9110 section 5.5) |
| 3 | `FIELD_TEXT` | VCHAR, obs-text, SP, HTAB |
| 4 | `QDTEXT` | `HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text` (section 5.6.4) |
| 5 | `CTEXT` | `HTAB / SP / %x21-27 / %x2A-5B / %x5D-7E / obs-text` (section 5.6.5) |
| 6 | `QUOTED_PAIR` | `HTAB / SP / VCHAR / obs-text` (the byte after `\`) |
| 7 | `ETAGC` | `"!" / %x23-7E / obs-text` (section 8.8.3) |
| 8 | `ATTR_CHAR` | `ALPHA / DIGIT / "!" / "#" / "$" / "&" / "+" / "-" / "." / "^" / "_" / "`" / "\|" / "~"` (RFC 8187 section 3.2.1) |
| 9 | `MIME_TOKEN` | any CHAR except SP, CTLs, and `tspecials` (RFC 2045 section 5.1); allows `{` and `}`, unlike `TCHAR` |
| 10 | `UNRESERVED` | `ALPHA / DIGIT / "-" / "." / "_" / "~"` (RFC 3986 section 2.3) |
| 11 | `SUB_DELIM` | `"!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="` (section 2.2) |
| 12 | `PCHAR_NO_PCT` | `unreserved / sub-delims / ":" / "@"` |
| 13 | `URI_TARGET` | `pchar / "/" / "?"` plus `%` (http-net's `TARGET`) |
| 14 | `HEXDIG` | `DIGIT / "A"-"F" / "a"-"f"` |
| 15 | `SF_KEY_START` | `lcalpha / "*"` (RFC 9651 section 3.1.2) |
| 16 | `SF_KEY` | `lcalpha / DIGIT / "_" / "-" / "." / "*"` |
| 17 | `SF_TOKEN` | `tchar / ":" / "/"` (section 3.3.4) |
| 18 | `SF_STRING` | `%x20-21 / %x23-5B / %x5D-7E` (section 3.3.3) |
| 19 | `TOKEN68` | `ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/"` (RFC 9110 section 11.2); `=` is padding |
| 20 | `B64` | `A-Z a-z 0-9 + /` (RFC 4648 section 4); `=` apart |
| 21 | `ATEXT` | RFC 5322 section 3.2.3 |
| 22 | `BCHAR_NOSPACE` | RFC 2046 section 5.1.1 `bcharsnospace` |
| 23 | `COOKIE_OCTET` | `%x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E` (rfc6265bis section 4.1.1), exposed for cookie-net |
| 24 | `AV_OCTET` | `%x20-3A / %x3C-7E`, same source |
| 25 | `LINK_PTOKEN` | reserved for RFC 8288 `ptokenchar`; unused at 1.0 |

The table test checks every class for all 256 bytes against an independent slow implementation written straight from the ABNF.

### 7.2 Quoted strings

The parser finds the closing `"` by scanning `QDTEXT` bytes and skipping the byte after each `\` (which must be `QUOTED_PAIR`), recording whether any `\` was seen. `as_plain()` returns the raw content when there is no quoted pair (the common case). `unescape_into` writes the value with each quoted pair replaced by the escaped byte. `eq_bytes` and `eq_ignore_ascii_case` compare the unescaped value without a buffer. A token and a quoted string with the same content compare equal (RFC 9110 section 5.6.6).

### 7.3 Lists and combined field lines

A comma ends an element only outside quoted strings and comments (and outside the angle brackets of a `Link` URI reference; `link` has its own walker). Empty elements are skipped up to `Limits::max_empty_elements`; one more is an error. Several field lines of one name are one list (RFC 9110 section 5.3): `list::combined` walks them as if joined by `, `, without joining. An empty line adds nothing. An element never spans two lines: a quoted string that starts on one line and ends on another is `UnterminatedQuote`.

### 7.4 Errors

```rust
pub struct ParseError { kind: ErrorKind, at: u32 }   // 8 bytes, Copy
```

`at` is the offset of the first byte that could not be accepted, relative to the value passed in. For combined lines it is relative to the start of the line, and the line index is packed into the upper 8 bits (offsets above 2^24 saturate). `ErrorKind` is a `#[non_exhaustive]` `u8` enum; each variant documents what was refused and what to do. `Display` prints the fixed message and the offset only. `WriteError` is separate: `Full`, `Forbidden { at }`, `OutOfRange`, `NotToken`.

### 7.5 Percent-encoding and base64 boundaries

parse-net needs percent-encoding inside its own grammars (RFC 8187 value-chars, RFC 9651 Display Strings with lowercase hex only, RFC 7578 file names), and may depend on nothing, so it holds the primitive: decode triples and literal bytes into a caller buffer, validate triples, encode with an `EncodeSet` (a 256-bit bitmap) and a hex case. url-lib owns everything URL-specific and depends on parse-net for the primitive and the RFC 3986 classes.

parse-net never contains a base64 codec. Where a grammar contains base64 (Structured Field byte sequences, `Basic` token68, RFC 2047 `B` words), it validates the alphabet and framing and returns a borrowed view with `decoded_len()`. With the `encode-lib` feature, views gain `decode_into` and writers gain byte-sequence output. Notes for encode-lib's design: RFC 9651 section 4.2.7 says missing padding and non-zero pad bits SHOULD NOT cause failure, so encode-lib needs a lenient mode beside its canonical one; csrf-sec's constant-time base64url should move there too.

### 7.6 Trusted-proxy resolution

```
 input: peer address, the configured header source (Forwarded or X-Forwarded-For, never both merged),
        a Trust predicate, max_hops
 1 peer not trusted                      -> ClientAddress::Peer(peer)          header ignored
 2 parse the whole chain (all lines)     -> malformed anywhere -> Err(Malformed)   caller uses the peer
 3 more than max_hops elements           -> Err(TooManyHops)
 4 walk from the rightmost element leftwards:
      address, trusted                   -> continue
      address, untrusted                 -> ClientAddress::Forwarded { addr, hops }
      "unknown" or obfuscated            -> ClientAddress::Unknown { hops }    nothing left of it is trustworthy
 5 every element trusted                 -> ClientAddress::Forwarded { leftmost, n }
```

Both header kinds present: the configured one is used and the other is reported, never combined (combining is a parser differential). IPv6 in `Forwarded` must be quoted and bracketed (RFC 7239 section 6). `X-Forwarded-For` has no RFC: comma-separated IPv4 and IPv6 literals with OWS, optional brackets around IPv6, optional `:port` after IPv4 or bracketed IPv6; anything else is `Malformed` (D-016). Cost [est.]: 30 to 80 ns for three hops.

### 7.7 Content negotiation

`Accept`: each media range has a specificity (type with parameters 4, exact type 3, `type/*` 2, `*/*` 1); an offer's weight is the q-value of the most specific matching range; `q=0` means not acceptable; ties go to the earlier offer; an absent header gives every offer 1.0; a malformed header is treated as absent and reported (`HeaderIgnored`). `Accept-Language`: RFC 4647 section 3.4 lookup by default, basic filtering (section 3.3.1) as the alternative. `Accept-Encoding`: `identity` acceptable unless `identity;q=0` or `*;q=0` with no explicit `identity`; an empty value means only `identity`; `x-gzip` equals `gzip`. `Accept-Charset`: as `Accept-Encoding` without the `identity` rule. Work is bounded by `max_list_members` times the offer count.

### 7.8 Dates

Calendar: Howard Hinnant's `days_from_civil` and `civil_from_days` over `i64` days, years 1 to 9999; outside is `OutOfRange`. IMF-fixdate is fixed 29 bytes parsed by position; names are case-sensitive; the weekday must agree (`WeekdayMismatch`). RFC 850 years: a date more than 50 years in the future is taken as the most recent past year with the same last two digits; that needs `now`, passed explicitly (D-005). asctime: day padded with a space or a second digit. Second `60`: refused in HTTP-date unless `Limits::allow_leap_second`; accepted in RFC 5322 dates and mapped to `59` (D-006). Formatting writes into a `[u8; 29]`.

### 7.9 Structured Field Values

The parser follows RFC 9651 section 4.2 as a loop with explicit state (top level, inner list, parameters), not recursion; depth is at most 2. Leading and trailing SP are discarded; HTAB only around list and dictionary separators. Duplicates in dictionaries and parameters: the last wins; views keep all members in order and `get` returns the last match. Integers at most 15 digits; decimals 12 integer and 3 fractional digits, stored as thousandths; Dates are `@` and an Integer; Display Strings use lowercase hex only and are UTF-8 validated during the parse by an incremental validator (no buffer). Byte sequences: alphabet and framing checked; padding optional on input; serialization always pads. Multi-line fields fail as a whole when any line fails.

### 7.10 `WWW-Authenticate`

`1#challenge` with comma-separated parameters inside a challenge, decided in one pass:

```
 token, 1*SP, then (token BWS "=" ...)           -> parameter of the current challenge
 token, 1*SP, then a token68                     -> new challenge with token68
 token then end, ",", or 1*SP and a token not followed by "=" -> new challenge, no payload
 token BWS "=" BWS (token / quoted-string)       -> parameter of the current challenge
```

A token68 ends at `,` or end; trailing `=` belongs to it. A repeated parameter name within one challenge is refused (RFC 9110 section 11.2). Scheme names compare case-insensitively.

### 7.11 Ranges

`range-unit "=" range-set`; `bytes` case-insensitive; other units reported as `NotBytes`; `first > last` invalid; numbers overflow-checked. Resolution: suffix ranges become absolute; `last` beyond the end is clamped; a range with `first >= length` is dropped; a zero suffix is unsatisfiable; nothing left gives `Unsatisfiable` (416). Budgets: more than `max_ranges`, more than two overlapping ranges, or descending order beyond that count give `Ignore` (serve 200). Coalescing only on request. Output goes into a caller array.

### 7.12 RFC 2231 reassembly without allocation

Section spans are collected into a fixed stack array (`[Span; 32]`, bounded by `max_rfc2231_sections`) in one pass, checked to be numbered 0 to n-1 without gaps or duplicates with a charset only on section 0, then decoded in order into the caller buffer. Linear in the parameters.

### 7.13 Writers

```rust
pub trait Sink {
    fn put(&mut self, bytes: &[u8]) -> Result<(), Full>;
    fn remaining(&self) -> Option<usize> { None }   // lets writers fail before writing half a value
}
```

Implemented for `SliceSink` (a cursor over `&mut [u8]`), `CountSink` (counts, writes nothing), and with `alloc` for `Vec<u8>`. Writers that can fail part way check `remaining()` first where the sink knows it, so a `SliceSink` never holds a half-written value after an error. `write_quoted` escapes only `"` and `\` and refuses CTLs other than HTAB. `write_word` writes a token when it can and a quoted string otherwise.

---

## 8. API outline

The full API, with signatures, errors, and examples, is written in `docs/API.md` at the `0.2.0` design lock. Item ids, grades (P0 to P3), tiers (1 to 3), and the version that ships each group:

| Group | Ids | Ships |
|---|---|---|
| Root | ROOT-1 (`VERSION`) | 0.1 |
| Errors | ERR-1 to ERR-4 | 0.3 |
| Limits | LIM-1, LIM-2 (0.3); LIM-3 (0.4) | 0.3, 0.4 |
| Byte classes | CLS-1 to CLS-22 | 0.3 |
| Scanning, numbers | SCN-1 to SCN-4, NUM-1 (0.3); NUM-2 (0.4) | 0.3, 0.4 |
| Writers | WRT-1 to WRT-11 | 0.3 |
| Lexical forms | TXT-1 to TXT-12 (0.3); TXT-13, TXT-14 (0.4) | 0.3, 0.4 |
| Lists | LST-1 to LST-4 | 0.3 |
| Parameters | PRM-1 to PRM-3, PRM-5, PRM-6 (0.3); PRM-4 (0.4) | 0.3, 0.4 |
| Media types | MED-1 to MED-6, MED-9, MED-10, MED-12 (0.3); MED-7, MED-8 (0.4); MED-11 (0.5) | 0.3 to 0.5 |
| Negotiation | NEG-1 to NEG-9 | 0.4 |
| HTTP dates | DAT-1 to DAT-10 | 0.3 |
| Mail dates | DAT-11 to DAT-13 | 0.5 |
| Entity tags | ETG-1 to ETG-7 | 0.4 |
| Ranges | RNG-1 to RNG-8 | 0.4 |
| RFC 8187, Content-Disposition | EXT-1 to EXT-4, DSP-1 to DSP-6 (0.4); DSP-7 (0.5) | 0.4, 0.5 |
| Cache-Control | CCH-1 to CCH-5 | 0.4 |
| Link | LNK-1 to LNK-4 | 0.5 |
| Forwarded | FWD-1 to FWD-6, FWD-8 (0.4); FWD-7 (0.5) | 0.4, 0.5 |
| Authorization | ATH-1, ATH-2, ATH-4, ATH-6 (0.4); ATH-3, ATH-5, ATH-7 (0.5) | 0.4, 0.5 |
| Host, Origin | HST-1 to HST-4 (0.3); ORG-1 to ORG-4 (0.4) | 0.3, 0.4 |
| Percent-encoding | PCT-1 to PCT-3, PCT-5, PCT-6 (0.3); PCT-4 (0.4) | 0.3, 0.4 |
| Structured Fields | SFV-1 to SFV-12, SFV-14, SFV-15 (0.4); SFV-13, SFV-16 (0.5) | 0.4, 0.5 |
| Email lexical layer | MAIL-1 to MAIL-14 | 0.5 |
| Owned forms | OWN | 0.5 |

Tier 1 (documented first in the README and rustdoc) is a set of free functions per field, because a grammar library has no single job: `parse_media_type`, `list`, `best_media`, `best_language`, `best_encoding`, `best_charset`, `http_date_at`, `http_date` (std), `HttpDate::from_unix` and `format`, `if_none_match`, `if_match`, `byte_ranges`, `parse_content_disposition`, `response_cache_control`, `request_cache_control`, `client_address`, `bearer`, `basic`, `parse_host_port`, `parse_origin`, `sfv::parse_item`, `sfv::parse_list`, `sfv::parse_dictionary`, `mail::fold`, `mail::encode_words`, `mail::parse_addr_spec`.

Grade counts (approximate, by item rows): P0 about 60, P1 about 95, P2 about 30, P3 3. P0 ships with the version that introduces it; P1 and P2 by 1.0; P3 may come after 1.0.

---

## 9. Threats

Every threat has an attack test that must fail to get through. Costs are estimates until measured.

| Id | Threat | Defence | Test | Cost [est.] |
|---|---|---|---|---|
| T1 | header injection through a written value | every writer validates as it writes; CR, LF, NUL, CTL refused | `test_writers_refuse_crlf_in_every_position` over every writer and every byte 0x00 to 0x1F, 0x7F | 0.1 ns per byte |
| T2 | decoded control bytes re-emitted (`%0D%0A` in an ext-value or encoded word) | decoders refuse CTL in output (`ControlInDecoded`) | `test_ext_value_percent_crlf_refused`, `test_encoded_word_crlf_refused`, `test_basic_credentials_ctl_refused` | none extra |
| T3 | comma inside a quoted string split by one parser and not another | quote- and comment-aware walker; unterminated quotes refused | `test_list_comma_in_quotes_is_one_element`, differential against the naive splitter | none |
| T4 | duplicate parameters read first by one component and last by another | `DuplicatePolicy::Refuse` default; RFC rules applied explicitly where they differ | `test_content_disposition_duplicate_filename_refused`, `test_media_type_duplicate_charset_refused` | none |
| T5 | case differentials (`Charset`, `w/`, `bearer`) | case rules per RFC, table-driven | `test_case_rules_table` | none |
| T6 | whitespace differentials (VT, FF, NBSP) | OWS is SP and HTAB only | `test_trim_ows_never_strips_vt_ff_nbsp`, `test_utf8_nbsp_prefix_not_trimmed` | none |
| T7 | `filename` vs `filename*` precedence; invalid `filename*` ignored by one component | `filename*` preferred when valid; an invalid `filename*` refuses the field | `test_invalid_filename_star_refuses_field` | none |
| T8 | multiple field lines combined differently | `combined` APIs read every line; documentation lists which fields are lists | `test_combined_equals_joined` property | none |
| T9 | quadratic work (nested comments, many parameters, many elements, many `Accept` members times offers) | counters and limits checked before work; linear walkers | `test_complexity_linear` at 1 KiB, 64 KiB, 1 MiB | a counter per element |
| T10 | stack exhaustion through nesting | no recursion; depth counters | `test_comment_depth_limit_plus_one_refused` at depth 10,000 | none |
| T11 | integer overflow (ranges, delta-seconds, SF integers, `Content-Range`, q-values) | checked arithmetic; saturation only where the RFC says | `test_range_u64_max_plus_one`, `test_delta_seconds_saturates`, `test_sf_integer_16_digits_refused` | none |
| T12 | range abuse to amplify work or output | `max_ranges` 16, overlap and order rules give `Ignore` | `test_range_17_ranges_ignored`, `test_range_three_overlapping_ignored` | 10 ns per range |
| T13 | client address spoofing through `X-Forwarded-For` | header ignored unless the peer is trusted; walk from the right; malformed fails closed | `test_xff_untrusted_peer_ignored`, `test_xff_leftmost_spoof_ignored`, `test_xff_malformed_fails_closed` | 30 to 80 ns |
| T14 | `Forwarded` and `X-Forwarded-For` both present and disagreeing | one chosen by configuration, never merged, the other reported | `test_both_forwarded_headers_reported` | none |
| T15 | host confusion (`a.com:80@b.com`, `127.1`, mapped IPv6, trailing dot) | userinfo refused; partial IPv4 refused; mapped IPv6 returned as V6; trailing dot kept | `test_host_userinfo_refused`, `test_host_partial_ipv4_refused` | none |
| T16 | `Origin` tricks (`null`, suffix hosts, trailing slash, case) | exact grammar; whole-host comparison | `test_origin_suffix_attack_not_same`, `test_origin_trailing_slash_refused` | none |
| T17 | file name tricks (`../`, `\`, NUL, overlong UTF-8, bidi override) | CTL and invalid UTF-8 refused; separators and bidi controls reported | `test_filename_nul_refused`, `test_filename_overlong_utf8_refused`, `test_filename_bidi_reported` | 1 ns per byte |
| T18 | charset confusion in ext-value | only the declared charset; unknown refused | `test_ext_value_charset_matrix` | none |
| T19 | Unicode attacks in Display Strings and encoded words | strict UTF-8 validation | `test_display_string_surrogate_refused` | none |
| T20 | date differentials (weekday, `Feb 30`, two-digit years, leap second, zone) | strict calendar; 50-year rule with explicit `now`; only `GMT` | `test_http_date_rejections_table` | none |
| T21 | `Authorization` confusion (two schemes, duplicate params) | one credential per field; duplicates refused; `Debug` redacted | `test_auth_duplicate_param_refused`, `test_credentials_debug_redacted` | none |
| T22 | log injection through error messages | errors carry kind and offset only | `test_error_display_contains_no_input` (and a fuzz assertion) | none |
| T23 | memory exhaustion | no allocation in any parse | counting allocator over all fuzz corpora | none |
| T24 | base64 differences in SF byte sequences (padding, pad bits) | RFC 9651 section 4.2.7 rules exactly | `test_sf_byteseq_padding_rules` | none |
| T25 | Unicode smuggled into tokens or names | byte classes are ASCII; bytes above 0x7F are only obs-text inside values | `test_tchar_table_exhaustive` | none |

parse-net never decides policy: it reports facts strictly. What to do with a duplicate under a caller-chosen policy, which proxies to trust, which file names to accept, belongs to the caller.

---

## 10. Performance

### 10.1 Targets

| Operation | Input | Target [est.] | Compared with |
|---|---|---|---|
| `check_field_value` | 64-byte ASCII value | 6 ns | http-net today (same algorithm) |
| `parse_media_type` | `text/html; charset=utf-8` | 25 ns | `mime` 0.3.17 [est. 40 ns] |
| `best_media` | Chrome's default `Accept`, 3 offers | 150 ns | no Rust crate; hand loop with `mime` |
| `HttpDate::parse_imf_fixdate` | 29 bytes | 10 ns | `httpdate` 1.0.3 [est. 20 ns] |
| `HttpDate::format` | | 8 ns | `httpdate::fmt_http_date` (allocates) [est. 40 ns] |
| `sfv::parse_list` | 10 tokens with one parameter each | 120 ns | `sfv` 0.16.0 owned [est. 600 ns], visitor [est. 200 ns] |
| `sfv::parse_dictionary` | 5 members | 150 ns | `sfv` 0.16.0 [est. 500 ns] |
| `if_none_match` | 3 tags | 20 ns | `headers::IfNoneMatch` [est. 150 ns] |
| `byte_ranges` | `bytes=0-499` | 40 ns | `headers::Range` [est. 120 ns] |
| `parse_content_disposition` | attachment with `filename` and `filename*` | 60 ns | `content_disposition` 0.4.0 [est. 400 ns], `mailparse` [est. 500 ns] |
| `response_cache_control` | `public, max-age=31536000, immutable` | 60 ns | `headers::CacheControl` [est. 150 ns] |
| `client_address` | 3-hop XFF, IPv4 | 60 ns | no crate |
| `mail::encode_words` | 40-byte UTF-8 subject | 200 ns | to be chosen at 0.6 |
| `MailDate::parse` | `Wed, 21 Oct 2026 17:38:00 +0200` | 40 ns | `mailparse::dateparse` [est. 150 ns] |

Every competitor number is an estimate until measured in 0.6. Each comparable row must be at least 20% faster than the best Rust competitor measured, at equal or stronger strictness, or it is a defect with a plan.

### 10.2 Method

criterion benchmarks in `benches/`, one file per module, inputs from real traffic shapes stored in `benches/data/`. Competitors are dev-dependencies only, benchmarked through their public API on the same inputs, including their allocation. Results in `docs/PERFORMANCE.md` with CPU, OS, compiler, and commands. More than 5% slower on any benchmark blocks the change. Consumer gate: http-net and ws-net run their suites before and after adoption.

### 10.3 `#[inline]`

Small classification and scanning functions are called across the crate boundary from http-net and ws-net; a non-generic function in another crate is not inlined without LTO. Each `#[inline]` is justified by the consumer benchmark (NFR-8) and recorded here when measured.

### 10.4 Efficiency

No allocation, no system calls, no clock reads (except Tier 1 `http_date` under `std`), no global state. One 1 KiB class table plus small month and weekday tables; all static data under 4 KiB [est.].

---

## 11. Testing

### 11.1 Unit tests

At the bottom of every source file, for every function and every `Ok` and `Err` path, named `test_<subject>_<condition>_<expected>`. Every `ErrorKind` variant has at least one test that produces it.

### 11.2 Conformance suites and vectors

| Source | Used for |
|---|---|
| httpwg `structured-field-tests` | SFV parse and serialize, whole and split into lines at member boundaries |
| greenbytes `tc2231` Content-Disposition cases | DSP and EXT, each case with a recorded verdict |
| RFC 9110 examples (5.6, 8.3, 8.8.3.2, 12.5, 14.1.2, 14.4) | text, media, etag, negotiation, ranges |
| RFC 9111 section 5.2 | cache |
| RFC 7239 sections 4 and 7 | forwarded |
| RFC 8288 section 3.5 | link |
| RFC 6266 appendix, RFC 8187 section 3.2.3 | disposition, ext-value |
| RFC 4647 section 3 | language matching |
| RFC 2047 section 8, RFC 2231 sections 3 and 4 | mail words and parameters |
| RFC 5322 appendix A | addr-spec, mailbox, date-time |
| RFC 9110 section 5.6.7 | dates |

Vectors are stored as data files in `tests/vectors/` so they run identically everywhere.

### 11.3 Property tests (proptest)

Never panics (every parse over arbitrary bytes); never allocates (counting allocator); round trips for every writer; combined lines (splitting a list at member boundaries into 1 to 8 lines gives the same members); SWAR equals bytewise; budgets never exceeded; HTTP-date `format(parse(x)) == x` and `parse(format(d)) == d`.

### 11.4 Fuzz targets (cargo-fuzz, corpus outside the repository)

`text_quoted`, `text_comment`, `list`, `params`, `media_type`, `media_range`, `accept_negotiate`, `http_date`, `mail_date`, `etag_condition`, `range`, `content_range`, `ext_value`, `content_disposition`, `cache_control`, `link`, `forwarded`, `xff`, `authorization`, `www_authenticate`, `host`, `origin`, `pct_decode`, `sfv_item`, `sfv_list`, `sfv_dictionary`, `sfv_roundtrip`, `mail_words`, `mime_params`, `addr_spec`, `fold_unfold`, and the differential targets (15). Each runs 24 hours clean before 1.0.

### 11.5 Differential tests

Dev-only comparisons with `httpdate`, `mime`, `sfv`, `headers`, `content_disposition`, and `mailparse` over the vectors and corpora. Every disagreement is recorded in `tests/differential/verdicts.md` (ours right, theirs right, ambiguous with the RFC text). An "ours wrong" verdict is a bug.

### 11.6 Complexity tests

For every walker, inputs of 1 KiB, 64 KiB, and 1 MiB with adversarial shapes: time scales linearly (within 1.2 of the size ratio) and the function returns the expected limit error.

### 11.7 Edge cases

The full edge-case list per module (byte classes, field values, OWS, quoted strings, comments, lists, parameters, media types, q-values, negotiation, dates, RFC 5322 dates, entity tags, ranges, Content-Range, ext-value and Content-Disposition, Cache-Control, Link, Forwarded and XFF, Authorization, WWW-Authenticate, Host, Origin, percent-encoding, SFV, mail) is the checklist each module's tests are written against. It is kept in `docs/API.md` beside each item from `0.2.0` on, so the test list and the contract stay in one place.

---

## 12. Ecosystem and dependencies

### 12.1 Uses

Nothing by default. Optional, non-default: `encode-lib` (first party, zero dependencies, `no_std`) for base64 decoding, once published (D-002). Dev-only: `proptest`, `criterion`, and competitor crates as benchmark and differential oracles.

### 12.2 Needs (not built yet)

| Crate | For | If it is late |
|---|---|---|
| encode-lib | base64 decode helpers behind the `encode-lib` feature | the helpers move to 0.6 and the move is recorded; no private codec is added (D-002) |
| url-lib | nothing; it depends on parse-net | n/a |

### 12.3 Talks to

Nothing at run time. Consumers are listed in 2.1.

---

## 13. Competitors

Read on 2026-10-21. No single Rust crate covers this scope; each covers a slice.

| Crate | Version | What it is | Runtime dependencies |
|---|---|---|---|
| `httparse` | 1.10.1 | HTTP/1.x head splitter with SIMD | none |
| `headers` | 0.4.2 | typed headers over `http` | `http`, `headers-core`, `base64`, `bytes`, `httpdate`, `mime`, `sha1` |
| `mime` | 0.3.17 | media type parsing | none |
| `sfv` | 0.16.0 | RFC 9651 parse and serialize, visitor API | `base64`, `ref-cast`, optional `indexmap`, `arbitrary` |
| `httpdate` | 1.0.3 | HTTP-date; years 1970 to 9999; RFC 850 pivot at 70 | none |
| `mail-parser` | 0.11.9 | liberal full email parser | `hashify`; optional `encoding_rs`, `rkyv`, `serde` |
| `mailparse` | 0.18.0 | email parser with header helpers | `charset`, `data-encoding`, `quoted_printable` |
| `content_disposition` | 0.4.0 | one parse function | `charset` |

Gaps parse-net closes: negotiation, `Forwarded` with trusted-proxy resolution, `Link`, `WWW-Authenticate`, and the email lexical layer, with no dependencies and no allocation; RFC 850 years by the RFC 9110 rule instead of a fixed pivot; dates before 1970. Where parse-net is behind by design: three charsets (UTF-8, US-ASCII, ISO-8859-1) against mail-parser's forty-one; SWAR (no `unsafe`) instead of httparse's SIMD, which targets longer inputs than single field values.

---

## 14. Open decisions

Every decision in the specification is closed (section 16). Questions that arise during the build are recorded here with a recommendation before they are acted on.

| Id | Question | Recommendation |
|---|---|---|
| (none open) | | |

---

## 15. Ideas

Each version adds at least one new defence idea: hypothesis, method, expected cost.

- **0.3: differential oracle in CI.** Hypothesis: running each parser and the corresponding competitor on the same fuzz input and flagging accept/refuse disagreements surfaces strictness bugs earlier than review. Method: dev-only fuzz targets comparing parse-net with `httpdate`, `mime`, `sfv`, `headers`, recording disagreements as corpus entries with a written verdict. Cost: CI time only (one hour per week per target [est.]).
- **0.4: writer-parser closure check.** Hypothesis: any byte string a writer accepts parses back to the same value. Method: proptest over random inputs to every writer, then parse. Cost: test time only.

---

## 16. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-10-21 | Zero runtime dependencies in the default build, first party included; `no_std` without `alloc` is the base build; sans-IO; `#![forbid(unsafe_code)]` with no exception | James: parse-net "depends on nothing" and the protocol crates depend on it. SWAR scanning needs no `unsafe` |
| D-002 | 2026-10-21 | base64: parse-net validates the alphabet and framing only; decoding comes through the optional, non-default `encode-lib` feature. If encode-lib is not published by 0.5, the decode helpers move to 0.6 and the move is recorded; no private codec is added (PN-2) | one codec in the portfolio |
| D-003 | 2026-10-21 | Name `parse-net` (PN-1) | James's choice; free on crates.io; the crate is about network message formats and `-net` matches its consumers |
| D-004 | 2026-10-21 | The percent-encoding primitive lives in parse-net; url-lib depends on it and owns URL encode sets and parsing (PN-3) | parse-net's own grammars need it and it may depend on nothing |
| D-005 | 2026-10-21 | RFC 850 two-digit years: `http_date_at(value, now)` (no_std Tier 1) and `http_date(value)` under `std`; never a fixed pivot (PN-4) | a fixed pivot at 70 disagrees with RFC 9110 for years 70 to 76 today |
| D-006 | 2026-10-21 | Second `60`: refused in HTTP-date unless `Limits::allow_leap_second`; accepted in RFC 5322 dates and mapped to 59 with a flag (PN-5) | RFC 5322 allows leap seconds; HTTP-date does not name them |
| D-007 | 2026-10-21 | Duplicate parameters refused by default; per-field exceptions apply the RFC's rule explicitly (PN-6) | strictness removes the differential (T4) |
| D-008 | 2026-10-21 | `addr-spec` and mailbox parsing live in parse-net; smtp-net keeps policy (SMTPUTF8, IDNA) (PN-7) | two consumers: gate-net login identifiers and smtp-net |
| D-009 | 2026-10-21 | Quoted-printable belongs to encode-lib (PN-8) | it is a transfer-encoding codec |
| D-010 | 2026-10-21 | ISO-8859-1 in RFC 8187: decode only (transcoded to UTF-8); writers always produce UTF-8 (PN-9) | RFC 8187 section 3.2.1: producers must use UTF-8 |
| D-011 | 2026-10-21 | http-net switches to the quote-aware list walker when it adopts parse-net (PN-10) | decided by James (cross-check X-7); no message http-net accepts today changes; recorded in http-net's CHANGELOG as a fix |
| D-012 | 2026-10-21 | Default range budget 16 ranges, at most two overlapping, configurable (PN-11) | enough for every real client [est.]; Apache's 200 is an amplification surface |
| D-013 | 2026-10-21 | MSRV 1.85, edition 2024 | portfolio standard; `core::net` needs 1.77, `core::error::Error` 1.81, `Option::is_none_or` 1.82 |
| D-014 | 2026-10-21 | CI builds `cargo doc` with default and with all features under `-D warnings` | a doc link to a feature-gated item breaks only when the feature is off |
| D-015 | 2026-10-21 | Owned types behind `alloc`, grade P2 (PN-12) | the core never allocates |
| D-016 | 2026-10-21 | `X-Forwarded-For` accepts the de facto shapes in 7.6 and refuses everything else, documented as non-RFC (PN-13) | proxies emit ports and brackets; anything else is a spoofing or garbage signal |
| D-017 | 2026-10-21 | csrf-sec does not depend on parse-net; its adapters (web-net and the service layer) use parse-net and hand csrf-sec facts; revisit at csrf-sec 2.0 (PN-14) | csrf-sec stays protocol-free and is at 1.0 |
| D-018 | 2026-10-21 | form-net refuses `filename*` by default (an opt-in exists there); parse-net decodes it either way (PN-15) | decided by James (cross-check X-5); RFC 7578 section 4.2 forbids senders from using it |
| D-019 | 2026-10-21 | Public repository and crate (PN-16) | generic, nothing proprietary, and every public crate in the stack depends on it |
| D-020 | 2026-10-21 | The RFC 6265 cookie-date algorithm lives in cookie-net (PN-17) | one consumer |
| D-021 | 2026-10-21 | `Content-Security-Policy`, `Strict-Transport-Security`, `Permissions-Policy` grammars later (P3) (PN-18) | one consumer (shield-sec) today |
| D-022 | 2026-10-21 | No async runtime; the REPS "MUST use tokio" clause does not apply (approved portfolio exception) | parse-net does no I/O and runs nothing |
| D-023 | 2026-10-21 | Error types implement `Display` and `core::error::Error` by hand; no `thiserror` (REPS exception) | zero dependencies (D-001) |
| D-024 | 2026-10-21 | The fuzz crate lives in `fuzz/`, is excluded from the package, and keeps its working corpus outside the repository; only hand-made seeds are committed | packages stay small; generated inputs never land in commits |
| D-025 | 2026-10-21 | `-D warnings` is enforced by CI (`RUSTFLAGS`) rather than `#![deny(warnings)]` in the crate root; the crate root denies the specific REPS lints (`missing_docs`, `unused_must_use`, `unused_results`, `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `unreachable`, `dbg_macro`, printing) plus `indexing_slicing` outside tests | a blanket `deny(warnings)` turns every new compiler lint into a build failure for anyone building from source on a newer toolchain; the named lints keep the REPS intent. `indexing_slicing` makes an out-of-bounds panic impossible by construction (NFR-4); overflow is covered by checked arithmetic on every value derived from input, debug-build tests and fuzzing with overflow checks on (`arithmetic_side_effects` was weighed and not adopted: it flags every bounded index increment, and the noise would hide the cases that matter) |
| D-026 | 2026-10-21 | `Civil::weekday` and `date::weekday_from_days` use ISO 8601 numbering (1 = Monday ... 7 = Sunday) | unambiguous and standard; a 0-based numbering invites off-by-one disagreements between consumers |
| D-027 | 2026-10-21 | `ParseError::new(kind, offset)` is public | `sfv::Visitor` implementors and crates wrapping parse-net must be able to build errors; offsets saturate, so no input can make it fail |
| D-028 | 2026-10-21 | No second quoting mode for `multipart/form-data`. form-net reads quoted values with `Quoted::raw()` (backslash literal) and refuses raw bytes containing `\"` (its O-11) | under that rule the RFC 9110 reading and the HTML reading agree on where every accepted value ends, so one parser serves both and no differential is introduced |
| D-029 | 2026-10-21 | `WriteError::InvalidSequence` for structured writers called out of order (`sfv::Writer`, `cache::Writer`) | misuse of a stateful writer is distinct from a forbidden byte or a full sink, and the caller fixes code, not data |
| D-030 | 2026-10-21 | Structured Field Dates are limited to years 1 to 9999, the `HttpDate` range | RFC 9651 section 3.3.7 sets no range beyond the Integer limits; one range in the crate means every Date converts to `HttpDate` without a second error path |
| D-031 | 2026-10-21 | `Host` parsing checks for `@` before anything else, so `a.com:80@b.com` is `InvalidHost` | userinfo is the attack (T15); reporting it as a bad port would hide it |
| D-032 | 2026-10-21 | `mail::unfold` validates first and returns `Result<Unfolded, _>`; the iterator cannot fail | the validate-then-view rule (PLAN 5); the specification's sketch had the iterator stop and report |
| D-033 | 2026-10-21 | `forwarded::client_address_detailed` takes the other header kind's lines and reports `other_present` | the caller already holds both; parse-net reports, never merges (T14) |
| D-034 | 2026-10-21 | API additions at design lock beyond the specification's sketch, each needed by a consumer or by symmetry: `Sink for &mut S`; `SliceSink::is_empty`, `clear`; `Class::contains`, `union`, `is_uri_target`, `is_sf_string_char`; `Word::is_empty`; `Params::raw`; `Limits` setters for every bound in 6.5; `QValue::from_thousandths`; `Outcome::index`; `MalformedPolicy` (renamed from the sketch's `Malformed`, which collided with `ErrorKind::Malformed` in prose); `HttpDate::MIN`, `MAX`, `parse_at_with`; `date::weekday_from_days`; `MailDate::format`, `offset_unknown`, `leap_second`; `RangeHeader::unit`, `is_empty`; `ExtValue::encoded`; `Filename::max_decoded_len`; `cache::request_lines`; `Challenge::scheme_is`, `param`; `HostPort::write_to`, `Host::is_empty`, `host::parse_host`; `pct::encoded_len`, `EncodeSet::empty`; `mail::MimeValue`, `Continuation`, `Domain`, `AddrSpec::is_ascii`, `MimeParams::iter`, `len` | recorded so the design lock lists every name the build will have |
| D-035 | 2026-10-21 | `If-Range` dates are read as IMF-fixdate only | RFC 9110 section 13.1.5 compares the date exactly against `Last-Modified`, which the server itself generated as IMF-fixdate; accepting obsolete forms here only adds a parse path |
| D-036 | 2026-10-21 | RFC 5322 obsolete two-digit years: below 50 are 20xx, 50 and above 19xx; three-digit years add 1900 | RFC 5322 section 4.3 states exactly this rule |
| D-037 | 2026-10-21 | Every parser reports a control byte as `BareCr`, `LineFeed`, `Nul`, or `Control`, wherever it occurs (inside quoted strings and comments too); `InvalidByte` is kept for printable bytes in the wrong place | a caller (and a log) can tell a smuggling attempt from a typo with one rule; inside a quoted string the only bytes that are neither `qdtext` nor a delimiter are controls, so the specific kind loses nothing |
| D-038 | 2026-10-21 | `HttpDate::to_system_time` returns `Option<SystemTime>` | `SystemTime` cannot hold dates before 1601 on Windows; an infallible signature would have to clamp or panic, and either breaks NFR-6 (same result on every platform) |
| D-039 | 2026-10-21 | RFC 850 years: taken in `now`'s century, moved back a century when more than 50 years ahead of `now` (the RFC 9110 rule), and moved forward a century when 50 or more years behind, so the year lies in the hundred years around `now` | RFC 9110 states only the future half; the window reads `01-Jan-00` in 2099 as 2100 (one year ahead) rather than 2000 (99 years back) |
| D-040 | 2026-10-21 | HST-4 extended with the WHATWG "ends in a number" rule: a host whose last label is decimal digits or `0x` and hex digits must be canonical dotted-decimal IPv4, else `InvalidAddress` | browsers resolve `0x7f.1` and `example.123` through their IPv4 parser while RFC 3986 calls them names; refusing them removes the disagreement (T15) |
| D-041 | 2026-10-21 | `#[inline]` on the byte-class predicates, `Class::contains`, `class::all`, `scan::find_byte`, `scan::find_either`, `scan::check_field_value`, `text::is_token`, `text::trim_ows`, `skip_ows`, and the `Sink` impls | they are called per field from http-net and ws-net across the crate boundary, where a non-generic function is not inlined without LTO; NFR-8 measures it in those crates' benchmarks before and after adoption, and any `#[inline]` the measurement does not support is removed |
| D-042 | 2026-10-21 | `NUM-2` (`parse_u32_saturating`), `PCT-4` (`decode_lower_only_into`), and the `First` and `Last` duplicate policies (PRM-4) ship in 0.3, ahead of their planned 0.4 | each was a few lines over code 0.3 already needed; shipping early moves nothing later |
| D-043 | 2026-10-21 | The differential fuzz targets (`diff_http_date` against `httpdate`, `diff_media_type` against `mime`) live in the fuzz crate with the oracles as its own dependencies, and every known disagreement class is listed in `tests/differential/verdicts.md` and skipped by the target with its verdict id | the oracles never enter parse-net's dependency tree; a new class stops the run until it has a written verdict (the 0.3 defence idea, PLAN 15) |
| D-044 | 2026-10-21 | `host::parse_uri_host_port` added beside `parse_host_port`: the same grammar with no OWS stripped, for request targets and URL authorities | found by http-net's `httparse` differential test during the 0.3 migration trial: validating a target with the field-value parser (which strips SP and HTAB, as every field parser does) accepted `CONNECT  example.com:443`. Field parsers keep stripping, because engines hand over trimmed values and callers who do not get the same answer; non-field contexts get a function that strips nothing |
| D-045 | 2026-10-21 | The list walker makes one pass with one table lookup per ordinary byte (an internal class bit, `LIST_PLAIN`: field text that is not `,` `"` `(` `)`), and records whether the value had no quoted string or comment so the element iterator can split on commas alone | the first version validated with three scans (field value, then a quote search, then the walk) and took 81 ns for three short browser lists against 21 ns for http-net's unvalidated split; one pass took it to about 50 ns, and `list::for_each` (validate and visit together) to about 30 ns. An eight-bytes-per-step skip was measured and dropped: on short values it was slower |
| D-046 | 2026-10-21 | The consumer gate (NFR-8) is measured as instructions per iteration with callgrind (valgrind 3.22 in WSL Ubuntu, release profile) over the bodies of the consumers' criterion benchmarks; criterion wall-clock numbers are recorded beside them | identical criterion runs on the development machines varied by up to 15%, three times the 5% margin; instruction counts are exact and repeatable. Results at 0.3: http-net `request_head` +3.9%, `response_write` +0.4%, `response_parse` +0.1%; ws-net `handshake/from_head` -23.3% (`docs/MIGRATION.md`) |
| D-047 | 2026-10-21 | `forwarded::Node` carries `Option<NodePort>` (`Number(u16)` or `Obfuscated(&[u8])`) for every node kind, replacing the design-lock sketch's `Option<u16>` on addresses and `unknown` and `Option<&[u8]>` on obfuscated nodes | RFC 7239 section 6 writes `node = nodename [ ":" node-port ]` and `node-port = port / obfport` for every `nodename`, so `"192.0.2.1:_p"` and `"_hidden:8080"` are valid and the sketch could not hold them |
| D-048 | 2026-10-21 | `AuthPayload::Params` holds `auth::AuthParams` (comma-separated, names matched case-insensitively, `BWS` around `=`), not `param::Params`; its `Debug` prints names only | `auth-param` lists are comma-separated with `BWS` (RFC 9110 section 11.2), a different grammar from `;` parameters (section 5.6.6), so the `param` walker cannot view them; parameter values (`Digest` responses, `nonce`) are secrets as much as a token68 |
| D-049 | 2026-10-21 | `parse_challenges` (ATH-5), `write_challenge_token68` (ATH-7), and `Filename::has_bidi_control` (DSP-7) ship in 0.4, ahead of their planned 0.5 | each sat beside 0.4 code that needed the same machinery (the credential parser, `write_challenge`, the file-name decoder); shipping early moves nothing later |
| D-050 | 2026-10-21 | The httpwg structured-field-tests parsing suite is vendored in `tests/sfv` at a pinned commit with its BSD-3-Clause license, read by `tests/sfv_conformance.rs` through `serde_json` (a dev-dependency), and excluded from the published crate | the 0.4 exit needs the suite in full on every platform without network access; the license allows redistribution with the notice; `cargo tree -e normal` stays empty |
| D-051 | 2026-10-21 | Of the suite's 8 `can_fail` cases parse-net refuses 4: partial and extra base64 padding, and the two Dates outside years 1 to 9999 | padding that does not complete the last quantum is not missing padding (which RFC 9651 section 4.2.7 asks parsers to accept) but a malformed one; the Date range is D-030. The suite permits either outcome |
| D-052 | 2026-10-21 | `WriteError::DuplicateName` added; `media::write` and `auth::write_challenge` refuse a parameter name given twice (ASCII case-insensitive) | found by the `www_authenticate` fuzz target's writer-parser closure check (the 0.4 defence idea, PLAN 15): both writers accepted a repeated name that every parser of the field refuses (RFC 9110 section 5.6.6 with threat T4, and section 11.2 with T21). `WriteError` is `#[non_exhaustive]`, so the variant is additive |
| D-053 | 2026-10-21 | D-006's reason is corrected; the behaviour stays: HTTP-date second `60` is refused unless `Limits::allow_leap_second` (then read as 59) | D-006 said HTTP-date does not name leap seconds, but RFC 9110 section 5.6.7's grammar comment reads `00:00:00 - 23:59:60 (leap second)`. The strict default is the specification's (LIM-3): HTTP senders write `Date` from a Unix clock, which has no 60th second, so a `:60` is far more likely a fuzzing or differential probe than a real timestamp. `docs/GRAMMAR.md` states the deviation |
| D-054 | 2026-10-21 | Every tc2231 case has a verdict (`tests/differential/tc2231.md`): 66 agree, 21 in five deviation classes (empty parameters accepted per RFC 9110 section 5.6.6; whitespace around `=` refused per the same section; RFC 2231 continuations not joined in HTTP; no charset guessed for a plain `filename`; an invalid `filename*` refuses the field) | the 0.4 exit requires a recorded verdict per case; each class follows an RFC sentence or the validate-then-view rule, and none leaves the caller unable to reach the browser behaviour |
| D-055 | 2026-10-21 | `sfv` API additions beyond the design lock: the iterator types `ParamIter`, `InnerIter`, `ListIter`, `DictIter`; `Item::new`; `is_empty` on every view; `DictionaryLines::get`; `Hash` on every view and `PartialEq`/`Eq` on `List` and `Dictionary` | the lock named the iterators' item types but not the types; `Item::new` is how a caller fills the slots of `index_into` (`SfParams` has no public constructor); the rest is symmetry with the other modules' views |
| D-056 | 2026-10-21 | The `diff_sfv` fuzz target compares parse-net with the `sfv` crate (0.16) as an Item, a List, and a Dictionary: both accept or both refuse, except refusals parse-net makes by recorded choice (`OutOfRange`, `InvalidBase64`, `TooLong`, `TooManyMembers`); where both accept, member counts and keys agree | the 0.3 differential defence idea extended to Structured Fields; each skipped class has a verdict in `tests/differential/verdicts.md` |
