# parse-net - API Reference

> Reference for every public item in `parse-net`, with signatures, behaviour, the errors each item can return, and examples.
> **Status: design lock (`0.2.0`).** This document is the contract for `0.3.0` to `1.0.0`. Each item carries the version that ships it; items marked with a later version than the current release are specified here and not yet in the crate. Names and signatures do not change after `0.2.0` without a decision-log entry in [`../dev/PLAN.md`](../dev/PLAN.md).

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Table of contents

- [Conventions](#conventions)
  - [Grades, tiers, versions](#grades-tiers-versions)
  - [Inputs](#inputs)
  - [Validate, then view](#validate-then-view)
  - [Feature flags](#feature-flags)
- [Tier 1 at a glance](#tier-1-at-a-glance)
- [Crate root](#crate-root)
  - [`VERSION`](#version)
- [Errors](#errors)
  - [`ParseError`](#parseerror)
  - [`ErrorKind`](#errorkind)
  - [`WriteError`](#writeerror)
- [Limits](#limits)
  - [`Limits`](#limits-1)
  - [`DuplicatePolicy`](#duplicatepolicy)
- [Byte classes: `class`](#byte-classes-class)
- [Scanning: `scan`](#scanning-scan)
- [Numbers: `num`](#numbers-num)
- [Writers: `write`](#writers-write)
  - [`Sink`, `Full`](#sink-full)
  - [`SliceSink`](#slicesink)
  - [`CountSink`](#countsink)
  - [Writer functions](#writer-functions)
- [Lexical forms: `text`](#lexical-forms-text)
  - [Tokens and whitespace](#tokens-and-whitespace)
  - [`Quoted`](#quoted)
  - [`Word`](#word)
  - [`Comment`](#comment)
- [Lists: `list`](#lists-list)
- [Parameters: `param`](#parameters-param)
- [Media types: `media`](#media-types-media)
- [Content negotiation: `negotiate`](#content-negotiation-negotiate)
- [Dates: `date`](#dates-date)
  - [`HttpDate`](#httpdate)
  - [Calendar functions](#calendar-functions)
  - [`MailDate`](#maildate)
- [Entity tags: `etag`](#entity-tags-etag)
- [Ranges: `range`](#ranges-range)
- [RFC 8187 values: `ext_value`](#rfc-8187-values-ext_value)
- [Content-Disposition: `disposition`](#content-disposition-disposition)
- [Cache-Control: `cache`](#cache-control-cache)
- [Link: `link`](#link-link)
- [Forwarded and X-Forwarded-*: `forwarded`](#forwarded-and-x-forwarded--forwarded)
- [Authorization and challenges: `auth`](#authorization-and-challenges-auth)
- [Host: `host`](#host-host)
- [Origin: `origin`](#origin-origin)
- [Percent-encoding: `pct`](#percent-encoding-pct)
- [Structured Field Values: `sfv`](#structured-field-values-sfv)
- [Email lexical layer: `mail`](#email-lexical-layer-mail)
- [Owned forms](#owned-forms)
- [Thread safety and sizes](#thread-safety-and-sizes)
- [Consumer checklists](#consumer-checklists)

---

## Conventions

### Grades, tiers, versions

Every item has an id (`TXT-5`), a **grade**, a **tier**, and the **version** that ships it.

| Grade | Meaning |
|---|---|
| P0 | the crate's job cannot be done without it |
| P1 | what users of the best libraries of this kind expect |
| P2 | strongly wanted by serious users |
| P3 | after 1.0 is acceptable |

| Tier | Meaning |
|---|---|
| 1 | one plain call: a free function or a one-line constructor, no configuration |
| 2 | configuration and richer views for the next 15% of uses |
| 3 | the full allocation-free surface, for other libraries |

### Inputs

"Input" always means one untrusted field value without its name. Engines usually strip leading and trailing OWS before handing a value over; every function also accepts unstripped input and strips SP and HTAB itself (never VT, FF, or any other byte). Inputs are `&[u8]`, because field values may contain `obs-text` (0x80 to 0xFF).

### Validate, then view

Every `parse_*` checks the whole value in one forward pass and returns a small `Copy` view into the caller's bytes. Iterators on a view walk text already proven valid: they yield items, never `Result`s, and cannot fail. A value is accepted or refused as a whole. Decoded forms (unescaped quoted strings, percent-decoded text, encoded words) are written into a buffer the caller provides by the `*_into` functions, which return `BufferTooSmall` without writing anything when the buffer is short.

### Feature flags

| Feature | Default | Adds |
|---|---|---|
| (none) | yes | everything not marked otherwise; `no_std`, no `alloc` |
| `alloc` | no | owned forms (`to_owned`), `Sink for Vec<u8>` |
| `std` | no | `HttpDate` to and from `SystemTime`, `HttpDate::now`, Tier 1 `http_date`; implies `alloc` |
| `encode-lib` | no | base64 decode and encode helpers (needs the first-party `encode-lib` crate; see [D-002](../dev/PLAN.md#16-decision-log)) |

---

## Tier 1 at a glance

The convention in every example is `use parse_net as pn;`.

```rust
use parse_net as pn;

// Media types (0.3)
let mt = pn::parse_media_type(b"text/html; charset=UTF-8")?;
assert!(mt.essence_is("text/html"));
assert!(mt.charset().is_some_and(|c| c.eq_ignore_ascii_case(b"utf-8")));

// Lists (0.3)
let codings: Vec<&[u8]> = pn::list(b"gzip, deflate;q=0.5")?.iter().collect();
assert_eq!(codings, [&b"gzip"[..], b"deflate;q=0.5"]);

// Dates (0.3)
let d = pn::HttpDate::from_unix(784_111_777)?;
assert_eq!(&d.format(), b"Sun, 06 Nov 1994 08:49:37 GMT");
let when = pn::http_date_at(b"Sunday, 06-Nov-94 08:49:37 GMT", 1_792_000_000)?;
assert_eq!(when, d);

// Host (0.3)
let hp = pn::parse_host_port(b"example.com:8443")?;
assert_eq!(hp.port, Some(8443));

// Negotiation (0.4)
let best = pn::best_media(Some(b"text/html;q=0.9, application/json"), &["text/html", "application/json"]);
assert_eq!(best, Some(1));
let lang = pn::best_language(Some(b"fr-CA, en;q=0.5"), &["en", "fr", "de"]);
assert_eq!(lang, Some(1));

// Conditional requests and ranges (0.4)
let current = pn::EntityTag::strong(b"v2")?;
assert!(pn::if_none_match(b"\"v1\", W/\"v2\"", &current)?);   // answer 304
let mut buf = [pn::ByteRange { start: 0, end: 0 }; 4];
assert_eq!(pn::byte_ranges(b"bytes=0-499", 10_000, &mut buf)?, pn::RangeOutcome::Ranges(1));

// Downloads, caching, proxies, auth, Structured Fields (0.4)
let cd = pn::parse_content_disposition(b"attachment; filename=\"a.txt\"")?;
let cc = pn::response_cache_control(b"public, max-age=31536000, immutable")?;
assert_eq!(cc.max_age, Some(31_536_000));
let site = pn::sfv::parse_item(b"same-origin")?;
let token = pn::bearer(b"Bearer mF_9.B5f-4.1JqM")?;
assert_eq!(token, Some(&b"mF_9.B5f-4.1JqM"[..]));
# Ok::<(), Box<dyn std::error::Error>>(())
```

---

## Crate root

### `VERSION`

`ROOT-1` | P0 | Tier 1 | 0.1

```rust
pub const VERSION: &str;
```

The crate version, populated by Cargo at build time (`env!("CARGO_PKG_VERSION")`).

```rust
use parse_net as pn;

assert_eq!(pn::VERSION.split('.').count(), 3);
```

The crate root re-exports the types and Tier 1 functions of every module (`ParseError`, `ErrorKind`, `WriteError`, `Limits`, `DuplicatePolicy`, `Sink`, `SliceSink`, `CountSink`, `Full`, `Quoted`, `Word`, `Comment`, `List`, `Params`, `Param`, `MediaType`, `MediaRange`, `Boundary`, `QValue`, `HttpDate`, `Civil`, `DateFormat`, `MailDate`, `EntityTag`, `Condition`, `ByteRange`, `RangeSpec`, `RangeOutcome`, `ContentRange`, `IfRange`, `ExtValue`, `Charset`, `ContentDisposition`, `DispositionType`, `Filename`, `ResponseDirectives`, `RequestDirectives`, `Directive`, `LinkValue`, `ClientAddress`, `ForwardedSource`, `Trust`, `Credentials`, `AuthPayload`, `Challenge`, `HostPort`, `Host`, `OriginValue`, `Origin`, and every Tier 1 function). Every module is also public for Tier 3 access: `class`, `scan`, `num`, `write`, `text`, `list`, `param`, `media`, `negotiate`, `date`, `etag`, `range`, `ext_value`, `disposition`, `cache`, `link`, `forwarded`, `auth`, `host`, `origin`, `pct`, `sfv`, `mail`.

---

## Errors

### `ParseError`

`ERR-1` | P0 | Tier 1 | 0.3

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ParseError { /* kind: ErrorKind, at: u32 */ }

impl ParseError {
    pub const fn new(kind: ErrorKind, offset: usize) -> ParseError;
    pub const fn kind(&self) -> ErrorKind;
    pub const fn offset(&self) -> usize;
    pub const fn line(&self) -> usize;
}
impl core::fmt::Display for ParseError {}
impl core::error::Error for ParseError {}
```

Why a value was refused, and where. Eight bytes, `Copy`, and it never contains input bytes, so it is safe to log.

- `kind()`: what was refused (see [`ErrorKind`](#errorkind)).
- `offset()`: the byte offset of the first byte that could not be accepted, relative to the start of the value passed in. For combined field lines it is relative to the start of the line named by `line()`. Offsets above 2^24 saturate at 2^24 - 1 when a line index is present, and at `u32::MAX` otherwise.
- `line()`: the zero-based index of the field line that failed when several lines were parsed as one field; `0` otherwise. Line indexes above 255 saturate at 255.
- `new(kind, offset)`: builds an error, for callers that implement [`sfv::Visitor`](#structured-field-values-sfv) or wrap parse-net. Offsets above `u32::MAX` saturate.
- `Display` writes the kind's fixed message and the offset, for example `invalid byte in token at offset 4`. No input byte is ever formatted, in `Display` or `Debug`.

```rust
use parse_net as pn;

let err = pn::parse_media_type(b"text/ html").unwrap_err();
assert_eq!(err.kind(), pn::ErrorKind::InvalidMediaType);
assert_eq!(err.offset(), 5);
assert_eq!(err.to_string(), "invalid media type at offset 5");
assert_eq!(core::mem::size_of::<pn::ParseError>(), 8);
```

### `ErrorKind`

`ERR-2` | P0 | Tier 1 | 0.3

```rust
#[non_exhaustive]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind { /* variants below */ }

impl ErrorKind {
    pub const fn message(self) -> &'static str;
}
```

Every variant names what was refused. Unless the row says otherwise, the caller's response is the same: treat the field as malformed. For a request field that means refusing the request (HTTP 400) or ignoring the field where its RFC allows that; for a field a server produced, it means a bug in the producer.

| Variant | Refused because | Typical producers |
|---|---|---|
| `Empty` | a value or element that must not be empty was empty | `parse_token`, `num`, `media`, `host` port digits |
| `NotToken` | bytes that must form a token do not | parameters, auth schemes, directive names |
| `InvalidByte` | a byte not allowed at this position | every parser |
| `BareCr` | a CR byte (a request-smuggling vector); refuse the whole message, do not just drop the field | `scan::check_field_value`, every parser |
| `LineFeed` | an LF byte inside a value | as `BareCr` |
| `Nul` | a NUL byte | as `BareCr` |
| `Control` | another control byte (0x01 to 0x1F except HTAB, or DEL) | as `BareCr` |
| `UnterminatedQuote` | a quoted string with no closing `"` (also: a quoted string that would have to continue on the next field line) | `text`, `list`, `param` |
| `InvalidQuotedPair` | the byte after `\` is not `HTAB / SP / VCHAR / obs-text` | `text` |
| `UnbalancedComment` | a `(` without its `)`, or a `)` without its `(` | `text::parse_comment`, `list` |
| `CommentTooDeep` | comment nesting beyond `Limits::max_comment_depth` | `text::parse_comment`, `list` |
| `TooManyMembers` | more list members, parameters, dictionary members, or encoded words than the limit allows | `list`, `param`, `sfv`, `mail` |
| `TooManyEmptyElements` | more empty list elements (`a, , , b`) than `Limits::max_empty_elements` | `list` |
| `TrailingSeparator` | a separator with nothing after it where the grammar forbids that (`a, b,` in a Structured Field list) | `sfv` |
| `ExpectedSeparator` | two members without the separator between them | `sfv`, `forwarded`, `auth` |
| `TrailingData` | bytes after a complete value | every single-value parser |
| `DuplicateParameter` | a parameter name repeated under `DuplicatePolicy::Refuse`, or wherever the RFC forbids repetition | `param`, `disposition`, `auth`, `forwarded` |
| `MissingValue` | `name` without `=value` where a value is required | `param`, `forwarded` |
| `InvalidNumber` | digits expected; a sign, space, or other byte found | `num`, `range`, `cache`, `sfv` |
| `NumberOverflow` | a number larger than its type or the RFC allows | `num`, `range`, `sfv` |
| `OutOfRange` | a value outside its valid range (a year outside 1 to 9999, a Structured Field integer outside plus or minus 999,999,999,999,999) | `date`, `sfv` |
| `InvalidDate` | a date that does not exist (`31 Apr`, `29 Feb 2023`, hour 24) or does not match any accepted format | `date` |
| `WeekdayMismatch` | the weekday does not agree with the date | `date` |
| `InvalidMediaType` | a media type that does not match `type "/" subtype *( OWS ";" OWS parameter )` | `media` |
| `Wildcard` | `*` as a type or subtype where a concrete media type is required (`Content-Type`) | `media::parse` |
| `InvalidBoundary` | a `boundary` parameter that breaks RFC 2046 section 5.1.1 | `MediaType::boundary` |
| `InvalidQValue` | a `q` value outside the RFC 9110 section 12.4.2 grammar | `negotiate` |
| `InvalidEntityTag` | an entity tag outside `[ "W/" ] DQUOTE *etagc DQUOTE` | `etag` |
| `InvalidRange` | a range set or `Content-Range` that is malformed or inconsistent | `range` |
| `InvalidCharset` | a malformed charset name in an extended value or encoded word | `ext_value`, `mail` |
| `UnsupportedCharset` | a well-formed charset parse-net does not decode (only UTF-8, US-ASCII, ISO-8859-1 are decoded) | `ext_value`, `mail` |
| `InvalidPercentEncoding` | a `%` not followed by two hex digits (or uppercase hex where only lowercase is allowed) | `pct`, `ext_value`, `sfv` |
| `InvalidUtf8` | bytes that must be UTF-8 are not (overlong forms and surrogates included) | `pct`, `ext_value`, `sfv`, `mail` |
| `ControlInDecoded` | a decoded value contains a control byte (`%0D%0A`, `%00`); never copy such a value into another header or a log | `ext_value`, `disposition`, `mail`, `auth` |
| `InvalidHost` | a host that is not a reg-name, IPv4, or IP literal; or userinfo (`@`) present | `host`, `origin`, `forwarded` |
| `InvalidPort` | a port that is not digits or is above 65535 | `host`, `origin` |
| `InvalidAddress` | an IP literal that is not a valid address, or an all-digits-and-dots name that is not a valid IPv4 address (`1.2.3`, `256.0.0.1`, `01.2.3.4`) | `host`, `forwarded` |
| `InvalidOrigin` | an `Origin` that is not `null` or `scheme "://" host [ ":" port ]` | `origin` |
| `InvalidKey` | a Structured Field key that does not match `( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" )` | `sfv` |
| `TooLong` | a string, token, key, byte sequence, address, or local part longer than its limit | `sfv`, `mail` |
| `InvalidBase64` | bytes outside the base64 alphabet or misplaced `=` | `sfv`, `auth`, `mail` |
| `InvalidEncodedWord` | an RFC 2047 encoded word that is malformed | `mail` |
| `SectionGap` | RFC 2231 sections that are missing, repeated, or out of order, or a charset on a section other than 0 | `mail` |
| `TooManySections` | more RFC 2231 sections than `Limits::max_rfc2231_sections` | `mail` |
| `InvalidAddrSpec` | an address outside RFC 5322 `addr-spec` (strict, no obsolete forms) | `mail` |
| `LineTooLong` | an email header line over 998 bytes | `mail` |
| `Malformed` | a structure that is wrong as a whole (`*` mixed with entity tags; a broken `X-Forwarded-For` chain); for a forwarded chain, use the peer address | `etag`, `forwarded` |
| `TooManyHops` | a forwarded chain longer than the hop limit; use the peer address | `forwarded` |
| `BufferTooSmall` | the caller's output buffer is shorter than the decoded value; nothing was written; retry with a buffer of the size the matching `*_len` function reports | every `*_into` |

`message()` returns the fixed text `Display` uses (`"invalid byte"`, `"bare CR"`, ...). Every variant has at least one test that produces it.

```rust
use parse_net as pn;

let err = pn::scan::check_field_value(b"a\rb").unwrap_err();
assert_eq!(err.kind(), pn::ErrorKind::BareCr);
assert_eq!(err.offset(), 1);
assert_eq!(pn::ErrorKind::BareCr.message(), "bare CR");
```

### `WriteError`

`ERR-3` | P0 | Tier 2 | 0.3

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WriteError {
    Full,
    Forbidden { at: u32 },
    OutOfRange,
    NotToken,
    InvalidSequence,
}
impl From<Full> for WriteError {}
impl core::fmt::Display for WriteError {}
impl core::error::Error for WriteError {}
```

Why a writer refused.

| Variant | Meaning | What to do |
|---|---|---|
| `Full` | the sink has no room. When the sink reports its room (`SliceSink`), nothing was written | retry with a larger buffer; `CountSink` gives the exact length |
| `Forbidden { at }` | the input byte at offset `at` is not allowed in the output grammar (CR, LF, NUL, another control, or a byte the format forbids) | refuse the input; never strip and retry silently |
| `OutOfRange` | a number outside the format's range (a `Content-Range` end below its start, a Structured Field integer above 15 digits) | fix the value |
| `NotToken` | a position that requires a token got something else (a parameter name, a media type) | fix the name |
| `InvalidSequence` | a structured writer (`sfv::Writer`, `cache::Writer`) was called out of order: a parameter before any item, `finish` with an inner list still open | a bug in the calling code |

`ERR-4` (P0, Tier 1, 0.3): `Display` and `core::error::Error` for both error types, implemented without `std` (stable since Rust 1.81). The text is fixed plus the offset; no input bytes.

```rust
use parse_net as pn;

let mut buf = [0u8; 64];
let mut out = pn::SliceSink::new(&mut buf);
let err = pn::write::write_field_value(b"evil\r\nSet-Cookie: x=1", &mut out).unwrap_err();
assert_eq!(err, pn::WriteError::Forbidden { at: 4 });
assert!(out.written().is_empty());
```

---

## Limits

### `Limits`

`LIM-1`, `LIM-2` | P0 | Tier 2 | 0.3; `LIM-3` (the policy switches) | P2 | Tier 2 | 0.4

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits { /* private */ }

impl Limits {
    pub const DEFAULT: Limits;
    pub const fn new() -> Limits;                                   // == DEFAULT
    pub const fn max_list_members(self, n: u16) -> Limits;          // 1024
    pub const fn max_inner_list_members(self, n: u16) -> Limits;    // 256
    pub const fn max_params(self, n: u16) -> Limits;                // 256
    pub const fn max_dictionary_members(self, n: u16) -> Limits;    // 1024
    pub const fn max_key_len(self, n: u16) -> Limits;               // 256
    pub const fn max_string_len(self, n: u16) -> Limits;            // 1024
    pub const fn max_token_len(self, n: u16) -> Limits;             // 512
    pub const fn max_byte_seq_len(self, n: u32) -> Limits;          // 16384
    pub const fn max_empty_elements(self, n: u16) -> Limits;        // 16
    pub const fn max_comment_depth(self, n: u8) -> Limits;          // 8
    pub const fn max_ranges(self, n: u16) -> Limits;                // 16
    pub const fn max_rfc2231_sections(self, n: u8) -> Limits;       // 32, capped at 32
    pub const fn max_encoded_words(self, n: u16) -> Limits;         // 64
    pub const fn max_hops(self, n: u8) -> Limits;                   // 16
    pub const fn allow_leap_second(self, yes: bool) -> Limits;      // false (0.4)
    pub const fn duplicate_params(self, p: DuplicatePolicy) -> Limits; // Refuse (0.4)
}
impl Default for Limits {}
```

The work and size bounds every parser enforces. Every bound is checked before the work it governs, and none allocates: they bound loops. The defaults meet every minimum RFC 9651 section 3 sets for parsers, so a conforming sender is never refused by default.

| Bound | Default | Source |
|---|---|---|
| list members | 1024 | RFC 9651 section 3.1 minimum |
| inner list members | 256 | RFC 9651 section 3.1.1 minimum |
| parameters per item or field | 256 | RFC 9651 section 3.1.2 minimum |
| dictionary members | 1024 | RFC 9651 section 3.2 minimum |
| key length | 256 | RFC 9651 minimum is 64; a longer key from a conforming sender is not refused |
| string length (decoded) | 1024 | RFC 9651 section 3.3.3 minimum |
| token length | 512 | RFC 9651 section 3.3.4 minimum |
| byte sequence length (decoded) | 16384 | RFC 9651 section 3.3.5 minimum |
| empty list elements | 16 | RFC 9110 section 5.6.1.2: "a reasonable number" |
| comment depth | 8 | none in the RFC |
| ranges | 16 | RFC 9110 section 14.2 permits refusal ([D-012](../dev/PLAN.md#16-decision-log)) |
| RFC 2231 sections | 32 | none in the RFC; the reassembly array holds 32 |
| encoded words per field | 64 | none in the RFC |
| forwarded hops | 16 | none in the RFC |

A setter may set a bound below the RFC minimum: that is the caller tightening deliberately, and it makes the parser non-conforming for that field. `max_rfc2231_sections` above 32 is stored as 32 (the size of the stack array that reassembles sections). `allow_leap_second(true)` lets HTTP-date accept second `60` ([D-006](../dev/PLAN.md#16-decision-log)).

```rust
use parse_net as pn;

const STRICT: pn::Limits = pn::Limits::DEFAULT.max_list_members(64).max_params(16);
let err = pn::list::parse(b"a, b, c", &pn::Limits::DEFAULT.max_list_members(2)).unwrap_err();
assert_eq!(err.kind(), pn::ErrorKind::TooManyMembers);
assert_eq!(err.offset(), 6);
# let _ = STRICT;
```

### `DuplicatePolicy`

`PRM-4` | P1 | Tier 2 | 0.4 (the type exists from 0.3 with `Refuse` as the only behaviour exercised by default)

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum DuplicatePolicy { #[default] Refuse, First, Last }
```

What a parameter parser does when a name repeats (names compare ASCII case-insensitively). `Refuse` (the default) fails with `DuplicateParameter` at the repeated name: a field one component reads first-wins and another last-wins is a known attack ([T4](../dev/PLAN.md#9-threats), [D-007](../dev/PLAN.md#16-decision-log)). `First` and `Last` exist for fields whose RFC states the rule; `Params::get` then returns the first or the last occurrence. Structured Fields always use last-wins, as RFC 9651 requires, whatever this setting says.

---

## Byte classes: `class`

`CLS-1` to `CLS-22` | P0 (CLS-22 P1) | Tier 3 | 0.3

```rust
pub mod class {
    pub const fn is_tchar(b: u8) -> bool;           pub const fn is_vchar(b: u8) -> bool;
    pub const fn is_obs_text(b: u8) -> bool;        pub const fn is_field_text(b: u8) -> bool;
    pub const fn is_qdtext(b: u8) -> bool;          pub const fn is_ctext(b: u8) -> bool;
    pub const fn is_quoted_pair_char(b: u8) -> bool;
    pub const fn is_etagc(b: u8) -> bool;           pub const fn is_attr_char(b: u8) -> bool;
    pub const fn is_mime_token_char(b: u8) -> bool;
    pub const fn is_unreserved(b: u8) -> bool;      pub const fn is_sub_delim(b: u8) -> bool;
    pub const fn is_pchar_no_pct(b: u8) -> bool;    pub const fn is_uri_target(b: u8) -> bool;
    pub const fn is_hexdig(b: u8) -> bool;          pub const fn hex_value(b: u8) -> Option<u8>;
    pub const fn is_sf_key_start(b: u8) -> bool;    pub const fn is_sf_key_char(b: u8) -> bool;
    pub const fn is_sf_token_char(b: u8) -> bool;   pub const fn is_sf_string_char(b: u8) -> bool;
    pub const fn is_token68_char(b: u8) -> bool;    pub const fn is_base64_char(b: u8) -> bool;
    pub const fn is_atext(b: u8) -> bool;           pub const fn is_bchar_nospace(b: u8) -> bool;
    pub const fn is_cookie_octet(b: u8) -> bool;    pub const fn is_av_octet(b: u8) -> bool;
    pub const fn all(s: &[u8], class: Class) -> bool;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct Class(/* u32 bit set */);
    impl Class {
        pub const TCHAR: Class;  pub const VCHAR: Class;  pub const OBS_TEXT: Class;
        pub const FIELD_TEXT: Class;  pub const QDTEXT: Class;  pub const CTEXT: Class;
        pub const QUOTED_PAIR: Class;  pub const ETAGC: Class;  pub const ATTR_CHAR: Class;
        pub const MIME_TOKEN: Class;  pub const UNRESERVED: Class;  pub const SUB_DELIM: Class;
        pub const PCHAR_NO_PCT: Class;  pub const URI_TARGET: Class;  pub const HEXDIG: Class;
        pub const SF_KEY_START: Class;  pub const SF_KEY: Class;  pub const SF_TOKEN: Class;
        pub const SF_STRING: Class;  pub const TOKEN68: Class;  pub const BASE64: Class;
        pub const ATEXT: Class;  pub const BCHAR_NOSPACE: Class;
        pub const COOKIE_OCTET: Class;  pub const AV_OCTET: Class;
        pub const fn contains(self, b: u8) -> bool;
        pub const fn union(self, other: Class) -> Class;
    }
}
```

One `static` table of 256 `u32` entries (1 KiB), built at compile time from the ABNF, one bit per class; every predicate is one load and one mask. The classes and their ABNF are listed in [`../dev/PLAN.md`](../dev/PLAN.md#71-the-byte-class-table) section 7.1. Every class is tested for all 256 bytes against a slow reference written straight from the ABNF. Every class is ASCII-only except `OBS_TEXT`, `FIELD_TEXT`, `QDTEXT`, `CTEXT`, `QUOTED_PAIR`, and `ETAGC`, which include 0x80 to 0xFF as `obs-text`. DEL (0x7F) is in no class.

- `hex_value(b)`: the value of one hex digit (either case), `None` otherwise.
- `all(s, class)`: whether every byte of `s` is in `class` (true for an empty `s`); stops at the first byte outside.
- `Class::union`: a class holding both; used by url-lib to build component classes.
- `is_uri_target` is `pchar / "/" / "?"` plus `%` (the `%XX` digits are checked by [`pct::validate_with`](#percent-encoding-pct)).

```rust
use parse_net::class::{self, Class};

assert!(class::is_tchar(b'!') && !class::is_tchar(b'('));
assert!(class::is_mime_token_char(b'{') && !class::is_tchar(b'{'));   // RFC 2045 vs RFC 9110
assert_eq!(class::hex_value(b'f'), Some(15));
assert!(class::all(b"no-cache", Class::TCHAR));
assert!(Class::UNRESERVED.union(Class::SUB_DELIM).contains(b'~'));
```

---

## Scanning: `scan`

```rust
pub mod scan {
    pub fn find_byte(needle: u8, hay: &[u8]) -> Option<usize>;
    pub fn find_either(a: u8, b: u8, hay: &[u8]) -> Option<usize>;
    pub fn check_field_value(value: &[u8]) -> Result<(), ParseError>;
    pub fn first_not_in(s: &[u8], class: Class) -> Option<usize>;
}
```

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| SCN-1 | `find_byte` | P0, 3, 0.3 | the index of the first `needle`; eight bytes per step (SWAR, no `unsafe`); identical to `hay.iter().position(..)` (property test) | none |
| SCN-2 | `find_either` | P1, 3, 0.3 | the index of the first byte equal to `a` or `b` | none |
| SCN-3 | `check_field_value` | P0, 3, 0.3 | RFC 9110 section 5.5: every byte is field-vchar, SP, HTAB, or obs-text; SWAR fast path over printable ASCII that agrees with the bytewise path for every byte at every position. Does not strip OWS; an empty value is valid | `BareCr`, `LineFeed`, `Nul`, `Control`, each at the offending offset |
| SCN-4 | `first_not_in` | P1, 3, 0.3 | the index of the first byte outside `class` | none |

`check_field_value` is the guard every engine runs on every field value; http-net maps `BareCr` to its smuggling error and the other three to its invalid-value error.

```rust
use parse_net::{scan, class::Class, ErrorKind};

assert_eq!(scan::find_byte(b';', b"text/html; charset=utf-8"), Some(9));
assert_eq!(scan::find_either(b',', b'"', b"a=\"x,y\", b"), Some(2));
assert!(scan::check_field_value(b"caf\xc3\xa9 \tok").is_ok());
assert_eq!(scan::check_field_value(b"abcdefgh\x00").unwrap_err().kind(), ErrorKind::Nul);
assert_eq!(scan::check_field_value(b"a\nb").unwrap_err().kind(), ErrorKind::LineFeed);
assert_eq!(scan::first_not_in(b"gzip, br", Class::TCHAR), Some(4));
```

Edge cases tested: empty value; one byte; all 256 bytes at positions 0, 1, 7, 8, 9, 15, 16, and n-1; CR alone, LF alone, CRLF; NUL; HTAB inside; VT and FF (refused as `Control`); a 1 MiB value.

---

## Numbers: `num`

```rust
pub mod num {
    pub fn parse_u64(digits: &[u8]) -> Result<u64, ParseError>;
    pub fn parse_u32_saturating(digits: &[u8]) -> Result<u32, ParseError>;
}
```

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| NUM-1 | `parse_u64` | P0, 3, 0.3 | `1*DIGIT` into `u64`; no sign, no space, no trimming; leading zeros allowed | `Empty`; `InvalidNumber` at the first non-digit; `NumberOverflow` at the digit that overflows |
| NUM-2 | `parse_u32_saturating` | P1, 3, 0.4 | the delta-seconds rule (RFC 9111 section 1.2.2): any number of digits; values above 2147483648 give 2147483648 | `Empty`, `InvalidNumber` |

```rust
use parse_net::{num, ErrorKind};

assert_eq!(num::parse_u64(b"18446744073709551615")?, u64::MAX);
assert_eq!(num::parse_u64(b"18446744073709551616").unwrap_err().kind(), ErrorKind::NumberOverflow);
assert_eq!(num::parse_u64(b"+1").unwrap_err().kind(), ErrorKind::InvalidNumber);
assert_eq!(num::parse_u32_saturating(b"99999999999999999999")?, 2_147_483_648);
# Ok::<(), parse_net::ParseError>(())
```

---

## Writers: `write`

### `Sink`, `Full`

`WRT-1` | P0 | Tier 2 | 0.3

```rust
pub trait Sink {
    fn put(&mut self, bytes: &[u8]) -> Result<(), Full>;
    fn remaining(&self) -> Option<usize> { None }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Full;

#[cfg(feature = "alloc")]
impl Sink for alloc::vec::Vec<u8> {}            // WRT-11, P1, Tier 2, 0.3
impl<S: Sink + ?Sized> Sink for &mut S {}
```

The one output abstraction every writer in parse-net (and in cookie-net, form-net, smtp-net) takes. `put` appends all of `bytes` or fails with `Full`. `remaining` reports how many more bytes fit, when the sink knows; writers that produce a value in several `put` calls check it first, so a sink that knows its room never holds half a value after an error. `Vec<u8>` cannot run out and reports `None`.

### `SliceSink`

`WRT-2` | P0 | Tier 3 | 0.3

```rust
pub struct SliceSink<'a> { /* buf: &'a mut [u8], len: usize */ }
impl<'a> SliceSink<'a> {
    pub fn new(buf: &'a mut [u8]) -> SliceSink<'a>;
    pub fn written(&self) -> &[u8];
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn clear(&mut self);
}
impl Sink for SliceSink<'_> {}
```

A cursor over a caller buffer. No allocation; reports `remaining`; a `put` that does not fit writes nothing.

### `CountSink`

`WRT-3` | P1 | Tier 3 | 0.3

```rust
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CountSink { /* n: usize */ }
impl CountSink {
    pub const fn new() -> CountSink;
    pub const fn count(&self) -> usize;
}
impl Sink for CountSink {}
```

Counts bytes and writes nothing: run a writer into it to learn the exact output length, then size a buffer once. Saturates at `usize::MAX`.

```rust
use parse_net::{self as pn, Sink};

let mut count = pn::CountSink::new();
pn::write::write_param(b"filename", b"my report.pdf", &mut count)?;
let mut buf = [0u8; 64];
let mut out = pn::SliceSink::new(&mut buf[..count.count()]);
pn::write::write_param(b"filename", b"my report.pdf", &mut out)?;
assert_eq!(out.written(), b"; filename=\"my report.pdf\"");
# Ok::<(), pn::WriteError>(())
```

### Writer functions

```rust
pub mod write {
    pub fn write_token(s: &[u8], out: &mut impl Sink) -> Result<(), WriteError>;
    pub fn write_quoted(s: &[u8], out: &mut impl Sink) -> Result<(), WriteError>;
    pub fn write_word(s: &[u8], out: &mut impl Sink) -> Result<(), WriteError>;
    pub fn write_decimal_u64(n: u64, out: &mut impl Sink) -> Result<(), WriteError>;
    pub fn write_hex_u64(n: u64, out: &mut impl Sink) -> Result<(), WriteError>;
    pub fn write_field_value(s: &[u8], out: &mut impl Sink) -> Result<(), WriteError>;
    pub fn write_param(name: &[u8], value: &[u8], out: &mut impl Sink) -> Result<(), WriteError>;
}
```

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| WRT-4 | `write_decimal_u64` | P0, 3, 0.3 | decimal digits, no sign, no padding (moved from http-net `push_decimal`) | `Full` |
| WRT-5 | `write_hex_u64` | P0, 3, 0.3 | lowercase hex, no prefix, no padding (moved from http-net `push_hex`) | `Full` |
| WRT-6 | `write_token` | P0, 3, 0.3 | the bytes as they are, after checking they form a token | `NotToken` (also for empty input), `Full` |
| WRT-7 | `write_quoted` | P0, 3, 0.3 | `"` + content + `"`, escaping only `"` and `\` (RFC 9110 section 5.6.4: senders SHOULD NOT generate other quoted pairs); HTAB, SP, VCHAR, obs-text written as they are | `Forbidden { at }` for CR, LF, NUL, other CTL, DEL; `Full` |
| WRT-8 | `write_word` | P0, 2, 0.3 | a token when the value is a non-empty token, a quoted string otherwise | as `write_quoted` |
| WRT-9 | `write_field_value` | P0, 3, 0.3 | the bytes as they are, after checking every byte is field-vchar, SP, HTAB, or obs-text: the header-injection guard every crate uses ([T1](../dev/PLAN.md#9-threats)) | `Forbidden { at }`, `Full` |
| WRT-10 | `write_param` | P0, 2, 0.3 | `; name=value`, the value through `write_word` | `NotToken` for the name, then as `write_word` |

Every writer validates all of its input before the first `put`, and checks `remaining` when the output takes several `put` calls, so after any error a `SliceSink` holds exactly what it held before. `parse(write(x)) == x` is a property test for every writer.

```rust
use parse_net::{self as pn, write};

let mut buf = [0u8; 64];
let mut out = pn::SliceSink::new(&mut buf);
write::write_word(b"gzip", &mut out)?;
write::write_param(b"title", b"say \"hi\"", &mut out)?;
assert_eq!(out.written(), b"gzip; title=\"say \\\"hi\\\"\"");
assert_eq!(write::write_quoted(b"a\nb", &mut out), Err(pn::WriteError::Forbidden { at: 1 }));
# Ok::<(), pn::WriteError>(())
```

Edge cases tested: every byte 0x00 to 0x1F and 0x7F at the first, middle, and last position of every writer's input; an empty quoted string (`""`); a buffer one byte short (nothing written); `u64::MAX` in decimal and hex; zero.

---

## Lexical forms: `text`

### Tokens and whitespace

```rust
pub mod text {
    pub fn is_token(s: &[u8]) -> bool;
    pub fn is_ows(b: u8) -> bool;
    pub fn trim_ows(s: &[u8]) -> &[u8];
    pub fn skip_ows(s: &[u8]) -> usize;
    pub fn parse_token(s: &[u8]) -> Result<(&[u8], usize), ParseError>;
    pub fn parse_quoted(s: &[u8]) -> Result<(Quoted<'_>, usize), ParseError>;
    pub fn parse_word(s: &[u8]) -> Result<(Word<'_>, usize), ParseError>;
    pub fn parse_comment(s: &[u8], limits: &Limits) -> Result<(Comment<'_>, usize), ParseError>;
}
```

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| TXT-1 | `is_token` | P0, 1, 0.3 | non-empty and every byte `tchar` | none |
| TXT-2 | `is_ows`, `trim_ows`, `skip_ows` | P0, 3, 0.3 | SP and HTAB only. VT, FF, NBSP, and every other byte are never stripped and later fail validation ([T6](../dev/PLAN.md#9-threats)); `<[u8]>::trim_ascii` is deliberately not used. `skip_ows` returns the count of leading SP and HTAB | none |
| TXT-3 | `parse_token` | P0, 3, 0.3 | the longest token prefix of `s` and its length (the rest is the caller's) | `Empty` when `s` does not start with a `tchar` |
| TXT-4 | BWS | P0, 3, 0.3 | "bad whitespace" (OWS a sender must not generate) is accepted where RFC 9110 allows it (`auth-param`, `Link` parameters) and never written | none |
| TXT-5 | `parse_quoted` | P0, 3, 0.3 | `s[0]` must be `"`; scans `qdtext` and `quoted-pair` to the closing `"`; returns the view and the length including both quotes | `InvalidByte` (offset 0) when `s` does not start with `"`; `InvalidByte` for a byte that is not `qdtext`; `InvalidQuotedPair` when the byte after `\` is not `HTAB / SP / VCHAR / obs-text`; `UnterminatedQuote` at the end of input |
| TXT-11 | `parse_word` | P0, 3, 0.3 | a quoted string when `s` starts with `"`, a token otherwise | as TXT-3 and TXT-5 |
| TXT-13 | `parse_comment` | P1, 3, 0.4 | `s[0]` must be `(`; `ctext`, `quoted-pair`, and nested comments, counted, never recursed; returns the view and the length including the outer parentheses | `InvalidByte`, `InvalidQuotedPair`, `UnbalancedComment` (no closing `)`), `CommentTooDeep` (nesting beyond `max_comment_depth`, at the `(` that exceeded it) |

```rust
use parse_net::text;

assert!(text::is_token(b"no-cache") && !text::is_token(b"no cache") && !text::is_token(b""));
assert_eq!(text::trim_ows(b" \t gzip \t"), b"gzip");
assert_eq!(text::trim_ows(b"\x0bgzip"), b"\x0bgzip");              // VT is not whitespace here
assert_eq!(text::parse_token(b"charset=utf-8")?, (&b"charset"[..], 7));
let (q, used) = text::parse_quoted(b"\"a \\\"b\\\" c\"; x")?;
assert_eq!(used, 12);
assert_eq!(q.raw(), b"a \\\"b\\\" c");
# Ok::<(), parse_net::ParseError>(())
```

### `Quoted`

`TXT-6` to `TXT-9` | P0 (TXT-8 P1) | Tier 3 | 0.3

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Quoted<'a> { /* raw content without the quotes, has_escapes */ }

impl<'a> Quoted<'a> {
    pub const fn raw(&self) -> &'a [u8];
    pub const fn has_escapes(&self) -> bool;
    pub const fn as_plain(&self) -> Option<&'a [u8]>;
    pub fn unescaped_len(&self) -> usize;
    pub fn bytes(&self) -> Unescape<'a>;                       // Iterator<Item = u8>
    pub fn unescape_into<'b>(&self, out: &'b mut [u8]) -> Result<&'b [u8], ParseError>;
    pub fn eq_bytes(&self, other: &[u8]) -> bool;
    pub fn eq_ignore_ascii_case(&self, other: &[u8]) -> bool;
}
```

A validated quoted string. `raw()` is the content between the quotes exactly as sent, quoted pairs included. `as_plain()` returns `raw()` when there is no quoted pair (the common case), so most values are used without a copy. `unescape_into` writes the value with every quoted pair replaced by the byte after the backslash (RFC 9110 section 5.6.4) and returns the written part of `out`; `BufferTooSmall` when `out` is shorter than `unescaped_len()`, with nothing written. `bytes()` iterates the unescaped bytes. `eq_bytes` and `eq_ignore_ascii_case` compare the unescaped value without a buffer.

```rust
use parse_net::text;

let (q, _) = text::parse_quoted(b"\"say \\\"hi\\\"\"")?;
assert!(q.has_escapes() && q.as_plain().is_none());
assert_eq!(q.unescaped_len(), 8);
let mut buf = [0u8; 8];
assert_eq!(q.unescape_into(&mut buf)?, b"say \"hi\"");
assert!(q.eq_bytes(b"say \"hi\""));
let mut short = [0u8; 7];
assert_eq!(q.unescape_into(&mut short).unwrap_err().kind(), parse_net::ErrorKind::BufferTooSmall);
# Ok::<(), parse_net::ParseError>(())
```

### `Word`

`TXT-10`, `TXT-12` | P0 (TXT-12 P1) | Tier 2 | 0.3

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Word<'a> { Token(&'a [u8]), Quoted(Quoted<'a>) }

impl<'a> Word<'a> {
    pub const fn as_plain(&self) -> Option<&'a [u8]>;
    pub fn as_str(&self) -> Option<&'a str>;
    pub fn eq_bytes(&self, other: &[u8]) -> bool;
    pub fn eq_ignore_ascii_case(&self, other: &[u8]) -> bool;
    pub fn unescape_into<'b>(&self, out: &'b mut [u8]) -> Result<&'b [u8], ParseError>;
    pub fn len(&self) -> usize;                 // unescaped length
    pub fn is_empty(&self) -> bool;
}
```

`token / quoted-string`, the value form of parameters and directives. A token and a quoted string with the same content compare equal, as RFC 9110 section 5.6.6 requires: `eq_bytes` and `eq_ignore_ascii_case` compare unescaped content, so `charset=utf-8` and `charset="utf-8"` match the same needle. `as_plain` is the token, or the quoted content when it has no quoted pair. `as_str` is `as_plain` when it is valid UTF-8. The derived `PartialEq` compares the forms structurally (token versus quoted); use `eq_bytes` for RFC equality.

```rust
use parse_net::text;

let (a, _) = text::parse_word(b"utf-8")?;
let (b, _) = text::parse_word(b"\"UTF-8\"")?;
assert!(a.eq_ignore_ascii_case(b"UTF-8") && b.eq_ignore_ascii_case(b"utf-8"));
assert_eq!(b.as_str(), Some("UTF-8"));
# Ok::<(), parse_net::ParseError>(())
```

### `Comment`

`TXT-14` | P1 | Tier 3 | 0.4

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Comment<'a> { /* raw text without the outer parentheses, depth reached */ }
impl<'a> Comment<'a> {
    pub const fn raw(&self) -> &'a [u8];
    pub const fn max_depth(&self) -> u8;   // 1 for "(a)", 2 for "(a(b))"
}
```

```rust
use parse_net::{text, Limits};

let (c, used) = text::parse_comment(b"(compatible; (nested)) rest", &Limits::DEFAULT)?;
assert_eq!((c.raw(), c.max_depth(), used), (&b"compatible; (nested)"[..], 2, 22));
# Ok::<(), parse_net::ParseError>(())
```

Edge cases tested: `""` (empty, valid); `"\""`; `"\\"`; `"\` (unterminated after an escape); `"a` (unterminated); `"a<NUL>"` (refused); `"\` followed by DEL (refused); obs-text inside (valid); a quoted HTAB; 64 KiB of `\\` (linear); `unescape_into` with a buffer of `unescaped_len - 1` (nothing written). Comments: `()`, `(a(b)c)`, `(\))`, `((a)`, `(a))`, depth at the limit and the limit plus one, 10,000 levels (refused at the limit, no stack growth).

---

## Lists: `list`

`LST-1` to `LST-4` | P0 (LST-2 P1) | 0.3

```rust
pub fn list(value: &[u8]) -> Result<List<'_>, ParseError>;                  // Tier 1

pub mod list {
    pub fn parse(value: &[u8], limits: &Limits) -> Result<List<'_>, ParseError>;
    pub fn combined<'a, I>(lines: I, limits: &Limits) -> Result<CombinedList<'a, I::IntoIter>, ParseError>
    where I: IntoIterator<Item = &'a [u8]>, I::IntoIter: Clone;
    pub fn contains_token<'a, I>(lines: I, token: &[u8]) -> bool
    where I: IntoIterator<Item = &'a [u8]>;
    pub fn for_each<'a>(value: &'a [u8], limits: &Limits, f: impl FnMut(&'a [u8])) -> Result<usize, ParseError>;

    #[derive(Clone, Copy, Debug)]
    pub struct List<'a> { /* value, count */ }
    impl<'a> List<'a> {
        pub fn iter(&self) -> Elements<'a>;
        pub const fn len(&self) -> usize;
        pub const fn is_empty(&self) -> bool;
    }
    impl<'a> IntoIterator for List<'a> { type Item = &'a [u8]; type IntoIter = Elements<'a>; }

    #[derive(Clone, Debug)]
    pub struct Elements<'a> { /* ... */ }          // Iterator<Item = &'a [u8]>, ExactSizeIterator

    #[derive(Clone, Debug)]
    pub struct CombinedList<'a, I> { /* lines, count */ }
    impl<'a, I: Iterator<Item = &'a [u8]> + Clone> CombinedList<'a, I> {
        pub fn iter(&self) -> CombinedElements<'a, I>;
        pub const fn len(&self) -> usize;
        pub const fn is_empty(&self) -> bool;
    }
}
```

The RFC 9110 section 5.6.1 `#rule`: comma-separated elements. An element is yielded trimmed of OWS, as raw bytes; its own grammar (a token, `token;params`, a media range) is the caller's.

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| LST-1 | `list`, `list::parse`, `List`, `Elements` | P0, 1, 0.3 | validates the whole value: every byte per SCN-3; quoted strings terminated with valid quoted pairs; comments balanced within `max_comment_depth`. A comma ends an element only outside quoted strings and comments ([T3](../dev/PLAN.md#9-threats)). Empty elements (`a, , b`, a leading or trailing comma) are skipped up to `max_empty_elements` (RFC 9110 section 5.6.1.2) | SCN-3 kinds; `UnterminatedQuote`, `InvalidQuotedPair`, `UnbalancedComment`, `CommentTooDeep`; `TooManyEmptyElements` at the comma that exceeded the budget; `TooManyMembers` at the element beyond `max_list_members` |
| LST-2 | `list::for_each` | P1, 3, 0.3 | validates and calls `f` for each element in one pass (no second scan); returns the element count. On error, `f` has seen the elements before the failure | as LST-1 |
| LST-3 | `list::combined`, `CombinedList` | P0, 2, 0.3 | several field lines of one name as one list, as if joined by `", "` (RFC 9110 section 5.3), without joining; an empty line adds nothing; an element never spans two lines, so a quote open at the end of a line is `UnterminatedQuote`. The empty-element and member budgets count across all lines | as LST-1, with `line()` set |
| LST-4 | `list::contains_token` | P0, 1, 0.3 | whether any element of any line equals `token` ASCII case-insensitively (`Connection: keep-alive, Upgrade`); a line that fails to parse counts as not containing it (fail closed) | none |

```rust
use parse_net::{self as pn, Limits};

let l = pn::list(b"a, \"b,c\" , , (d, e) f,")?;
let all: Vec<&[u8]> = l.iter().collect();
assert_eq!(all, [&b"a"[..], b"\"b,c\"", b"(d, e) f"]);
assert_eq!(l.len(), 3);

let lines: [&[u8]; 3] = [b"gzip", b"", b"br, zstd"];
let c = pn::list::combined(lines, &Limits::DEFAULT)?;
assert_eq!(c.iter().collect::<Vec<_>>(), [&b"gzip"[..], b"br", b"zstd"]);

assert!(pn::list::contains_token([&b"keep-alive, Upgrade"[..]], b"upgrade"));
# Ok::<(), pn::ParseError>(())
```

Edge cases tested: empty value (zero elements); `,`; `, ,`; `a,`; `,a`; `a,,b`; 16 and 17 empty elements; 1024 and 1025 elements; `a, "b,c"`; `a, (b,c)`; elements with parameters; OWS before a comma; two lines where the second is empty; a quoted string spanning lines (refused); the combined-lines property (splitting at every comma into 1 to 8 lines gives the same elements).

---

## Parameters: `param`

`PRM-1` to `PRM-6` | 0.3 (PRM-4 0.4)

```rust
pub mod param {
    pub fn parse(s: &[u8], limits: &Limits) -> Result<(Params<'_>, usize), ParseError>;

    #[derive(Clone, Copy)]
    pub struct Params<'a> { /* validated text, count, policy */ }
    impl<'a> Params<'a> {
        pub fn iter(&self) -> ParamIter<'a>;                      // Iterator<Item = Param<'a>>
        pub fn get(&self, name: &str) -> Option<Word<'a>>;
        pub const fn len(&self) -> usize;
        pub const fn is_empty(&self) -> bool;
        pub const fn raw(&self) -> &'a [u8];
    }
    impl core::fmt::Debug for Params<'_> {}                      // names only

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Param<'a> { pub name: &'a [u8], pub value: Word<'a> }
}
```

RFC 9110 section 5.6.6: `parameters = *( OWS ";" OWS [ parameter ] )`, `parameter = parameter-name "=" parameter-value`, `parameter-value = ( token / quoted-string )`.

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| PRM-1 | `param::parse` | P0, 3, 0.3 | `s` starts at the first `;` (or is empty). Parses as long as the grammar continues and returns the view and the bytes used (trailing OWS after the last parameter is not used); the caller decides whether what follows (`,` in a list, end of value) is allowed. Empty parameters (`;;`, a trailing `;`) are allowed, as the grammar says. No whitespace around `=` (BWS is not in this grammar) | `NotToken` for a bad name; `MissingValue` for a name with no `=`; `InvalidByte` for whitespace around `=` or a bad value byte; `UnterminatedQuote`, `InvalidQuotedPair`; `DuplicateParameter` under `Refuse`; `TooManyMembers` beyond `max_params` |
| PRM-2 | `Params::get` | P0, 2, 0.3 | ASCII case-insensitive name lookup; the first match (`Refuse`, `First`) or the last (`Last`) | none |
| PRM-3 | `Params::iter`, `Param` | P0, 2, 0.3 | every parameter in order (with `First` or `Last`, duplicates included) | none |
| PRM-5 | `len`, `is_empty`, `raw` | P1, 2, 0.3 | the parameter count; the validated text | none |
| PRM-6 | `Debug` | P1, 2, 0.3 | prints parameter names only: values can be secrets (`Authorization` parameters) | none |

```rust
use parse_net::{param, Limits};

let (p, used) = param::parse(b"; charset=utf-8;format=\"flowed\" , next", &Limits::DEFAULT)?;
assert_eq!(used, 31);
assert!(p.get("Charset").is_some_and(|v| v.eq_bytes(b"utf-8")));
assert!(p.get("format").is_some_and(|v| v.eq_bytes(b"flowed")));
assert_eq!(format!("{p:?}"), "Params([\"charset\", \"format\"])");

let dup = param::parse(b";a=1;A=2", &Limits::DEFAULT).unwrap_err();
assert_eq!((dup.kind(), dup.offset()), (parse_net::ErrorKind::DuplicateParameter, 5));
# Ok::<(), parse_net::ParseError>(())
```

Edge cases tested: `;`, `;;`, `; a=b`, `;a=`, `;a`, `;a =b`, `;a= b`, `;A=b` against `;a=b` (duplicate), 256 and 257 parameters, `""` as a value, a value with escapes.

---

## Media types: `media`

```rust
pub fn parse_media_type(value: &[u8]) -> Result<MediaType<'_>, ParseError>;   // Tier 1

pub mod media {
    pub fn parse(value: &[u8], limits: &Limits) -> Result<MediaType<'_>, ParseError>;
    pub fn parse_range(value: &[u8], limits: &Limits) -> Result<MediaRange<'_>, ParseError>;  // 0.4
    pub fn write(type_: &str, subtype: &str, params: &[(&str, &str)], out: &mut impl Sink) -> Result<(), WriteError>;

    #[derive(Clone, Copy, Debug)]
    pub struct MediaType<'a> { /* type, subtype, params */ }
    impl<'a> MediaType<'a> {
        pub const fn type_(&self) -> &'a [u8];
        pub const fn subtype(&self) -> &'a [u8];
        pub fn suffix(&self) -> Option<&'a [u8]>;
        pub fn essence_is(&self, essence: &str) -> bool;
        pub fn is(&self, type_: &str, subtype: &str) -> bool;
        pub const fn params(&self) -> Params<'a>;
        pub fn param(&self, name: &str) -> Option<Word<'a>>;
        pub fn charset(&self) -> Option<Word<'a>>;
        pub fn boundary(&self) -> Result<Option<Boundary<'a>>, ParseError>;
        pub fn is_json(&self) -> bool;
        pub fn is_form_urlencoded(&self) -> bool;
        pub fn is_multipart_form_data(&self) -> bool;
        pub fn write_canonical(&self, out: &mut impl Sink) -> Result<(), WriteError>;
        #[cfg(feature = "alloc")] pub fn to_owned(&self) -> OwnedMediaType;   // 0.5
    }

    #[derive(Clone, Copy, Debug)]
    pub struct MediaRange<'a> { /* type or *, subtype or *, params, weight */ }
    impl<'a> MediaRange<'a> {
        pub const fn type_(&self) -> &'a [u8];
        pub const fn subtype(&self) -> &'a [u8];
        pub fn matches(&self, offer: &MediaType<'_>) -> bool;
        pub const fn specificity(&self) -> u8;
        pub const fn weight(&self) -> QValue;
        pub const fn params(&self) -> Params<'a>;
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct Boundary<'a>(/* validated bytes */);
    impl<'a> Boundary<'a> { pub const fn as_bytes(&self) -> &'a [u8]; }
}
```

RFC 9110 section 8.3.1: `media-type = type "/" subtype parameters`; type, subtype, and parameter names are case-insensitive; parameter values are case-sensitive unless the parameter's definition says otherwise (`charset` is case-insensitive, section 8.3.2).

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| MED-1 | `parse_media_type`, `media::parse` | P0, 1, 0.3 | tokens around `/`; OWS allowed only before `;` and around the whole value; parameters per PRM with `DuplicatePolicy::Refuse` ([T4](../dev/PLAN.md#9-threats)) | `InvalidMediaType` (missing `/`, empty or non-token type or subtype, whitespace inside the essence, bytes after the parameters); `Wildcard` for `*` as type or subtype; PRM errors |
| MED-2 | `type_`, `subtype`, `params`, `param` | P0, 1, 0.3 | raw case kept | none |
| MED-3 | `essence_is`, `is` | P0, 1, 0.3 | ASCII case-insensitive comparison of `type/subtype` | none |
| MED-4 | `charset` | P0, 1, 0.3 | the `charset` parameter; compare it case-insensitively | none |
| MED-5 | `boundary` | P0, 1, 0.3 | RFC 2046 section 5.1.1: 1 to 70 `bchars`, last not SP; token or quoted form (a quoted boundary cannot contain escapes: `\` is not a `bchar`); absent gives `Ok(None)` | `InvalidBoundary` |
| MED-6 | `suffix`, `is_json`, `is_form_urlencoded`, `is_multipart_form_data` | P1, 1, 0.3 | `suffix` is the part after the last `+` of the subtype (`json` of `ld+json`); `is_json` is `application/json` or any `+json` suffix | none |
| MED-7 | `media::parse_range`, `MediaRange` | P1, 2, 0.4 | `*/*`, `type/*`, or a media type; the first `q` parameter ends the media-type parameters (`params()`), and it and every parameter after it are `accept-ext`, ignored for matching | `Wildcard` for `*/subtype`; `InvalidQValue`; MED-1 errors |
| MED-8 | `MediaRange::matches`, `specificity` | P1, 2, 0.4 | a range matches an offer when type and subtype match (or are `*`) and every range parameter is present in the offer with an equal value (case-sensitive except `charset`); specificity 4 (with parameters), 3 (exact), 2 (`type/*`), 1 (`*/*`) | none |
| MED-9 | `media::write` | P0, 2, 0.3 | `type/subtype` then `; name=value` for each pair, values through `write_word` | `NotToken`, `Forbidden`, `Full` |
| MED-10 | `write_canonical` | P1, 2, 0.3 | lowercase type, subtype, and parameter names; values as given; `; ` between parameters | `Full` |
| MED-11 | `OwnedMediaType` | P2, 2, 0.5 | `alloc`; see [Owned forms](#owned-forms) | none |
| MED-12 | `Boundary` | P0, 3, 0.3 | validated, unquoted bytes | none |

```rust
use parse_net as pn;

let mt = pn::parse_media_type(b"Multipart/Form-Data; boundary=\"----x y\"")?;
assert!(mt.is_multipart_form_data() && mt.is("multipart", "form-data"));
assert_eq!(mt.boundary()?.map(|b| b.as_bytes()), Some(&b"----x y"[..]));

let ld = pn::parse_media_type(b"application/ld+json")?;
assert_eq!(ld.suffix(), Some(&b"json"[..]));
assert!(ld.is_json());

assert_eq!(pn::parse_media_type(b"text/*").unwrap_err().kind(), pn::ErrorKind::Wildcard);
assert_eq!(pn::parse_media_type(b"text /html").unwrap_err().kind(), pn::ErrorKind::InvalidMediaType);

let mut buf = [0u8; 64];
let mut out = pn::SliceSink::new(&mut buf);
pn::media::write("text", "plain", &[("charset", "utf-8")], &mut out)?;
assert_eq!(out.written(), b"text/plain; charset=utf-8");
# Ok::<(), Box<dyn std::error::Error>>(())
```

Edge cases tested: `text/html`, `TEXT/HTML`, `text/html;`, `text/html ;charset=utf-8`, `text/ html`, `text /html`, `text/`, `/html`, `*/*`, `text/*` (refused here, accepted as ranges), `application/vnd.api+json`, `multipart/form-data; boundary=` (empty), boundaries of 70 and 71 characters, a boundary ending in a space, a quoted boundary with a space inside, a boundary with `\`, two `boundary` parameters (refused).

---

## Content negotiation: `negotiate`

`NEG-1` to `NEG-9` | 0.4

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QValue(/* 0..=1000 thousandths */);
impl QValue {
    pub const ONE: QValue;
    pub const ZERO: QValue;
    pub const fn from_thousandths(t: u16) -> Option<QValue>;
    pub const fn thousandths(self) -> u16;
    pub fn parse(s: &[u8]) -> Result<QValue, ParseError>;
}

pub fn best_media(accept: Option<&[u8]>, offers: &[&str]) -> Option<usize>;            // Tier 1
pub fn best_language(accept_language: Option<&[u8]>, offers: &[&str]) -> Option<usize>;
pub fn best_encoding(accept_encoding: Option<&[u8]>, offers: &[&str]) -> Option<usize>;
pub fn best_charset(accept_charset: Option<&[u8]>, offers: &[&str]) -> Option<usize>;

pub mod negotiate {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Negotiator { /* limits, language matching, malformed policy */ }
    impl Negotiator {
        pub const fn new() -> Negotiator;
        pub const fn limits(self, l: Limits) -> Negotiator;
        pub const fn language_matching(self, m: LanguageMatching) -> Negotiator;
        pub const fn on_malformed(self, p: MalformedPolicy) -> Negotiator;
        pub fn media(&self, accept: Option<&[u8]>, offers: &[&str]) -> Outcome;
        pub fn media_lines<'a, I>(&self, lines: I, offers: &[&str]) -> Outcome
        where I: IntoIterator<Item = &'a [u8]>, I::IntoIter: Clone;
        pub fn language(&self, value: Option<&[u8]>, offers: &[&str]) -> Outcome;
        pub fn encoding(&self, value: Option<&[u8]>, offers: &[&str]) -> Outcome;
        pub fn charset(&self, value: Option<&[u8]>, offers: &[&str]) -> Outcome;
    }
    impl Default for Negotiator {}

    #[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
    pub enum LanguageMatching { #[default] Lookup, BasicFilter }
    #[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
    pub enum MalformedPolicy { #[default] TreatAsAbsent, Refuse }

    #[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Outcome {
        Chosen { index: usize, weight: QValue },
        NoneAcceptable,
        HeaderIgnored { index: usize },
        Refused(ParseError),
    }
    impl Outcome { pub const fn index(&self) -> Option<usize>; }

    pub fn parse_accept(value: &[u8], limits: &Limits) -> Result<AcceptList<'_>, ParseError>;   // iter: MediaRange
    pub fn parse_weighted(value: &[u8], limits: &Limits) -> Result<WeightedList<'_>, ParseError>; // iter: Weighted
    #[derive(Clone, Copy, Debug)]
    pub struct Weighted<'a> { pub value: &'a [u8], pub weight: QValue, pub params: Params<'a> }
}
```

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| NEG-1 | `QValue`, `QValue::parse` | P1, 3, 0.4 | `( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )` (RFC 9110 section 12.4.2), stored as thousandths: no floating point. In a list, the parameter name `q` is case-insensitive | `InvalidQValue` for `1.5`, `0.1234`, `.5`, `-1`, `1.001`, an empty value |
| NEG-2 | `best_media` | P1, 1, 0.4 | the index of the best offer for `Accept` (offers are media types like `"text/html"`). An offer's weight is the q-value of the most specific matching range (specificity per MED-8); `q=0` means not acceptable; the highest weight wins and ties go to the earlier offer (server preference). An absent header gives every offer weight 1, so the first offer wins. A malformed header is treated as absent (RFC 9110 lets a server ignore it). `None`: no offer is acceptable (answer 406 or send a default) | none |
| NEG-3 | `best_language` | P1, 1, 0.4 | RFC 4647 section 3.4 lookup: each range in descending q order is matched against the offers case-insensitively, truncating the range one subtag at a time (`en-US` matches an `en` offer); `*` matches any offer at its weight; `q=0` excludes | none |
| NEG-4 | `best_encoding` | P1, 1, 0.4 | RFC 9110 section 12.5.3: `identity` is acceptable unless `identity;q=0`, or `*;q=0` without an explicit `identity`; an empty field value means only `identity`; `x-gzip` equals `gzip` and `x-compress` equals `compress` (section 8.4.1) | none |
| NEG-5 | `best_charset` | P2, 1, 0.4 | as `best_encoding` without the `identity` rule | none |
| NEG-6 | `Negotiator`, `Outcome` | P1, 2, 0.4 | the configurable form. `HeaderIgnored { index }` reports that the header was malformed and treated as absent; with `MalformedPolicy::Refuse` the outcome is `Refused(error)` instead, so the caller can answer 400 | none (reported in `Outcome`) |
| NEG-7 | `media_lines` | P1, 2, 0.4 | several `Accept` field lines as one list (LST-3) | as NEG-6 |
| NEG-8 | `parse_accept`, `parse_weighted` | P2, 3, 0.4 | raw access for other selection rules: media ranges with weights; `token *( ";" param )` with weights | LST, PRM, MED-7, NEG-1 errors |
| NEG-9 | `LanguageMatching::BasicFilter` | P2, 2, 0.4 | RFC 4647 section 3.3.1: a range matches a tag when it equals the tag or is a prefix followed by `-`; the best-weighted offer wins | none |

Work is bounded: members times offers, with members at most `max_list_members` (the caller controls the offer count).

```rust
use parse_net::{self as pn, negotiate::{Negotiator, MalformedPolicy, Outcome}};

let chrome = b"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
assert_eq!(pn::best_media(Some(chrome), &["application/json", "text/html"]), Some(1));
assert_eq!(pn::best_media(None, &["application/json", "text/html"]), Some(0));
assert_eq!(pn::best_media(Some(b"text/*;q=0.5, text/html;q=0"), &["text/html"]), None);

assert_eq!(pn::best_language(Some(b"en-US, fr;q=0.8"), &["fr", "en"]), Some(1));
assert_eq!(pn::best_encoding(Some(b"gzip;q=1.0, identity; q=0.5, *;q=0"), &["br", "identity"]), Some(1));
assert_eq!(pn::best_encoding(Some(b""), &["gzip", "identity"]), Some(1));

let strict = Negotiator::new().on_malformed(MalformedPolicy::Refuse);
assert!(matches!(strict.media(Some(b"text/html;q=2"), &["text/html"]), Outcome::Refused(_)));
```

Edge cases tested: absent header; empty header (`Accept-Encoding:` means identity only); every offer at `q=0`; ties; `*/*;q=0` with `text/html`; `text/*;q=0.5, text/html;q=0`; parameters on ranges; `Accept-Language: *`; an `en-US` range against an `en` offer; offers in different case; 1024 members against 32 offers (bounded). q-values: `q=0`, `q=0.`, `q=0.000`, `q=1`, `q=1.000`, `q=1.001`, `q=0.0001`, `q=.5`, `Q=0.5`, `q=-1`, `q= 0.5`, a missing value, two `q` parameters.

---

## Dates: `date`

### `HttpDate`

`DAT-1` to `DAT-8`, `DAT-10` | 0.3

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HttpDate { /* seconds since 1970-01-01T00:00:00Z, i64, years 1 to 9999 */ }

impl HttpDate {
    pub const MIN: HttpDate;                                   // 0001-01-01T00:00:00Z
    pub const MAX: HttpDate;                                   // 9999-12-31T23:59:59Z
    pub const fn from_unix(secs: i64) -> Result<HttpDate, ParseError>;
    pub const fn unix(self) -> i64;
    pub fn parse_at(value: &[u8], now: i64) -> Result<HttpDate, ParseError>;
    pub fn parse_at_with(value: &[u8], now: i64, limits: &Limits) -> Result<HttpDate, ParseError>;
    pub fn parse_imf_fixdate(value: &[u8]) -> Result<HttpDate, ParseError>;
    pub fn parse_detailed(value: &[u8], now: i64) -> Result<(HttpDate, DateFormat), ParseError>;
    pub fn format(self) -> [u8; 29];
    pub fn write_to(self, out: &mut impl Sink) -> Result<(), WriteError>;
    pub fn civil(self) -> Civil;
    #[cfg(feature = "std")] pub fn now() -> HttpDate;
    #[cfg(feature = "std")] pub fn from_system_time(t: std::time::SystemTime) -> Result<HttpDate, ParseError>;
    #[cfg(feature = "std")] pub fn to_system_time(self) -> std::time::SystemTime;
}

pub fn http_date_at(value: &[u8], now: i64) -> Result<HttpDate, ParseError>;             // Tier 1, no_std
#[cfg(feature = "std")]
pub fn http_date(value: &[u8]) -> Result<HttpDate, ParseError>;                          // Tier 1, std clock

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DateFormat { ImfFixdate, Rfc850, Asctime }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Civil {
    pub year: u16, pub month: u8, pub day: u8,
    pub hour: u8, pub minute: u8, pub second: u8,
    pub weekday: u8,                                           // ISO 8601: 1 = Monday ... 7 = Sunday
}
```

RFC 9110 section 5.6.7. A point in time with one-second resolution, from year 1 to year 9999 (the RFC 9651 Date range), UTC.

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| DAT-1 | `from_unix`, `unix`, `MIN`, `MAX` | P0, 1, 0.3 | seconds since the Unix epoch, negative for dates before 1970 | `OutOfRange` outside years 1 to 9999 |
| DAT-2 | `http_date_at`, `parse_at`, `parse_at_with` | P0, 1, 0.3 | all three formats: IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`), RFC 850 (`Sunday, 06-Nov-94 08:49:37 GMT`), asctime (`Sun Nov  6 08:49:37 1994`). Names are case-sensitive (HTTP-date is case-sensitive). The weekday must agree with the date. Only `GMT` is accepted as the zone. The RFC 850 two-digit year is resolved against `now` (Unix seconds) by the RFC 9110 rule: a date more than 50 years in the future is taken as the most recent past year with the same last two digits ([D-005](../dev/PLAN.md#16-decision-log)). Second `60` is refused unless `Limits::allow_leap_second` (then read as 59) | `InvalidDate` (no format matches, a day beyond the month, `29 Feb` in a non-leap year, hour 24, minute or second 60); `WeekdayMismatch`; `TrailingData` |
| DAT-3 | `http_date` | P1, 1, 0.3 | `std`: `parse_at` with `now` from `SystemTime::now()` | as DAT-2 |
| DAT-4 | `parse_imf_fixdate` | P0, 3, 0.3 | exactly the 29-byte IMF-fixdate, the only format senders may generate; parsed by position with no searching; needs no clock | as DAT-2 |
| DAT-5 | `parse_detailed` | P2, 3, 0.3 | also reports the format seen (a sender still using RFC 850 is a signal) | as DAT-2 |
| DAT-6 | `format`, `write_to` | P0, 1, 0.3 | IMF-fixdate (moved from http-net `blocking.rs`, now over the full year range) | `write_to`: `Full` |
| DAT-7 | `civil`, `Civil` | P1, 2, 0.3 | broken-down UTC time | none |
| DAT-8 | `now`, `from_system_time`, `to_system_time` | P1, 1, 0.3 | `std`; times before 1970 supported; sub-second parts truncated toward the past | `OutOfRange` |
| DAT-10 | `DateFormat` | P2, 3, 0.3 | | |

```rust
use parse_net as pn;

let d = pn::HttpDate::parse_imf_fixdate(b"Sun, 06 Nov 1994 08:49:37 GMT")?;
assert_eq!(d.unix(), 784_111_777);
assert_eq!(&d.format(), b"Sun, 06 Nov 1994 08:49:37 GMT");

let now = 1_792_540_800; // 2026-10-21
assert_eq!(pn::http_date_at(b"Sun Nov  6 08:49:37 1994", now)?, d);
let (_, fmt) = pn::HttpDate::parse_detailed(b"Sunday, 06-Nov-94 08:49:37 GMT", now)?;
assert_eq!(fmt, pn::DateFormat::Rfc850);
// Two-digit years by the 50-year rule: "76" is 2076 in 2026, "77" is 1977.
assert_eq!(pn::http_date_at(b"Wednesday, 01-Jan-76 00:00:00 GMT", now)?.civil().year, 2076);
assert_eq!(pn::http_date_at(b"Saturday, 01-Jan-77 00:00:00 GMT", now)?.civil().year, 1977);

let bad = pn::http_date_at(b"Mon, 06 Nov 1994 08:49:37 GMT", now).unwrap_err();
assert_eq!(bad.kind(), pn::ErrorKind::WeekdayMismatch);
assert_eq!(pn::HttpDate::from_unix(-62_135_596_801).unwrap_err().kind(), pn::ErrorKind::OutOfRange);
# Ok::<(), pn::ParseError>(())
```

Edge cases tested: the three RFC 9110 examples; `Mon` for a Sunday (mismatch); `sun,` (lowercase, refused); `UTC` and `+0000` zones (refused); `29 Feb 2024` (valid) and `29 Feb 2023` (refused); `31 Apr`; `24:00:00`; `23:59:60` with and without `allow_leap_second`; year `0000`; the last second of 9999; year 10000; RFC 850 years `75` and `77` against a 2026 `now`; asctime with a space-padded day, a two-digit day, and a missing pad; a trailing space; inputs of 28 and 30 bytes; every byte position replaced by every byte (fuzz); `format(parse(x)) == x` for every valid IMF-fixdate and `parse(format(d)) == d` for dates sampled across years 1 to 9999.

### Calendar functions

`DAT-9` | P1 | Tier 3 | 0.3

```rust
pub mod date {
    pub const fn days_from_civil(year: i32, month: u8, day: u8) -> i64;
    pub const fn civil_from_days(days: i64) -> (i32, u8, u8);
    pub const fn is_leap_year(year: i32) -> bool;
    pub const fn days_in_month(year: i32, month: u8) -> u8;
    pub const fn weekday_from_days(days: i64) -> u8;          // ISO 8601: 1 = Monday ... 7 = Sunday
}
```

The proleptic Gregorian calendar after Howard Hinnant's algorithms, in `i64` days since 1970-01-01, `const fn`, with no panics: `days_from_civil` does not validate its input (pair it with `days_in_month`); `civil_from_days` accepts any `i64` and clamps to the years an `i32` can hold; `days_in_month` returns 0 for a month outside 1 to 12.

```rust
use parse_net::date;

assert_eq!(date::days_from_civil(1970, 1, 1), 0);
assert_eq!(date::civil_from_days(-1), (1969, 12, 31));
assert!(date::is_leap_year(2000) && !date::is_leap_year(1900));
assert_eq!(date::days_in_month(2024, 2), 29);
assert_eq!(date::weekday_from_days(0), 4);   // 1970-01-01 was a Thursday
```

### `MailDate`

`DAT-11` to `DAT-13` | 0.5

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MailDate { /* utc seconds i64, offset minutes i16, offset_unknown, leap_second */ }

impl MailDate {
    pub fn new(utc_secs: i64, offset_minutes: i16) -> Result<MailDate, ParseError>;
    pub fn parse(value: &[u8], obsolete: bool) -> Result<MailDate, ParseError>;
    pub fn write_to(self, out: &mut impl Sink) -> Result<(), WriteError>;
    pub fn format(self) -> ([u8; 31], usize);                   // bytes and length
    pub const fn utc(self) -> i64;
    pub const fn offset_minutes(self) -> i16;
    pub const fn offset_unknown(self) -> bool;                  // "-0000"
    pub const fn leap_second(self) -> bool;                     // ":60" was read as ":59"
}
```

RFC 5322 section 3.3 `date-time`.

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| DAT-11 | `new`, `write_to`, `format` | P1, 2, 0.5 | `Tue, 21 Oct 2026 17:38:00 +0200`: always writes the weekday, a two-digit day, four-digit year, seconds, and a numeric zone; the offset is within plus or minus 99:59 | `new`: `OutOfRange` (year outside 1 to 9999 in local time, offset beyond 99:59); `write_to`: `Full` |
| DAT-12 | `parse` (strict) | P2, 2, 0.5 | optional weekday (must match), 1 or 2 digit day, 4 digit year, optional seconds, CFWS between tokens (comments skipped, depth-limited), `+hhmm` / `-hhmm` with minutes below 60; `-0000` sets `offset_unknown`; second `60` accepted and read as 59 with `leap_second` set ([D-006](../dev/PLAN.md#16-decision-log)) | `InvalidDate`, `WeekdayMismatch`, `TrailingData`, `UnbalancedComment`, `CommentTooDeep` |
| DAT-13 | `parse` with `obsolete = true` | P3, 2, 0.5 | RFC 5322 section 4.3: two- and three-digit years (two-digit below 50 are 20xx, others 19xx; three-digit years add 1900), `UT`, `GMT`, `EST`/`EDT`, `CST`/`CDT`, `MST`/`MDT`, `PST`/`PDT`, and the military zones (read as `-0000`, as the RFC says) | as DAT-12 |

```rust
use parse_net::MailDate;

let d = MailDate::parse(b"Tue, 21 Oct 2026 17:38:00 +0200", false)?;
assert_eq!(d.offset_minutes(), 120);
let mut buf = [0u8; 64];
let mut out = parse_net::SliceSink::new(&mut buf);
d.write_to(&mut out).expect("room");
assert_eq!(out.written(), b"Tue, 21 Oct 2026 17:38:00 +0200");
assert!(MailDate::parse(b"21 Oct 26 17:38 EDT", false).is_err());
assert_eq!(MailDate::parse(b"21 Oct 26 17:38 EDT", true)?.offset_minutes(), -240);
# Ok::<(), parse_net::ParseError>(())
```

Edge cases tested: no weekday; a weekday mismatch; a one-digit day; `+2400` (accepted: the offset may reach 99:59) and `+0060` (refused: minutes must be below 60); `-0000`; comments between tokens; obsolete zones and two-digit years only with `obsolete = true`; seconds omitted; a leap second.

---

## Entity tags: `etag`

`ETG-1` to `ETG-7` | P1 | 0.4

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EntityTag<'a> { /* weak, opaque without quotes */ }
impl<'a> EntityTag<'a> {
    pub fn parse(value: &'a [u8]) -> Result<EntityTag<'a>, ParseError>;
    pub const fn strong(opaque: &'a [u8]) -> Result<EntityTag<'a>, ParseError>;
    pub const fn weak(opaque: &'a [u8]) -> Result<EntityTag<'a>, ParseError>;
    pub const fn is_weak(&self) -> bool;
    pub const fn opaque(&self) -> &'a [u8];
    pub fn strong_eq(&self, other: &EntityTag<'_>) -> bool;
    pub fn weak_eq(&self, other: &EntityTag<'_>) -> bool;
    pub fn write_to(&self, out: &mut impl Sink) -> Result<(), WriteError>;
}

#[derive(Clone, Copy, Debug)]
pub enum Condition<'a> { Any, Tags(TagList<'a>) }           // TagList: iter() -> EntityTag, len()
pub fn parse_condition(value: &[u8], limits: &Limits) -> Result<Condition<'_>, ParseError>;
pub fn if_none_match(value: &[u8], current: &EntityTag<'_>) -> Result<bool, ParseError>;        // Tier 1
pub fn if_match(value: &[u8], current: Option<&EntityTag<'_>>) -> Result<bool, ParseError>;     // Tier 1
```

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| ETG-1 | `EntityTag::parse` | P1, 2, 0.4 | `[ "W/" ] DQUOTE *etagc DQUOTE` (RFC 9110 section 8.8.3); `W/` is case-sensitive | `InvalidEntityTag` (lowercase `w/`, no quotes, a byte outside `etagc`, `W/ "a"`); `TrailingData` |
| ETG-2 | `strong`, `weak` | P1, 2, 0.4 | build a tag from opaque bytes, checking `etagc` | `InvalidEntityTag` |
| ETG-3 | `strong_eq`, `weak_eq` | P1, 2, 0.4 | RFC 9110 section 8.8.3.2: strong comparison needs both strong and equal opaque bytes; weak comparison needs equal opaque bytes | none |
| ETG-4 | `write_to` | P1, 2, 0.4 | `W/"..."` or `"..."` | `Full` |
| ETG-5 | `parse_condition`, `Condition`, `TagList` | P1, 3, 0.4 | `"*"` or `1#entity-tag` (empty elements skipped per LST-1) | `Malformed` for `*` mixed with tags; `InvalidEntityTag`; LST errors |
| ETG-6 | `if_none_match` | P1, 1, 0.4 | true when the condition matches `current` by weak comparison, or is `*` (a current representation exists, since the caller passes one): send 304 (GET, HEAD) or 412 (other methods) | as ETG-5 |
| ETG-7 | `if_match` | P1, 1, 0.4 | true when the condition matches `current` by strong comparison, or is `*` and `current` is `Some`: the precondition holds | as ETG-5 |

```rust
use parse_net::{self as pn, EntityTag};

let v2 = EntityTag::strong(b"v2")?;
assert!(pn::if_none_match(b"\"v1\", W/\"v2\"", &v2)?);         // weak comparison: 304
assert!(!pn::if_match(b"W/\"v2\"", Some(&v2))?);               // strong comparison: 412
assert!(pn::if_match(b"*", Some(&v2))? && !pn::if_match(b"*", None)?);
assert_eq!(EntityTag::parse(b"w/\"x\"").unwrap_err().kind(), pn::ErrorKind::InvalidEntityTag);
# Ok::<(), pn::ParseError>(())
```

Edge cases tested: `""` (empty, valid); `W/""`; `w/"a"`; `"a"b`; `"a`; `W/ "a"`; byte 0x7F inside; `*, "a"`; `"a", , "b"`; `If-None-Match: *`; the RFC 9110 section 8.8.3.2 comparison table, row by row.

---

## Ranges: `range`

`RNG-1` to `RNG-8` | P1 | 0.4

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RangeSpec { From(u64), FromTo(u64, u64), Suffix(u64) }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ByteRange { pub start: u64, pub end: u64 }        // inclusive end
impl ByteRange { pub const fn len(&self) -> u64; }

#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeOutcome { Ranges(usize), Unsatisfiable, Ignore, NotBytes }

pub fn byte_ranges(value: &[u8], length: u64, out: &mut [ByteRange]) -> Result<RangeOutcome, ParseError>; // Tier 1

pub mod range {
    pub fn parse(value: &[u8], limits: &Limits) -> Result<RangeHeader<'_>, ParseError>;
    pub fn resolve(h: &RangeHeader<'_>, length: u64, coalesce: bool, limits: &Limits, out: &mut [ByteRange]) -> RangeOutcome;
    pub fn parse_content_range(value: &[u8]) -> Result<ContentRange, ParseError>;
    pub fn write_content_range(r: ByteRange, complete: Option<u64>, out: &mut impl Sink) -> Result<(), WriteError>;
    pub fn write_unsatisfied(complete: u64, out: &mut impl Sink) -> Result<(), WriteError>;
    pub fn parse_if_range(value: &[u8]) -> Result<IfRange<'_>, ParseError>;

    #[derive(Clone, Copy, Debug)]
    pub struct RangeHeader<'a> { /* unit, specs text, count */ }
    impl<'a> RangeHeader<'a> {
        pub fn is_bytes(&self) -> bool;
        pub const fn unit(&self) -> &'a [u8];
        pub fn specs(&self) -> Specs<'a>;                 // Iterator<Item = RangeSpec>; empty unless is_bytes
        pub const fn len(&self) -> usize;
        pub const fn is_empty(&self) -> bool;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ContentRange { Satisfied { range: ByteRange, complete: Option<u64> }, Unsatisfied { complete: u64 } }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IfRange<'a> { Date(HttpDate), Tag(EntityTag<'a>) }
impl IfRange<'_> {
    pub fn matches(&self, current_tag: Option<&EntityTag<'_>>, last_modified: Option<HttpDate>) -> bool;
}
```

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| RNG-1 | `range::parse`, `RangeHeader`, `RangeSpec` | P1, 3, 0.4 | RFC 9110 section 14.1.2: `range-unit "=" range-set`, no whitespace around `=`; the unit compares case-insensitively; other units are kept (`is_bytes` false) and their range set is not interpreted; numbers overflow-checked into `u64` | `InvalidRange` (`first > last`, an empty set, a malformed spec); `NumberOverflow`; LST errors |
| RNG-2 | `byte_ranges` | P1, 1, 0.4 | parse and resolve with the defaults, no coalescing. `Ranges(n)`: the first `n` entries of `out` are the satisfiable ranges, in request order; `Unsatisfiable`: answer 416; `Ignore`: serve the whole representation (200); `NotBytes`: another unit (serve 200). When `out` is too small for the ranges, the outcome is `Ignore`, never a silent truncation | as RNG-1 |
| RNG-3 | `range::resolve` | P1, 2, 0.4 | suffix ranges become absolute; `last` beyond the end is clamped; a range with `first >= length` is dropped; a zero suffix is unsatisfiable; more than `max_ranges` ranges, more than two overlapping ranges, or descending order across more than two ranges give `Ignore` (RFC 9110 section 14.2 allows ignoring abusive sets, [T12](../dev/PLAN.md#9-threats)); with `coalesce`, overlapping and adjacent ranges are merged in ascending order | none (an outcome) |
| RNG-4 | `parse_content_range`, `ContentRange` | P1, 2, 0.4 | RFC 9110 section 14.4: `bytes first-last/complete`, `bytes first-last/*`, `bytes */complete` | `InvalidRange` (`last < first`, `last >= complete`, a missing space, another unit); `NumberOverflow` |
| RNG-5 | `write_content_range` | P1, 2, 0.4 | `bytes 0-499/1234` or `bytes 0-499/*` | `OutOfRange` when `end < start` or `end >= complete`; `Full` |
| RNG-6 | `write_unsatisfied` | P1, 2, 0.4 | `bytes */1234` | `Full` |
| RNG-7 | `parse_if_range`, `IfRange::matches` | P1, 2, 0.4 | a value starting with `W/` or `"` is an entity tag, otherwise an HTTP-date (IMF-fixdate only: a sender generating `If-Range` must use it). RFC 9110 section 13.1.5: a tag matches by strong comparison (a weak tag parses, never matches); a date matches when it equals `last_modified` exactly. Not matching means: send the whole representation | ETG-1 or DAT-4 errors |
| RNG-8 | `ByteRange::len` | P1, 3, 0.4 | `end - start + 1`, saturating at `u64::MAX` (the full `u64` range) | none |

```rust
use parse_net::{self as pn, ByteRange, RangeOutcome, range};

let mut out = [ByteRange { start: 0, end: 0 }; 8];
assert_eq!(pn::byte_ranges(b"bytes=0-99, -100", 1000, &mut out)?, RangeOutcome::Ranges(2));
assert_eq!(out[1], ByteRange { start: 900, end: 999 });
assert_eq!(pn::byte_ranges(b"bytes=2000-", 1000, &mut out)?, RangeOutcome::Unsatisfiable);
assert_eq!(pn::byte_ranges(b"items=0-5", 1000, &mut out)?, RangeOutcome::NotBytes);

let mut buf = [0u8; 32];
let mut sink = pn::SliceSink::new(&mut buf);
range::write_content_range(out[0], Some(1000), &mut sink).expect("room");
assert_eq!(sink.written(), b"bytes 0-99/1000");
# Ok::<(), pn::ParseError>(())
```

Edge cases tested: `bytes=0-0`; `bytes=0-`; `bytes=-0` (unsatisfiable); `bytes=-1` on an empty representation; `bytes=5-4` (invalid); `bytes=0-18446744073709551615`; `bytes=0-18446744073709551616` (overflow); `BYTES=0-1`; `bytes = 0-1` (refused); `bytes=0-1,`; 16 and 17 ranges; three overlapping; descending order; `items=0-5`; an output buffer of 1 with 2 ranges (`Ignore`). `Content-Range`: `bytes 0-0/1`, `bytes 0-0/*`, `bytes */0`, `bytes 1-0/5`, `bytes 0-5/5`, a missing space.

---

## RFC 8187 values: `ext_value`

`EXT-1` to `EXT-4` | 0.4

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Charset { Utf8, Iso8859_1 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtValue<'a> { /* charset, language, encoded */ }
impl<'a> ExtValue<'a> {
    pub fn parse(value: &'a [u8]) -> Result<ExtValue<'a>, ParseError>;
    pub const fn charset(&self) -> Charset;
    pub const fn language(&self) -> &'a [u8];
    pub const fn encoded(&self) -> &'a [u8];
    pub fn max_decoded_len(&self) -> usize;
    pub fn decode_into<'b>(&self, out: &'b mut [u8]) -> Result<&'b str, ParseError>;
}
pub fn write_ext_value(text: &str, out: &mut impl Sink) -> Result<(), WriteError>;
```

RFC 8187 section 3.2.1: `ext-value = charset "'" [ language ] "'" value-chars`.

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| EXT-1 | `ExtValue::parse` | P0, 3, 0.4 | the charset is `UTF-8` or `ISO-8859-1`, case-insensitive; the language is empty or letters, digits, and `-` (the `Language-Tag` shape, not validated against a registry); `value-chars` are `attr-char` or `%XX` | `InvalidCharset` (no `'`, an empty or malformed charset); `UnsupportedCharset` (any other charset, [T18](../dev/PLAN.md#9-threats)); `InvalidPercentEncoding`; `InvalidByte` |
| EXT-2 | `decode_into` | P0, 3, 0.4 | percent-decodes into `out` and returns it as `&str`: UTF-8 is validated (overlong forms and surrogates refused); ISO-8859-1 is transcoded (each byte to one code point). A decoded control byte (`%00`, `%0D`, `%0A`, any C0 or DEL) is refused ([T2](../dev/PLAN.md#9-threats)) | `InvalidUtf8`, `ControlInDecoded`, `BufferTooSmall` (nothing written) |
| EXT-3 | `write_ext_value` | P1, 2, 0.4 | always `UTF-8''`, `attr-char` bytes literal, every other byte `%XX` with uppercase hex; ISO-8859-1 is never written ([D-010](../dev/PLAN.md#16-decision-log)) | `Forbidden { at }` for a control character in `text`; `Full` |
| EXT-4 | `max_decoded_len` | P1, 3, 0.4 | an upper bound for `decode_into`: exact for UTF-8, doubled for ISO-8859-1 | none |

```rust
use parse_net::{ExtValue, Charset};

let v = ExtValue::parse(b"UTF-8'en'%E2%82%AC%20rates.txt")?;
assert_eq!((v.charset(), v.language()), (Charset::Utf8, &b"en"[..]));
let mut buf = [0u8; 32];
assert_eq!(v.decode_into(&mut buf)?, "\u{20ac} rates.txt");
let latin = ExtValue::parse(b"iso-8859-1''caf%E9")?;
assert_eq!(latin.decode_into(&mut buf)?, "caf\u{e9}");
assert_eq!(ExtValue::parse(b"UTF-8''a%0Db")?.decode_into(&mut buf).unwrap_err().kind(),
           parse_net::ErrorKind::ControlInDecoded);
# Ok::<(), parse_net::ParseError>(())
```

Edge cases tested: `UTF-8''`, `utf-8''a`, `UTF-8'en'a`, `ISO-8859-1''%E9`, `UTF-16''a` (unsupported), `UTF-8''%`, `UTF-8''%G0`, `UTF-8''%C3` (truncated UTF-8), `UTF-8''%C0%AF` (overlong), `UTF-8''%00`, `UTF-8''a%2Fb` (decodes to `a/b`; the separator is reported by `Filename::has_path_separator`).

---

## Content-Disposition: `disposition`

`DSP-1` to `DSP-7` | 0.4 (DSP-7 0.5)

```rust
pub fn parse_content_disposition(value: &[u8]) -> Result<ContentDisposition<'_>, ParseError>;  // Tier 1
pub fn write_attachment(filename: &str, out: &mut impl Sink) -> Result<(), WriteError>;

pub mod disposition {
    pub fn parse(value: &[u8], limits: &Limits) -> Result<ContentDisposition<'_>, ParseError>;
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispositionType<'a> { Inline, Attachment, FormData, Other(&'a [u8]) }

#[derive(Clone, Copy, Debug)]
pub struct ContentDisposition<'a> { /* kind, params */ }
impl<'a> ContentDisposition<'a> {
    pub const fn kind(&self) -> DispositionType<'a>;
    pub const fn params(&self) -> Params<'a>;
    pub fn name(&self) -> Option<Word<'a>>;
    pub fn filename(&self) -> Option<Filename<'a>>;
    pub fn filename_plain(&self) -> Option<Word<'a>>;
    pub fn filename_ext(&self) -> Option<ExtValue<'a>>;
}

#[derive(Clone, Copy, Debug)]
pub enum Filename<'a> { Plain(Word<'a>), Ext(ExtValue<'a>) }
impl<'a> Filename<'a> {
    pub fn max_decoded_len(&self) -> usize;
    pub fn decode_into<'b>(&self, out: &'b mut [u8]) -> Result<&'b str, ParseError>;
    pub fn decode_percent_into<'b>(&self, out: &'b mut [u8]) -> Result<&'b str, ParseError>;
    pub fn has_path_separator(&self) -> bool;
    pub fn has_bidi_control(&self) -> bool;                    // 0.5
}
```

RFC 6266 section 4.1 (and its use in `multipart/form-data` part headers, RFC 7578 section 4.2).

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| DSP-1 | `parse_content_disposition`, `disposition::parse` | P0, 1, 0.4 | `disposition-type *( OWS ";" OWS disposition-parm )`; the type token is case-insensitive; parameters per PRM with `DuplicatePolicy::Refuse` (a repeated `filename` is a known differential, [T4](../dev/PLAN.md#9-threats)); a `filename*` value must parse as EXT-1, and an invalid one refuses the whole field rather than falling back silently ([T7](../dev/PLAN.md#9-threats)) | `NotToken` (type); PRM errors; EXT-1 errors; `TrailingData` |
| DSP-2 | `kind`, `name`, `params` | P0, 1, 0.4 | `name` is the `form-data` field name | none |
| DSP-3 | `filename` | P0, 1, 0.4 | `filename*` when present, else `filename` (RFC 6266 section 4.3) | none |
| DSP-4 | `Filename::decode_into`, `decode_percent_into`, `has_path_separator` | P0, 2, 0.4 | `decode_into`: the unescaped `filename` as UTF-8 (`InvalidUtf8` otherwise), or the decoded `filename*`. `decode_percent_into`: RFC 7578 section 2 file names, `%XX` in a plain `filename` decoded. Decoded control bytes are refused in both. Separators (`/`, `\`) pass through and `has_path_separator` reports them: the file-name policy belongs to path-lib and customs-sec | `InvalidUtf8`, `ControlInDecoded`, `InvalidPercentEncoding`, `BufferTooSmall` |
| DSP-5 | `write_attachment` | P1, 1, 0.4 | `attachment; filename="<ascii fallback>"; filename*=UTF-8''<encoded>`; the fallback replaces every non-ASCII byte, `"`, `\`, and control with `_`; when the name is plain printable ASCII without `"` or `\`, only `filename` is written | `Forbidden { at }` for a control character in `filename`; `Full` |
| DSP-6 | `filename_plain`, `filename_ext` | P1, 2, 0.4 | raw access to both parameters | none |
| DSP-7 | `Filename::has_bidi_control` | P2, 2, 0.5 | true when the decoded name contains U+202A to U+202E or U+2066 to U+2069 (bidirectional controls that disguise extensions, [T17](../dev/PLAN.md#9-threats)); reported, not refused | none |

```rust
use parse_net as pn;

let cd = pn::parse_content_disposition(
    b"attachment; filename=\"EURO rates.txt\"; filename*=utf-8''%e2%82%ac%20rates.txt")?;
assert_eq!(cd.kind(), pn::DispositionType::Attachment);
let mut buf = [0u8; 64];
assert_eq!(cd.filename().expect("present").decode_into(&mut buf)?, "\u{20ac} rates.txt");

let part = pn::parse_content_disposition(b"form-data; name=\"avatar\"; filename=\"../me.png\"")?;
assert!(part.name().is_some_and(|n| n.eq_bytes(b"avatar")));
assert!(part.filename().is_some_and(|f| f.has_path_separator()));

let mut sink = pn::SliceSink::new(&mut buf);
pn::write_attachment("\u{20ac} rates.txt", &mut sink).expect("room");
assert_eq!(sink.written(), b"attachment; filename=\"_ rates.txt\"; filename*=UTF-8''%E2%82%AC%20rates.txt");
# Ok::<(), pn::ParseError>(())
```

Note for form-net (its decision O-11): browsers do not backslash-escape in `multipart/form-data`, so form-net reads a quoted parameter with `Quoted::raw()` (backslash literal) and refuses a value whose raw bytes contain `\"`. Under that rule the RFC 9110 reading parse-net performs and the HTML reading agree on where every accepted value ends, so no second quoting mode is needed ([D-028](../dev/PLAN.md#16-decision-log)). form-net refuses `filename*` by default ([D-018](../dev/PLAN.md#16-decision-log)); parse-net decodes it either way.

Edge cases tested: both `filename` and `filename*`; an invalid `filename*` with a valid `filename` (field refused); a duplicate `filename`; `attachment;` alone; `inline`; `form-data; name="a"; filename=""`; an unknown type token; every greenbytes `tc2231` case with a recorded verdict.

---

## Cache-Control: `cache`

`CCH-1` to `CCH-5` | 0.4

```rust
pub fn response_cache_control(value: &[u8]) -> Result<ResponseDirectives, ParseError>;  // Tier 1
pub fn request_cache_control(value: &[u8]) -> Result<RequestDirectives, ParseError>;    // Tier 1

pub mod cache {
    pub fn parse(value: &[u8], limits: &Limits) -> Result<Directives<'_>, ParseError>;     // iter: Directive
    pub fn response_lines<'a, I>(lines: I) -> Result<ResponseDirectives, ParseError>
    where I: IntoIterator<Item = &'a [u8]>, I::IntoIter: Clone;
    pub fn request_lines<'a, I>(lines: I) -> Result<RequestDirectives, ParseError>
    where I: IntoIterator<Item = &'a [u8]>, I::IntoIter: Clone;

    pub struct Writer<'s, S: Sink> { /* sink, first */ }
    impl<'s, S: Sink> Writer<'s, S> {
        pub fn new(out: &'s mut S) -> Writer<'s, S>;
        pub fn flag(&mut self, name: &str) -> Result<&mut Self, WriteError>;
        pub fn seconds(&mut self, name: &str, secs: u32) -> Result<&mut Self, WriteError>;
        pub fn fields(&mut self, name: &str, fields: &[&str]) -> Result<&mut Self, WriteError>;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Directive<'a> { pub name: &'a [u8], pub value: Option<Word<'a>> }

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResponseDirectives {
    pub max_age: Option<u32>, pub s_maxage: Option<u32>,
    pub no_cache: bool, pub no_store: bool, pub private: bool, pub public: bool,
    pub must_revalidate: bool, pub proxy_revalidate: bool, pub must_understand: bool,
    pub no_transform: bool, pub immutable: bool,
    pub stale_while_revalidate: Option<u32>, pub stale_if_error: Option<u32>,
    pub duplicates: bool, pub invalid_values: bool, pub unknown: u16,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequestDirectives {
    pub max_age: Option<u32>, pub max_stale: Option<Option<u32>>, pub min_fresh: Option<u32>,
    pub no_cache: bool, pub no_store: bool, pub no_transform: bool, pub only_if_cached: bool,
    pub stale_if_error: Option<u32>,
    pub duplicates: bool, pub invalid_values: bool, pub unknown: u16,
}
```

RFC 9111 section 5.2: `Cache-Control = #cache-directive`, `cache-directive = token [ "=" ( token / quoted-string ) ]`.

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| CCH-1 | `cache::parse`, `Directive` | P1, 3, 0.4 | every directive in order, raw; names compare case-insensitively | LST, TXT errors; `NotToken` |
| CCH-2 | `response_cache_control`, `response_lines` | P1, 1, 0.4 | the known response directives, including `immutable` (RFC 8246), `stale-while-revalidate` and `stale-if-error` (RFC 5861). The first occurrence of a duplicated directive wins and `duplicates` is set (RFC 9111 section 4.2.1); quoted and token arguments are both accepted (section 5.2); delta-seconds saturate at 2147483648 (section 1.2.2); a non-numeric argument sets `invalid_values` and leaves the field `None` (the caller treats the response as stale); `no-cache="Set-Cookie"` and `private="..."` set the flag (the field list is available through CCH-1); conflicting directives (`private, public`) are both reported | LST errors only: unknown or malformed arguments are reported in the struct, not refused |
| CCH-3 | `request_cache_control`, `request_lines` | P1, 1, 0.4 | the same rules for request directives; `max-stale` without a value is `Some(None)` | as CCH-2 |
| CCH-4 | `cache::Writer` | P1, 2, 0.4 | `public, max-age=60, no-cache="Set-Cookie, Authorization"`; delta-seconds always in token form (senders must not quote them); field lists always quoted; names checked as tokens | `NotToken`, `Full` |
| CCH-5 | `unknown` | P2, 2, 0.4 | the count of extension directives, available raw through CCH-1 | none |

```rust
use parse_net::{self as pn, cache::Writer};

let cc = pn::response_cache_control(b"public, max-age=\"60\", MAX-AGE=5, x-ext=1")?;
assert_eq!((cc.public, cc.max_age, cc.duplicates, cc.unknown), (true, Some(60), true, 1));
let big = pn::response_cache_control(b"max-age=99999999999999999999")?;
assert_eq!(big.max_age, Some(2_147_483_648));
let req = pn::request_cache_control(b"max-stale, no-cache")?;
assert_eq!(req.max_stale, Some(None));

let mut buf = [0u8; 64];
let mut out = pn::SliceSink::new(&mut buf);
Writer::new(&mut out).flag("public").and_then(|w| w.seconds("max-age", 60)).expect("room");
assert_eq!(out.written(), b"public, max-age=60");
# Ok::<(), pn::ParseError>(())
```

Edge cases tested: `max-age=0`, `max-age="60"`, `max-age=60s` (invalid value), `max-age=99999999999999999999` (saturates), `max-age=1, max-age=2` (first wins, flag), `no-cache="Set-Cookie"`, `private, public`, an unknown directive, empty elements, uppercase names.

---

## Link: `link`

`LNK-1` to `LNK-4` | P2 | 0.5

```rust
pub fn parse_link(value: &[u8], limits: &Limits) -> Result<Links<'_>, ParseError>;     // iter: LinkValue

#[derive(Clone, Copy, Debug)]
pub struct LinkValue<'a> { /* target, params */ }
impl<'a> LinkValue<'a> {
    pub const fn target(&self) -> &'a [u8];
    pub fn rel(&self) -> Option<Word<'a>>;
    pub fn rels(&self) -> RelIter<'a>;                   // Iterator<Item = &'a [u8]>
    pub fn has_rel(&self, rel: &str) -> bool;
    pub fn anchor(&self) -> Option<Word<'a>>;
    pub fn hreflang(&self) -> HreflangIter<'a>;          // every hreflang, in order
    pub fn title(&self) -> Option<Filename<'a>>;
    pub fn media(&self) -> Option<Word<'a>>;
    pub fn type_(&self) -> Option<Word<'a>>;
    pub const fn params(&self) -> LinkParams<'a>;        // iter: (name, Option<Word>)
}
pub fn write_link(target: &[u8], params: &[(&str, &str)], out: &mut impl Sink) -> Result<(), WriteError>;
```

RFC 8288 section 3: `link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )`, `link-param = token BWS [ "=" BWS ( token / quoted-string ) ]`.

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| LNK-1 | `parse_link`, `Links`, `LinkValue` | P2, 2, 0.5 | commas inside `<...>` do not split; target bytes are RFC 3986 characters (validated with `%XX`), not resolved (url-lib resolves); a parameter value is optional (`; crossorigin`); BWS around `=` accepted | `InvalidByte` (a target byte outside RFC 3986, a space in the target); `UnterminatedQuote`; `InvalidPercentEncoding`; LST and PRM errors; `TrailingData` |
| LNK-2 | `rel`, `rels`, `has_rel` | P2, 2, 0.5 | the first `rel` only; later `rel` parameters are ignored (RFC 8288 section 3.3); `rels` splits it on spaces; `has_rel` compares case-insensitively | none |
| LNK-3 | `title` | P2, 2, 0.5 | `title*` (RFC 8187) when present, else `title` | none |
| LNK-4 | `write_link` | P2, 2, 0.5 | `<target>; name=value`, values through `write_word` | `Forbidden { at }` for `<`, `>`, SP, or a control in the target; `NotToken`; `Full` |

```rust
use parse_net::{parse_link, Limits};

let links = parse_link(b"<https://x.test/p?page=2,3>; rel=\"next last\", </a>; rel=prev; crossorigin", &Limits::DEFAULT)?;
let all: Vec<_> = links.iter().collect();
assert_eq!(all[0].target(), b"https://x.test/p?page=2,3");
assert!(all[0].has_rel("last") && all[1].has_rel("prev"));
# Ok::<(), parse_net::ParseError>(())
```

Edge cases tested: `<a>; rel=next`, `<a,b>; rel=next`, `<a>; rel="next prev"`, two `rel` (the second ignored), `title*=UTF-8''%E2%82%AC`, a missing `>`, a target with a space (refused), a parameter without a value.

---

## Forwarded and X-Forwarded-*: `forwarded`

`FWD-1` to `FWD-8` | P1 (FWD-7 P3, FWD-8 P2) | 0.4 (FWD-7 0.5)

```rust
pub trait Trust { fn is_trusted(&self, addr: core::net::IpAddr) -> bool; }
impl<F: Fn(core::net::IpAddr) -> bool> Trust for F {}

#[derive(Clone, Copy, Debug)]
pub enum ForwardedSource<'a> {
    Forwarded(&'a [&'a [u8]]),          // every Forwarded field line, in order
    XForwardedFor(&'a [&'a [u8]]),      // every X-Forwarded-For field line, in order
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClientAddress {
    Peer(core::net::IpAddr),
    Forwarded { addr: core::net::IpAddr, hops: u8 },
    Unknown { hops: u8 },
}

pub fn client_address(peer: core::net::IpAddr, source: ForwardedSource<'_>, trust: &impl Trust, max_hops: u8)
    -> Result<ClientAddress, ParseError>;                                                 // Tier 1

pub mod forwarded {
    pub fn client_address_detailed(peer: IpAddr, source: ForwardedSource<'_>, other_lines: &[&[u8]],
        trust: &impl Trust, max_hops: u8) -> Result<Resolved, ParseError>;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Resolved { pub address: ClientAddress, pub other_present: bool }

    pub fn parse<'a>(lines: &'a [&'a [u8]], limits: &Limits) -> Result<ForwardedElements<'a>, ParseError>; // iter: Element
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Element<'a> { pub for_: Option<Node<'a>>, pub by: Option<Node<'a>>,
                             pub host: Option<HostPort<'a>>, pub proto: Option<Proto> }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Node<'a> { Addr(IpAddr, Option<u16>), Unknown(Option<u16>), Obfuscated(&'a [u8], Option<&'a [u8]>) }
    #[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Proto { Http, Https }

    pub fn parse_x_forwarded_for<'a>(lines: &'a [&'a [u8]], limits: &Limits) -> Result<XffChain<'a>, ParseError>; // iter: (IpAddr, Option<u16>)
    pub fn parse_x_forwarded_proto(value: &[u8]) -> Result<Proto, ParseError>;
    pub fn parse_x_forwarded_host(value: &[u8]) -> Result<HostPort<'_>, ParseError>;
    pub fn write_element(e: &Element<'_>, out: &mut impl Sink) -> Result<(), WriteError>;   // 0.5
}
```

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| FWD-1 | `client_address`, `ClientAddress`, `Trust` | P1, 1, 0.4 | the algorithm in [PLAN 7.6](../dev/PLAN.md#76-trusted-proxy-resolution): an untrusted peer gives `Peer(peer)` and the header is never read; otherwise the whole chain is parsed and walked from the right; the first untrusted address is the client; `unknown` or an obfuscated node gives `Unknown` (nothing left of it can be trusted); all trusted gives the leftmost. Never merges the two header kinds ([T13](../dev/PLAN.md#9-threats)) | `Malformed` anywhere in the chain (fail closed: use the peer); `TooManyHops` beyond `max_hops` |
| FWD-2 | `forwarded::parse`, `Element`, `Node` | P1, 2, 0.4 | RFC 7239 section 4: `1#forwarded-element`, `forwarded-element = [ forwarded-pair ] *( ";" [ forwarded-pair ] )`; parameter names case-insensitive; values token or quoted; IPv6 must be quoted and bracketed (`for="[2001:db8::1]:4711"`), unquoted IPv6 refused; obfuscated identifiers are `_` then `ALPHA / DIGIT / "." / "_" / "-"`; ports are digits or obfuscated | `DuplicateParameter` (a name twice in one element); `InvalidAddress`; `InvalidPort`; `InvalidHost`; LST and PRM errors |
| FWD-3 | `parse_x_forwarded_for`, `XffChain` | P1, 2, 0.4 | the de facto grammar, documented as such ([D-016](../dev/PLAN.md#16-decision-log)): comma-separated IPv4 or IPv6 literals with OWS; brackets optional around IPv6; an optional `:port` after IPv4 or bracketed IPv6; nothing else | `Malformed` (an empty element, a name, garbage) |
| FWD-4 | `parse_x_forwarded_proto` | P1, 2, 0.4 | `http` or `https`, case-insensitive; a comma list only when every value is equal | `Malformed` |
| FWD-5 | `parse_x_forwarded_host` | P1, 2, 0.4 | one `HostPort` (HST-1) | `Malformed` for a list; HST errors |
| FWD-6 | `Element::host`, `Element::proto` | P1, 2, 0.4 | values validated as `Host` (HST-1) and as `http` / `https` | as FWD-2 |
| FWD-7 | `write_element` | P3, 2, 0.5 | for proxy-net: quotes IPv6 and ports; `for=192.0.2.60;proto=https;by=203.0.113.43` | `Full` |
| FWD-8 | `client_address_detailed`, `Resolved` | P2, 2, 0.4 | as FWD-1, and `other_present` reports whether the other header kind's lines (`other_lines`) are non-empty, so the caller can log a likely spoofing attempt ([T14](../dev/PLAN.md#9-threats)) | as FWD-1 |

```rust
use core::net::IpAddr;
use parse_net::{self as pn, ClientAddress, ForwardedSource};

let proxy: IpAddr = "10.0.0.2".parse()?;
let trusted = |a: IpAddr| a == proxy || a == "10.0.0.1".parse::<IpAddr>().unwrap_or(proxy);
let xff: [&[u8]; 1] = [b"203.0.113.9, 198.51.100.7, 10.0.0.1"];
let ip = pn::client_address(proxy, ForwardedSource::XForwardedFor(&xff), &trusted, 16)?;
assert_eq!(ip, ClientAddress::Forwarded { addr: "198.51.100.7".parse()?, hops: 2 });

// The same header from an untrusted peer is ignored entirely.
let stranger: IpAddr = "192.0.2.1".parse()?;
assert_eq!(pn::client_address(stranger, ForwardedSource::XForwardedFor(&xff), &trusted, 16)?,
           ClientAddress::Peer(stranger));

let fwd: [&[u8]; 1] = [b"for=192.0.2.60;proto=http;by=203.0.113.43, for=\"[2001:db8:cafe::17]:4711\""];
let elems: Vec<_> = pn::forwarded::parse(&fwd, &pn::Limits::DEFAULT)?.iter().collect();
assert_eq!(elems.len(), 2);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Edge cases tested: an untrusted peer; a trusted peer with an empty header; `for=192.0.2.60;proto=http;by=203.0.113.43`; `for="[2001:db8:cafe::17]:4711"`; unquoted IPv6 (refused); `for=unknown`; `for=_hidden`; `For=` (uppercase name); a duplicate `for` in one element; 16 and 17 hops; XFF with spaces, ports, brackets, garbage, an empty element; every hop trusted; both header kinds present.

---

## Authorization and challenges: `auth`

`ATH-1` to `ATH-7` | P1 (ATH-3, ATH-7 P2) | 0.4 (ATH-3, ATH-5, ATH-7 0.5)

```rust
pub fn bearer(value: &[u8]) -> Result<Option<&[u8]>, ParseError>;          // Tier 1
pub fn basic(value: &[u8]) -> Result<Option<&[u8]>, ParseError>;           // Tier 1
#[cfg(feature = "encode-lib")]
pub fn basic_decode_into<'b>(value: &[u8], out: &'b mut [u8]) -> Result<Option<(&'b [u8], &'b [u8])>, ParseError>;

pub mod auth {
    pub fn parse_credentials(value: &[u8], limits: &Limits) -> Result<Credentials<'_>, ParseError>;
    pub fn parse_challenges(value: &[u8], limits: &Limits) -> Result<Challenges<'_>, ParseError>; // iter: Challenge
    pub fn write_challenge(scheme: &str, params: &[(&str, &str)], out: &mut impl Sink) -> Result<(), WriteError>;
    pub fn write_challenge_token68(scheme: &str, token68: &[u8], out: &mut impl Sink) -> Result<(), WriteError>;
}

#[derive(Clone, Copy)]
pub struct Credentials<'a> { /* scheme, payload */ }
impl<'a> Credentials<'a> {
    pub const fn scheme(&self) -> &'a [u8];
    pub fn scheme_is(&self, s: &str) -> bool;
    pub const fn payload(&self) -> AuthPayload<'a>;
}
impl core::fmt::Debug for Credentials<'_> {}                // scheme only

#[derive(Clone, Copy)]
pub enum AuthPayload<'a> { None, Token68(&'a [u8]), Params(Params<'a>) }
impl core::fmt::Debug for AuthPayload<'_> {}                // redacted

#[derive(Clone, Copy, Debug)]
pub struct Challenge<'a> { /* scheme, payload */ }
impl<'a> Challenge<'a> {
    pub const fn scheme(&self) -> &'a [u8];
    pub fn scheme_is(&self, s: &str) -> bool;
    pub const fn payload(&self) -> AuthPayload<'a>;
    pub fn param(&self, name: &str) -> Option<Word<'a>>;    // realm, error, scope, ...
}
```

RFC 9110 section 11: `credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`, `challenge` the same shape, `WWW-Authenticate = #challenge`.

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| ATH-1 | `bearer` | P1, 1, 0.4 | scheme `Bearer` (case-insensitive), `1*SP`, then a `b64token` (RFC 6750 section 2.1: the token68 characters plus trailing `=`); `Ok(None)` for another scheme | `InvalidByte`, `TrailingData` (a second word), `Empty` (scheme alone) |
| ATH-2 | `basic` | P1, 1, 0.4 | scheme `Basic`; the token68 text (base64, alphabet checked, not decoded) | `InvalidBase64`, as ATH-1 |
| ATH-3 | `basic_decode_into` | P2, 1, 0.5 | `encode-lib`: decodes into `out` and splits at the first `:` (RFC 7617 section 2) into user and password; a decoded control byte is refused | `ControlInDecoded`, `InvalidBase64`, `BufferTooSmall` |
| ATH-4 | `parse_credentials`, `Credentials`, `AuthPayload` | P1, 2, 0.4 | one credential per field; parameter names unique ([T21](../dev/PLAN.md#9-threats)); BWS around `=` accepted; `Debug` prints the scheme only: credentials are secrets | `NotToken`, `DuplicateParameter`, `TrailingData`, PRM errors |
| ATH-5 | `parse_challenges`, `Challenge` | P1, 2, 0.5 | the one-pass algorithm in [PLAN 7.10](../dev/PLAN.md#710-www-authenticate), which resolves where one challenge ends and the next begins; a token68 ends at `,` or the end, trailing `=` included | `DuplicateParameter` (a name twice in one challenge), `NotToken`, `ExpectedSeparator`, LST errors |
| ATH-6 | `write_challenge` | P1, 2, 0.4 | `Bearer realm="api", error="invalid_token"`; `realm` always quoted (RFC 9110 section 11.5); other values through `write_word` | `NotToken`, `Forbidden`, `Full` |
| ATH-7 | `write_challenge_token68` | P2, 2, 0.5 | `Negotiate <token68>` | `Forbidden` for a byte outside token68, `Full` |

```rust
use parse_net::{self as pn, auth, Limits};

assert_eq!(pn::bearer(b"bearer  mF_9.B5f-4.1JqM==")?, Some(&b"mF_9.B5f-4.1JqM=="[..]));
assert_eq!(pn::bearer(b"Basic dXNlcjpwYXNz")?, None);
assert_eq!(pn::basic(b"Basic dXNlcjpwYXNz")?, Some(&b"dXNlcjpwYXNz"[..]));

let c = auth::parse_credentials(b"Digest username=\"a\", realm=\"r\"", &Limits::DEFAULT)?;
assert!(c.scheme_is("digest"));
assert_eq!(format!("{c:?}"), "Credentials { scheme: \"Digest\", .. }");
assert!(auth::parse_credentials(b"Digest a=b, a=c", &Limits::DEFAULT).is_err());
# Ok::<(), pn::ParseError>(())
```

Edge cases tested: `Bearer abc`, `bearer abc`, `Bearer  abc` (`1*SP` allows two spaces), `Bearer` alone, `Bearer abc def`, `Bearer abc==`, `Basic`, `Digest a=b, a=c`, `Negotiate token68===`, an empty value. Challenges: `Basic realm="a", Bearer`; `Bearer realm="a", error="invalid_token"`; the RFC 9110 example `Newauth realm="apps", type=1, title="Login to \"apps\"", Basic realm="simple"`; a token68 followed by a challenge; empty elements between challenges.

---

## Host: `host`

`HST-1` to `HST-4` | P0 (HST-3 P1) | 0.3

```rust
pub fn parse_host_port(value: &[u8]) -> Result<HostPort<'_>, ParseError>;    // Tier 1

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HostPort<'a> { pub host: Host<'a>, pub port: Option<u16>, pub empty_port: bool }
impl HostPort<'_> { pub fn write_to(&self, out: &mut impl Sink) -> Result<(), WriteError>; }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Host<'a> {
    Name(&'a [u8]),
    V4(core::net::Ipv4Addr),
    V6(core::net::Ipv6Addr),
    Future(&'a [u8]),                    // "vX.yyy" inside the brackets
}
impl<'a> Host<'a> {
    pub fn eq_ignore_ascii_case(&self, other: &Host<'_>) -> bool;
    pub fn write_to(&self, out: &mut impl Sink) -> Result<(), WriteError>;
    pub fn is_empty(&self) -> bool;
}

pub mod host {
    pub fn parse_host(value: &[u8]) -> Result<Host<'_>, ParseError>;            // no port
}
```

RFC 9110 section 7.2 citing RFC 3986 section 3.2.2: `Host = uri-host [ ":" port ]`.

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| HST-1 | `parse_host_port`, `HostPort`, `Host`, `host::parse_host` | P0, 1, 0.3 | reg-name (`unreserved / pct-encoded / sub-delims`, each `%` followed by two hex digits); IPv4 dotted decimal with no leading zeros; `[IPv6]` in every RFC 4291 text form, validated by the RFC 3986 `IPv6address` grammar; `[vX.…]` IPvFuture; port `*DIGIT` up to 65535; an empty port (`a:`) is accepted with `empty_port = true` and `port = None`; an empty value is `Ok` with an empty `Name` (RFC 9112 section 3.2: the target has no authority) and the caller decides. A name is returned as sent: case and a trailing dot are kept (callers normalize) | `InvalidHost` (userinfo: any `@`, checked first, so `a.com:80@b.com` is refused as a host and not as a port; a byte outside the reg-name class; `:80` with no host, an unbracketed IPv6); `InvalidAddress` (a malformed IP literal, `[zz]`, `[::1`); `InvalidPort` (non-digits, above 65535); `InvalidPercentEncoding` |
| HST-2 | `Host::eq_ignore_ascii_case` | P0, 2, 0.3 | names compare ASCII case-insensitively; IP literals compare by value (`[::1]` equals `[0:0::1]`) | none |
| HST-3 | `Host::write_to`, `HostPort::write_to` | P1, 2, 0.3 | names as given, IPv6 bracketed in its RFC 5952 form, a port after `:` | `Full` |
| HST-4 | all-digit names | P0, 1, 0.3 | a name made only of digits and dots that is not a valid IPv4 address (`1.2.3`, `256.1.1.1`, `01.2.3.4`, `127.1`) is refused, not read as a name: WHATWG and RFC 3986 disagree on such hosts, and refusing removes the differential ([T15](../dev/PLAN.md#9-threats)) | `InvalidAddress` |

`[::ffff:127.0.0.1]` is returned as `V6` (callers see exactly what was sent).

```rust
use core::net::Ipv6Addr;
use parse_net::{self as pn, Host, HostPort};

assert_eq!(pn::parse_host_port(b"[::1]:8080")?,
           HostPort { host: Host::V6(Ipv6Addr::LOCALHOST), port: Some(8080), empty_port: false });
assert_eq!(pn::parse_host_port(b"Example.COM.")?.host, Host::Name(b"Example.COM."));
assert_eq!(pn::parse_host_port(b"127.1").unwrap_err().kind(), pn::ErrorKind::InvalidAddress);
assert_eq!(pn::parse_host_port(b"a.com:80@b.com").unwrap_err().kind(), pn::ErrorKind::InvalidHost);
assert_eq!(pn::parse_host_port(b"user@b.com").unwrap_err().kind(), pn::ErrorKind::InvalidHost);
assert_eq!(pn::parse_host_port(b"a:65536").unwrap_err().kind(), pn::ErrorKind::InvalidPort);
# Ok::<(), pn::ParseError>(())
```

Edge cases tested: empty; `a`; `a:`; `a:0`; `a:65535`; `a:65536`; `a:-1`; `[::1]`; `[::1]:80`; `[::1`; `::1` (unbracketed, refused); `[v1.x]`; `1.2.3.4`; `1.2.3`; `01.2.3.4`; `256.0.0.1`; `a@b`; `%41.com`; `a b`; a trailing dot; every RFC 4291 IPv6 form (compressed, mixed with IPv4, all zeros, the maximum).

---

## Origin: `origin`

`ORG-1` to `ORG-4` | P1 (ORG-4 P2) | 0.4

```rust
pub fn parse_origin(value: &[u8]) -> Result<OriginValue<'_>, ParseError>;     // Tier 1

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OriginValue<'a> { Null, Origin(Origin<'a>) }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Origin<'a> { pub scheme: &'a [u8], pub host: Host<'a>, pub port: Option<u16> }
impl<'a> Origin<'a> {
    pub fn effective_port(&self) -> Option<u16>;
    pub fn same_origin(&self, other: &Origin<'_>) -> bool;
    pub fn write_to(&self, out: &mut impl Sink) -> Result<(), WriteError>;
}
```

RFC 6454 section 7: `origin = "null" / serialized-origin`, `serialized-origin = scheme "://" host [ ":" port ]`.

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| ORG-1 | `parse_origin`, `OriginValue`, `Origin` | P1, 1, 0.4 | `null` is case-sensitive; the scheme is ALPHA then ALPHA / DIGIT / `+` / `-` / `.` (any case accepted, compared case-insensitively); the host per HST-1, not empty; a path, query, fragment, trailing `/`, userinfo, or an empty port is refused ([T16](../dev/PLAN.md#9-threats)) | `InvalidOrigin`; HST errors |
| ORG-2 | `effective_port` | P1, 2, 0.4 | the port, or 80 for `http` and `ws`, 443 for `https` and `wss`; `None` for another scheme with no port | none |
| ORG-3 | `same_origin` | P1, 1, 0.4 | scheme and host compared case-insensitively as whole values (never prefixes or suffixes) and effective ports equal | none |
| ORG-4 | `Origin::write_to` | P2, 2, 0.4 | lowercase scheme; omits a default port | `Full` |

```rust
use parse_net::{self as pn, OriginValue};

let OriginValue::Origin(a) = pn::parse_origin(b"https://app.example.com")? else { unreachable!() };
let OriginValue::Origin(b) = pn::parse_origin(b"HTTPS://APP.example.com:443")? else { unreachable!() };
assert!(a.same_origin(&b));
let OriginValue::Origin(evil) = pn::parse_origin(b"https://app.example.com.evil.test")? else { unreachable!() };
assert!(!a.same_origin(&evil));
assert_eq!(pn::parse_origin(b"https://app.example.com/").unwrap_err().kind(), pn::ErrorKind::InvalidOrigin);
assert_eq!(pn::parse_origin(b"null")?, OriginValue::Null);
# Ok::<(), pn::ParseError>(())
```

Edge cases tested: `null`, `Null` (refused), `https://a.com`, `https://a.com:443`, `https://a.com/`, `https://a.com:`, `https://user@a.com`, `HTTPS://A.COM`, `file://` (refused: no host), a very long host.

---

## Percent-encoding: `pct`

`PCT-1` to `PCT-6` | P0 (PCT-4, PCT-6 P1) | 0.3 (PCT-4 0.4)

```rust
pub mod pct {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct EncodeSet(/* [u64; 4], bit set = must encode */);
    impl EncodeSet {
        pub const CONTROLS_AND_NON_ASCII: EncodeSet;   // C0, DEL, and 0x80 to 0xFF
        pub const ATTR_CHAR_COMPLEMENT: EncodeSet;     // RFC 8187: everything but attr-char
        pub const SF_DISPLAY: EncodeSet;               // RFC 9651: "%", DQUOTE, and outside %x20-7E
        pub const fn empty() -> EncodeSet;
        pub const fn add(self, b: u8) -> EncodeSet;
        pub const fn remove(self, b: u8) -> EncodeSet;
        pub const fn contains(&self, b: u8) -> bool;
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum HexCase { Upper, Lower }

    pub fn validate(input: &[u8]) -> Result<(), ParseError>;
    pub fn validate_with(input: &[u8], allowed: Class) -> Result<(), ParseError>;
    pub fn decoded_len(input: &[u8]) -> Result<usize, ParseError>;
    pub fn decode_into<'b>(input: &[u8], out: &'b mut [u8]) -> Result<&'b [u8], ParseError>;
    pub fn decode_utf8_into<'b>(input: &[u8], out: &'b mut [u8]) -> Result<&'b str, ParseError>;
    pub fn decode_lower_only_into<'b>(input: &[u8], out: &'b mut [u8]) -> Result<&'b [u8], ParseError>;  // 0.4
    pub fn encoded_len(input: &[u8], set: &EncodeSet) -> usize;
    pub fn encode(input: &[u8], set: &EncodeSet, case: HexCase, out: &mut impl Sink) -> Result<(), WriteError>;
}
```

The primitive parse-net's own grammars need (RFC 8187 values, RFC 9651 Display Strings, RFC 7578 file names). Everything URL-specific (component encode sets, `+` as space, normalization) belongs to url-lib, which builds its sets with `add` and `remove` ([D-004](../dev/PLAN.md#16-decision-log)).

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| PCT-1 | `validate`, `validate_with` | P0, 3, 0.3 | every `%` is followed by two hex digits (either case); `validate_with` also requires every other byte to be in `allowed` (`validate_with(input, Class::URI_TARGET)` replaces http-net's `is_target_chars`) | `InvalidPercentEncoding` at the `%`; `InvalidByte` |
| PCT-2 | `decode_into`, `decoded_len` | P0, 3, 0.3 | `%XX` decoded (either case), every other byte copied; `decoded_len` validates and counts | `InvalidPercentEncoding`; `BufferTooSmall` (nothing written) |
| PCT-3 | `decode_utf8_into` | P0, 3, 0.3 | as `decode_into`, then the decoded bytes must be UTF-8 | `InvalidUtf8`, as PCT-2 |
| PCT-4 | `decode_lower_only_into` | P1, 3, 0.4 | uppercase hex is refused (RFC 9651 section 4.2.10) | `InvalidPercentEncoding`, `BufferTooSmall` |
| PCT-5 | `encode`, `encoded_len`, `EncodeSet`, `HexCase` | P0, 3, 0.3 | every byte in the set, and every byte above 0x7F whatever the set says, is written as `%XX`; others as they are | `Full` |
| PCT-6 | named sets | P1, 3, 0.3 | only the sets parse-net's grammars use | none |

```rust
use parse_net::{self as pn, pct::{self, EncodeSet, HexCase}, class::Class};

let mut buf = [0u8; 16];
assert_eq!(pct::decode_utf8_into(b"caf%C3%A9", &mut buf)?, "caf\u{e9}");
assert_eq!(pct::validate(b"%4").unwrap_err().kind(), pn::ErrorKind::InvalidPercentEncoding);
assert!(pct::validate_with(b"/a/b?c=%20", Class::URI_TARGET).is_ok());

let mut out = pn::SliceSink::new(&mut buf);
pct::encode(b"a b/c", &EncodeSet::ATTR_CHAR_COMPLEMENT, HexCase::Upper, &mut out).expect("room");
assert_eq!(out.written(), b"a%20b%2Fc");
# Ok::<(), pn::ParseError>(())
```

Edge cases tested: `%`, `%4`, `%4g`, `%41`, `%c3%a9` against `%C3%A9` (both valid in `decode_into`, only lowercase in `decode_lower_only_into`), `%00`, decoded invalid UTF-8, a buffer one byte short.

---

## Structured Field Values: `sfv`

`SFV-1` to `SFV-16` | P1 (SFV-14, SFV-16 P2) | 0.4 (SFV-13, SFV-16 0.5)

```rust
pub mod sfv {
    pub fn parse_item(value: &[u8]) -> Result<Item<'_>, ParseError>;                    // Tier 1
    pub fn parse_list(value: &[u8]) -> Result<List<'_>, ParseError>;                    // Tier 1
    pub fn parse_dictionary(value: &[u8]) -> Result<Dictionary<'_>, ParseError>;        // Tier 1
    pub fn parse_list_lines<'a>(lines: &'a [&'a [u8]]) -> Result<ListLines<'a>, ParseError>;
    pub fn parse_dictionary_lines<'a>(lines: &'a [&'a [u8]]) -> Result<DictionaryLines<'a>, ParseError>;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Parser { /* limits */ }
    impl Parser {
        pub const fn new(limits: Limits) -> Parser;
        pub fn item<'a>(&self, v: &'a [u8]) -> Result<Item<'a>, ParseError>;
        pub fn list<'a>(&self, v: &'a [u8]) -> Result<List<'a>, ParseError>;
        pub fn dictionary<'a>(&self, v: &'a [u8]) -> Result<Dictionary<'a>, ParseError>;
        pub fn list_lines<'a>(&self, lines: &'a [&'a [u8]]) -> Result<ListLines<'a>, ParseError>;
        pub fn dictionary_lines<'a>(&self, lines: &'a [&'a [u8]]) -> Result<DictionaryLines<'a>, ParseError>;
        pub fn visit_item<'a, V: Visitor<'a>>(&self, v: &'a [u8], visitor: &mut V) -> Result<(), ParseError>;
        pub fn visit_list<'a, V: Visitor<'a>>(&self, v: &'a [u8], visitor: &mut V) -> Result<(), ParseError>;
        pub fn visit_dictionary<'a, V: Visitor<'a>>(&self, v: &'a [u8], visitor: &mut V) -> Result<(), ParseError>;
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum BareItem<'a> {
        Integer(i64), Decimal(Decimal), String(SfString<'a>), Token(&'a str),
        ByteSeq(ByteSeq<'a>), Boolean(bool), Date(i64), DisplayString(DisplayString<'a>),
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Decimal(/* thousandths, i64 */);
    impl Decimal {
        pub const fn from_thousandths(t: i64) -> Result<Decimal, ParseError>;   // OutOfRange beyond 12 integer digits
        pub const fn thousandths(self) -> i64;
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Item<'a> { pub bare: BareItem<'a>, pub params: SfParams<'a> }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Member<'a> { Item(Item<'a>), InnerList(InnerList<'a>) }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct InnerList<'a> { /* items text, count, params */ }   // iter() -> Item, len(), params()

    #[derive(Clone, Copy, Debug)] pub struct List<'a> { /* text, count */ }        // iter() -> Member, len()
    #[derive(Clone, Copy, Debug)] pub struct Dictionary<'a> { /* text, count */ }  // iter() -> (&str, Member), len()
    #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct SfParams<'a> { /* text, count */ } // iter() -> (&str, BareItem)
    #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct SfString<'a> { /* raw */ }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct ByteSeq<'a> { /* raw base64 */ }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct DisplayString<'a> { /* raw */ }

    impl<'a> Dictionary<'a> {
        pub fn get(&self, key: &str) -> Option<Member<'a>>;
        pub fn index_into<'i>(&self, slots: &'i mut [(&'a str, Member<'a>)]) -> Result<&'i [(&'a str, Member<'a>)], ParseError>;
    }
    impl<'a> SfParams<'a> {
        pub fn get(&self, key: &str) -> Option<BareItem<'a>>;
        pub const fn len(&self) -> usize;
        pub const fn is_empty(&self) -> bool;
    }
    impl<'a> SfString<'a> {
        pub const fn raw(&self) -> &'a str;                     // ASCII by construction
        pub fn as_plain(&self) -> Option<&'a str>;              // Some when no escapes
        pub fn unescaped_len(&self) -> usize;
        pub fn unescape_into<'b>(&self, out: &'b mut [u8]) -> Result<&'b str, ParseError>;
        pub fn eq_str(&self, other: &str) -> bool;
    }
    impl<'a> ByteSeq<'a> {
        pub const fn raw(&self) -> &'a [u8];
        pub fn decoded_len(&self) -> usize;
        #[cfg(feature = "encode-lib")] pub fn decode_into<'b>(&self, out: &'b mut [u8]) -> Result<&'b [u8], ParseError>;
    }
    impl<'a> DisplayString<'a> {
        pub const fn raw(&self) -> &'a [u8];
        pub fn decoded_len(&self) -> usize;
        pub fn decode_into<'b>(&self, out: &'b mut [u8]) -> Result<&'b str, ParseError>;
    }

    pub trait Visitor<'a> {
        fn item(&mut self, bare: BareItem<'a>) -> Result<(), ParseError>;
        fn param(&mut self, key: &'a str, value: BareItem<'a>) -> Result<(), ParseError>;
        fn inner_list_start(&mut self) -> Result<(), ParseError> { Ok(()) }
        fn inner_list_end(&mut self) -> Result<(), ParseError> { Ok(()) }
        fn key(&mut self, key: &'a str) -> Result<(), ParseError> { Ok(()) }
    }

    pub struct Writer<'s, S: Sink> { /* sink, state */ }                         // 0.5
    impl<'s, S: Sink> Writer<'s, S> {
        pub fn item(out: &'s mut S) -> Writer<'s, S>;
        pub fn list(out: &'s mut S) -> Writer<'s, S>;
        pub fn dictionary(out: &'s mut S) -> Writer<'s, S>;
        pub fn bare(&mut self, b: &BareItem<'_>) -> Result<&mut Self, WriteError>;
        pub fn integer(&mut self, v: i64) -> Result<&mut Self, WriteError>;
        pub fn decimal(&mut self, thousandths: i64) -> Result<&mut Self, WriteError>;
        pub fn string(&mut self, s: &str) -> Result<&mut Self, WriteError>;
        pub fn token(&mut self, t: &str) -> Result<&mut Self, WriteError>;
        pub fn boolean(&mut self, b: bool) -> Result<&mut Self, WriteError>;
        pub fn date(&mut self, secs: i64) -> Result<&mut Self, WriteError>;
        pub fn display_string(&mut self, s: &str) -> Result<&mut Self, WriteError>;
        #[cfg(feature = "encode-lib")] pub fn bytes(&mut self, b: &[u8]) -> Result<&mut Self, WriteError>;
        pub fn param(&mut self, key: &str, v: &BareItem<'_>) -> Result<&mut Self, WriteError>;
        pub fn key(&mut self, key: &str) -> Result<&mut Self, WriteError>;
        pub fn open_inner_list(&mut self) -> Result<&mut Self, WriteError>;
        pub fn close_inner_list(&mut self) -> Result<&mut Self, WriteError>;
        pub fn finish(self) -> Result<(), WriteError>;
    }
    #[cfg(feature = "alloc")] pub mod owned { /* OwnedBareItem, OwnedItem, OwnedList, OwnedDictionary */ }
}
```

RFC 9651. The parser follows section 4.2 exactly, as a loop with explicit state, not recursion (depth is at most 2: an inner list inside a list or dictionary). A field is accepted or refused as a whole, as section 4.2 requires.

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| SFV-1 | `parse_item` | P1, 1, 0.4 | section 4.2.3; leading and trailing SP discarded (SP only) | `TrailingData`; the bare item errors below |
| SFV-2 | `parse_list` | P1, 1, 0.4 | section 4.2.1; OWS (SP and HTAB) around commas; an empty value is an empty list | `TrailingSeparator` (`a, b,`), `ExpectedSeparator`, `TooManyMembers` beyond `max_list_members` or `max_inner_list_members` |
| SFV-3 | `parse_dictionary` | P1, 1, 0.4 | section 4.2.2; a key with no `=` is Boolean true (parameters still allowed); duplicate keys: the last wins, as the RFC requires; views keep every member in order | as SFV-2, `InvalidKey`, `TooManyMembers` beyond `max_dictionary_members` |
| SFV-4 | `parse_list_lines`, `parse_dictionary_lines` | P1, 2, 0.4 | several field lines as one field (joined by `, ` without copying); an empty line or a line that fails on its own fails the whole field | as SFV-2 and SFV-3, with `line()` |
| SFV-5 | Integer, Decimal | P1, 2, 0.4 | Integer: optional `-`, at most 15 digits (plus or minus 999,999,999,999,999). Decimal: at most 12 integer and 3 fractional digits, at least one fractional digit, stored as thousandths | `InvalidNumber` (`-` alone, `1.`, `.5`, `+1`), `NumberOverflow` (16 digits, 13 integer digits, 4 fractional digits) |
| SFV-6 | `SfString` | P1, 2, 0.4 | `DQUOTE *( unescaped / "\" ( DQUOTE / "\" ) ) DQUOTE`; only `\"` and `\\` escapes; bytes outside `%x20-7E` refused | `InvalidByte`, `InvalidQuotedPair`, `UnterminatedQuote`, `TooLong` beyond `max_string_len` (decoded) |
| SFV-7 | Token | P1, 2, 0.4 | first `ALPHA / "*"`, then `tchar / ":" / "/"`; returned as `&str` (ASCII by construction) | `InvalidByte`, `TooLong` beyond `max_token_len` |
| SFV-8 | `ByteSeq` | P1, 2, 0.4 | `":" *base64 ":"`; the alphabet and the position of `=` are checked; missing padding and non-zero pad bits are accepted, as section 4.2.7 says they should not cause failure ([T24](../dev/PLAN.md#9-threats)); `decoded_len` is exact; decoding needs `encode-lib` | `InvalidBase64`, `UnterminatedQuote` (no closing `:`), `TooLong` beyond `max_byte_seq_len` (decoded) |
| SFV-9 | Boolean | P1, 2, 0.4 | `?1` and `?0` only | `InvalidByte` |
| SFV-10 | Date | P1, 2, 0.4 | `@` and an Integer, seconds since the epoch; years 1 to 9999 (section 3.3.7 sets no range; parse-net keeps the `HttpDate` range, so every Date converts) | `InvalidNumber` (a Decimal after `@`), `OutOfRange` |
| SFV-11 | `DisplayString` | P1, 2, 0.4 | `%"` then printable ASCII except `%` and `"`, or `%xx` with lowercase hex; the decoded bytes are UTF-8 validated during the parse by an incremental validator (no buffer, [T19](../dev/PLAN.md#9-threats)); `decode_into` writes the text | `InvalidPercentEncoding` (uppercase hex, a broken triple), `InvalidUtf8` (including surrogates and overlong forms), `UnterminatedQuote`, `TooLong` |
| SFV-12 | keys | P1, 2, 0.4 | `( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" )`; at most `max_key_len` (default 256, RFC minimum 64) | `InvalidKey` (uppercase, a digit first), `TooLong` |
| SFV-13 | `Writer` | P1, 2, 0.5 | canonical serialization (section 4.1): `?1`, decimals with the shortest fractional part (`1.5`, `1.0` for whole numbers), strings with only `\"` and `\\` escaped, Display Strings with lowercase `%xx` for `%`, `"`, and everything outside `%x20-7E`, byte sequences always padded; a dictionary member whose value is Boolean true is written as its key alone | `OutOfRange` (an integer beyond 15 digits, a decimal beyond 12 integer digits, a date outside years 1 to 9999); `Forbidden { at }` (a non-ASCII or control byte in a string); `NotToken` (an invalid token or key); `InvalidSequence` (a parameter before any item, two items in an `item` writer, `finish` with an open inner list or with no item); `Full` |
| SFV-14 | `Visitor`, `visit_*` | P2, 3, 0.4 | a single pass with no view, for callers that read one key or count items; a visitor error stops the parse and is returned | as the matching parse, plus the visitor's |
| SFV-15 | `Dictionary::get`, `index_into` | P1, 2, 0.4 | `get` is a linear scan returning the last match; `index_into` fills a caller array with one slot per distinct key (last wins), for callers that look up many keys | `index_into`: `BufferTooSmall` when there are more distinct keys than slots |
| SFV-16 | `owned` types | P2, 2, 0.5 | `alloc`; see [Owned forms](#owned-forms) | none |

```rust
use parse_net::sfv::{self, BareItem, Member};

let site = sfv::parse_item(b"same-origin")?;
assert_eq!(site.bare, BareItem::Token("same-origin"));

let prio = sfv::parse_dictionary(b"u=1, i")?;
assert_eq!(prio.get("u").map(|m| matches!(m, Member::Item(i) if i.bare == BareItem::Integer(1))), Some(true));
assert_eq!(prio.get("i").map(|m| matches!(m, Member::Item(i) if i.bare == BareItem::Boolean(true))), Some(true));

let list = sfv::parse_list(b"(\"foo\" \"bar\");lvl=5, abc;a=?0")?;
assert_eq!(list.len(), 2);
let Some(Member::InnerList(inner)) = list.iter().next() else { unreachable!() };
assert_eq!(inner.len(), 2);

assert!(sfv::parse_list(b"a, b,").is_err());                  // trailing comma
assert!(sfv::parse_item(b"%\"%C3%A9\"").is_err());            // uppercase hex in a Display String
let text = sfv::parse_item(b"%\"caf%c3%a9\"")?;
let BareItem::DisplayString(d) = text.bare else { unreachable!() };
let mut buf = [0u8; 8];
assert_eq!(d.decode_into(&mut buf)?, "caf\u{e9}");
# Ok::<(), parse_net::ParseError>(())
```

Conformance: the httpwg `structured-field-tests` suite runs in full (every parse and serialize test, and every list and dictionary also split into several lines at member boundaries). Edge cases tested beyond it: a tab before an item (refused), tabs around list commas (accepted), `?2`, `@1.5`, `@-62135596801` (out of range), `%"%C3%A9"` (uppercase refused), `%"%c3"` (truncated UTF-8), duplicate dictionary keys with parameters, an inner list with a space before `)`, the empty inner list `()`, keys `a*b`, `*`, `A`, 15- and 16-digit integers, `-0`, decimal `-0.0`, byte sequences without padding, with non-zero pad bits, and with whitespace (refused).

---

## Email lexical layer: `mail`

`MAIL-1` to `MAIL-14` | P1 (MAIL-2, MAIL-5, MAIL-6, MAIL-11, MAIL-12 P2) | 0.5

```rust
pub mod mail {
    pub fn check_header_value(value: &[u8]) -> Result<(), ParseError>;
    pub fn is_field_name(name: &[u8]) -> bool;
    pub fn unfold(value: &[u8]) -> Result<Unfolded<'_>, ParseError>;           // iter: &[u8] pieces
    pub fn fold(name: &str, value: &[u8], out: &mut impl Sink) -> Result<(), WriteError>;
    pub fn encode_words(text: &str, room_first_line: usize, out: &mut impl Sink) -> Result<(), WriteError>;
    #[cfg(feature = "encode-lib")]
    pub fn encode_words_b(text: &str, room_first_line: usize, out: &mut impl Sink) -> Result<(), WriteError>;
    pub fn decode_words<'b>(value: &[u8], limits: &Limits, out: &'b mut [u8]) -> Result<&'b str, ParseError>;
    pub fn parse_mime_params(s: &[u8], limits: &Limits) -> Result<(MimeParams<'_>, usize), ParseError>;
    pub fn write_mime_param(name: &str, value: &str, out: &mut impl Sink) -> Result<(), WriteError>;
    pub fn parse_addr_spec(value: &[u8]) -> Result<AddrSpec<'_>, ParseError>;
    pub fn parse_mailbox(value: &[u8], limits: &Limits) -> Result<Mailbox<'_>, ParseError>;
    pub fn parse_msg_id(value: &[u8]) -> Result<MsgId<'_>, ParseError>;
    pub fn write_msg_id(left: &str, right: &str, out: &mut impl Sink) -> Result<(), WriteError>;
    pub use crate::MailDate;

    #[derive(Clone, Copy, Debug)]
    pub struct MimeParams<'a> { /* text, count */ }
    impl<'a> MimeParams<'a> {
        pub fn get(&self, name: &str) -> Option<MimeValue<'a>>;
        pub fn decode_into<'b>(&self, name: &str, out: &'b mut [u8]) -> Result<Option<&'b str>, ParseError>;
        pub fn iter(&self) -> MimeParamIter<'a>;                  // raw parameters, sections included
        pub const fn len(&self) -> usize;
    }
    #[derive(Clone, Copy, Debug)]
    pub enum MimeValue<'a> { Plain(Word<'a>), Extended(ExtValue<'a>), Continued(Continuation<'a>) }
    #[derive(Clone, Copy, Debug)]
    pub struct Continuation<'a> { /* params text, name */ }
    impl Continuation<'_> {
        pub fn sections(&self) -> usize;
        pub fn max_decoded_len(&self) -> usize;
        pub fn decode_into<'b>(&self, out: &'b mut [u8]) -> Result<&'b str, ParseError>;
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AddrSpec<'a> { pub local: LocalPart<'a>, pub domain: Domain<'a> }
    impl AddrSpec<'_> { pub fn is_ascii(&self) -> bool; }      // false: needs SMTPUTF8
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum LocalPart<'a> { DotAtom(&'a [u8]), Quoted(Quoted<'a>) }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Domain<'a> { DotAtom(&'a [u8]), Literal(&'a [u8]) }   // Literal: inside [ ]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Mailbox<'a> { pub display_name: Option<&'a [u8]>, pub addr: AddrSpec<'a> }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MsgId<'a> { pub left: &'a [u8], pub right: &'a [u8] }
}
```

The grammar smtp-net needs to write mail and gate-net needs to validate login addresses ([D-008](../dev/PLAN.md#16-decision-log)). Charsets decoded: UTF-8, US-ASCII, ISO-8859-1 only.

| Id | Item | Grade, tier, version | Behaviour | Errors |
|---|---|---|---|---|
| MAIL-1 | `check_header_value` | P1, 1, 0.5 | no CR, LF, or NUL; no physical line over 998 bytes (RFC 5322 section 2.1.1) | `BareCr`, `LineFeed`, `Nul`, `LineTooLong` |
| MAIL-2 | `unfold` | P2, 2, 0.5 | validates, then iterates the pieces between `CRLF WSP` folds (the CRLF removed, the WSP kept, RFC 5322 section 2.2.3) | `BareCr`, `LineFeed` (a CRLF not followed by WSP, or a lone CR or LF) |
| MAIL-3 | `fold` | P1, 1, 0.5 | writes `Name: value` and CRLF-SP folds at whitespace so lines stay within 78 columns where possible; never a line of only whitespace; never over 998 | `NotToken` for a name outside `ftext`; `Forbidden { at }` for CR, LF, NUL in `value`; `OutOfRange` for a word longer than 998 - the folding indent; `Full` |
| MAIL-4 | `encode_words` (Q) | P1, 1, 0.5 | RFC 2047: printable ASCII text without `=?` is written as it is; otherwise `=?UTF-8?Q?...?=` words of at most 75 bytes, split only on UTF-8 character boundaries, separated by CRLF SP; the first word fits in `room_first_line` | `Forbidden { at }` for a control character; `Full` |
| MAIL-5 | `encode_words_b` | P2, 1, 0.5 | `encode-lib`: the B encoding, used when Q would be longer | as MAIL-4 |
| MAIL-6 | `decode_words` | P2, 2, 0.5 | decodes encoded words in unstructured text into `out`; whitespace between adjacent encoded words is dropped (RFC 2047 section 6.2); text outside encoded words copied; `_` is a space in Q; words inside quoted strings are not decoded (section 5); B needs `encode-lib` | `UnsupportedCharset`, `InvalidEncodedWord`, `ControlInDecoded` (CR, LF, NUL), `InvalidUtf8`, `TooManyMembers` beyond `max_encoded_words`, `BufferTooSmall` |
| MAIL-7 | `parse_mime_params`, `MimeParams` | P1, 3, 0.5 | RFC 2045 section 5.1 with the MIME `token` class (allows `{` and `}`); case-insensitive names; CFWS between parameters | `NotToken`, `MissingValue`, `DuplicateParameter`, `UnterminatedQuote`, `TooManyMembers` |
| MAIL-8 | RFC 2231 (`get`, `decode_into`, `Continuation`) | P1, 2, 0.5 | the reassembly in [PLAN 7.12](../dev/PLAN.md#712-rfc-2231-reassembly-without-allocation): sections `name*0`, `name*1*`, ... numbered from 0 without gaps or duplicates; a charset only on section 0; decoded in order into `out` | `SectionGap`, `TooManySections`, EXT-1 and EXT-2 errors, `BufferTooSmall` |
| MAIL-9 | `write_mime_param` | P1, 1, 0.5 | `; name=token`, `; name="quoted"`, or, for non-ASCII or long values, `; name*=UTF-8''...` split into `name*0*`, `name*1*` sections so no line passes 78 columns | `NotToken` (name), `Forbidden { at }` (control), `Full` |
| MAIL-10 | `parse_addr_spec`, `AddrSpec`, `LocalPart`, `Domain` | P1, 1, 0.5 | RFC 5322 section 3.4.1 without obsolete forms, comments, or folding: `dot-atom` or quoted local part, `@`, `dot-atom` domain or `[domain-literal]`; local part at most 64 octets and the whole address at most 254 (RFC 5321 section 4.5.3.1); non-ASCII accepted only as valid UTF-8 (RFC 6532), never as raw obs-text; `is_ascii` false means SMTPUTF8 is needed | `InvalidAddrSpec` (a leading, trailing, or doubled dot, a missing `@`, a comment), `TooLong`, `InvalidUtf8` |
| MAIL-11 | `parse_mailbox`, `Mailbox` | P2, 2, 0.5 | `[display-name] "<" addr-spec ">"` or a bare `addr-spec`; the display name is returned raw (phrases or encoded words; decode with `decode_words`) | as MAIL-10, `UnterminatedQuote`, `UnbalancedComment` |
| MAIL-12 | `parse_msg_id`, `write_msg_id` | P2, 2, 0.5 | `"<" id-left "@" id-right ">"`, `dot-atom-text` on both sides (or a `no-fold-literal` on the right) | `InvalidAddrSpec`; writer: `Forbidden`, `Full` |
| MAIL-13 | `MailDate` re-export | P1, 1, 0.5 | DAT-11 to DAT-13 | |
| MAIL-14 | `is_field_name` | P1, 3, 0.5 | `ftext = %d33-57 / %d59-126` (RFC 5322 section 3.6.8), non-empty | none |

```rust
use parse_net::{mail, SliceSink, Limits};

let mut buf = [0u8; 256];
let mut out = SliceSink::new(&mut buf);
mail::encode_words("Caf\u{e9} au lait", 64, &mut out).expect("room");
assert_eq!(out.written(), b"=?UTF-8?Q?Caf=C3=A9_au_lait?=");

let a = mail::parse_addr_spec(b"\"john doe\"@example.com")?;
assert!(a.is_ascii());
assert!(mail::parse_addr_spec(b"john..doe@example.com").is_err());

let (p, _) = mail::parse_mime_params(b"; filename*0*=UTF-8''caf%C3%A9; filename*1=\".txt\"", &Limits::DEFAULT)?;
let mut name = [0u8; 32];
assert_eq!(p.decode_into("filename", &mut name)?, Some("caf\u{e9}.txt"));
# Ok::<(), parse_net::ParseError>(())
```

Edge cases tested: a header value of exactly 998 bytes and of 999; folding a single 1,000-byte word (refused); an encoded word of exactly 75 bytes; a multi-byte UTF-8 character at the split point; `=?utf-8?q?a_b?=`; adjacent encoded words separated by whitespace; an encoded word inside a quoted string (not decoded); RFC 2231 `*0`, `*1`, a missing `*1` with `*2` present, `*00`, a charset on `*1`, 32 and 33 sections; `addr-spec` with a quoted local part, with `..`, with a leading dot, with 64- and 65-byte local parts, with a `[192.0.2.1]` domain literal, with a UTF-8 local part, with a comment (refused).

---

## Owned forms

`OWN`, `MED-11`, `SFV-16` | P2 | Tier 2 | 0.5 | `alloc` feature

```rust
#[cfg(feature = "alloc")]
pub struct OwnedMediaType { /* String, offsets */ }       // MediaType::to_owned, as_view
#[cfg(feature = "alloc")]
pub struct OwnedEntityTag { /* weak, Vec<u8> */ }          // EntityTag::to_owned, as_view
#[cfg(feature = "alloc")]
pub struct OwnedHostPort { /* host bytes or address, port */ }   // HostPort::to_owned, as_view
#[cfg(feature = "alloc")]
pub mod sfv::owned { /* OwnedBareItem, OwnedItem, OwnedList, OwnedDictionary: to_owned on each view, as_view back */ }
```

For callers that must keep a parsed value beyond the input buffer. Each allocates once per value (`to_owned`) and gives the same view back (`as_view`), so every accessor works on both. Owned forms are never used inside parse-net, and nothing else in the crate allocates.

---

## Thread safety and sizes

Every public type is `Send + Sync + Unpin` (checked at compile time), holds no interior mutability, and every view is `Copy`. There is no global mutable state; the class table is immutable `static` data. Sizes on 64-bit targets, checked by tests so a change that grows them is noticed:

| Type | Size |
|---|---|
| `ParseError` | 8 bytes |
| `Quoted`, `Word`, `Params`, `List`, `EntityTag` | 24 bytes |
| `MediaType` | 56 bytes |
| `HttpDate` | 8 bytes |
| `sfv::Item` | at most 64 bytes |

---

## Consumer checklists

The 0.2 review of this API against each consumer's needs. "Moves" means the consumer deletes its copy when it adopts parse-net ([PLAN 6.3](../dev/PLAN.md#63-what-moves-out-of-http-net-and-ws-net)). Every consumer uses parse-net with default features (`no_std`, no allocator) unless the row says otherwise.

### http-net (adopts at its 0.4)

| http-net today | parse-net | Note |
|---|---|---|
| `syntax.rs` `TCHAR`, `FIELD`, `HEX`, `QDTEXT` bits | `class::is_tchar`, `is_field_text`, `is_hexdig`, `is_qdtext` | the equality test (every byte, every class) is in parse-net's suite and repeated in http-net's migration branch |
| `is_token`, `is_ows`, `trim_ows` | `text::is_token`, `is_ows`, `trim_ows` | same behaviour, VT and FF kept |
| `check_field_value` (SWAR) | `scan::check_field_value` | `BareCr` maps to http-net's smuggling error; `LineFeed`, `Nul`, `Control` to its invalid-value error |
| `parse_decimal` (`Option`) | `num::parse_u64` (`Result`) | same accepted set |
| `hex_value` | `class::hex_value` | same |
| `list_elements` | `list(value)?.iter()`, `list::contains_token` | quote-aware already; parse-net also refuses unterminated quotes and bounds empty elements ([D-011](../dev/PLAN.md#16-decision-log)) |
| `find_byte` | `scan::find_byte` | same SWAR algorithm; `#[inline]` justified by http-net's `request_head` benchmark (NFR-8) |
| `push_hex`, `push_decimal` | `write::write_hex_u64`, `write_decimal_u64` with `Sink for Vec<u8>` (`alloc`) | optional: http-net may keep its own, its 7.9 says these stay |
| `blocking.rs` `http_date` | `HttpDate::from_unix(secs)?.format()` | full year range |
| `is_host_value` | `parse_host_port` | stricter: real IPv4 and IPv6 validation, ports above 65535 and `127.1` refused (HST-4); http-net may keep its check until url-lib exists (its 7.9) |
| `is_target_chars` | `pct::validate_with(t, Class::URI_TARGET)` | optional until url-lib |
| `is_reason`, `is_protocol`, head scanning, chunk lines | stay in http-net | RFC 9112 |
| `Date`, `Last-Modified`, conditional requests, ranges, media types for callers | `HttpDate`, `etag`, `range`, `media` | from parse-net 0.3 and 0.4 |

### ws-net

| ws-net today | parse-net | Note |
|---|---|---|
| `head.rs` `is_token` | `text::is_token` | |
| `head.rs` `trim_ows` | `text::trim_ows` | |
| `head.rs` `is_control`, `is_visible` | `scan::check_field_value`, `class::all(s, Class::VCHAR)` | |
| `handshake.rs` `list`, `list_has` | `list`, `list::contains_token` | commas inside quoted strings no longer split |
| `Sec-WebSocket-Extensions` | `list` then `param::parse` per element | RFC 6455 section 9.1 extensions with parameters become readable |
| `Sec-WebSocket-Protocol` | `list` of tokens | |
| `Origin` checks | `parse_origin`, `Origin::same_origin` | from 0.4 |
| `base64.rs`, `sha1.rs` | not parse-net | encode-lib and crypt-io |

### cookie-net (its 0.3 needs parse-net 0.3)

| Need | parse-net |
|---|---|
| cookie names are tokens | `text::is_token`, `class::is_tchar` |
| cookie value and attribute value bytes | `class::is_cookie_octet`, `is_av_octet` (table bits only; cookie grammar stays in cookie-net) |
| OWS around pairs | `text::trim_ows` |
| `Expires` written | `HttpDate::write_to` (or `format`) |
| `Expires` read on the server, if ever | `HttpDate::parse_imf_fixdate` (the lenient client cookie-date algorithm stays in cookie-net, [D-020](../dev/PLAN.md#16-decision-log)) |
| `Domain` syntax | `host::parse_host` (a leading dot is cookie-net's rule) |
| output | `Sink`, `SliceSink`, `CountSink` (exact `encoded_len`), `write::write_field_value` |
| `;` search | `scan::find_byte` |

### form-net (its 0.3 waits for parse-net 0.4)

| form-net need (its section 3.3) | parse-net |
|---|---|
| media type parse, case-insensitive type and subtype, parameters in order, no allocation | `media::parse`, `MediaType::is_multipart_form_data`, `is_form_urlencoded`, `charset`, `params().iter()` |
| `boundary` validated | `MediaType::boundary` (RFC 2046) |
| every parameter including duplicates | duplicates are refused at parse time by default (`DuplicateParameter`): form-net refuses them too, so the outcome is the same; `DuplicatePolicy::First` with `Params::iter` shows them all if form-net wants its own error mapping |
| quoted-string in RFC 9110 mode | `Word::unescape_into` |
| quoted-string in form-data mode (backslash literal) | `Quoted::raw` plus refusing raw bytes containing `\"`; see the note under [Content-Disposition](#content-disposition-disposition) |
| `filename*` decode, UTF-8 only, into a caller buffer | `ContentDisposition::filename_ext`, then `ExtValue::charset() == Charset::Utf8` and `decode_into` |
| `Content-Disposition` type, parameters, raw value bytes | `disposition::parse`, `kind`, `name`, `filename_plain`, `params` |
| RFC 7578 percent-encoded file names | `Filename::decode_percent_into`, `pct::decode_into` |
| budgets per call | `Limits::max_params` and the other bounds; the maximum input length is the caller's check on `value.len()` |
| legacy RFC 2047 names (optional) | `mail::decode_words` (0.5) |

### smtp-net (its 0.3 needs parse-net 0.5, or a private interim module with these signatures)

| Need | parse-net |
|---|---|
| `Date` header | `MailDate::new`, `write_to` |
| header folding | `mail::fold` |
| `Subject` and display names | `mail::encode_words` (Q); `encode_words_b` with `encode-lib` |
| `Content-Type` and `Content-Disposition` with RFC 2231 | `media::write`, `mail::write_mime_param` |
| reading parameters of received parts | `mail::parse_mime_params`, `MimeParams::decode_into` |
| addresses | `mail::parse_addr_spec`, `AddrSpec::is_ascii` (SMTPUTF8), `parse_mailbox` |
| `Message-ID` | `mail::write_msg_id`, `parse_msg_id` |
| header checks | `mail::check_header_value`, `is_field_name` |
| base64 and quoted-printable bodies | not parse-net: encode-lib ([D-002](../dev/PLAN.md#16-decision-log), [D-009](../dev/PLAN.md#16-decision-log)); smtp-net keeps its interim encoders until encode-lib publishes |
