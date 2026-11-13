# parse-net - Migration

- [0.9 to 0.10](#09-to-010)
- [Moving http-net and ws-net onto parse-net (0.3)](#moving-http-net-and-ws-net-onto-parse-net-03)

---

## 0.9 to 0.10

`0.10.0` simplified the API before 1.0: root parsers are all named `parse_*`, Tier 1 calls take no `Limits`, abbreviations became words, and each thing has one way to do it. There are no deprecated aliases: the compiler names every call that needs changing, and these tables give its replacement. It also has security fixes, and fixes four negotiation cases from issue #14; the behaviour changes are listed below the tables. `MediaRange::params` returns `media::RangeParams` (every parameter but `q`), with the same `iter`, `get`, `len`, and `is_empty`.

```toml
[dependencies]
parse-net = { version = "0.10", default-features = false }
```

### Renamed calls and items

| 0.9 | 0.10 |
|---|---|
| `parse_net::list(value)` | `parse_net::parse_list(value)` |
| `parse_net::http_date(value)` (`std`) | `parse_net::parse_http_date(value)` |
| `parse_net::http_date_at(value, now)` | `parse_net::parse_http_date_at(value, now)` |
| `HttpDate::parse_at(value, now)` | `parse_net::parse_http_date_at(value, now)` |
| `HttpDate::parse_at_with(value, now, &limits)` | `HttpDate::parse_with_limits(value, now, &limits)` |
| `parse_net::response_cache_control(value)` | `parse_net::parse_response_cache_control(value)` |
| `parse_net::request_cache_control(value)` | `parse_net::parse_request_cache_control(value)` |
| `cache::response_lines(lines)` | `cache::parse_response_lines(lines)` |
| `cache::request_lines(lines)` | `cache::parse_request_lines(lines)` |
| `list::combined(lines, &limits)` | `list::parse_lines(lines, &limits)` |
| `MailDate::parse(value, false)` | `MailDate::parse(value)` |
| `MailDate::parse(value, true)` | `MailDate::parse_obsolete(value)` |
| `mail::encode_words_b(text, room, out)` | `mail::encode_words_base64(text, room, out)` |
| module `pct` | module `percent` |
| `pct::decode_lower_only_into(input, out)` | `percent::decode_lowercase_into(input, out)` |
| module `sfv` | module `structured` |
| module `ext_value`, `ExtValue`, `write_ext_value` | module `extended_value`, `ExtendedValue`, `write_extended_value` |
| `forwarded::XffChain` | `forwarded::XForwardedFor` |
| `view.to_owned()` on `MediaType`, `EntityTag`, `HostPort`, and the `structured` views | `view.into_owned()` (the old name shadowed `ToOwned::to_owned`, which these `Copy` views also have, and gives a view, not an owned value) |

### Changed signatures

| 0.9 | 0.10 |
|---|---|
| `client_address(peer, source, &trust, 16)?` | `client_address(peer, source, &trust)`: no `Result`, at most 16 trusted hops |
| `client_address(peer, source, &trust, n)?` | `forwarded::client_address_with_limits(peer, source, &trust, &Limits::DEFAULT.max_hops(n))` |
| `client_address_detailed(peer, source, other, &trust, n)?` | `client_address_detailed(peer, source, other, &trust, &limits)`: no `Result` |
| `if_none_match(value, &tag)?` | `if_none_match(value, Representation::Tagged(tag))?` |
| `if_match(value, Some(&tag))?` | `if_match(value, Representation::Tagged(tag))?` |
| `if_match(value, None)?` | `if_match(value, Representation::Absent)?` |
| a representation without a tag | `Representation::Untagged` (new: `*` matches it, no tag does) |
| `HostPort { host, port, empty_port: false }` | `HostPort::new(host, port)` |
| `Origin { scheme, host, port }` | `Origin::new(scheme, host, port)` |
| `forwarded::Element { for_, by, host, proto }` | `let mut e = Element::new();` then set the fields |
| a `match` on `Host` or `forwarded::Node` | add a `_` arm: both are `#[non_exhaustive]`, as are `HostPort`, `Origin`, and `Element` |

`client_address` no longer fails. `ClientAddress::Unknown` now covers every case with no reliable client address, including text that is not an address at the decision point and more trusted hops than the limit. Where 0.9 code answered an error with the peer address, treat the client as unknown instead (one shared rate-limit bucket, or a refusal): the peer is a trusted proxy.

### Calls that lost their `Limits`

The plain call uses `Limits::DEFAULT`; the full form takes the limits as before.

| 0.9 | 0.10, default limits | 0.10, other limits |
|---|---|---|
| `parse_link(value, &limits)` | `parse_link(value)` | `link::parse(value, &limits)` |
| `etag::parse_condition(value, &limits)` (also at the root) | `if_match`, `if_none_match` for the answer | `etag::parse(value, &limits)` |
| `mail::parse_mailbox(value, &limits)` | `mail::parse_mailbox(value)` | `mail::parse_mailbox_with_limits(value, &limits)` |
| `mail::decode_words(value, &limits, out)` | `mail::decode_words(value, out)` | `mail::decode_words_with_limits(value, &limits, out)` |
| `mail::decode_phrase(value, &limits, out)` | `mail::decode_phrase(value, out)` | `mail::decode_phrase_with_limits(value, &limits, out)` |

### Behaviour changes

Each fixes a reading two conforming implementations could disagree on, or a wrong answer.

| Call | 0.9 | 0.10 |
|---|---|---|
| `client_address` | read and counted the whole chain, so one junk entry left of the client, 16 padding entries, or an upstream `unknown` failed the call | reads from the right only up to the client: text left of it is never read |
| `parse_content_disposition` | `form-data; filename="a.php"; filename*=UTF-8''a.png` gave `a.png` | refused (`ForbiddenParameter`): RFC 7578 forbids `filename*` in `form-data` |
| `parse_content_disposition` | `filename*0=`, `filename*1*=` were ignored | refused (`ForbiddenParameter`): some clients join them into another name |
| `mail::parse_mime_params` | `name*` beside `name*0` read the continuation | refused (`ForbiddenParameter`) |
| `Filename::has_path_separator` | `filename="..\..\web.config"` was not flagged (it decodes to `....web.config`) | flagged: browsers send `\` literally |
| `parse_response_cache_control` and the other struct readers | one directive that did not parse (`ext=a b`) refused the field, losing a `no-store` beside it | the directive is skipped and `invalid_values` set |
| `parse_host_port`, `parse_origin`, `host::parse_uri_host_port` | `%41.example` and other escapes were accepted and compared raw | any `%` is `InvalidHost` |
| `parse_link` | `rel="pre\load"` was read raw by `rels` and `has_rel` | refused (`InvalidQuotedPair`) |
| `MimeParams::decode_into` | a plain value passed HTAB and C1 controls | refused (`ControlInDecoded`), as every other decoder does |
| `mail::parse_addr_spec` | accepted C1 controls (`a\u{85}b@example.com`) | refused (`InvalidAddrSpec`) |
| `mail::parse_mailbox` | `John\r\n Doe <j@example.com>` failed | read: a fold between words is FWS |
| `mail::encode_words`, `encode_words_base64` | with no room for one character, started with a fold, which read back as a leading space | the first word holds one character and runs past the room |
| `best_media`, `best_language` | the four issue #14 cases | as RFC 9110 and RFC 4647 say (the release notes list them) |

### By consumer

| Crate | What changes |
|---|---|
| ws-net | `parse_net::list(value)` to `parse_net::parse_list(value)`; `parse_host_port` and `parse_uri_host_port` now refuse any `%` in a host |
| web-net | `parse_net::http_date` to `parse_net::parse_http_date`; `if_none_match` and `if_match` take a `Representation`; re-run its negotiation tests (issue #14 changed four answers) |
| smtp-net | `mail::encode_words_b` to `mail::encode_words_base64`; `mail::parse_mailbox(v, &Limits::DEFAULT)` to `mail::parse_mailbox(v)` and `mail::decode_words(v, &Limits::DEFAULT, out)` to `mail::decode_words(v, out)` (or the `_with_limits` forms) |
| form-net | `ExtValue` to `ExtendedValue` (its own `Content-Disposition` reader already refuses both file names, starred parameters, and backslash names) |
| http-net, cookie-net | nothing: `class`, `scan`, `date`, `HttpDate`, and the sinks keep their names |

---

## Moving http-net and ws-net onto parse-net (0.3)

For the maintainers of http-net and ws-net. Each section lists what the crate carries today, the parse-net item that replaces it, and every behaviour that changes. Both migrations were tried against parse-net 0.3.0 on 2026-10-21: the full test suites of both crates passed, and the instruction counts are in [Cost](#cost).

Use parse-net with default features (`no_std`, no allocator):

```toml
[dependencies]
parse-net = { version = "0.3", default-features = false }
```

The manifest's dependency note changes from "no dependencies" to "no third-party dependencies".

---

### http-net

`src/syntax.rs` keeps its internal names, so no call site changes except the list walker. The moved items become re-exports or one-line adapters:

```rust
pub(crate) use parse_net::{
    class::{hex_value, is_qdtext, is_tchar},
    scan::find_byte,
    text::{is_ows, is_token, trim_ows},
};

pub(crate) fn check_field_value(value: &[u8]) -> Result<(), HttpError> {
    match parse_net::scan::check_field_value(value) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == parse_net::ErrorKind::BareCr => Err(HttpError::BareCr),
        Err(_) => Err(HttpError::InvalidHeaderValue),
    }
}

pub(crate) fn is_reason(s: &[u8]) -> bool {
    parse_net::class::all(s, parse_net::class::Class::FIELD_TEXT)
}

pub(crate) fn is_target_chars(s: &[u8]) -> bool {
    parse_net::percent::validate_with(s, parse_net::class::Class::URI_TARGET).is_ok()
}

pub(crate) fn is_host_value(s: &[u8]) -> bool {
    parse_net::host::parse_uri_host_port(s).is_ok()
}

pub(crate) fn parse_decimal(s: &[u8]) -> Option<u64> {
    parse_net::num::parse_u64(s).ok()
}
```

| http-net item | parse-net | Behaviour |
|---|---|---|
| `TCHAR`, `FIELD`, `HEX`, `QDTEXT` table bits, `is_tchar`, `is_qdtext`, `hex_value` | `class::is_tchar`, `class::is_field_text`, `class::is_hexdig`, `class::is_qdtext`, `class::hex_value` | identical for all 256 bytes (tested exhaustively in both crates) |
| `is_token`, `is_ows`, `trim_ows` | `text::is_token`, `text::is_ows`, `text::trim_ows` | identical; VT and FF are still never stripped |
| `check_field_value` | `scan::check_field_value` | identical accept set (every byte at every position of a 17-byte value, tested); the error kinds are finer (`BareCr`, `LineFeed`, `Nul`, `Control`) and map onto http-net's two errors as above |
| `is_reason` | `class::all(s, Class::FIELD_TEXT)` | identical |
| `is_target_chars` | `percent::validate_with(s, Class::URI_TARGET)` | identical |
| `parse_decimal` | `num::parse_u64` | identical accept set; returns `Result` |
| `find_byte` | `scan::find_byte` | same SWAR algorithm |
| `is_host_value` | `host::parse_uri_host_port` | **stricter**, see below |
| `list_elements` | `list::for_each`, `parse_list(value)?.iter()`, `list::contains_token` | **refuses malformed lists**, see below |
| `blocking.rs` `parse_http_date`, `two_digits`, `civil_from_days` | `HttpDate::from_unix(secs)?.format()` | identical output for every date from 1970; the full range is years 1 to 9999 |
| `is_protocol`, `push_hex`, `push_decimal`, head scanning, chunk lines, target forms | stay in http-net | RFC 9112 framing and serialization |

#### Use `parse_uri_host_port`, not `parse_host_port`, for targets

`parse_host_port` is a field-value parser: like every parse-net field parser, it strips SP and HTAB around the value. A request target is not a field value. Validating an authority-form or absolute-form target with it would accept `CONNECT  example.com:443` (two spaces), which the request line grammar refuses. `host::parse_uri_host_port` strips nothing and is right for both the `Host` field (already trimmed by http-net's head scanner) and targets. http-net's own `httparse` differential test found this during the trial.

#### `Host` validation is stricter

| Value | Before | After | Why |
|---|---|---|---|
| `example.com:99999` | accepted | refused | a port above 65535 cannot be used, and the WHATWG URL standard refuses it; RFC 3986 grammar alone allows any digits |
| `[zz]`, `[::1::2]` | accepted (the bracket body was only checked for hex digits, `:`, `.`, `v`) | refused | not an IPv6 address |
| `127.1`, `0x7f.0.0.1`, `1.2.3`, `01.2.3.4`, `example.123`, `0` | accepted as names | refused | browsers read these as IPv4 addresses and RFC 3986 reads them as names; refusing removes the disagreement (parse-net HST-4, D-040) |

Every one of these was refused or ambiguous downstream already; no browser sends them. Update `tests/adversarial.rs` (move `example.com:99999` to the refused list) and the independent reference parser in `tests/common/reference.rs` (port at most 65535, IP literals checked with `std::net::Ipv6Addr`, numeric names checked with `std::net::Ipv4Addr`).

#### Lists refuse malformed values

http-net's walker already respected quoted strings ([D-011](../dev/PLAN.md#16-decision-log)); parse-net's also skips commas inside comments, refuses an unterminated quote or an unbalanced comment instead of running to the end of the value, and bounds empty elements (16 by default). Map the error per field:

| Field | On a malformed list |
|---|---|
| `Transfer-Encoding` | `HttpError::InvalidTransferEncoding` |
| `Connection`, `Upgrade`, `Expect` | `HttpError::InvalidHeaderValue` |

Use `list::for_each` where the elements are only scanned once (all four fields in `scan_fields`): it validates and visits in one pass, which is what keeps `request_head` within its budget. The list change refuses messages that were accepted before, all of them invalid HTTP: a `Connection`, `Upgrade`, or `Expect` value with an unterminated quoted string, an unbalanced comment, or more than 16 empty elements (for example `Connection: keep-alive, "x`). For `Transfer-Encoding` nothing changes in practice: a value with an unterminated quote or a parameter on `chunked` was already refused by the transfer-coding rules.

Record both changes in http-net's CHANGELOG as fixes of latent parser differentials.

---

### ws-net

| ws-net item | parse-net | Behaviour |
|---|---|---|
| `head.rs` `is_token`, `trim_ows` | `text::is_token`, `text::trim_ows` (re-exported) | identical |
| `head.rs` `is_visible` | `!s.is_empty() && class::all(s, Class::VCHAR)` | identical |
| `head.rs` `is_control` (field values, reason phrase) | `scan::check_field_value(s).is_err()` | identical accept set |
| `handshake.rs` `list` | `parse_list(value)` (a `Result`) | commas inside quoted strings no longer split; a malformed `Sec-WebSocket-Protocol` is `HandshakeError::InvalidProtocol`; a malformed `Sec-WebSocket-Extensions` in a response is treated as an offered extension and refused (fail closed) |
| `handshake.rs` `list_has` | `list::contains_token([value], token)` | a malformed line counts as not containing the token (fail closed) |
| `Sec-WebSocket-Extensions` with parameters (RFC 6455 section 9.1) | `list` and then `param::parse` on each element | newly readable when ws-net adds extension support |
| `base64.rs`, `sha1.rs` | not parse-net | encode-lib and crypt-io |

---

### Cost

NFR-8 requires each consumer's benchmarks to stay within 5% after the move. Wall-clock timing on the development machines varied by up to 15% between identical runs, more than the margin being measured, so the gate was measured as instructions per iteration with callgrind (valgrind 3.22, WSL Ubuntu, release profile), which is exact and repeatable. The workloads are the bodies of the crates' own criterion benchmarks.

| Workload | Before | After | Change |
|---|---|---|---|
| http-net `request_head` (browser GET, 12 fields, answered) | 8,569 | 8,905 | +3.9% |
| http-net `response_write` (5 fields, 1 KiB body) | 2,335 | 2,345 | +0.4% |
| http-net `response_parse` (client, 1 KiB body) | 2,972 | 2,974 | +0.1% |
| ws-net `handshake/from_head` (browser upgrade request and response) | 43,348 | 33,261 | -23.3% |

The http-net increase is the work that was not done before: the list walker now validates quoting and comments, and `Host` now validates IP literals and port ranges. Both are inside the budget. ws-net got faster because its token and visible-character checks were byte comparisons against a list, and parse-net's are one table lookup per byte.
