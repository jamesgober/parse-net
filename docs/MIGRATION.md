# Moving http-net and ws-net onto parse-net

For the maintainers of http-net and ws-net. Each section lists what the crate carries today, the parse-net item that replaces it, and every behaviour that changes. Both migrations were tried against parse-net 0.3.0 on 2026-10-21: the full test suites of both crates passed, and the instruction counts are in [Cost](#cost).

Use parse-net with default features (`no_std`, no allocator):

```toml
[dependencies]
parse-net = { version = "0.3", default-features = false }
```

The manifest's dependency note changes from "no dependencies" to "no third-party dependencies".

---

## http-net

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
    parse_net::pct::validate_with(s, parse_net::class::Class::URI_TARGET).is_ok()
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
| `is_target_chars` | `pct::validate_with(s, Class::URI_TARGET)` | identical |
| `parse_decimal` | `num::parse_u64` | identical accept set; returns `Result` |
| `find_byte` | `scan::find_byte` | same SWAR algorithm |
| `is_host_value` | `host::parse_uri_host_port` | **stricter**, see below |
| `list_elements` | `list::for_each`, `list(value)?.iter()`, `list::contains_token` | **refuses malformed lists**, see below |
| `blocking.rs` `http_date`, `two_digits`, `civil_from_days` | `HttpDate::from_unix(secs)?.format()` | identical output for every date from 1970; the full range is years 1 to 9999 |
| `is_protocol`, `push_hex`, `push_decimal`, head scanning, chunk lines, target forms | stay in http-net | RFC 9112 framing and serialization |

### Use `parse_uri_host_port`, not `parse_host_port`, for targets

`parse_host_port` is a field-value parser: like every parse-net field parser, it strips SP and HTAB around the value. A request target is not a field value. Validating an authority-form or absolute-form target with it would accept `CONNECT  example.com:443` (two spaces), which the request line grammar refuses. `host::parse_uri_host_port` strips nothing and is right for both the `Host` field (already trimmed by http-net's head scanner) and targets. http-net's own `httparse` differential test found this during the trial.

### `Host` validation is stricter

| Value | Before | After | Why |
|---|---|---|---|
| `example.com:99999` | accepted | refused | a port above 65535 cannot be used, and the WHATWG URL standard refuses it; RFC 3986 grammar alone allows any digits |
| `[zz]`, `[::1::2]` | accepted (the bracket body was only checked for hex digits, `:`, `.`, `v`) | refused | not an IPv6 address |
| `127.1`, `0x7f.0.0.1`, `1.2.3`, `01.2.3.4`, `example.123`, `0` | accepted as names | refused | browsers read these as IPv4 addresses and RFC 3986 reads them as names; refusing removes the disagreement (parse-net HST-4, D-040) |

Every one of these was refused or ambiguous downstream already; no browser sends them. Update `tests/adversarial.rs` (move `example.com:99999` to the refused list) and the independent reference parser in `tests/common/reference.rs` (port at most 65535, IP literals checked with `std::net::Ipv6Addr`, numeric names checked with `std::net::Ipv4Addr`).

### Lists refuse malformed values

http-net's walker already respected quoted strings ([D-011](../dev/PLAN.md#16-decision-log)); parse-net's also skips commas inside comments, refuses an unterminated quote or an unbalanced comment instead of running to the end of the value, and bounds empty elements (16 by default). Map the error per field:

| Field | On a malformed list |
|---|---|
| `Transfer-Encoding` | `HttpError::InvalidTransferEncoding` |
| `Connection`, `Upgrade`, `Expect` | `HttpError::InvalidHeaderValue` |

Use `list::for_each` where the elements are only scanned once (all four fields in `scan_fields`): it validates and visits in one pass, which is what keeps `request_head` within its budget. The list change refuses messages that were accepted before, all of them invalid HTTP: a `Connection`, `Upgrade`, or `Expect` value with an unterminated quoted string, an unbalanced comment, or more than 16 empty elements (for example `Connection: keep-alive, "x`). For `Transfer-Encoding` nothing changes in practice: a value with an unterminated quote or a parameter on `chunked` was already refused by the transfer-coding rules.

Record both changes in http-net's CHANGELOG as fixes of latent parser differentials.

---

## ws-net

| ws-net item | parse-net | Behaviour |
|---|---|---|
| `head.rs` `is_token`, `trim_ows` | `text::is_token`, `text::trim_ows` (re-exported) | identical |
| `head.rs` `is_visible` | `!s.is_empty() && class::all(s, Class::VCHAR)` | identical |
| `head.rs` `is_control` (field values, reason phrase) | `scan::check_field_value(s).is_err()` | identical accept set |
| `handshake.rs` `list` | `list(value)` (a `Result`) | commas inside quoted strings no longer split; a malformed `Sec-WebSocket-Protocol` is `HandshakeError::InvalidProtocol`; a malformed `Sec-WebSocket-Extensions` in a response is treated as an offered extension and refused (fail closed) |
| `handshake.rs` `list_has` | `list::contains_token([value], token)` | a malformed line counts as not containing the token (fail closed) |
| `Sec-WebSocket-Extensions` with parameters (RFC 6455 section 9.1) | `list` and then `param::parse` on each element | newly readable when ws-net adds extension support |
| `base64.rs`, `sha1.rs` | not parse-net | encode-lib and crypt-io |

---

## Cost

NFR-8 requires each consumer's benchmarks to stay within 5% after the move. Wall-clock timing on the development machines varied by up to 15% between identical runs, more than the margin being measured, so the gate was measured as instructions per iteration with callgrind (valgrind 3.22, WSL Ubuntu, release profile), which is exact and repeatable. The workloads are the bodies of the crates' own criterion benchmarks.

| Workload | Before | After | Change |
|---|---|---|---|
| http-net `request_head` (browser GET, 12 fields, answered) | 8,569 | 8,905 | +3.9% |
| http-net `response_write` (5 fields, 1 KiB body) | 2,335 | 2,345 | +0.4% |
| http-net `response_parse` (client, 1 KiB body) | 2,972 | 2,974 | +0.1% |
| ws-net `handshake/from_head` (browser upgrade request and response) | 43,348 | 33,261 | -23.3% |

The http-net increase is the work that was not done before: the list walker now validates quoting and comments, and `Host` now validates IP literals and port ranges. Both are inside the budget. ws-net got faster because its token and visible-character checks were byte comparisons against a list, and parse-net's are one table lookup per byte.
