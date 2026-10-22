# Architecture

How parse-net is built: the rules every module follows, the modules and how
they depend on each other, the byte-class table, the views and their sizes,
and the algorithms that are not obvious from the grammar. For each field's
grammar see [GRAMMAR.md](GRAMMAR.md); for the API see [API.md](API.md).

## Rules

1. **Validate, then view.** Every parser checks the whole value in one
   forward pass and returns a small `Copy` view over the input. Iterators on
   a view walk text already proven valid, so they yield items, never
   `Result`s. A field is accepted or refused as a whole.
2. **Zero-copy.** Views hold `&[u8]` slices of the caller's bytes. Decoded
   forms (unescaped quoted strings, percent-decoded values, encoded words,
   RFC 2231 continuations) are written into a caller buffer by `*_into`
   functions, which size the output in a first pass and write nothing on
   error, or compared in place without decoding.
3. **No allocation, no recursion, no floating point.** Nesting (comments) is
   counted, never recursed; Structured Field inner lists cannot nest, so that
   parser is a loop. Quality values are thousandths in a `u16`; Structured
   Field decimals are thousandths in an `i64`. Only the owned forms, behind
   the `alloc` feature, allocate, once per value.
4. **Strict by default, lenient only where the RFC says recipients should
   be.** Each leniency is named in GRAMMAR.md with the sentence that asks for
   it.
5. **Bytes, not strings.** Field values may hold `obs-text`, so inputs and
   views are `&[u8]`; views offer `as_str` or `decode_into` for UTF-8, never
   a lossy conversion.
6. **Writers cannot produce what parsers refuse.** Every writer validates as
   it writes, refuses a forbidden byte with its offset, and reserves its room
   first, so a `SliceSink` never holds half a value. Property tests and fuzz
   targets check that what a writer writes parses back to the same value.
7. **Errors carry a position, never content.** A `ParseError` is 8 bytes:
   a kind, a field-line index, and a byte offset. `Display` prints a fixed
   message and the offset; no input byte is ever formatted.
8. **One table.** Every byte class is a bit in one 256-entry `u32` table,
   built at compile time, so classifying a byte is one load and one mask.

## Modules

```
src/
  lib.rs            crate documentation, root re-exports, VERSION
  class.rs          the byte-class table and the is_* predicates
  scan.rs           SWAR search and field-value validation
  error.rs          ParseError, ErrorKind, WriteError, Full
  limits.rs         Limits, DuplicatePolicy
  utf8.rs           an incremental UTF-8 validator (internal)
  write.rs          Sink, SliceSink, CountSink, token/quoted/number writers
  num.rs            decimal digits with overflow checks
  text.rs           token, OWS, quoted-string, comment, Word
  list.rs           #rule lists and combined field lines
  param.rs          RFC 9110 parameters
  media.rs          media types, media ranges, boundaries
  negotiate.rs      q-values and Accept-* selection
  date.rs           the calendar and HttpDate
  date/mail_date.rs MailDate (RFC 5322 date-time)
  etag.rs           entity tags and conditions
  range.rs          Range, Content-Range, If-Range
  ext_value.rs      RFC 8187 values
  disposition.rs    Content-Disposition
  cache.rs          Cache-Control
  link.rs           Link
  forwarded.rs      Forwarded, X-Forwarded-*, client-address resolution
  auth.rs           Authorization, WWW-Authenticate
  host.rs           Host
  origin.rs         Origin
  pct.rs            the percent-encoding primitive
  sfv/mod.rs        Structured Field views, Parser, Visitor
  sfv/parse.rs      the RFC 9651 section 4.2 algorithms (internal)
  sfv/write.rs      the canonical writer
  sfv/owned.rs      owned Structured Field values (alloc)
  mail/mod.rs       header values, folding, unfolding
  mail/words.rs     RFC 2047 encoded words
  mail/params.rs    MIME parameters and RFC 2231 continuations
  mail/addr.rs      addr-spec, mailbox, msg-id
  owned.rs          owned media types, entity tags, host-ports (alloc)
```

Every module uses only the shared modules (`class`, `scan`, `error`,
`limits`, `utf8`, `write`, `num`, `text`) plus these field modules:
`disposition` and `link` use `ext_value`; `negotiate` uses `media`;
`forwarded` and `origin` use `host`; `range` uses `date` and `etag`; `mail`
uses `ext_value` and re-exports `MailDate`; `owned` uses the views it owns.
The graph has no cycles.

## The byte-class table

`class.rs` holds one `[u32; 256]` built by a `const fn`; each bit is one
class, and each predicate is one load and one mask. Every class is tested for
all 256 bytes against a slow implementation written from the ABNF.

| Bit | Class | Source |
|---|---|---|
| 0 | `TCHAR` | RFC 9110 section 5.6.2 |
| 1 | `VCHAR` | RFC 5234 |
| 2 | `OBS_TEXT` | RFC 9110 section 5.5 |
| 3 | `FIELD_TEXT` | VCHAR, obs-text, SP, HTAB |
| 4 | `QDTEXT` | RFC 9110 section 5.6.4 |
| 5 | `CTEXT` | RFC 9110 section 5.6.5 |
| 6 | `QUOTED_PAIR` | the byte after `\` |
| 7 | `ETAGC` | RFC 9110 section 8.8.3 |
| 8 | `ATTR_CHAR` | RFC 8187 section 3.2.1 |
| 9 | `MIME_TOKEN` | RFC 2045 section 5.1 (allows `{` and `}`) |
| 10 | `UNRESERVED` | RFC 3986 section 2.3 |
| 11 | `SUB_DELIM` | RFC 3986 section 2.2 |
| 12 | `PCHAR_NO_PCT` | `unreserved / sub-delims / ":" / "@"` |
| 13 | `URI_TARGET` | `pchar / "/" / "?"` and `%` |
| 14 | `HEXDIG` | RFC 5234 |
| 15 | `SF_KEY_START` | RFC 9651 section 3.1.2 |
| 16 | `SF_KEY` | RFC 9651 section 3.1.2 |
| 17 | `SF_TOKEN` | RFC 9651 section 3.3.4 |
| 18 | `SF_STRING` | RFC 9651 section 3.3.3 |
| 19 | `TOKEN68` | RFC 9110 section 11.2 |
| 20 | `BASE64` | RFC 4648 section 4 |
| 21 | `ATEXT` | RFC 5322 section 3.2.3 |
| 22 | `BCHAR_NOSPACE` | RFC 2046 section 5.1.1 |
| 23 | `COOKIE_OCTET` | RFC 6265bis section 4.1.1, for cookie-net |
| 24 | `AV_OCTET` | RFC 6265bis, for cookie-net |
| 25 | reserved | |
| 26 | `LIST_PLAIN` (internal) | field text that is not `,`, `"`, `(`, `)`: lets the list walker classify a byte in one lookup (D-045) |

## Views and their sizes

All views are `Copy`, `Send`, `Sync`, and `Unpin`; the sizes below (64-bit
targets) are pinned by `tests/types.rs`, so a change that grows a view is
noticed.

| View | Holds | Bytes |
|---|---|---|
| `ParseError` | kind (`u8`), field line (`u8`), offset (`u32`) | 8 |
| `Quoted`, `Word` | the content between the quotes, a quoted-pair flag | 24 |
| `Params`, `List` | the validated text, a member count, a policy | 24 |
| `MediaType` | type, subtype, `Params` | 56 |
| `HttpDate` | seconds since the epoch | 8 |
| `MailDate` | UTC seconds, offset minutes, two flags | 16 |
| `EntityTag` | a weak flag and the opaque slice | 24 |
| `ByteRange` | first and last byte | 16 |
| `ExtValue` | charset, language, encoded text | 40 |
| `ContentDisposition` | type and `Params` | 48 |
| `HostPort` | host, port, empty-port flag | 32 |
| `Origin` | scheme, host, port | 48 |
| `Credentials` | scheme and payload | 48 |
| `LinkValue` | target and parameter text | 40 |
| `mail::AddrSpec` | local part and domain | 48 |
| `sfv::BareItem` | the largest variant: a slice and a flag | 24 |
| `sfv::Item` | bare item and parameter text | 48 |
| `sfv::Member` | item or inner list | 56 |
| `sfv::List`, `sfv::Dictionary` | the validated text and a count | 24 |

## Algorithms

### Quoted strings

The parser scans `QDTEXT` bytes for the closing `"`, skipping the byte after
each `\` (which must be `QUOTED_PAIR`), and records whether it saw a `\`.
Without one, `as_plain` returns the raw content, so most values need no copy.
`unescape_into` writes the value with each pair replaced by its second byte
(RFC 9110 section 5.6.4); `eq_bytes` and `eq_ignore_ascii_case` compare the
unescaped value against a needle without a buffer. A token and a quoted
string with the same content compare equal (section 5.6.6).

### Lists and combined field lines

The list walker makes one pass with one table lookup per ordinary byte. A
comma ends an element only outside quoted strings and comments. Empty
elements are skipped up to `Limits::max_empty_elements` (16 by default);
one more is an error. Several field lines are read as one list, as if joined
by `, `, without copying; an element never spans two lines. The walker also
records whether a value had no quoted string or comment, so the element
iterator can then split on commas alone (D-045). `Link` has its own walker,
because a comma inside `<...>` does not split.

### Scanning

`scan::find_byte`, `find_either`, and `check_field_value` read eight bytes at
a time in a `u64` (SWAR) with no `unsafe`: a byte equal to the needle, or a
byte below 0x20 other than HTAB, or 0x7F, is found with the usual
has-zero-byte arithmetic, then located exactly. Property tests prove each
equal to its bytewise definition.

### Content negotiation

Each media range has a specificity: an exact type with parameters 4, an exact
type 3, `type/*` 2, `*/*` 1. An offer's weight is the q-value of the most
specific range that matches it; `q=0` means not acceptable; ties go to the
earlier offer (the server's preference). Offers are scored in groups of 32
per pass over the header, so the work is bounded by the member limit times
the number of offers. An absent header gives every offer weight 1; a header
that does not parse is treated as absent and reported as
`Outcome::HeaderIgnored`, or refused with `MalformedPolicy::Refuse`.
`Accept-Language` uses RFC 4647 lookup (truncate the range from the right)
or basic filtering (prefix on a `-` boundary). `Accept-Encoding` keeps
`identity` acceptable unless `identity;q=0`, or `*;q=0` without an explicit
`identity`.

### Dates

The calendar is Howard Hinnant's `days_from_civil` and `civil_from_days` over
`i64` days, valid for years 1 to 9999. IMF-fixdate is 29 bytes parsed by
position. RFC 850 two-digit years are resolved against a `now` the caller
passes (`http_date_at`), or the system clock with `std` (`http_date`): a date
more than 50 years ahead is taken as the most recent past year with the same
last two digits (D-039). Formatting writes into a `[u8; 29]` (HTTP) or
`[u8; 31]` (mail) by table lookup. `MailDate` parses RFC 5322 `date-time`
with CFWS between the tokens and keeps the zone offset; the obsolete forms of
section 4.3 are read only when asked for.

### Structured Fields

The parser implements RFC 9651 section 4.2 over a cursor, as plain functions
with an events trait (`Events`) so the same code drives the views (which
discard events), the public `Visitor`, and validation. Inner lists cannot
nest, so the depth is at most two and nothing recurses. Display Strings are
UTF-8 validated during the parse by the incremental validator, so no buffer
is needed. Views store the validated text and re-walk it with relaxed limits,
so an iterator never fails. `Dictionary::get` returns the last value for a
key; `index_into` fills a caller array with one slot per distinct key.

The writer is a small state machine (empty, after a member, after a key,
inside an inner list, after an inner item, and a pending parameter key) that
refuses out-of-order calls with `InvalidSequence`. It writes the canonical
form of section 4.1: decimals with the shortest fraction, strings with only
`\"` and `\\`, byte sequences padded with zero pad bits, Display Strings with
lowercase `%xx` for exactly the bytes that need it, and a dictionary member
whose value is Boolean true as its key alone.

### Trusted-proxy resolution

```
 1 peer not trusted                    -> ClientAddress::Peer(peer); the header is not read
 2 parse the whole chain (all lines)   -> malformed anywhere -> error: use the peer
 3 more than max_hops elements         -> TooManyHops
 4 walk from the rightmost element:
     an address, trusted               -> continue
     an address, not trusted           -> ClientAddress::Forwarded { addr, hops }
     unknown, obfuscated, or no for=   -> ClientAddress::Unknown { hops }
 5 every element trusted               -> ClientAddress::Forwarded { leftmost, hops }
```

The deployment chooses `Forwarded` or `X-Forwarded-For`; the two are never
merged, because two proxies could order them differently.
`client_address_detailed` reports whether the other kind was also present, a
likely spoofing attempt.

### `WWW-Authenticate`

The field is `#challenge`, and a challenge's parameters are comma-separated
too, so the parser decides at each element whether it starts a new challenge:
`token 1*SP` then something other than `token BWS "="` starts one (with a
token68 or with parameters); `token BWS "="` continues the current one. A
token68 ends at `,` or the end and keeps its `=` padding. A parameter name
repeated within a challenge is refused (RFC 9110 section 11.2).

### Ranges

`resolve` turns suffix ranges into absolute ones, clamps a last position past
the end, drops a range that starts past the end, and reports `Unsatisfiable`
when nothing is left. More than `Limits::max_ranges` ranges (16 by default),
more than two overlapping ranges, or more than two ranges out of order give
`RangeOutcome::Ignore`: serve the whole representation, as RFC 9110 section
14.2 allows. Overlaps are coalesced only on request, since coalescing changes
the multipart shape. The output goes into a caller array.

### RFC 2231 continuations without allocation

`filename*0*=UTF-8''a%20b; filename*1=".txt"` is validated at parse time and
decoded on request: the sections of a name are placed in a 32-slot stack
array by number in one pass over the parameters, checked to run from 0 with
no gap (duplicates are refused as duplicate parameters, and a section number
at or above `Limits::max_rfc2231_sections` is `TooManySections`), then
decoded in order, `%XX` in extended sections, with the charset of section 0
(UTF-8, US-ASCII, or ISO-8859-1 transcoded). The decoder runs twice: once to
validate and size, once to write.

### Encoded words

`decode_words` walks unstructured text once to size and validate, once to
write. An encoded word is recognized only when it stands between whitespace
(or the start or end) and has the full `=?charset?enc?text?=` shape;
otherwise the bytes are ordinary text. Whitespace after an encoded word is
held back until the next token shows whether it is another encoded word
(then the whitespace is dropped, RFC 2047 section 6.2). Each word must hold
whole UTF-8 characters. `encode_words` splits only between characters and
keeps each word within 75 bytes.

### Writers and sinks

```rust
pub trait Sink {
    fn put(&mut self, bytes: &[u8]) -> Result<(), Full>;
    fn remaining(&self) -> Option<usize> { None }
}
```

`SliceSink` writes into a caller array and reports its room; `CountSink`
counts and writes nothing; `Vec<u8>` (with `alloc`) grows. Writers that build
a value from parts write it once into a `CountSink`, check the room with
`remaining`, then write it for real, so a `SliceSink` is never left holding
half a value. Structured writers (`sfv::Writer`, `cache::Writer`) reserve per
call.

## Features

| Feature | Default | Adds |
|---|---|---|
| (none) | yes | everything not listed below; `no_std`, no allocator |
| `alloc` | no | the owned forms, `Sink for Vec<u8>` |
| `std` | no | `HttpDate` to and from `SystemTime`, `HttpDate::now`, `http_date`; implies `alloc` |
| `encode-lib` | no | declared and empty until encode-lib is published; base64 decoding then moves here (D-002) |

`core::error::Error` is implemented without `std`.

## Bounds

Every bound is checked before the work it governs, and none allocates; they
bound loops. The defaults meet every RFC 9651 minimum.

| Bound | Default |
|---|---|
| list members | 1024 |
| inner-list members | 256 |
| parameters per item or field | 256 (RFC 9110 parameters under `Refuse`: 64, D-072) |
| dictionary members | 1024 |
| key length | 256 |
| string length (decoded) | 1024 |
| token length | 512 |
| byte-sequence length (decoded) | 16384 |
| empty list elements | 16 |
| comment depth | 8 |
| ranges | 16 |
| RFC 2231 sections | 32 |
| encoded words per field | 64 |
| forwarded hops | 16 |
