<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>CHANGELOG</b>
</h1>
<p>
  All notable changes to <code>parse-net</code> will be documented in this file. The format is based on <a href="https://keepachangelog.com/en/1.1.0/">Keep a Changelog</a>,
  and this project adheres to <a href="https://semver.org/spec/v2.0.0.html/">Semantic Versioning</a>.
</p>

---

## [Unreleased]

---

## [0.9.3] - 2026-11-08

Fixes from a review of the code added since 0.9.0, and a faster
`Cache-Control` reader. No call changes its signature.

### Fixed

- `mail::decode_phrase` decoded an encoded word with a comment or a quoted
  string right before it: `(c)=?UTF-8?Q?a?=` read as `a`, and
  `"x"=?UTF-8?Q?a?=` as `x a`. RFC 2047 section 5 wants whitespace on both
  sides of an encoded word in a phrase, and 0.9.2 checked only the side
  after it. Both are now text, as the mirror cases were (D-084).
- `mail::write_mime_param_at` with a room past 78 could put a whole value on
  the first line, past 78 columns, and past 998 bytes for a long one. A room
  past 78 is now read as 78, as `encode_words` caps its own (D-084).

### Changed

- `response_cache_control` and `request_cache_control` compare directive
  names as two or three words instead of byte by byte: 881 to 823
  instructions (-6.6%) for `public, max-age=31536000, immutable`.

### Documentation

- `decode_phrase`: folds are read between words and inside comments; a
  quoted string must be unfolded first (`mail::unfold`), as for
  `parse_mime_params` (D-078). An empty word, `""` or an encoded word with no
  text, counts as a word.
- The question left open for web-net, whether `Strict-Transport-Security`
  needs the optional-parameter shape without a leading `;`, is closed:
  web-net writes HSTS and reads none, and its grammar stays PN-18 for 1.x
  (D-083).

---

## [0.9.2] - 2026-11-07

Two additions smtp-net asked for while adopting 0.9.1, and faster MIME
parameter writing. No 0.9.1 call changes its signature or its output.

### Added

- `mail::decode_phrase`: the text of a `phrase` (RFC 5322 section 3.2.5),
  such as the display name `parse_mailbox` returns raw. Comments are
  dropped, quoted strings lose their quotes and their quoted pairs are
  unescaped, and the words are joined by one space; RFC 2047 encoded words
  are decoded where section 5 allows them in a phrase, a whole atom between
  whitespace, and two of them with only whitespace between are joined with
  none (section 6.2). The text meets `decode_words`' rules: UTF-8, no control
  character but HTAB, C1 included. For smtp-net and gate-net (D-081).
- `mail::write_mime_param_at(name, value, room_first_line, out)`:
  `write_mime_param` for a parameter that does not start a line. A one-line
  form that does not fit in the room goes on a new line, `;CRLF name=value`,
  before the value is split into sections, and the call returns the columns
  left on its last line, so parameters chain. With a room of 78 it writes
  what `write_mime_param` writes (D-082).
- Fuzz target `mail_phrase` (38 targets): plain phrases read back as their
  words, any text through a quoted string reads back unchanged, and every
  display name `parse_mailbox` accepts decodes or fails with a listed error;
  `mime_params` now writes mid-line too and checks the room returned.
  Property tests for both functions, threat cases for display names, complexity cases,
  counting-allocator coverage, and benchmark rows.

### Performance

- `write_mime_param` on a quoted value: 30% fewer instructions (3,271 to
  2,292), from writing the runs between escapes whole and checking an ASCII
  value's controls a byte at a time; 5.5% on an extended value.
- `decode_words` on `Q` words: 3% fewer instructions (5,462 to 5,295), from
  writing runs of plain bytes whole.

### Notes

- `class::is_atext`, which smtp-net asked for, has been public since 0.5;
  nothing changed.
- The `list` fuzz target found its split point by parsing the value up to
  every comma, which is quadratic on a comment that holds many escaped
  commas: one 3.5 KB input took 130 ms a run. It now finds the commas
  outside quotes and comments in one pass (1.5 ms on that input). The
  library took 10 microseconds on it; only the harness changed.

---

## [0.9.1] - 2026-11-05

Two additions consumers asked for while adopting 0.9.0. No 0.9.0 call
changes its signature; `decode_words` now reads `B` words it refused.

### Added

- `param::parse_optional`, with `OptionalParams` and `OptionalParam`: RFC
  6455 section 9.1 extension parameters, whose value may be left out.
  permessage-deflate (RFC 7692) sends `client_max_window_bits` and
  `server_no_context_takeover` that way, and `param::parse` refuses them with
  `MissingValue`. Every other rule is `param::parse`'s: empty parameters,
  bytes used, no whitespace around `=`, the duplicate policy, and the
  64-name limit under `Refuse`. `find` returns the parameter, so its `value`
  tells a bare name from one with a value; `contains` asks whether it is
  there. Found by ws-net adopting 0.9.0 (D-079).
- `mail::encode_words_b`: RFC 2047 `B` encoded words, `=?UTF-8?B?...?=`, of
  at most 75 bytes, split only between characters, folded as
  `encode_words` folds. For text that is mostly not ASCII it is the shorter
  form: a Japanese subject is one 64-byte word against two words, 144 bytes,
  in `Q`. For smtp-net (D-080).
- Fuzz targets `param_optional`, `mail_words_b`, and `diff_b64` (against the
  `base64` crate's canonical engine; 37 targets, four differential, the
  weekly workflow runs it); property tests against a plain reference reader,
  against `param::parse`, and for the `B` round trip; complexity cases for
  bare names and `B` words; counting-allocator coverage; benchmark rows.

### Changed

- `mail::decode_words` reads `B` words, which it refused with
  `InvalidEncodedWord`: a widening, allowed in a 0.9.x patch. The base64 is
  strict, so every byte string has one encoding: whole groups of four, `=`
  only as the last one or two characters with zero bits under it, nothing
  outside the alphabet, no whitespace inside the word, and at most 75 bytes
  to a word. Every decoded byte meets the Q rules: no control character (C0,
  DEL, C1), whole UTF-8 characters, ASCII for US-ASCII. A word that breaks
  one is `InvalidEncodedWord`, `ControlInDecoded`, or `InvalidUtf8`, at the
  group of four that holds it.
- The base64 is a private codec for one word at a time, with no public API:
  this reverses D-002 for `B` words, decided for smtp-net and ws-net and
  recorded for James (D-080, `dev/READINESS-1.0.md`). The `encode-lib`
  feature stays, as a documented no-op, so builds that name it keep working;
  `basic_decode_into`, `ByteSeq::decode_into`, and `sfv::Writer::bytes` still
  wait for encode-lib.

### Performance

- A full benchmark run on a quiet machine, the first since 0.7: every row is
  25% to 81% faster than its competitor, and both estimates are met
  (`client_address` 37.6 ns against 60, `encode_words` 176 ns against 200).
  `response_cache_control` reads 25% (33% on the loaded 0.9.0 run).
- `decode_words` on one `B` word is 61% faster than `mailparse` (145 ns
  against 373 ns): a clean word goes out in one piece.
- `param::parse` and the Q paths stay within 1.5% of 0.9.0 in instructions,
  the size of the moves code layout makes in unchanged functions.

---

## [0.9.0] - 2026-11-03

Beta: the pre-1.0 polish pass. Three independent reviews of the whole crate
found 46 defects; all are fixed, each with a regression test. `0.9.0` refuses
some inputs that `0.8.0` accepted, and accepts some it refused.

### Security

- `write_element` quotes every host that is not a token: a `Host` holding a
  comma or a semicolon, legal in a reg-name, forged a `Forwarded` hop or pair
  that the next proxy read.
- `Host`, `Origin`, and `write_element` refuse bytes no parsed value holds, so
  their public fields cannot carry CR, LF, or NUL through a writer.
- The numeric-name rule (D-040) reads percent-decoded bytes: `127.0.0.%31` and
  `127%2e1` passed as names, and a browser reads them as addresses.
- `decode_words` refuses raw controls in its text, and is linear: failed
  candidates each scanned to the end of the value, 62 seconds for 1 MiB.
- RFC 2231 continuations refuse C1 controls, across sections too, and a
  section given twice, whose value depended on the parameters' order.
- A malformed `max-stale` no longer reads as any staleness.
- `Debug` of a bare credential hides it (it may be a key sent without a
  scheme), and `OwnedMediaType`'s `Debug` hides parameter values.
- `check_header_value`, `fold`, and `pct::encode` refuse or encode every
  control but HTAB (D-078).

### Added

- `range::parse_if_range_at`: `If-Range` in all three date forms; without a
  clock, `parse_if_range` reads IMF-fixdate and asctime (D-035).
- `forwarded::Proto::{Ws, Wss, Other}`: `proto` takes any URI scheme, where
  `proto=wss` failed whole chains closed (D-077).
- `dev/READINESS-1.0.md`: what stands between parse-net and 1.0.

### Changed

- `byte_ranges` reads the one-range shape by position (815 to 197
  instructions); `client_address` decides and validates in one pass (3,193 to
  1,289); the repeated-name table zeroes nothing for short lists;
  `Content-Disposition` stops revalidating `filename*` (D-074). Every compared
  row is at least 30% faster than its competitor.
- Numerals past `u64::MAX` in `Range` saturate (RFC 9110 section 14.1.2,
  D-075); a non-zero suffix on an empty representation is `Ignore`, not 416.
- `*` stands alone in `If-Match` and `If-None-Match`.
- `Negotiator` refuses what the fields' grammar forbids (`language-range`,
  parameters other than `q`), never chooses an invalid offer, and places
  `Refused` errors by line and offset (D-076).
- Control bytes keep their kind in ranges, entity tags, and after a backslash
  (D-037); `InvalidQuotedPair` is now for grammars that allow no such pair.
- `for=UNKNOWN` reads as `unknown`; a repeated pair of any name in a
  `Forwarded` element is refused.
- `Link` reads a quoted `title*` and ignores `title*` after the first;
  `write_link` and `write_challenge` refuse what their parsers would.
- Leading empty list elements are read in credentials and challenges.
- `Cache-Control` budgets span field lines, and a trailing comma counts as an
  empty element, in `Cache-Control`, entity-tag lists, and ranges.
- `fold` folds after the colon and splits long whitespace runs, so values that
  fit are no longer refused; `write_mime_param`, `write_msg_id`, and
  `encode_words` keep the 998-byte line limit.
- `decode_words` reads folds as whitespace, treats a lone `"` as text, and
  never errors on what does not stand alone as an encoded word.
- `parse_mailbox` reads comments around an angle address; comments in mail
  fields may fold. RFC 2231 section numbers past three digits count, values
  keep `{` and `}`, and US-ASCII holds in every section.
- Display String triples count toward `max_string_len`; `civil_from_days`
  clamps to real dates; many error offsets now point at the failure; refusals
  in `decode_words` and `MimeParams::decode_into` write nothing.

### Testing

- `tests/review_core.rs`, `tests/review_security.rs`, `tests/review_mail.rs`:
  a regression for each finding.
- Property tests: the one-pass `client_address`, `xff_member`, and the
  `byte_ranges` path against the code they replaced; no host can forge a
  `Forwarded` pair through `write_element`.
- `tests/complexity.rs` gains the adversarial `decode_words` shapes, and its
  time bound on an optimised build is 2.0 of the size ratio (D-073).

---

## [0.8.0] - 2026-10-29

Alpha: parse-net in use by published consumers. http-net 0.8.0 and 0.9.0
depend on parse-net 0.7, cookie-net 0.3.0 to 0.7.0 and form-net 0.3.0 to
0.5.0 on 0.6.1, all with green CI; none has an API change open. No API
change.

### Changed

- The complexity tests check timing on an optimised build only (the CI job
  `Complexity (release)`, at the 1.2 bound); an unoptimised build checks the
  limit errors and prints the times. The 2.0 bound for debug builds failed
  on a macOS runner on a single-loop walker (D-073).
- The weekly differential fuzz workflow builds for
  `x86_64-unknown-linux-gnu`: the installed cargo-fuzz is a musl build and
  defaulted to its own target, where the address sanitizer cannot link.

---

## [0.7.0] - 2026-10-24

Hardening: every walker checked against adversarial input, every threat
tested, every fuzz target run for 24 hours.

### Added

- `param::MAX_CHECKED_PARAMS` (64): the most parameters one element may have
  where repeated names are refused (D-072).
- `tests/threats.rs`: an attack test for each row of the threat table that
  had none, and where the others live.
- `tests/complexity.rs`: every walker fed 1 KiB, 64 KiB, and 1 MiB of
  adversarial input; the default limits give the expected limit error, and
  with every limit raised the time grows with the input, within 1.2 of the
  size ratio in a release build (a CI job) and 2.0 in a debug build (D-073).
- `docs/SECURITY.md` (the threat model, tests, costs, reporting) and
  `docs/PLATFORM-NOTES.md` (features, `no_std`, stack use).
- A weekly CI workflow runs the differential fuzz targets for 30 minutes
  each (`.github/workflows/fuzz.yml`).

### Changed

- The repeated-name check of RFC 9110 parameters under
  `DuplicatePolicy::Refuse`, authentication parameters, and MIME parameters
  compares names from a table of up to 64 offsets on the stack. It read every
  earlier parameter again, so a field of many parameters cost the square of
  its length: 8.8 seconds for 1 MiB with `max_params` raised, and about 100
  times a normal parse at the default limits. Those lists now hold at most
  64 parameters per element; `max_params` keeps its default of 256 for
  Structured Fields (D-072).
- `decode_words` refuses every decoded control character (C0 including
  HTAB, DEL, C1), as ext-values do; it refused only CR, LF, and NUL, so an
  encoded ESC reached the decoded text (D-071).
- `param::parse` walks a shrinking slice; `Params::get` and the parameter
  iterator read validated text without validating it again;
  `parse_u32_saturating` reads up to nine digits without saturating steps.
  `parse_media_type` with `charset` went from 32.0 ns to 26.1 ns (30% faster
  than `mime`) and `response_cache_control` from 47.8 ns to 41.2 ns (31%
  faster than `headers`), so every compared row meets the 20% target
  (D-069).
- The `homepage` key, which repeated `repository`, is gone from the
  manifest.

### Fixed

- `mail::fold` wrote whitespace that ends a value past the 998-byte line
  limit when the last word filled the line (a 989-byte word and a TAB after
  `Subject: ` made 999 bytes). It is refused with `OutOfRange`, like a word
  that does not fit: a fold before it would leave a line of only
  whitespace. Found by the 24-hour fuzz run.

### Testing

- Property tests compare the new parameter walker with the 0.6 walker
  (kept as a test-only reference), `Params::get` and the iterator with the
  checked word parser, and `parse_u32_saturating` with exact arithmetic. One
  found a bug in a draft of the new `get` before it shipped: a name could
  match across an empty parameter (`;;a=""` and `;a`).
- The `pct_decode` and `sfv_roundtrip` fuzz targets check every error they
  see, and every fuzz target now checks that an error prints exactly its
  kind's message and position.

---

## [0.6.1] - 2026-10-22

### Fixed

- `parse_condition`, `if_none_match`, and `if_match` counted the comma after
  each entity tag as an empty list element, so a list of more than 16 tags
  was refused with `TooManyEmptyElements`. The one-pass walker of 0.6.0 left
  the separator for its next pass to read. A unit test now reads lists of 17,
  100, and 1024 tags, and a property test compares the walker with the
  general list walker on long lists.

---

## [0.6.0] - 2026-10-22

Optimisation: every operation measured against the Rust crates that do the
same work.

### Added

- `benches/`: criterion benchmarks against `mime`, `httpdate`, `sfv`,
  `headers`, `content_disposition`, and `mailparse` on real traffic shapes,
  as their own crate so the competitors never enter parse-net's dependency
  tree (D-066); a CI job keeps them building.
- `docs/PERFORMANCE.md`: the results, what changed, the method, the machine,
  and the commands.
- Property tests: the `MailDate` fast path agrees with the general parser;
  the `X-Forwarded-For` IPv4 reader agrees with `core::net::Ipv4Addr`.

### Changed

- Entity-tag lists, `Cache-Control`, and range sets are validated and read in
  one pass by a walker for their own grammar (D-067): `if_none_match` 63 ns
  to 18 ns, `byte_ranges` 40 ns to 28 ns.
- `best_media` validates and scores in the same pass and compares exact
  forms first: 861 ns to 461 ns.
- `MailDate::parse` reads the canonical form by position (D-068): 54 ns to
  22 ns. `client_address` reads IPv4 with a byte-level parser: 196 ns to
  110 ns. `encode_words` builds each word on the stack from a length table.
- `Cache-Control` names are dispatched on length; `Params::get` and
  `MediaRange::matches` compare exact bytes before ignoring case.
- `parse_media_type` and `response_cache_control` are 17% and 19% faster
  than their competitors, below the 20% target; the plan is in
  `docs/PERFORMANCE.md` (D-069).

---

## [0.5.0] - 2026-10-22

Feature complete: links, Structured Field writing, the email lexical layer,
and owned forms.

### Added

- `link`: `parse_link`, `Links`, `LinkValue` (`target`, `rel`, `rels`,
  `has_rel`, `anchor`, `hreflang`, `title` with `title*`, `media`, `type_`,
  `params`), `LinkParams`, `write_link` (RFC 8288).
- `sfv::Writer`: canonical Structured Field serialization (RFC 9651 section
  4.1) for Items, Lists, and Dictionaries, with typed value methods, `bare`,
  `param`, `param_key`, `key`, inner lists, and `finish`.
- `MailDate`: RFC 5322 `date-time` with `new`, `parse` (strict, or with the
  obsolete forms of section 4.3), `format`, `write_to`, `utc`,
  `offset_minutes`, `offset_unknown`, `leap_second`.
- `mail`: `check_header_value`, `is_field_name`, `unfold`, `fold`,
  `encode_words` and `decode_words` (RFC 2047 Q), `parse_mime_params` and
  `MimeParams` with RFC 2231 continuations (`MimeValue`, `Continuation`),
  `write_mime_param`, `parse_addr_spec` (`AddrSpec`, `LocalPart`, `Domain`),
  `parse_mailbox` (`Mailbox`), `parse_msg_id` and `write_msg_id` (`MsgId`).
- `forwarded::write_element`.
- With `alloc`: `OwnedMediaType`, `OwnedEntityTag`, `OwnedHostPort`, and
  `sfv::owned` (`OwnedBareItem`, `OwnedItem`, `OwnedList`,
  `OwnedDictionary`), each with `to_owned` on the view and `as_view` back.
- `ext_value::Charset::UsAscii`.
- Tests: the httpwg serialisation tests (547 cases), and every accepted
  parse case serialized again and compared with its canonical form; property
  tests for every 0.5 parser (no panic) and writer (its output parses back);
  counting-allocator tests over every 0.5 parse and write; size and trait
  checks for every 0.4 and 0.5 view; an example for every public item.
- Fuzz targets: `link`, `mail_date`, `mail_words`, `mime_params`,
  `addr_spec`, `fold_unfold`, `sfv_roundtrip`.
- `docs/ARCHITECTURE.md`; `docs/GRAMMAR.md` extended to Link and the email
  layer.

### Changed

- `docs/API.md`: `Writer::param_key` (D-059), `Charset::UsAscii` (D-058),
  the iterator types (D-064); the `MailDate` example said "Tue, 21 Oct 2026",
  which is a Wednesday.
- The base64 decode helpers (ATH-3, MAIL-5, `ByteSeq::decode_into`,
  `sfv::Writer::bytes`, `B` encoded words) move to 0.6, as D-002 provides,
  because encode-lib is not published (D-062).

---

## [0.4.0] - 2026-10-22

Extended: the web layer and what form-net needs.

### Added

- `media`: `parse_range` and `MediaRange` (`matches`, `specificity`,
  `weight`, `params`) for `Accept` members.
- `negotiate`: `QValue`, `best_media`, `best_language`, `best_encoding`,
  `best_charset`; `Negotiator` with `LanguageMatching` (RFC 4647 lookup or
  basic filtering), `MalformedPolicy`, and `Outcome`, including
  `media_lines`; `parse_accept` (`AcceptList`) and `parse_weighted`
  (`WeightedList`, `Weighted`) for other selection rules.
- `etag`: `EntityTag` (`parse`, `strong`, `weak`, `strong_eq`, `weak_eq`,
  `write_to`), `Condition`, `TagList`, `parse_condition`, `if_match`,
  `if_none_match`.
- `range`: `parse`, `RangeHeader`, `RangeSpec`, `resolve` and `byte_ranges`
  with `RangeOutcome` (overlap and order rules against range abuse),
  `ByteRange`, `parse_content_range`, `ContentRange`, `write_content_range`,
  `write_unsatisfied`, `parse_if_range`, `IfRange`.
- `ext_value`: RFC 8187 `ExtValue` (UTF-8 and ISO-8859-1, decoded controls
  refused), `Charset`, `write_ext_value`.
- `disposition`: `parse_content_disposition`, `parse`, `ContentDisposition`,
  `DispositionType`, `Filename` (`decode_into`, `decode_percent_into`,
  `max_decoded_len`, `has_path_separator`, `has_bidi_control`),
  `write_attachment` with an ASCII fallback.
- `cache`: `parse`, `Directive`, `Directives`, `response_cache_control`,
  `request_cache_control`, `response_lines`, `request_lines`,
  `ResponseDirectives`, `RequestDirectives`, `Writer`.
- `forwarded`: `client_address` and `client_address_detailed` with `Trust`,
  `ForwardedSource`, `ClientAddress`, `Resolved`; `parse`, `Element`, `Node`,
  `NodePort`, `Proto`; `parse_x_forwarded_for` (`XffChain`),
  `parse_x_forwarded_proto`, `parse_x_forwarded_host`.
- `auth`: `parse_credentials`, `Credentials`, `AuthPayload`, `AuthParams`
  (redacted `Debug`), `bearer`, `basic`, `parse_challenges`, `Challenges`,
  `Challenge`, `write_challenge`, `write_challenge_token68`.
- `origin`: `parse_origin`, `OriginValue`, `Origin` (`same_origin`,
  `effective_port`, `write_to`).
- `sfv`: RFC 9651 parsing: `parse_item`, `parse_list`, `parse_dictionary`,
  `parse_list_lines`, `parse_dictionary_lines`, `Parser` with `Limits` and the
  single-pass `visit_item`, `visit_list`, `visit_dictionary` through
  `Visitor`; `BareItem` (all eight types, Date and Display String included),
  `Decimal`, `SfString`, `ByteSeq`, `DisplayString`, `Item`, `Member`,
  `InnerList`, `List`, `Dictionary` (`get`, `index_into`), `SfParams`,
  `ListLines`, `DictionaryLines`, and their iterators.
- `WriteError::DuplicateName`.
- Tests: the httpwg structured-field-tests suite in full (1598 cases), again
  with every list and dictionary split into one line per member; every
  greenbytes tc2231 case with a recorded verdict
  (`tests/differential/tc2231.md`); property tests for every 0.4 parser and
  the writer-parser closure check for every 0.4 writer; counting-allocator
  tests over every 0.4 parse and write.
- Fuzz targets: `media_range`, `accept_negotiate`, `etag_condition`, `range`,
  `content_range`, `ext_value`, `content_disposition`, `cache_control`,
  `forwarded`, `xff`, `authorization`, `www_authenticate`, `origin`,
  `sfv_item`, `sfv_list`, `sfv_dictionary`, and the differential oracle
  `diff_sfv` (against `sfv`), with verdicts V-5 to V-7.
- `docs/GRAMMAR.md`: for every field, the ABNF from its RFC, the case rules,
  each leniency or strictness and the RFC text behind it, and the function
  that parses it.

### Changed

- `media::write` refuses a parameter name given twice (`DuplicateName`), so
  its output always parses (D-052).
- `docs/API.md`: `Node` ports (D-047), `AuthParams` (D-048), the `sfv`
  additions (D-055); `parse_challenges`, `write_challenge_token68`, and
  `has_bidi_control` shipped in 0.4, ahead of plan (D-049).
- `RangeHeader::len` is documented as the size of the range set whatever the
  unit.

---

## [0.3.0] - 2026-10-22

The core: what http-net, ws-net, and cookie-net need.

### Added

- Errors: `ParseError` (8 bytes: kind, field line, offset; never input bytes)
  with `kind`, `offset`, `line`, `new`; `ErrorKind` with 49 variants and
  `message`; `WriteError` (`Full`, `Forbidden`, `OutOfRange`, `NotToken`,
  `InvalidSequence`); `Full`; `Display` and `core::error::Error` for all.
- `Limits` with every bound and its setter, RFC-sourced defaults, and
  `DuplicatePolicy` (`Refuse`, `First`, `Last`).
- `class`: the byte-class table (25 public classes in one 1 KiB table), the
  `is_*` predicates, `hex_value`, `Class` with `contains` and `union`, `all`.
- `scan`: `find_byte`, `find_either`, `check_field_value` (SWAR, eight bytes
  per step), `first_not_in`.
- `num`: `parse_u64`, `parse_u32_saturating` (the `delta-seconds` rule).
- `write`: `Sink`, `SliceSink`, `CountSink`, `Sink for Vec<u8>` (`alloc`),
  `Sink for &mut S`; `write_token`, `write_quoted`, `write_word`,
  `write_param`, `write_field_value`, `write_decimal_u64`, `write_hex_u64`.
- `text`: `is_token`, `is_ows`, `trim_ows`, `skip_ows`, `parse_token`,
  `parse_quoted`, `parse_word`, `parse_comment`; `Quoted` (zero-copy, buffer-free
  comparison, `unescape_into`), `Word`, `Comment`.
- `list`: `list`, `parse`, `for_each`, `combined` (several field lines as one
  list, no copy), `contains_token`; `List`, `Elements`, `CombinedList`.
- `param`: `parse`, `Params` (`get`, `iter`, names-only `Debug`), `Param`.
- `media`: `parse_media_type`, `parse`, `write`; `MediaType` with `essence_is`,
  `is`, `charset`, `boundary` (RFC 2046), `suffix`, `is_json`,
  `is_form_urlencoded`, `is_multipart_form_data`, `write_canonical`; `Boundary`.
- `date`: `HttpDate` (`from_unix`, `unix`, `MIN`, `MAX`, `parse_at`,
  `parse_at_with`, `parse_imf_fixdate`, `parse_detailed`, `format`, `write_to`,
  `civil`; `now`, `from_system_time`, `to_system_time` with `std`),
  `http_date_at`, `http_date` (`std`), `Civil`, `DateFormat`,
  `days_from_civil`, `civil_from_days`, `is_leap_year`, `days_in_month`,
  `weekday_from_days`.
- `host`: `parse_host_port`, `parse_uri_host_port` (strips nothing, for
  targets and URLs), `parse_host`; `HostPort`, `Host` with
  `eq_ignore_ascii_case` and `write_to`.
- `pct`: `validate`, `validate_with`, `decoded_len`, `decode_into`,
  `decode_utf8_into`, `decode_lower_only_into`, `encoded_len`, `encode`;
  `EncodeSet` with three named sets; `HexCase`.
- Tests: unit tests on every path; property tests (no parser panics, writer
  round trips, SWAR equals bytewise, combined lines equal joined); counting
  allocator tests over every parse and every write into a `SliceSink`; RFC
  vectors in `tests/vectors/`; compile-time `Send + Sync + Unpin` and size
  checks.
- Fuzz targets: `text_quoted`, `text_comment`, `list`, `params`, `media_type`,
  `http_date`, `host`, `pct_decode`, and the differential oracles
  `diff_http_date` (against `httpdate`) and `diff_media_type` (against `mime`),
  with the verdicts in `tests/differential/verdicts.md`.
- `docs/MIGRATION.md` for the http-net and ws-net maintainers.

### Changed

- `docs/API.md`: control bytes are reported with the same four kinds by every
  parser (D-037); `HttpDate::to_system_time` returns `Option` (D-038); the
  RFC 850 century window (D-039); numeric host names (D-040);
  `host::parse_uri_host_port` (D-044); `parse_u32_saturating`,
  `decode_lower_only_into`, and the `First` and `Last` duplicate policies
  shipped in 0.3, ahead of plan (D-042).

---

## [0.2.0] - 2026-10-22

The design lock: the public API through 1.0, written down before the code. No
parsing code yet.

### Added

- `docs/API.md`: every public item from `0.3.0` to `1.0.0` with its id, grade,
  tier, shipping version, signature, behaviour, every `ErrorKind` it can
  return, examples, and the edge cases its tests cover; the `ErrorKind` table
  with what each variant refuses and what to do; the `Limits` defaults and
  their RFC sources; one coverage checklist per consumer (http-net, ws-net,
  cookie-net, form-net, smtp-net).
- `dev/PLAN.md` decisions D-026 to D-036 made at the design lock (ISO weekday
  numbering, a public `ParseError::new`, no second quoting mode for
  `multipart/form-data`, `WriteError::InvalidSequence`, the Structured Field
  Date range, `@` checked first in `Host`, `mail::unfold` validating first,
  `If-Range` dates as IMF-fixdate, the RFC 5322 obsolete-year rule, and the
  names added beyond the specification's sketch).

### Changed

- `dev/ROADMAP.md`: 0.1.0 marked done; 0.2.0 items checked.

## [0.1.0] - 2026-10-21

The scaffold and the plan. No parsing code yet.

### Added

- Crate manifest (edition 2024, MSRV 1.85, no dependencies, features `alloc`,
  `std`, and `encode-lib` declared ahead of their code), `Apache-2.0 OR MIT`
  license, README, REPS, `deny.toml`, `clippy.toml`, `rustfmt.toml`,
  `.gitattributes`.
- Crate root: `VERSION`, `#![no_std]`, `#![forbid(unsafe_code)]`, missing docs
  denied, and `unwrap`, `expect`, `panic`, slice indexing, and printing denied
  in library code.
- CI: Linux, macOS, and Windows on stable and 1.85 (format, clippy and tests in
  three feature modes, examples, documentation with default and all features);
  a bare-metal `thumbv7em-none-eabi` build with no features and with `alloc`; a
  check that the default build has zero runtime dependencies; `cargo package`;
  `cargo audit` and `cargo deny`.
- `dev/PLAN.md` (purpose, scope, requirements, design, byte-class table,
  algorithms, API outline, threats, performance targets, testing, competitors,
  decision log D-001 to D-025), `dev/DIRECTIVES.md`, and `dev/ROADMAP.md`
  (0.1 to 1.0 with exit criteria).
- `fuzz/` crate skeleton; targets arrive with the parsers they cover.

[Unreleased]: https://github.com/jamesgober/parse-net/compare/v0.9.3...HEAD
[0.9.3]: https://github.com/jamesgober/parse-net/compare/v0.9.2...v0.9.3
[0.9.2]: https://github.com/jamesgober/parse-net/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/jamesgober/parse-net/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/jamesgober/parse-net/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/jamesgober/parse-net/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/jamesgober/parse-net/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/jamesgober/parse-net/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/jamesgober/parse-net/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/jamesgober/parse-net/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/jamesgober/parse-net/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jamesgober/parse-net/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/parse-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/parse-net/releases/tag/v0.1.0
