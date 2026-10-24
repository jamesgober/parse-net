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

[Unreleased]: https://github.com/jamesgober/parse-net/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/jamesgober/parse-net/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/jamesgober/parse-net/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/jamesgober/parse-net/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/jamesgober/parse-net/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/jamesgober/parse-net/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jamesgober/parse-net/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/parse-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/parse-net/releases/tag/v0.1.0
