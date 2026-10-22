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

[Unreleased]: https://github.com/jamesgober/parse-net/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/jamesgober/parse-net/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/parse-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/parse-net/releases/tag/v0.1.0
