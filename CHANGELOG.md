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

## [0.2.0] - 2026-10-21

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

[Unreleased]: https://github.com/jamesgober/parse-net/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jamesgober/parse-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/parse-net/releases/tag/v0.1.0
