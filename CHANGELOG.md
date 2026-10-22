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

[Unreleased]: https://github.com/jamesgober/parse-net/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jamesgober/parse-net/releases/tag/v0.1.0
