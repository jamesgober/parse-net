# parse-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each version has hard exit criteria. Item ids (ERR-1, TXT-5, ...) are defined in [`PLAN.md`](./PLAN.md) section 8 and in `docs/API.md`.
>
> **Anti-deferral rule:** no listed item moves to a later version unless this file records the move and the reason.
>
> **Release routine after every version:** finish the version (every item done, version bumped everywhere, CHANGELOG rolled, `docs/release/vX.Y.Z.md` written, README and `docs/API.md` checked against the build); local gate on Windows and WSL, stable and 1.85; commit and push (the scaffold to `main`, later versions on a `feature/` branch with a pull request, squash-merged after CI passes); wait for green CI; tag `vX.Y.Z`; GitHub release from the release notes (pre-release for 0.x); `cargo doc` clean in both feature modes; `cargo publish`; verify crates.io and docs.rs.

## v0.1.0 - Scaffold (DONE, 2026-10-21)

Exit: CI green on every platform; crate on crates.io; docs.rs build green.

- [x] Repository in the customs-sec layout; `Cargo.toml` (edition 2024, MSRV 1.85, no dependencies, features `alloc`, `std`, `encode-lib` declared empty until used).
- [x] `src/lib.rs` with `VERSION` (ROOT-1), `no_std`, `forbid(unsafe_code)`, the lint set (D-025).
- [x] CI: Linux, macOS, Windows on stable and 1.85 (fmt, clippy and tests in three feature modes, examples, docs in both modes); bare-metal `thumbv7em-none-eabi` build; zero-dependency check; package; audit and deny.
- [x] `dev/PLAN.md` from the specification with the decision log; `dev/DIRECTIVES.md`; this file.
- [x] README, CHANGELOG, `docs/API.md`, `docs/release/v0.1.0.md`; `fuzz/` crate skeleton.
- [x] Publish 0.1.0 to claim the name (crates.io and docs.rs green).

## v0.2.0 - Design lock (DONE, 2026-10-22)

Exit: James approves `docs/API.md`; no `todo` in the API document.

- [x] `docs/API.md` written for every item in PLAN section 8, with signatures, behaviour, every `ErrorKind` each item can return, and examples, in the metrics-lib format.
- [x] One checklist per consumer (http-net, ws-net, cookie-net, form-net, smtp-net) proving the API covers what each needs, kept in `docs/API.md`.
- [x] The edge-case lists placed beside each item (PLAN 11.7).
- [x] Open decisions closed or kept open with a date (all PN-1 to PN-18 are closed in the decision log; design-lock decisions D-026 to D-036 added).
- [x] James approves `docs/API.md` (2026-10-22, with the go-ahead to release).

## v0.3.0 - Core (what http-net, ws-net, and cookie-net need)

Exit: every item below implemented with unit tests, property tests, and fuzz targets; counting-allocator tests pass; the http-net and ws-net migration branches pass their full test suites and stay within 5% on their benchmarks (NFR-8).

- [ ] ERR-1 to ERR-4, LIM-1, LIM-2.
- [ ] CLS-1 to CLS-22, SCN-1 to SCN-4, NUM-1.
- [ ] WRT-1 to WRT-11.
- [ ] TXT-1 to TXT-12, LST-1 to LST-4, PRM-1 to PRM-3, PRM-5, PRM-6.
- [ ] MED-1 to MED-6, MED-9, MED-10, MED-12.
- [ ] DAT-1 to DAT-10.
- [ ] HST-1 to HST-4.
- [ ] PCT-1 to PCT-3, PCT-5, PCT-6.
- [ ] `docs/MIGRATION.md`; draft pull requests in http-net and ws-net that switch to parse-net, with before and after benchmarks (merged in their own release cycles).
- [ ] Defence idea: differential oracle (PLAN 15).

## v0.4.0 - Extended (web layer and form-net)

Exit: conformance suites pass (httpwg structured-field-tests in full; every tc2231 case with a recorded verdict); every new parser has a fuzz target that has run 1 hour clean.

- [ ] TXT-13, TXT-14, LIM-3, NUM-2, PRM-4, MED-7, MED-8.
- [ ] NEG-1 to NEG-9.
- [ ] ETG-1 to ETG-7, RNG-1 to RNG-8.
- [ ] EXT-1 to EXT-4, DSP-1 to DSP-6.
- [ ] CCH-1 to CCH-5.
- [ ] FWD-1 to FWD-6, FWD-8.
- [ ] ATH-1, ATH-2, ATH-4, ATH-6.
- [ ] ORG-1 to ORG-4, PCT-4.
- [ ] SFV-1 to SFV-12, SFV-14, SFV-15.
- [ ] `docs/GRAMMAR.md`.
- [ ] Defence idea: writer-parser closure check (PLAN 15).

## v0.5.0 - Feature complete (smtp-net, links, challenges, owned forms)

Exit: every P0, P1, and P2 item exists; every public item has a doctest; `cargo tree -e normal` is empty for the default build.

- [ ] LNK-1 to LNK-4.
- [ ] ATH-3, ATH-5, ATH-7, FWD-7.
- [ ] SFV-13, SFV-16.
- [ ] DAT-11 to DAT-13, MAIL-1 to MAIL-14.
- [ ] DSP-7, MED-11, OWN.
- [ ] The `encode-lib` feature, if encode-lib is published; otherwise the move is recorded here (D-002).
- [ ] `docs/ARCHITECTURE.md`.

## v0.6.0 - Optimisation

Exit: every comparable row of PLAN 10.1 at least 20% faster than the best Rust competitor, or a recorded plan; no regression over 5% against 0.5.

- [ ] Benchmarks for every row of PLAN 10.1 against the named competitors.
- [ ] SWAR fast paths where measured to help; `#[inline]` decisions recorded with the consumer benchmark that justified each.
- [ ] `docs/PERFORMANCE.md`.

## v0.7.0 - Hardening

Exit: no open fuzz or differential finding marked "ours wrong"; threat table fully tested.

- [ ] Every fuzz target 24 hours clean; differential targets running weekly.
- [ ] Attack tests T1 to T25 all present and passing; complexity tests (PLAN 11.6).
- [ ] `docs/SECURITY.md`, `docs/PLATFORM-NOTES.md`.

## v0.8.0 - Alpha

Exit: two consumers in published releases with green CI; no API change requested by them that is still open.

- [ ] http-net and ws-net releases on parse-net published; cookie-net 0.3 and form-net built on it.

## v0.9.0 - Beta and release candidates

Exit: four consumers end to end; no breaking change for one full release cycle.

- [ ] smtp-net and web-net built on it; API frozen except for fixes found by consumers; `0.9.x` release candidates.

## v1.0.0 - Stable

Exit: every P0, P1, P2 item shipped (or its reason recorded in PLAN); release routine completed; James's go.

- [ ] Full audit (API, docs, tests, benchmarks, security) recorded in `docs/STABILITY-1.0.md`; API frozen until 2.0.
