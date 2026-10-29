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

## v0.3.0 - Core (what http-net, ws-net, and cookie-net need) (DONE, 2026-10-21)

Exit: every item below implemented with unit tests, property tests, and fuzz targets; counting-allocator tests pass; the http-net and ws-net migration branches pass their full test suites and stay within 5% on their benchmarks (NFR-8).

- [x] ERR-1 to ERR-4, LIM-1, LIM-2.
- [x] CLS-1 to CLS-22, SCN-1 to SCN-4, NUM-1 (and NUM-2, PCT-4, PRM-4 ahead of plan, D-042).
- [x] WRT-1 to WRT-11.
- [x] TXT-1 to TXT-12, LST-1 to LST-4, PRM-1 to PRM-3, PRM-5, PRM-6.
- [x] MED-1 to MED-6, MED-9, MED-10, MED-12.
- [x] DAT-1 to DAT-10.
- [x] HST-1 to HST-4, and `host::parse_uri_host_port` (D-044).
- [x] PCT-1 to PCT-3, PCT-5, PCT-6.
- [x] `docs/MIGRATION.md`; the http-net and ws-net migrations tried on 2026-10-21: both full test suites pass; instruction counts http-net +3.9% / +0.4% / +0.1%, ws-net -23.3% (D-046). Draft pull requests open in both repositories once 0.3.0 is on crates.io (they cannot build against an unpublished version; merged in their own release cycles).
- [x] Defence idea: differential oracle (PLAN 15): `diff_http_date` and `diff_media_type`, verdicts V-1 to V-4.

Unit tests, property tests, fuzz targets (each run 60 s clean in WSL, 1.3 to 13.7 million inputs), and counting-allocator tests cover every item above.

## v0.4.0 - Extended (web layer and form-net) (DONE, 2026-10-22)

Exit: conformance suites pass (httpwg structured-field-tests in full; every tc2231 case with a recorded verdict); every new parser has a fuzz target that has run 1 hour clean.

- [x] TXT-13, TXT-14, LIM-3, NUM-2, PRM-4, MED-7, MED-8 (NUM-2, PCT-4, and PRM-4's policies shipped in 0.3, D-042).
- [x] NEG-1 to NEG-9.
- [x] ETG-1 to ETG-7, RNG-1 to RNG-8.
- [x] EXT-1 to EXT-4, DSP-1 to DSP-6 (and DSP-7, ahead of 0.5, D-049).
- [x] CCH-1 to CCH-5.
- [x] FWD-1 to FWD-6, FWD-8 (node ports as `NodePort`, D-047).
- [x] ATH-1, ATH-2, ATH-4, ATH-6 (and ATH-5, ATH-7, ahead of 0.5, D-049; `AuthParams`, D-048).
- [x] ORG-1 to ORG-4, PCT-4.
- [x] SFV-1 to SFV-12, SFV-14, SFV-15 (additions in D-055).
- [x] `docs/GRAMMAR.md`.
- [x] Defence idea: writer-parser closure check (PLAN 15): property tests over every writer and the round trips in the fuzz targets; it found that `write_challenge` and `media::write` accepted a repeated parameter name that every parser refuses (D-052).
- [x] httpwg structured-field-tests: all 1598 cases, and every list and dictionary again one line per member (D-050, D-051).
- [x] tc2231: every case with a verdict, 66 agree and 21 in five recorded classes (D-054).
- [x] Every new parser's fuzz target 1 hour clean (17 targets, including the `diff_sfv` oracle, D-056): 6.6 to 407 million inputs each in WSL Ubuntu, 2026-10-21.

## v0.5.0 - Feature complete (smtp-net, links, challenges, owned forms) (DONE, 2026-10-22)

Exit: every P0, P1, and P2 item exists; every public item has a doctest; `cargo tree -e normal` is empty for the default build.

- [x] LNK-1 to LNK-4 (empty values written as the name alone, D-061).
- [x] FWD-7 (`forwarded::write_element`). ATH-5 and ATH-7 shipped in 0.4 (D-049).
- [x] SFV-13 (the writer, with `param_key`, D-059, and canonical views, D-060; the httpwg serialisation tests and every parse case's canonical form pass), SFV-16.
- [x] DAT-11 to DAT-13, MAIL-1 to MAIL-4, MAIL-6 to MAIL-14 (US-ASCII through `Charset::UsAscii`, D-058).
- [x] MED-11, OWN: `OwnedMediaType`, `OwnedEntityTag`, `OwnedHostPort`, `sfv::owned`. DSP-7 shipped in 0.4 (D-049).
- [x] The `encode-lib` feature: encode-lib is not published, so ATH-3, MAIL-5, `ByteSeq::decode_into`, `sfv::Writer::bytes`, and `B` encoded words move to 0.6, recorded per D-002 (D-062).
- [x] `docs/ARCHITECTURE.md`; `docs/GRAMMAR.md` extended to Link and the email layer.
- [x] Every public item has a doctest (560 items).
- [x] Fuzz targets for the 0.5 parsers and writers (`link`, `mail_date`, `mail_words`, `mime_params`, `addr_spec`, `fold_unfold`, `sfv_roundtrip`): all 34 targets ten minutes clean against 0.5.
- [x] Property tests (no panic; every 0.5 writer's output parses back) and counting-allocator tests for every 0.5 parse and write.

## v0.6.0 - Optimisation (DONE, 2026-10-22)

Exit: every comparable row of PLAN 10.1 at least 20% faster than the best Rust competitor, or a recorded plan; no regression over 5% against 0.5.

- [ ] Moved from 0.5 (D-062): ATH-3 `basic_decode_into`, MAIL-5 `encode_words_b`, `ByteSeq::decode_into`, `sfv::Writer::bytes`, `B` encoded words, behind `encode-lib`. encode-lib is still not published; they move to 0.7, then to the first release after encode-lib appears (D-002).
- [x] Benchmarks for every row of PLAN 10.1 against the named competitors (`benches/`, D-066).
- [x] SWAR fast paths where measured to help (`scan`, from 0.3); `#[inline]` decisions recorded in `docs/PERFORMANCE.md` with D-041.
- [x] `docs/PERFORMANCE.md`.
- [x] Exit: 10 of 12 compared rows at least 20% faster; `parse_media_type` (17%) and `response_cache_control` (19%) have a recorded plan (D-069); no regression against 0.5.

## v0.7.0 - Hardening (DONE, 2026-10-24)

Exit: no open fuzz or differential finding marked "ours wrong"; threat table fully tested.

- [x] From 0.6 (D-069): the slice-cursor rewrite of `param::parse` and the validated reads; `parse_media_type` (30%) and `response_cache_control` (31%) meet the 20% target.
- [ ] From 0.5 (D-062): the `encode-lib` helpers. encode-lib is still not published; they wait for the first release after it appears (D-002).
- [x] Every fuzz target 24 hours clean; differential targets weekly in CI (D-073).
- [x] Attack tests T1 to T25 all present and passing (`tests/threats.rs` and the tests it lists); complexity tests for every walker (`tests/complexity.rs`). They and the fuzz run found the quadratic repeated-name check (D-072), the decoded controls `decode_words` let through (D-071), a 999-byte line from `mail::fold`, and the entity-tag list bug fixed in 0.6.1.
- [x] `docs/SECURITY.md`, `docs/PLATFORM-NOTES.md`.

## v0.8.0 - Alpha (DONE, 2026-10-29)

Exit: two consumers in published releases with green CI; no API change requested by them that is still open.

- [x] Consumers published on parse-net, CI green on their `main` branches: http-net 0.8.0 and 0.9.0 (`parse-net ^0.7`, its only runtime dependency), cookie-net 0.3.0 to 0.7.0 and form-net 0.3.0 to 0.5.0 (`^0.6.1`). serve-net and LexerSketch Studio run against http-net on parse-net with no change.
- [x] No API change requested by a consumer is open. One measurement note: form-net's `FormKind::detect` took 114 ns against its 100 ns estimate on parse-net 0.6.1 (it parses, then looks for repeated names itself, then calls `get` twice); it is in the 0.9 polish list.
- [ ] Moved to 0.9: ws-net on parse-net (ws-net 0.2.0 still carries its own grammar).

## v0.9.0 - Beta and release candidates

Exit: four consumers end to end; no breaking change for one full release cycle; the pre-1.0 polish pass below done before any release candidate.

- [ ] smtp-net and web-net built on it; ws-net on it (from 0.8); cookie-net and form-net on `^0.7` or later; API frozen except for fixes found by consumers; `0.9.x` release candidates.

### Pre-1.0 polish pass (0.9.x, before the first release candidate)

James's standing rule: go back and fix any issues and tune performance before getting close to release. Nothing accepted, deferred, or missed is silently final; whatever is still open after this pass goes in the 1.0 readiness note for James, with its reason.

- [ ] Revisit every accepted gap, deferred item, known issue, and missed target:
  - the `encode-lib` helpers (D-002, D-062): `basic_decode_into`, `encode_words_b`, `ByteSeq::decode_into`, `sfv::Writer::bytes`, `B` encoded words, if encode-lib is published by then;
  - `client_address` at 101 ns against its 60 ns estimate (`docs/PERFORMANCE.md`);
  - the narrowest benchmark margins, `byte_ranges` (21%) and `Content-Disposition` (24%);
  - form-net's `FormKind::detect` at 114 ns against 100 ns: re-measure on parse-net 0.7 or later, and if still over, show form-net how to use the `Refuse` error offset instead of its own repeated-name walk;
  - the fixed 64-parameter table for lists that refuse repeats (D-072): still the right size, or a size consumers need to set;
  - the bidi set reported by `has_bidi_control` (D-070) and the timing bound of the complexity tests (D-073);
  - the ambiguous differential verdicts V-5 and V-6 (`tests/differential/verdicts.md`) and the tc2231 deviation classes (D-054);
  - every P0, P1, and P2 item of PLAN section 8 shipped, or its reason recorded.
- [ ] A fresh performance pass: the whole benchmark suite on a quiet machine, a callgrind profile of every row, and tuning where it pays; no row below 20% and no regression against 0.7.
- [ ] The security and edge-case review again: the threat table T1 to T25 against the code as it is, the edge-case lists in `docs/API.md`, every fuzz target 24 hours on the release candidate code, and the differential targets' latest weekly runs.

## v1.0.0 - Stable

Exit: every P0, P1, P2 item shipped (or its reason recorded in PLAN); release routine completed; James's go.

- [ ] Full audit (API, docs, tests, benchmarks, security) recorded in `docs/STABILITY-1.0.md`; API frozen until 2.0.
