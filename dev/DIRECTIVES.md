# parse-net - Engineering Directives

> Engineering standards and the definition of done for this project. Read alongside `REPS.md` (root, authoritative), [`PLAN.md`](./PLAN.md) (design and decisions), and [`ROADMAP.md`](./ROADMAP.md) (current phase). If anything here conflicts with `REPS.md`, `REPS.md` wins, except where `PLAN.md` records an approved exception (D-022: no async runtime; D-023: hand-written error impls; D-025: lint configuration).

---

## 0. Philosophy

This library is built and maintained to a production standard and treated as a flagship piece of work. Plan the full path, then build one verified step at a time. "Good enough" is treated as a defect. It is a member of the `-net` family: network formats, sans-IO. Every protocol crate in the stack reads its field values through parse-net, so a mistake here is a mistake everywhere, and a parser differential here is a security hole everywhere. A security component that cannot name the attack it stops, and prove it with a test, does not ship.

---

## 1. What this is

parse-net reads what is inside an Internet message field value (HTTP, Structured Fields, email) and writes field values back out safely. It does not frame messages, store headers, parse URLs, decode base64, or decide policy. See `PLAN.md` sections 1 to 3.

---

## 2. Engineering law (non-negotiable)

- **Depends on nothing.** Zero runtime dependencies in the default build, first party included. One optional, non-default first-party dependency (`encode-lib`) is allowed for base64 only, by published version, never a `path` dependency. Dev-only tooling (`criterion`, `proptest`, competitor crates as oracles) is allowed.
- **no_std, no allocator, sans-IO.** The base build is `no_std` without `alloc`, checked in CI on a bare-metal target. No parse, compare, or write-into-slice path allocates; a counting allocator proves it. No I/O, no clock reads (except the `std` Tier 1 `http_date`), no global state.
- **Validate, then view.** A parse checks the whole value in one forward pass and returns a `Copy` view over the caller's bytes. Iterators over a view cannot fail. Decoded forms go into caller buffers.
- **Unsafe.** `#![forbid(unsafe_code)]`, no exception. SWAR scanning needs none.
- **Hostile-input hardening.** Every input may be adversarial: every budget (counts, depth, lengths) checked before the work it governs; no recursion; linear time; checked or saturating arithmetic on every value derived from input; no reachable panics (`indexing_slicing`, `unwrap_used`, `expect_used`, `panic` denied).
- **Strict by default.** Anything two conforming implementations could read differently is refused, unless the RFC tells recipients to accept it; then it is accepted, documented with the RFC sentence, and tested.
- **Writers cannot produce what parsers refuse.** No writer emits CR, LF, NUL, or a byte its grammar forbids; `parse(write(x)) == x` is a property test for every writer.
- **Errors carry kind and offset only.** Never input bytes, in `Display`, `Debug`, or anywhere else. Credentials never appear in `Debug`.
- **Performance.** At least 20% faster than the best Rust competitor for each comparable operation, at equal or stronger strictness, measured with criterion and published. No regression over 5%. `#[inline]` only where a consumer benchmark justifies it.
- **Cross-platform.** Linux, macOS, and Windows on stable and MSRV 1.85; `thumbv7em-none-eabi` builds. Results are identical on every platform.
- **Error handling.** Every fallible path returns `Result`; `ErrorKind` and `WriteError` are `#[non_exhaustive]` and every variant says what was refused and what to do.
- **Production-ready.** `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!`/`todo!`/`unimplemented!`/`unreachable!`/`dbg!`/printing in library code; every public item has rustdoc with a runnable example; every claim in the docs maps to a test.

---

## 3. Definition of done

1. Compiles clean on Linux, macOS, and Windows, stable and MSRV 1.85; the bare-metal target builds with no features and with `alloc`.
2. `fmt`, `clippy -D warnings` (all targets; default, all, and no default features), tests in the same three modes, `cargo doc -D warnings` with default and all features, `cargo package` in a fresh target directory: clean on Windows and in WSL Ubuntu, stable and 1.85.
3. `cargo audit` and `cargo deny check` pass; `cargo tree -e normal` shows only the crate itself.
4. No `unwrap`/`expect`/`todo!`/`dbg!` in shipping code.
5. A Tier-1 API exists and headlines the docs (`use parse_net as pn;`).
6. Every parser has a fuzz target and a "never panics" property test; every writer has a round-trip property test; every threat in `PLAN.md` section 9 has an attack test that must fail to get through; every edge case the change touches has a test.
7. Counting-allocator tests cover every new parse and every write into a `SliceSink`.
8. Hot-path changes carry benchmarks; no regression over 5%.
9. `README.md`, `docs/API.md`, and `CHANGELOG.md` updated in the same change; the matching `docs/release/vX.Y.Z.md` written before the tag; every version string bumped.
10. `PLAN.md` decision log updated for every design decision made during the work; at least one new defence idea per version in `PLAN.md` section 15.
11. v1.0.0 only after the full audit (API, docs, tests, benchmarks, security) is recorded in `docs/STABILITY-1.0.md` and James has given the go.

---

## 4. Project-specific invariants

- A parse either refuses the whole value or returns a view whose iterators cannot fail.
- No function allocates unless its name or feature says so (`to_owned`, `alloc` items).
- No function recurses; nesting depth is a counter compared with a limit.
- Every function is linear in its input length (negotiation: linear in members times offers, with members bounded).
- `ParseError` is 8 bytes and contains no input data.
- OWS is SP and HTAB only.
- Every writer refuses CR, LF, and NUL in every position.
- The byte-class table equals the slow ABNF reference for all 256 bytes in every class.
- The same input (and the same `now`) gives the same result on every platform.
- Nothing panics on any input.

---

## 5. Writing style

- Plain, specific, human prose in every shipping file. No marketing voice.
- Banned in shipping files: "comprehensive", "robust", "seamless", "leverage", the em-dash character (U+2014), and emoji.
- Every security measure states its cost (latency, memory); estimates are labelled as estimates, measurements as measured.
- Release notes in the past tense.
- Commits: imperative present tense, descriptive subject line.
