# Performance

How fast parse-net is against the Rust crates that do the same work, how
that was measured, and what changed in 0.6 to get there. Every number here
comes from the benchmark crate in [`benches/`](../benches) and can be
reproduced with the commands at the end.

## Results

Median time per call (criterion), parse-net and the fastest competitor on the
same input, through each competitor's own public API. Owned-result APIs are
measured with their allocation, since that is what a caller pays. "Faster"
is `1 - parse-net / competitor`. The target (dev/PLAN.md section 10.1) is at
least 20% faster than the best Rust competitor at equal or stronger
strictness.

| Operation | Input | parse-net | Competitor | Faster | Target |
|---|---|---|---|---|---|
| `byte_ranges` | `bytes=0-499` | 10.2 ns | 42.9 ns (`headers`) | 76% | met |
| `scan::check_field_value` | 64-byte `User-Agent` text | 8.3 ns | 30.4 ns (bytewise loop, http-net's former code) | 73% | met |
| `HttpDate::format` | | 23.8 ns | 71.9 ns (`httpdate`, allocates a `String`) | 67% | met |
| `sfv::parse_list` | 10 tokens with one parameter each | 504 ns | 1408 ns (`sfv` 0.16.0, owned) | 64% | met |
| `sfv::parse_dictionary` | 5 members of mixed types | 207 ns | 531 ns (`sfv`, owned) | 61% | met |
| `MailDate::parse` | `Wed, 21 Oct 2026 17:38:00 +0200` | 31.6 ns | 76.6 ns (`mailparse` 0.15.0) | 59% | met |
| `HttpDate::parse_imf_fixdate` | `Sun, 06 Nov 1994 08:49:37 GMT` | 23.5 ns | 53.6 ns (`httpdate` 1.0.3) | 56% | met |
| `if_none_match` | 3 tags | 28.6 ns | 53.6 ns (`headers` 0.4.2) | 47% | met |
| `parse_content_disposition` and `filename` | `attachment; filename="a.txt"; filename*=UTF-8''%E2%82%AC.txt` | 173 ns | 298 ns (`content_disposition` 0.4.0; `mailparse` 371 ns) | 42% | met |
| `parse_media_type` and `charset` | `text/html; charset=utf-8` | 32.3 ns | 55.1 ns (`mime` 0.3.17) | 41% | met |
| `response_cache_control` | `public, max-age=31536000, immutable` | 54.5 ns | 81.3 ns (`headers`) | 33% | met |
| `best_media` | Chrome's navigation `Accept`, 3 offers | 609 ns | 879 ns (`mime` and a selection loop) | 31% | met |
| `client_address` | 3-hop `X-Forwarded-For`, IPv4 | 70 ns | no Rust crate resolves through trusted proxies | n/a | estimate 60 ns: see below |
| `mail::encode_words` | 36-byte UTF-8 subject (PLAN row: 40 bytes) | 256 ns | no allocation-free Rust encoder | n/a | estimate 200 ns: see below |

parse-net validates every byte of the field in these rows (where it has been
compared, it is the stricter side: `mime` accepts values parse-net refuses,
`tests/differential/verdicts.md`), and none of its numbers include an
allocation.

The numbers are from one run of the whole suite at 0.9.0, on a machine that
other builds were using at the same time (load average 14 to 26 on 32
threads). That lifts the absolute times by about 30% on both sides of every
row, so the percentages stand and the times are high. The two rows with an
estimate have no other side to compare with: `encode_words` measured 185 ns
on a quiet machine at 0.7, with the same instruction count; `client_address`
measured 101 ns there at 0.7, and its count has fallen 60% since, so a quiet
run should land near 40 ns. That run is on the list for the release
candidates.

## What 0.9 changed

Instructions per call (callgrind), which other builds do not disturb:

| Operation | 0.8 | 0.9 | Change |
|---|---|---|---|
| `byte_ranges` | 815 | 197 | -76% |
| `client_address` | 3,193 | 1,289 | -60% |
| `parse_content_disposition` and `filename` | 4,014 | 3,585 | -11% |
| `parse_media_type` and `charset` | 797 | 729 | -9% |
| `response_cache_control` | 884 | 881 | flat |

- `byte_ranges` reads the shape nearly every request sends by position:
  `bytes=a-b`, `bytes=a-`, or `bytes=-n`. Anything else takes the general path,
  and a property test compares the two (D-074).
- `client_address` decides and validates a chain in one pass, instead of
  walking it again from the left for every hop.
- The repeated-name table of D-072 cost every parameter list 512 bytes of
  zeroing for nothing. Eight offsets now sit inline and the rest of the table
  is written only past eight.
- `Content-Disposition` reads `filename*` with the in-place `Params::get`, and
  stops checking validated text again in `filename_ext`.

`best_media` rose from 10,244 to 10,840 instructions over 0.7 to 0.9, the cost
of the repeated-name table on each of its members, and is the narrowest row at
31%.

## What 0.7 changed

The two rows below the target at 0.6 (D-069) met it once the parameter
walker shared by media types, `Content-Disposition`, and RFC 2231
parameters, and the number reader shared with `Cache-Control`, were
rewritten:

| Operation | 0.6 | 0.7 | Instructions per call, 0.6 to 0.7 |
|---|---|---|---|
| `parse_media_type` and `charset` | 32.0 ns (17% faster than `mime`) | 26.1 ns (30% faster) | 885 to 705 |
| `response_cache_control` | 47.8 ns (19% faster than `headers`) | 41.2 ns (31% faster) | 922 to 884 |
| `parse_content_disposition` and `filename` | 158 ns | 133 ns | 4,112 to 3,909 |

- `param::parse` walks a shrinking slice and computes an offset only for an
  error.
- `Params::get` (and so `charset()`) compares the name asked for in place,
  then reads the value without validating it again; the parameter iterator
  does the same. Each is checked against the checked reads by a property
  test.
- `parse_u32_saturating` reads up to nine digits, which cannot overflow, in
  a loop without saturating steps.

The repeated-name check also changed (D-072): it compares names from a
table of up to 64 offsets instead of reading the earlier parameters again,
which was quadratic. The rows above have one or two parameters, so the
change shows in the complexity tests, not here.

## What 0.6 changed

Instructions per call (callgrind, release build), before and after, for the
rows that changed:

| Operation | 0.5 | 0.6 | Change |
|---|---|---|---|
| `best_media` | 20,161 | 10,903 | -46% |
| `encode_words` | 7,513 | 5,703 | -24% |
| `client_address` | 5,469 | 3,193 | -42% |
| `MailDate::parse` (canonical form) | 1,527 | fixed-position path | 54 ns to 22 ns |
| `response_cache_control` | 1,084 | 925 | -15% |
| `byte_ranges` | 998 | 815 | -18% |
| `parse_media_type` and `charset` | 972 | 877 | -10% |

- Entity-tag lists, `Cache-Control`, and range sets are validated and read in
  one pass by a walker for their own grammar, instead of the general list
  walker followed by a second pass per element. The views keep the validated
  text and re-walk it without fallible steps.
- `best_media` validates the header in the same pass that scores the first
  group of offers, touches only the offer slots in use, and compares media
  types with an exact compare before the case-insensitive one.
- `Cache-Control` names are dispatched on length, then compared with one OR
  per byte (exact for the lowercase-letter names in its table).
- `MailDate` reads the canonical form mailers write by position; any other
  shape, or any value that fails a check there, takes the general path, so
  results and errors are identical (a property test compares the two paths).
- `encode_words` walks UTF-8 bytes with a 256-entry length table and builds
  each encoded word on the stack.
- `X-Forwarded-For` members are dispatched by shape (no colon: IPv4; one:
  IPv4 with a port; more: IPv6), and IPv4 is read by a byte-level parser with
  `core`'s exact rules (a property test compares it with `core`).

No benchmark regressed. The one row measured slower than in its 0.5 run,
`check_field_value` (5.1 ns then, 5.4 ns at 0.6), is code 0.6 did not
change, so the difference is run-to-run variation.

## `#[inline]`

`#[inline]` is on the byte-class predicates, `Class::contains`, `class::all`,
the scanners, `text::is_token`, `trim_ows`, `skip_ows`, and the `Sink`
implementations (D-041): they are called per field from http-net and ws-net
across the crate boundary, where a small non-generic function is not inlined
without LTO, and the consumer gate (NFR-8) measured them there. The 0.6
helpers (`cache::skip_ws`, `words::q_byte_len`) are inside generic or
crate-local hot loops and carry `#[inline]` for the same reason. Nothing else
is marked.

## Method

- criterion 0.5.1, default settings (3 s warm-up, 100 samples), medians
  reported; inputs are real traffic shapes stored as files in
  `benches/data/`.
- The competitors are dependencies of the benchmark crate only; it is its own
  Cargo workspace, so they never enter parse-net's dependency tree or its
  MSRV build (D-066).
- Machine: AMD Ryzen 9 9950X3D (16 cores, 32 threads), 64 GB, Ubuntu 24.04 in
  WSL2 (Linux 6.6), Rust 1.99.0, release profile.
- Wall-clock times on this machine move by up to 15% between identical runs,
  for both sides; each comparison above is from one run, where both sides
  share the conditions. Instruction counts (callgrind from valgrind 3.22, a
  driver that calls one operation 1,000 and 11,000 times, the difference
  divided by 10,000) are exact and were used to find and confirm every change
  (D-046).

## Commands

```bash
cd benches
cargo bench -- --noplot
```

One group, such as the Structured Field benchmarks:

```bash
cargo bench --bench sfv -- --noplot
```
