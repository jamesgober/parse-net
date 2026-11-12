# Performance

How fast parse-net is against the Rust crates that do the same work, how
that was measured, and what changed in each release to get there. Every number here
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
| `scan::check_field_value` | 64-byte `User-Agent` text | 4.68 ns | 24.3 ns (bytewise loop, http-net's former code) | 81% | met |
| `byte_ranges` | `bytes=0-499` | 7.71 ns | 33.5 ns (`headers`) | 77% | met |
| `structured::parse_dictionary` | 5 members of mixed types | 147 ns | 504 ns (`sfv` 0.16.0, owned) | 71% | met |
| `structured::parse_list` | 10 tokens with one parameter each | 352 ns | 991 ns (`sfv`, owned) | 64% | met |
| `HttpDate::format` | | 17.2 ns | 44.4 ns (`httpdate`, allocates a `String`) | 61% | met |
| `mail::decode_words`, one `B` word | 39 bytes of Japanese, `=?UTF-8?B?...?=` | 145 ns | 373 ns (`mailparse` 0.15.0, `parse_header` and `get_value`, allocates) | 61% | met |
| `MailDate::parse` | `Wed, 21 Oct 2026 17:38:00 +0200` | 20.0 ns | 47.3 ns (`mailparse`) | 58% | met |
| `if_none_match` | 3 tags | 17.9 ns | 42.4 ns (`headers` 0.4.2) | 58% | met |
| `HttpDate::parse_imf_fixdate` | `Sun, 06 Nov 1994 08:49:37 GMT` | 14.8 ns | 32.5 ns (`httpdate` 1.0.3) | 55% | met |
| `parse_media_type` and `charset` | `text/html; charset=utf-8` | 20.6 ns | 37.6 ns (`mime` 0.3.17) | 45% | met |
| `parse_content_disposition` and `filename` | `attachment; filename="a.txt"; filename*=UTF-8''%E2%82%AC.txt` | 108 ns | 173 ns (`mailparse`; `content_disposition` 0.4.0 178 ns) | 38% | met |
| `best_media` | Chrome's navigation `Accept`, 3 offers | 444 ns | 630 ns (`mime` and a selection loop) | 30% | met |
| `parse_response_cache_control` | `public, max-age=31536000, immutable` | 37.8 ns | 50.7 ns (`headers`) | 25% | met; 6.6% fewer instructions at 0.9.3, wall clock waits for a quiet run |
| `client_address` | 3-hop `X-Forwarded-For`, IPv4 | 37.6 ns | no Rust crate resolves through trusted proxies | n/a | estimate 60 ns: met |
| `mail::encode_words` | 36-byte UTF-8 subject (PLAN row: 40 bytes) | 176 ns | no allocation-free Rust encoder | n/a | estimate 200 ns: met |
| `mail::encode_words_base64` | the same subject; 39 bytes of Japanese | 92.2 ns; 103 ns (`encode_words` 131 ns) | no allocation-free Rust encoder | n/a | none set |
| `param::parse_optional` and `find` | `; client_max_window_bits; server_no_context_takeover` | 29.2 ns | no Rust crate reads RFC 6455 extension parameters as a library call; `param::parse` and `get` on the same names with values, 24.6 ns | n/a | none set |

parse-net validates every byte of the field in these rows (where it has been
compared, it is the stricter side: `mime` accepts values parse-net refuses,
`tests/differential/verdicts.md`), and none of its numbers include an
allocation.

The numbers are from one run of the whole suite at 0.9.1 on a quiet machine
(load average 0.7 to 2.0 on 32 threads), the first since 0.7. Every row is
faster than at 0.9.0, whose run shared the machine with other builds. The
percentages moved little, except `parse_response_cache_control`: `headers` gained
more from the quiet machine than parse-net did, and the row reads 25% where
the loaded run read 33%. It is the narrowest row, above the 20% target, and
is on the list for the release candidates.

`B` is the shorter encoding for text that is mostly not ASCII, and the
faster: the Japanese subject is one 64-byte word in `B` and two words, 144
bytes, in `Q`. The
`parse_optional` row reads 4.6 ns more than `parse` on the valued list:
`find` walks the list through the iterator, where `Params::get` skips the
names it does not want.

## What 0.10.0 changed

Instructions per call (callgrind), 0.9.3 against 0.10.0 built side by side
from the same driver: every row within one instruction of 0.9.3 (the renames
change no code path), except negotiation, which issue #14's fixes rewrote.
`best_media` on the browser `Accept` 10,861 to 10,702 (-1.5%), on four ranges
with parameters 8,014 to 7,959 (-0.7%), and `best_language` on five ranges
10,547 to 9,990 (-5.3%). Lookup no longer ranks every range against every
offer twice over; the media check walks the parameters on each side of `q`
on its own, and the parameter split is inlined.

The security fixes of 0.10.0, in the same measure: `client_address` 1,314 to
913 (-30.5%) for a 3-hop `X-Forwarded-For` and 5,350 to 3,077 (-42.5%) for a
2-element `Forwarded`, since it now stops at the client;
`parse_response_cache_control` 835 to 801 (-4.1%), the walk handing
directives to a visitor; `mail::parse_mailbox` 1,622 to 1,562 (-3.7%).
`parse_content_disposition` costs 2.9% to 3.2% more (3,597 to 3,703 with
`filename*`, 2,370 to 2,445 for a `form-data` part): two byte searches for
the `*` of an RFC 2231 continuation, which it now refuses. A full walk over
the parameters for the same check cost 7%.

## What 0.9.3 changed

Instructions per call (callgrind), 0.9.2 against 0.9.3:
`parse_response_cache_control` on `public, max-age=31536000, immutable` 881 to 823
(-6.6%). The directive names were compared a byte at a time after the
length had picked the candidate; the length is a constant there, so the
name is now compared as two or three overlapping words with `0x20` OR-ed
into every byte of a word at once (a test checks it against the byte rule
for every name, every position, and every byte value). Skipping whitespace
after a directive only when there is some saved 4 more and was left out.
The `decode_phrase` fix reads one byte, and only for an atom that starts
with `=?`: 3,179 to 3,180 on two `Q` words, 1,204 to 1,197 on a quoted name
with a comment. `write_mime_param_at` on the file name after
`Content-Disposition: attachment`: 2,324 to 2,300.

## What 0.9.2 changed

Instructions per call (callgrind), 0.9.1 against 0.9.2 built side by side:
`write_mime_param` on a 44-byte quoted file name 3,271 to 2,292 (-30%), on
a non-ASCII one 2,088 to 1,974 (-5.5%); `decode_words` on two `Q` words
5,462 to 5,295 (-3%). `decode_words` on `B` words, `encode_words`, and
`encode_words_base64` stayed within 0.5%. The quoted form now writes the runs
between escapes whole, an ASCII value's controls are checked a byte at a time
rather than a `char` at a time, the one-line form is chosen once for both of
the writer's passes, and a `Q` word's plain bytes go out as one run.

The new calls: `decode_phrase` on `"Doe, Jane" (Sales)` 1,204 instructions
(1,802 before its ASCII words went out whole), on two `Q` words 3,179;
`write_mime_param_at` on the file name after `Content-Disposition:
attachment` 2,324.

The wall-clock rows for 0.9.2 wait for a quiet machine: the run of
2026-11-06 shared the host with other builds (load average 350 on 32
threads, every row about ten times its 0.9.1 time). Read on that run and on
Windows under load, `parse_mailbox` and `decode_phrase` together took 31% to
47% of the time `mailparse::addrparse` takes for the mailbox and its display
name (a quoted name with a comment, and two `Q` words), which allocates
`String`s; the ratio is kept for the table until the quiet run.

## What 0.9.1 changed

Instructions per call (callgrind), 0.9.0 against 0.9.1 built side by side:
`param::parse` 1,009 to 1,012, four valued names 671 to 670,
`parse_media_type` 747 to 749, `Content-Disposition` 3,601 to 3,604, Q
decoding 5,420 to 5,408, Q encoding 5,717 to 5,722. Those are code layout,
not new work: `client_address`, whose code did not change, moved 1,304 to
1,321. The `parse_optional` branch is compiled out of `parse` (D-079).

Two things were measured and fixed on the way. Moving the Q encoder's
plain-text test into a function shared with the `B` encoder cost it 136
instructions (2.4%), so `put_words` keeps its own copy. The first `B`
decoder, byte by byte, took 481 ns against `mailparse`'s 442 ns: a word that
passes every check now goes out in one piece, and the base64 groups are read
four characters to a table lookup, which brought it to 145 ns.

## What 0.9 changed

Instructions per call (callgrind), which other builds do not disturb:

| Operation | 0.8 | 0.9 | Change |
|---|---|---|---|
| `byte_ranges` | 815 | 197 | -76% |
| `client_address` | 3,193 | 1,289 | -60% |
| `parse_content_disposition` and `filename` | 4,014 | 3,585 | -11% |
| `parse_media_type` and `charset` | 797 | 729 | -9% |
| `parse_response_cache_control` | 884 | 881 | flat |

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
| `parse_response_cache_control` | 47.8 ns (19% faster than `headers`) | 41.2 ns (31% faster) | 922 to 884 |
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
| `parse_response_cache_control` | 1,084 | 925 | -15% |
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
