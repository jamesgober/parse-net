# Security

What parse-net defends against, how each defence is tested, what it costs,
and what it leaves to the caller. The threat table is the one in
[`dev/PLAN.md` section 9](../dev/PLAN.md#9-threats); this page adds where
each test lives and the measured cost.

## Reporting a vulnerability

Email **me@jamesgober.com** with a description, an input that shows the
problem if you have one, and the affected versions. Please do not open a
public issue for a security report. Expect an acknowledgement within three
days; a confirmed issue gets a fixed release and a note in the CHANGELOG
and the release notes.

A finding counts if a parse-net function, given any input, panics,
allocates (in a parse), reads or writes out of bounds, takes time that grows
faster than its input, accepts what the RFC forbids where the documentation
says it refuses, or lets a writer emit CR, LF, or NUL.

## Trust boundaries

Every input is untrusted: field values, parameters,
`Content-Disposition` file names, `Forwarded` and `X-Forwarded-For` chains,
encoded words, and Structured Fields all arrive from the peer. parse-net
holds no state, performs no I/O, and allocates nothing in any parse, so the
only resources an input can consume are the caller's stack (bounded, no
recursion) and time (linear, bounded by [`Limits`](API.md)).

What the caller decides, and parse-net only reports:

- **Which proxies are trusted.** `client_address` reads `Forwarded` or
  `X-Forwarded-For` only from a peer the caller marks trusted (`Trust`), and
  walks from the right; the caller supplies the trust list.
- **What to do with a suspicious file name.** `Filename::has_path_separator`
  and `has_bidi_control` report; whether to rename, refuse, or keep the name
  is the application's policy.
- **Which limits fit the deployment.** Every default meets the RFC minimums;
  raising a limit raises the work an input can cause, linearly.

## Threats and defences

| Id | Threat | Defence | Tests | Cost |
|---|---|---|---|---|
| T1 | header injection through a written value | every writer validates as it writes; CR, LF, NUL, and the other controls are refused, and a refused write leaves the sink as it was | `write::tests::test_writers_refuse_crlf_in_every_position` (every writer, every byte 0x00 to 0x1F and 0x7F) | the field-value scan: 5.4 ns for 64 bytes (`docs/PERFORMANCE.md`) |
| T2 | decoded control bytes re-emitted (`%0D%0A` in an ext-value, `=0D=0A` in an encoded word) | every decoder refuses a decoded control character with `ControlInDecoded`: C0 (HTAB included), DEL, and C1, in ext-values, RFC 2231 parameters, and encoded words (D-071) | `ext_value::tests::test_ext_value_percent_crlf_refused`; `threats.rs`: `test_encoded_word_crlf_refused`, `test_basic_credentials_ctl_refused` | one comparison per decoded byte |
| T3 | a comma inside a quoted string split by one parser and not another | the list walker is quote- and comment-aware; an unterminated quote refuses the field | `list::tests::test_list_comma_in_quotes_is_one_element`; the property tests split and rejoin lists | none |
| T4 | a repeated parameter read first by one component and last by another | `DuplicatePolicy::Refuse` by default; RFC rules applied where they differ (`filename` and `filename*` are different names) | `threats.rs`: `test_content_disposition_duplicate_filename_refused`, `test_media_type_duplicate_charset_refused`, `test_repeat_checks_compare_whole_names` | a name table on the stack, at most 64 names per element (D-072) |
| T5 | case differentials (`Charset`, `w/`, `bearer`) | case rules per RFC, from one table | `threats.rs`: `test_case_rules_table` | none |
| T6 | whitespace differentials (VT, FF, NBSP) | OWS is SP and HTAB only; anything else is refused or kept, never stripped | `text::tests::test_trim_ows_never_strips_vt_ff_nbsp`; `threats.rs`: `test_utf8_nbsp_prefix_not_trimmed` | none |
| T7 | `filename` and `filename*` precedence; an invalid `filename*` ignored by one component | `filename*` is preferred when valid; an invalid `filename*` refuses the field rather than falling back | `threats.rs`: `test_invalid_filename_star_refuses_field` | none |
| T8 | several field lines combined differently | the `combined` and `*_lines` functions read every line as one list | `properties.rs`: `test_combined_equals_joined` | none |
| T9 | quadratic work (nested comments, many parameters, many members, `Accept` members times offers) | counters and limits checked before the work; single-pass walkers; repeated-name checks compare names from a bounded table (D-072) | `complexity.rs`: `test_complexity_linear`, every walker at 1 KiB, 64 KiB, and 1 MiB | a counter per element |
| T10 | stack exhaustion through nesting | no recursion anywhere; comment depth is a counter | `text::tests::test_comment_depth_limit_plus_one_refused` (depth 10,000) | none |
| T11 | integer overflow (ranges, delta-seconds, Structured Field integers, `Content-Range`, q-values) | checked arithmetic; saturation only where the RFC says (delta-seconds at 2^31) | `threats.rs`: `test_range_u64_max_plus_one`, `test_delta_seconds_saturates`, `test_sf_integer_16_digits_refused` | none |
| T12 | range requests that amplify work or output | at most 16 ranges by default; overlapping or disordered sets are answered with `Ignore` | `range::tests::test_range_17_ranges_ignored`, `test_range_three_overlapping_ignored` | `byte_ranges` 28 ns for one range |
| T13 | client address spoofing through `X-Forwarded-For` | the header is ignored unless the peer is trusted; the chain is walked from the right; a malformed chain fails closed | `forwarded::tests::test_xff_untrusted_peer_ignored`, `test_xff_leftmost_spoof_ignored`, `test_xff_malformed_fails_closed` | `client_address` 110 ns for three hops |
| T14 | `Forwarded` and `X-Forwarded-For` present and disagreeing | one source chosen by configuration, never merged; the other is reported | `forwarded::tests::test_both_forwarded_headers_reported` | none |
| T15 | host confusion (`a.com:80@b.com`, `127.1`, mapped IPv6, a trailing dot) | userinfo refused; partial IPv4 refused; mapped IPv6 returned as IPv6; a trailing dot kept | `host::tests::test_host_userinfo_refused`, `test_host_partial_ipv4_refused` | none |
| T16 | `Origin` tricks (`null`, suffix hosts, a trailing slash, case) | the exact grammar; whole-host comparison | `origin::tests::test_origin_suffix_attack_not_same`, `test_origin_trailing_slash_refused` | none |
| T17 | file name tricks (`../`, `\`, NUL, overlong UTF-8, bidi overrides) | controls and invalid UTF-8 refused; separators and the embedding, override, and isolate controls (U+202A to U+202E, U+2066 to U+2069, the set rustc's `text_direction_codepoint_in_literal` lint reports; D-070) reported | `disposition::tests::test_filename_nul_refused`, `test_filename_overlong_utf8_refused`; `threats.rs`: `test_filename_bidi_reported` | only when asked: one pass over the name |
| T18 | charset confusion in an ext-value | only the declared charset (UTF-8 or ISO-8859-1); anything else refused | `ext_value::tests::test_ext_value_charset_matrix` | none |
| T19 | Unicode attacks in Display Strings and encoded words | strict UTF-8: surrogates, overlong forms, and code points above U+10FFFF refused | `threats.rs`: `test_display_string_surrogate_refused` | none |
| T20 | date differentials (weekday, `Feb 30`, two-digit years, a leap second, the zone) | a strict calendar; the 50-year rule with an explicit `now`; only `GMT` | `date::tests::test_http_date_rejections_table` | none |
| T21 | `Authorization` confusion (two schemes, repeated parameters) | one credential per field; repeated names refused; `Debug` prints the scheme only | `auth::tests::test_credentials_debug_redacted`; `threats.rs`: `test_auth_duplicate_param_refused` | none |
| T22 | log injection through error messages | an error carries its kind and an offset, never input bytes | `threats.rs`: `test_error_display_contains_no_input`; every fuzz target checks each error it sees | none |
| T23 | memory exhaustion | no parse allocates | `no_alloc.rs` (a counting allocator over every parser); every fuzz target runs under it | none |
| T24 | base64 differences in Structured Field byte sequences | RFC 9651 section 4.2.7: missing padding and non-zero pad bits read; partial or extra padding refused | `threats.rs`: `test_sf_byteseq_padding_rules` | none |
| T25 | Unicode smuggled into tokens or names | the byte classes are ASCII; bytes above 0x7F appear only as obs-text inside values | `class::tests::test_tchar_table_exhaustive` | none |

Unit tests are named `module::tests::name` (in `src/`); the others are in
`tests/`.

## Resource bounds

Every parse is bounded by [`Limits`](API.md) (defaults in the `Limits`
documentation, each at or above the RFC minimum) and walks its input once.
The complexity tests check both halves for every walker: under the default
limits a 1 MiB adversarial input stops with the expected limit error, and
with every limit at its maximum the time grows with the input, within 1.2 of
the size ratio.

One bound is fixed rather than configurable: a parameter list that refuses
repeated names (RFC 9110 parameters under `DuplicatePolicy::Refuse`,
authentication parameters, MIME parameters) holds at most 64 parameters per
element, `param::MAX_CHECKED_PARAMS`. Finding a repeat without allocating
means comparing each name with the earlier ones; a table of their offsets
on the stack makes that a comparison of short names, never a second read of
the field. Before 0.7 the check read every earlier parameter again, so a
field of many parameters cost the square of its length (D-072).

## Fuzzing

34 cargo-fuzz targets cover every parser, every writer's round trip, and
three differential comparisons (`diff_http_date` against `httpdate`,
`diff_media_type` against `mime`, `diff_sfv` against `sfv`). Each of the 31
parser targets runs under the counting allocator (a parse that allocates
fails the run), checks that every error it sees prints as exactly its kind's message and
position, with no input bytes, and asserts the properties its parser
documents; the differential targets compare results instead, since the
crates they call allocate. Every target runs
24 hours clean before a release that changes parsing code (0.7 onward); the
differential targets run every week in CI (`.github/workflows/fuzz.yml`).
Corpora live outside the repository; the seeds are in `fuzz/seeds/`.

## Differential verdicts

Every disagreement with another implementation is recorded in
[`tests/differential/verdicts.md`](../tests/differential/verdicts.md) with a
verdict: ours right, theirs right (a parse-net bug, fixed test-first), or
ambiguous with the RFC text. None is open as "theirs right". In summary:

- `httpdate`: parse-net applies RFC 9110's 50-year rule to two-digit years,
  reads dates before 1970, and refuses VT, FF, CR, and LF around a date
  where `httpdate` strips them (threat T6).
- `sfv`: parse-net refuses partial base64 padding, Dates outside years 1 to
  9999, and input beyond its limits; `sfv` accepts all three. The first two
  are marked `can_fail` by the httpwg suite; the third is threat T9.
- `mime`: parse-net is stricter by design (repeated parameters, whitespace
  around `=`, control bytes, `*` in a `Content-Type`); where both accept,
  both read the same essence.

## Not covered

- **Base64 decoding** of `Basic` credentials and Structured Field byte
  sequences waits for encode-lib (D-002): the text is validated, not
  decoded.
- **TLS, authentication, and authorization** are the caller's: parse-net
  reads credentials and reports what they say.
- **Policy**: which file names to accept, which proxies to trust, and which
  limits to use are decisions parse-net reports on and never makes.
