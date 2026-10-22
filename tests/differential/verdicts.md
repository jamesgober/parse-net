# Differential verdicts

Disagreements between parse-net and other implementations found by the differential fuzz targets (`fuzz/fuzz_targets/diff_*.rs`) and the conformance runs. Each has a verdict: **ours right**, **theirs right** (a parse-net bug, fixed test-first), or **ambiguous** (with the RFC text). An open "theirs right" blocks a release.

| Id | Found | Against | Input class | parse-net | Other | Verdict |
|---|---|---|---|---|---|---|
| V-1 | 0.3.0 | `httpdate` 1.0.3 | RFC 850 date with a two-digit year from 70 to 76, such as `Thursday, 01-Jan-76 00:00:00 GMT` read in 2026 | 2076 | 1976 (fixed pivot at 70) | **ours right**: RFC 9110 section 5.6.7 says a recipient "MUST interpret a timestamp that appears to be more than 50 years in the future as representing the most recent year in the past that had the same last two digits"; 2076 is less than 50 years ahead of 2026, so it stays 2076. The fuzz target skips RFC 850 input so this known class does not stop the run |
| V-2 | 0.3.0 | `httpdate` 1.0.3 | any valid date before 1970 | accepted | refused (its range is 1970 to 9999) | **ours right**: HTTP-date has no lower bound; parse-net supports years 1 to 9999, the RFC 9651 Date range |
| V-3 | 0.3.0 | `httpdate` 1.0.3 | a valid date with leading or trailing SP or HTAB | accepted | refused | **ours right**: field values are compared without surrounding OWS (RFC 9110 section 5.5), and every parse-net function strips SP and HTAB, so a caller passing an unstripped value gets the same answer as one passing a stripped value |
| V-4 | 0.3.0 | `httpdate` 1.0.3 | a valid date with leading or trailing VT, FF, CR, or LF (first found: `\x0c\x0c\x0cThu Oct  6 08:32:37 1994`) | refused | accepted (it trims every ASCII whitespace byte) | **ours right**: VT, FF, CR, and LF are not OWS and are not allowed in a field value (RFC 9110 section 5.5); stripping them silently is the whitespace differential of threat T6 |
| - | 0.3.0 | `mime` 0.3.17 | `type/a+b` with a structured syntax suffix | n/a | n/a | not a disagreement: `mime::Mime::subtype` returns the subtype without its `+suffix`, so the target first compared different things; it now compares the whole essence |

parse-net is stricter than `mime` by design (duplicate parameters, whitespace around `=`, control bytes, `*` in a `Content-Type`); the media-type target asserts only that where both accept, both read the same essence.
