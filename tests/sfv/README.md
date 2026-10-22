# RFC 9651 conformance suite

The JSON files here are the parsing tests of
[httpwg/structured-field-tests](https://github.com/httpwg/structured-field-tests)
at commit `3c6d77618d9d4c73e107fd7b90f15026675457b1`, unmodified, under the
license in [LICENSE.md](LICENSE.md). `tests/sfv_conformance.rs` runs every
case. Neither is part of the published crate.

To update: download the same files at a newer commit, change the commit here,
and update the case counts in `tests/sfv_conformance.rs`.

Optional (`can_fail`) cases that parse-net refuses:

| Case | Why |
|---|---|
| binary: partially padded | Padding, when present, completes the last quantum. |
| binary: extra padding | As above. |
| date: syntactic max date | Outside years 1 to 9999, the range every date type here shares (D-030). |
| date: syntactic min date | As above. |
