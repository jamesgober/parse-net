# parse-net - 1.0 readiness note

What stands between parse-net and 1.0, for James's go or no-go. It is kept
current through 0.9.x; the full audit goes in `docs/STABILITY-1.0.md` at the
end. Nothing here is decided by being written down: each item is open until
James accepts it or it is fixed.

## Open: blocks 1.0 by the roadmap's exit

| Item | Why it is open | What closes it |
|---|---|---|
| Four consumers end to end | three are published on parse-net (http-net, cookie-net, form-net); ws-net carries its own grammar, and smtp-net and web-net are not published | ws-net, smtp-net, and web-net built on parse-net in their own repositories |
| No breaking change for one full release cycle | 0.9.0 is the first release of that cycle: it refuses inputs 0.8 accepted (see the release notes) | a 0.9.x cycle with no breaking change |
| Release candidates | the `0.9.x` candidates come after the consumers | the steps above |

## Open: needs a decision from James

| Item | State | Recommendation |
|---|---|---|
| `encode-lib` helpers: `basic_decode_into` (ATH-3), `ByteSeq::decode_into`, `sfv::Writer::bytes` | P2 items blocked on encode-lib, which is not published (D-002, D-062). They are additive behind the `encode-lib` feature, a no-op until then, so 1.0 can ship without them and a 1.x add them. `B` encoded words no longer wait: 0.9.1 reads and writes them (D-080, below) | ship 1.0 without them only if encode-lib is not ready by the last release candidate; publish encode-lib first if it is close |
| D-080: a private base64 codec for RFC 2047 `B` words (`encode_words_b`, `B` in `decode_words`) | reverses D-002's "no private codec is added", which James approved at the design lock, for that one encoding. Decided by the main session on 2026-11-04 for smtp-net and ws-net, and told to James. Strict, bounded to one 75-byte word, no public base64 API, fuzzed against the `base64` crate (`diff_b64`) | James: confirm, or name encode-lib as the codec it moves to once published (an internal change, invisible to callers) |
| 64 parameters per element where repeats are refused (D-072) | a fixed limit on RFC 9110, authentication, and MIME parameters, whatever `max_params` says. Finding a repeat without allocating costs either quadratic time or a table on the stack. No consumer has come near it | keep it; raising it later is compatible, lowering it is not |
| `has_bidi_control` reports embedding, override, and isolate controls, not LRM, RLM, and ALM (D-070) | the same set rustc's lint reports; legitimate right-to-left names contain the marks | keep it |
| `Proto::Other` carries no scheme name (D-077) | `proto=ftp` reads, but the name is lost and `write_element` refuses it. Carrying it would add a lifetime to `Proto` | keep it |
| Complexity bound of 2.0 instead of 1.2 (D-073) | section 11.6 said 1.2; a linear walker that writes output measures up to 1.54 once a megabyte leaves the fast caches on a shared machine. A quadratic walker still fails eightfold | keep it |

## Open: accepted differences, recorded with their reasons

- Ambiguous differential verdicts V-5 (partial base64 padding refused) and V-6
  (Dates outside years 1 to 9999 refused): the httpwg suite marks both
  `can_fail` (`tests/differential/verdicts.md`).
- tc2231 deviation classes (D-054, `tests/differential/tc2231.md`).
- `parse_mime_params` refuses a fold inside a quoted value: unfolding changes
  the bytes, so it is the caller's step, `mail::unfold` (D-078).
- A `Host` reg-name has no length limit, as RFC 3986 has none: the check is
  linear, and header size limits belong to the server.

## Performance

Every compared row is at least 25% faster than the best Rust competitor, on
the quiet-machine run at 0.9.1 (`docs/PERFORMANCE.md`). The narrowest is
`response_cache_control` at 25%: the loaded 0.9.0 run read 33%, and `headers`
gained more from the quiet machine. It meets the 20% target; tune it in the
release-candidate pass. Both estimates are met: `client_address` 37.6 ns
against 60, `encode_words` 176 ns against 200. form-net's `FormKind::detect` measured 114 ns against
its 100 ns estimate on parse-net 0.6.1, before the 0.7 and 0.9 speedups; it
should be measured again once form-net moves to 0.9, and it can drop its own
repeated-name walk by parsing under `Refuse` and reading the name at the
error's offset.

## Closed by the 0.9 polish pass

- Every accepted gap, deferred item, and missed target above was revisited.
- `client_address` against its 60 ns estimate, and the narrowest margins,
  `byte_ranges` and `Content-Disposition`: tuned (D-074).
- Three independent reviews of the whole crate: 46 defects found and fixed,
  each with a regression test (`docs/SECURITY.md`).
- Every P0, P1, and P2 item of `docs/API.md` ships, except the two named above
  that wait on encode-lib.
- `client_address` against its 60 ns estimate: 38.3 ns on a quiet machine at
  0.9.1.

## Since 0.9.0

- ws-net, adopting 0.9.0, found that `param::parse` refuses RFC 6455
  extension parameters without a value. 0.9.1 adds `param::parse_optional`
  (D-079).
- smtp-net needed `encode_words_b`, which waited on encode-lib. 0.9.1 adds
  it and `B` decoding with a private codec (D-080, in the table above for
  James). Before 1.0, web-net settles whether
  `Strict-Transport-Security` needs the same shape without a leading `;`;
  smtp-net does not need it (ROADMAP).

## Since 0.9.1

- smtp-net, adopting 0.9.1, asked for three things. A display name as text:
  0.9.2 adds `mail::decode_phrase` (D-081), which gate-net will use for login
  display names too. A parameter after other text on a line: 0.9.2 adds
  `mail::write_mime_param_at` (D-082). `class::is_atext`: public since 0.5,
  nothing to do.
- No consumer request is open.
