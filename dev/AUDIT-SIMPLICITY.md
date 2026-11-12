# parse-net - simplicity audit (0.9.3, for 0.10.0)

James, 2026-11-11: the API may be simplified before 1.0, renames and
signature changes included. This audit checks the public API of `0.9.3`
(575 public items, 108 free functions, 24 modules) against the library
standard's API rules: Tier 1 one-liners with no builder or configuration that
work with plain `?`, names a newcomer can read without the documentation, one
way to do each thing, and `docs/API.md` covering every public item. Fixes ship
in `0.10.0` with a migration table (`docs/MIGRATION.md`); there are no
deprecated aliases.

## What passes

- **The HTTP Tier 1.** One call per field, plain `?`, no configuration:
  `parse_media_type`, `parse_host_port`, `parse_origin`,
  `parse_content_disposition`, `best_media` and its siblings, `if_none_match`,
  `if_match`, `byte_ranges`, `client_address`, `bearer`, `basic`,
  `sfv::parse_item`. Each returns a view or an answer; none needs a builder,
  a type parameter, or a `Limits`.
- **Errors.** One `ParseError` (kind and offset) for every parse and one
  `WriteError` for every writer, both `core::error::Error`, so `?` works into
  `Box<dyn Error>` and into the caller's own error type.
- **Writers.** Every writer is `write_x(value, out)` over one `Sink` trait,
  with `SliceSink` and `CountSink`; a refused write leaves the sink as it
  was.
- **Tiers.** Each module's full surface is `module::parse(value, &limits)`
  beside its Tier 1 call (`media::parse` beside `parse_media_type`), which is
  the standard's Tier 3, not a second way.
- **Answer functions.** Functions named for their answer (`best_media`,
  `if_none_match`, `byte_ranges`, `client_address`, `bearer`) return the
  answer, not a view, and read well as they are.

## Findings

| # | Rule | Finding | Fix in 0.10.0 |
|---|---|---|---|
| S-1 | readable names, one way | Root parsers are named two ways: `parse_media_type`, `parse_host_port`, `parse_origin`, `parse_link`, `parse_content_disposition`, against `list`, `http_date`, `http_date_at`, `response_cache_control`, `request_cache_control`. A newcomer who has met `parse_media_type` guesses `parse_list` and finds nothing | every root function that returns a view of a field is `parse_*`: `parse_list`, `parse_http_date`, `parse_http_date_at`, `parse_response_cache_control`, `parse_request_cache_control`. Answer functions keep their names |
| S-2 | Tier 1 without configuration | Two root functions need a `Limits`: `parse_link(value, &limits)` and `parse_condition(value, &limits)` | `parse_link(value)`; the limits form is `link::parse(value, &limits)`, as in `media`. `parse_condition` leaves the root, since `if_match` and `if_none_match` are the Tier 1 for those fields; the limits form is `etag::parse(value, &limits)` |
| S-3 | Tier 1 without configuration | Email has no call without a `Limits`: `mail::parse_mailbox(value, &limits)`, `mail::decode_words(value, &limits, out)`, `mail::decode_phrase(value, &limits, out)`, the three calls a mail client makes most | `mail::parse_mailbox(value)`, `mail::decode_words(value, out)`, `mail::decode_phrase(value, out)`; each with a `_with_limits` form taking `&Limits` |
| S-4 | one way | `HttpDate::parse_at(value, now)` is `http_date_at(value, now)` under a second name | `HttpDate::parse_at` goes; `parse_http_date_at` is the call. `HttpDate::parse_at_with(value, now, &limits)` becomes `HttpDate::parse_with_limits`, the suffix every limits form uses |
| S-5 | readable at the call site | `MailDate::parse(value, false)`: the `bool` says nothing where it is read | `MailDate::parse(value)` reads RFC 5322 section 3.3; `MailDate::parse_obsolete(value)` also takes the obsolete forms of section 4.3 |
| S-6 | no abbreviations | `mail::encode_words_b`: `B` is RFC 2047's letter for base64 | `mail::encode_words_base64` |
| S-7 | no abbreviations | Module `pct`, function `pct::decode_lower_only_into` | module `percent`; `percent::decode_lowercase_into` (refuses uppercase hex) |
| S-8 | no abbreviations | Module `sfv` | module `structured` (RFC 9651 Structured Field Values) |
| S-9 | no abbreviations | `ExtValue`, `write_ext_value`, module `ext_value` (RFC 8187's `ext-value`) | `ExtendedValue`, `write_extended_value`, module `extended_value` |
| S-10 | no abbreviations | `forwarded::XffChain` | `forwarded::XForwardedFor`, named for its field as `ContentDisposition` is |
| S-11 | one way to name | Several-line forms are named three ways: `list::combined(lines, &limits)`, `cache::response_lines(lines)` and `cache::request_lines(lines)`, `sfv::parse_list_lines(lines)` | `list::parse_lines`, `cache::parse_response_lines`, `cache::parse_request_lines`, `structured::parse_list_lines` |
| S-12 | Tier 1 documented first, runnable | The crate documentation and the README end Tier 1 with a ` ```text ` block that says the calls "arrive with 0.4.0 and 0.5.0"; they shipped in 0.4 and 0.5, and the block is not compiled. Neither shows an email call | one compiled Tier 1 block in both, with the email calls |
| S-13 | `docs/API.md` | The header says "Current release: `0.5.0`" and reads as the 0.2 design contract (grades, item ids, "specified here and not yet in the crate"). It lacks the metrics-lib layout's title block and navigation, and nothing checks that it covers every public item | the metrics-lib title block and navigation, the current release, the naming rule, every public item named (checked by script before each release), and the design ids and grades explained as links to `dev/PLAN.md` |

## Kept, with the reason

- `list::for_each(value, &limits, f)`: a Tier 3 one-pass walk, the fastest
  way to visit a list once (D-045). It is the one call that hands out
  elements before the whole value is checked, which its documentation says
  first.
- `date::days_from_civil`, `civil_from_days`, `Civil`: "civil date" is the
  calendar term these algorithms are known by; http-net and cookie-net call
  them, and a rename would not make them clearer.
- `QValue`: `q` is the parameter name on the wire (`q=0.5`), the word a
  reader looks for.
- `range::resolve(header, length, coalesce, &limits, out)` keeps its `bool`:
  Tier 3 for servers that coalesce, beside `byte_ranges`, the Tier 1.
- `EntityTag::parse`, `QValue::parse`, `ExtendedValue::parse`: one element,
  not a field, is read by its type's `parse`; a field value is read by a free
  `parse_*`. The rule is written in `docs/API.md`.
- `param::parse`, `param::parse_optional`, `mail::parse_mime_params`,
  `text::parse_*` return the bytes used beside the view: they read
  parameters or words that follow other text, and the caller needs to know
  where they stopped.

## Dependents

| Crate | Uses that change |
|---|---|
| ws-net | `parse_net::list(value)` becomes `parse_list(value)` (S-1) |
| web-net | `http_date` becomes `parse_http_date` (S-1) |
| smtp-net | `encode_words_b` becomes `encode_words_base64` (S-6); `parse_mailbox`, `decode_words` lose their `&Limits` argument or move to `_with_limits` (S-3) |
| form-net | `ExtValue` becomes `ExtendedValue`, `Charset` stays (S-9) |
| http-net | none: it calls `class`, `scan`, `date::civil_from_days`, `weekday_from_days`, `HttpDate::from_unix` |
| cookie-net | none: it calls `class`, `scan`, `date`, `Sink`, `SliceSink`, `CountSink`, `Full`, `HttpDate` |
