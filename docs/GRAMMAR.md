# Grammar

For each field parse-net reads: the ABNF from its RFC, how case is treated,
any leniency parse-net applies or declines and the RFC text behind it, and the
function that parses it. ABNF is quoted from the RFCs (IETF Trust; code
components under the Revised BSD License). Where a parse-net rule is stricter
or looser than the ABNF, the row says so and why; nothing is lenient without a
sentence from the RFC that asks for it.

Rules every parser shares:

- Field values arrive without surrounding whitespace, and every parser strips
  SP and HTAB (only those) from both ends anyway: "A field value does not
  include leading or trailing whitespace. When a specific version of HTTP
  allows such whitespace to appear in a message, a field parsing
  implementation MUST exclude such whitespace prior to evaluating the field
  value." (RFC 9110 section 5.5). VT, FF, CR, LF, and NUL are refused, never
  stripped (threat T6).
- A control byte is reported as `BareCr`, `LineFeed`, `Nul`, or `Control`
  wherever it occurs, including inside quoted strings and comments (D-037).
- Bytes above 0x7F are accepted only where the grammar has `obs-text`.

Contents: [lexical elements](#lexical-elements), [lists](#lists),
[parameters](#parameters), [media types](#media-types-and-ranges),
[negotiation](#accept-fields), [dates](#http-date), [Host](#host),
[percent-encoding](#percent-encoding), [entity tags](#entity-tags-and-conditions),
[ranges](#ranges), [ext-value](#ext-value), [Content-Disposition](#content-disposition),
[Cache-Control](#cache-control), [Forwarded](#forwarded), [X-Forwarded-*](#x-forwarded-),
[authentication](#authorization-and-www-authenticate), [Origin](#origin),
[Structured Fields](#structured-field-values), [Link](#link),
[email dates](#email-dates), [email header values](#email-header-values),
[encoded words](#encoded-words), [MIME parameters](#mime-parameters),
[addresses and message identifiers](#addresses-and-message-identifiers).

## Lexical elements

RFC 9110 sections 5.6.2 to 5.6.5.

```abnf
token          = 1*tchar
tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
               / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
               / DIGIT / ALPHA
OWS            = *( SP / HTAB )
RWS            = 1*( SP / HTAB )
BWS            = OWS
quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE
qdtext         = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )
comment        = "(" *( ctext / quoted-pair / comment ) ")"
ctext          = HTAB / SP / %x21-27 / %x2A-5B / %x5D-7E / obs-text
obs-text       = %x80-FF
```

- Case: tokens are compared as the field defines; `Quoted::eq_ignore_ascii_case`
  and `Word::eq_ignore_ascii_case` exist for fields that say so.
- A token and a quoted string with the same content are equal: "The quoted
  and unquoted values are equivalent." (section 5.6.6).
- Comments nest; the depth is limited by `Limits::max_comment_depth`
  (`CommentTooDeep`), because the grammar is recursive and the input is not
  trusted.
- Functions: `text::parse_token`, `parse_quoted`, `parse_word`,
  `parse_comment`, `trim_ows`, `skip_ows`, `is_token`.

## Lists

RFC 9110 section 5.6.1.

```abnf
#element => [ element ] *( OWS "," OWS [ element ] )
```

- Empty elements are skipped, up to `Limits::max_empty_elements` (default
  16), then `TooManyEmptyElements`: "A recipient MUST parse and ignore a
  reasonable number of empty list elements: enough to handle common mistakes
  by senders that merge values, but not so much that they could be used as a
  denial-of-service mechanism." (section 5.6.1.2).
- Commas inside quoted strings and comments do not split.
- Several field lines are read as one list joined by commas (section 5.3);
  `list::combined` does this without copying.
- Functions: `list`, `list::combined`, `list::contains_token`,
  `list::for_each`.

## Parameters

RFC 9110 section 5.6.6.

```abnf
parameters      = *( OWS ";" OWS [ parameter ] )
parameter       = parameter-name "=" parameter-value
parameter-name  = token
parameter-value = ( token / quoted-string )
```

- Case: "Parameter names are case-insensitive. Parameter values might or
  might not be case-sensitive, depending on the semantics of the parameter
  name."
- No whitespace around `=`: "Parameters do not allow whitespace (not even
  "bad" whitespace) around the "=" character." `a = b` is refused.
- Empty parameters (`;;`, a trailing `;`) are accepted, as the `[ parameter ]`
  in the rule allows.
- A repeated name is refused by default (`DuplicateParameter`, threat T4);
  `DuplicatePolicy::First` and `Last` exist for fields whose RFC picks one.
- Function: `param::parse`, with `Params::get`, `iter`, `len`.

## Media types and ranges

RFC 9110 sections 8.3.1 and 12.5.1.

```abnf
media-type  = type "/" subtype parameters
type        = token
subtype     = token
media-range = ( "*/*" / ( type "/*" ) / ( type "/" subtype ) ) parameters
```

- Case: "The type and subtype tokens are case-insensitive." The `charset`
  value is compared case-insensitively too (section 8.3.1, citing RFC 2046
  section 4.1.2).
- `parse_media_type` refuses `*` as type or subtype (`Wildcard`): a
  `Content-Type` names one type. `media::parse_range` accepts `*/*` and
  `type/*` and refuses `*/subtype`, which the rule does not produce.
- In a media range, parameters after `q` are accept extensions, ignored for
  matching.
- `boundary` follows RFC 2046 section 5.1.1 (1 to 70 characters from its
  `bchars`, not ending in a space): `MediaType::boundary`.
- Functions: `parse_media_type`, `media::parse`, `media::parse_range`,
  `MediaRange::matches`, `media::write`.

## Accept fields

RFC 9110 sections 12.4.2 and 12.5; RFC 4647 section 2.1.

```abnf
weight          = OWS ";" OWS "q=" qvalue
qvalue          = ( "0" [ "." *3DIGIT ] ) / ( "1" [ "." *3"0" ] )
Accept          = #( media-range [ weight ] )
Accept-Charset  = #( ( token / "*" ) [ weight ] )
Accept-Encoding = #( codings [ weight ] )
codings         = content-coding / "identity" / "*"
Accept-Language = #( language-range [ weight ] )
language-range  = (1*8ALPHA *("-" 1*8alphanum)) / "*"
```

- `q` is matched case-insensitively ("a common parameter, named "q"
  (case-insensitive)", section 12.4.2); `1.5`, `0.1234`, `.5` are refused
  (`InvalidQValue`).
- A malformed `Accept*` field is treated as absent by default
  (`MalformedPolicy::TreatAsAbsent`, reported as `Outcome::HeaderIgnored`).
  Section 12.4.1 lets an origin server "disregard the header field" when no
  representation is acceptable; parse-net applies the same choice to a field
  that does not parse, and says so. `MalformedPolicy::Refuse` reports
  `Outcome::Refused` for callers that answer 400.
- Language tags are compared case-insensitively; matching is RFC 4647 lookup
  (section 3.4) by default, basic filtering (section 3.3.1) on request.
- `x-gzip` and `x-compress` match `gzip` and `compress` (section 8.4.1.1,
  8.4.1.3).
- Functions: `best_media`, `best_language`, `best_encoding`, `best_charset`,
  `negotiate::Negotiator`, `negotiate::parse_accept`, `parse_weighted`.

## HTTP-date

RFC 9110 section 5.6.7.

```abnf
HTTP-date    = IMF-fixdate / obs-date
IMF-fixdate  = day-name "," SP date1 SP time-of-day SP GMT
obs-date     = rfc850-date / asctime-date
rfc850-date  = day-name-l "," SP date2 SP time-of-day SP GMT
asctime-date = day-name SP date3 SP time-of-day SP year
date1        = day SP month SP year
date2        = day "-" month "-" 2DIGIT
date3        = month SP ( 2DIGIT / ( SP DIGIT ) )
GMT          = %s"GMT"
```

- All three formats are read: "A recipient that parses a timestamp value in
  an HTTP field MUST accept all three HTTP-date formats." Writers produce
  IMF-fixdate only.
- Names are case-sensitive, as the `%s` strings in the RFC grammar are; only
  `GMT` is accepted.
- RFC 850 two-digit years: "Recipients of a timestamp value in rfc850-date
  format, which uses a two-digit year, MUST interpret a timestamp that appears
  to be more than 50 years in the future as representing the most recent year
  in the past that had the same last two digits." (D-039)
- The weekday must match the date (`WeekdayMismatch`).
- Stricter than the ABNF: the grammar's comment allows second `60`
  (`; 00:00:00 - 23:59:60 (leap second)`), but parse-net refuses it unless
  `Limits::allow_leap_second`, which reads it as `59`. No HTTP sender
  generates one (senders write `Date` from a Unix clock), and Unix time has
  no 60th second to hold it (D-053).
- Years 1 to 9999; dates before 1970 are valid (verdict V-2).
- Functions: `http_date` (`std`), `http_date_at`, `HttpDate::parse_at`,
  `parse_imf_fixdate`, `HttpDate::format`, `write_to`.

## Host

RFC 9110 section 7.2; RFC 3986 section 3.2.2.

```abnf
Host        = uri-host [ ":" port ]
host        = IP-literal / IPv4address / reg-name
IP-literal  = "[" ( IPv6address / IPvFuture  ) "]"
IPvFuture   = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
reg-name    = *( unreserved / pct-encoded / sub-delims )
port        = *DIGIT
```

- Case: "The scheme and host are case-insensitive" (RFC 9110 section 4.2.3);
  `Host::eq_ignore_ascii_case` compares names that way and IP literals by
  value.
- Stricter than the ABNF, for the reasons in D-031 and D-040: `@` anywhere is
  `InvalidHost` (userinfo is not part of `Host`, threat T15); a name whose
  last label is all digits or `0x` hex must be canonical dotted-decimal IPv4,
  so `127.1` and `0x7f.0.0.1` are refused rather than read as names that a
  later resolver turns into addresses (the WHATWG URL "ends in a number"
  rule).
- `port` is `*DIGIT`; an empty port (`a.com:`) is reported as
  `HostPort::empty_port`, and a value above 65535 is `InvalidPort`.
- `parse_host_port` strips OWS like every field parser; `parse_uri_host_port`
  strips nothing, for request targets and URL authorities (D-044).
- Functions: `parse_host_port`, `host::parse_uri_host_port`,
  `HostPort::write_to`.

## Percent-encoding

RFC 3986 section 2.1.

```abnf
pct-encoded = "%" HEXDIG HEXDIG
```

- Either hex case decodes: "The uppercase hexadecimal digits 'A' through
  'F' are equivalent to the lowercase digits 'a' through 'f', respectively."
  `pct::decode_lower_only_into` accepts lowercase only, for RFC 9651 Display
  Strings.
- `decode_utf8_into` refuses decoded bytes that are not UTF-8, overlong forms
  and surrogates included.
- Functions: `pct::validate`, `validate_with`, `decoded_len`, `decode_into`,
  `decode_utf8_into`, `decode_lower_only_into`, `encode`.

## Entity tags and conditions

RFC 9110 sections 8.8.3, 13.1.1, and 13.1.2.

```abnf
entity-tag    = [ weak ] opaque-tag
weak          = %x57.2F ; W/
opaque-tag    = DQUOTE *etagc DQUOTE
etagc         = "!" / %x23-7E ; '#'-'~'
              / obs-text
If-Match      = "*" / #entity-tag
If-None-Match = "*" / #entity-tag
```

- `W/` is case-sensitive ("its opaque value with "W/" (case-sensitive)"):
  `w/"x"` is `InvalidEntityTag`. An unquoted tag is refused.
- Comparison follows the section 8.8.3.2 table: `strong_eq`, `weak_eq`;
  `If-Match` uses strong comparison, `If-None-Match` weak.
- Functions: `EntityTag::parse`, `strong`, `weak`, `etag::parse_condition`,
  `if_match`, `if_none_match`.

## Ranges

RFC 9110 sections 14.1.2, 14.4, and 13.1.5.

```abnf
Range             = ranges-specifier
ranges-specifier  = range-unit "=" range-set
range-set         = range-spec *( OWS "," OWS range-spec )
range-spec        = int-range / suffix-range / other-range
int-range         = first-pos "-" [ last-pos ]
suffix-range      = "-" suffix-length
Content-Range     = range-unit SP ( range-resp / unsatisfied-range )
range-resp        = incl-range "/" ( complete-length / "*" )
unsatisfied-range = "*/" complete-length
If-Range          = entity-tag / HTTP-date
```

- "Range units are compared in a case-insensitive fashion." Another unit
  parses (its set is kept raw) and resolves to `RangeOutcome::NotBytes`.
- Resolution refuses abusive sets as section 14.2 allows ("A server that
  supports range requests MAY ignore or reject a Range header field that
  contains [...] a ranges-specifier with more than two overlapping ranges, or
  a set of many small ranges that are not listed in ascending order"): more
  ranges than
  `Limits::max_ranges` (default 16), more than two overlapping ranges, or
  more than two descents in order give `RangeOutcome::Ignore` (serve 200).
- `If-Range` dates are IMF-fixdate only (D-035): the date is compared exactly
  with the server's own `Last-Modified`.
- Functions: `range::parse`, `resolve`, `byte_ranges`, `parse_content_range`,
  `write_content_range`, `write_unsatisfied`, `parse_if_range`.

## ext-value

RFC 8187 section 3.2.1.

```abnf
ext-value     = charset  "'" [ language ] "'" value-chars
charset       = "UTF-8" / mime-charset
mime-charset  = 1*mime-charsetc
value-chars   = *( pct-encoded / attr-char )
attr-char     = ALPHA / DIGIT
              / "!" / "#" / "$" / "&" / "+" / "-" / "."
              / "^" / "_" / "`" / "|" / "~"
```

- Charset names are case-insensitive. UTF-8 and ISO-8859-1 are decoded
  (ISO-8859-1 transcoded to UTF-8, D-010); another charset is
  `UnsupportedCharset`. Writers produce UTF-8 only, as section 3.2.1 requires
  of producers.
- Decoded C0 controls, DEL, and C1 controls are refused (`ControlInDecoded`):
  a file name is shown to people and handed to file systems.
- Functions: `ExtValue::parse`, `decode_into`, `max_decoded_len`,
  `write_ext_value`.

## Content-Disposition

RFC 6266 section 4.1 (and RFC 7578 section 4.2 for `form-data`).

```abnf
content-disposition = "Content-Disposition" ":"
                       disposition-type *( ";" disposition-parm )
disposition-type    = "inline" | "attachment" | disp-ext-type
                    ; case-insensitive
disp-ext-type       = token
disposition-parm    = filename-parm | disp-ext-parm
filename-parm       = "filename" "=" value
                    | "filename*" "=" ext-value
disp-ext-parm       = token "=" value
                    | ext-token "=" ext-value
```

- The parameters are read with the RFC 9110 rule above (so no whitespace
  around `=`, empty parameters accepted); tc2231 classes C-1 and C-2.
- `filename*` is preferred over `filename` (section 4.3) and must decode at
  parse time; an undecodable `filename*` refuses the field (tc2231 C-5).
- RFC 2231 continuations (`filename*0=`) are not joined: RFC 6266 takes the
  RFC 5987 profile, which leaves them out (tc2231 C-3). They belong to the
  mail layer.
- A plain `filename` decodes as UTF-8 or not at all; no charset is guessed
  for `obs-text` (tc2231 C-4).
- The name is returned as sent: `Filename::has_path_separator` and
  `has_bidi_control` report what a caller must check (section 4.3: "Recipients
  SHOULD strip or replace character sequences that are known to cause
  confusion"); the policy is the caller's.
- Every case of the greenbytes tc2231 suite has a verdict in
  `tests/differential/tc2231.md`.
- Functions: `parse_content_disposition`, `disposition::parse`,
  `ContentDisposition::filename`, `Filename::decode_into`,
  `write_attachment`.

## Cache-Control

RFC 9111 section 5.2.

```abnf
Cache-Control   = #cache-directive
cache-directive = token [ "=" ( token / quoted-string ) ]
delta-seconds   = 1*DIGIT
```

- "Cache directives are identified by a token, to be compared
  case-insensitively".
- Both argument forms are read for every directive.
- `delta-seconds` saturates at 2147483648 (RFC 9111 section 1.2.2).
- A repeated directive keeps its first value and sets `duplicates`: "When
  there is more than one value present for a given directive [...] either
  the first occurrence should be used or the response should be considered
  stale" (section 4.2.1). An argument that does not parse leaves the field
  `None` and sets `invalid_values`. Conflicting directives are all reported;
  the same section says "the most restrictive directive should be honored",
  which is the cache's decision.
- Functions: `response_cache_control`, `request_cache_control`,
  `cache::parse`, `response_lines`, `request_lines`, `cache::Writer`.

## Forwarded

RFC 7239 sections 4 and 6.

```abnf
Forwarded         = 1#forwarded-element
forwarded-element = [ forwarded-pair ] *( ";" [ forwarded-pair ] )
forwarded-pair    = token "=" value
value             = token / quoted-string
node              = nodename [ ":" node-port ]
nodename          = IPv4address / "[" IPv6address "]" /
                    "unknown" / obfnode
obfnode           = "_" 1*( ALPHA / DIGIT / "." / "_" / "-")
node-port         = port / obfport
port              = 1*5DIGIT
obfport           = "_" 1*(ALPHA / DIGIT / "." / "_" / "-")
```

- Parameter names are case-insensitive; "Each parameter MUST NOT occur more
  than once per field-value": a repeat is refused.
- An IPv6 address or a node with a port must be quoted ("an IPv6 address and
  any nodename with node-port specified MUST be quoted"); unquoted, it is
  refused.
- `client_address` walks the chain from the right through trusted proxies
  only, and stops at `unknown`, an obfuscated node, or an element without
  `for` (`ClientAddress::Unknown`). A malformed chain is an error: use the
  peer address.
- Functions: `forwarded::parse`, `client_address`,
  `client_address_detailed`.

## X-Forwarded-*

No RFC: the de facto forms. `X-Forwarded-For` is a comma-separated list of IP
addresses, each optionally with a port (IPv6 in brackets when it has one);
`X-Forwarded-Proto` is `http` or `https`; `X-Forwarded-Host` follows the
`Host` grammar. The leftmost address is whatever the client sent; only
addresses appended by trusted proxies are meaningful, which is why the
resolver walks from the right.

- Functions: `forwarded::parse_x_forwarded_for`, `parse_x_forwarded_proto`,
  `parse_x_forwarded_host`, `client_address` with
  `ForwardedSource::XForwardedFor`.

## Authorization and WWW-Authenticate

RFC 9110 section 11.

```abnf
credentials      = auth-scheme [ 1*SP ( token68 / [ auth-param *( OWS ","
                   OWS auth-param ) ] ) ]
challenge        = auth-scheme [ 1*SP ( token68 / [ auth-param *( OWS ","
                   OWS auth-param ) ] ) ]
WWW-Authenticate = #challenge
auth-scheme      = token
auth-param       = token BWS "=" BWS ( token / quoted-string )
token68          = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" )
                   *"="
```

- The scheme "uses a case-insensitive token"; parameter names are "matched
  case-insensitively and each parameter name MUST only occur once per
  challenge": a repeat is refused, and `write_challenge` refuses one too
  (`WriteError::DuplicateName`).
- `BWS` around `=` is accepted here, as the rule says, unlike section 5.6.6
  parameters.
- `Debug` prints the scheme and parameter names only: credentials are
  secrets.
- Functions: `auth::parse_credentials`, `bearer`, `basic`,
  `auth::parse_challenges`, `write_challenge`, `write_challenge_token68`.

## Origin

RFC 6454 section 7.1.

```abnf
origin              = "Origin:" OWS origin-list-or-null OWS
origin-list-or-null = %x6E %x75 %x6C %x6C / origin-list
origin-list         = serialized-origin *( SP serialized-origin )
serialized-origin   = scheme "://" host [ ":" port ]
```

- `null` is case-sensitive (the `%x` form). The scheme is compared
  case-insensitively; the host by the `Host` rules.
- One origin only: a space-separated `origin-list` is refused. Browsers send
  one (the Fetch standard serializes a single origin), and a list would leave
  the caller to pick which origin to trust; refusing fails closed for CSRF
  checks.
- A path, query, fragment, trailing `/`, userinfo, or empty port is refused
  (`InvalidOrigin`, `InvalidHost`).
- Functions: `parse_origin`, `Origin::same_origin`, `effective_port`,
  `write_to`.

## Structured Field Values

RFC 9651. The RFC's ABNF is non-normative ("If there is disagreement between
the parsing algorithms and ABNF, the specified algorithms take precedence"),
so parse-net implements the section 4.2 algorithms; the ABNF is quoted for
reference.

```abnf
sf-list       = list-member *( OWS "," OWS list-member )
list-member   = sf-item / inner-list
inner-list    = "(" *SP [ sf-item *( 1*SP sf-item ) *SP ] ")"
                parameters
parameters    = *( ";" *SP parameter )
parameter     = param-key [ "=" param-value ]
key           = ( lcalpha / "*" )
                *( lcalpha / DIGIT / "_" / "-" / "." / "*" )
sf-dictionary = dict-member *( OWS "," OWS dict-member )
dict-member   = member-key ( parameters / ( "=" member-value ))
sf-item       = bare-item parameters
bare-item     = sf-integer / sf-decimal / sf-string / sf-token
                / sf-binary / sf-boolean / sf-date / sf-displaystring
sf-integer       = ["-"] 1*15DIGIT
sf-decimal       = ["-"] 1*12DIGIT "." 1*3DIGIT
sf-string        = DQUOTE *( unescaped / "%" / bs-escaped ) DQUOTE
sf-token         = ( ALPHA / "*" ) *( tchar / ":" / "/" )
sf-binary        = ":" base64 ":"
sf-boolean       = "?" ( "0" / "1" )
sf-date          = "@" sf-integer
sf-displaystring = "%" DQUOTE *( unescaped / "\" / pct-encoded )
                   DQUOTE
base64           = *( ALPHA / DIGIT / "+" / "/" ) *"="
pct-encoded      = "%" lc-hexdig lc-hexdig
```

- Keys are lowercase; everything else is case-sensitive.
- The field is accepted or refused whole: "If parsing fails, either the
  entire field value MUST be ignored (i.e., treated as if the field were not
  present in the section), or alternatively the complete HTTP message MUST be
  treated as malformed."
- Only SP is discarded around the value and inside inner lists; OWS (SP and
  HTAB) around list and dictionary commas.
- Byte sequences: missing padding and non-zero pad bits are accepted ("parsers
  SHOULD NOT fail when "=" padding is not present" and "SHOULD NOT fail when
  non-zero pad bits are present"); padding that does not complete the last
  quantum, or extra padding, is refused (`InvalidBase64`).
- Dates are limited to years 1 to 9999, the `HttpDate` range (D-030); the
  RFC sets no range of its own.
- Display Strings: lowercase hex only, and the decoded bytes must be UTF-8.
- Limits: each `Limits` default meets the section 3 minimum (1024 list and
  dictionary members, 256 inner-list members and parameters, keys of at least
  64 characters with a default of 256, 1024-character strings, 512-character
  tokens, 16384-byte byte sequences).
- Conformance: the httpwg structured-field-tests suite runs whole, and every
  list and dictionary again split into one line per member
  (`tests/sfv_conformance.rs`); the 4 optional cases parse-net refuses are
  listed in `tests/sfv/README.md`.
- Functions: `sfv::parse_item`, `parse_list`, `parse_dictionary`,
  `parse_list_lines`, `parse_dictionary_lines`, `sfv::Parser` (limits and
  `visit_*`), `Dictionary::get`, `index_into`.
- The writer (`sfv::Writer`) produces the canonical form of section 4.1;
  every accepted parse case is serialized again and compared with the
  suite's `canonical`, and the four serialisation-only files run whole.

## Link

RFC 8288 section 3.

```abnf
Link       = #link-value
link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )
link-param = token BWS [ "=" BWS ( token / quoted-string ) ]
```

- Parameter names are case-insensitive; a parameter value is optional
  (`; crossorigin`), and `BWS` around `=` is accepted, as the rule says.
- `rel`: "The rel parameter MUST be present but MUST NOT appear more than
  once in a given link-value; occurrences after the first MUST be ignored by
  parsers." `rel` and the other single-valued parameters (`anchor`,
  `media`, `title`, `title*`, `type`) return the first occurrence;
  `hreflang` may repeat and returns every one.
- The target is checked as RFC 3986 characters with well-formed `%XX` and
  returned as sent. RFC 8288 section 3.1 says a relative reference must be
  resolved; parse-net leaves resolution to the caller (url-lib), since it
  needs the base URI.
- `title*` is an RFC 8187 value decoded at parse time, as `filename*` is.
- Functions: `parse_link`, `LinkValue`, `link::write_link`.

## Email dates

RFC 5322 section 3.3, and section 4.3 for the obsolete forms.

```abnf
date-time   =   [ day-of-week "," ] date time [CFWS]
day-of-week =   ([FWS] day-name) / obs-day-of-week
date        =   day month year
day         =   ([FWS] 1*2DIGIT FWS) / obs-day
year        =   (FWS 4*DIGIT FWS) / obs-year
time        =   time-of-day zone
time-of-day =   hour ":" minute [ ":" second ]
zone        =   (FWS ( "+" / "-" ) 4DIGIT) / obs-zone
```

- Names are case-insensitive (RFC 5234 quoted strings); comments and folding
  whitespace may separate the tokens; the weekday, when present, must match.
- `-0000` sets `offset_unknown`: the time is UTC and the local zone is not
  known (section 3.3). Second `60` is read as `59` with `leap_second` set.
- Years outside 1 to 9999 are `OutOfRange`, the range every date type here
  shares.
- With `obsolete`: two-digit years below 50 are 20xx and others 19xx, and
  three-digit years add 1900 (section 4.3, D-036); `UT`, `GMT`, and the North
  American zones; the military zones are read as `-0000`, because "they
  SHOULD all be considered equivalent to "-0000" unless there is out-of-band
  information confirming their meaning." `J` is not a zone.
- Writers always produce the weekday, a two-digit day, a four-digit year,
  seconds, and a numeric zone.
- Functions: `MailDate::parse`, `new`, `format`, `write_to`.

## Email header values

RFC 5322 sections 2.1.1, 2.2.3, and 3.6.8.

```abnf
field-name = 1*ftext
ftext      = %d33-57 / %d59-126
```

- A header value for writing has no CR, LF, or NUL and is at most 998
  bytes (the line limit of section 2.1.1, which `Name: ` also counts
  toward): `mail::check_header_value`.
- Unfolding removes a CRLF only when WSP follows it (section 2.2.3); any
  other CR or LF is refused: `mail::unfold`.
- Folding inserts CRLF before existing whitespace so lines stay within 78
  columns where the words allow, never makes a line of only whitespace, and
  refuses a word that cannot fit in 998: `mail::fold`.
- `mail::is_field_name`.

## Encoded words

RFC 2047 sections 2 to 6.

```abnf
encoded-word = "=?" charset "?" encoding "?" encoded-text "?="
charset      = token
encoding     = token
```

- An encoded word is decoded only when it stands between whitespace (or
  the start or end of the text) and has the whole shape; anything else is
  ordinary text. Inside a quoted string nothing is decoded (section 5).
- "any 'linear-white-space' that separates a pair of adjacent
  'encoded-word's is ignored" (section 6.2); other whitespace is kept.
- Q: `_` is a space and `=XX` a byte (either hex case read); each UTF-8 word
  must hold whole characters. Charsets UTF-8, US-ASCII, and ISO-8859-1
  (transcoded), with an optional RFC 2231 `*language`. Decoded CR, LF, and
  NUL are refused. `B` waits for encode-lib (D-002).
- Encoding: "An 'encoded-word' may not be more than 75 characters long";
  words split only between characters and are separated by CRLF SP.
  Printable ASCII without `=?` is written as it is.
- Functions: `mail::decode_words`, `mail::encode_words`.

## MIME parameters

RFC 2045 section 5.1 and RFC 2231 sections 3 to 7.

```abnf
parameter := attribute "=" value
attribute := token
value     := token / quoted-string

regular-parameter-name := attribute [section]
section                := initial-section / other-sections
initial-section        := "*0"
other-sections         := "*" ("1" / "2" / "3" / "4" / "5" /
                               "6" / "7" / "8" / "9") *DIGIT)
extended-initial-name  := attribute [initial-section] "*"
extended-other-names   := attribute other-sections "*"
```

- Tokens use the MIME class (which allows `{` and `}`, unlike HTTP
  `tchar`); names are case-insensitive; comments and folding whitespace may
  separate the parts; a name given twice (sections counted one by one) is
  refused.
- A section number with a leading zero (`*01`) is not a section (the
  grammar excludes it), so that parameter is an ordinary one.
- Continuations are validated at parse time: sections run from 0 with no
  gap, at most `Limits::max_rfc2231_sections` (32 by default), a charset
  only on section 0, and the joined value decodes. Charsets: UTF-8,
  US-ASCII, ISO-8859-1 (transcoded).
- Writing picks a token, a quoted string, a single `name*=UTF-8''...`, or
  `name*0*`, `name*1*` sections on folded lines, whichever keeps the line
  within 78 columns.
- Functions: `mail::parse_mime_params`, `MimeParams::get`, `decode_into`,
  `Continuation`, `mail::write_mime_param`.

## Addresses and message identifiers

RFC 5322 sections 3.2.3, 3.4, and 3.6.4; RFC 6532; RFC 5321 section
4.5.3.1.

```abnf
atext          = ALPHA / DIGIT / "!" / "#" / "$" / "%" / "&" / "'" /
                 "*" / "+" / "-" / "/" / "=" / "?" / "^" / "_" / "`" /
                 "{" / "|" / "}" / "~"
dot-atom-text  = 1*atext *("." 1*atext)
addr-spec      = local-part "@" domain
local-part     = dot-atom / quoted-string / obs-local-part
domain         = dot-atom / domain-literal / obs-domain
dtext          = %d33-90 / %d94-126 / obs-dtext
mailbox        = name-addr / addr-spec
name-addr      = [display-name] angle-addr
msg-id         = [CFWS] "<" id-left "@" id-right ">" [CFWS]
id-left        = dot-atom-text / obs-id-left
id-right       = dot-atom-text / no-fold-literal / obs-id-right
no-fold-literal = "[" *dtext "]"
```

- Stricter than the ABNF, for login validation (D-008): no obsolete forms,
  no comments, and no folding inside an `addr-spec`; the local part is at
  most 64 octets and the address at most 254 (RFC 5321).
- Non-ASCII is accepted only as valid UTF-8 (RFC 6532), never as raw
  obs-text; `AddrSpec::is_ascii` says whether SMTPUTF8 is needed.
- A mailbox's display name is checked as a phrase (atoms, `.`, quoted
  strings, comments, UTF-8) and returned raw, encoded words included.
- Functions: `mail::parse_addr_spec`, `parse_mailbox`, `parse_msg_id`,
  `write_msg_id`.
