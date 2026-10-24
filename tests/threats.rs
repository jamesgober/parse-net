//! Attack tests for the threat table (dev/PLAN.md section 9): each test sends
//! the attack and checks that the defence stops it.
//!
//! The rows whose tests live beside the code they defend are listed here so
//! the table can be checked in one place:
//!
//! | Threat | Tests elsewhere |
//! |---|---|
//! | T1 | `write::tests::test_writers_refuse_crlf_in_every_position` |
//! | T2 | `ext_value::tests::test_ext_value_percent_crlf_refused` |
//! | T3 | `list::tests::test_list_comma_in_quotes_is_one_element` |
//! | T6 | `text::tests::test_trim_ows_never_strips_vt_ff_nbsp` |
//! | T8 | `properties::test_combined_equals_joined` |
//! | T9 | `complexity.rs` (`test_complexity_linear`) |
//! | T10 | `text::tests::test_comment_depth_limit_plus_one_refused` |
//! | T12 | `range::tests::test_range_17_ranges_ignored`, `test_range_three_overlapping_ignored` |
//! | T13 | `forwarded::tests::test_xff_untrusted_peer_ignored`, `test_xff_leftmost_spoof_ignored`, `test_xff_malformed_fails_closed` |
//! | T14 | `forwarded::tests::test_both_forwarded_headers_reported` |
//! | T15 | `host::tests::test_host_userinfo_refused`, `test_host_partial_ipv4_refused` |
//! | T16 | `origin::tests::test_origin_suffix_attack_not_same`, `test_origin_trailing_slash_refused` |
//! | T17 | `disposition::tests::test_filename_nul_refused`, `test_filename_overlong_utf8_refused` |
//! | T18 | `ext_value::tests::test_ext_value_charset_matrix` |
//! | T20 | `date::tests::test_http_date_rejections_table` |
//! | T21 | `auth::tests::test_credentials_debug_redacted` |
//! | T23 | `no_alloc.rs` (the counting allocator) |
//! | T25 | `class::tests::test_tchar_table_exhaustive` |

use parse_net::{
    self as pn, ErrorKind, Limits, auth, cache, etag, mail, media, range, sfv, sfv::BareItem, text,
};

fn kind<T>(r: Result<T, pn::ParseError>) -> ErrorKind {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e.kind(),
    }
}

// T2: decoded control bytes are refused, not re-emitted.

#[test]
fn test_encoded_word_crlf_refused() {
    let mut out = [0u8; 64];
    // Every control character, as in ext-values (D-071): C0 (HTAB
    // included), DEL, and C1 in UTF-8 and in ISO-8859-1. ESC would carry a
    // terminal escape sequence into a log or a display.
    for word in [
        &b"=?UTF-8?Q?a=0D=0Ab?="[..],
        b"=?UTF-8?Q?a=0Ab?=",
        b"=?UTF-8?Q?a=00b?=",
        b"=?UTF-8?Q?a=09b?=",
        b"=?UTF-8?Q?a=1B[2Jb?=",
        b"=?UTF-8?Q?a=7Fb?=",
        b"=?UTF-8?Q?a=C2=85b?=",
        b"=?UTF-8?Q?a=C2=9Bb?=",
        b"=?ISO-8859-1?Q?a=85b?=",
        b"=?us-ascii?Q?a=1Fb?=",
    ] {
        assert_eq!(
            kind(mail::decode_words(word, &Limits::DEFAULT, &mut out)),
            ErrorKind::ControlInDecoded,
            "{word:?}"
        );
    }
    assert_eq!(
        mail::decode_words(b"=?UTF-8?Q?a_b?=", &Limits::DEFAULT, &mut out),
        Ok("a b")
    );
    // The neighbours of C1 are text: U+00A0 and U+00C2 itself.
    assert_eq!(
        mail::decode_words(b"=?UTF-8?Q?=C2=A0=C3=82?=", &Limits::DEFAULT, &mut out),
        Ok("\u{a0}\u{c2}")
    );
    assert_eq!(
        mail::decode_words(b"=?ISO-8859-1?Q?=A0=C2?=", &Limits::DEFAULT, &mut out),
        Ok("\u{a0}\u{c2}")
    );
}

#[test]
fn test_basic_credentials_ctl_refused() {
    // The credentials field is checked before anything is read from it;
    // base64 decoding itself waits for encode-lib (dev/PLAN.md, D-002).
    assert_eq!(kind(auth::basic(b"Basic YWxh\r\nX: y")), ErrorKind::BareCr);
    assert_eq!(kind(auth::basic(b"Basic YWxh\nX")), ErrorKind::LineFeed);
    assert_eq!(kind(auth::basic(b"Basic YW\x00xh")), ErrorKind::Nul);
    assert_eq!(kind(auth::basic(b"Basic YW\x01xh")), ErrorKind::Control);
    assert_eq!(
        auth::basic(b"Basic YWxhZGRpbjpvcGVuc2VzYW1l"),
        Ok(Some(&b"YWxhZGRpbjpvcGVuc2VzYW1l"[..]))
    );
}

// T4: a repeated parameter is refused, never read first by one component
// and last by another.

#[test]
fn test_content_disposition_duplicate_filename_refused() {
    for v in [
        &b"attachment; filename=a.txt; filename=b.exe"[..],
        b"attachment; filename=a.txt; FILENAME=b.exe",
        b"attachment; filename*=UTF-8''a.txt; filename*=UTF-8''b.exe",
    ] {
        assert_eq!(
            kind(pn::parse_content_disposition(v)),
            ErrorKind::DuplicateParameter,
            "{v:?}"
        );
    }
    // `filename` and `filename*` are different parameters (RFC 6266).
    assert!(
        pn::parse_content_disposition(b"attachment; filename=a.txt; filename*=UTF-8''b.txt")
            .is_ok()
    );
}

#[test]
fn test_media_type_duplicate_charset_refused() {
    for v in [
        &b"text/html; charset=utf-8; charset=latin1"[..],
        b"text/html; charset=utf-8; Charset=latin1",
        b"text/html;charset=utf-8;CHARSET=\"utf-8\"",
        b"multipart/form-data; boundary=a; boundary=b",
    ] {
        assert_eq!(
            kind(pn::parse_media_type(v)),
            ErrorKind::DuplicateParameter,
            "{v:?}"
        );
    }
}

// T5: case rules follow the RFCs, one table.

#[test]
fn test_case_rules_table() {
    // Case-insensitive: media type essence and parameter names (RFC 9110
    // 8.3.1, 5.6.6), authentication schemes (11.1), range units (14.1),
    // Cache-Control directive names (RFC 9111 5.2).
    let mt = pn::parse_media_type(b"Text/HTML; Charset=UTF-8").unwrap();
    assert!(mt.essence_is("text/html"));
    assert!(
        mt.charset()
            .is_some_and(|c| c.eq_ignore_ascii_case(b"utf-8"))
    );
    assert!(mt.param("CHARSET").is_some());
    assert_eq!(auth::bearer(b"bEaReR abc"), Ok(Some(&b"abc"[..])));
    assert!(range::parse(b"Bytes=0-1", &Limits::DEFAULT).is_ok_and(|r| r.is_bytes()));
    assert_eq!(
        pn::response_cache_control(b"MAX-AGE=5").unwrap().max_age,
        Some(5)
    );
    // Case-sensitive: the weak prefix `W/` (RFC 9110 8.8.3) and the opaque
    // tag; token values compare as sent unless the field says otherwise.
    assert_eq!(
        kind(pn::EntityTag::parse(b"w/\"x\"")),
        ErrorKind::InvalidEntityTag
    );
    let weak = pn::EntityTag::parse(b"W/\"x\"").unwrap();
    assert!(weak.is_weak());
    let upper = pn::EntityTag::parse(b"\"X\"").unwrap();
    let lower = pn::EntityTag::parse(b"\"x\"").unwrap();
    assert!(!upper.strong_eq(&lower));
    // Structured Field tokens and keys: keys must be lowercase (RFC 9651
    // 3.1.2); tokens keep their case.
    assert_eq!(kind(sfv::parse_dictionary(b"A=1")), ErrorKind::InvalidKey);
    assert_eq!(
        sfv::parse_item(b"Tok").unwrap().bare,
        BareItem::Token("Tok")
    );
}

// T6: only SP and HTAB are whitespace.

#[test]
fn test_utf8_nbsp_prefix_not_trimmed() {
    let nbsp = b"\xc2\xa0text/html";
    assert_eq!(text::trim_ows(nbsp), nbsp);
    assert_eq!(text::skip_ows(nbsp), 0);
    assert!(pn::parse_media_type(nbsp).is_err());
    assert!(pn::parse_media_type(b"text/html\xc2\xa0").is_err());
    assert!(pn::list(b"a,\xc2\xa0b").is_ok_and(|l| l.iter().any(|e| e == b"\xc2\xa0b")));
    for ws in [&b"\x0btext/html"[..], b"\x0ctext/html", b"\rtext/html"] {
        assert!(pn::parse_media_type(ws).is_err(), "{ws:?}");
    }
}

// T7: an invalid `filename*` refuses the field rather than letting a
// component fall back to `filename`.

#[test]
fn test_invalid_filename_star_refuses_field() {
    for v in [
        &b"attachment; filename=safe.txt; filename*=UTF-8''%ZZ"[..],
        b"attachment; filename=safe.txt; filename*=UTF-8''%C3",
        b"attachment; filename=safe.txt; filename*=KOI8-R''x",
        b"attachment; filename=safe.txt; filename*=UTF-8'x",
        b"attachment; filename=safe.txt; filename*=UTF-8''%0D%0A",
    ] {
        assert!(pn::parse_content_disposition(v).is_err(), "{v:?}");
    }
    let cd = pn::parse_content_disposition(b"attachment; filename=a.txt; filename*=UTF-8''b.txt")
        .unwrap();
    assert!(cd.filename_ext().is_some());
}

// T11: overflow is refused, or saturates only where the RFC says.

#[test]
fn test_range_u64_max_plus_one() {
    let max = b"bytes=18446744073709551615-18446744073709551615";
    assert!(range::parse(max, &Limits::DEFAULT).is_ok());
    for v in [
        &b"bytes=18446744073709551616-"[..],
        b"bytes=0-18446744073709551616",
        b"bytes=-18446744073709551616",
    ] {
        assert_eq!(
            kind(range::parse(v, &Limits::DEFAULT)),
            ErrorKind::NumberOverflow,
            "{v:?}"
        );
    }
    assert_eq!(
        kind(range::parse_content_range(
            b"bytes 0-1/18446744073709551616"
        )),
        ErrorKind::NumberOverflow
    );
    assert_eq!(
        kind(range::parse_content_range(
            b"bytes 18446744073709551616-1/*"
        )),
        ErrorKind::NumberOverflow
    );
}

#[test]
fn test_delta_seconds_saturates() {
    // RFC 9111 1.2.2: a delta-seconds too large is read as 2^31.
    let d = |v: &[u8]| pn::response_cache_control(v).unwrap().max_age;
    assert_eq!(d(b"max-age=2147483647"), Some(2_147_483_647));
    assert_eq!(d(b"max-age=2147483648"), Some(2_147_483_648));
    assert_eq!(
        d(b"max-age=99999999999999999999999999"),
        Some(2_147_483_648)
    );
    assert_eq!(d(b"max-age=\"99999999999\""), Some(2_147_483_648));
    let r = pn::response_cache_control(b"max-age=-1").unwrap();
    assert!(r.max_age.is_none() && r.invalid_values);
    let _ = cache::RequestDirectives::default();
}

#[test]
fn test_sf_integer_16_digits_refused() {
    assert_eq!(
        sfv::parse_item(b"999999999999999").unwrap().bare,
        BareItem::Integer(999_999_999_999_999)
    );
    assert_eq!(
        sfv::parse_item(b"-999999999999999").unwrap().bare,
        BareItem::Integer(-999_999_999_999_999)
    );
    assert!(sfv::parse_item(b"1000000000000000").is_err());
    assert!(sfv::parse_item(b"-1000000000000000").is_err());
    assert!(sfv::parse_item(b"99999999999999999999999").is_err());
}

// T17: separators and bidi controls in file names are reported.

#[test]
fn test_filename_bidi_reported() {
    // U+202E RIGHT-TO-LEFT OVERRIDE: `invoice\u{202e}fdp.exe` shows as
    // `invoiceexe.pdf`.
    let cd = pn::parse_content_disposition(b"attachment; filename*=UTF-8''invoice%E2%80%AEfdp.exe")
        .unwrap();
    assert!(cd.filename().unwrap().has_bidi_control());
    // The embedding, override, and isolate controls: the set rustc's
    // `text_direction_codepoint_in_literal` lint reports (D-070). The
    // implicit marks (LRM, RLM, ALM) cannot reorder Latin letters and occur in
    // legitimate right-to-left names, so they are not reported.
    let has = |c: &str| {
        let v = format!("attachment; filename*=UTF-8''a{c}b.txt");
        pn::parse_content_disposition(v.as_bytes())
            .unwrap()
            .filename()
            .unwrap()
            .has_bidi_control()
    };
    for c in [
        "%E2%80%AA",
        "%E2%80%AB",
        "%E2%80%AC",
        "%E2%80%AD",
        "%E2%80%AE",
        "%E2%81%A6",
        "%E2%81%A7",
        "%E2%81%A8",
        "%E2%81%A9",
    ] {
        assert!(has(c), "{c}");
    }
    for c in [
        "%E2%80%8E",
        "%E2%80%8F",
        "%D8%9C",
        "%E2%80%A9",
        "%E2%80%AF",
        "%E2%81%A5",
        "%E2%81%AA",
    ] {
        assert!(!has(c), "{c}");
    }
    // A plain `filename` is checked after percent-decoding too.
    let cd = pn::parse_content_disposition(b"attachment; filename=\"a%E2%80%AEb.txt\"").unwrap();
    assert!(cd.filename().unwrap().has_bidi_control());
    let plain =
        pn::parse_content_disposition(b"attachment; filename*=UTF-8''%E2%82%AC.txt").unwrap();
    assert!(!plain.filename().unwrap().has_bidi_control());
}

// T19: Display Strings must be valid UTF-8.

#[test]
fn test_display_string_surrogate_refused() {
    for v in [
        &b"%\"%ed%a0%80\""[..],
        b"%\"%ed%bf%bf\"",
        b"%\"%c0%af\"",
        b"%\"%f4%90%80%80\"",
        b"%\"%c3\"",
    ] {
        assert_eq!(kind(sfv::parse_item(v)), ErrorKind::InvalidUtf8, "{v:?}");
    }
    assert!(sfv::parse_item(b"%\"%e2%82%ac\"").is_ok());
}

// T21: one credential per field, no repeated parameter.

#[test]
fn test_auth_duplicate_param_refused() {
    let l = &Limits::DEFAULT;
    assert_eq!(
        kind(auth::parse_credentials(
            b"Digest username=\"a\", username=\"b\"",
            l
        )),
        ErrorKind::DuplicateParameter
    );
    assert_eq!(
        kind(auth::parse_credentials(b"Digest realm=a, REALM=b", l)),
        ErrorKind::DuplicateParameter
    );
    assert_eq!(
        kind(auth::parse_challenges(b"Basic realm=\"a\", realm=\"b\"", l)),
        ErrorKind::DuplicateParameter
    );
    assert!(auth::parse_credentials(b"Basic a, Bearer b", l).is_err());
}

// T22: errors carry a kind and an offset, never input bytes.

#[test]
fn test_error_display_contains_no_input() {
    let marker = "SECRETzq";
    let inputs: [Vec<u8>; 10] = [
        format!("text/{marker}\r").into_bytes(),
        format!("{marker}; a=\"\x01\"").into_bytes(),
        format!("attachment; filename*=UTF-8''{marker}%ZZ").into_bytes(),
        format!("Basic {marker}\n").into_bytes(),
        format!("bytes={marker}").into_bytes(),
        format!("max-age={marker}, \x00").into_bytes(),
        format!("\"{marker}").into_bytes(),
        format!("W/\"{marker}\"x").into_bytes(),
        format!("{marker}=?UTF-8?Q?=0A?=").into_bytes(),
        format!("a=:{marker}:").into_bytes(),
    ];
    let mut out = [0u8; 64];
    let tag = pn::EntityTag::strong(b"x").unwrap();
    for v in &inputs {
        let errors = [
            pn::parse_media_type(v).err(),
            pn::parse_content_disposition(v).err(),
            auth::basic(v).err(),
            range::parse(v, &Limits::DEFAULT).err(),
            pn::response_cache_control(v).err(),
            etag::if_none_match(v, &tag).err(),
            mail::decode_words(v, &Limits::DEFAULT, &mut out).err(),
            sfv::parse_dictionary(v).err(),
            media::parse_range(v, &Limits::DEFAULT).err(),
        ];
        for e in errors.into_iter().flatten() {
            let shown = format!("{e} {e:?}");
            assert!(!shown.contains(marker), "{shown}");
            assert!(shown.contains("offset"), "{shown}");
        }
    }
}

// T24: base64 in byte sequences follows RFC 9651 section 4.2.7.

#[test]
fn test_sf_byteseq_padding_rules() {
    let len = |v: &[u8]| match sfv::parse_item(v).unwrap().bare {
        BareItem::ByteSeq(b) => b.decoded_len(),
        other => panic!("{other:?}"),
    };
    // Full padding and no padding are both read (parsers SHOULD NOT fail
    // when `=` padding is absent).
    assert_eq!(len(b":YQ==:"), 1);
    assert_eq!(len(b":YQ:"), 1);
    assert_eq!(len(b":YWI=:"), 2);
    assert_eq!(len(b":YWI:"), 2);
    // Non-zero pad bits are read too (they SHOULD NOT fail either).
    assert_eq!(len(b":YR==:"), 1);
    // Partial or excess padding, padding inside, a single leftover symbol,
    // and bytes outside the alphabet are refused.
    for v in [
        &b":YQ=:"[..],
        b":YQ===:",
        b":YQ=a:",
        b":Y:",
        b":YWJj=:",
        b":Y-Q=:",
        b":YQ_=:",
    ] {
        assert_eq!(kind(sfv::parse_item(v)), ErrorKind::InvalidBase64, "{v:?}");
    }
}

// T4 and T9: the repeat check compares whole names from a table of at most
// 64 (D-072), for every parameter grammar that refuses repeats.

#[test]
fn test_repeat_checks_compare_whole_names() {
    let l = &Limits::DEFAULT;
    let names: Vec<String> = (0..63).map(|i| format!("n{i}")).collect();
    let auth_ok = names
        .iter()
        .map(|n| format!("{n}=1"))
        .collect::<Vec<_>>()
        .join(", ");
    let mime_ok = names
        .iter()
        .map(|n| format!("; {n}=1"))
        .collect::<Vec<_>>()
        .concat();
    for (i, n) in names.iter().enumerate() {
        let up = n.to_uppercase();
        // Optional whitespace before `=` (auth) and comments (MIME) do not
        // hide a repeat.
        let a = format!("Digest {auth_ok}, {up} = 2");
        assert_eq!(
            kind(auth::parse_credentials(a.as_bytes(), l)),
            ErrorKind::DuplicateParameter,
            "{i}"
        );
        let m = format!("{mime_ok}; (c) {up} (d) = 2");
        assert_eq!(
            kind(mail::parse_mime_params(m.as_bytes(), l)),
            ErrorKind::DuplicateParameter,
            "{i}"
        );
    }
    // A prefix or an extension of an earlier name is another name; so is
    // the RFC 2231 `name*`.
    for other in ["n", "n1x", "xn1", "n100", "n1*"] {
        let a = format!("Digest {auth_ok}, {other}=2");
        assert!(auth::parse_credentials(a.as_bytes(), l).is_ok(), "{other}");
    }
    for other in ["n", "n1x", "xn1", "n100"] {
        let m = format!("{mime_ok}; {other}=2");
        assert!(mail::parse_mime_params(m.as_bytes(), l).is_ok(), "{other}");
    }
    assert!(mail::parse_mime_params(b"; n*=UTF-8''x; n=y", l).is_ok());
    // 64 parameters are read; the 65th is refused whatever `max_params` says.
    let wide = Limits::DEFAULT.max_params(u16::MAX);
    let a64 = format!("Digest {auth_ok}, last=1");
    assert_eq!(
        auth::parse_credentials(a64.as_bytes(), &wide).map(|_| ()),
        Ok(())
    );
    let a65 = format!("{a64}, more=1");
    assert_eq!(
        kind(auth::parse_credentials(a65.as_bytes(), &wide)),
        ErrorKind::TooManyMembers
    );
    let m64 = format!("{mime_ok}; last=1");
    assert!(mail::parse_mime_params(m64.as_bytes(), &wide).is_ok());
    let m65 = format!("{m64}; more=1");
    assert_eq!(
        kind(mail::parse_mime_params(m65.as_bytes(), &wide)),
        ErrorKind::TooManyMembers
    );
    assert_eq!(pn::param::MAX_CHECKED_PARAMS, 64);
}
