//! Regressions from the 0.9 security and edge-case review of the core grammar
//! (`F` numbers from that review). Each test states what the contract or the
//! RFC requires, for an input that once got it wrong.

use parse_net::negotiate::{MalformedPolicy, Negotiator, Outcome, parse_accept, parse_weighted};
use parse_net::*;

const L: Limits = Limits::DEFAULT;

fn kind_at<T>(r: Result<T, ParseError>) -> (ErrorKind, usize) {
    let e = r.err().expect("an error");
    (e.kind(), e.offset())
}

fn strict() -> Negotiator {
    Negotiator::new().on_malformed(MalformedPolicy::Refuse)
}

// F1, cache.rs:516
#[test]
fn f01_bad_max_stale_is_not_any_staleness() {
    let r = request_cache_control(b"max-stale=abc").unwrap();
    assert!(r.invalid_values);
    assert_eq!(r.max_stale, None);
}

// F2, range.rs:274-284, 646
#[test]
fn f02_large_range_numerals_do_not_fail_to_parse() {
    let mut o = [ByteRange { start: 0, end: 0 }; 1];
    assert_eq!(
        byte_ranges(b"bytes=0-99999999999999999999", 10, &mut o),
        Ok(RangeOutcome::Ranges(1))
    );
    assert_eq!(o[0], ByteRange { start: 0, end: 9 });
}
#[test]
fn f02b_large_first_pos_is_unsatisfiable() {
    let mut o = [ByteRange { start: 0, end: 0 }; 1];
    assert_eq!(
        byte_ranges(b"bytes=99999999999999999999-", 10, &mut o),
        Ok(RangeOutcome::Unsatisfiable)
    );
}
#[test]
fn f02c_large_suffix_is_the_whole_representation() {
    let mut o = [ByteRange { start: 0, end: 0 }; 1];
    assert_eq!(
        byte_ranges(b"bytes=-99999999999999999999", 10, &mut o),
        Ok(RangeOutcome::Ranges(1))
    );
}

// F3, range.rs:480
#[test]
fn f03_nonzero_suffix_on_empty_representation_is_satisfiable() {
    let mut o = [ByteRange { start: 0, end: 0 }; 1];
    assert_ne!(
        byte_ranges(b"bytes=-1", 0, &mut o),
        Ok(RangeOutcome::Unsatisfiable)
    );
}

// F4, etag.rs:386-389, 416
#[test]
fn f04_star_with_a_comma_is_refused() {
    for v in [&b"*,"[..], b",*", b"*, ", b", *", b"*,,"] {
        assert!(
            parse_condition(v, &L).is_err(),
            "{:?}",
            String::from_utf8_lossy(v)
        );
    }
}
#[test]
fn f04b_if_none_match_star_comma_is_refused() {
    assert!(if_none_match(b"*,", &EntityTag::strong(b"v").unwrap()).is_err());
}

// F5, negotiate.rs:458
#[test]
fn f05_refused_offset_is_relative_to_the_value() {
    let v = b"text/html, image/png;q=2";
    let want = parse_accept(v, &L).unwrap_err();
    assert_eq!(want.offset(), 23);
    let Outcome::Refused(e) = strict().media(Some(v), &["text/html"]) else {
        panic!()
    };
    assert_eq!(e.offset(), 23);
}
#[test]
fn f05b_refused_names_the_line() {
    let lines: [&[u8]; 2] = [b"text/html", b"text/plain, image/png;q=2"];
    let Outcome::Refused(e) = strict().media_lines(lines, &["text/html"]) else {
        panic!()
    };
    assert_eq!((e.line(), e.offset()), (1, 24));
}

// F6, negotiate.rs:417, 392
#[test]
fn f06_absent_header_never_chooses_an_invalid_offer() {
    assert_eq!(best_media(None, &["not a type", "text/html"]), Some(1));
}
#[test]
fn f06b_ignored_header_never_chooses_an_invalid_offer() {
    assert_eq!(
        Negotiator::new()
            .media(Some(b"text/html;q=9"), &["not a type", "text/html"])
            .index(),
        Some(1)
    );
}

// F7, negotiate.rs:520, 975
#[test]
fn f07_language_range_grammar_is_enforced() {
    for v in [
        &b"en_US"[..],
        b"123456789",
        b"abcdefghi",
        b"en-abcdefghi",
        b"en-",
        b"-",
        b"!!!",
        b"en;foo=bar",
    ] {
        assert!(
            matches!(strict().language(Some(v), &["en"]), Outcome::Refused(_)),
            "{:?}",
            String::from_utf8_lossy(v)
        );
    }
}
#[test]
fn f07b_coding_members_take_a_weight_only() {
    assert!(matches!(
        strict().encoding(Some(b"gzip;foo=bar"), &["gzip"]),
        Outcome::Refused(_)
    ));
}
#[test]
fn f07c_charset_members_take_a_weight_only() {
    assert!(matches!(
        strict().charset(Some(b"utf-8;foo=bar"), &["utf-8"]),
        Outcome::Refused(_)
    ));
}

// F8, range.rs:265-286, 315-320, 619-647 and etag.rs:232-234, 81-82, 392-400
#[test]
fn f08_range_reports_control_kinds() {
    let mut o = [ByteRange { start: 0, end: 0 }; 1];
    assert_eq!(
        kind_at(byte_ranges(b"bytes=0-1\r", 10, &mut o)),
        (ErrorKind::BareCr, 9)
    );
    assert_eq!(
        kind_at(byte_ranges(b"bytes=0\n-1", 10, &mut o)),
        (ErrorKind::LineFeed, 7)
    );
    assert_eq!(
        kind_at(byte_ranges(b"bytes=0\x00-1", 10, &mut o)),
        (ErrorKind::Nul, 7)
    );
    assert_eq!(
        kind_at(byte_ranges(b"\rbytes=0-1", 10, &mut o)),
        (ErrorKind::BareCr, 0)
    );
    assert_eq!(
        kind_at(byte_ranges(b"by\rtes=0-1", 10, &mut o)),
        (ErrorKind::BareCr, 2)
    );
}
#[test]
fn f08b_content_range_reports_control_kinds() {
    assert_eq!(
        kind_at(range::parse_content_range(b"bytes 0-1/5\r")),
        (ErrorKind::BareCr, 11)
    );
    assert_eq!(
        kind_at(range::parse_content_range(b"bytes\r0-1/5")),
        (ErrorKind::BareCr, 5)
    );
}
#[test]
fn f08c_entity_tag_reports_control_kinds() {
    assert_eq!(
        kind_at(EntityTag::parse(b"\r\"a\"")),
        (ErrorKind::BareCr, 0)
    );
    assert_eq!(
        kind_at(EntityTag::parse(b"\"a\"\r")),
        (ErrorKind::BareCr, 3)
    );
    assert_eq!(
        kind_at(EntityTag::parse(b"W/\r\"a\"")),
        (ErrorKind::BareCr, 2)
    );
    assert_eq!(
        kind_at(parse_condition(b"\"a\",\r\"b\"", &L)),
        (ErrorKind::BareCr, 4)
    );
    assert_eq!(kind_at(parse_condition(b"\x00", &L)), (ErrorKind::Nul, 0));
}

// F9, text.rs:215, 313
#[test]
fn f09_control_after_backslash_keeps_its_kind() {
    assert_eq!(
        kind_at(text::parse_quoted(b"\"\\\r\"")),
        (ErrorKind::BareCr, 2)
    );
    assert_eq!(
        kind_at(text::parse_comment(b"(\\\n)", &L)),
        (ErrorKind::LineFeed, 2)
    );
    assert_eq!(kind_at(list(b"a, \"\\\x00\"")), (ErrorKind::Nul, 5));
}

// F10, cache.rs:596, 625
#[test]
fn f10_response_lines_budget_counts_across_lines() {
    let many: Vec<u8> = (0..1024).flat_map(|_| b"a,".iter().copied()).collect();
    let many = &many[..many.len() - 1];
    let two: [&[u8]; 2] = [many, many];
    assert!(list::combined(two, &L).is_err());
    assert_eq!(
        cache::response_lines(two).unwrap_err().kind(),
        ErrorKind::TooManyMembers
    );
}

// F11, cache.rs:88-114, etag.rs:372-420, range.rs:332-360 against list.rs:61
#[test]
fn f11_trailing_empty_element_counts_everywhere() {
    let a: Vec<u8> = core::iter::once(b'a').chain([b','; 17]).collect();
    assert_eq!(
        list::parse(&a, &L).unwrap_err().kind(),
        ErrorKind::TooManyEmptyElements
    );
    assert_eq!(
        cache::parse(&a, &L).unwrap_err().kind(),
        ErrorKind::TooManyEmptyElements
    );
}
#[test]
fn f11b_etag() {
    let mut t = b"\"a\"".to_vec();
    t.extend([b','; 17]);
    assert_eq!(
        parse_condition(&t, &L).unwrap_err().kind(),
        ErrorKind::TooManyEmptyElements
    );
}
#[test]
fn f11c_range() {
    let mut r = b"bytes=0-0".to_vec();
    r.extend([b','; 17]);
    assert_eq!(
        range::parse(&r, &L).unwrap_err().kind(),
        ErrorKind::TooManyEmptyElements
    );
}

// F12, etag.rs:386-391
#[test]
fn f12_star_after_tags_is_malformed() {
    assert_eq!(
        parse_condition(b"\"a\", *", &L).unwrap_err().kind(),
        ErrorKind::Malformed
    );
}

// F13, range.rs:645-647, 634, 640
#[test]
fn f13_content_range_shape_errors_are_invalid_range() {
    for v in [
        &b"bytes -1/5"[..],
        b"bytes 0-/5",
        b"bytes 0-1/",
        b"bytes */",
        b"bytes -/5",
    ] {
        assert_eq!(
            range::parse_content_range(v).unwrap_err().kind(),
            ErrorKind::InvalidRange,
            "{:?}",
            String::from_utf8_lossy(v)
        );
    }
}

// F14, etag.rs:394-395
#[test]
fn f14_unterminated_weak_tag_kind_matches_strong() {
    assert_eq!(
        parse_condition(b"W/\"a", &L).unwrap_err().kind(),
        parse_condition(b"\"a", &L).unwrap_err().kind()
    );
}

// F15: offsets. negotiate.rs:125-139, media.rs:178-181, negotiate.rs:981, 987-991
#[test]
fn f15a_qvalue_offset_is_the_bad_byte() {
    assert_eq!(QValue::parse(b"1.5").unwrap_err().offset(), 2);
    assert_eq!(QValue::parse(b"1.001").unwrap_err().offset(), 4);
}
#[test]
fn f15b_range_qvalue_offset_is_the_bad_byte() {
    assert_eq!(
        parse_accept(b"text/html;q=0.1x", &L).unwrap_err().offset(),
        15
    );
}
#[test]
fn f15c_weighted_trailing_offset_is_the_bad_byte() {
    assert_eq!(parse_weighted(b"gzip x", &L).unwrap_err().offset(), 5);
}
#[test]
fn f15d_weighted_quoted_q_offset_matches_accept() {
    assert_eq!(
        parse_weighted(b"a;x=1;q=\"0.5\"", &L).unwrap_err().offset(),
        6
    );
}

// F16, param.rs:414-416
#[test]
fn f16_raw_ends_at_the_last_parameter() {
    let r = media::parse_range(b"text/html;a=1 ;q=0.5", &L).unwrap();
    assert_eq!(r.params().raw(), b";a=1");
}

// F17, range.rs:811
#[test]
fn f17_if_range_reads_all_three_date_forms() {
    // An RFC 850 date needs a clock to place its year.
    assert!(range::parse_if_range_at(b"Sunday, 06-Nov-94 08:49:37 GMT", 1_792_540_800).is_ok());
    assert_eq!(
        range::parse_if_range(b"Sunday, 06-Nov-94 08:49:37 GMT")
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidDate
    );
}
#[test]
fn f17b_asctime() {
    assert!(range::parse_if_range(b"Sun Nov  6 08:49:37 1994").is_ok());
}
