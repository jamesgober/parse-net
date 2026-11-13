//! Regressions in the mail, Structured Field, and date code. Each test states what the contract or the RFC requires, for an input
//! that once got it wrong.

#![cfg(feature = "alloc")]

use parse_net::{
    ErrorKind as K, Limits, MailDate, SliceSink, WriteError,
    date::{civil_from_days, days_from_civil},
    mail::{self, MimeValue},
    structured::{self, Parser},
};

const L: Limits = Limits::DEFAULT;

fn dec(v: &[u8]) -> Result<String, (K, usize)> {
    let mut buf = vec![0u8; v.len() * 2 + 16];
    mail::decode_words(v, &mut buf)
        .map(String::from)
        .map_err(|e| (e.kind(), e.offset()))
}

fn enc(text: &str, room: usize) -> Vec<u8> {
    let mut v = Vec::new();
    mail::encode_words(text, room, &mut v).unwrap();
    v
}

fn fold(name: &str, value: &[u8]) -> Result<Vec<u8>, WriteError> {
    let mut v = Vec::new();
    mail::fold(name, value, &mut v).map(|()| v)
}

fn lines_ok(v: &[u8], max: usize) {
    for line in v.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        assert!(line.len() <= max, "{} bytes", line.len());
    }
}

fn param(v: &[u8], name: &str) -> Result<String, (K, usize)> {
    let (p, _) = mail::parse_mime_params(v, &L).map_err(|e| (e.kind(), e.offset()))?;
    let mut buf = [0u8; 256];
    p.decode_into(name, &mut buf)
        .map(|s| s.unwrap_or("").to_owned())
        .map_err(|e| (e.kind(), e.offset()))
}

// Finding 1 (quadratic work) is in tests/complexity.rs.

// Finding 2: raw controls in unstructured text.
#[test]
fn test_decode_words_refuses_raw_controls() {
    assert_eq!(dec(b"subject\r\nBcc: e@x.y").unwrap_err().0, K::BareCr);
    assert_eq!(dec(b"a\nb").unwrap_err().0, K::LineFeed);
    assert_eq!(dec(b"a\0b").unwrap_err(), (K::Nul, 1));
    assert_eq!(dec(b"a\x1b[31mb").unwrap_err(), (K::Control, 1));
    assert_eq!(dec(b"a\x7fb").unwrap_err(), (K::Control, 1));
    assert_eq!(dec(b"a\xc2\x85b").unwrap_err(), (K::Control, 2));
    assert_eq!(dec(b"\"a\rb\"").unwrap_err().0, K::BareCr);
    assert_eq!(dec(b"a\tb").unwrap(), "a\tb");
    assert_eq!(dec("caf\u{e9} ok".as_bytes()).unwrap(), "caf\u{e9} ok");
}

// Finding 3: C1 controls in RFC 2231 continuations.
#[test]
fn test_rfc2231_refuses_c1_across_sections() {
    for v in [
        &b"; t*0*=UTF-8''%C2%85"[..],
        b"; t*0*=UTF-8''%C2; t*1*=%85",
        b"; t*0*=iso-8859-1''%85",
        b"; t*0*=iso-8859-1''a; t*1=\"\x85\"",
    ] {
        assert_eq!(
            mail::parse_mime_params(v, &L).unwrap_err().kind(),
            K::ControlInDecoded,
            "{v:?}"
        );
    }
    // Plain U+00A0 and a section that happens to start with 0xA0 are text.
    assert_eq!(param(b"; t*0*=UTF-8''%C2%A0", "t").unwrap(), "\u{a0}");
}

// Finding 4: a section given twice.
#[test]
fn test_rfc2231_section_given_twice_refused() {
    for v in [
        &b"; t*0=a; t*0*=UTF-8''b"[..],
        b"; t*0*=UTF-8''b; t*0=a",
        b"; t*0=a; t*1=b; t*1*=c",
    ] {
        assert_eq!(
            mail::parse_mime_params(v, &L).unwrap_err().kind(),
            K::SectionGap,
            "{v:?}"
        );
    }
}

// Finding 5: Display String length.
#[test]
fn test_display_string_triples_count_toward_the_limit() {
    let long = format!("%\"{}\"", "%41".repeat(2000));
    assert_eq!(
        structured::parse_item(long.as_bytes()).unwrap_err().kind(),
        K::TooLong
    );
    let p = Parser::new(L.max_string_len(4));
    assert!(p.item(b"%\"%41%41%41%41\"").is_ok());
    assert_eq!(
        p.item(b"%\"%41%41%41%41%41\"").unwrap_err().kind(),
        K::TooLong
    );
}

// Finding 6: line lengths in the other writers.
#[test]
fn test_writers_keep_the_line_limit() {
    let long = "n".repeat(1000);
    let mut v = Vec::new();
    assert_eq!(
        mail::write_mime_param(&long, "x", &mut v),
        Err(WriteError::OutOfRange)
    );
    assert_eq!(
        mail::write_mime_param(&"n".repeat(80), "x", &mut v),
        Err(WriteError::OutOfRange)
    );
    assert!(v.is_empty());
    mail::write_mime_param(&"n".repeat(60), &"\u{e9}".repeat(20), &mut v).unwrap();
    lines_ok(&v, 78);

    assert_eq!(
        mail::write_msg_id(&"a".repeat(2000), "b.c", &mut Vec::new()),
        Err(WriteError::OutOfRange)
    );

    let plain = enc(&"a".repeat(1200), 60);
    assert!(plain.starts_with(b"=?UTF-8?Q?"), "encoded past the limit");
    lines_ok(&plain, 78);
    assert_eq!(enc("short", 10), b"short");
}

// Finding 7: section numbers past three digits.
#[test]
fn test_rfc2231_large_section_numbers() {
    assert_eq!(
        mail::parse_mime_params(b"; t*0=a; t*1000=b", &L)
            .unwrap_err()
            .kind(),
        K::TooManySections
    );
    // No section 0 at all is a gap first.
    assert_eq!(
        mail::parse_mime_params(b"; t*1000=b", &L)
            .unwrap_err()
            .kind(),
        K::SectionGap
    );
    assert_eq!(
        mail::parse_mime_params(b"; t*0=a; t*99999999999999999999999=b", &L)
            .unwrap_err()
            .kind(),
        K::TooManySections
    );
}

// Finding 8: fold refused what fits.
#[test]
fn test_fold_keeps_values_that_fit() {
    // A fold after the colon.
    let v = fold("S", &[b'w'; 997]).unwrap();
    lines_ok(&v, 998);
    assert_eq!(mail::unfold(&v).unwrap().iter().count(), 2);
    let long_name = "n".repeat(100);
    lines_ok(&fold(&long_name, &[b'w'; 950]).unwrap(), 998);
    let mut spaced = vec![b' '];
    spaced.extend_from_slice(&[b'w'; 950]);
    lines_ok(&fold(&long_name, &spaced).unwrap(), 998);
    // A long run of whitespace before a word.
    let mut run = vec![b'a'];
    run.extend_from_slice(&[b' '; 950]);
    run.extend_from_slice(&[b'w'; 100]);
    let v = fold("S", &run).unwrap();
    lines_ok(&v, 998);
    let joined: Vec<u8> = mail::unfold(&v)
        .unwrap()
        .iter()
        .flatten()
        .copied()
        .collect();
    assert_eq!(&joined[b"S: ".len()..], &run[..]);
    // Existing whitespace folds at 78 columns.
    let mut soft = vec![b' '];
    soft.extend_from_slice(&[b'w'; 75]);
    lines_ok(&fold("Subject", &soft).unwrap(), 78);
    // Still one line while it fits: the writer's own space does not fold.
    assert_eq!(fold("Subject", &[b'w'; 989]).unwrap().len(), 998);
    // A word that fits nowhere.
    assert_eq!(fold("S", &[b'w'; 998]), Err(WriteError::OutOfRange));
}

// Finding 9: what does not stand alone is not an encoded word.
#[test]
fn test_decode_words_ordinary_text_is_not_refused() {
    assert_eq!(dec(b"=?KOI8-R?Q?a?=x").unwrap(), "=?KOI8-R?Q?a?=x");
    assert_eq!(dec(b"=?UTF-8?Z?a?=x").unwrap(), "=?UTF-8?Z?a?=x");
    assert_eq!(dec(b"=?KOI8-R?Q?a?=").unwrap_err().0, K::UnsupportedCharset);
}

// Finding 10: encode then decode, folds included.
#[test]
fn test_decode_words_reads_folded_output() {
    let text = "\u{e9}".repeat(30);
    assert_eq!(dec(&enc(&text, 70)).unwrap(), text);
    // No leading fold, so no leading space.
    assert_eq!(dec(&enc("\u{e9}", 5)).unwrap(), "\u{e9}");
    assert_eq!(dec(b"a\r\n b").unwrap(), "a b");
}

// Finding 11: an unbalanced quote does not stop decoding.
#[test]
fn test_decode_words_lone_quote_is_text() {
    assert_eq!(
        dec(b"5\" disk =?UTF-8?Q?=C3=A9?=").unwrap(),
        "5\" disk \u{e9}"
    );
    assert_eq!(
        dec(b"say \"hi =?UTF-8?Q?=C3=A9?=").unwrap(),
        "say \"hi \u{e9}"
    );
    // A real quoted string still blocks it.
    assert_eq!(
        dec(b"\"=?UTF-8?Q?=C3=A9?=\" x").unwrap(),
        "\"=?UTF-8?Q?=C3=A9?=\" x"
    );
}

// Finding 12: US-ASCII in plain sections.
#[test]
fn test_rfc2231_us_ascii_applies_to_every_section() {
    assert_eq!(
        mail::parse_mime_params(b"; t*0*=us-ascii''a; t*1=\"\xc3\xa9\"", &L)
            .unwrap_err()
            .kind(),
        K::InvalidByte
    );
}

// Finding 13: RFC 2231 keeps `{` and `}`.
#[test]
fn test_rfc2231_attribute_chars() {
    assert_eq!(param(b"; t*=UTF-8''a{b}", "t").unwrap(), "a{b}");
    assert_eq!(param(b"; t*0*=UTF-8''a{; t*1*=b}", "t").unwrap(), "a{b}");
    // RFC 8187 for HTTP does not.
    assert!(parse_net::ExtendedValue::parse(b"UTF-8''a{b}").is_err());
}

// Finding 14: the calendar's clamp.
#[test]
fn test_civil_from_days_clamps_to_real_dates() {
    let last = days_from_civil(i32::MAX, 12, 31);
    assert_eq!(civil_from_days(last), (i32::MAX, 12, 31));
    assert_eq!(civil_from_days(last + 1), (i32::MAX, 12, 31));
    assert_eq!(civil_from_days(last + 60), (i32::MAX, 12, 31));
    let first = days_from_civil(i32::MIN, 1, 1);
    assert_eq!(civil_from_days(first), (i32::MIN, 1, 1));
    assert_eq!(civil_from_days(first - 1), (i32::MIN, 1, 1));
    let y = -2_147_482_000;
    assert_eq!(civil_from_days(days_from_civil(y, 6, 15)), (y, 6, 15));
}

// Finding 15: folds inside comments.
#[test]
fn test_mail_comments_may_fold() {
    assert!(MailDate::parse(b"21 Oct 2026 17:38 +0000 (a\r\n b)").is_ok());
    assert_eq!(param(b"; a=1 (x\r\n y)", "a").unwrap(), "1");
    assert!(mail::parse_mailbox(b"Jane (a\r\n b) <j@x.y>").is_ok());
    assert_eq!(
        MailDate::parse(b"21 Oct 2026 17:38 +0000 (a\rb)")
            .unwrap_err()
            .kind(),
        K::BareCr
    );
}

// Finding 16: comments around an angle address.
#[test]
fn test_mailbox_comments_around_the_address() {
    let m = mail::parse_mailbox(b"Jane <j@x.y> (work)").unwrap();
    assert_eq!(m.display_name, Some(&b"Jane"[..]));
    let m = mail::parse_mailbox(b"<a@b.c> (comment)").unwrap();
    assert_eq!(m.display_name, None);
    let m = mail::parse_mailbox(b"(comment) <a@b.c>").unwrap();
    assert_eq!(m.display_name, None);
    assert!(mail::parse_mailbox(b"<a@b.c> trailing").is_err());
    assert!(mail::parse_mailbox(b"<\"a>b\"@c.d>").is_ok());
    assert!(mail::parse_mailbox(b"\"a<b\"@c.d").is_ok());
    assert!(mail::parse_mailbox(b"a@b.c").is_ok());
}

// Finding 17: every control but HTAB.
#[test]
fn test_header_writers_refuse_every_control() {
    for v in [&b"a\x1bb"[..], b"a\x7fb", b"a\x01b"] {
        assert_eq!(mail::check_header_value(v).unwrap_err().kind(), K::Control);
        assert_eq!(fold("S", v), Err(WriteError::Forbidden { at: 1 }));
    }
    assert!(mail::check_header_value(b"a\tb").is_ok());
    assert!(fold("S", b"a\tb").is_ok());
    assert_eq!(
        mail::parse_addr_spec(b"\"a\\\nb\"@x.y").unwrap_err().kind(),
        K::LineFeed
    );
}

// Finding 18: offsets point at the failure, and refusals write nothing.
#[test]
fn test_mail_offsets_point_at_the_failure() {
    let at = |v: &[u8]| {
        let e = mail::parse_mime_params(v, &L).unwrap_err();
        (e.kind(), e.offset())
    };
    assert_eq!(at(b"; xxxxxxx=1; t*1=a"), (K::SectionGap, 13));
    assert_eq!(at(b"; t*0=a; t*2=b"), (K::SectionGap, 9));
    assert_eq!(at(b"; t*0=a; t*0=b").0, K::DuplicateParameter);
    assert_eq!(at(b"; t*0*=UTF-8''%41%0A"), (K::ControlInDecoded, 17));

    assert_eq!(
        dec(b"=?UTF-8?Q?a=0Ab?=").unwrap_err(),
        (K::ControlInDecoded, 11)
    );
    assert_eq!(
        dec(b"=?ISO-8859-1?Q?=E9?= raw \xff").unwrap_err(),
        (K::InvalidUtf8, 25)
    );

    let e = MailDate::parse(b"Mon, 30 Feb 2026 00:00 +0000").unwrap_err();
    assert_eq!((e.kind(), e.offset()), (K::InvalidDate, 5));
    let e = MailDate::parse(b"(c) Mon, 21 Oct 2026 00:00 +0000").unwrap_err();
    assert_eq!((e.kind(), e.offset()), (K::WeekdayMismatch, 4));

    let e = structured::parse_item(b"1.x").unwrap_err();
    assert_eq!((e.kind(), e.offset()), (K::InvalidNumber, 2));

    let mut buf = [7u8; 16];
    assert!(mail::decode_words(b"ok \xff", &mut buf).is_err());
    assert_eq!(buf, [7u8; 16], "nothing written");
    let (p, _) = mail::parse_mime_params(b"; t=\"\xff\"", &L).unwrap();
    assert_eq!(
        p.decode_into("t", &mut buf).unwrap_err().kind(),
        K::InvalidUtf8
    );
    assert_eq!(buf, [7u8; 16], "nothing written");
}

#[test]
fn test_continuation_decodes_after_the_checks() {
    let (p, _) = mail::parse_mime_params(b"; t*0*=UTF-8''%C3; t*1*=%A9x", &L).unwrap();
    let Some(MimeValue::Continued(c)) = p.get("t") else {
        panic!("a continuation")
    };
    let mut buf = [0u8; 16];
    assert_eq!(c.decode_into(&mut buf).unwrap(), "\u{e9}x");
    let mut out = [0u8; 8];
    let mut sink = SliceSink::new(&mut out);
    assert!(mail::encode_words("a", 60, &mut sink).is_ok());
}

// From the code added after 0.9.0 (`decode_phrase`,
// `write_mime_param_at`, `B` words, `param::parse_optional`).

fn phrase(v: &[u8]) -> Result<String, (K, usize)> {
    let mut buf = vec![0u8; v.len() * 2 + 16];
    mail::decode_phrase(v, &mut buf)
        .map(String::from)
        .map_err(|e| (e.kind(), e.offset()))
}

#[test]
fn test_phrase_encoded_word_needs_space_before_it() {
    // RFC 2047 section 5 (3): an encoded word in a phrase is separated by
    // whitespace from any adjacent word or special, on both sides. 0.9.2
    // checked only the side after it.
    assert_eq!(phrase(b"(c)=?UTF-8?Q?a?=").unwrap(), "=?UTF-8?Q?a?=");
    assert_eq!(phrase(b"\"x\"=?UTF-8?Q?a?=").unwrap(), "x =?UTF-8?Q?a?=");
    assert_eq!(phrase(b"(c)\r\n =?UTF-8?Q?a?=").unwrap(), "a");
    assert_eq!(phrase(b"\"x\"\t=?UTF-8?Q?a?=").unwrap(), "x a");
}

#[test]
fn test_mime_param_at_room_past_a_line() {
    // The room is 78 less what the line holds; a larger one would put a
    // whole value on one line past 78 columns, and past 998 bytes the
    // header could not be sent.
    let long = "x".repeat(1200);
    for room in [79, 500, usize::MAX] {
        let mut buf = vec![0u8; 4096];
        let mut out = SliceSink::new(&mut buf);
        let left = mail::write_mime_param_at("filename", &long, room, &mut out).unwrap();
        let w = std::str::from_utf8(out.written()).unwrap();
        assert!(w.split("\r\n").all(|line| line.len() <= 78), "{room}");
        assert_eq!(left, 78 - w.rsplit("\r\n").next().unwrap().len());
    }
    let mut buf = [0u8; 64];
    let mut out = SliceSink::new(&mut buf);
    assert_eq!(
        mail::write_mime_param_at("charset", "utf-8", usize::MAX, &mut out),
        Ok(78 - 15)
    );
    assert!(matches!(
        mail::write_mime_param_at("a", "b", 1000, &mut SliceSink::new(&mut [0u8; 2])),
        Err(WriteError::Full)
    ));
}
