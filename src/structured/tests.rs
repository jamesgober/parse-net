use super::*;
use std::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

fn k<T: core::fmt::Debug>(r: Result<T>) -> ErrorKind {
    r.unwrap_err().kind()
}

fn int(v: &[u8]) -> i64 {
    match parse_item(v).unwrap().bare {
        BareItem::Integer(i) => i,
        other => panic!("{other:?}"),
    }
}

fn no_slot() -> (&'static str, Member<'static>) {
    ("", Member::Item(Item::new(BareItem::Boolean(false))))
}

#[test]
fn test_integer_edge_cases() {
    assert_eq!(int(b"0"), 0);
    assert_eq!(int(b"-0"), 0);
    assert_eq!(int(b"999999999999999"), 999_999_999_999_999);
    assert_eq!(int(b"-999999999999999"), -999_999_999_999_999);
    assert_eq!(int(b"042"), 42);
    assert_eq!(
        k(parse_item(b"1000000000000000")),
        ErrorKind::NumberOverflow
    );
    assert_eq!(k(parse_item(b"-")), ErrorKind::InvalidNumber);
    assert_eq!(k(parse_item(b"--1")), ErrorKind::InvalidNumber);
    assert_eq!(k(parse_item(b"+1")), ErrorKind::InvalidByte);
    assert_eq!(k(parse_item(b"1a")), ErrorKind::TrailingData);
}

#[test]
fn test_decimal_edge_cases() {
    let d = |v: &[u8]| match parse_item(v).unwrap().bare {
        BareItem::Decimal(d) => d.thousandths(),
        other => panic!("{other:?}"),
    };
    assert_eq!(d(b"1.5"), 1500);
    assert_eq!(d(b"-0.001"), -1);
    assert_eq!(d(b"999999999999.999"), 999_999_999_999_999);
    assert_eq!(k(parse_item(b"1.")), ErrorKind::InvalidNumber);
    assert_eq!(k(parse_item(b"1.0001")), ErrorKind::NumberOverflow);
    assert_eq!(k(parse_item(b"1000000000000.0")), ErrorKind::NumberOverflow);
    assert_eq!(k(parse_item(b".5")), ErrorKind::InvalidByte);
    assert_eq!(k(parse_item(b"1.2.3")), ErrorKind::TrailingData);
    assert!(Decimal::from_thousandths(-1_000_000_000_000_000).is_err());
}

#[test]
fn test_string_edge_cases() {
    let BareItem::String(s) = parse_item(b"\"\"").unwrap().bare else {
        panic!()
    };
    assert_eq!(s.as_plain(), Some(""));
    let BareItem::String(s) = parse_item(br#""a\\b\"c""#).unwrap().bare else {
        panic!()
    };
    assert_eq!(s.as_plain(), None);
    assert_eq!(s.unescaped_len(), 5);
    assert!(s.eq_str("a\\b\"c"));
    assert!(!s.eq_str("a\\b\""));
    let mut short = [0u8; 4];
    assert_eq!(k(s.unescape_into(&mut short)), ErrorKind::BufferTooSmall);
    assert_eq!(short, [0; 4]);
    assert_eq!(k(parse_item(br#""\n""#)), ErrorKind::InvalidQuotedPair);
    assert_eq!(k(parse_item(b"\"abc")), ErrorKind::UnterminatedQuote);
    assert_eq!(k(parse_item(b"\"a\\")), ErrorKind::UnterminatedQuote);
    assert_eq!(k(parse_item(b"\"a\tb\"")), ErrorKind::InvalidByte);
    assert_eq!(k(parse_item(b"\"a\x00b\"")), ErrorKind::Nul);
    assert_eq!(
        k(parse_item("\"\u{e9}\"".as_bytes())),
        ErrorKind::InvalidByte
    );
}

#[test]
fn test_token_and_boolean() {
    assert_eq!(
        parse_item(b"*foo/bar:1").unwrap().bare,
        BareItem::Token("*foo/bar:1")
    );
    assert_eq!(parse_item(b"?0").unwrap().bare, BareItem::Boolean(false));
    assert_eq!(k(parse_item(b"?")), ErrorKind::InvalidByte);
    assert_eq!(k(parse_item(b"?2")), ErrorKind::InvalidByte);
    assert_eq!(k(parse_item(b"?1x")), ErrorKind::TrailingData);
}

#[test]
fn test_byte_seq_edge_cases() {
    let len = |v: &[u8]| match parse_item(v).unwrap().bare {
        BareItem::ByteSeq(b) => b.decoded_len(),
        other => panic!("{other:?}"),
    };
    assert_eq!(len(b"::"), 0);
    assert_eq!(len(b":YQ==:"), 1);
    assert_eq!(len(b":YQ:"), 1);
    assert_eq!(len(b":YWI=:"), 2);
    assert_eq!(len(b":YWJj:"), 3);
    assert_eq!(k(parse_item(b":Y:")), ErrorKind::InvalidBase64);
    assert_eq!(k(parse_item(b":YQ=:")), ErrorKind::InvalidBase64);
    assert_eq!(k(parse_item(b":YWJj=:")), ErrorKind::InvalidBase64);
    assert_eq!(k(parse_item(b":YQ===:")), ErrorKind::InvalidBase64);
    assert_eq!(k(parse_item(b":YQ")), ErrorKind::UnterminatedQuote);
    assert_eq!(k(parse_item(b":Y Q:")), ErrorKind::InvalidBase64);
    assert_eq!(k(parse_item(b":YQ=a:")), ErrorKind::InvalidBase64);
}

#[test]
fn test_date_edge_cases() {
    assert_eq!(parse_item(b"@0").unwrap().bare, BareItem::Date(0));
    assert_eq!(parse_item(b"@-1").unwrap().bare, BareItem::Date(-1));
    assert_eq!(k(parse_item(b"@1.5")), ErrorKind::InvalidNumber);
    assert_eq!(k(parse_item(b"@")), ErrorKind::InvalidNumber);
    assert_eq!(k(parse_item(b"@999999999999999")), ErrorKind::OutOfRange);
}

#[test]
fn test_display_string_edge_cases() {
    let BareItem::DisplayString(d) = parse_item(b"%\"\"").unwrap().bare else {
        panic!()
    };
    assert_eq!(d.decoded_len(), 0);
    let BareItem::DisplayString(d) = parse_item(b"%\"f%c3%bc%c3%bc\"").unwrap().bare else {
        panic!()
    };
    assert_eq!(d.decoded_len(), 5);
    let mut buf = [0u8; 5];
    assert_eq!(d.decode_into(&mut buf).unwrap(), "f\u{fc}\u{fc}");
    assert_eq!(
        k(parse_item(b"%\"%C3%BC\"")),
        ErrorKind::InvalidPercentEncoding
    );
    assert_eq!(k(parse_item(b"%\"%c3\"")), ErrorKind::InvalidUtf8);
    assert_eq!(k(parse_item(b"%\"%c3a\"")), ErrorKind::InvalidUtf8);
    assert_eq!(k(parse_item(b"%\"%c0%af\"")), ErrorKind::InvalidUtf8);
    assert_eq!(k(parse_item(b"%\"%ed%a0%80\"")), ErrorKind::InvalidUtf8);
    assert_eq!(
        k(parse_item(b"%\"%g0\"")),
        ErrorKind::InvalidPercentEncoding
    );
    assert_eq!(k(parse_item(b"%\"%a\"")), ErrorKind::InvalidPercentEncoding);
    assert_eq!(k(parse_item(b"%x")), ErrorKind::InvalidByte);
    assert_eq!(
        k(parse_item("%\"\u{fc}\"".as_bytes())),
        ErrorKind::InvalidByte
    );
    assert_eq!(k(parse_item(b"%\"abc")), ErrorKind::UnterminatedQuote);
}

#[test]
fn test_params_edge_cases() {
    let i = parse_item(b"1; a; b=?0;c=\"x\";a=2").unwrap();
    assert_eq!(i.params.len(), 4);
    assert_eq!(i.params.get("a"), Some(BareItem::Integer(2)));
    assert_eq!(i.params.get("b"), Some(BareItem::Boolean(false)));
    assert_eq!(i.params.get("z"), None);
    let keys: Vec<&str> = i.params.iter().map(|(k, _)| k).collect();
    assert_eq!(keys, ["a", "b", "c", "a"]);
    assert_eq!(k(parse_item(b"1;A=1")), ErrorKind::InvalidKey);
    assert_eq!(k(parse_item(b"1;")), ErrorKind::InvalidKey);
    assert_eq!(k(parse_item(b"1 ;a")), ErrorKind::TrailingData);
    assert_eq!(k(parse_item(b"1;a =1")), ErrorKind::TrailingData);
    assert_eq!(k(parse_item(b"1;a=(1)")), ErrorKind::InvalidByte);
}

#[test]
fn test_list_edge_cases() {
    assert!(parse_list(b"").unwrap().is_empty());
    assert!(parse_list(b"   ").unwrap().is_empty());
    let l = parse_list(b"  a ,\tb,c  ").unwrap();
    assert_eq!(l.len(), 3);
    let toks: Vec<_> = l
        .iter()
        .map(|m| match m {
            Member::Item(i) => i.bare,
            Member::InnerList(_) => panic!(),
        })
        .collect();
    assert_eq!(
        toks,
        [
            BareItem::Token("a"),
            BareItem::Token("b"),
            BareItem::Token("c")
        ]
    );
    assert_eq!(k(parse_list(b"a,")), ErrorKind::TrailingSeparator);
    assert_eq!(k(parse_list(b"a, ")), ErrorKind::TrailingSeparator);
    assert_eq!(k(parse_list(b",a")), ErrorKind::InvalidByte);
    assert_eq!(k(parse_list(b"a,,b")), ErrorKind::InvalidByte);
    assert_eq!(k(parse_list(b"a b")), ErrorKind::ExpectedSeparator);
    assert_eq!(k(parse_list(b"\ta")), ErrorKind::InvalidByte);
}

#[test]
fn test_inner_list_edge_cases() {
    let l = parse_list(b"(), ( 1  2 );a=1;b, (\"x\";p)").unwrap();
    let members: Vec<_> = l.iter().collect();
    assert_eq!(members.len(), 3);
    let Member::InnerList(empty) = members[0] else {
        panic!()
    };
    assert!(empty.is_empty() && empty.params().is_empty());
    let Member::InnerList(two) = members[1] else {
        panic!()
    };
    assert_eq!(two.len(), 2);
    let items: Vec<_> = two.iter().map(|i| i.bare).collect();
    assert_eq!(items, [BareItem::Integer(1), BareItem::Integer(2)]);
    assert_eq!(two.params().get("a"), Some(BareItem::Integer(1)));
    assert_eq!(two.params().get("b"), Some(BareItem::Boolean(true)));
    let Member::InnerList(one) = members[2] else {
        panic!()
    };
    assert_eq!(
        one.iter().next().unwrap().params.get("p"),
        Some(BareItem::Boolean(true))
    );
    assert_eq!(k(parse_list(b"(1")), ErrorKind::UnterminatedQuote);
    assert_eq!(k(parse_list(b"(1 ")), ErrorKind::UnterminatedQuote);
    assert_eq!(k(parse_list(b"(1,2)")), ErrorKind::ExpectedSeparator);
    assert_eq!(k(parse_list(b"((1))")), ErrorKind::InvalidByte);
    assert_eq!(k(parse_list(b"(1\t2)")), ErrorKind::ExpectedSeparator);
    assert_eq!(k(parse_item(b"(1)")), ErrorKind::InvalidByte);
}

#[test]
fn test_dictionary_edge_cases() {
    let d = parse_dictionary(b"a=1, b, c=(x y);q, d;p=?0, a=2").unwrap();
    assert_eq!(d.len(), 5);
    assert!(matches!(d.get("a"), Some(Member::Item(i)) if i.bare == BareItem::Integer(2)));
    assert!(matches!(d.get("b"), Some(Member::Item(i)) if i.bare == BareItem::Boolean(true)));
    assert!(matches!(d.get("c"), Some(Member::InnerList(l)) if l.len() == 2));
    let Some(Member::Item(dd)) = d.get("d") else {
        panic!()
    };
    assert_eq!(dd.bare, BareItem::Boolean(true));
    assert_eq!(dd.params.get("p"), Some(BareItem::Boolean(false)));
    assert!(d.get("e").is_none());
    let keys: Vec<_> = d.iter().map(|(k, _)| k).collect();
    assert_eq!(keys, ["a", "b", "c", "d", "a"]);
    assert_eq!(k(parse_dictionary(b"A=1")), ErrorKind::InvalidKey);
    assert_eq!(k(parse_dictionary(b"a=1,")), ErrorKind::TrailingSeparator);
    assert_eq!(k(parse_dictionary(b"a =1")), ErrorKind::ExpectedSeparator);
    assert_eq!(k(parse_dictionary(b"1=a")), ErrorKind::InvalidKey);
}

#[test]
fn test_index_into_too_few_slots_refused() {
    let d = parse_dictionary(b"a, b, a, c").unwrap();
    let mut slots = [no_slot(); 2];
    assert_eq!(k(d.index_into(&mut slots)), ErrorKind::BufferTooSmall);
    let mut slots = [no_slot(); 3];
    let keys: Vec<_> = d
        .index_into(&mut slots)
        .unwrap()
        .iter()
        .map(|(k, _)| *k)
        .collect();
    assert_eq!(keys, ["a", "b", "c"]);
}

#[test]
fn test_limits_plus_one_refused() {
    let p = Parser::new;
    let at = |n: usize| vec!["a"; n].join(",");
    let l = Limits::DEFAULT.max_list_members(3);
    assert!(p(l).list(at(3).as_bytes()).is_ok());
    assert_eq!(k(p(l).list(at(4).as_bytes())), ErrorKind::TooManyMembers);
    let l = Limits::DEFAULT.max_dictionary_members(3);
    assert!(p(l).dictionary(at(3).as_bytes()).is_ok());
    assert_eq!(
        k(p(l).dictionary(at(4).as_bytes())),
        ErrorKind::TooManyMembers
    );
    let l = Limits::DEFAULT.max_inner_list_members(2);
    assert!(p(l).list(b"(1 2)").is_ok());
    assert_eq!(k(p(l).list(b"(1 2 3)")), ErrorKind::TooManyMembers);
    let l = Limits::DEFAULT.max_params(1);
    assert!(p(l).item(b"1;a").is_ok());
    assert_eq!(k(p(l).item(b"1;a;b")), ErrorKind::TooManyMembers);
    let l = Limits::DEFAULT.max_key_len(2);
    assert!(p(l).item(b"1;ab").is_ok());
    assert_eq!(k(p(l).item(b"1;abc")), ErrorKind::TooLong);
    let l = Limits::DEFAULT.max_string_len(2);
    assert!(p(l).item(br#""a\"""#).is_ok());
    assert_eq!(k(p(l).item(b"\"abc\"")), ErrorKind::TooLong);
    assert_eq!(k(p(l).item(b"%\"abc\"")), ErrorKind::TooLong);
    let l = Limits::DEFAULT.max_token_len(2);
    assert!(p(l).item(b"ab").is_ok());
    assert_eq!(k(p(l).item(b"abc")), ErrorKind::TooLong);
    let l = Limits::DEFAULT.max_byte_seq_len(2);
    assert!(p(l).item(b":YWI=:").is_ok());
    assert_eq!(k(p(l).item(b":YWJj:")), ErrorKind::TooLong);
}

#[test]
fn test_default_limits_meet_rfc_minimums() {
    let members = vec!["a"; 1024].join(",");
    assert_eq!(parse_list(members.as_bytes()).unwrap().len(), 1024);
    let inner = format!("({})", vec!["1"; 256].join(" "));
    assert!(parse_list(inner.as_bytes()).is_ok());
    let mut params = String::new();
    for i in 0..256 {
        params.push_str(";k");
        params.push_str(&i.to_string());
    }
    assert!(parse_item(format!("1{params}").as_bytes()).is_ok());
    let key = "k".repeat(64);
    assert!(parse_dictionary(format!("{key}=1").as_bytes()).is_ok());
    let s = format!("\"{}\"", "x".repeat(1024));
    assert!(parse_item(s.as_bytes()).is_ok());
    let t = "t".repeat(512);
    assert!(parse_item(t.as_bytes()).is_ok());
    let b = format!(":{}:", "AAAA".repeat(16384 / 3));
    assert!(parse_item(b.as_bytes()).is_ok());
}

#[test]
fn test_lines_combined() {
    let lines: [&[u8]; 3] = [b"a=1", b" b ", b"a=3"];
    let d = parse_dictionary_lines(&lines).unwrap();
    assert_eq!(d.len(), 3);
    assert!(matches!(d.get("a"), Some(Member::Item(i)) if i.bare == BareItem::Integer(3)));
    assert_eq!(d.iter().count(), 3);
    let lines: [&[u8]; 2] = [b"1, 2", b"(3 4)"];
    let l = parse_list_lines(&lines).unwrap();
    assert_eq!(l.len(), 3);
    assert_eq!(l.iter().count(), 3);
    let bad: [&[u8]; 2] = [b"1", b""];
    let e = parse_list_lines(&bad).unwrap_err();
    assert_eq!((e.kind(), e.line()), (ErrorKind::Empty, 1));
    let bad: [&[u8]; 2] = [b"1", b"2,"];
    let e = parse_list_lines(&bad).unwrap_err();
    assert_eq!((e.kind(), e.line()), (ErrorKind::TrailingSeparator, 1));
    let lim = Parser::new(Limits::DEFAULT.max_list_members(2));
    let three: [&[u8]; 2] = [b"1, 2", b"3"];
    assert_eq!(k(lim.list_lines(&three)), ErrorKind::TooManyMembers);
}

#[derive(Default)]
struct Log(Vec<String>);

impl<'a> Visitor<'a> for Log {
    fn item(&mut self, bare: BareItem<'a>) -> Result<()> {
        self.0.push(format!("i:{bare:?}"));
        Ok(())
    }
    fn param(&mut self, key: &'a str, _: BareItem<'a>) -> Result<()> {
        self.0.push(format!("p:{key}"));
        Ok(())
    }
    fn inner_list_start(&mut self) -> Result<()> {
        self.0.push("(".into());
        Ok(())
    }
    fn inner_list_end(&mut self) -> Result<()> {
        self.0.push(")".into());
        Ok(())
    }
    fn key(&mut self, key: &'a str) -> Result<()> {
        self.0.push(format!("k:{key}"));
        Ok(())
    }
}

#[test]
fn test_visitor_events_in_order() {
    let mut log = Log::default();
    Parser::default()
        .visit_dictionary(b"a=(1);x, b;y", &mut log)
        .unwrap();
    assert_eq!(
        log.0,
        [
            "k:a",
            "(",
            "i:Integer(1)",
            ")",
            "p:x",
            "k:b",
            "i:Boolean(true)",
            "p:y"
        ]
    );
    let mut log = Log::default();
    Parser::default().visit_item(b"?1;z", &mut log).unwrap();
    assert_eq!(log.0, ["i:Boolean(true)", "p:z"]);
}

#[test]
fn test_visitor_error_stops_parse() {
    struct Stop;
    impl<'a> Visitor<'a> for Stop {
        fn item(&mut self, _: BareItem<'a>) -> Result<()> {
            err(ErrorKind::Malformed, 7)
        }
        fn param(&mut self, _: &'a str, _: BareItem<'a>) -> Result<()> {
            Ok(())
        }
    }
    let e = Parser::default()
        .visit_list(b"1, 2", &mut Stop)
        .unwrap_err();
    assert_eq!((e.kind(), e.offset()), (ErrorKind::Malformed, 7));
}

#[test]
fn test_views_agree_with_visitor() {
    let inputs: [&[u8]; 4] = [
        b"a, (b c);d, \"e\"",
        b"1;a;b=2",
        b"()",
        b"?0, @1, %\"x\", :AA==:",
    ];
    for v in inputs {
        let mut log = Log::default();
        Parser::default().visit_list(v, &mut log).unwrap();
        let items = log.0.iter().filter(|e| e.starts_with("i:")).count();
        let seen: usize = parse_list(v)
            .unwrap()
            .iter()
            .map(|m| match m {
                Member::Item(_) => 1,
                Member::InnerList(l) => l.iter().count(),
            })
            .sum();
        assert_eq!(seen, items);
    }
}

#[test]
fn test_offsets_point_at_failure() {
    let e = parse_list(b"  a, b c").unwrap_err();
    assert_eq!((e.kind(), e.offset()), (ErrorKind::ExpectedSeparator, 7));
    let e = parse_item(b"\"ab\\x\"").unwrap_err();
    assert_eq!(e.offset(), 4);
}

#[test]
fn test_control_bytes_named() {
    assert_eq!(k(parse_list(b"a,\rb")), ErrorKind::BareCr);
    assert_eq!(k(parse_list(b"a\n")), ErrorKind::LineFeed);
    assert_eq!(k(parse_item(b"\x7f")), ErrorKind::Control);
}

#[test]
fn test_long_input_linear() {
    let big = "a, ".repeat(1000) + "a";
    let p = Parser::new(Limits::DEFAULT.max_list_members(u16::MAX));
    assert_eq!(p.list(big.as_bytes()).unwrap().len(), 1001);
    let s = format!("\"{}\"", "\\\\".repeat(1000));
    let p = Parser::new(Limits::DEFAULT.max_string_len(u16::MAX));
    assert!(p.item(s.as_bytes()).is_ok());
}
