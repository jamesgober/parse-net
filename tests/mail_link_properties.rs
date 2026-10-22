//! Property tests for the 0.5 parsers and writers: `Link`, the email layer,
//! `MailDate`, `Forwarded` writing, and the Structured Field writer. No
//! parser panics on any input, and every writer's output parses back to
//! what was written (the writer-parser closure check).

use core::net::IpAddr;

use parse_net::{
    Limits, MailDate, SliceSink, forwarded, link, mail,
    sfv::{self, BareItem, Member, Writer},
};
use proptest::prelude::*;

fn bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..96)
}

/// Bytes weighted toward the delimiters the mail and link grammars use.
fn grammar_bytes() -> impl Strategy<Value = Vec<u8>> {
    let interesting = prop::sample::select(
        b"azAZ09<>@.;=,:*'%\"\\()[] \t\r\n?_-=+/!#\x00\x7f\xc3\xa9\x80".to_vec(),
    );
    prop::collection::vec(interesting, 0..64)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn test_mail_and_link_parsers_never_panic(v in bytes(), g in grammar_bytes()) {
        let mut out = [0u8; 512];
        for input in [&v[..], &g[..]] {
            if let Ok(l) = parse_net::parse_link(input, &Limits::DEFAULT) {
                for x in l.iter() {
                    let _ = x.rels().count();
                    if let Some(t) = x.title() {
                        let _ = t.decode_into(&mut out);
                    }
                }
            }
            let _ = MailDate::parse(input, false);
            let _ = MailDate::parse(input, true);
            let _ = mail::check_header_value(input);
            if let Ok(u) = mail::unfold(input) {
                let _ = u.iter().count();
            }
            let _ = mail::decode_words(input, &Limits::DEFAULT, &mut out);
            if let Ok((p, _)) = mail::parse_mime_params(input, &Limits::DEFAULT) {
                for (n, _) in p.iter() {
                    if let Ok(n) = std::str::from_utf8(n) {
                        let _ = p.decode_into(n, &mut out);
                    }
                }
            }
            let _ = mail::parse_addr_spec(input);
            let _ = mail::parse_mailbox(input, &Limits::DEFAULT);
            let _ = mail::parse_msg_id(input);
        }
    }

    #[test]
    fn test_link_write_round_trip(
        target in "[a-zA-Z0-9/?#:@!$&'()*+,;=._~-]{0,24}",
        params in prop::collection::vec(("[a-z][a-z0-9-]{0,6}", "[ -~]{0,10}"), 0..4),
    ) {
        let pairs: Vec<(&str, &str)> = params.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
        let mut buf = [0u8; 512];
        let mut out = SliceSink::new(&mut buf);
        link::write_link(target.as_bytes(), &pairs, &mut out).expect("valid input");
        let l = parse_net::parse_link(out.written(), &Limits::DEFAULT).expect("written link parses");
        let v = l.iter().next().expect("one link");
        prop_assert_eq!(v.target(), target.as_bytes());
        let got: Vec<_> = v.params().iter().collect();
        prop_assert_eq!(got.len(), pairs.len());
        for ((name, w), (n, val)) in got.iter().zip(&pairs) {
            prop_assert_eq!(*name, n.as_bytes());
            match w {
                None => prop_assert!(val.is_empty()),
                Some(w) => prop_assert!(w.eq_bytes(val.as_bytes())),
            }
        }
    }

    #[test]
    fn test_mail_date_round_trip(secs in -62_135_596_800i64..253_402_300_799, off in -5999i16..=5999) {
        if let Ok(d) = MailDate::new(secs, off) {
            let (b, n) = d.format();
            let back = MailDate::parse(&b[..n], false).expect("formatted date parses");
            prop_assert_eq!((back.utc(), back.offset_minutes()), (secs, off));
        }
    }

    #[test]
    fn test_encoded_words_round_trip(text in "\\PC{0,80}", room in 0usize..90) {
        let mut buf = vec![0u8; 8192];
        let mut out = SliceSink::new(&mut buf);
        mail::encode_words(&text, room, &mut out).expect("no control characters");
        let flat: Vec<u8> = mail::unfold(out.written()).expect("unfolds").iter().flatten().copied().collect();
        let mut dec = vec![0u8; 8192];
        let l = Limits::DEFAULT.max_encoded_words(u16::MAX);
        // When nothing fits in `room`, the words start after a fold, whose
        // space stays in front (as it would after `Subject:`).
        let lead = if out.written().starts_with(b"\r\n ") { " " } else { "" };
        prop_assert_eq!(mail::decode_words(&flat, &l, &mut dec).expect("decodes"), format!("{lead}{text}"));
    }

    #[test]
    fn test_mime_param_round_trip(value in "\\PC{0,200}") {
        let mut buf = vec![0u8; 8192];
        let mut out = SliceSink::new(&mut buf);
        mail::write_mime_param("filename", &value, &mut out).expect("no control characters");
        let written = out.written();
        prop_assert!(written.split(|&b| b == b'\n').all(|l| l.len() <= 79));
        let (p, used) = mail::parse_mime_params(written, &Limits::DEFAULT).expect("written parameter parses");
        prop_assert_eq!(used, written.len());
        let mut dec = vec![0u8; 8192];
        prop_assert_eq!(p.decode_into("filename", &mut dec).expect("decodes"), Some(value.as_str()));
    }

    #[test]
    fn test_fold_round_trip(words in prop::collection::vec("[!-~]{1,30}", 1..40)) {
        let value = words.join(" ");
        let mut buf = vec![0u8; 8192];
        let mut out = SliceSink::new(&mut buf);
        mail::fold("Subject", value.as_bytes(), &mut out).expect("short words fold");
        let written = out.written();
        prop_assert!(written.split(|&b| b == b'\n').all(|l| l.len() <= 79));
        let body = &written[b"Subject: ".len()..];
        let flat: Vec<u8> = mail::unfold(body).expect("unfolds").iter().flatten().copied().collect();
        prop_assert_eq!(flat, value.into_bytes());
    }

    #[test]
    fn test_addr_spec_round_trip(local in "[a-z0-9!#$%&'*+/=?^_`{|}~-]{1,10}(\\.[a-z0-9-]{1,8}){0,2}", domain in "[a-z0-9-]{1,10}(\\.[a-z]{2,6}){1,2}") {
        let text = format!("{local}@{domain}");
        let a = mail::parse_addr_spec(text.as_bytes()).expect("generated address parses");
        prop_assert!(a.is_ascii());
        let mut buf = [0u8; 128];
        let mut out = SliceSink::new(&mut buf);
        mail::write_msg_id(&local, &domain, &mut out).expect("dot-atoms write");
        let id = mail::parse_msg_id(out.written()).expect("written id parses");
        prop_assert_eq!((id.left, id.right), (local.as_bytes(), domain.as_bytes()));
    }

    #[test]
    fn test_forwarded_element_round_trip(a in any::<[u8; 4]>(), b in any::<[u16; 8]>(), port in prop::option::of(any::<u16>()), https in any::<bool>()) {
        let v4 = IpAddr::from(a);
        let v6 = IpAddr::from(b);
        let e = forwarded::Element {
            for_: Some(forwarded::Node::Addr(v4, port.map(forwarded::NodePort::Number))),
            by: Some(forwarded::Node::Addr(v6, None)),
            host: None,
            proto: Some(if https { forwarded::Proto::Https } else { forwarded::Proto::Http }),
        };
        let mut buf = [0u8; 128];
        let mut out = SliceSink::new(&mut buf);
        forwarded::write_element(&e, &mut out).expect("room");
        let lines = [out.written()];
        let parsed = forwarded::parse(&lines, &Limits::DEFAULT).expect("written element parses");
        prop_assert_eq!(parsed.iter().next(), Some(e));
    }

    #[test]
    fn test_sfv_writer_round_trip(ints in prop::collection::vec(-999_999_999_999_999i64..=999_999_999_999_999, 1..5), decs in prop::collection::vec(-999_999_999_999_999i64..=999_999_999_999_999, 0..3), strs in prop::collection::vec("[ -~]{0,12}", 0..3), toks in prop::collection::vec("[a-zA-Z*][a-zA-Z0-9:/!#$%&'*+.^_`|~-]{0,8}", 0..3), disp in "\\PC{0,12}") {
        let mut buf = vec![0u8; 4096];
        let mut out = SliceSink::new(&mut buf);
        let mut w = Writer::list(&mut out);
        for &i in &ints {
            w.integer(i).expect("in range");
        }
        for &d in &decs {
            w.decimal(d).expect("in range");
        }
        w.open_inner_list().expect("open");
        for s in &strs {
            w.string(s).expect("printable");
        }
        for t in &toks {
            w.token(t).expect("token");
        }
        w.close_inner_list().expect("close");
        w.param_key("d").expect("key").display_string(&disp).expect("text");
        w.finish().expect("finish");
        let l = sfv::parse_list(out.written()).expect("written list parses");
        let members: Vec<_> = l.iter().collect();
        prop_assert_eq!(members.len(), ints.len() + decs.len() + 1);
        for (m, &i) in members.iter().zip(&ints) {
            prop_assert!(matches!(m, Member::Item(x) if x.bare == BareItem::Integer(i)));
        }
        for (m, &d) in members[ints.len()..].iter().zip(&decs) {
            prop_assert!(matches!(m, Member::Item(x) if matches!(x.bare, BareItem::Decimal(v) if v.thousandths() == d)));
        }
        let Some(Member::InnerList(inner)) = members.last() else {
            return Err(TestCaseError::fail("no inner list"));
        };
        let items: Vec<_> = inner.iter().collect();
        prop_assert_eq!(items.len(), strs.len() + toks.len());
        for (i, s) in items.iter().zip(&strs) {
            prop_assert!(matches!(i.bare, BareItem::String(x) if x.eq_str(s)));
        }
        let Some(BareItem::DisplayString(d)) = inner.params().get("d") else {
            return Err(TestCaseError::fail("no display string"));
        };
        let mut text = vec![0u8; 256];
        prop_assert_eq!(d.decode_into(&mut text).expect("decodes"), disp.as_str());
    }
}
