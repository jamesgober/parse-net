//! Property tests for the web layer (0.4): no parser panics on any input,
//! every writer's output parses back to what was written (the
//! writer-parser closure check), and Structured Field lists and
//! dictionaries split into lines at member boundaries read as the whole
//! value.

use core::net::IpAddr;

use parse_net::{
    self as pn, ByteRange, ContentRange, EntityTag, ForwardedSource, Limits, OriginValue,
    SliceSink, auth, cache, etag, forwarded, media, negotiate, range,
    sfv::{self, Member},
};
use proptest::prelude::*;

fn bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..96)
}

/// Bytes weighted toward the delimiters the web-layer grammars care about.
fn grammar_bytes() -> impl Strategy<Value = Vec<u8>> {
    let interesting = prop::sample::select(
        b"abcz09-._*/:;=,\"\\()[]<>@?%' \t\r\nW/=+qQ*\x00\x7f\x80\xc3\xa9".to_vec(),
    );
    prop::collection::vec(interesting, 0..64)
}

/// A Structured Field bare item, as text.
fn sf_bare() -> impl Strategy<Value = String> {
    prop_oneof![
        (-999_999_999_999_999i64..=999_999_999_999_999).prop_map(|i| i.to_string()),
        (-999_999_999_999i64..=999_999_999_999, 0u16..1000)
            .prop_map(|(i, f)| format!("{i}.{f:03}")),
        "[ !#-\\[\\]-~]{0,8}".prop_map(|s| format!("\"{s}\"")),
        "[a-zA-Z*][a-zA-Z0-9:/!#$%&'*+.^_`|~-]{0,8}",
        "([A-Za-z0-9+/]{4}){0,3}".prop_map(|s| format!(":{s}:")),
        any::<bool>().prop_map(|b| if b {
            "?1".to_string()
        } else {
            "?0".to_string()
        }),
        (0i64..253_402_300_799).prop_map(|d| format!("@{d}")),
        "[a-z ]{0,6}".prop_map(|s| format!("%\"{s}%c3%a9\"")),
    ]
}

fn sf_params() -> impl Strategy<Value = String> {
    prop::collection::vec(
        ("[a-z*][a-z0-9_.*-]{0,4}", prop::option::of(sf_bare())),
        0..3,
    )
    .prop_map(|ps| {
        ps.into_iter()
            .map(|(k, v)| match v {
                Some(v) => format!(";{k}={v}"),
                None => format!(";{k}"),
            })
            .collect()
    })
}

fn sf_member() -> impl Strategy<Value = String> {
    prop_oneof![
        (sf_bare(), sf_params()).prop_map(|(b, p)| b + &p),
        (
            prop::collection::vec((sf_bare(), sf_params()), 0..3),
            sf_params()
        )
            .prop_map(|(items, p)| {
                let inner: Vec<String> = items.into_iter().map(|(b, p)| b + &p).collect();
                format!("({}){p}", inner.join(" "))
            }),
    ]
}

/// Joins `parts` into lines, cutting where `cuts` says.
fn split_lines(parts: &[String], cuts: &[bool]) -> Vec<String> {
    let mut lines = vec![String::new()];
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            if cuts[i % cuts.len()] {
                lines.push(String::new());
            } else {
                lines.last_mut().expect("one line").push_str(", ");
            }
        }
        lines.last_mut().expect("one line").push_str(p);
    }
    lines
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn test_web_parsers_never_panic(v in bytes(), g in grammar_bytes()) {
        let l = Limits::DEFAULT;
        let mut out = [0u8; 256];
        let mut ranges = [ByteRange { start: 0, end: 0 }; 8];
        for input in [&v[..], &g[..]] {
            let _ = media::parse_range(input, &l);
            let _ = pn::best_media(Some(input), &["text/html", "application/json"]);
            let _ = pn::best_language(Some(input), &["en", "de-CH"]);
            let _ = pn::best_encoding(Some(input), &["gzip", "identity"]);
            let _ = pn::best_charset(Some(input), &["utf-8"]);
            if let Ok(a) = negotiate::parse_accept(input, &l) {
                prop_assert_eq!(a.iter().count(), a.len());
            }
            if let Ok(w) = negotiate::parse_weighted(input, &l) {
                prop_assert_eq!(w.iter().count(), w.len());
            }
            let _ = EntityTag::parse(input);
            let _ = etag::parse_condition(input, &l);
            let _ = range::byte_ranges(input, 10_000, &mut ranges);
            let _ = range::parse_content_range(input);
            let _ = range::parse_if_range(input);
            if let Ok(e) = pn::ExtValue::parse(input) {
                let _ = e.decode_into(&mut out);
            }
            if let Ok(d) = pn::parse_content_disposition(input) {
                if let Some(f) = d.filename() {
                    let _ = f.decode_into(&mut out);
                    let _ = f.has_path_separator();
                }
            }
            let _ = pn::response_cache_control(input);
            let _ = pn::request_cache_control(input);
            let _ = pn::parse_origin(input);
            let lines = [input];
            let _ = forwarded::parse(&lines, &l);
            let _ = forwarded::parse_x_forwarded_for(&lines, &l);
            let _ = forwarded::parse_x_forwarded_host(input);
            let trust = |_: IpAddr| true;
            let peer = IpAddr::from([10, 0, 0, 1]);
            let _ = pn::client_address(peer, ForwardedSource::Forwarded(&lines), &trust, 8);
            let _ = pn::client_address(peer, ForwardedSource::XForwardedFor(&lines), &trust, 8);
            let _ = auth::parse_credentials(input, &l);
            let _ = pn::basic(input);
            let _ = pn::bearer(input);
            if let Ok(c) = auth::parse_challenges(input, &l) {
                prop_assert_eq!(c.iter().count(), c.len());
            }
            if let Ok(i) = sfv::parse_item(input) {
                prop_assert_eq!(i.params.iter().count(), i.params.len());
            }
            if let Ok(s) = sfv::parse_list(input) {
                prop_assert_eq!(s.iter().count(), s.len());
            }
            if let Ok(d) = sfv::parse_dictionary(input) {
                prop_assert_eq!(d.iter().count(), d.len());
            }
        }
    }

    #[test]
    fn test_xff_ipv4_agrees_with_core(
        text in prop_oneof![
            "[0-9.]{0,20}",
            (0u16..1000, 0u16..1000, 0u16..300, 0u16..300, any::<bool>())
                .prop_map(|(a, b, c, d, zero)| if zero { format!("{a}.0{b}.{c}.{d}") } else { format!("{a}.{b}.{c}.{d}") }),
        ],
        port in prop::option::of(any::<u16>()),
    ) {
        // The chain parser's own IPv4 reader must accept exactly what
        // `core::net::Ipv4Addr` accepts.
        let line = match port {
            Some(p) => format!("{text}:{p}"),
            None => text.clone(),
        };
        let lines = [line.as_bytes()];
        let ours = forwarded::parse_x_forwarded_for(&lines, &Limits::DEFAULT)
            .ok()
            .and_then(|c| c.iter().next())
            .map(|(a, _)| a);
        let core = text.parse::<core::net::Ipv4Addr>().ok().map(IpAddr::V4);
        prop_assert_eq!(ours, core, "{}", line);
    }

    #[test]
    fn test_entity_tag_write_round_trip(opaque in "[!#-~]{0,24}", weak in any::<bool>()) {
        let t = if weak { EntityTag::weak(opaque.as_bytes()) } else { EntityTag::strong(opaque.as_bytes()) };
        let t = t.expect("etagc only");
        let mut buf = [0u8; 64];
        let mut out = SliceSink::new(&mut buf);
        t.write_to(&mut out).expect("room");
        prop_assert_eq!(EntityTag::parse(out.written()), Ok(t));
    }

    #[test]
    fn test_content_range_write_round_trip(start in 0u64..u64::MAX / 2, len in 1u64..1 << 40, known in any::<bool>()) {
        let r = ByteRange { start, end: start + len - 1 };
        let complete = known.then_some(r.end + 1 + len);
        let mut buf = [0u8; 96];
        let mut out = SliceSink::new(&mut buf);
        range::write_content_range(r, complete, &mut out).expect("valid");
        prop_assert_eq!(range::parse_content_range(out.written()), Ok(ContentRange::Satisfied { range: r, complete }));
        let mut out = SliceSink::new(&mut buf);
        range::write_unsatisfied(len, &mut out).expect("room");
        prop_assert_eq!(range::parse_content_range(out.written()), Ok(ContentRange::Unsatisfied { complete: len }));
    }

    #[test]
    fn test_ext_value_write_round_trip(text in "\\PC{0,24}") {
        let mut buf = [0u8; 512];
        let mut out = SliceSink::new(&mut buf);
        pn::write_ext_value(&text, &mut out).expect("room");
        let v = pn::ExtValue::parse(out.written()).expect("writer output parses");
        let mut back = [0u8; 128];
        prop_assert_eq!(v.decode_into(&mut back).expect("decodes"), text.as_str());
    }

    #[test]
    fn test_attachment_write_round_trip(name in "\\PC{0,24}") {
        let mut buf = [0u8; 1024];
        let mut out = SliceSink::new(&mut buf);
        pn::write_attachment(&name, &mut out).expect("no control characters");
        let d = pn::parse_content_disposition(out.written()).expect("writer output parses");
        let mut back = [0u8; 128];
        let f = d.filename().expect("a file name");
        prop_assert_eq!(f.decode_into(&mut back).expect("decodes"), name.as_str());
    }

    #[test]
    fn test_cache_writer_round_trip(
        flags in prop::collection::vec("[a-z][a-z-]{0,10}", 0..4),
        ages in prop::collection::vec(("[a-z][a-z-]{0,10}", any::<u32>()), 0..4),
    ) {
        let mut buf = [0u8; 512];
        let mut out = SliceSink::new(&mut buf);
        let mut w = cache::Writer::new(&mut out);
        for f in &flags {
            w.flag(f).expect("token");
        }
        for (n, s) in &ages {
            w.seconds(n, *s).expect("token");
        }
        let d = cache::parse(out.written(), &Limits::DEFAULT).expect("writer output parses");
        let got: Vec<_> = d.iter().collect();
        prop_assert_eq!(got.len(), flags.len() + ages.len());
        for (g, f) in got.iter().zip(&flags) {
            prop_assert_eq!(g.name, f.as_bytes());
            prop_assert!(g.value.is_none());
        }
        for (g, (n, s)) in got[flags.len()..].iter().zip(&ages) {
            prop_assert_eq!(g.name, n.as_bytes());
            prop_assert!(g.value.expect("argument").eq_bytes(s.to_string().as_bytes()));
        }
    }

    #[test]
    fn test_origin_write_round_trip(scheme in "[a-zA-Z][a-zA-Z0-9+.-]{0,6}", host in "[a-zA-Z0-9-]{1,10}(\\.[a-z0-9-]{1,10}){0,2}", port in prop::option::of(any::<u16>())) {
        let text = match port {
            Some(p) => format!("{scheme}://{host}:{p}"),
            None => format!("{scheme}://{host}"),
        };
        let Ok(OriginValue::Origin(o)) = pn::parse_origin(text.as_bytes()) else {
            // A numeric-looking last label is an IPv4 attempt (D-040).
            return Ok(());
        };
        let mut buf = [0u8; 96];
        let mut out = SliceSink::new(&mut buf);
        o.write_to(&mut out).expect("room");
        let Ok(OriginValue::Origin(back)) = pn::parse_origin(out.written()) else {
            return Err(TestCaseError::fail("written origin refused"));
        };
        prop_assert!(o.same_origin(&back));
    }

    #[test]
    fn test_challenge_write_round_trip(
        scheme in "[A-Za-z][A-Za-z0-9-]{0,8}",
        params in prop::collection::vec(("[a-z][a-z0-9_-]{0,6}", "[ -~]{0,12}"), 0..4),
    ) {
        let mut seen = std::collections::HashSet::new();
        let params: Vec<(&str, &str)> = params
            .iter()
            .filter(|(n, _)| seen.insert(n.clone()))
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let mut buf = [0u8; 512];
        let mut out = SliceSink::new(&mut buf);
        auth::write_challenge(&scheme, &params, &mut out).expect("valid");
        let cs = auth::parse_challenges(out.written(), &Limits::DEFAULT).expect("writer output parses");
        prop_assert_eq!(cs.len(), 1);
        let c = cs.iter().next().expect("one");
        prop_assert!(c.scheme_is(&scheme));
        for (n, v) in &params {
            prop_assert!(c.param(n).expect("present").eq_bytes(v.as_bytes()));
        }
    }

    #[test]
    fn test_media_range_matches_written_offer(t in "[a-z]{1,8}", s in "[a-z0-9.+-]{1,12}") {
        let mut buf = [0u8; 64];
        let mut out = SliceSink::new(&mut buf);
        media::write(&t, &s, &[], &mut out).expect("valid");
        let offer = pn::parse_media_type(out.written()).expect("parses");
        for range in [format!("{t}/{s}"), format!("{t}/*"), "*/*".to_string()] {
            let r = media::parse_range(range.as_bytes(), &Limits::DEFAULT).expect("parses");
            prop_assert!(r.matches(&offer));
        }
        let offers = [std::str::from_utf8(out.written()).expect("ASCII")];
        prop_assert_eq!(pn::best_media(Some(format!("{t}/*").as_bytes()), &offers), Some(0));
    }

    #[test]
    fn test_sfv_lines_equal_joined(members in prop::collection::vec(sf_member(), 1..10), cuts in prop::collection::vec(any::<bool>(), 10)) {
        let joined = members.join(", ");
        let whole = sfv::parse_list(joined.as_bytes()).expect("generated list parses");
        prop_assert_eq!(whole.len(), members.len());
        let lines = split_lines(&members, &cuts);
        let refs: Vec<&[u8]> = lines.iter().map(String::as_bytes).collect();
        let ll = sfv::parse_list_lines(&refs).expect("lines parse");
        let a: Vec<Member<'_>> = whole.iter().collect();
        let b: Vec<Member<'_>> = ll.iter().collect();
        prop_assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(&b) {
            prop_assert_eq!(member_items(x), member_items(y));
        }
    }

    #[test]
    fn test_sfv_dictionary_lines_equal_joined(
        members in prop::collection::vec(("[a-z*][a-z0-9_.*-]{0,4}", sf_member()), 1..10),
        cuts in prop::collection::vec(any::<bool>(), 10),
    ) {
        let parts: Vec<String> = members.iter().map(|(k, m)| format!("{k}={m}")).collect();
        let joined = parts.join(", ");
        let whole = sfv::parse_dictionary(joined.as_bytes()).expect("generated dictionary parses");
        let lines = split_lines(&parts, &cuts);
        let refs: Vec<&[u8]> = lines.iter().map(String::as_bytes).collect();
        let dl = sfv::parse_dictionary_lines(&refs).expect("lines parse");
        prop_assert_eq!(whole.len(), dl.len());
        for (k, _) in &members {
            let a = whole.get(k).map(|m| member_items(&m));
            let b = dl.get(k).map(|m| member_items(&m));
            prop_assert_eq!(a, b);
        }
    }
}

/// A member's bare items, for comparing members from different texts.
fn member_items(m: &Member<'_>) -> Vec<String> {
    match m {
        Member::Item(i) => vec![format!("{:?}", i.bare)],
        Member::InnerList(l) => l.iter().map(|i| format!("{:?}", i.bare)).collect(),
    }
}
