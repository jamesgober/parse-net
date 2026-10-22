//! Property tests: no parser panics on any input, every writer's output
//! parses back to its input, the SWAR fast paths agree with the bytewise
//! definitions, and several field lines read as one list equal the joined
//! value.

use parse_net::{
    self as pn, HttpDate, Limits, SliceSink,
    class::{self, Class},
    list, media, param, pct, scan, text, write,
};
use proptest::prelude::*;

fn bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..96)
}

/// Bytes weighted toward the delimiters the grammars care about.
fn grammar_bytes() -> impl Strategy<Value = Vec<u8>> {
    let interesting = prop::sample::select(
        b"abcAZ09-._~!#$%&'*+^`|\"\\(),;=/:?@[] \t\r\n\x00\x7f\x80\xffvVxX".to_vec(),
    );
    prop::collection::vec(interesting, 0..64)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn test_parsers_never_panic(v in bytes(), g in grammar_bytes()) {
        for input in [&v[..], &g[..]] {
            let _ = scan::check_field_value(input);
            let _ = text::parse_token(input);
            let _ = text::parse_quoted(input);
            let _ = text::parse_word(input);
            let _ = text::parse_comment(input, &Limits::DEFAULT);
            if let Ok(l) = pn::list(input) {
                prop_assert_eq!(l.iter().count(), l.len());
            }
            if let Ok((p, used)) = param::parse(input, &Limits::DEFAULT) {
                prop_assert!(used <= input.len());
                prop_assert_eq!(p.iter().count(), p.len());
            }
            if let Ok(m) = pn::parse_media_type(input) {
                let _ = m.boundary();
                let mut buf = [0u8; 256];
                let mut out = SliceSink::new(&mut buf);
                if m.write_canonical(&mut out).is_ok() {
                    prop_assert!(pn::parse_media_type(out.written()).is_ok());
                }
            }
            let _ = HttpDate::parse_at(input, 1_792_540_800);
            let _ = HttpDate::parse_imf_fixdate(input);
            let _ = pn::parse_host_port(input);
            let _ = pct::validate(input);
            let _ = pct::validate_with(input, Class::URI_TARGET);
            let mut out = [0u8; 128];
            let _ = pct::decode_utf8_into(input, &mut out);
            let _ = pct::decode_lower_only_into(input, &mut out);
            let _ = pn::num::parse_u64(input);
            let _ = pn::num::parse_u32_saturating(input);
        }
    }

    #[test]
    fn test_errors_never_contain_input(v in grammar_bytes()) {
        let errors = [
            pn::list(&v).err(),
            pn::parse_media_type(&v).err(),
            pn::parse_host_port(&v).err(),
            HttpDate::parse_at(&v, 0).err(),
        ];
        for e in errors.into_iter().flatten() {
            let text = e.to_string();
            prop_assert!(text.bytes().all(|b| b.is_ascii_graphic() || b == b' '));
            prop_assert!(text.starts_with(e.kind().message()));
        }
    }

    #[test]
    fn test_swar_equals_bytewise(v in bytes(), needle in any::<u8>(), other in any::<u8>()) {
        prop_assert_eq!(scan::find_byte(needle, &v), v.iter().position(|&b| b == needle));
        prop_assert_eq!(
            scan::find_either(needle, other, &v),
            v.iter().position(|&b| b == needle || b == other)
        );
        let bad = v.iter().position(|&b| !class::is_field_text(b));
        prop_assert_eq!(scan::check_field_value(&v).err().map(|e| e.offset()), bad);
        prop_assert_eq!(scan::first_not_in(&v, Class::TCHAR), v.iter().position(|&b| !class::is_tchar(b)));
    }

    #[test]
    fn test_quoted_round_trip(v in bytes()) {
        let mut buf = [0u8; 256];
        let mut out = SliceSink::new(&mut buf);
        match write::write_quoted(&v, &mut out) {
            Ok(()) => {
                let (q, used) = text::parse_quoted(out.written()).expect("writer output parses");
                prop_assert_eq!(used, out.len());
                prop_assert!(q.eq_bytes(&v));
                let mut back = [0u8; 128];
                prop_assert_eq!(q.unescape_into(&mut back).expect("fits"), &v[..]);
            }
            Err(pn::WriteError::Forbidden { at }) => {
                let b = v[at as usize];
                prop_assert!(b != b'\t' && (b < 0x20 || b == 0x7f));
            }
            Err(e) => prop_assert!(false, "unexpected {e:?}"),
        }
    }

    #[test]
    fn test_word_and_param_round_trip(name in "[a-zA-Z0-9!#$%&'*+.^_`|~-]{1,12}", value in bytes()) {
        let mut buf = [0u8; 512];
        let mut out = SliceSink::new(&mut buf);
        if write::write_param(name.as_bytes(), &value, &mut out).is_ok() {
            let (p, used) = param::parse(out.written(), &Limits::DEFAULT).expect("parses");
            prop_assert_eq!(used, out.len());
            prop_assert!(p.get(&name).expect("present").eq_bytes(&value));
        }
    }

    #[test]
    fn test_media_write_round_trip(
        t in "[a-z]{1,8}", s in "[a-z0-9.+-]{1,12}",
        params in prop::collection::vec(("[a-z]{1,6}", "[ -~]{0,10}"), 0..4),
    ) {
        let pairs: Vec<(&str, &str)> = params.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
        let mut buf = [0u8; 512];
        let mut out = SliceSink::new(&mut buf);
        media::write(&t, &s, &pairs, &mut out).expect("valid input");
        // Duplicate names are refused on parse, as they must be.
        let mut seen = std::collections::HashSet::new();
        let unique = params.iter().all(|(n, _)| seen.insert(n.to_ascii_lowercase()));
        match pn::parse_media_type(out.written()) {
            Ok(m) => {
                prop_assert!(unique);
                prop_assert!(m.is(&t, &s));
                for (n, v) in &params {
                    prop_assert!(m.param(n).expect("present").eq_bytes(v.as_bytes()));
                }
            }
            Err(e) => prop_assert!(!unique && e.kind() == pn::ErrorKind::DuplicateParameter),
        }
    }

    #[test]
    fn test_http_date_round_trip(secs in HttpDate::MIN.unix()..=HttpDate::MAX.unix()) {
        let d = HttpDate::from_unix(secs).expect("in range");
        let text = d.format();
        prop_assert_eq!(HttpDate::parse_imf_fixdate(&text), Ok(d));
        prop_assert_eq!(HttpDate::parse_at(&text, 0), Ok(d));
        let c = d.civil();
        prop_assert_eq!(pn::date::days_from_civil(i32::from(c.year), c.month, c.day), secs.div_euclid(86_400));
    }

    #[test]
    fn test_pct_round_trip(v in bytes()) {
        let mut buf = [0u8; 512];
        let mut out = SliceSink::new(&mut buf);
        pct::encode(&v, &pct::EncodeSet::ATTR_CHAR_COMPLEMENT, pct::HexCase::Upper, &mut out).expect("room");
        let mut back = [0u8; 128];
        prop_assert_eq!(pct::decode_into(out.written(), &mut back).expect("valid"), &v[..]);
        prop_assert_eq!(pct::decoded_len(out.written()), Ok(v.len()));
    }

    #[test]
    fn test_host_write_round_trip(v in grammar_bytes()) {
        if let Ok(hp) = pn::parse_host_port(&v) {
            let mut buf = [0u8; 256];
            let mut out = SliceSink::new(&mut buf);
            hp.write_to(&mut out).expect("room");
            let back = pn::parse_host_port(out.written()).expect("writer output parses");
            prop_assert!(back.host.eq_ignore_ascii_case(&hp.host));
            prop_assert_eq!(back.port, hp.port);
        }
    }

    #[test]
    fn test_combined_equals_joined(elements in prop::collection::vec("[a-z]{0,4}(;[a-z]=\"[a-z ,]{0,4}\")?", 0..12), cuts in prop::collection::vec(any::<bool>(), 12)) {
        let joined = elements.join(", ");
        let whole: Vec<Vec<u8>> = pn::list(joined.as_bytes()).expect("valid").iter().map(<[u8]>::to_vec).collect();
        // Split the same elements into lines at element boundaries.
        let mut lines: Vec<String> = vec![String::new()];
        for (i, e) in elements.iter().enumerate() {
            if i > 0 {
                if cuts[i] {
                    lines.push(String::new());
                } else {
                    lines.last_mut().expect("one line").push_str(", ");
                }
            }
            lines.last_mut().expect("one line").push_str(e);
        }
        let refs: Vec<&[u8]> = lines.iter().map(|l| l.as_bytes()).collect();
        let c = list::combined(refs.iter().copied(), &Limits::DEFAULT).expect("valid");
        let got: Vec<Vec<u8>> = c.iter().map(<[u8]>::to_vec).collect();
        prop_assert_eq!(got, whole);
    }
}
