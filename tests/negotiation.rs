//! Content negotiation against the RFC rules: regressions for the
//! counterexamples of issue 14, and property tests that compare
//! `Negotiator` with plain reference readers of RFC 9110 section 12.5.1
//! (media precedence) and RFC 4647 section 3.4 (lookup).

#![cfg(feature = "alloc")]

use parse_net::{
    QValue,
    negotiate::{MalformedPolicy, Negotiator, Outcome},
};
use proptest::prelude::*;

fn strict() -> Negotiator {
    Negotiator::new().on_malformed(MalformedPolicy::Refuse)
}

fn chosen(index: usize, thousandths: u16) -> Outcome {
    Outcome::Chosen {
        index,
        weight: QValue::from_thousandths(thousandths).expect("0 to 1000"),
    }
}

// Issue 14, case 1. RFC 9110 section 12.5.1: "If more than one media range
// applies to a given type, the most specific reference has precedence." A
// range with two parameters is more specific than one with one of them.
#[test]
fn test_media_more_parameters_take_precedence() {
    let n = strict();
    let offers = ["text/html;a=1;b=2"];
    assert_eq!(
        n.media(Some(b"text/html;a=1;q=1,text/html;a=1;b=2;q=0"), &offers),
        Outcome::NoneAcceptable
    );
    // The same two ranges in the other order: the same answer.
    assert_eq!(
        n.media(Some(b"text/html;a=1;b=2;q=0,text/html;a=1;q=1"), &offers),
        Outcome::NoneAcceptable
    );
    // The more specific range does not apply to an offer without `b`.
    assert_eq!(
        n.media(
            Some(b"text/html;a=1;q=1,text/html;a=1;b=2;q=0"),
            &["text/html;a=1"]
        ),
        chosen(0, 1000)
    );
    // The RFC's own example.
    let accept = b"text/*;q=0.3, text/plain;q=0.7, text/plain;format=flowed, text/plain;format=fixed;q=0.4, */*;q=0.5";
    for (offer, q) in [
        ("text/plain;format=flowed", 1000),
        ("text/plain", 700),
        ("text/html", 300),
        ("image/jpeg", 500),
        ("text/plain;format=fixed", 400),
        ("text/html;level=3", 300),
    ] {
        assert_eq!(n.media(Some(accept), &[offer]), chosen(0, q), "{offer}");
    }
}

// Issue 14, case 2. RFC 9110 section 12.5.1: "Recipients SHOULD process any
// parameter named "q" as weight, regardless of parameter ordering."
#[test]
fn test_media_parameter_after_q_is_a_media_parameter() {
    let n = strict();
    let offers = ["text/html;level=1", "text/html;level=2"];
    assert_eq!(
        n.media(Some(b"text/html;q=1;level=2"), &offers),
        chosen(1, 1000)
    );
    assert_eq!(
        n.media(Some(b"text/html;level=2;q=1"), &offers),
        chosen(1, 1000)
    );
    assert_eq!(
        n.media(Some(b"text/html;q=0.5;level=1, text/html;q=0"), &offers),
        chosen(0, 500)
    );
    // "Anything but level 2": the q=0 range keeps its parameter.
    assert_eq!(
        n.media(Some(b"text/html;q=0;level=2, text/html;q=0.5"), &offers),
        chosen(0, 500)
    );
    assert_eq!(
        n.media(
            Some(b"text/html;q=0;level=2, text/html;q=0.5"),
            &offers[1..]
        ),
        Outcome::NoneAcceptable
    );
}

// Issue 14, case 3. RFC 4647 section 3.4: each range is taken in priority
// order and shortened until it matches before the next range is tried.
#[test]
fn test_language_lookup_shortens_the_first_range_first() {
    let n = strict();
    assert_eq!(
        n.language(Some(b"en-US;q=1,en;q=0.1,fr;q=0.5"), &["en", "fr"]),
        chosen(0, 1000)
    );
    // Without the truncation reaching an offer, the next range is tried.
    assert_eq!(
        n.language(Some(b"de-CH;q=1,en;q=0.1,fr;q=0.5"), &["en", "fr"]),
        chosen(1, 500)
    );
    // An exact match at a higher weight still wins.
    assert_eq!(
        n.language(Some(b"fr, en-US;q=0.9"), &["en", "fr"]),
        chosen(1, 1000)
    );
    // A singleton goes with the subtag after it: `zh-x` is never reached.
    assert_eq!(
        n.language(Some(b"zh-x-private"), &["zh-x", "zh"]),
        chosen(1, 1000)
    );
    // `q=0` makes an offer unacceptable, however it would be reached.
    assert_eq!(
        n.language(Some(b"en-US, en;q=0"), &["en"]),
        Outcome::NoneAcceptable
    );
}

// Issue 14, case 4. RFC 4647 section 3.4: "If the language range "*" is
// followed by other language ranges, it is skipped."
#[test]
fn test_language_lookup_skips_a_wildcard_with_ranges_after_it() {
    let n = strict();
    assert_eq!(
        n.language(Some(b"*;q=1,fr;q=0.5"), &["en", "fr"]),
        chosen(1, 500)
    );
    // Last in priority, it gives the default: the first offer.
    assert_eq!(
        n.language(Some(b"fr, *;q=0.1"), &["en", "de"]),
        chosen(0, 100)
    );
    assert_eq!(n.language(Some(b"*"), &["en", "fr"]), chosen(0, 1000));
    // Priority is by weight, then order: here `*` comes last.
    assert_eq!(
        n.language(Some(b"*;q=0.2, de;q=0.5"), &["en", "fr"]),
        chosen(0, 200)
    );
}

/// RFC 4647 section 3.4 as written: sort the ranges by weight, then walk
/// each, shortening it until an offer matches.
fn reference_lookup(ranges: &[(String, u16)], offers: &[String]) -> Outcome {
    let refused: Vec<bool> = offers
        .iter()
        .map(|o| {
            ranges
                .iter()
                .any(|(r, w)| *w == 0 && r.eq_ignore_ascii_case(o))
        })
        .collect();
    let mut list: Vec<&(String, u16)> = ranges.iter().filter(|(_, w)| *w > 0).collect();
    list.sort_by_key(|r| core::cmp::Reverse(r.1)); // stable: header order between equals
    let find =
        |t: &str| (0..offers.len()).find(|&i| !refused[i] && offers[i].eq_ignore_ascii_case(t));
    for (k, (r, w)) in list.iter().enumerate() {
        if r == "*" {
            if k + 1 == list.len() {
                if let Some(i) = (0..offers.len()).find(|&i| !refused[i]) {
                    return chosen(i, *w);
                }
            }
            continue;
        }
        let mut t = r.clone();
        loop {
            if let Some(i) = find(&t) {
                return chosen(i, *w);
            }
            let Some(cut) = t.rfind('-') else { break };
            t.truncate(cut);
            // Trailing singletons go with the subtag after them.
            loop {
                match t.rfind('-') {
                    Some(d) if t.len() - d == 2 => t.truncate(d),
                    None if t.len() == 1 => t.clear(),
                    _ => break,
                }
            }
            if t.is_empty() {
                break;
            }
        }
    }
    Outcome::NoneAcceptable
}

fn subtag() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "en", "EN", "fr", "de", "ch", "us", "x", "a", "1", "latn",
    ])
    .prop_map(String::from)
}

fn tag() -> impl Strategy<Value = String> {
    (
        prop::sample::select(vec!["en", "fr", "De", "zh", "x"]),
        prop::collection::vec(subtag(), 0..4),
    )
        .prop_map(|(first, rest)| {
            core::iter::once(first.to_string())
                .chain(rest)
                .collect::<Vec<_>>()
                .join("-")
        })
}

fn weight() -> impl Strategy<Value = u16> {
    prop::sample::select(vec![0u16, 100, 500, 1000])
}

/// One media range over two parameters, `a=1` and `b=2`, either or both.
fn media_range() -> impl Strategy<Value = (u8, bool, bool, u16)> {
    (0u8..3, any::<bool>(), any::<bool>(), weight())
}

fn media_text(level: u8, a: bool, b: bool) -> String {
    let mut s = String::from(match level {
        0 => "*/*",
        1 => "text/*",
        _ => "text/html",
    });
    if a {
        s.push_str(";a=1");
    }
    if b {
        s.push_str(";b=2");
    }
    s
}

proptest! {
    #[test]
    fn language_lookup_matches_reference(
        ranges in prop::collection::vec((prop_oneof![9 => tag(), 1 => Just(String::from("*"))], weight()), 1..6),
        offers in prop::collection::vec(tag(), 1..5),
    ) {
        let header = ranges
            .iter()
            .map(|(r, w)| match w {
                1000 => r.clone(),
                w => format!("{r};q={}", f64::from(*w) / 1000.0),
            })
            .collect::<Vec<_>>()
            .join(", ");
        let offer_refs: Vec<&str> = offers.iter().map(String::as_str).collect();
        let ours = strict().language(Some(header.as_bytes()), &offer_refs);
        prop_assume!(!matches!(ours, Outcome::Refused(_))); // a generated range the grammar refuses
        prop_assert_eq!(ours, reference_lookup(&ranges, &offers), "{}", header);
    }

    #[test]
    fn media_most_specific_range_decides(
        ranges in prop::collection::vec(media_range(), 1..6),
        q_first in any::<bool>(),
        offer_a in any::<bool>(),
        offer_b in any::<bool>(),
    ) {
        let header = ranges
            .iter()
            .map(|&(level, a, b, w)| {
                let base = media_text(level, a, b);
                let q = format!("q={}", f64::from(w) / 1000.0);
                match (q_first, base.split_once(';')) {
                    // `q` moved before the parameters: the same range.
                    (true, Some((essence, params))) => format!("{essence};{q};{params}"),
                    _ => format!("{base};{q}"),
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        let offer = media_text(2, offer_a, offer_b);
        // RFC 9110 section 12.5.1: the matching range of highest precedence
        // (an exact type over `type/*` over `*/*`, then more parameters),
        // the earlier one between equals.
        let mut best: Option<((u8, u8), u16)> = None;
        for &(level, a, b, w) in &ranges {
            if (a && !offer_a) || (b && !offer_b) {
                continue;
            }
            let rank = (level, u8::from(a) + u8::from(b));
            if best.is_none_or(|(r, _)| rank > r) {
                best = Some((rank, w));
            }
        }
        let expect = match best {
            Some((_, w)) if w > 0 => chosen(0, w),
            _ => Outcome::NoneAcceptable,
        };
        prop_assert_eq!(strict().media(Some(header.as_bytes()), &[offer.as_str()]), expect, "{}", header);
    }
}
