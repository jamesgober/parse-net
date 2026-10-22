//! `Accept` negotiation: parse-net's `best_media` against a hand-written
//! selection over `mime` (no Rust crate negotiates).

use criterion::{Criterion, black_box, criterion_group, criterion_main};

const ACCEPT: &[u8] = include_bytes!("../data/accept_chrome.txt");
const OFFERS: [&str; 3] = ["application/json", "text/html", "image/webp"];

/// The RFC 9110 section 12.5.1 rule over `mime`: the weight of an offer is
/// the q of the most specific range that matches it.
fn with_mime(accept: &str, offers: &[&str]) -> Option<usize> {
    let ranges: Vec<(mime::Mime, u16)> = accept
        .split(',')
        .filter_map(|r| r.trim().parse::<mime::Mime>().ok())
        .map(|m| {
            let q = m
                .get_param("q")
                .and_then(|q| q.as_str().parse::<f32>().ok())
                .map_or(1000, |q| (q * 1000.0) as u16);
            (m, q)
        })
        .collect();
    let mut best: Option<(usize, u16)> = None;
    for (i, offer) in offers.iter().enumerate() {
        let o: mime::Mime = offer.parse().ok()?;
        let mut weight = None;
        let mut spec = 0;
        for (r, q) in &ranges {
            let s = if r.type_() == mime::STAR {
                1
            } else if r.subtype() == mime::STAR && r.type_() == o.type_() {
                2
            } else if r.type_() == o.type_() && r.subtype() == o.subtype() {
                3
            } else {
                0
            };
            if s > spec {
                spec = s;
                weight = Some(*q);
            }
        }
        if let Some(w) = weight.filter(|&w| w > 0) {
            if best.is_none_or(|(_, bw)| w > bw) {
                best = Some((i, w));
            }
        }
    }
    best.map(|(i, _)| i)
}

fn bench(c: &mut Criterion) {
    let text = std::str::from_utf8(ACCEPT).expect("ASCII");
    assert_eq!(parse_net::best_media(Some(ACCEPT), &OFFERS), with_mime(text, &OFFERS));
    let mut g = c.benchmark_group("best_media/chrome-accept, 3 offers");
    g.bench_function("parse-net", |b| b.iter(|| parse_net::best_media(Some(black_box(ACCEPT)), black_box(&OFFERS))));
    g.bench_function("mime + loop", |b| b.iter(|| with_mime(black_box(text), black_box(&OFFERS))));
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
