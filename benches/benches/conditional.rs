//! Conditional and range requests: parse-net against `headers`.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use headers::Header;

const INM: &[u8] = include_bytes!("../data/if_none_match.txt");
const RANGE: &[u8] = include_bytes!("../data/range.txt");

fn bench(c: &mut Criterion) {
    let current = parse_net::EntityTag::strong(b"v2-b").expect("tag");
    let h_current: headers::ETag = "\"v2-b\"".parse().expect("tag");
    let inm_value = http::HeaderValue::from_bytes(INM).expect("value");
    let mut g = c.benchmark_group("if_none_match/3 tags");
    g.bench_function("parse-net", |b| {
        b.iter(|| parse_net::if_none_match(black_box(INM), black_box(&current)).expect("valid"))
    });
    g.bench_function("headers", |b| {
        b.iter(|| {
            let h = headers::IfNoneMatch::decode(&mut std::iter::once(black_box(&inm_value)))
                .expect("valid");
            !h.precondition_passes(black_box(&h_current))
        })
    });
    g.finish();

    let range_value = http::HeaderValue::from_bytes(RANGE).expect("value");
    let mut out = [parse_net::ByteRange { start: 0, end: 0 }; 16];
    let mut g = c.benchmark_group("byte_ranges/bytes=0-499");
    g.bench_function("parse-net", |b| {
        b.iter(|| {
            parse_net::range::byte_ranges(black_box(RANGE), black_box(10_000), &mut out)
                .expect("valid")
        })
    });
    g.bench_function("headers", |b| {
        b.iter(|| {
            let r = headers::Range::decode(&mut std::iter::once(black_box(&range_value)))
                .expect("valid");
            r.satisfiable_ranges(black_box(10_000)).count()
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
