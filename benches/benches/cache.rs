//! `Cache-Control`: parse-net against `headers`.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use headers::Header;

const VALUE: &[u8] = include_bytes!("../data/cache_control.txt");

fn bench(c: &mut Criterion) {
    let value = http::HeaderValue::from_bytes(VALUE).expect("value");
    let mut g = c.benchmark_group("cache_control/public, max-age, immutable");
    g.bench_function("parse-net", |b| {
        b.iter(|| {
            parse_net::response_cache_control(black_box(VALUE))
                .expect("valid")
                .max_age
        })
    });
    g.bench_function("headers", |b| {
        b.iter(|| {
            let cc = headers::CacheControl::decode(&mut std::iter::once(black_box(&value)))
                .expect("valid");
            cc.max_age()
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
