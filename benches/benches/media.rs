//! `Content-Type` parsing: parse-net against `mime`.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

const VALUE: &[u8] = include_bytes!("../data/media_type.txt");

fn bench(c: &mut Criterion) {
    let text = std::str::from_utf8(VALUE).expect("ASCII");
    let mut g = c.benchmark_group("parse_media_type/text-html-charset");
    g.bench_function("parse-net", |b| {
        b.iter(|| {
            let m = parse_net::parse_media_type(black_box(VALUE)).expect("valid");
            m.charset().is_some()
        })
    });
    g.bench_function("mime", |b| {
        b.iter(|| {
            let m: mime::Mime = black_box(text).parse().expect("valid");
            m.get_param(mime::CHARSET).is_some()
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
