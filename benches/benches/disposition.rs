//! `Content-Disposition` with `filename*`: parse-net against
//! `content_disposition` and `mailparse`, each reading the file name.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

const VALUE: &[u8] = include_bytes!("../data/content_disposition.txt");

fn bench(c: &mut Criterion) {
    let text = std::str::from_utf8(VALUE).expect("ASCII");
    let mut buf = [0u8; 64];
    let mut g = c.benchmark_group("content_disposition/attachment with filename*");
    g.bench_function("parse-net", |b| {
        b.iter(|| {
            let d = parse_net::parse_content_disposition(black_box(VALUE)).expect("valid");
            d.filename().expect("a name").decode_into(&mut buf).expect("decodes").len()
        })
    });
    g.bench_function("content_disposition", |b| {
        b.iter(|| {
            let d = content_disposition::parse_content_disposition(black_box(text));
            d.filename_full().map(|f| f.len())
        })
    });
    g.bench_function("mailparse", |b| {
        b.iter(|| {
            let d = mailparse::parse_content_disposition(black_box(text));
            d.params.get("filename").map(String::len)
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
