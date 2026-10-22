//! HTTP-date: parse-net against `httpdate`, parsing and formatting.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

const DATE: &[u8] = include_bytes!("../data/imf_fixdate.txt");

fn bench(c: &mut Criterion) {
    let text = std::str::from_utf8(DATE).expect("ASCII");
    let mut g = c.benchmark_group("http_date/parse imf-fixdate");
    g.bench_function("parse-net", |b| {
        b.iter(|| parse_net::HttpDate::parse_imf_fixdate(black_box(DATE)).expect("valid"))
    });
    g.bench_function("httpdate", |b| {
        b.iter(|| httpdate::parse_http_date(black_box(text)).expect("valid"))
    });
    g.finish();

    let d = parse_net::HttpDate::parse_imf_fixdate(DATE).expect("valid");
    let t = httpdate::parse_http_date(text).expect("valid");
    let mut g = c.benchmark_group("http_date/format");
    g.bench_function("parse-net", |b| b.iter(|| black_box(d).format()));
    g.bench_function("httpdate", |b| {
        b.iter(|| httpdate::fmt_http_date(black_box(t)))
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
