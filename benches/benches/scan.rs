//! Field-value validation: parse-net's SWAR scan against the bytewise
//! definition (http-net's former loop; httparse validates the same class).

use criterion::{Criterion, black_box, criterion_group, criterion_main};

const VALUE: &[u8] = include_bytes!("../data/field_value_64.txt");

fn bytewise(v: &[u8]) -> bool {
    v.iter().all(|&b| b == b'\t' || (b >= 0x20 && b != 0x7f))
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("check_field_value/64 bytes");
    g.bench_function("parse-net", |b| b.iter(|| parse_net::scan::check_field_value(black_box(VALUE)).is_ok()));
    g.bench_function("bytewise", |b| b.iter(|| bytewise(black_box(VALUE))));
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
