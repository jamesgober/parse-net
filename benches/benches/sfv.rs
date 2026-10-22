//! Structured Fields: parse-net against the `sfv` crate.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

const LIST: &[u8] = include_bytes!("../data/sfv_list.txt");
const DICT: &[u8] = include_bytes!("../data/sfv_dictionary.txt");

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("sfv/list of 10 tokens with a parameter");
    g.bench_function("parse-net", |b| {
        b.iter(|| {
            let l = parse_net::sfv::parse_list(black_box(LIST)).expect("valid");
            l.iter().count()
        })
    });
    g.bench_function("sfv", |b| {
        b.iter(|| {
            let l = sfv::Parser::new(black_box(LIST))
                .parse::<sfv::List>()
                .expect("valid");
            l.len()
        })
    });
    g.finish();

    let mut g = c.benchmark_group("sfv/dictionary of 5 members");
    g.bench_function("parse-net", |b| {
        b.iter(|| {
            let d = parse_net::sfv::parse_dictionary(black_box(DICT)).expect("valid");
            d.get("u").is_some()
        })
    });
    g.bench_function("sfv", |b| {
        b.iter(|| {
            let d = sfv::Parser::new(black_box(DICT))
                .parse::<sfv::Dictionary>()
                .expect("valid");
            d.get("u").is_some()
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
