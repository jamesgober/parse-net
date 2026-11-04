//! Parameter lists: `param::parse_optional` on a permessage-deflate offer,
//! and `param::parse` on the same names with values, for its cost against
//! the required-value walker. No competitor reads RFC 6455 extension
//! parameters as a library call.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use parse_net::{Limits, param};

const OFFER: &[u8] = include_bytes!("../data/deflate_offer.txt");
const VALUED: &[u8] = include_bytes!("../data/deflate_valued.txt");

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("param/permessage-deflate offer");
    g.bench_function("parse_optional", |b| {
        b.iter(|| {
            let (p, _) = param::parse_optional(black_box(OFFER), &Limits::DEFAULT).expect("valid");
            p.find("client_max_window_bits").is_some()
        })
    });
    g.bench_function("parse, values on every name", |b| {
        b.iter(|| {
            let (p, _) = param::parse(black_box(VALUED), &Limits::DEFAULT).expect("valid");
            p.get("client_max_window_bits").is_some()
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
