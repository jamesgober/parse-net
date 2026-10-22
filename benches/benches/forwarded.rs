//! Client-address resolution over a three-hop `X-Forwarded-For` (no Rust
//! crate resolves through trusted proxies to compare with).

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::net::IpAddr;

const XFF: &[u8] = include_bytes!("../data/xff.txt");

fn bench(c: &mut Criterion) {
    let peer: IpAddr = "10.0.0.2".parse().expect("ip");
    let trusted = |a: IpAddr| a == peer || a == IpAddr::from([150, 172, 238, 178]);
    let lines: [&[u8]; 1] = [XFF];
    let mut g = c.benchmark_group("client_address/3-hop xff");
    g.bench_function("parse-net", |b| {
        b.iter(|| {
            parse_net::client_address(
                black_box(peer),
                parse_net::ForwardedSource::XForwardedFor(black_box(&lines)),
                &trusted,
                16,
            )
            .expect("valid")
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
