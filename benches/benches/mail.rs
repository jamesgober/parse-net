//! Email: RFC 5322 dates against `mailparse`, and encoded-word writing.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

const DATE: &[u8] = include_bytes!("../data/mail_date.txt");
const SUBJECT: &[u8] = include_bytes!("../data/subject.txt");

fn bench(c: &mut Criterion) {
    let text = std::str::from_utf8(DATE).expect("ASCII");
    let mut g = c.benchmark_group("mail_date/parse");
    g.bench_function("parse-net", |b| {
        b.iter(|| {
            parse_net::MailDate::parse(black_box(DATE), false)
                .expect("valid")
                .utc()
        })
    });
    g.bench_function("mailparse", |b| {
        b.iter(|| mailparse::dateparse(black_box(text)).expect("valid"))
    });
    g.finish();

    let subject = std::str::from_utf8(SUBJECT).expect("UTF-8");
    let mut buf = [0u8; 512];
    let mut g = c.benchmark_group("encode_words/36-byte UTF-8 subject");
    g.bench_function("parse-net", |b| {
        b.iter(|| {
            let mut out = parse_net::SliceSink::new(&mut buf);
            parse_net::mail::encode_words(black_box(subject), 66, &mut out).expect("room");
            out.len()
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
