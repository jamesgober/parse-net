//! Email: RFC 5322 dates and B-word decoding against `mailparse`, and
//! encoded-word writing in Q and B.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

const DATE: &[u8] = include_bytes!("../data/mail_date.txt");
const SUBJECT: &[u8] = include_bytes!("../data/subject.txt");
const SUBJECT_CJK: &[u8] = include_bytes!("../data/subject_cjk.txt");
const SUBJECT_B: &[u8] = include_bytes!("../data/subject_b.txt");

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
    g.bench_function("parse-net, B", |b| {
        b.iter(|| {
            let mut out = parse_net::SliceSink::new(&mut buf);
            parse_net::mail::encode_words_b(black_box(subject), 66, &mut out).expect("room");
            out.len()
        })
    });
    g.finish();

    let cjk = std::str::from_utf8(SUBJECT_CJK).expect("UTF-8");
    let mut g = c.benchmark_group("encode_words/39-byte Japanese subject");
    g.bench_function("parse-net, B", |b| {
        b.iter(|| {
            let mut out = parse_net::SliceSink::new(&mut buf);
            parse_net::mail::encode_words_b(black_box(cjk), 66, &mut out).expect("room");
            out.len()
        })
    });
    g.bench_function("parse-net, Q", |b| {
        b.iter(|| {
            let mut out = parse_net::SliceSink::new(&mut buf);
            parse_net::mail::encode_words(black_box(cjk), 66, &mut out).expect("room");
            out.len()
        })
    });
    g.finish();

    // The same B word: mailparse decodes it into a `String` as it reads the
    // header, so its time includes the allocation, as a caller's would.
    let mut header = b"Subject: ".to_vec();
    header.extend_from_slice(SUBJECT_B);
    let mut text = [0u8; 256];
    let mut g = c.benchmark_group("decode_words/one B word, 39 bytes of Japanese");
    g.bench_function("parse-net", |b| {
        b.iter(|| {
            parse_net::mail::decode_words(black_box(SUBJECT_B), &parse_net::Limits::DEFAULT, &mut text)
                .expect("valid")
                .len()
        })
    });
    g.bench_function("mailparse", |b| {
        b.iter(|| {
            let (h, _) = mailparse::parse_header(black_box(&header)).expect("valid");
            h.get_value().len()
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
