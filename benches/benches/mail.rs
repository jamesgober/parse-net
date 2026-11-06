//! Email: RFC 5322 dates, B-word decoding, and display names against
//! `mailparse`; encoded-word and MIME parameter writing.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

const DATE: &[u8] = include_bytes!("../data/mail_date.txt");
const SUBJECT: &[u8] = include_bytes!("../data/subject.txt");
const SUBJECT_CJK: &[u8] = include_bytes!("../data/subject_cjk.txt");
const SUBJECT_B: &[u8] = include_bytes!("../data/subject_b.txt");
const MAILBOX_QUOTED: &[u8] = include_bytes!("../data/mailbox_quoted.txt");
const MAILBOX_ENCODED: &[u8] = include_bytes!("../data/mailbox_encoded.txt");

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
            parse_net::mail::decode_words(
                black_box(SUBJECT_B),
                &parse_net::Limits::DEFAULT,
                &mut text,
            )
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

    // A mailbox and its display name as text: mailparse reads both into
    // `String`s, so its time includes the allocations, as a caller's would.
    let mut name = [0u8; 128];
    for (label, mailbox) in [
        ("quoted, with a comment", MAILBOX_QUOTED),
        ("two Q words", MAILBOX_ENCODED),
    ] {
        let text = std::str::from_utf8(mailbox).expect("ASCII");
        let mut g = c.benchmark_group(format!("mailbox display name/{label}"));
        g.bench_function("parse-net", |b| {
            b.iter(|| {
                let m =
                    parse_net::mail::parse_mailbox(black_box(mailbox), &parse_net::Limits::DEFAULT)
                        .expect("valid");
                let raw = m.display_name.expect("named");
                parse_net::mail::decode_phrase(raw, &parse_net::Limits::DEFAULT, &mut name)
                    .expect("valid")
                    .len()
            })
        });
        g.bench_function("mailparse", |b| {
            b.iter(
                || match &mailparse::addrparse(black_box(text)).expect("valid")[0] {
                    mailparse::MailAddr::Single(s) => {
                        s.display_name.as_ref().map_or(0, String::len)
                    }
                    mailparse::MailAddr::Group(_) => 0,
                },
            )
        });
        g.finish();
    }

    let mut g = c.benchmark_group("write_mime_param_at/filename after Content-Disposition");
    g.bench_function("parse-net", |b| {
        b.iter(|| {
            let mut out = parse_net::SliceSink::new(&mut buf);
            parse_net::mail::write_mime_param_at(
                "filename",
                black_box("quarterly report for the northern region.pdf"),
                47,
                &mut out,
            )
            .expect("room")
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
