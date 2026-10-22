//! Complexity tests (dev/PLAN.md section 11.6, threat T9): every walker, fed
//! adversarial inputs of 1 KiB, 64 KiB, and 1 MiB, returns the expected
//! limit error under the default limits and, with every limit raised to its
//! maximum, takes time that grows no faster than the input (within 1.2 of
//! the size ratio).
//!
//! Timing is the best of several runs; a case that misses the bound is
//! measured again (up to three times) before it fails, so a busy machine
//! does not fail the test while a quadratic walker (16 times the ratio from
//! 64 KiB to 1 MiB) always does.

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use parse_net::{
    self as pn, ErrorKind, Limits, auth, cache, etag, forwarded, link, list, mail, media,
    negotiate, param, pct, range, sfv, text,
};

const SIZES: [usize; 3] = [1 << 10, 1 << 16, 1 << 20];

/// Every limit at its maximum, so a walker reads as far as the input goes.
const FULL: Limits = Limits::DEFAULT
    .max_list_members(u16::MAX)
    .max_inner_list_members(u16::MAX)
    .max_params(u16::MAX)
    .max_dictionary_members(u16::MAX)
    .max_key_len(u16::MAX)
    .max_string_len(u16::MAX)
    .max_token_len(u16::MAX)
    .max_byte_seq_len(u32::MAX)
    .max_empty_elements(u16::MAX)
    .max_comment_depth(u8::MAX)
    .max_ranges(u16::MAX)
    .max_encoded_words(u16::MAX)
    .max_hops(u8::MAX);

type Outcome = Result<(), ErrorKind>;

fn outcome<T>(r: Result<T, pn::ParseError>) -> Outcome {
    r.map(|_| ()).map_err(|e| e.kind())
}

/// A distinct token for every `i`: `x` and base-26 letters.
fn name(i: usize) -> String {
    let mut s = String::from("x");
    let mut n = i;
    loop {
        s.push(char::from(b'a' + (n % 26) as u8));
        n /= 26;
        if n == 0 {
            return s;
        }
    }
}

/// Names that all share their length, first byte, and last byte, so no
/// cheap filter tells them apart: `y` + four letters + `y`.
fn colliding_name(i: usize) -> String {
    let mut s = String::from("y");
    let mut n = i;
    for _ in 0..4 {
        s.push(char::from(b'a' + (n % 26) as u8));
        n /= 26;
    }
    s.push('y');
    s
}

/// `prefix`, then units while they fit in `size`, then `suffix`.
fn build(prefix: &str, unit: impl Fn(usize) -> String, suffix: &str, size: usize) -> Vec<u8> {
    let mut v = prefix.as_bytes().to_vec();
    for i in 0.. {
        let u = unit(i);
        if v.len() + u.len() + suffix.len() > size {
            break;
        }
        v.extend_from_slice(u.as_bytes());
    }
    v.extend_from_slice(suffix.as_bytes());
    v
}

struct Case {
    name: &'static str,
    input: fn(usize) -> Vec<u8>,
    /// The function under the default limits.
    default: fn(&[u8]) -> Outcome,
    /// The expected outcome of `default` at 1 MiB.
    expect: Outcome,
    /// The function with every limit at its maximum (timed).
    full: fn(&[u8]) -> Outcome,
}

/// The time of one call: the best, over several samples, of a batch of
/// calls long enough (about a millisecond) that the clock's resolution does
/// not matter, divided by its length.
fn best_time(f: fn(&[u8]) -> Outcome, v: &[u8]) -> Duration {
    let once = Instant::now();
    let _ = black_box(f(black_box(v)));
    let once = once.elapsed().as_nanos().max(1);
    let reps = u32::try_from((1_000_000 / once).clamp(1, 100_000)).unwrap_or(1);
    let mut best = Duration::MAX;
    let start = Instant::now();
    let mut samples = 0;
    while samples < 3 || (samples < 32 && start.elapsed() < Duration::from_millis(60)) {
        let t = Instant::now();
        for _ in 0..reps {
            let _ = black_box(f(black_box(v)));
        }
        best = best.min(t.elapsed() / reps);
        samples += 1;
    }
    best.max(Duration::from_nanos(1))
}

fn ratios(c: &Case, inputs: &[Vec<u8>; 3]) -> (f64, f64, [Duration; 3]) {
    let t = [0, 1, 2].map(|i| best_time(c.full, &inputs[i]));
    let r = |a: usize, b: usize| {
        let time = t[b].as_secs_f64() / t[a].as_secs_f64();
        let size = inputs[b].len() as f64 / inputs[a].len() as f64;
        time / size
    };
    (r(0, 1), r(1, 2), t)
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "field value, obs-text and spaces",
            input: |n| build("", |_| "a\u{80} b\t".into(), "", n),
            default: |v| outcome(pn::scan::check_field_value(v)),
            expect: Ok(()),
            full: |v| outcome(pn::scan::check_field_value(v)),
        },
        Case {
            name: "list, many members",
            input: |n| build("", |_| "a,".into(), "a", n),
            default: |v| outcome(list::parse(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(list::parse(v, &FULL)),
        },
        Case {
            name: "list, empty elements",
            input: |n| build("a", |_| ", ".into(), "a", n),
            default: |v| outcome(list::parse(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyEmptyElements),
            full: |v| outcome(list::parse(v, &FULL)),
        },
        Case {
            name: "list, quoted members with escapes and commas",
            input: |n| build("", |_| "\"a\\\"b,c\",".into(), "a", n),
            default: |v| outcome(list::parse(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(list::parse(v, &FULL)),
        },
        Case {
            name: "quoted string of escapes",
            input: |n| build("\"", |_| "\\a".into(), "\"", n),
            default: |v| outcome(text::parse_quoted(v)),
            expect: Ok(()),
            full: |v| outcome(text::parse_quoted(v)),
        },
        Case {
            name: "comment, deep nesting",
            input: |n| build("", |_| "(".into(), "", n),
            default: |v| outcome(text::parse_comment(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::CommentTooDeep),
            full: |v| outcome(text::parse_comment(v, &FULL)),
        },
        Case {
            name: "comment, long with escapes",
            input: |n| build("(", |_| "a\\)(b)".into(), ")", n),
            default: |v| outcome(text::parse_comment(v, &Limits::DEFAULT)),
            expect: Ok(()),
            full: |v| outcome(text::parse_comment(v, &FULL)),
        },
        Case {
            name: "parameters, distinct names",
            input: |n| build("", |i| format!(";{}=1", name(i)), "", n),
            default: |v| outcome(param::parse(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(param::parse(v, &FULL)),
        },
        Case {
            name: "parameters, names no filter separates",
            input: |n| build("", |i| format!(";{}=1", colliding_name(i)), "", n),
            default: |v| outcome(param::parse(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(param::parse(v, &FULL)),
        },
        Case {
            name: "media type, many parameters",
            input: |n| build("text/html", |i| format!("; {}=\"v\"", name(i)), "", n),
            default: |v| outcome(media::parse(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(media::parse(v, &FULL)),
        },
        Case {
            name: "Accept, many ranges",
            input: |n| build("", |i| format!("text/{};q=0.5,", name(i)), "*/*", n),
            default: |v| outcome(negotiate::parse_accept(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| {
                let _ = negotiate::best_media(
                    Some(v),
                    &["application/json", "text/html", "image/webp"],
                );
                outcome(negotiate::parse_accept(v, &FULL))
            },
        },
        Case {
            name: "Accept-Language, many tags",
            input: |n| build("", |i| format!("{};q=0.1,", name(i)), "en", n),
            default: |v| outcome(negotiate::parse_weighted(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(negotiate::parse_weighted(v, &FULL)),
        },
        Case {
            name: "If-None-Match, many tags",
            input: |n| build("", |i| format!("W/\"{}\",", name(i)), "\"z\"", n),
            default: |v| outcome(etag::parse_condition(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(etag::parse_condition(v, &FULL)),
        },
        Case {
            name: "Range, many ranges",
            input: |n| build("bytes=", |i| format!("{i}-{},", i + 1), "0-", n),
            default: |v| outcome(range::parse(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(range::parse(v, &FULL)),
        },
        Case {
            name: "ext-value, long percent-encoded",
            input: |n| build("UTF-8''", |_| "%E2%82%AC".into(), "", n),
            default: |v| outcome(pn::ExtValue::parse(v)),
            expect: Ok(()),
            full: |v| outcome(pn::ExtValue::parse(v)),
        },
        Case {
            name: "Content-Disposition, long filename*",
            input: |n| build("attachment; filename*=UTF-8''", |_| "%41b".into(), "", n),
            default: |v| outcome(pn::disposition::parse(v, &Limits::DEFAULT)),
            expect: Ok(()),
            full: |v| outcome(pn::disposition::parse(v, &FULL)),
        },
        Case {
            name: "Content-Disposition, many parameters",
            input: |n| build("attachment", |i| format!("; {}=a", name(i)), "", n),
            default: |v| outcome(pn::disposition::parse(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(pn::disposition::parse(v, &FULL)),
        },
        Case {
            name: "Cache-Control, many directives",
            input: |n| build("", |i| format!("{}=1,", name(i)), "max-age=1", n),
            default: |v| outcome(cache::parse(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(cache::parse(v, &FULL)),
        },
        Case {
            name: "Cache-Control, repeated known directives",
            input: |n| build("", |_| "max-age=1, no-cache=\"a,b\",".into(), "public", n),
            default: |v| outcome(pn::response_cache_control(v)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(cache::parse(v, &FULL)),
        },
        Case {
            name: "Link, many links",
            input: |n| build("", |i| format!("<https://a/{i}>; rel=next,"), "<b>", n),
            default: |v| outcome(link::parse_link(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(link::parse_link(v, &FULL)),
        },
        Case {
            name: "Link, many parameters",
            input: |n| build("<a>", |i| format!("; {}=x", name(i)), "", n),
            default: |v| outcome(link::parse_link(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(link::parse_link(v, &FULL)),
        },
        Case {
            name: "Forwarded, many hops",
            input: |n| {
                build(
                    "",
                    |i| format!("for=10.0.{}.{},", (i / 250) % 250, i % 250),
                    "for=1.2.3.4",
                    n,
                )
            },
            // The list is checked against `max_list_members` before hops are
            // counted.
            default: |v| outcome(forwarded::parse(&[v], &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(forwarded::parse(&[v], &FULL)),
        },
        Case {
            name: "X-Forwarded-For, many hops",
            input: |n| {
                build(
                    "",
                    |i| format!("10.0.{}.{}, ", (i / 250) % 250, i % 250),
                    "1.2.3.4",
                    n,
                )
            },
            default: |v| outcome(forwarded::parse_x_forwarded_for(&[v], &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyHops),
            full: |v| outcome(forwarded::parse_x_forwarded_for(&[v], &FULL)),
        },
        Case {
            name: "Authorization, many parameters",
            input: |n| build("Digest ", |i| format!("{}=\"v\", ", name(i)), "z=1", n),
            default: |v| outcome(auth::parse_credentials(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(auth::parse_credentials(v, &FULL)),
        },
        Case {
            name: "Authorization, names no filter separates, long values",
            input: |n| {
                build(
                    "Digest ",
                    |i| format!("{}=\"{}\", ", colliding_name(i), "v".repeat(64)),
                    "z=1",
                    n,
                )
            },
            default: |v| outcome(auth::parse_credentials(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(auth::parse_credentials(v, &FULL)),
        },
        Case {
            name: "parameters, one long value then names no filter separates",
            input: |n| {
                let mut v = format!(";a=\"{}\"", "x".repeat(n / 2)).into_bytes();
                v.extend(build(
                    "",
                    |i| format!(";{}=1", colliding_name(i)),
                    "",
                    n / 2,
                ));
                v
            },
            default: |v| outcome(param::parse(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(param::parse(v, &FULL)),
        },
        Case {
            name: "MIME parameters, names no filter separates, long comments",
            input: |n| {
                build(
                    "",
                    |i| format!("; {}=v ({})", colliding_name(i), "c".repeat(32)),
                    "",
                    n,
                )
            },
            default: |v| outcome(mail::parse_mime_params(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(mail::parse_mime_params(v, &FULL)),
        },
        Case {
            name: "WWW-Authenticate, many challenges",
            input: |n| build("", |i| format!("Basic realm=\"{i}\", "), "Bearer", n),
            default: |v| outcome(auth::parse_challenges(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(auth::parse_challenges(v, &FULL)),
        },
        Case {
            name: "Host, long name",
            input: |n| build("", |_| "a.".into(), "a", n),
            // RFC 3986 sets no length for a reg-name; the check is linear.
            default: |v| outcome(pn::host::parse_host(v)),
            expect: Ok(()),
            full: |v| outcome(pn::host::parse_host(v)),
        },
        Case {
            name: "percent-encoding, long",
            input: |n| build("", |_| "%41a".into(), "", n),
            default: |v| outcome(pct::validate(v)),
            expect: Ok(()),
            full: |v| outcome(pct::validate(v)),
        },
        Case {
            name: "Structured Field string, long with escapes",
            input: |n| build("\"", |_| "a\\\"".into(), "\"", n),
            default: |v| outcome(sfv::parse_item(v)),
            expect: Err(ErrorKind::TooLong),
            full: |v| outcome(sfv::Parser::new(FULL).item(v)),
        },
        Case {
            name: "Structured Field byte sequence, long",
            input: |n| build(":", |_| "YWJj".into(), ":", n),
            default: |v| outcome(sfv::parse_item(v)),
            expect: Err(ErrorKind::TooLong),
            full: |v| outcome(sfv::Parser::new(FULL).item(v)),
        },
        Case {
            name: "Structured Field list, many members with parameters",
            input: |n| build("", |i| format!("a;{}=1, ", name(i)), "a", n),
            default: |v| outcome(sfv::parse_list(v)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(sfv::Parser::new(FULL).list(v)),
        },
        Case {
            name: "Structured Field inner list, many items",
            input: |n| build("(", |_| "a ".into(), "a)", n),
            default: |v| outcome(sfv::parse_list(v)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(sfv::Parser::new(FULL).list(v)),
        },
        Case {
            name: "Structured Field item, many parameters no filter separates",
            input: |n| build("a", |i| format!(";{}=1", colliding_name(i)), "", n),
            default: |v| outcome(sfv::parse_item(v)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(sfv::Parser::new(FULL).item(v)),
        },
        Case {
            name: "Structured Field dictionary, distinct keys",
            input: |n| build("", |i| format!("{}=1, ", name(i)), "z", n),
            default: |v| outcome(sfv::parse_dictionary(v)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(sfv::Parser::new(FULL).dictionary(v)),
        },
        Case {
            name: "Structured Field dictionary, one key repeated",
            input: |n| build("", |_| "a=1, ".into(), "a", n),
            default: |v| outcome(sfv::parse_dictionary(v)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(sfv::Parser::new(FULL).dictionary(v)),
        },
        Case {
            name: "Structured Field dictionary, keys no filter separates",
            input: |n| build("", |i| format!("{}=1, ", colliding_name(i)), "z", n),
            default: |v| outcome(sfv::parse_dictionary(v)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(sfv::Parser::new(FULL).dictionary(v)),
        },
        Case {
            name: "encoded words, many",
            input: |n| build("", |_| "=?UTF-8?Q?a=C3=A9?= ".into(), "z", n),
            default: |v| {
                outcome(mail::decode_words(
                    v,
                    &Limits::DEFAULT,
                    &mut vec![0; v.len()],
                ))
            },
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(mail::decode_words(v, &FULL, &mut vec![0; v.len()])),
        },
        Case {
            name: "MIME parameters, many",
            input: |n| build("", |i| format!("; {}=\"v\"", name(i)), "", n),
            default: |v| outcome(mail::parse_mime_params(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(mail::parse_mime_params(v, &FULL)),
        },
        Case {
            name: "MIME parameters, many RFC 2231 sections",
            input: |n| build("", |i| format!("; t*{i}=a"), "", n),
            // Each section is a parameter: the 64-parameter cap comes first
            // at this size (`TooManySections` below it).
            default: |v| outcome(mail::parse_mime_params(v, &Limits::DEFAULT)),
            expect: Err(ErrorKind::TooManyMembers),
            full: |v| outcome(mail::parse_mime_params(v, &FULL)),
        },
        Case {
            name: "addr-spec, long dotted local part",
            input: |n| build("", |_| "a.".into(), "a@example.com", n),
            default: |v| outcome(mail::parse_addr_spec(v)),
            expect: Err(ErrorKind::TooLong),
            full: |v| outcome(mail::parse_addr_spec(v)),
        },
        Case {
            // The display name: the addr-spec takes no comments (MAIL-10).
            name: "mailbox, display name of words and comments",
            input: |n| build("", |_| "a (b) ".into(), "<a@b>", n),
            default: |v| outcome(mail::parse_mailbox(v, &Limits::DEFAULT)),
            expect: Ok(()),
            full: |v| outcome(mail::parse_mailbox(v, &FULL)),
        },
        Case {
            name: "unfold, many folds",
            input: |n| build("a", |_| "\r\n a".into(), "", n),
            default: |v| {
                mail::unfold(v)
                    .map(|u| {
                        u.iter().for_each(|p| {
                            black_box(p);
                        })
                    })
                    .map_err(|e| e.kind())
            },
            expect: Ok(()),
            full: |v| {
                mail::unfold(v)
                    .map(|u| {
                        u.iter().for_each(|p| {
                            black_box(p);
                        })
                    })
                    .map_err(|e| e.kind())
            },
        },
        Case {
            name: "RFC 5322 date, long comments",
            input: |n| build("Wed, 21 Oct 2026 17:38:00 +0200 ", |_| "(a) ".into(), "", n),
            default: |v| outcome(pn::MailDate::parse(v, false)),
            expect: Ok(()),
            full: |v| outcome(pn::MailDate::parse(v, true)),
        },
    ]
}

#[test]
fn test_complexity_linear() {
    let mut failures = Vec::new();
    for c in cases() {
        let inputs = SIZES.map(|n| (c.input)(n));
        let got = (c.default)(&inputs[2]);
        if got != c.expect {
            failures.push(format!(
                "{}: {got:?} at 1 MiB, expected {:?}",
                c.name, c.expect
            ));
        }
        let mut last = None;
        let passed = (0..3).any(|_| {
            let (a, b, t) = ratios(&c, &inputs);
            last = Some((a, b, t));
            a <= 1.2 && b <= 1.2
        });
        let (a, b, t) = last.unwrap();
        println!(
            "{:<60} {:>10.1?} {:>10.1?} {:>10.1?}   x{a:.2} x{b:.2}",
            c.name, t[0], t[1], t[2]
        );
        if !passed {
            failures.push(format!("{}: time over size grew x{a:.2} (1 KiB to 64 KiB) and x{b:.2} (64 KiB to 1 MiB); times {t:?}", c.name));
        }
    }
    assert!(failures.is_empty(), "not linear:\n{}", failures.join("\n"));
}
