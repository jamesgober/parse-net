#![no_main]
//! Header folding: no panic, no allocation; a folded value keeps its lines
//! within 998 bytes, never writes a line of only whitespace, and unfolds
//! back to the value.

use libfuzzer_sys::fuzz_target;
use parse_net::mail;

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; 65536];
    common::no_alloc(|| {
        if let Err(e) = mail::check_header_value(data) {
            common::check_error(&e);
        }
        match mail::unfold(data) {
            Ok(u) => {
                let total: usize = u.iter().map(<[u8]>::len).sum();
                assert!(total <= data.len());
            }
            Err(e) => common::check_error(&e),
        }
        let mut out = parse_net::SliceSink::new(&mut buf);
        if mail::fold("Subject", data, &mut out).is_ok() {
            let written = out.written();
            for line in written.split(|&b| b == b'\n') {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                assert!(line.len() <= 998);
                assert!(line.is_empty() || !line.iter().all(|&b| b == b' ' || b == b'\t'));
            }
            let body = &written[b"Subject:".len()..];
            let u = mail::unfold(body).expect("folded output unfolds");
            let mut n = 0;
            let mut matches = true;
            // The writer adds one space after the colon when the value does
            // not start with whitespace.
            let skip = usize::from(data.first().is_some_and(|&b| b != b' ' && b != b'\t'));
            for p in u.iter() {
                for &b in p {
                    if n >= skip {
                        matches &= data.get(n - skip) == Some(&b);
                    }
                    n += 1;
                }
            }
            assert!(matches && n == data.len() + skip);
        }
    });
});
