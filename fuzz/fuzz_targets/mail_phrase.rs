#![no_main]
//! Phrases (display names): no panic, no allocation. Decoded text holds no
//! control character but HTAB and never grows past twice the input; a
//! phrase of atoms alone reads back as its words joined by one space; any
//! text in a quoted string reads back unchanged; and a display name that
//! `parse_mailbox` accepts decodes or fails with a listed error.

use libfuzzer_sys::fuzz_target;
use parse_net::{Limits, mail};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

/// The words of `v`, split at SP, HTAB, and `CRLF WSP`, joined by one space,
/// into `out`; `None` for a byte no plain phrase holds.
fn plain_words<'b>(v: &[u8], out: &'b mut [u8]) -> Option<&'b [u8]> {
    let mut n = 0;
    let mut i = 0;
    let mut word = false;
    while i < v.len() {
        let b = v[i];
        let ws = match (b, v.get(i + 1), v.get(i + 2)) {
            (b' ' | b'\t', _, _) => 1,
            (b'\r', Some(b'\n'), Some(b' ' | b'\t')) => 3,
            _ => 0,
        };
        if ws > 0 {
            word = false;
            i += ws;
            continue;
        }
        if !(parse_net::class::is_atext(b) || b == b'.' || b >= 0x80) {
            return None;
        }
        if !word && n > 0 {
            out[n] = b' ';
            n += 1;
        }
        word = true;
        out[n] = b;
        n += 1;
        i += 1;
    }
    Some(&out[..n])
}

fuzz_target!(|data: &[u8]| {
    let mut out = [0u8; 16384];
    let mut want = [0u8; 8192];
    let mut quoted = [0u8; 16384];
    common::no_alloc(|| {
        match mail::decode_phrase(data, &Limits::DEFAULT, &mut out) {
            Ok(s) => {
                assert!(s.len() <= 2 * data.len());
                assert!(!s.chars().any(|c| c.is_control() && c != '\t'), "{s:?}");
                let encoded = data.windows(2).any(|w| w == b"=?");
                if !encoded {
                    if let Some(w) = plain_words(data, &mut want) {
                        assert_eq!(s.as_bytes(), w);
                    }
                }
            }
            Err(e) => common::check_error(&e),
        }

        // Any text without a control character goes through a quoted string.
        if let Ok(text) = core::str::from_utf8(data) {
            if !text.chars().any(|c| c.is_control() && c != '\t') && data.len() < 8000 {
                let mut n = 0;
                quoted[n] = b'"';
                n += 1;
                for &b in data {
                    if b == b'"' || b == b'\\' {
                        quoted[n] = b'\\';
                        n += 1;
                    }
                    quoted[n] = b;
                    n += 1;
                }
                quoted[n] = b'"';
                n += 1;
                let back = mail::decode_phrase(&quoted[..n], &Limits::DEFAULT, &mut out).expect("quoted text decodes");
                assert_eq!(back, text);
            }
        }

        if let Ok(m) = mail::parse_mailbox(data, &Limits::DEFAULT) {
            if let Some(name) = m.display_name {
                match mail::decode_phrase(name, &Limits::DEFAULT, &mut out) {
                    Ok(s) => assert!(s.len() <= 2 * name.len()),
                    Err(e) => common::check_error(&e),
                }
            }
        }
    });
});
