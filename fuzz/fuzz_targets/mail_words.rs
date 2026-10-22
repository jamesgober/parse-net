#![no_main]
//! RFC 2047 words: no panic, no allocation; decoding never exceeds the
//! buffer, and any text encoded, unfolded, and decoded comes back unchanged.

use libfuzzer_sys::fuzz_target;
use parse_net::{Limits, SliceSink, mail};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let mut out = [0u8; 8192];
    let mut enc = [0u8; 32768];
    let mut flat = [0u8; 32768];
    common::no_alloc(|| {
        match mail::decode_words(data, &Limits::DEFAULT, &mut out) {
            Ok(s) => assert!(s.len() <= out.len()),
            Err(e) => common::check_error(&e),
        }
        let Ok(text) = core::str::from_utf8(data) else { return };
        let room = data.first().map_or(70, |&b| usize::from(b % 80));
        let mut sink = SliceSink::new(&mut enc);
        if mail::encode_words(text, room, &mut sink).is_err() {
            assert!(text.chars().any(char::is_control));
            return;
        }
        let written = sink.written();
        for word in written.split(|&b| b == b'\n') {
            let word = word.strip_suffix(b"\r").unwrap_or(word);
            let word = word.strip_prefix(b" ").unwrap_or(word);
            if word.starts_with(b"=?") {
                assert!(word.len() <= 75);
            }
        }
        let pieces = mail::unfold(written).expect("encoded words unfold");
        let mut n = 0;
        for p in pieces.iter() {
            flat[n..n + p.len()].copy_from_slice(p);
            n += p.len();
        }
        let limits = Limits::DEFAULT.max_encoded_words(u16::MAX);
        let back = mail::decode_words(&flat[..n], &limits, &mut out).expect("encoded words decode");
        assert_eq!(back, text);
    });
});
