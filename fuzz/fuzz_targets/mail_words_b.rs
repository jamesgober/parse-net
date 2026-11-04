#![no_main]
//! RFC 2047 `B` words: no panic, no allocation. Any text encoded with
//! `encode_words_b`, unfolded, and decoded comes back unchanged, in words of
//! at most 75 bytes, and reads back as `encode_words` does; the decoder, fed
//! arbitrary text as a `B` word, never writes more than three bytes for four.

use libfuzzer_sys::fuzz_target;
use parse_net::{Limits, SliceSink, mail};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

/// Encodes `text`, unfolds it into `flat`, and decodes it into `out`, without
/// the space of a fold before the first word.
fn round_trip<'b>(
    written: &[u8],
    flat: &mut [u8],
    out: &'b mut [u8],
) -> &'b str {
    let pieces = mail::unfold(written).expect("encoded words unfold");
    let mut n = 0;
    for p in pieces.iter() {
        flat[n..n + p.len()].copy_from_slice(p);
        n += p.len();
    }
    let limits = Limits::DEFAULT.max_encoded_words(u16::MAX);
    let back = mail::decode_words(&flat[..n], &limits, out).expect("encoded words decode");
    if written.starts_with(b"\r\n ") {
        back.strip_prefix(' ').expect("the fold's space")
    } else {
        back
    }
}

fuzz_target!(|data: &[u8]| {
    let mut out = [0u8; 8192];
    let mut enc = [0u8; 32768];
    let mut flat = [0u8; 32768];
    let mut word = [0u8; 8192];
    common::no_alloc(|| {
        // The bytes as the text of one `B` word.
        let n = data.len().min(word.len() - 12);
        word[..10].copy_from_slice(b"=?UTF-8?B?");
        word[10..10 + n].copy_from_slice(&data[..n]);
        word[10 + n..12 + n].copy_from_slice(b"?=");
        match mail::decode_words(&word[..12 + n], &Limits::DEFAULT, &mut out) {
            Ok(s) => {
                let shaped = !data[..n].iter().any(|b| matches!(b, b'?' | b' ' | b'\t' | b'\r' | b'\n'));
                assert!(!shaped || s.len() <= n / 4 * 3, "{} bytes from {n}", s.len());
            }
            Err(e) => common::check_error(&e),
        }

        let Ok(text) = core::str::from_utf8(data) else { return };
        let room = data.first().map_or(70, |&b| usize::from(b % 80));
        let mut sink = SliceSink::new(&mut enc);
        if mail::encode_words_b(text, room, &mut sink).is_err() {
            assert!(text.chars().any(char::is_control));
            return;
        }
        let written = sink.written();
        for (i, line) in written.split(|&b| b == b'\n').enumerate() {
            let w = line.strip_suffix(b"\r").unwrap_or(line);
            let w = w.strip_prefix(b" ").unwrap_or(w);
            if w.starts_with(b"=?") {
                assert!(w.starts_with(b"=?UTF-8?B?"));
                assert!(w.len() <= if i == 0 { room.min(75) } else { 75 });
            }
        }
        let back = round_trip(written, &mut flat, &mut out);
        assert_eq!(back, text);

        // The Q form of the same text reads back the same.
        let mut sink = SliceSink::new(&mut enc);
        mail::encode_words(text, room, &mut sink).expect("Q takes what B took");
        let back = round_trip(sink.written(), &mut flat, &mut out);
        assert_eq!(back, text);
    });
});
