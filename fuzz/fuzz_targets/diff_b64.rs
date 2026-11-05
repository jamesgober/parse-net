#![no_main]
//! Differential oracle (dev/PLAN.md section 15): the base64 of `B` encoded
//! words (D-080) against the `base64` crate's STANDARD engine, which demands
//! canonical padding and zero bits under it, as parse-net does. Each input
//! byte picks a base64 character or a near miss, the result goes in an
//! ISO-8859-1 `B` word, and `decode_words` must read exactly what `base64`
//! reads: the same bytes, or a refusal, or `ControlInDecoded` for a decoded
//! control byte, and nothing past the 75-byte word limit.

use base64::Engine;
use libfuzzer_sys::fuzz_target;
use parse_net::{ErrorKind, Limits, mail};

/// The alphabet, padding, and near misses (URL-safe letters, `.`, `*`).
const SYMBOLS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_.*";

fuzz_target!(|data: &[u8]| {
    let text: Vec<u8> = data
        .iter()
        .map(|&b| SYMBOLS[usize::from(b) % SYMBOLS.len()])
        .collect();
    let mut word = b"=?ISO-8859-1?B?".to_vec();
    word.extend_from_slice(&text);
    word.extend_from_slice(b"?=");
    let mut out = [0u8; 256];
    let ours = mail::decode_words(&word, &Limits::DEFAULT, &mut out).map(String::from);
    let theirs = base64::engine::general_purpose::STANDARD.decode(&text);
    if word.len() > 75 {
        assert_eq!(ours.map_err(|e| e.kind()), Err(ErrorKind::InvalidEncodedWord));
        return;
    }
    match theirs {
        Err(_) => {
            assert_eq!(
                ours.map_err(|e| e.kind()),
                Err(ErrorKind::InvalidEncodedWord),
                "base64 refuses {:?}",
                String::from_utf8_lossy(&text)
            );
        }
        Ok(bytes) if bytes.iter().any(|&b| b < 0x20 || (0x7f..=0x9f).contains(&b)) => {
            assert_eq!(ours.map_err(|e| e.kind()), Err(ErrorKind::ControlInDecoded));
        }
        Ok(bytes) => {
            let latin1: String = bytes.iter().map(|&b| char::from(b)).collect();
            assert_eq!(ours.expect("base64 reads it"), latin1);
        }
    }
});
