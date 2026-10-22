#![no_main]
//! Content negotiation: no panic, no allocation; a chosen index is always
//! one of the offers, and the raw lists count what they iterate.

use libfuzzer_sys::fuzz_target;
use parse_net::{
    self as pn, Limits,
    negotiate::{self, LanguageMatching, MalformedPolicy, Negotiator, Outcome},
};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

const MEDIA: [&str; 4] = ["text/html", "application/json", "image/webp", "text/plain;charset=utf-8"];
const LANGS: [&str; 4] = ["en", "en-US", "de-CH-1996", "zh-Hant"];
const CODINGS: [&str; 4] = ["identity", "gzip", "br", "zstd"];
const CHARSETS: [&str; 3] = ["utf-8", "iso-8859-1", "windows-1252"];

fn check(o: Outcome, n: usize) {
    if let Some(i) = o.index() {
        assert!(i < n);
    }
}

fuzz_target!(|data: &[u8]| {
    common::no_alloc(|| {
        for (h, offers) in [(Some(data), &MEDIA[..]), (None, &MEDIA[..1])] {
            assert!(pn::best_media(h, offers).is_none_or(|i| i < offers.len()));
        }
        assert!(pn::best_language(Some(data), &LANGS).is_none_or(|i| i < LANGS.len()));
        assert!(pn::best_encoding(Some(data), &CODINGS).is_none_or(|i| i < CODINGS.len()));
        assert!(pn::best_charset(Some(data), &CHARSETS).is_none_or(|i| i < CHARSETS.len()));
        let strict = Negotiator::new()
            .on_malformed(MalformedPolicy::Refuse)
            .language_matching(LanguageMatching::BasicFilter);
        check(strict.media(Some(data), &MEDIA), MEDIA.len());
        check(strict.language(Some(data), &LANGS), LANGS.len());
        check(strict.encoding(Some(data), &CODINGS), CODINGS.len());
        check(strict.charset(Some(data), &CHARSETS), CHARSETS.len());
        let halves = data.split_at(data.len() / 2);
        check(strict.media_lines([halves.0, halves.1], &MEDIA), MEDIA.len());
        match negotiate::parse_accept(data, &Limits::DEFAULT) {
            Ok(l) => assert_eq!(l.iter().count(), l.len()),
            Err(e) => common::check_error(&e),
        }
        match negotiate::parse_weighted(data, &Limits::DEFAULT) {
            Ok(l) => assert_eq!(l.iter().count(), l.len()),
            Err(e) => common::check_error(&e),
        }
        let _ = negotiate::QValue::parse(data);
    });
});
