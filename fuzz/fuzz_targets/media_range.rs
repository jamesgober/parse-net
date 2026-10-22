#![no_main]
//! Media ranges: no panic, no allocation; matching is consistent with
//! specificity, and a range always matches an offer it was written from.

use libfuzzer_sys::fuzz_target;
use parse_net::{Limits, media, parse_media_type};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let r = common::no_alloc(|| {
        let r = media::parse_range(data, &Limits::DEFAULT)?;
        let _ = r.weight();
        assert!((1..=4).contains(&r.specificity()));
        if r.type_() != b"*" && r.subtype() != b"*" && r.params().is_empty() {
            let mut buf = [0u8; 4096];
            let mut out = parse_net::SliceSink::new(&mut buf);
            let ty = core::str::from_utf8(r.type_()).expect("token");
            let sub = core::str::from_utf8(r.subtype()).expect("token");
            media::write(ty, sub, &[], &mut out).expect("room");
            let offer = parse_media_type(out.written()).expect("written type parses");
            assert!(r.matches(&offer));
        }
        Ok(())
    });
    if let Err(e) = r {
        common::check_error(&e);
    }
});
