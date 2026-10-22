#![no_main]
//! Media types: no panic, no allocation, and the canonical form parses back
//! to the same essence and parameter count.

use libfuzzer_sys::fuzz_target;
use parse_net::{SliceSink, parse_media_type};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; 8192];
    let parsed = common::no_alloc(|| {
        let r = parse_media_type(data);
        if let Ok(m) = r {
            let _ = m.boundary();
            let _ = m.is_json();
            let mut out = SliceSink::new(&mut buf);
            m.write_canonical(&mut out).expect("room");
            let back = parse_media_type(out.written()).expect("canonical form parses");
            assert!(back.type_().eq_ignore_ascii_case(m.type_()));
            assert!(back.subtype().eq_ignore_ascii_case(m.subtype()));
            assert_eq!(back.params().len(), m.params().len());
        }
        r.map(|_| ())
    });
    if let Err(e) = parsed {
        common::check_error(&e);
    }
});
