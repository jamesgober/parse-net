#![no_main]
//! Entity tags and conditions: no panic, no allocation; a parsed tag writes
//! back to the same bytes, and every listed tag compares equal to itself.

use libfuzzer_sys::fuzz_target;
use parse_net::{EntityTag, Limits, SliceSink, etag};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; 4200];
    common::no_alloc(|| {
        if let Ok(t) = EntityTag::parse(data) {
            let mut out = SliceSink::new(&mut buf);
            t.write_to(&mut out).expect("room");
            let back = EntityTag::parse(out.written()).expect("written tag parses");
            assert_eq!(back, t);
            assert!(t.weak_eq(&back));
            assert_eq!(t.strong_eq(&back), !t.is_weak());
        }
        match etag::parse_condition(data, &Limits::DEFAULT) {
            Ok(etag::Condition::Tags(list)) => {
                assert_eq!(list.iter().count(), list.len());
                for t in list.iter() {
                    assert!(t.weak_eq(&t));
                    // `true`: a listed tag matches, so the condition fails.
                    assert_eq!(etag::if_none_match(data, &t), Ok(true));
                }
            }
            Ok(etag::Condition::Any) => {}
            Err(e) => {
                common::check_error(&e);
                assert!(etag::if_none_match(data, &EntityTag::strong(b"x").expect("tag")).is_err());
            }
        }
        let _ = etag::if_match(data, None);
    });
});
