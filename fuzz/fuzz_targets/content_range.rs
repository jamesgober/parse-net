#![no_main]
//! `Content-Range` and `If-Range`: no panic, no allocation; a parsed
//! `Content-Range` writes back to a value that parses to the same range.

use libfuzzer_sys::fuzz_target;
use parse_net::{ContentRange, SliceSink, range};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; 128];
    common::no_alloc(|| {
        match range::parse_content_range(data) {
            Ok(c) => {
                let mut out = SliceSink::new(&mut buf);
                match c {
                    ContentRange::Satisfied { range: r, complete } => {
                        range::write_content_range(r, complete, &mut out).expect("valid range writes")
                    }
                    ContentRange::Unsatisfied { complete } => {
                        range::write_unsatisfied(complete, &mut out).expect("room")
                    }
                }
                assert_eq!(range::parse_content_range(out.written()), Ok(c));
            }
            Err(e) => common::check_error(&e),
        }
        if let Ok(c) = range::parse_if_range(data) {
            let _ = c.matches(None, None);
        }
    });
});
