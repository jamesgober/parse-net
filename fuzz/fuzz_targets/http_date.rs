#![no_main]
//! HTTP-date: no panic, no allocation, every accepted date formats back to
//! an IMF-fixdate that parses to the same instant, and an accepted
//! IMF-fixdate formats back to exactly its input.

use libfuzzer_sys::fuzz_target;
use parse_net::{HttpDate, text};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let errors = common::no_alloc(|| {
        let mut errors = [None; 3];
        for (slot, now) in errors.iter_mut().zip([0i64, 1_792_540_800, HttpDate::MAX.unix()]) {
            match HttpDate::parse_at(data, now) {
                Ok(d) => assert_eq!(HttpDate::parse_imf_fixdate(&d.format()), Ok(d)),
                Err(e) => *slot = Some(e),
            }
        }
        if let Ok(d) = HttpDate::parse_imf_fixdate(data) {
            assert_eq!(&d.format()[..], text::trim_ows(data));
        }
        errors
    });
    for e in errors.iter().flatten() {
        common::check_error(e);
    }
});
