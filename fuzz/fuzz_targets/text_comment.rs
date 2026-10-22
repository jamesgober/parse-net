#![no_main]
//! Comments: no panic, no allocation, no recursion, depth bounded.

use libfuzzer_sys::fuzz_target;
use parse_net::{Limits, text};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let limits = Limits::DEFAULT.max_comment_depth(4);
    let parsed = common::no_alloc(|| text::parse_comment(data, &limits));
    match parsed {
        Ok((c, used)) => {
            assert!(c.max_depth() >= 1 && c.max_depth() <= 4);
            assert_eq!(c.raw().len() + 2, used);
        }
        Err(e) => common::check_error(&e),
    }
});
