#![no_main]
//! Parameters: no panic, no allocation, the count matches the iterator, the
//! raw text is exactly the bytes used, and every name can be looked up.

use libfuzzer_sys::fuzz_target;
use parse_net::{DuplicatePolicy, Limits, param};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    for policy in [DuplicatePolicy::Refuse, DuplicatePolicy::Last] {
        let limits = Limits::DEFAULT.duplicate_params(policy);
        let parsed = common::no_alloc(|| {
            let r = param::parse(data, &limits);
            if let Ok((p, used)) = r {
                assert!(used <= data.len());
                assert_eq!(p.iter().count(), p.len());
                assert_eq!(p.raw().len(), used);
                for x in p.iter() {
                    let name = core::str::from_utf8(x.name).expect("names are tokens");
                    assert!(p.get(name).is_some());
                }
            }
            r
        });
        if let Err(e) = parsed {
            common::check_error(&e);
        }
    }
});
