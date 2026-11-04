#![no_main]
//! Parameters whose value may be left out: no panic, no allocation, the
//! count matches the iterator, the raw text is exactly the bytes used, every
//! name can be found, and wherever `param::parse` reads the input this reads
//! the same parameters.

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
            let r = param::parse_optional(data, &limits);
            if let Ok((p, used)) = r {
                assert!(used <= data.len());
                assert_eq!(p.iter().count(), p.len());
                assert_eq!(p.raw().len(), used);
                for x in p.iter() {
                    let name = core::str::from_utf8(x.name).expect("names are tokens");
                    assert!(p.find(name).is_some() && p.contains(name));
                }
            }
            if let Ok((q, used)) = param::parse(data, &limits) {
                let (p, o_used) = r.expect("parse_optional reads what parse reads");
                assert_eq!((p.raw(), o_used), (q.raw(), used));
                assert!(p.iter().map(|x| x.value).eq(q.iter().map(|x| Some(x.value))));
            }
            r
        });
        if let Err(e) = parsed {
            common::check_error(&e);
        }
    }
});
