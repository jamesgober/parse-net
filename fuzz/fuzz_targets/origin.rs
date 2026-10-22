#![no_main]
//! `Origin`: no panic, no allocation; a parsed origin writes back to a value
//! that parses to the same origin.

use libfuzzer_sys::fuzz_target;
use parse_net::{OriginValue, SliceSink, parse_origin};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; 4200];
    let r = common::no_alloc(|| {
        if let OriginValue::Origin(o) = parse_origin(data)? {
            let mut out = SliceSink::new(&mut buf);
            o.write_to(&mut out).expect("room");
            let OriginValue::Origin(back) = parse_origin(out.written()).expect("written origin parses") else {
                panic!("null from a written origin");
            };
            assert!(o.same_origin(&back) && back.same_origin(&o));
        }
        Ok(())
    });
    if let Err(e) = r {
        common::check_error(&e);
    }
});
