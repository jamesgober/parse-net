#![no_main]
//! RFC 5322 dates: no panic, no allocation; a parsed date formats to text
//! that parses back, strictly, to the same instant and offset.

use libfuzzer_sys::fuzz_target;
use parse_net::MailDate;

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    common::no_alloc(|| {
        for obsolete in [false, true] {
            match MailDate::parse(data, obsolete) {
                Ok(d) => {
                    let (b, n) = d.format();
                    let back = MailDate::parse(&b[..n], false).expect("formatted date parses");
                    assert_eq!((back.utc(), back.offset_minutes()), (d.utc(), d.offset_minutes()));
                    assert_eq!(back.offset_unknown(), d.offset_unknown());
                }
                Err(e) => common::check_error(&e),
            }
        }
    });
});
