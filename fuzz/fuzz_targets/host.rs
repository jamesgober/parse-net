#![no_main]
//! Host: no panic, no allocation, and the written form parses back to an
//! equal host and port.

use libfuzzer_sys::fuzz_target;
use parse_net::{SliceSink, parse_host_port};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; 8192];
    let parsed = common::no_alloc(|| {
        let r = parse_host_port(data);
        if let Ok(hp) = r {
            let mut out = SliceSink::new(&mut buf);
            hp.write_to(&mut out).expect("room");
            let back = parse_host_port(out.written()).expect("written host parses");
            assert!(back.host.eq_ignore_ascii_case(&hp.host));
            assert_eq!(back.port, hp.port);
        }
        r.map(|_| ())
    });
    if let Err(e) = parsed {
        common::check_error(&e);
    }
});
