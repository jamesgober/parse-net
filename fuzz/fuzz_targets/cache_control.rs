#![no_main]
//! `Cache-Control`: no panic, no allocation; the directive list counts what
//! it iterates, and the writer's output parses.

use libfuzzer_sys::fuzz_target;
use parse_net::{Limits, SliceSink, cache};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; 8192];
    common::no_alloc(|| {
        match cache::parse(data, &Limits::DEFAULT) {
            Ok(d) => assert_eq!(d.iter().count(), d.len()),
            Err(e) => common::check_error(&e),
        }
        let _ = cache::response_cache_control(data);
        let _ = cache::request_cache_control(data);
        let half = data.split_at(data.len() / 2);
        let _ = cache::response_lines([half.0, half.1]);
        let _ = cache::request_lines([half.0, half.1]);
        if let Ok(text) = core::str::from_utf8(data) {
            let mut out = SliceSink::new(&mut buf);
            let mut w = cache::Writer::new(&mut out);
            let mut wrote = 0usize;
            for part in text.split(' ') {
                wrote += usize::from(w.flag(part).is_ok());
                wrote += usize::from(w.seconds(part, u32::MAX).is_ok());
            }
            let written = out.written();
            let d = cache::parse(written, &Limits::DEFAULT.max_list_members(u16::MAX)).expect("written list parses");
            assert_eq!(d.len(), wrote);
        }
    });
});
