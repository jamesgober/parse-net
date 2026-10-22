#![no_main]
//! Quoted strings and words: no panic, no allocation, consistent views, and
//! the writer's output parses back to the unescaped value.

use libfuzzer_sys::fuzz_target;
use parse_net::{SliceSink, text, write};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; 4096];
    let parsed = common::no_alloc(|| {
        let r = text::parse_quoted(data);
        if let Ok((q, used)) = r {
            assert!(used >= 2 && used <= data.len());
            assert_eq!(q.raw().len() + 2, used);
            if let Ok(v) = q.unescape_into(&mut buf) {
                assert_eq!(v.len(), q.unescaped_len());
            }
        }
        let _ = text::parse_word(data);
        r.map(|_| ())
    });
    if let Err(e) = parsed {
        common::check_error(&e);
    }
    // Whatever the writer accepts must parse back to the same bytes.
    let mut out_buf = [0u8; 8192];
    let mut out = SliceSink::new(&mut out_buf);
    if write::write_quoted(data, &mut out).is_ok() {
        let (q, used) = text::parse_quoted(out.written()).expect("writer output parses");
        assert_eq!(used, out.len());
        assert!(q.eq_bytes(data));
    }
});
