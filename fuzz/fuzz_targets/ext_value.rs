#![no_main]
//! RFC 8187 `ext-value`: no panic, no allocation; a value that decodes
//! writes back and decodes to the same text.

use libfuzzer_sys::fuzz_target;
use parse_net::{ExtValue, SliceSink, write_ext_value};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let mut text = [0u8; 4096];
    let mut buf = [0u8; 13_000];
    let mut again = [0u8; 4096];
    let r = common::no_alloc(|| {
        let v = ExtValue::parse(data)?;
        let max = v.max_decoded_len();
        let decoded = v.decode_into(&mut text[..max.min(4096)])?;
        assert!(decoded.len() <= max);
        let mut out = SliceSink::new(&mut buf);
        if write_ext_value(decoded, &mut out).is_ok() {
            let back = ExtValue::parse(out.written()).expect("written value parses");
            assert_eq!(back.decode_into(&mut again).expect("decodes"), decoded);
        }
        Ok(())
    });
    if let Err(e) = r {
        common::check_error(&e);
    }
});
