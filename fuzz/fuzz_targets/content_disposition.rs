#![no_main]
//! `Content-Disposition`: no panic, no allocation; a file name decodes
//! within its bound, and `write_attachment` output parses back to a name
//! that decodes to the input.

use libfuzzer_sys::fuzz_target;
use parse_net::{SliceSink, parse_content_disposition, write_attachment};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let mut name = [0u8; 4096];
    let mut buf = [0u8; 16_384];
    common::no_alloc(|| {
        match parse_content_disposition(data) {
            Ok(d) => {
                let _ = d.kind();
                let _ = d.name();
                if let Some(f) = d.filename() {
                    let _ = f.has_path_separator();
                    let _ = f.has_bidi_control();
                    let max = f.max_decoded_len();
                    if let Ok(s) = f.decode_into(&mut name) {
                        assert!(s.len() <= max);
                    }
                    let _ = f.decode_percent_into(&mut name);
                }
            }
            Err(e) => common::check_error(&e),
        }
        if let Ok(text) = core::str::from_utf8(data) {
            let mut out = SliceSink::new(&mut buf);
            if write_attachment(text, &mut out).is_ok() {
                let d = parse_content_disposition(out.written()).expect("written value parses");
                let f = d.filename().expect("a file name");
                assert_eq!(f.decode_into(&mut name).expect("decodes"), text);
            }
        }
    });
});
