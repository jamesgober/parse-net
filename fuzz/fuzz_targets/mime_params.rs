#![no_main]
//! MIME parameters: no panic, no allocation; every value decodes within its
//! bound, and a value written by `write_mime_param` parses back unchanged.

use libfuzzer_sys::fuzz_target;
use parse_net::{Limits, SliceSink, mail};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let mut out = [0u8; 16384];
    let mut buf = [0u8; 65536];
    common::no_alloc(|| {
        match mail::parse_mime_params(data, &Limits::DEFAULT) {
            Ok((p, used)) => {
                assert!(used <= data.len());
                assert_eq!(p.iter().count(), p.len());
                for (name, _) in p.iter() {
                    if let Ok(name) = core::str::from_utf8(name) {
                        let _ = p.get(name);
                        let _ = p.decode_into(name, &mut out);
                    }
                }
            }
            Err(e) => common::check_error(&e),
        }
        let Ok(value) = core::str::from_utf8(data) else { return };
        let mut sink = SliceSink::new(&mut buf);
        match mail::write_mime_param("filename", value, &mut sink) {
            Ok(()) => {
                let written = sink.written();
                for line in written.split(|&b| b == b'\n') {
                    assert!(line.len() <= 79);
                }
                let (p, used) = mail::parse_mime_params(written, &Limits::DEFAULT).expect("written parameter parses");
                assert_eq!(used, written.len());
                assert_eq!(p.decode_into("filename", &mut out).expect("decodes"), Some(value));
            }
            Err(_) => assert!(value.chars().any(char::is_control) || value.len() > 1000),
        }
    });
});
