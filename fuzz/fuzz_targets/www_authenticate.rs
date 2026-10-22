#![no_main]
//! `WWW-Authenticate`: no panic, no allocation; the challenge list counts
//! what it iterates, and a written challenge parses back to its scheme and
//! parameters.

use libfuzzer_sys::fuzz_target;
use parse_net::{AuthPayload, Limits, SliceSink, auth};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; 16_384];
    let mut val = [0u8; 4096];
    common::no_alloc(|| {
        match auth::parse_challenges(data, &Limits::DEFAULT) {
            Ok(cs) => {
                assert_eq!(cs.iter().count(), cs.len());
                for c in cs.iter() {
                    if let AuthPayload::Params(p) = c.payload() {
                        assert_eq!(p.iter().count(), p.len());
                    }
                }
            }
            Err(e) => common::check_error(&e),
        }
        // A challenge from the input: scheme, then up to three parameters
        // split on spaces as `name=value`.
        let Ok(text) = core::str::from_utf8(data) else { return };
        let mut parts = text.split(' ');
        let scheme = parts.next().unwrap_or("");
        let mut params = [("", ""); 3];
        let mut n = 0;
        for p in parts.take(3) {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            params[n] = (k, v);
            n += 1;
        }
        let mut out = SliceSink::new(&mut buf);
        if auth::write_challenge(scheme, &params[..n], &mut out).is_ok() {
            let cs = auth::parse_challenges(out.written(), &Limits::DEFAULT).expect("written challenge parses");
            let c = cs.iter().next().expect("one challenge");
            assert!(c.scheme_is(scheme));
            for (k, v) in &params[..n] {
                let got = c.param(k).expect("parameter present");
                assert_eq!(got.unescape_into(&mut val).expect("room"), v.as_bytes());
            }
        }
    });
});
