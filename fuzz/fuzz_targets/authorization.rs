#![no_main]
//! `Authorization`: no panic, no allocation; `Debug` never prints a
//! credential, and `basic` and `bearer` agree with the general parse.

use libfuzzer_sys::fuzz_target;
use parse_net::{AuthPayload, Limits, auth};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let r = common::no_alloc(|| {
        let _ = auth::bearer(data);
        let _ = auth::basic(data);
        let c = auth::parse_credentials(data, &Limits::DEFAULT)?;
        if let AuthPayload::Params(p) = c.payload() {
            assert_eq!(p.iter().count(), p.len());
        }
        if let Ok(Some(t)) = auth::bearer(data) {
            assert!(c.scheme_is("Bearer"));
            assert_eq!(c.payload(), AuthPayload::Token68(t));
        }
        Ok(c)
    });
    match r {
        Ok(c) => {
            let shown = format!("{c:?}");
            if let AuthPayload::Token68(t) = c.payload() {
                // `Debug` prints the scheme, so a token that also occurs in
                // the scheme proves nothing.
                let scheme = String::from_utf8_lossy(c.scheme());
                let t = String::from_utf8_lossy(t);
                if t.len() >= 8 && !scheme.contains(&*t) {
                    assert!(!shown.contains(&*t), "Debug printed the credential");
                }
            }
        }
        Err(e) => common::check_error(&e),
    }
});
