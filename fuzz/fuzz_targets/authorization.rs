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
            // `Debug` prints the scheme and nothing else: an exact match,
            // since a token can occur in the fixed text (`Credenti` in
            // `Credentials`, found by the 0.7 run).
            let scheme = core::str::from_utf8(c.scheme()).unwrap_or("?");
            let want = format!("Credentials {{ scheme: {scheme:?}, .. }}");
            assert_eq!(format!("{c:?}"), want, "Debug printed more than the scheme");
        }
        Err(e) => common::check_error(&e),
    }
});
