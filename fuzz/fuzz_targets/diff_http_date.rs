#![no_main]
//! Differential oracle (dev/PLAN.md section 15): parse-net and the `httpdate`
//! crate on the same input. A disagreement outside the classes recorded in
//! tests/differential/verdicts.md stops the run for a written verdict.

use std::time::UNIX_EPOCH;

use libfuzzer_sys::fuzz_target;
use parse_net::HttpDate;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // httpdate resolves RFC 850 years with a fixed pivot at 70 (verdict V-1);
    // compare only the formats where both read the year the same way.
    if text.contains('-') {
        return;
    }
    let ours = HttpDate::parse_at(data, 1_792_540_800).ok();
    let theirs = httpdate::parse_http_date(text).ok();
    match (ours, theirs) {
        (Some(a), Some(b)) => {
            let secs = b
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(-1);
            assert_eq!(a.unix(), secs, "both accept {text:?} but disagree on the instant");
        }
        (None, None) => {}
        // V-2: httpdate cannot represent dates before 1970.
        (Some(a), None) if a.unix() < 0 => {}
        // V-3: parse-net strips OWS (RFC 9110 section 5.5); httpdate does not.
        (Some(_), None) if text != text.trim_matches([' ', '\t']) => {}
        // V-4: httpdate trims VT, FF, CR, and LF as whitespace; parse-net
        // refuses them (they are not OWS, threat T6).
        (None, Some(_)) if text.bytes().any(|b| matches!(b, 0x0b | 0x0c | 0x0d | 0x0a)) => {}
        (a, b) => panic!("disagreement on {text:?}: parse-net {a:?}, httpdate {b:?}"),
    }
});
