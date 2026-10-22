#![no_main]
//! Differential oracle (dev/PLAN.md section 15): parse-net and the `mime`
//! crate on the same input. Where both accept, the type and subtype must
//! agree. parse-net is stricter by design; acceptance differences are
//! classified in tests/differential/verdicts.md.

use libfuzzer_sys::fuzz_target;
use parse_net::parse_media_type;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let ours = parse_media_type(data).ok();
    let theirs = text.parse::<mime::Mime>().ok();
    if let (Some(a), Some(b)) = (ours, theirs) {
        // `mime` splits a structured syntax suffix out of the subtype, so the
        // whole essence is compared.
        let ours = [a.type_(), b"/", a.subtype()].concat();
        assert!(
            ours.eq_ignore_ascii_case(b.essence_str().as_bytes()),
            "essence of {text:?}"
        );
    }
});
