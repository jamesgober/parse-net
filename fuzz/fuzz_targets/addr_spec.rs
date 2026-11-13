#![no_main]
//! Addresses: no panic, no allocation; `addr-spec`, `mailbox`, and `msg-id`
//! agree with each other, and an ASCII message identifier rewrites to
//! itself.

use libfuzzer_sys::fuzz_target;
use parse_net::{SliceSink, mail};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; 8192];
    common::no_alloc(|| {
        match mail::parse_addr_spec(data) {
            Ok(a) => {
                let _ = a.is_ascii();
                let m = mail::parse_mailbox(data).expect("an addr-spec is a mailbox");
                assert!(m.display_name.is_none());
            }
            Err(e) => common::check_error(&e),
        }
        if let Err(e) = mail::parse_mailbox(data) {
            common::check_error(&e);
        }
        match mail::parse_msg_id(data) {
            Ok(id) => {
                if let (Ok(l), Ok(r)) = (core::str::from_utf8(id.left), core::str::from_utf8(id.right)) {
                    // Past 998 bytes no line can hold it, so it is not written.
                    if l.is_ascii() && r.is_ascii() && l.len() + r.len() + 3 <= 998 {
                        let mut out = SliceSink::new(&mut buf);
                        mail::write_msg_id(l, r, &mut out).expect("a parsed ASCII id writes");
                        let back = mail::parse_msg_id(out.written()).expect("written id parses");
                        assert_eq!((back.left, back.right), (id.left, id.right));
                    }
                }
            }
            Err(e) => common::check_error(&e),
        }
    });
});
