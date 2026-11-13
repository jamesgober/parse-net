#![no_main]
//! Percent-decoding: no panic, no allocation, the decoded length agrees with
//! the decoder, and encoding the decoded bytes decodes back to them.

use libfuzzer_sys::fuzz_target;
use parse_net::{SliceSink, percent};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; 4096];
    let mut scratch = [0u8; 4096];
    let decoded = common::no_alloc(|| {
        let len = percent::decoded_len(data);
        let out = percent::decode_into(data, &mut buf).map(<[u8]>::len);
        assert_eq!(len.is_ok(), out.is_ok());
        if let (Ok(a), Ok(b)) = (len, out) {
            assert_eq!(a, b);
        }
        for e in [
            len.err(),
            out.err(),
            percent::validate(data).err(),
            percent::decode_utf8_into(data, &mut scratch).err(),
            percent::decode_lowercase_into(data, &mut scratch).err(),
        ]
        .iter()
        .flatten()
        {
            common::check_error(e);
        }
        out
    });
    if let Ok(n) = decoded {
        let plain = buf[..n].to_vec();
        let mut enc = [0u8; 16384];
        let mut out = SliceSink::new(&mut enc);
        percent::encode(&plain, &percent::EncodeSet::ATTR_CHAR_COMPLEMENT, percent::HexCase::Lower, &mut out)
            .expect("room");
        let mut back = [0u8; 4096];
        let again = percent::decode_lowercase_into(out.written(), &mut back).expect("valid");
        assert_eq!(again, &plain[..]);
    }
});
