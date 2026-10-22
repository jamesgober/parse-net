#![no_main]
//! `Range`: no panic, no allocation; every resolved range lies inside the
//! representation, in order when coalesced, and never overlaps its neighbour.

use libfuzzer_sys::fuzz_target;
use parse_net::{ByteRange, Limits, RangeOutcome, range};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    // The first eight bytes choose the representation length.
    let (len_bytes, value) = data.split_at(data.len().min(8));
    let mut n = [0u8; 8];
    n[..len_bytes.len()].copy_from_slice(len_bytes);
    let length = u64::from_le_bytes(n) % 1_000_000_007;
    let mut out = [ByteRange { start: 0, end: 0 }; 16];
    common::no_alloc(|| {
        match range::parse(value, &Limits::DEFAULT) {
            Ok(h) => {
                if h.is_bytes() {
                    assert_eq!(h.specs().count(), h.len());
                }
                for coalesce in [false, true] {
                    if let RangeOutcome::Ranges(k) = range::resolve(&h, length, coalesce, &Limits::DEFAULT, &mut out) {
                        assert!(k >= 1 && k <= out.len());
                        for r in &out[..k] {
                            assert!(r.start <= r.end && r.end < length);
                        }
                        if coalesce {
                            for w in out[..k].windows(2) {
                                assert!(w[0].end.saturating_add(1) < w[1].start);
                            }
                        }
                    }
                }
            }
            Err(e) => common::check_error(&e),
        }
        let _ = range::byte_ranges(value, length, &mut out);
    });
});
