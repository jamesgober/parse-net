#![no_main]
//! Lists: no panic, no allocation, the element count matches the iterator,
//! no element is empty, and the value split into two lines at its first
//! separator gives the same elements.

use libfuzzer_sys::fuzz_target;
use parse_net::{Limits, list};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let parsed = common::no_alloc(|| {
        let r = list::parse(data, &Limits::DEFAULT);
        if let Ok(l) = r {
            assert_eq!(l.iter().count(), l.len());
            assert!(l.iter().all(|e| !e.is_empty()));
        }
        let _ = list::contains_token([data], b"upgrade");
        r
    });
    match parsed {
        Ok(l) => {
            let whole: Vec<&[u8]> = l.iter().collect();
            // Split at the first top-level comma, found by re-joining elements.
            if let Some((i, _)) = data.iter().enumerate().find(|&(i, &b)| {
                b == b',' && list::parse(&data[..i], &Limits::DEFAULT).is_ok()
            }) {
                let lines = [&data[..i], &data[i + 1..]];
                if let Ok(c) = list::combined(lines, &Limits::DEFAULT) {
                    assert_eq!(c.iter().collect::<Vec<_>>(), whole);
                }
            }
        }
        Err(e) => common::check_error(&e),
    }
});
