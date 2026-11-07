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
            // Split at the first comma outside quotes and comments whose prefix
            // is a list. Trying every comma reparsed each prefix: quadratic on
            // a comment holding a thousand escaped commas.
            if let Some(i) = top_level_commas(data)
                .take(16)
                .find(|&i| list::parse(&data[..i], &Limits::DEFAULT).is_ok())
            {
                let lines = [&data[..i], &data[i + 1..]];
                if let Ok(c) = list::combined(lines, &Limits::DEFAULT) {
                    assert_eq!(c.iter().collect::<Vec<_>>(), whole);
                }
            }
        }
        Err(e) => common::check_error(&e),
    }
});

/// Offsets of the commas outside quoted strings and comments, in one pass.
fn top_level_commas(data: &[u8]) -> impl Iterator<Item = usize> + '_ {
    let (mut quote, mut depth, mut escape) = (false, 0usize, false);
    data.iter().enumerate().filter_map(move |(i, &b)| {
        if escape {
            escape = false;
        } else if (quote || depth > 0) && b == b'\\' {
            escape = true;
        } else if quote {
            quote = b != b'"';
        } else if b == b'(' {
            depth += 1;
        } else if depth > 0 {
            depth -= usize::from(b == b')');
        } else if b == b'"' {
            quote = true;
        } else if b == b',' {
            return Some(i);
        }
        None
    })
}
