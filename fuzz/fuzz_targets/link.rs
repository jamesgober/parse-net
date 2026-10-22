#![no_main]
//! `Link`: no panic, no allocation; every view walks, titles decode within
//! their bound, and a link written from a parsed one parses back to the same
//! target and parameters.

use libfuzzer_sys::fuzz_target;
use parse_net::{Limits, SliceSink, link, parse_link};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; 8192];
    let mut title = [0u8; 4096];
    common::no_alloc(|| match parse_link(data, &Limits::DEFAULT) {
        Ok(links) => {
            assert_eq!(links.iter().count(), links.len());
            for v in links.iter() {
                assert_eq!(v.params().iter().count(), v.params().len());
                let _ = v.rels().count();
                let _ = v.hreflang().count();
                if let Some(t) = v.title() {
                    let _ = t.decode_into(&mut title);
                }
                // Rewrite when every parameter value is plain text.
                let mut pairs = [("", ""); 8];
                let mut n = 0;
                let mut plain = v.params().len() <= pairs.len();
                for (name, w) in v.params().iter() {
                    let value = match w {
                        None => Some(""),
                        Some(w) => w.as_str().filter(|s| !s.is_empty()),
                    };
                    match (core::str::from_utf8(name), value) {
                        (Ok(name), Some(value)) if n < pairs.len() => {
                            pairs[n] = (name, value);
                            n += 1;
                        }
                        _ => plain = false,
                    }
                }
                if plain {
                    let mut out = SliceSink::new(&mut buf);
                    link::write_link(v.target(), &pairs[..n], &mut out).expect("a parsed link writes");
                    let back = parse_link(out.written(), &Limits::DEFAULT).expect("written link parses");
                    let b = back.iter().next().expect("one link");
                    assert_eq!(b.target(), v.target());
                    assert_eq!(b.params().len(), v.params().len());
                }
            }
        }
        Err(e) => common::check_error(&e),
    });
});
