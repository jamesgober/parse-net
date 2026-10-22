#![no_main]
//! Structured Fields: whatever parses serializes canonically, the canonical
//! text parses to the same members, and serializing it again changes
//! nothing.

use libfuzzer_sys::fuzz_target;
use parse_net::{
    SliceSink, WriteError,
    sfv::{self, Item, Member, Writer},
};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fn item(w: &mut Writer<'_, SliceSink<'_>>, i: Item<'_>) -> Result<(), WriteError> {
    w.bare(&i.bare)?;
    for (k, v) in i.params.iter() {
        w.param(k, &v)?;
    }
    Ok(())
}

fn member(w: &mut Writer<'_, SliceSink<'_>>, m: Member<'_>) -> Result<(), WriteError> {
    match m {
        Member::Item(i) => item(w, i),
        Member::InnerList(l) => {
            w.open_inner_list()?;
            for i in l.iter() {
                item(w, i)?;
            }
            w.close_inner_list()?;
            for (k, v) in l.params().iter() {
                w.param(k, &v)?;
            }
            Ok(())
        }
    }
}

fn list_text<'b>(v: &[u8], buf: &'b mut [u8]) -> Option<&'b [u8]> {
    let l = sfv::parse_list(v).ok()?;
    if l.is_empty() {
        return None;
    }
    let mut out = SliceSink::new(buf);
    let mut w = Writer::list(&mut out);
    for m in l.iter() {
        member(&mut w, m).expect("a parsed member writes");
    }
    w.finish().expect("a non-empty list finishes");
    let n = out.len();
    Some(&buf[..n])
}

fuzz_target!(|data: &[u8]| {
    let mut a = [0u8; 65536];
    let mut b = [0u8; 65536];
    common::no_alloc(|| {
        if let Some(first) = list_text(data, &mut a) {
            let members = sfv::parse_list(first).expect("canonical text parses").len();
            assert_eq!(members, sfv::parse_list(data).map(|l| l.len()).unwrap_or(0));
            let second = list_text(first, &mut b).expect("canonical text serializes");
            assert_eq!(first, second);
        }
        if let Ok(i) = sfv::parse_item(data) {
            let mut out = SliceSink::new(&mut a);
            let mut w = Writer::item(&mut out);
            item(&mut w, i).expect("a parsed item writes");
            w.finish().expect("finishes");
            let n = out.len();
            assert!(sfv::parse_item(&a[..n]).is_ok());
        }
        if let Ok(d) = sfv::parse_dictionary(data) {
            if !d.is_empty() {
                let mut out = SliceSink::new(&mut a);
                let mut w = Writer::dictionary(&mut out);
                for (k, m) in d.iter() {
                    w.key(k).expect("key");
                    member(&mut w, m).expect("a parsed member writes");
                }
                w.finish().expect("finishes");
                let n = out.len();
                let back = sfv::parse_dictionary(&a[..n]).expect("written dictionary parses");
                assert_eq!(back.len(), d.len());
            }
        }
    });
});
