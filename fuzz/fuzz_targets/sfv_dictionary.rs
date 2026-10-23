#![no_main]
//! Structured Field Dictionaries: no panic, no allocation; every view
//! decodes, lookups find the last value, `index_into` holds one slot per
//! distinct key, and the visitor agrees with the view.

use libfuzzer_sys::fuzz_target;
use parse_net::{
    ParseError,
    sfv::{self, BareItem, Decimal, Item, Member, Parser, SfParams, Visitor},
};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fn walk_bare(b: BareItem<'_>, buf: &mut [u8]) {
    match b {
        BareItem::String(s) => {
            let u = s.unescape_into(buf).expect("room");
            assert!(s.eq_str(u));
            assert_eq!(u.len(), s.unescaped_len());
        }
        BareItem::DisplayString(d) => {
            let t = d.decode_into(buf).expect("validated at parse");
            assert_eq!(t.len(), d.decoded_len());
        }
        BareItem::ByteSeq(b) => assert!(b.decoded_len() <= b.raw().len()),
        BareItem::Decimal(d) => assert!(Decimal::from_thousandths(d.thousandths()).is_ok()),
        _ => {}
    }
}

fn walk_item(i: Item<'_>, buf: &mut [u8]) {
    walk_bare(i.bare, buf);
    walk_params(i.params, buf);
}

fn walk_params(p: SfParams<'_>, buf: &mut [u8]) {
    assert_eq!(p.iter().count(), p.len());
    for (k, v) in p.iter() {
        walk_bare(v, buf);
        assert!(p.get(k).is_some());
    }
}

fn walk_member(m: Member<'_>, buf: &mut [u8]) {
    match m {
        Member::Item(i) => walk_item(i, buf),
        Member::InnerList(l) => {
            assert_eq!(l.iter().count(), l.len());
            for i in l.iter() {
                walk_item(i, buf);
            }
            walk_params(l.params(), buf);
        }
    }
}

/// Counts items and parameters, to compare a visit with a view walk.
#[derive(Default, PartialEq, Debug)]
struct Count(usize, usize);

impl<'a> Visitor<'a> for Count {
    fn item(&mut self, _: BareItem<'a>) -> Result<(), ParseError> {
        self.0 += 1;
        Ok(())
    }
    fn param(&mut self, _: &'a str, _: BareItem<'a>) -> Result<(), ParseError> {
        self.1 += 1;
        Ok(())
    }
}

fn count_member(m: Member<'_>, c: &mut Count) {
    match m {
        Member::Item(i) => {
            c.0 += 1;
            c.1 += i.params.len();
        }
        Member::InnerList(l) => {
            for i in l.iter() {
                c.0 += 1;
                c.1 += i.params.len();
            }
            c.1 += l.params().len();
        }
    }
}

/// Splits on `\n` into at most 8 lines.
fn lines(data: &[u8]) -> ([&[u8]; 8], usize) {
    let mut out: [&[u8]; 8] = [&[]; 8];
    let mut n = 0;
    for l in data.splitn(8, |&b| b == b'\n') {
        out[n] = l;
        n += 1;
    }
    (out, n)
}

fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; 4096];
    let mut slots = [("", Member::Item(Item::new(BareItem::Boolean(false)))); 1024];
    common::no_alloc(|| {
        let mut visited = Count::default();
        let v = Parser::default().visit_dictionary(data, &mut visited);
        match sfv::parse_dictionary(data) {
            Ok(d) => {
                assert!(v.is_ok());
                assert_eq!(d.iter().count(), d.len());
                let mut seen = Count::default();
                for (n, (k, m)) in d.iter().enumerate() {
                    walk_member(m, &mut buf);
                    count_member(m, &mut seen);
                    // The reference scan walks the whole dictionary, so it
                    // runs for the first keys only: on every key it made the
                    // harness quadratic (1.5 s for 1019 members, a timeout in
                    // the 0.7 run). `index_into` below checks every key.
                    if n < 32 {
                        let last = d.iter().filter(|(x, _)| *x == k).last().map(|(_, m)| m);
                        assert_eq!(d.get(k), last);
                    }
                }
                assert_eq!(visited, seen);
                let index = d.index_into(&mut slots).expect("1024 slots");
                assert!(index.len() <= d.len());
                for (k, m) in index {
                    assert_eq!(d.get(k), Some(*m));
                }
            }
            Err(e) => {
                assert_eq!(v, Err(e));
                common::check_error(&e);
            }
        }
        let (ls, n) = lines(data);
        let _ = sfv::parse_dictionary_lines(&ls[..n]);
    });
});
