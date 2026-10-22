#![no_main]
//! Differential oracle (dev/PLAN.md section 15): parse-net and the `sfv`
//! crate on the same input, as an Item, a List, and a Dictionary. Both must
//! accept or both refuse, except where parse-net refuses by a recorded
//! choice (tests/differential/verdicts.md): a Date outside years 1 to 9999,
//! partial or extra base64 padding, and the configured limits. Where both
//! accept, the member counts must agree.

use libfuzzer_sys::fuzz_target;
use parse_net::{ErrorKind, ParseError, sfv as ours};

/// The refusals parse-net makes on purpose that `sfv` does not.
fn recorded(e: &ParseError) -> bool {
    matches!(
        e.kind(),
        ErrorKind::OutOfRange | ErrorKind::InvalidBase64 | ErrorKind::TooLong | ErrorKind::TooManyMembers
    )
}

fn agree<T, U>(what: &str, data: &[u8], a: &Result<T, ParseError>, b: &Result<U, sfv::Error>) {
    match (a, b) {
        (Ok(_), Err(e)) => panic!("{what}: parse-net accepts, sfv refuses ({e}): {data:?}"),
        (Err(e), Ok(_)) if !recorded(e) => {
            panic!("{what}: parse-net refuses ({e}), sfv accepts: {data:?}")
        }
        _ => {}
    }
}

fuzz_target!(|data: &[u8]| {
    let item = ours::parse_item(data);
    let theirs = sfv::Parser::new(data).parse::<sfv::Item>();
    agree("item", data, &item, &theirs);
    if let (Ok(a), Ok(b)) = (&item, &theirs) {
        assert_eq!(a.params.iter().map(|(k, _)| k).collect::<std::collections::BTreeSet<_>>().len(), b.params.len());
    }

    let list = ours::parse_list(data);
    let theirs = sfv::Parser::new(data).parse::<sfv::List>();
    agree("list", data, &list, &theirs);
    if let (Ok(a), Ok(b)) = (&list, &theirs) {
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b) {
            match (x, y) {
                (ours::Member::Item(_), sfv::ListEntry::Item(_)) => {}
                (ours::Member::InnerList(l), sfv::ListEntry::InnerList(m)) => {
                    assert_eq!(l.len(), m.items.len())
                }
                _ => panic!("member kinds differ: {data:?}"),
            }
        }
    }

    let dict = ours::parse_dictionary(data);
    let theirs = sfv::Parser::new(data).parse::<sfv::Dictionary>();
    agree("dictionary", data, &dict, &theirs);
    if let (Ok(a), Ok(b)) = (&dict, &theirs) {
        let keys: std::collections::BTreeSet<&str> = a.iter().map(|(k, _)| k).collect();
        assert_eq!(keys.len(), b.len());
        for k in keys {
            assert!(b.contains_key(k), "key {k} missing in sfv: {data:?}");
        }
    }
});
