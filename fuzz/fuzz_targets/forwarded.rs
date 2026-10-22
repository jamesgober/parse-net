#![no_main]
//! `Forwarded`: no panic, no allocation; the element list counts what it
//! iterates, and resolution never reports more hops than allowed.

use libfuzzer_sys::fuzz_target;
use core::net::IpAddr;
use parse_net::{ClientAddress, ForwardedSource, Limits, client_address, forwarded};

#[path = "common.rs"]
mod common;

#[global_allocator]
static GLOBAL: common::Counting = common::Counting;

fuzz_target!(|data: &[u8]| {
    let lines: [&[u8]; 2] = [data, b"for=192.0.2.60"];
    let peer: IpAddr = IpAddr::from([10, 0, 0, 1]);
    common::no_alloc(|| {
        match forwarded::parse(&lines[..1], &Limits::DEFAULT) {
            Ok(f) => assert_eq!(f.iter().count(), f.len()),
            Err(e) => common::check_error(&e),
        }
        for max in [0u8, 1, 3, 255] {
            let all = |_: IpAddr| true;
            let private = |a: IpAddr| match a {
                IpAddr::V4(v) => v.is_private(),
                IpAddr::V6(_) => false,
            };
            for r in [
                client_address(peer, ForwardedSource::Forwarded(&lines), &all, max),
                client_address(peer, ForwardedSource::Forwarded(&lines), &private, max),
            ] {
                match r {
                    Ok(ClientAddress::Forwarded { hops, .. } | ClientAddress::Unknown { hops }) => {
                        assert!(hops >= 1 && hops <= max)
                    }
                    Ok(_) => {}
                    Err(e) => common::check_error(&e),
                }
            }
        }
    });
});
