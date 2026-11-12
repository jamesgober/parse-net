#![no_main]
//! `Forwarded`: no panic, no allocation; the element list counts what it
//! iterates, resolution never reports more hops than allowed, and no text
//! left of the element a trusted proxy appended changes the answer.

use core::net::IpAddr;
use libfuzzer_sys::fuzz_target;
use parse_net::{
    ClientAddress, ForwardedSource, Limits, client_address, forwarded,
    forwarded::client_address_with_limits,
};

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
            let limits = Limits::DEFAULT.max_hops(max);
            for r in [
                client_address_with_limits(peer, ForwardedSource::Forwarded(&lines), &all, &limits),
                client_address_with_limits(
                    peer,
                    ForwardedSource::Forwarded(&lines),
                    &private,
                    &limits,
                ),
            ] {
                match r {
                    ClientAddress::Forwarded { hops, .. } => assert!(hops >= 1 && hops <= max),
                    ClientAddress::Unknown { hops } => assert!(hops <= max),
                    _ => {}
                }
            }
        }
        let only_peer = |a: IpAddr| a == peer;
        assert_eq!(
            client_address(peer, ForwardedSource::Forwarded(&lines), &only_peer),
            ClientAddress::Forwarded {
                addr: IpAddr::from([192, 0, 2, 60]),
                hops: 1
            }
        );
    });
});
