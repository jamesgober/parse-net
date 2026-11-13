#![no_main]
//! `X-Forwarded-*`: no panic, no allocation; the chain counts what it
//! iterates, resolution through an untrusted peer ignores the header, and
//! no text left of the address a trusted proxy appended changes the answer.

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
    let lines: [&[u8]; 1] = [data];
    let peer: IpAddr = IpAddr::from([10, 0, 0, 1]);
    common::no_alloc(|| {
        match forwarded::parse_x_forwarded_for(&lines, &Limits::DEFAULT) {
            Ok(c) => assert_eq!(c.iter().count(), c.len()),
            Err(e) => common::check_error(&e),
        }
        let _ = forwarded::parse_x_forwarded_proto(data);
        let _ = forwarded::parse_x_forwarded_host(data);
        let none = |_: IpAddr| false;
        assert_eq!(
            client_address(peer, ForwardedSource::XForwardedFor(&lines), &none),
            ClientAddress::Peer(peer)
        );
        let all = |_: IpAddr| true;
        let eight = Limits::DEFAULT.max_hops(8);
        match client_address_with_limits(peer, ForwardedSource::XForwardedFor(&lines), &all, &eight)
        {
            ClientAddress::Forwarded { hops, .. } => assert!((1..=8).contains(&hops)),
            ClientAddress::Unknown { hops } => assert!((1..=8).contains(&hops)),
            _ => {}
        }
        let appended: [&[u8]; 2] = [data, b"198.51.100.7"];
        let only_peer = |a: IpAddr| a == peer;
        assert_eq!(
            client_address(peer, ForwardedSource::XForwardedFor(&appended), &only_peer),
            ClientAddress::Forwarded {
                addr: IpAddr::from([198, 51, 100, 7]),
                hops: 1
            }
        );
    });
});
