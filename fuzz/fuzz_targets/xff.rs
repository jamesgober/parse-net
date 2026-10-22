#![no_main]
//! `X-Forwarded-*`: no panic, no allocation; the chain counts what it
//! iterates, and resolution through an untrusted peer ignores the header.

use libfuzzer_sys::fuzz_target;
use core::net::IpAddr;
use parse_net::{ClientAddress, ForwardedSource, Limits, client_address, forwarded};

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
            client_address(peer, ForwardedSource::XForwardedFor(&lines), &none, 16),
            Ok(ClientAddress::Peer(peer))
        );
        let all = |_: IpAddr| true;
        if let Ok(ClientAddress::Forwarded { hops, .. } | ClientAddress::Unknown { hops }) =
            client_address(peer, ForwardedSource::XForwardedFor(&lines), &all, 8)
        {
            assert!(hops >= 1 && hops <= 8);
        }
    });
});
