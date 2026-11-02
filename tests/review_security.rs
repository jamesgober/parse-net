//! Regressions from the 0.9 security review of the HTTP-facing modules. Each
//! test sends an attack or an edge case that once got through, or pins a
//! behaviour the review checked and found sound.

use core::net::IpAddr;

use parse_net::{
    self as pn, ClientAddress, ErrorKind, ForwardedSource, Host, HostPort, Limits, Origin,
    SliceSink,
    auth::{self, AuthPayload},
    forwarded::{self, Element, Node},
    host::parse_host,
    link,
    pct::{self, EncodeSet, HexCase},
};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn has_crlf(b: &[u8]) -> bool {
    b.iter().any(|&c| c == b'\r' || c == b'\n' || c == 0)
}

// ---- writers ---------------------------------------------------------------

#[test]
fn w1_host_write_to_refuses_crlf() {
    let mut buf = [0u8; 64];
    let mut out = SliceSink::new(&mut buf);
    let r = Host::Name(b"a\r\nX-Evil: 1").write_to(&mut out);
    println!("{r:?} {:?}", String::from_utf8_lossy(out.written()));
    assert!(!has_crlf(out.written()), "writer emitted CR/LF");
}

#[test]
fn w2_host_future_write_to_refuses_nul() {
    let mut buf = [0u8; 64];
    let mut out = SliceSink::new(&mut buf);
    let r = Host::Future(b"v1.\0\r\n").write_to(&mut out);
    println!("{r:?} {:?}", String::from_utf8_lossy(out.written()));
    assert!(!has_crlf(out.written()), "writer emitted NUL/CR/LF");
}

#[test]
fn w3_hostport_write_to_refuses_crlf() {
    let mut buf = [0u8; 64];
    let mut out = SliceSink::new(&mut buf);
    let hp = HostPort {
        host: Host::Name(b"a\r\nb"),
        port: Some(80),
        empty_port: false,
    };
    let r = hp.write_to(&mut out);
    println!("{r:?} {:?}", String::from_utf8_lossy(out.written()));
    assert!(!has_crlf(out.written()), "writer emitted CR/LF");
}

#[test]
fn w4_origin_write_to_refuses_crlf() {
    let mut buf = [0u8; 64];
    let mut out = SliceSink::new(&mut buf);
    let o = Origin {
        scheme: b"http\r\nX-Evil: 1\r\n",
        host: Host::Name(b"a"),
        port: None,
    };
    let r = o.write_to(&mut out);
    println!("{r:?} {:?}", String::from_utf8_lossy(out.written()));
    assert!(!has_crlf(out.written()), "writer emitted CR/LF");
}

#[test]
fn w5_write_element_refuses_crlf() {
    let mut buf = [0u8; 96];
    let mut out = SliceSink::new(&mut buf);
    let e = Element {
        for_: None,
        by: None,
        host: Some(HostPort {
            host: Host::Name(b"a\r\nX-Evil: 1"),
            port: None,
            empty_port: false,
        }),
        proto: None,
    };
    let r = forwarded::write_element(&e, &mut out);
    println!("{r:?} {:?}", String::from_utf8_lossy(out.written()));
    assert!(!has_crlf(out.written()), "writer emitted CR/LF");
}

/// From the wire: a `Host` value the parser accepts forges a Forwarded element.
#[test]
fn w6_write_element_host_comma_forges_hop() {
    let peer = ip("10.0.0.1");
    let client = ip("198.51.100.7");
    let attacker_host: &[u8] = b"a.example,for=203.0.113.66;x=y";
    let hp = pn::parse_host_port(attacker_host).expect("the Host parser accepts it");
    let e = Element {
        for_: Some(Node::Addr(client, None)),
        by: None,
        host: Some(hp),
        proto: None,
    };
    let mut buf = [0u8; 128];
    let mut out = SliceSink::new(&mut buf);
    forwarded::write_element(&e, &mut out).unwrap();
    let wire = out.written().to_vec();
    println!("wire: {}", String::from_utf8_lossy(&wire));
    let lines: [&[u8]; 1] = [&wire];
    let got = pn::client_address(
        peer,
        ForwardedSource::Forwarded(&lines),
        &|a: IpAddr| a == peer,
        16,
    );
    println!("client_address: {got:?}");
    assert_eq!(
        got,
        Ok(ClientAddress::Forwarded {
            addr: client,
            hops: 1
        })
    );
}

#[test]
fn w7_write_element_host_semicolon_forges_proto() {
    let hp = pn::parse_host_port(b"a.example;proto=https").unwrap();
    let e = Element {
        for_: None,
        by: None,
        host: Some(hp),
        proto: None,
    };
    let mut buf = [0u8; 64];
    let mut out = SliceSink::new(&mut buf);
    forwarded::write_element(&e, &mut out).unwrap();
    let wire = out.written().to_vec();
    println!("wire: {}", String::from_utf8_lossy(&wire));
    let lines: [&[u8]; 1] = [&wire];
    let back = forwarded::parse(&lines, &Limits::DEFAULT);
    println!("{:?}", back.map(|b| b.iter().next()));
    let back = forwarded::parse(&lines, &Limits::DEFAULT)
        .unwrap()
        .iter()
        .next()
        .unwrap();
    assert_eq!(back, e, "round trip");
}

#[test]
fn w8_write_element_paren_host_parses_back() {
    let hp = pn::parse_host_port(b"a(b").unwrap();
    let e = Element {
        for_: None,
        by: None,
        host: Some(hp),
        proto: None,
    };
    let mut buf = [0u8; 64];
    let mut out = SliceSink::new(&mut buf);
    forwarded::write_element(&e, &mut out).unwrap();
    let wire = out.written().to_vec();
    let lines: [&[u8]; 1] = [&wire];
    let r = forwarded::parse(&lines, &Limits::DEFAULT);
    println!(
        "{:?} -> {:?}",
        String::from_utf8_lossy(&wire),
        r.as_ref().map(|x| x.len())
    );
    assert!(r.is_ok());
}

#[test]
fn w9_write_element_empty_host_parses_back() {
    let hp = pn::parse_host_port(b"").unwrap();
    let e = Element {
        for_: None,
        by: None,
        host: Some(hp),
        proto: None,
    };
    let mut buf = [0u8; 64];
    let mut out = SliceSink::new(&mut buf);
    forwarded::write_element(&e, &mut out).unwrap();
    let wire = out.written().to_vec();
    let lines: [&[u8]; 1] = [&wire];
    let r = forwarded::parse(&lines, &Limits::DEFAULT);
    println!(
        "{:?} -> {:?}",
        String::from_utf8_lossy(&wire),
        r.as_ref().map(|x| x.len())
    );
    assert!(r.is_ok());
}

#[test]
fn w10_write_link_title_star_parses_back() {
    let mut buf = [0u8; 64];
    let mut out = SliceSink::new(&mut buf);
    // What the parser would refuse is not written.
    assert!(link::write_link(b"/a", &[("title*", "hello")], &mut out).is_err());
    assert!(out.written().is_empty());
    link::write_link(b"/a", &[("title*", "UTF-8''hello")], &mut out).unwrap();
    assert!(pn::parse_link(out.written(), &Limits::DEFAULT).is_ok());
    // An empty value writes the name alone, which parses (found by fuzzing
    // the first version of this check).
    let mut buf = [0u8; 64];
    let mut out = SliceSink::new(&mut buf);
    link::write_link(b"/a", &[("title*", "")], &mut out).unwrap();
    assert!(pn::parse_link(out.written(), &Limits::DEFAULT).is_ok());
}

#[test]
fn w11_write_link_title_star_control_refused() {
    let mut buf = [0u8; 64];
    let mut out = SliceSink::new(&mut buf);
    let r = link::write_link(b"/a", &[("title*", "UTF-8''a%0D%0AX")], &mut out);
    println!("{r:?} {:?}", String::from_utf8_lossy(out.written()));
    assert!(r.is_err() || pn::parse_link(out.written(), &Limits::DEFAULT).is_ok());
}

#[test]
fn w12_pct_encode_never_emits_crlf() {
    let mut buf = [0u8; 16];
    let mut out = SliceSink::new(&mut buf);
    pct::encode(b"a\r\nb", &EncodeSet::empty(), HexCase::Upper, &mut out).unwrap();
    println!("{:?}", String::from_utf8_lossy(out.written()));
    assert!(!has_crlf(out.written()));
}

#[test]
fn w13_write_challenge_65_params_parses_back() {
    let names: Vec<String> = (0..65).map(|i| format!("p{i}")).collect();
    let params: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "v")).collect();
    let mut buf = [0u8; 1024];
    let mut out = SliceSink::new(&mut buf);
    // The parser reads 64 (D-072), so the writer stops there too.
    assert_eq!(
        auth::write_challenge("Basic", &params, &mut out),
        Err(pn::WriteError::OutOfRange)
    );
    auth::write_challenge("Basic", &params[..64], &mut out).unwrap();
    assert!(auth::parse_challenges(out.written(), &Limits::DEFAULT).is_ok());
}

// ---- forwarded -------------------------------------------------------------

#[test]
fn f1_unknown_is_case_insensitive() {
    // RFC 7239 section 6 ABNF literal "unknown"; RFC 5234 section 2.3.
    for v in [&b"for=UNKNOWN"[..], b"for=Unknown", b"for=\"UNKNOWN:80\""] {
        let lines = [v];
        let r = forwarded::parse(&lines, &Limits::DEFAULT);
        println!(
            "{:?} -> {:?}",
            String::from_utf8_lossy(v),
            r.as_ref().map(|_| ())
        );
        assert!(r.is_ok());
    }
    let peer = ip("10.0.0.1");
    let lines: [&[u8]; 1] = [b"for=Unknown"];
    let got = pn::client_address(
        peer,
        ForwardedSource::Forwarded(&lines),
        &|a: IpAddr| a == peer,
        16,
    );
    println!("{got:?}");
    assert_eq!(got, Ok(ClientAddress::Unknown { hops: 1 }));
}

#[test]
fn f2_iter_agrees_with_len_under_custom_limits() {
    let l = Limits::DEFAULT.max_empty_elements(64);
    let a = format!("for=1.1.1.1{}", ",".repeat(20));
    let lines: [&[u8]; 2] = [a.as_bytes(), b"for=2.2.2.2"];
    let p = forwarded::parse(&lines, &l).unwrap();
    let seen: Vec<_> = p.iter().map(|e| e.for_).collect();
    println!("len {} iter {:?}", p.len(), seen);
    assert_eq!(p.len(), seen.len());
}

#[test]
fn f3_proto_any_uri_scheme() {
    // RFC 7239 section 5.4: any URI scheme name.
    let lines: [&[u8]; 1] = [b"for=192.0.2.60;proto=wss"];
    let r = forwarded::parse(&lines, &Limits::DEFAULT);
    println!("{:?}", r.as_ref().map(|x| x.len()));
    assert!(r.is_ok());
}

#[test]
fn f4_repeated_extension_param_refused() {
    // RFC 7239 section 4; GRAMMAR.md: "a repeat is refused".
    let lines: [&[u8]; 1] = [b"ext=1;ext=2"];
    let r = forwarded::parse(&lines, &Limits::DEFAULT);
    println!("{:?}", r.as_ref().map(|x| x.len()));
    assert!(r.is_err());
}

// ---- host ------------------------------------------------------------------

#[test]
fn h1_percent_encoded_number_refused() {
    // D-040 / T15: WHATWG percent-decodes before "ends in a number".
    for v in [
        &b"127.0.0.%31"[..],
        b"127%2e0%2e0%2e1",
        b"127%2e1",
        b"example.%31",
        b"0x7f.0.0.%31",
        b"%37%66.1%2e",
    ] {
        let r = pn::parse_host_port(v);
        println!("{:?} -> {:?}", String::from_utf8_lossy(v), r);
        assert!(r.is_err(), "{}", String::from_utf8_lossy(v));
    }
}

#[test]
fn h2_parse_host_port_error_offset() {
    let e = parse_host(b" a:80").unwrap_err();
    println!("{:?} at {}", e.kind(), e.offset());
    assert_eq!(e.offset(), 2, "the ':' is at offset 2");
}

// ---- origin ----------------------------------------------------------------

#[test]
fn o1_origin_percent_number_refused() {
    let r = pn::parse_origin(b"http://127.0.0.%31");
    println!("{r:?}");
    assert!(r.is_err());
}

// ---- auth ------------------------------------------------------------------

#[test]
fn a1_credentials_leading_empty_list_element() {
    // RFC 9110 5.6.1.2: a recipient MUST parse and ignore a reasonable number
    // of empty list elements; credentials use #auth-param.
    for v in [&b"Digest , a=b"[..], b"Digest ,a=b, c=d", b"Digest ,"] {
        let r = auth::parse_credentials(v, &Limits::DEFAULT);
        println!(
            "{:?} -> {:?}",
            String::from_utf8_lossy(v),
            r.as_ref().map(|c| c.payload())
        );
        assert!(r.is_ok());
    }
}

#[test]
fn a2_challenge_leading_empty_list_element() {
    let v: &[u8] = b"Digest , realm=x";
    let r = auth::parse_challenges(v, &Limits::DEFAULT);
    println!("{:?}", r.as_ref().map(|c| c.len()));
    assert!(r.is_ok());
}

#[test]
fn a3_params_get_under_custom_limits() {
    let l = Limits::DEFAULT.max_empty_elements(64);
    let v = format!("Digest a=1{}b=2", ",".repeat(20));
    let c = auth::parse_credentials(v.as_bytes(), &l).unwrap();
    let AuthPayload::Params(p) = c.payload() else {
        panic!()
    };
    println!(
        "len {} get(a) {:?} iter {}",
        p.len(),
        p.get("a"),
        p.iter().count()
    );
    assert!(p.get("a").is_some());
    assert_eq!(p.len(), p.iter().count());
}

#[test]
fn a4_challenge_params_under_custom_limits() {
    let l = Limits::DEFAULT.max_empty_elements(64);
    let v = format!("Digest a=1{}b=2", ",".repeat(20));
    let c = auth::parse_challenges(v.as_bytes(), &l).unwrap();
    let first = c.iter().next().unwrap();
    println!("param(a) {:?}", first.param("a"));
    assert!(first.param("a").is_some());
}

#[test]
fn a5_debug_redaction() {
    let c = auth::parse_credentials(b"Bearer s3cr3t", &Limits::DEFAULT).unwrap();
    let d = format!("{c:?} {:?}", c.payload());
    println!("{d}");
    assert!(!d.contains("s3cr3t"));
    // A bare key in the scheme position.
    let c = auth::parse_credentials(b"sk_live_s3cr3t", &Limits::DEFAULT).unwrap();
    let d = format!("{c:?}");
    println!("{d}");
    assert!(
        !d.contains("s3cr3t"),
        "a bare API key prints through the scheme"
    );
}

#[test]
fn a6_owned_media_debug_redacted() {
    // param.rs: "Debug prints the parameter names only: values can be secrets."
    let m = pn::parse_media_type(b"a/b; token=s3cr3t").unwrap();
    let view = format!("{m:?}");
    let owned = format!("{:?}", m.to_owned());
    println!("{view}\n{owned}");
    let needle: Vec<String> = b"s3cr3t".iter().map(|b| b.to_string()).collect();
    assert!(
        !owned.contains(&needle.join(", ")),
        "the secret's bytes print in decimal"
    );
}

// ---- link ------------------------------------------------------------------

#[test]
fn l1_title_star_quoted_form_accepted() {
    // RFC 8288 section 3: any link-param token or quoted-string; recipients
    // MUST parse both. Appendix B.3 decodes after reading either form.
    let v: &[u8] = b"</a>; title*=\"UTF-8''x\"";
    let r = pn::parse_link(v, &Limits::DEFAULT);
    println!("{:?}", r.as_ref().map(|l| l.len()));
    assert!(r.is_ok());
    let l = pn::parse_link(v, &Limits::DEFAULT).unwrap();
    assert!(matches!(
        l.iter().next().unwrap().title(),
        Some(pn::Filename::Ext(_))
    ));
}

#[test]
fn l2_second_title_star_ignored() {
    // RFC 8288 3.4.1: occurrences after the first are ignored by parsers.
    let v: &[u8] = b"</a>; title*=UTF-8''ok; title*=bad";
    let r = pn::parse_link(v, &Limits::DEFAULT);
    println!("{:?}", r.as_ref().map(|l| l.len()));
    assert!(r.is_ok());
}

// ---- disproofs: these are expected to pass ----------------------------------

#[test]
fn ok_filename_star_quoted_offsets() {
    for (v, at) in [
        (&b"attachment; filename*=\"\""[..], 22usize),
        (b"attachment;filename*=\"\"", 21),
        (b"   attachment; filename*=\"UTF-8''a\"", 25),
        (b"\t a;filename*=\"x\"", 14),
    ] {
        let e = pn::parse_content_disposition(v).unwrap_err();
        assert_eq!(
            (e.kind(), e.offset()),
            (ErrorKind::InvalidCharset, at),
            "{v:?}"
        );
        assert_eq!(v[e.offset()], b'"');
    }
}

#[test]
fn ok_filename_star_bypass_attempts_refused() {
    for v in [
        &b"attachment; FILENAME*=UTF-8''%ZZ"[..],
        b"attachment; filename=a; FileName*=UTF-8''%C0%AF",
        b"attachment;;;filename*=UTF-8''%00",
        b"attachment; x=\"filename*=ok\"; filename*=UTF-8''%0a",
        b"attachment; x=\"a\\\"; filename*=UTF-8''ok; y=\\\"\"; filename*=bad",
        b"attachment; filename*=UTF-8''a; filename*=UTF-8''b",
        b"attachment; filename*=UTF-8''a; FILENAME*=UTF-8''b",
        b"attachment; filename*=UTF-8''a'b",
        b"attachment; filename*=UTF-8''%7F",
        b"attachment; filename*=UTF-8''%C2%80",
        b"attachment; filename*=UTF-8''%C2%9F",
        b"attachment; filename*=UTF-8''%09",
        b"attachment; filename*=ISO-8859-1''%80",
        b"attachment; filename*=ISO-8859-1''%9F",
        b"attachment; filename*=US-ASCII''%80",
        b"attachment; filename*=UTF-8''%ED%A0%80",
        b"attachment; filename*=UTF-8''%F4%90%80%80",
        b"attachment; filename*=UTF-8''%E2%82",
    ] {
        assert!(
            pn::parse_content_disposition(v).is_err(),
            "{}",
            String::from_utf8_lossy(v)
        );
    }
}

#[test]
fn ok_filename_star_in_quoted_neighbour_not_seen() {
    let v: &[u8] = b"attachment; x=\"; filename*=UTF-8''evil.exe\"; filename=good.txt";
    let cd = pn::parse_content_disposition(v).unwrap();
    assert!(cd.filename_ext().is_none());
    assert!(cd.filename_plain().unwrap().eq_bytes(b"good.txt"));
}

#[test]
fn ok_hops() {
    let peer = ip("10.0.0.1");
    let t = |a: IpAddr| a.is_loopback() || a == ip("10.0.0.1");
    let lines: [&[u8]; 2] = [b"9.9.9.9, 127.0.0.1", b"8.8.8.8:80, 127.0.0.2"];
    assert_eq!(
        pn::client_address(peer, ForwardedSource::XForwardedFor(&lines), &t, 16),
        Ok(ClientAddress::Forwarded {
            addr: ip("8.8.8.8"),
            hops: 2
        })
    );
    // 255 hops, none saturated.
    let chain = vec!["127.0.0.1"; 255].join(",");
    let l: [&[u8]; 1] = [chain.as_bytes()];
    assert_eq!(
        pn::client_address(peer, ForwardedSource::XForwardedFor(&l), &t, 255),
        Ok(ClientAddress::Forwarded {
            addr: ip("127.0.0.1"),
            hops: 255
        })
    );
    // Forwarded, 255 trusted elements: the default member limit is above 255.
    let chain = vec!["for=127.0.0.1"; 255].join(",");
    let l: [&[u8]; 1] = [chain.as_bytes()];
    assert_eq!(
        pn::client_address(peer, ForwardedSource::Forwarded(&l), &t, 255),
        Ok(ClientAddress::Forwarded {
            addr: ip("127.0.0.1"),
            hops: 255
        })
    );
    // Empty lines fail closed for XFF; Forwarded treats them as no elements.
    let e: [&[u8]; 2] = [b"1.1.1.1", b""];
    assert_eq!(
        pn::client_address(peer, ForwardedSource::XForwardedFor(&e), &t, 16)
            .unwrap_err()
            .kind(),
        ErrorKind::Malformed
    );
    let e: [&[u8]; 2] = [b"for=1.1.1.1", b""];
    assert_eq!(
        pn::client_address(peer, ForwardedSource::Forwarded(&e), &t, 16),
        Ok(ClientAddress::Forwarded {
            addr: ip("1.1.1.1"),
            hops: 1
        })
    );
    // max_hops 0 with a chain, and with no chain.
    let c: [&[u8]; 1] = [b"1.1.1.1"];
    assert_eq!(
        pn::client_address(peer, ForwardedSource::XForwardedFor(&c), &t, 0)
            .unwrap_err()
            .kind(),
        ErrorKind::TooManyHops
    );
    // Quoted comma in Forwarded must not split.
    let q: [&[u8]; 1] = [b"for=1.1.1.1;x=\"a,for=2.2.2.2\""];
    assert_eq!(
        pn::client_address(peer, ForwardedSource::Forwarded(&q), &t, 16),
        Ok(ClientAddress::Forwarded {
            addr: ip("1.1.1.1"),
            hops: 1
        })
    );
}

#[test]
fn ok_ipv4_prefix_edges() {
    let lim = Limits::DEFAULT;
    for bad in [
        &b"256.1.1.1"[..],
        b"1.1.1.256",
        b"1.1.1.1.",
        b"1.1.1.1.1",
        b"01.1.1.1",
        b"1.1.1.01",
        b"00.0.0.0",
        b"1.1.1.1000",
        b"1.1.1",
        b"1.1.1.",
        b".1.1.1",
        b"1..1.1",
        b"1.1.1.1:",
        b"1.1.1.1:65536",
        b"1.1.1.1:_x",
        b"1.1.1.1:80:80",
        b"1.1.1.1 :80",
        b"[1.1.1.1]",
        b"\xff.1.1.1",
        b"999.999.999.999",
        b"\xc2\xa01.1.1.1",
        b"[::1]x",
        b"[::1]:",
        b"[]",
        b"::ffff:1.1.1.1:80",
    ] {
        assert!(
            forwarded::parse_x_forwarded_for(&[bad], &lim).is_err(),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
    for good in [
        &b"0.0.0.0"[..],
        b"255.255.255.255",
        b"1.1.1.1:0",
        b"1.1.1.1:65535",
        b"::ffff:1.1.1.1",
    ] {
        assert!(forwarded::parse_x_forwarded_for(&[good], &lim).is_ok());
    }
}

#[test]
fn ok_host_origin_confusion() {
    for bad in [
        &b"a.com:80@b.com"[..],
        b"127.1",
        b"0x7f.1",
        b"1.2.3.4.",
        b"example.123",
        b"example.123.",
        b"example.0X7F",
        b"a\\b",
        b"a#b",
        b"a/b",
        b"a?b",
        b"[::1]@b",
        b"[::ffff:1.2.3.256]",
        b"a b",
        b"a\tb",
        b"1.2.3.4:80:80",
    ] {
        assert!(
            pn::parse_host_port(bad).is_err(),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
    for bad in [
        &b"NULL"[..],
        b"null x",
        b"https://a.com/",
        b"https://a.com#",
        b"https://a.com?",
        b"https://u@a.com",
        b"https://a.com:",
        b"https://",
        b"https:///a",
        b"https://:80",
        b"://a",
        b"1a://a",
        b"https//a",
        b"https://a.com, https://b.com",
        b"https://a.com https://b.com",
        b"https://a.com\\@b.com",
    ] {
        assert!(
            pn::parse_origin(bad).is_err(),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
}

#[test]
fn ok_bidi_and_separators() {
    let f = |v: &'static [u8]| {
        pn::parse_content_disposition(v)
            .unwrap()
            .filename()
            .unwrap()
    };
    assert!(f(b"attachment; filename=\"a\\\\b\"").has_path_separator());
    assert!(f(b"attachment; filename=\"a%5\\Cb\"").has_path_separator());
    assert!(f(b"attachment; filename=\"%%2f\"").has_path_separator());
    assert!(f(b"attachment; filename=\"a%zz%2f\"").has_path_separator());
    assert!(f(b"attachment; filename=\"%E2\\\x80%AE\"").has_bidi_control());
    assert!(
        f(b"attachment; filename*=UTF-8''%E2%E2%80%AE"
            .as_slice()
            .get(..0)
            .map_or(b"attachment; filename*=UTF-8''%E2%80%AE", |_| {
                b"attachment; filename*=UTF-8''%E2%80%AE"
            }))
        .has_bidi_control()
    );
}
