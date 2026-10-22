//! Counting-allocator tests: no parse, compare, or write into a `SliceSink`
//! allocates (NFR-1).
//!
//! The allocator counts allocations made by this thread only, so the test
//! harness running other tests in parallel cannot disturb the count.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use parse_net::{
    self as pn, HttpDate, Limits, SliceSink, class::Class, list, media, param, pct, scan, text,
    write,
};

struct Counting;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call is forwarded unchanged to the system allocator, which
// upholds the `GlobalAlloc` contract; the only addition is a thread-local
// counter increment, which does not allocate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
        // SAFETY: the caller's layout is passed through as received.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` was allocated by `System` with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
        // SAFETY: forwarded unchanged; `ptr` came from `System`.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn allocations(f: impl FnOnce()) -> usize {
    let before = ALLOCATIONS.with(Cell::get);
    f();
    ALLOCATIONS.with(Cell::get) - before
}

/// Inputs covering every parser's accept and refuse paths.
const INPUTS: &[&[u8]] = &[
    b"",
    b"text/html; charset=utf-8",
    b"Multipart/Form-Data; boundary=\"----x y\"",
    b"a, \"b,c\" , , (d, (e)) f;g=\"h\\\"i\",",
    b"gzip;q=0.5, br",
    b"Sun, 06 Nov 1994 08:49:37 GMT",
    b"Sunday, 06-Nov-94 08:49:37 GMT",
    b"Sun Nov  6 08:49:37 1994",
    b"[2001:db8::1]:8443",
    b"example.com:80",
    b"127.1",
    b"caf%C3%A9%20%e2%82%ac",
    b"\"unterminated",
    b"bad\r\nvalue",
    b";a=1;A=2",
    b"(((((((((deep)))))))))",
];

#[test]
fn test_parsing_never_allocates() {
    let mut out = [0u8; 256];
    let n = allocations(|| {
        for &v in INPUTS {
            let _ = scan::check_field_value(v);
            let _ = scan::find_byte(b',', v);
            let _ = scan::find_either(b',', b'"', v);
            let _ = scan::first_not_in(v, Class::TCHAR);
            let _ = text::trim_ows(v);
            let _ = text::parse_token(v);
            let _ = text::parse_word(v).map(|(w, _)| w.eq_ignore_ascii_case(b"x"));
            if let Ok((q, _)) = text::parse_quoted(v) {
                let _ = q.unescape_into(&mut out);
                let _ = q.eq_bytes(b"x");
            }
            let _ = text::parse_comment(v, &Limits::DEFAULT);
            if let Ok(l) = pn::list(v) {
                for e in l.iter() {
                    let _ = e.len();
                }
            }
            let lines = [v, v];
            if let Ok(c) = list::combined(lines, &Limits::DEFAULT) {
                for e in c.iter() {
                    let _ = e.len();
                }
            }
            let _ = list::contains_token([v], b"upgrade");
            if let Ok((p, _)) = param::parse(v, &Limits::DEFAULT) {
                let _ = p.get("a");
                for x in p.iter() {
                    let _ = x.value.len();
                }
            }
            if let Ok(m) = pn::parse_media_type(v) {
                let _ = m.boundary();
                let _ = m.charset();
                let _ = m.is_json();
            }
            let _ = HttpDate::parse_at(v, 1_792_540_800).map(HttpDate::format);
            let _ = HttpDate::parse_imf_fixdate(v).map(HttpDate::civil);
            let _ = pn::parse_host_port(v);
            let _ = pct::decode_utf8_into(v, &mut out);
            let _ = pct::decode_lower_only_into(v, &mut out);
            let _ = pct::validate_with(v, Class::URI_TARGET);
            let _ = pn::num::parse_u64(v);
        }
    });
    assert_eq!(n, 0, "a parse allocated");
}

#[test]
fn test_writing_into_slice_sink_never_allocates() {
    let mut buf = [0u8; 1024];
    let n = allocations(|| {
        let mut out = SliceSink::new(&mut buf);
        let _ = write::write_token(b"gzip", &mut out);
        let _ = write::write_quoted(b"a \"b\"", &mut out);
        let _ = write::write_word(b"x y", &mut out);
        let _ = write::write_param(b"charset", b"utf-8", &mut out);
        let _ = write::write_field_value(b"text/html", &mut out);
        let _ = write::write_field_value(b"bad\r\n", &mut out);
        let _ = write::write_decimal_u64(u64::MAX, &mut out);
        let _ = write::write_hex_u64(u64::MAX, &mut out);
        let _ = media::write("text", "plain", &[("charset", "utf-8")], &mut out);
        if let Ok(m) = pn::parse_media_type(b"Text/HTML;Charset=UTF-8") {
            let _ = m.write_canonical(&mut out);
        }
        let _ = HttpDate::MAX.write_to(&mut out);
        if let Ok(hp) = pn::parse_host_port(b"[::1]:80") {
            let _ = hp.write_to(&mut out);
        }
        let _ = pct::encode(
            b"a b",
            &pct::EncodeSet::ATTR_CHAR_COMPLEMENT,
            pct::HexCase::Upper,
            &mut out,
        );
    });
    assert_eq!(n, 0, "a write allocated");
}

#[test]
fn test_counter_sees_allocations() {
    // Proves the counter works, so a zero above means something.
    let n = allocations(|| drop(std::hint::black_box(vec![1u8; 16])));
    assert!(n >= 1);
}
