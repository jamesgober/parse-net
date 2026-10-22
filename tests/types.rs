//! Compile-time and size checks on the public types (NFR-11, NFR-15).

use parse_net::{
    self as pn, Boundary, Civil, Comment, CountSink, DateFormat, DuplicatePolicy, ErrorKind, Host,
    HostPort, HttpDate, Limits, List, MediaType, Param, Params, ParseError, Quoted, Word,
    WriteError,
    class::Class,
    list::{CombinedList, Elements},
    pct::{EncodeSet, HexCase},
};

fn assert_traits<T: Send + Sync + Unpin>() {}
fn assert_copy<T: Copy>() {}

#[test]
fn test_public_types_are_send_sync_unpin() {
    assert_traits::<ParseError>();
    assert_traits::<ErrorKind>();
    assert_traits::<WriteError>();
    assert_traits::<Limits>();
    assert_traits::<DuplicatePolicy>();
    assert_traits::<Class>();
    assert_traits::<Quoted<'static>>();
    assert_traits::<Word<'static>>();
    assert_traits::<Comment<'static>>();
    assert_traits::<List<'static>>();
    assert_traits::<Elements<'static>>();
    assert_traits::<CombinedList<'static, core::slice::Iter<'static, &'static [u8]>>>();
    assert_traits::<Params<'static>>();
    assert_traits::<Param<'static>>();
    assert_traits::<MediaType<'static>>();
    assert_traits::<Boundary<'static>>();
    assert_traits::<HttpDate>();
    assert_traits::<Civil>();
    assert_traits::<DateFormat>();
    assert_traits::<Host<'static>>();
    assert_traits::<HostPort<'static>>();
    assert_traits::<EncodeSet>();
    assert_traits::<HexCase>();
    assert_traits::<CountSink>();
    assert_traits::<pn::SliceSink<'static>>();
}

#[test]
fn test_views_are_copy() {
    assert_copy::<Quoted<'static>>();
    assert_copy::<Word<'static>>();
    assert_copy::<Comment<'static>>();
    assert_copy::<List<'static>>();
    assert_copy::<Params<'static>>();
    assert_copy::<Param<'static>>();
    assert_copy::<MediaType<'static>>();
    assert_copy::<Boundary<'static>>();
    assert_copy::<HttpDate>();
    assert_copy::<Host<'static>>();
    assert_copy::<HostPort<'static>>();
    assert_copy::<ParseError>();
}

#[cfg(target_pointer_width = "64")]
#[test]
fn test_view_sizes() {
    use core::mem::size_of;
    assert_eq!(size_of::<ParseError>(), 8);
    assert_eq!(size_of::<Quoted<'static>>(), 24);
    assert_eq!(size_of::<Word<'static>>(), 24);
    assert_eq!(size_of::<Params<'static>>(), 24);
    assert_eq!(size_of::<List<'static>>(), 24);
    assert_eq!(size_of::<MediaType<'static>>(), 56);
    assert_eq!(size_of::<HttpDate>(), 8);
}
