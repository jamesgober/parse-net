//! Shared by every fuzz target: a counting allocator, so a target can assert
//! that the code under test allocates nothing, and the error-text check.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

pub struct Counting;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call is forwarded unchanged to the system allocator; the only
// addition is a thread-local counter increment, which does not allocate.
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

/// Runs `f` and panics if it allocated.
pub fn no_alloc<T>(f: impl FnOnce() -> T) -> T {
    let before = ALLOCATIONS.with(Cell::get);
    let out = f();
    assert_eq!(
        ALLOCATIONS.with(Cell::get),
        before,
        "the code under test allocated"
    );
    out
}

/// An error's text is the fixed message plus an offset: never input bytes.
#[allow(dead_code)]
pub fn check_error(e: &parse_net::ParseError) {
    let text = e.to_string();
    assert!(text.starts_with(e.kind().message()));
    assert!(text.bytes().all(|b| b.is_ascii_graphic() || b == b' '));
}
