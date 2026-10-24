# Platform notes

Where parse-net builds and runs, what each feature adds, and what it asks of
a target. The short version: any target with `core`, on Rust 1.85 or later.

## Toolchain

- **MSRV:** Rust 1.85, edition 2024. CI builds, lints, and tests on 1.85 and
  on stable; raising the MSRV is a minor-version change, noted in the
  CHANGELOG.
- **No build script, no proc macros, no `unsafe`** (`#![forbid(unsafe_code)]`).
  The library code also denies `unwrap`, `expect`, `panic!`, `unreachable!`,
  and slice indexing (clippy), so a parse returns an error rather than
  panicking on any input; the fuzz targets check that.

## Features

| Feature | Default | Adds | Needs |
|---|---|---|---|
| (none) | yes | every parser, validator, and writer into a `Sink` (`SliceSink`, `CountSink`) | `core` only |
| `alloc` | no | owned forms (`OwnedMediaType`, `OwnedEntityTag`, `OwnedHostPort`, Structured Field owned values), `Sink for Vec<u8>`, functions returning `String` | an allocator |
| `std` | no | `HttpDate` to and from `SystemTime`, and `http_date`, which reads the system clock for the RFC 850 two-digit year rule; implies `alloc` | `std` |
| `encode-lib` | no | declared and empty until encode-lib is published; then base64 decoding of `Basic` credentials and Structured Field byte sequences (D-002) | encode-lib |

The default build has no dependencies at all; CI checks that `cargo tree`
for it lists parse-net alone. No feature changes what a parser accepts:
features add owned forms and conveniences, never a different grammar.

## `no_std` and bare metal

parse-net is `#![no_std]`. CI builds it for `thumbv7em-none-eabi` (Cortex-M4
and M7, no operating system, no `std`) with no features and with `alloc`,
and runs clippy there, on 1.85 and on stable. That target has no `std` to
link, so the build fails if anything reaches for it.

Nothing in the crate needs:

- **an allocator** (without `alloc`): every parse returns a view over the
  input; every writer writes into a caller's `Sink`;
- **a clock**: functions that need the current time take it as an argument
  (`HttpDate::parse_at(value, now)`); only the `std` convenience reads the
  system clock;
- **floating point**: q-values are integer thousandths (`QValue`), Structured
  Field decimals are fixed point (`Decimal`);
- **atomics, threads, or I/O**: there is no global state; every view is
  `Copy`, `Send`, and `Sync`.

## Stack

No function recurses (nested comments are counted, not followed), so stack
use is fixed per call. The largest frames hold small tables on the stack in
place of an allocation:

| Where | Holds | Size on 64-bit (32-bit) |
|---|---|---|
| `best_media` and `Negotiator::media_lines` | 32 parsed offers per group | about 1.8 KiB (1 KiB) |
| RFC 2231 continuation reassembly | 32 section slots | about 1 KiB (512 bytes) |
| repeated-name check (`param`, `auth`, MIME parameters) | 64 name offsets (D-072) | 512 bytes (256 bytes) |
| `encode_words` | one encoded word | 63 bytes |

Two chains hold two of these at once: `best_media` parses each member with
the parameter walker (the offer group and a name table, about 2.3 KiB on
64-bit), and `parse_mime_params` reassembles RFC 2231 sections while its
name table is live (about 1.5 KiB). No other chain holds more than one.

## Pointer width and byte order

Offsets and lengths are `usize`; input lengths and counts never exceed it.
The crate is tested on 64-bit hosts (Linux, macOS, Windows) and built for
32-bit Arm. Nothing depends on byte order: the SWAR scanners read bytes
into words with `from_le_bytes` and compare lanes, so the result is the same
on either order. 16-bit targets are not tested.

## Operating systems

CI runs the full test suite on Linux (Ubuntu), macOS, and Windows, on 1.85
and on stable. parse-net does no I/O and has no platform-specific code; the
`std` feature uses only `std::time::SystemTime`.
