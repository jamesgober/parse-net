# Fuzzing

cargo-fuzz targets for every parser and decoder in parse-net. Targets are added with the parsers they cover, from `0.3.0` on; the list is in [`../dev/PLAN.md`](../dev/PLAN.md) section 11.4.

Each target asserts: no panic, no allocation, no error message that contains input bytes, and, where a writer exists, that what the writer produces parses back to the same value.

## Running

Requires nightly and `cargo install cargo-fuzz`. Keep the working corpus **outside** the repository; the first directory is where new inputs are written, the second holds the committed seeds:

```
cargo +nightly fuzz run <target> ~/fuzz-corpus/parse-net/<target> fuzz/seeds/<target>
```

Nothing under `fuzz/corpus/` or `fuzz/artifacts/` is committed. A crash found by fuzzing is fixed test-first: the input becomes a unit test next to the parser before the fix lands.
