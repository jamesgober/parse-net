# parse-net - API Reference

> Reference for every public item in `parse-net`, with examples.
> **Status: scaffold (`0.1.0`).** The public API is written here at `0.2.0` (design lock); see [`../dev/ROADMAP.md`](../dev/ROADMAP.md) and the planned shape in [`../dev/PLAN.md`](../dev/PLAN.md) section 8.

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Table of contents

- [`VERSION`](#version)

## `VERSION`

```rust
pub const VERSION: &str;
```

The crate version, populated by Cargo at build time.

```rust
use parse_net as pn;

assert_eq!(pn::VERSION.split('.').count(), 3);
```
