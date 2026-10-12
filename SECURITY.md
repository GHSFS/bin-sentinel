# Security Policy

## Supported Versions

Security updates are applied to the latest release series on the `main` branch.

| Version | Supported          |
| ------- | ------------------ |
| Latest (`0.x`) | :white_check_mark: |
| `< 0.1.0` | :x:                |

## Binary Parsing & Memory Safety Invariants

1. **Zero `unsafe` Code**: All PE32/PE32+ and Linux/BSD ELF64 binary structure parsers are implemented in 100% safe Rust using checked slice indexing and saturating/checked integer arithmetic.
2. **Untrusted Binary Bounds Protection**: Malformed `e_lfanew`, `e_phoff`, `e_shoff` offsets, truncated headers, overlapping section tables, and out-of-bounds raw data pointers are rejected deterministically without panicking or over-allocating memory.
3. **Constant-Time Patch Verification**: Declarative byte patches validate expected target bytes using branchless constant-time comparison (`constant_time_eq`) and compute pre-patch/post-patch SHA-256 digests prior to atomic file replacement.
4. **Sensitive Buffer Zeroization**: Intermediate binary patch buffers are scrubbed from memory on drop via `zeroize`.

## Reporting a Vulnerability

If you discover a potential security issue, parser crash on malformed inputs, or memory safety flaw:

1. **Do not open a public issue** with exploit details before a fix is available.
2. Report the finding via [GitHub Security Advisories](../../security/advisories/new) or contact the maintainers directly with a minimal reproduction case.
3. We review reports promptly and coordinate fixes and release notes upon resolution.
