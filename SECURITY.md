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
5. **Bounded Linear Scanning & Deterministic Memory Consumption**: Cryptographic constant and S-Box scanning operates strictly over bounded byte slices with linear byte matching, preventing unbounded recursion or denial-of-service on large untrusted binaries.
6. **Bounded PE Import & Export Directory Parsing**: PE import descriptors (`IMAGE_IMPORT_DESCRIPTOR`), Import Lookup/Address Tables (ILT/IAT), and Export Directories (`IMAGE_EXPORT_DIRECTORY`) enforce hard caps (max 1,024 descriptors, max 4,096 thunks per descriptor, max 65,536 export symbols). RVA-to-file-offset translation guards against null RVAs, cyclic thunk tables, and truncated binary buffers, preventing infinite loops and out-of-bounds indexing.
7. **Pure-Rust Imphash & Dynamic API Hash Resolution**: RFC 1321 MD5 message digest calculation (`imphash`) and dynamic API hash evaluation (ROR13, CRC32, DJB2, FNV-1a) run in 100% safe Rust without external C dependencies, static bounds validation, and zero execution of untrusted binary code.
8. **Safe Static x86_64 Code Pattern Scanning & Evasive Syscall Telemetry**: Instruction pattern scanning operates in 100% safe Rust without code execution or dynamic disassembly runtimes. All slice reads are strictly bounds-checked with saturating offsets. Direct kernel system call stubs (SysWhispers/Hell's Gate), anti-debug timing probes (`RDTSC`/`RDTSCP`), and hypervisor queries (`CPUID`/`SMSW`) are statically extracted with section correlation and RWX anomaly flagging without executing untrusted payload bytes.
9. **Safe Declarative Pattern Rule Matching & Backtracking Defenses**: The hex and wildcard pattern rule scanner operates with strict resource bounds: maximum byte jump span of 4,096 bytes (`MAX_JUMP_LIMIT`), maximum match byte span of 65,536 bytes (`MAX_MATCH_SPAN`), recursion depth ceiling of 64 (`MAX_DFS_DEPTH`), and maximum match cap of 1,000 matches per pattern. Pure-Rust tokenization rejects unclosed jump brackets and uneven nibbles. Static pattern evaluation runs with zero execution of untrusted binary code and maps hits to PE/ELF section tables with automated RWX anomaly detection.
10. **Zero-Dependency Mach-O & Universal Fat Binary Safety Invariants**: All 64-bit Mach-O (`0xFEEDFACF`) and Universal Fat (`0xCAFEBABE`) binary parsers are implemented in 100% safe pure Rust with zero unsafe blocks. Multi-architecture slices, load commands (`LC_SEGMENT_64`, `LC_MAIN`, `LC_LOAD_DYLIB`, `LC_CODE_SIGNATURE`), and section tables enforce strict bounds checking (`checked_add`, safe LE/BE byte readers). Truncated slice offsets, malformed command sizes (`cmdsize < 8` or overflowing the Mach-O slice), and corrupted section bounds are deterministically rejected with descriptive errors. Digital code signature presence, PIE flags, stack execution permissions, and Writable/Executable (`RWX`) memory segments are audited statically without executing candidate binary code.
11. **PE Authenticode, Certificate Table & EOF Overlay Safety Invariants**: The Authenticode attribute certificate table parser and ASN.1 DER parser operate in 100% safe pure Rust with zero `unsafe` blocks. Parsing enforces strict resource ceilings (max 64 certificate entries, 4-byte ASN.1 length bounds, checked offset additions). Integer arithmetic for alignment (`(len + 7) & !7`) and section ranges uses checked and saturating operations, guarding against 32-bit and 64-bit wrap-around. Authenticode image hashing excludes PE `CheckSum` and Security Directory entries and processes sections in ascending file offset order without executing code. Appended EOF overlay detection computes physical image boundaries via checked section and certificate extents with bounded Shannon entropy profiling. Computed vs embedded digest comparisons employ branchless constant-time evaluation to eliminate timing side-channels.

## Reporting a Vulnerability

If you discover a potential security issue, parser crash on malformed inputs, or memory safety flaw:

1. **Do not open a public issue** with exploit details before a fix is available.
2. Report the finding via [GitHub Security Advisories](../../security/advisories/new) or contact the maintainers directly with a minimal reproduction case.
3. We review reports promptly and coordinate fixes and release notes upon resolution.
