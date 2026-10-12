# Changelog

All notable changes to `bin-sentinel` (`bsentinel`) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-13

### Added
- Zero-dependency Linux and BSD ELF64 binary parser (`src/elf/`):
  - Strict validation of 64-bit ELF identification magic (`\x7FELF`), architecture class, and byte order.
  - Complete parsing of ELF executable header (`Ehdr`), program header segments (`Phdr`), and section tables (`Shdr`).
  - Automated security mitigation evaluation:
    - Position-Independent Executable (`PIE`) detection from `ET_DYN` object types and dynamic flags.
    - Relocation Read-Only (`RELRO`) classification into Full, Partial, or None via `PT_GNU_RELRO` and `BIND_NOW` flags.
    - Non-executable stack (`NX`) verification via `PT_GNU_STACK` permission flags.
    - Stack canary detection via symbol table inspection for `__stack_chk_fail` and related protection symbols.
  - Per-section Shannon entropy calculation and detection of writable-and-executable (`RWX`) segments.
  - Dynamic tag array reader for library dependencies (`DT_NEEDED`), runtime search paths (`DT_RPATH`, `DT_RUNPATH`), and sonames (`DT_SONAME`).
  - Symbol table parser extracting function, object, and global/weak symbol definitions from `.dynsym` and `.symtab`.
  - Deterministic synthetic ELF64 sample binary builder (`build_synthetic_elf64`).
- CLI subcommands:
  - `bsentinel inspect-elf <file> [--json]`: human-readable and structured JSON inspection of ELF64 binaries.
  - `bsentinel synth-elf <output>`: generates valid synthetic ELF64 test binaries for validation pipelines.
- Modular integration test suite in `tests/elf_test.rs`.

## [0.1.0] - 2026-10-13

### Added
- Zero-dependency Windows PE32 (`0x10B`) and PE32+ (`0x20B`) static binary parser (`src/pe.rs`):
  - Checked bounds validation for DOS `MZ` header (`e_lfanew`), `PE\0\0` signature, COFF file header, Optional header, and section table headers.
  - Automated extraction of exploit mitigation flags (`ASLR`, `HighEntropyVA`, `DEP/NX`, `Control Flow Guard`).
  - Per-section permission decoding (`R`/`W`/`X`), Shannon entropy calculation, and writable+executable (`RWX`) anomaly detection.
  - Deterministic synthetic PE64 sample generator (`build_synthetic_pe64` and `bsentinel synth-pe <output>`).
- Statistical entropy and packer heuristic detector (`src/entropy.rs`):
  - Exact Shannon entropy ($0.0..=8.0$ bits/byte) and Pearson's Chi-square ($\chi^2$, $df=255$) uniformity analysis.
  - Byte distribution classifier reporting null byte ratio, printable ASCII ratio, and high-byte ratio.
  - Sliding-window entropy profiling (`bsentinel entropy <file> --window <bytes> [--json]`).
  - Packer and protector heuristics detecting `UPX0`/`UPX1`/`UPX!`, `.vmp0`/`.vmp1` (VMProtect), `.themida`, RWX sections, and high-entropy code sections ($\ge 7.2$ bits/byte).
- Static ASCII & UTF-16LE string and Indicator of Compromise (IoC) extractor (`src/strings.rs`):
  - Contiguous printable ASCII and UTF-16LE wide string scanner (`bsentinel strings <file> [--min-len <n>] [--ioc-only] [--json]`).
  - Built-in IoC classification for URLs (`http://`, `https://`, `ftp://`), IPv4 endpoints, Windows Registry keys (`HKLM\`, `HKCU\`, `CurrentVersion\Run`), and sensitive Win32 injection/debugging APIs (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `IsDebuggerPresent`, `NtQueryInformationProcess`).
- Verified declarative byte-patching engine (`src/patch.rs`):
  - Branchless constant-time expected-byte verification (`constant_time_eq`) at target file offset, aborting with `PatchMismatch` if original bytes differ.
  - Pre-patch and post-patch SHA-256 cryptographic digest calculation and optional `.bak` backup creation (`bsentinel patch <file> --offset <off> --expect <hex> --replace <hex> [--backup] [--json]`).
  - Proactive memory wiping of mutable binary buffers on drop via `zeroize`.
- Multi-language documentation & self-hosted SVG visual suite across 10 languages (`en`, `ko`, `zh-CN`, `es`, `hi`, `ar`, `pt-BR`, `ru`, `fr`, `id`).
- Modular integration test suites (`tests/pe_entropy_test.rs` and `tests/patch_strings_test.rs`).
