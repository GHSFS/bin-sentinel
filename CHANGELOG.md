# Changelog

All notable changes to `bin-sentinel` (`bsentinel`) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2026-10-13

### Added
- PE Authenticode digital signature and attribute certificate table inspector (`src/authenticode/`):
  - Digital Certificate Table parser (`parser.rs`):
    - Traversal of PE `IMAGE_DIRECTORY_ENTRY_SECURITY` (Data Directory index 4) with file offset and length bounds validation.
    - 8-byte aligned `WIN_CERTIFICATE` entry extraction supporting revisions `WIN_CERT_REVISION_1_0` (0x0100) and `WIN_CERT_REVISION_2_0` (0x0200).
    - Certificate container classifications: `WIN_CERT_TYPE_X509` (0x0001), `WIN_CERT_TYPE_PKCS_SIGNED_DATA` (0x0002), and Terminal Server signed structures.
  - PKCS#7 / CMS SignedData ASN.1 DER parser (`parser.rs`):
    - Structural extraction of `SpcIndirectDataContent` message digests and algorithm identification (`SHA-256`, `SHA-1`, `SHA-384`, `SHA-512`, `MD5`).
    - Detection of countersignatures and RFC 3161 timestamp tokens (`1.3.6.1.4.1.311.3.3.1` and `1.2.840.113549.1.9.6`).
    - Program name and description metadata extraction from `spcSpOpusInfo` attributes.
  - Microsoft Authenticode PE image digest calculator (`digest.rs`):
    - Implementation of official Microsoft Authenticode PE image hashing specification.
    - Deterministic exclusion of PE Optional Header `CheckSum` field (4 bytes) and Security Directory entry (8 bytes).
    - Section table ordering sorted ascending by `PointerToRawData` and sequential section chunk hashing.
    - Hash calculation for both SHA-256 (via `sha2`) and pure-Rust RFC 3174 SHA-1 (`sha1.rs`).
    - Constant-time verification between calculated image digests and embedded certificate digests.
  - Physical PE boundary analysis and EOF overlay detector (`overlay.rs`):
    - Calculation of legitimate binary physical boundary: `max(raw_section_end)` + Certificate Table size.
    - Detection of appended trailing data past the legitimate image boundary.
    - High-resolution Shannon entropy calculation, overlay file size ratio, and signature heuristics (ZIP, 7-Zip, RAR, GZIP, XZ, nested PE "MZ", nested ELF, nested Mach-O, PDF, and PNG).
  - Deterministic synthetic signed PE64 generator (`synthetic.rs`):
    - `build_synthetic_signed_pe64` building structurally valid 64-bit PE binaries with genuine Authenticode SHA-256 digests and optional overlay injection for automated test pipelines.
- CLI subcommand:
  - `bsentinel sig-check <file> [--json]`: comprehensive digital signature, digest verification, and overlay telemetry report in clean terminal table or JSON format.
- Modular integration test suite in `tests/authenticode_test.rs` covering unsigned PE inspection, valid signed PE verification, tampered code digest mismatch alerts, EOF overlay detection, and CLI JSON verification.

## [0.7.0] - 2026-10-13

### Added
- Zero-dependency macOS/iOS Mach-O binary forensics engine (`src/macho/`):
  - Architecture and container support:
    - 64-bit Mach-O headers (`0xFEEDFACF` / `MH_MAGIC_64` and byte-swapped `MH_CIGAM_64`).
    - Universal Fat multi-architecture container parser (`0xCAFEBABE` / `FAT_MAGIC` and `FAT_CIGAM`) unpacking `fat_arch` descriptors and isolating nested 64-bit slices (ARM64, x86_64).
  - Load command analysis:
    - `LC_SEGMENT_64`: 64-bit memory segments (`__PAGEZERO`, `__TEXT`, `__DATA`, `__LINKEDIT`), memory protections (`maxprot`, `initprot`), embedded `section_64` tables, and per-section Shannon entropy profiling.
    - `LC_MAIN`: application entry point file offset and stack size configuration.
    - `LC_LOAD_DYLIB`: linked dynamic libraries and framework path dependencies.
    - `LC_CODE_SIGNATURE`: digital signature data offset and superblob payload size.
  - Security hardening and anomaly detection:
    - Position-Independent Executable (`PIE`) flag verification (`MH_PIE`).
    - Non-executable stack detection (`MH_ALLOW_STACK_EXECUTION` audit).
    - Apple digital code signature presence verification (`LC_CODE_SIGNATURE`).
    - Writable & Executable (`RWX`) segment permission anomaly alerts.
    - High-entropy and packed code section heuristic detection.
  - Deterministic synthetic Mach-O generator (`synthetic.rs`):
    - `build_synthetic_macho64` and `build_synthetic_macho_universal` generating structurally valid 64-bit and Universal dual-architecture test binaries with 4KB page alignment.
- CLI subcommands:
  - `bsentinel inspect-macho <file> [--json]`: forensic telemetry reporting architecture slices, load commands, sections, linked libraries, and security mitigations in human-readable table or JSON format.
  - `bsentinel synth-macho <output> [--universal]`: generate deterministic 64-bit Mach-O or Universal Fat test samples for automated pipelines.
- Modular integration test suite in `tests/macho_test.rs` covering header validation, load command parsing, multi-slice Fat containers, RWX anomaly alerting, and CLI table/JSON validation.

## [0.6.0] - 2026-10-13

### Added
- Declarative YARA-style hex signature and pattern rule scanner (`src/rules/`):
  - Advanced hex pattern tokenization (`parser.rs`):
    - Full wildcard bytes (`??` and `?`) matching any candidate byte value.
    - Nibble-level wildcards: high-nibble (`?8`, matching `(b & 0x0F) == 0x08`) and low-nibble (`4?`, matching `(b & 0xF0) == 0x40`).
    - Bounded byte jump intervals: fixed jumps `[N]` and range jumps `[min-max]` (e.g. `[2-6]`) with security bounds checking (`MAX_JUMP_LIMIT`).
    - Continuous and whitespace-delimited hex sequence formatting (`48 83 EC ?? [2-6] E8`).
  - String condition tokenization:
    - ASCII string patterns with optional case-insensitive evaluation (`nocase`).
    - UTF-16LE wide string patterns with case-insensitive ASCII character normalization.
  - Multi-pattern declarative rule engine (`engine.rs`):
    - Rule conditions: `all` (every defined pattern must match), `any` (at least one pattern matches), and `count(N)` (at least N distinct patterns match).
    - Threat severity classification: `Low`, `Medium`, `High`, and `Critical`.
    - Flexible JSON rule deserialization supporting single rules, lists of rules, and wrapped `RuleSetDefinition` schemas.
  - High-performance slice matcher (`matcher.rs`):
    - Fast-path linear scanner for jump-free byte patterns operating at memory bandwidth speeds.
    - DFS jump resolution with recursion depth limits (`MAX_DFS_DEPTH = 64`) and match span limits (`MAX_MATCH_SPAN = 65536`) to protect against catastrophic backtracking.
    - Automated PE and ELF section correlation resolving containing section names, RVAs, virtual addresses, and alerting on matches inside anomalous RWX sections.
- CLI subcommand:
  - `bsentinel rule-scan <file> [--pattern <hex>] [--rules <file.json>] [--json]`: fast ad-hoc signature or structured multi-rule triage with human-readable table and structured JSON reports.
- Modular CLI command architecture (`src/commands/`):
  - Refactored CLI handlers into domain modules (`inspect.rs`, `forensics.rs`, `rules.rs`, `mod.rs`), streamlining `src/main.rs` to an 18-line entry point.
- Dedicated integration test suite in `tests/rules_test.rs` covering wildcards, jumps, strings, JSON rule sets, PE/ELF section mapping, and CLI execution.

## [0.5.0] - 2026-10-13

### Added
- Pure-Rust x86_64 instruction pattern scanner and control-flow disassembler (`src/disasm/`):
  - Direct system call stub detection (`rules_control.rs`):
    - Windows NT direct syscall stubs (`4C 8B D1 B8 <ssn> 0F 05 [C3]`, e.g. SysWhispers / Hell's Gate / Halo's Gate patterns) extracting System Service Numbers (SSN).
    - Linux direct syscall invocations (`B8 <sys_nr> 0F 05 [C3]`).
    - Standalone 64-bit `SYSCALL` (`0F 05`) and legacy 32-bit `INT 0x80` (`CD 80`) software interrupts.
  - Anti-analysis and anti-debugging timing probe detection:
    - `RDTSC` (`0F 31`) and `RDTSCP` (`0F 01 F9`) cycle count probes used for latency threshold evasion and sleep-skipping checks.
  - Hypervisor and virtual machine fingerprinting detection:
    - `CPUID` (`0F A2`) processor information and hypervisor leaf queries.
    - `SMSW` (`0F 01 F0` / `0F 01 E0`) machine status word queries.
  - Software traps and breakpoint detection:
    - `UD2` (`0F 0B`) compiler unreachable assertions and panic traps.
    - `INT 3` (`0xCC`) software breakpoints (distinguishing single break traps from multi-byte compiler function alignment padding runs).
    - `ICEBP` / `INT 1` (`0xF1`) single-step in-circuit emulator breakpoint traps.
    - `INTO` (`0xCE`) overflow traps.
  - Function prologue and stack frame setup detection (`rules_frame.rs`):
    - Standard frame pointer prologues (`55 48 89 E5` / `55 48 8B EC` push rbp; mov rbp, rsp).
    - Compound frame pointer setups with immediate stack allocation (`sub rsp, imm8/imm32`).
    - Windows x64 ABI non-volatile register preservation and argument home spill sequences (`mov [rsp+8], rcx`, `mov [rsp+disp], rbx`, `push rbx; sub rsp, imm8`).
    - Legacy 32-bit frame setup (`55 89 E5`).
  - Function epilogue and stack teardown detection:
    - Standard near returns (`C3`), returns with caller popping (`C2 <imm16>`).
    - Frame teardown sequences (`48 89 EC 5D C3` mov rsp, rbp; pop rbp; ret, `leave; ret`, `pop rbp; ret`, `add rsp, imm; ret`).
  - Indirect branches and control-flow pivots:
    - `JMP RSP` (`FF E4`) stack pivot gadgets and shellcode bounce points.
    - Indirect register jumps and calls (`FF E0` jmp rax, `FF D0` call rax, `FF D2` call rdx).
    - RIP-relative indirect calls and jumps (`FF 25 <disp32>`, `FF 15 <disp32>`).
  - Automated executable section and RVA correlation (`scanner.rs`):
    - Resolves containing sections (`.text`, `.rdata`, etc.) and RVAs/virtual addresses for valid PE and ELF binaries.
    - Flags security risk alerts when sensitive code sequences (direct syscalls, timing checks) are located inside anomalous RWX sections or outside executable segments.
- CLI subcommand:
  - `bsentinel scan-code <file> [--json]`: comprehensive x86_64 code pattern scan with structured telemetry and heuristic risk alerts.
- Dedicated integration test suite in `tests/disasm_test.rs`.

## [0.4.0] - 2026-10-13

### Added
- PE Import Directory (`IMAGE_IMPORT_DESCRIPTOR`), Import Lookup Table (ILT/IAT), and Export Directory (`IMAGE_EXPORT_DIRECTORY`) parser (`src/imports/parser.rs`):
  - Robust bounds-checked parsing of both 32-bit (PE32) and 64-bit (PE32+) import tables.
  - Full support for named imports (`IMAGE_IMPORT_BY_NAME` with hints) and ordinal imports across multiple DLL descriptors.
  - Complete parsing of Export Directory structures (`IMAGE_EXPORT_DIRECTORY`), including `AddressOfFunctions`, `AddressOfNames`, and `AddressOfNameOrdinals` tables.
  - Forwarded export detection and string resolution (e.g. forwarders pointing inside the export directory boundary like `NTDLL.RtlAllocateHeap`).
- Pure-Rust RFC 1321 MD5 message digest and Mandiant `imphash` implementation (`src/imports/imphash.rs`):
  - Zero-external-dependency RFC 1321 MD5 hashing engine with standard test vector verification.
  - Strict Mandiant / FireEye `imphash` specification compliance (lowercase symbol normalisation, stripping `.dll`, `.sys`, `.ocx` extensions, formatting named and ordinal imports, and MD5 hexadecimal encoding).
- Dynamic API hash resolution engine (`src/imports/api_hash.rs`):
  - Implements 4 standard hashing algorithms commonly observed in evasive shellcode and stealth loaders: Rotate Right 13 (`ROR13`), IEEE 802.3 `CRC32`, `DJB2`, and `FNV-1a`.
  - Curated database of over 80 high-frequency Windows APIs (`kernel32.dll`, `ntdll.dll`, `user32.dll`, `advapi32.dll`, `ws2_32.dll`, `wininet.dll`).
  - Automated hash matching against known APIs and dynamically exported functions from inspected binaries.
- Deterministic synthetic PE32 and PE32+ generator with valid import and export directories (`src/imports/synthetic.rs`).
- CLI subcommand:
  - `bsentinel imports <file> [--resolve-hash <hex>] [--json]`: comprehensive import/export table analysis, imphash generation, and dynamic API hash resolution.
- Isolated integration test suite in `tests/imports_test.rs`.

## [0.3.0] - 2026-10-13

### Added
- Embedded cryptographic constant, S-Box, and lookup table scanner (`src/crypto_scan/`):
  - Static byte-signature matching for common block ciphers, stream ciphers, hash functions, and cyclic redundancy checks:
    - AES-128/192/256 (Rijndael) forward substitution box (`AES_FORWARD_SBOX`, 256 bytes) and inverse substitution box (`AES_INVERSE_SBOX`, 256 bytes).
    - AES key expansion round constants (`AES_RCON`, 10 bytes).
    - ChaCha20 and Salsa20 state expansion constants (`"expand 32-byte k"` and `"expand 16-byte k"`).
    - SHA-256 initial state vectors (`H0..H7` in Little-Endian and Big-Endian) and first 16 round constants (`K[0..15]`).
    - SHA-512 initial state vectors (`H0..H7` in Little-Endian and Big-Endian) and round constants.
    - MD5 state vectors (`A, B, C, D` in Little-Endian and Big-Endian).
    - SHA-1 state vectors (`H0..H4` in Little-Endian and Big-Endian).
    - IEEE 802.3 CRC-32 standard precomputed lookup table (first 16 entries in Little-Endian).
    - TEA and XTEA golden ratio delta constant (`0x9E3779B9`) in Little-Endian and Big-Endian byte sequences with occurrence tracking.
    - SM4 commercial block cipher substitution box (`SM4_SBOX`, 256 bytes).
  - Automated executable section and RVA correlation:
    - Cross-references file offsets against PE section tables (`PeInfo`) to resolve containing sections and RVAs.
    - Cross-references file offsets against ELF section headers (`ElfInfo`) to resolve containing sections and virtual memory addresses.
- CLI subcommand:
  - `bsentinel crypto-scan <file> [--json]`: human-readable and structured JSON output for automated forensics workflows.
- Integration test suite in `tests/crypto_scan_test.rs`.

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
