# Changelog

All notable changes to `bin-sentinel` (`bsentinel`) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.14.0] - 2026-10-15

### Added
- Base64, Hex & Encoded Payload Carve & Decode Engine (`src/carve/`):
  - Zero-dependency RFC 4648 Base64 & URL-Safe Base64 scanner and decoder (`base64.rs`):
    - Streaming candidate hunter scanning both ASCII and UTF-16LE wide-character byte streams (e.g. PowerShell dropper commands).
    - Configurable minimum length filter (`min_length`, default: 16) and degenerate/zero-padding heuristic rejection.
  - Multi-format Hex candidate scanner and decoder (`hex.rs`):
    - Contiguous hex stream detector (`[0-9a-fA-F]{24,}`) with hex letter distribution validation to prevent false positives on decimal numbers.
    - Formatted hex sequence detector supporting C/Python/ASM escaped hex (`\x4d\x5a\x90...`), comma/0x sequences (`0x4d, 0x5a...`), and space/colon/dash-separated byte pairs.
  - Heuristic payload classifier and confidence scoring engine (`classifier.rs`):
    - Magic header identification for nested executables: PE32/PE32+ (`MZ` + `PE\0\0`, architecture, DLL/EXE flag), Linux ELF32/ELF64 (`\x7FELF`), and Apple Mach-O (64-bit, 32-bit, Universal Fat).
    - Archive and document container detection: ZIP/APK/Office (`PK\x03\x04`), GZIP (`\x1F\x8B`), 7-Zip (`7z\xBC\xAF\x27\x1C`), and Adobe PDF (`%PDF-`).
    - Embedded script syntax detection: PowerShell cradle keywords (`invoke-expression`, `downloadstring`, `start-process`, `bypass`), Unix Shell scripts (`#!/bin/`, `curl`, `wget`, `chmod +x`, `bash -i`), and Windows Batch scripts (`@echo off`, `certutil -decode`, `bitsadmin`).
    - Network IoC extraction: HTTP/HTTPS/FTP URLs and IPv4 addresses.
    - High-entropy shellcode detection (entropy >= 6.80 with x86/x64 prologues, NOP sleds, or syscall stubs).
    - Objective confidence scoring (0..=100) and automatic preview hex/text generation.
  - High-level orchestrator and safe extraction pipeline (`mod.rs`):
    - Section and RVA mapping against parent PE, ELF, and Mach-O container binaries with Read-Write-Execute (`RWX`) anomaly alerting.
    - Multi-candidate disambiguation prioritizing higher-confidence interpretations on offset collisions.
    - Safe payload extraction (`--extract-dir <dir>`) with strict path traversal defenses (`dest.starts_with(out_dir)`) and extension deduction (`.exe`, `.elf`, `.ps1`, `.sh`, `.zip`, etc.).
  - CLI subcommand:
    - `bsentinel carve <file> [--min-len <n>] [--extract-dir <dir>] [--json]`: human-readable terminal table rendering with color-coded previews, RWX section alerts, and structured machine-readable JSON output.
  - Comprehensive integration test suite (`tests/carve_test.rs`):
    - 10 integration test cases covering Base64 nested PE extraction, URL-safe Base64 PowerShell cradles, contiguous hex streams, formatted hex variants, UTF-16LE encoded commands, PE section/RWX mapping, directory extraction, noise/false-positive rejection, malformed/truncated resilience, and CLI execution.

## [0.13.0] - 2026-10-14

### Added
- PE TLS Callback Directory & Exception Unwind (`.pdata`) Analyzer (`src/callbacks/`):
  - Zero-dependency PE TLS Directory (`IMAGE_DIRECTORY_ENTRY_TLS`) parser (`tls.rs`):
    - Full support for both 64-bit (`IMAGE_TLS_DIRECTORY64`, 40 bytes) and 32-bit (`IMAGE_TLS_DIRECTORY32`, 24 bytes) structures.
    - Endian-safe extraction of raw template boundaries (`StartAddressOfRawData`, `EndAddressOfRawData`), `AddressOfIndex`, and `AddressOfCallBacks`.
    - Bidirectional Virtual Address (VA) to Relative Virtual Address (RVA) resolution against image base and section table boundaries.
    - Safe sequential traversal of null-terminated callback pointer arrays bounded by `MAX_TLS_CALLBACKS` (256 entries).
    - Section and permission mapping resolving whether callbacks reside in executable, writable, or anomalous Read-Write-Execute (`RWX`) segments.
    - Automated forensic alert generation flagging pre-main execution hooks, non-standard section targets, and stealth loader indicators.
  - x64 Exception Directory (`IMAGE_DIRECTORY_ENTRY_EXCEPTION` / `.pdata`) parser (`unwind.rs`):
    - Table-based structured exception handling parser iterating 12-byte `RUNTIME_FUNCTION` entries (`begin_rva`, `end_rva`, `unwind_info_rva`).
    - Bounded iteration up to 4,096 functions with table truncation alerts.
    - Integrity checks detecting inverted or zero function spans (`end_rva <= begin_rva`) and unmapped function addresses.
    - `UNWIND_INFO` structure decoder unpacking version, prolog size, frame register/offset, and unwind flags (`UNW_FLAG_NHANDLER`, `UNW_FLAG_EHANDLER`, `UNW_FLAG_UHANDLER`, `UNW_FLAG_CHAININFO`).
    - Custom exception handler and termination handler RVA resolution with section permission auditing to detect handlers pointing into anomalous RWX or non-executable memory.
  - Deterministic synthetic PE builder (`synthetic.rs`):
    - `build_synthetic_callbacks_pe` generating valid PE32+ binaries with customizable TLS directories, callback pointer arrays, and `.pdata` exception tables with handlers for offline automated testing.
  - CLI subcommand:
    - `bsentinel callbacks <file> [--json]`: formatted terminal tables displaying TLS directory metadata, callback execution hooks, and runtime function exception handlers alongside structured machine-readable JSON output.
  - Comprehensive integration test suite (`tests/callbacks_test.rs`) covering clean binaries, valid TLS callbacks, exception tables with handlers, RWX execution anomalies, inverted function spans, unmapped handlers, multi-callback arrays, malformed inputs, real Windows binaries, and CLI JSON execution.

## [0.12.0] - 2026-10-14

### Added
- PE Resource Directory (`.rsrc`), application manifest, and UAC privilege extractor (`src/resources/`):
  - Zero-dependency 3-level PE resource directory tree traversal (`parser.rs`):
    - Traversal across Level 1 (Resource Types), Level 2 (Names and IDs), and Level 3 (Languages and Locales) down to `IMAGE_RESOURCE_DATA_ENTRY` leaves.
    - Resource identifier resolution mapping standard Windows types (`RT_MANIFEST`, `RT_VERSION`, `RT_ICON`, `RT_GROUP_ICON`, `RT_RCDATA`, `RT_BITMAP`, `RT_STRING`, `RT_DIALOG`, `RT_HTML`, etc.) and UTF-16LE named resource strings (`IMAGE_RESOURCE_DIR_STRING_U`).
    - Standard Windows language code decoding (`0x0409` English US, `0x0412` Korean, `0x0000` Neutral, `0x0804` Chinese, etc.).
    - Circular reference loop protection (`HashSet` tracking of visited directory offsets) and recursion depth bounding preventing denial-of-service on cyclic or corrupted resource tables.
  - Application manifest (`RT_MANIFEST`) extraction and privilege level analyzer (`manifest.rs`):
    - Transparent string decoding handling UTF-8, UTF-16LE, and UTF-16BE with Byte Order Mark (BOM) normalization.
    - Extraction of User Account Control (UAC) `requestedExecutionLevel` (`requireAdministrator`, `highestAvailable`, `asInvoker`).
    - Detection of accessibility UI access bypass (`uiAccess="true"`).
    - Detection of UAC prompt bypass declarations (`<autoElevate>true</autoElevate>`).
    - Extraction of assembly identity metadata (`name`, `version`, `processorArchitecture`).
    - Automated security alert generation when administrative privilege elevation or auto-elevation is detected.
  - Windows Version Information (`RT_VERSION`) parser (`version.rs`):
    - `VS_VERSIONINFO` header parsing and `VS_FIXEDFILEINFO` 32-bit field unpacking (`dwFileVersionMS`, `dwFileVersionLS`, `dwProductVersionMS`, `dwProductVersionLS`).
    - Fallback UTF-16 StringTable property extractor recovering `CompanyName`, `FileDescription`, `FileVersion`, `InternalName`, `LegalCopyright`, `OriginalFilename`, `ProductName`, and `ProductVersion`.
  - High-entropy resource blob detection (`parser.rs`):
    - Per-resource Shannon entropy calculation isolating compressed, encrypted, or packed blobs (threshold >= 7.20 in payloads >= 512 bytes).
    - Automated forensic alert generation highlighting potential dropper stages, encrypted shellcode, or embedded container payloads.
  - Deterministic synthetic PE resource builder (`synthetic.rs`):
    - `build_synthetic_resource_pe` supporting customizable UAC execution levels, autoElevate tags, version properties, and high-entropy RCDATA payload generation for reliable offline testing.
  - CLI subcommand:
    - `bsentinel resources <file> [--json]`: formatted terminal tables displaying resource counts, type breakdown, manifest configuration, version strings, and high-entropy anomalies, alongside structured machine-readable JSON telemetry.
  - Comprehensive integration test suite (`tests/resources_test.rs`) covering clean binaries without resources, synthetic 3-level tree verification, UAC `requireAdministrator` and `asInvoker` detection, high-entropy RCDATA detection, version property extraction, malformed/truncated resource resilience, and end-to-end CLI JSON and table execution.

## [0.11.0] - 2026-10-13

### Added
- Single-byte and multi-byte XOR, ADD, and ROL deobfuscation scanner & key recovery engine (`src/deobfuscate/`):
  - Brute-force single-byte transformations (`decoder.rs` & `scanner.rs`):
    - Exhaustive single-byte XOR decryption (keys `0x01..=0xFF`).
    - Exhaustive single-byte additive cipher decoding (keys `0x01..=0xFF`).
    - Bitwise rotate-left/rotate-right decoding (shifts `1..=7`).
    - Bounded sliding window analysis (256-byte window, 64-byte stride) with intermediate buffer zeroization (`zeroize`).
  - Known-plaintext crib dragging and repeating key recovery (`decoder.rs`):
    - Multi-phase crib dragging evaluating candidate keys against standard plaintext signatures (`http://`, `https://`, `MZ`, `\x7FELF`, `HKLM\`, `HKCU\`, `Software\`).
    - Key period validation and deduction for repeating single-byte, 2-byte, 4-byte, 8-byte, and 16-byte XOR keys.
    - Phase-aligned multi-byte slice decoding around recovered key positions.
  - Semantic decoded payload classification (`decoder.rs`):
    - Network URL extraction (`http://`, `https://`, `ftp://`).
    - Dotted-decimal IPv4 address validation.
    - Windows Registry hive key path detection (`HKLM\`, `HKCU\`, `Software\Microsoft\`, etc.).
    - Executable header magic detection: Windows PE (`MZ` / `PE\0\0`), Linux/BSD ELF (`\x7FELF`), and macOS Mach-O (`0xFEEDFACF`, `0xCAFEBABE`).
    - Contiguous printable ASCII string sequence detection with word-boundary heuristics.
  - Container and executable section correlation (`scanner.rs`):
    - Automated section resolution and Relative Virtual Address (RVA) mapping across PE (`.text`, `.data`, `.rdata`), ELF, and Mach-O containers.
  - CLI subcommand:
    - `bsentinel xor-scan <file> [--json]`: human-readable terminal table reporting offset, RVA, section, cipher method, recovered key, confidence rating, and payload content, alongside structured JSON export.
  - Comprehensive integration test suite (`tests/deobfuscate_test.rs`) covering single-byte XOR URL/IPv4, single-byte ADD Registry keys, ROL URL decoding, multi-byte XOR decoding, crib drag recovery, synthetic PE header detection, CLI JSON output, and zero false positives on random data.

## [0.10.0] - 2026-10-13

### Added
- PE Rich Header forensic decoder, compiler toolchain fingerprinter, and checksum validator (`src/rich/`):
  - Zero-dependency PE Rich header locator and parser (`parser.rs`):
    - Linear scan locating the `"Rich"` magic marker (`0x68636952`) within the DOS stub area bounded by `e_lfanew`.
    - XOR decryption using the 32-bit checksum key stored immediately after `"Rich"`.
    - Reverse search locating the `"DanS"` entry marker (`0x536E6144`) and verifying triple 32-bit zero-padding invariants.
    - Decryption of `@comp.id` records extracting 16-bit Product IDs, 16-bit build numbers, and 32-bit invocation counts.
  - Microsoft toolchain dictionary and Visual Studio fingerprinter (`database.rs`):
    - Comprehensive product ID lookup table resolving C compilers (`Utc*_C`), C++ compilers (`Utc*_CPP`), Linkers (`Linker*`), Resource compilers (`Cvtres*`), Macro Assemblers (`Masm*`), and Import/Export modules.
    - Automated mapping of build numbers and tool IDs to Visual Studio suite targets (VS 97 through VS 2022).
    - Overall primary toolchain detection summarizing dominant compiler suites.
  - Authentic 32-bit `ROL` checksum computation and verification (`parser.rs`):
    - Implementation of Microsoft's authentic checksum algorithm iterating across DOS header bytes (with `e_lfanew` cleared) and `@comp.id` records via 32-bit `rotate_left`.
    - Immediate detection and reporting of checksum tampering or synthetic watermark forgery.
  - Clear data cryptographic hashing (`types.rs`):
    - RFC 1321 MD5 hash of decrypted clear data matching standard VirusTotal / threat intelligence `rich_pe_header_hash`.
    - High-assurance SHA-256 hash of clear data for reproducible binary triage.
  - Deterministic synthetic Rich PE image builder (`synthetic.rs`):
    - `build_synthetic_rich_pe` generating compliant PE64 binaries with authentic or intentionally corrupted Rich headers for automated test pipelines.
  - CLI subcommand:
    - `bsentinel rich <file> [--json]`: formatted terminal table reporting header location, primary toolset, XOR key, checksum validity, clear data hashes, and individual compilation records, with optional structured JSON output.
  - Comprehensive integration test suite (`tests/rich_test.rs`) covering synthetic PE parsing, checksum verification, tamper detection, Visual Studio version identification, corrupted header resilience, and end-to-end CLI JSON and table verification.

## [0.9.0] - 2026-10-13

### Added
- Structural binary diffing and declarative patch manifest engine (`src/diff/`):
  - Binary comparison and format mapping engine (`engine.rs`):
    - Linear scan identifying contiguous byte differences between arbitrary binary streams.
    - Automated format classification across Windows PE, Linux/BSD ELF, Apple Mach-O, and raw byte streams.
    - Automatic correlation of differing hunks to containing binary sections (`.text`, `.data`, `.rdata`, etc.) and computing relative virtual addresses (RVAs).
    - Per-section Shannon entropy deltas identifying compressed or encrypted modifications.
    - Security mitigation diffing detecting alterations to ASLR, DEP/NX, CFG, PIE, RELRO, and Code Signing.
  - Declarative patch recipe manifest and atomic application engine (`recipe.rs`):
    - `PatchRecipe` and `PatchOperation` data structures with formatted JSON serialization.
    - Reversible patches with automatic `reverse()` manifest synthesis swapping expected and replacement bytes and pre/post hashes.
    - Multi-phase atomic verification: constant-time verification of all patch targets prior to applying any disk modifications.
    - Dry-run validation mode calculating prospective post-patch SHA-256 without writing to disk.
    - Automatic `.bak` backup generation prior to live modifications.
    - `zeroize` memory scrubbing of sensitive payload buffers during and after patch operations.
  - CLI subcommands:
    - `bsentinel diff <original> <modified> [--out-recipe <json>] [--json]`: human-readable terminal summary and structured JSON diffing output with section-level details.
    - `bsentinel apply-recipe <file> <recipe.json> [--dry-run] [--reverse] [--backup] [--json]`: verified atomic recipe application and reversal.
  - Comprehensive unit and integration test suite (`tests/diff_test.rs`) covering raw byte hunking, PE section and RVA resolution, ELF section mapping, recipe JSON roundtrips, dry-run safety, live application with backup, clean reversal, and tamper rejection.

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
