# BinSentinel Roadmap

This document tracks shipped capabilities and planned binary analysis, reverse-engineering triage, and forensic verification features for `bin-sentinel` (`bsentinel`).

---

## Shipped Capabilities

- [x] **Zero-Dependency PE32/PE32+ Header & Section Inspector (`src/pe.rs`)** — Checked bounds parsing for DOS, COFF, Optional, and Section headers, security mitigation verification (`ASLR`, `HighEntropyVA`, `DEP/NX`, `CFG`), `RWX` permission anomaly detection, and deterministic synthetic PE64 test binary generation (`bsentinel inspect`, `bsentinel synth-pe`).
- [x] **Zero-Dependency Linux/BSD ELF64 Header, Segment & Section Inspector (`src/elf/`)** — Checked bounds parsing for ELF64 `Ehdr`, `Phdr`, and `Shdr` tables, automated security hardening analysis (`PIE`, `RELRO`, `NX`, `Stack Canary`), section entropy profiling, `.dynamic` tags, dynamic symbol resolution, and synthetic sample generation (`bsentinel inspect-elf`, `bsentinel synth-elf`).
- [x] **Statistical Entropy & Packer Heuristic Analyzer (`src/entropy.rs`)** — Full-file and sliding-window Shannon entropy ($0.0..=8.0$ bits/byte), Chi-square ($\chi^2$) uniformity testing, byte class ratios, and heuristic detection for UPX, VMProtect, Themida, and compressed/encrypted code sections (`bsentinel entropy`).
- [x] **Static ASCII / UTF-16LE String & IoC Extractor (`src/strings.rs`)** — Offset-indexed ASCII and UTF-16LE wide string extraction with automated classification of URLs, IPv4 addresses, Windows Registry persistence keys, and sensitive Win32 process injection/anti-debug APIs (`bsentinel strings`).
- [x] **Verified Declarative Byte-Patching Engine (`src/patch.rs`)** — Constant-time expected-byte verification, pre/post SHA-256 integrity digests, optional `.bak` backup creation, and `zeroize` buffer scrubbing (`bsentinel patch`).
- [x] **Cryptographic Constant & S-Box Scanner (`src/crypto_scan/`)** — Detect embedded cryptographic primitives, AES/Rijndael forward/inverse S-Boxes and Rcon, ChaCha20/Salsa20 sigma/tau magic constants, SHA-256/SHA-512 initial states and round constants, MD5/SHA-1 states, CRC-32 standard lookup tables, TEA/XTEA golden-ratio delta `0x9E3779B9`, and SM4 cipher S-Box with automated PE and ELF section and RVA resolution (`bsentinel crypto-scan`).
- [x] **PE Import/Export Directory (IAT/ILT/EAT), imphash & Dynamic API Hash Resolver (`src/imports/`)** — Zero-dependency PE32/PE32+ Import Directory (`IMAGE_IMPORT_DESCRIPTOR`), Import Lookup Table, and Export Directory (`IMAGE_EXPORT_DIRECTORY`) parsing with forwarder resolution, Mandiant `imphash` (MD5 hex) generation, and dynamic API hash resolution (`ROR13`, `CRC32`, `DJB2`, `FNV-1a`) against common Windows DLL exports (`bsentinel imports`).
- [x] **x86_64 Prologue/Epilogue & Control-Flow Pattern Scanner (`src/disasm/`)** — Pure-Rust instruction pattern scanner identifying function prologues, direct system call stubs (SysWhispers / Hell's Gate / Halo's Gate EDR bypasses), `RDTSC`/`RDTSCP` anti-debug timing checks, `CPUID`/`SMSW` VM probes, `INT 3`/`UD2` software traps, and `JMP RSP` stack pivots with automated PE and ELF section and RVA resolution (`bsentinel scan-code`).
- [x] **YARA-Style Hex & Wildcard Pattern Rule Scanner (`src/rules/`)** — Declarative byte-signature and rule matching engine supporting exact hex bytes, full wildcards (`??`), nibble wildcards (`?8`, `4?`), bounded byte jumps (`[2-6]`), case-insensitive ASCII and UTF-16LE wide string patterns, multi-pattern boolean rule evaluation (`all`, `any`, `count`), JSON rule files, and PE/ELF section and RWX anomaly correlation (`bsentinel rule-scan`).
- [x] **Mach-O Universal (Fat) & ARM64/x86_64 Binary Parser (`src/macho/`)** — Zero-dependency macOS/iOS Mach-O parser supporting 64-bit binaries (`0xFEEDFACF`) and Universal Fat multi-architecture containers (`0xCAFEBABE`), load commands (`LC_SEGMENT_64`, `LC_MAIN`, `LC_LOAD_DYLIB`, `LC_CODE_SIGNATURE`), section Shannon entropy profiling, security mitigations (`PIE`, `CodeSignature`, non-executable stack), and deterministic sample generation (`bsentinel inspect-macho`, `bsentinel synth-macho`).
- [x] **PE Authenticode Digital Signature & EOF Overlay Inspector (`src/authenticode/`)** — Zero-dependency PE certificate table (`IMAGE_DIRECTORY_ENTRY_SECURITY` / `WIN_CERTIFICATE`) parser, PKCS#7 / CMS SignedData ASN.1 DER parser (`SpcIndirectDataContent` message digests, timestamp tokens, Opus info), Microsoft Authenticode PE image digest calculation (excluding checksum and security directory) for SHA-256 and pure-Rust SHA-1, physical boundary calculation, Shannon entropy profiling and heuristic classification for appended EOF overlays, and deterministic signed PE generator (`bsentinel sig-check`).

---

## Planned Milestones

### Phase 2: Code Signing, Digital Signatures & Binary Diffing
- [ ] **Structural Binary Diff & Patch Recipe Generator (`src/diff.rs`)** — Compare two binaries section-by-section and byte-by-byte, exporting a reproducible JSON declarative patch manifest (`bsentinel diff <orig> <modified>`).
- [ ] **PE Rich Header & Compiler Toolchain Fingerprinter (`src/rich.rs`)** — Decrypt XOR-masked Microsoft Rich headers to identify Visual Studio linker/compiler build versions and object counts (`bsentinel rich`).
- [ ] **PE Resource Directory (`.rsrc`) & Manifest Inspector (`src/resources.rs`)** — Traverse 3-level PE resource trees to extract embedded XML UAC manifests, `VS_VERSIONINFO` metadata, icons, and high-entropy embedded payloads (`bsentinel resources`).
- [ ] **TLS Callback & Exception Directory (`pdata`) Analyzer (`src/callbacks.rs`)** — Inspect `IMAGE_DIRECTORY_ENTRY_TLS` pre-entry-point callbacks and x64 unwind info structures frequently abused for anti-debug execution (`bsentinel callbacks`).
- [ ] **Deobfuscation & XOR/ADD/ROL Single-Byte & Multi-Byte Brute-Force Decoder (`src/deobfuscate.rs`)** — Automatically recover XOR-, ADD-, or rotate-encoded URLs and configuration strings from binary sections (`bsentinel xor-scan`).
- [ ] **SARIF & CycloneDX Forensic Report Exporter (`src/report.rs`)** — Export static analysis alerts, mitigation audits, and IoC findings in standard SARIF v2.1.0 format for GitHub Code Scanning integration (`bsentinel report --sarif`).

### Phase 3: Platform Subsystems, Kernel Drivers & Format Carving
- [ ] **Windows Kernel Driver (`SYS`) & Security Inspector (`src/driver_meta.rs`)** — Inspect DriverEntry signatures, WDF/KMDF metadata, IOCTL dispatch handlers, and kernel device ACL descriptors (`bsentinel inspect-driver`).
- [ ] **Linux Core Dump (`ET_CORE`) & Note Segment Extractor (`src/coredump.rs`)** — Parse core dump memory mappings, registers, signal numbers, and crash state (`bsentinel inspect-core`).
- [ ] **Apple dyld Shared Cache Mapping Inspector (`src/dyld_cache.rs`)** — Parse macOS/iOS `dyld_v1` cache headers, slide info, and dylib entry points (`bsentinel inspect-dyld`).
- [ ] **Unified Multi-Format Binary Triage Dispatcher (`src/triage.rs`)** — Auto-detect binary format from magic bytes and dispatch all relevant telemetry (`bsentinel triage`).
- [ ] **WebAssembly (`\0asm`) Binary Module & Function Import/Export Inspector (`src/wasm.rs`)** — Parse Wasm binary modules, custom name sections, imported host functions, and memory limits (`bsentinel inspect-wasm`).
- [ ] **Android Dalvik Executable (`dex\n035\0`) Header & Class Pool Inspector (`src/dex.rs`)** — Parse DEX headers, string/type identifiers, and class def tables (`bsentinel inspect-dex`).

### Phase 4: Low-Level Forensics, Crash Dumps & Memory Analysis
- [ ] **Windows 64-bit Kernel Crash Dump Physical Memory Parser (`src/memory_dump.rs`)** — Parse complete 64-bit kernel memory crash dumps, physical memory runs (`PHYSICAL_MEMORY_RUN`), and KDDEBUGGER_DATA64 blocks (`bsentinel inspect-kernel-dmp`).
- [ ] **PE Export Address Table Collision & Hash Stomping Detector (`src/eat_collision.rs`)** — Scan export directories for hash collisions, duplicate ordinals, and null name pointer anomalies used to blind API monitoring hooks (`bsentinel check-eat`).
- [ ] **Apple Mach-O Code Directory (CodeDir) CDHash & Slot Validator (`src/cdhash.rs`)** — Validate authentic CDHash (SHA-1/SHA-256) and verify per-page code slot hashes against binary slices (`bsentinel cdhash`).
- [ ] **Linux ELF GNU Property Note & Control-Flow Mitigation Inspector (`src/elf_notes.rs`)** — Inspect ELF `.note.gnu.property` descriptors to verify Linux AArch64 BTI/PAC and x86_64 IBT/SHSTK enforcement (`bsentinel inspect-notes`).
- [ ] **PE Authenticode Dual-Signature Architecture & Metadata Extractor (`src/dual_sig.rs`)** — Parse secondary nested `WIN_CERTIFICATE` entries and SpcSpOpusInfo publisher metadata (`bsentinel inspect-dual-sig`).

