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

---

## Planned Milestones

### Phase 1: Cross-Platform Executable Formats & Cryptographic Forensics
- [ ] **YARA-Style Hex & Wildcard Pattern Rule Scanner (`src/rules.rs`)** — Fast declarative byte-signature matcher supporting nibble wildcards (`48 8B ?? ?? E8`), relative jump ranges, and boolean rule expressions (`bsentinel rule-scan`).

### Phase 2: Code Signing, Mach-O & Binary Diffing
- [ ] **Mach-O Universal (Fat) & ARM64/x86_64 Binary Parser (`src/macho.rs`)** — Parse macOS/iOS Mach-O headers, load commands (`LC_SEGMENT_64`, `LC_CODE_SIGNATURE`, `LC_MAIN`), and universal fat binary slices (`bsentinel inspect-macho`).
- [ ] **PE Authenticode & Overlay Digital Signature Inspector (`src/authenticode.rs`)** — Inspect `IMAGE_DIRECTORY_ENTRY_SECURITY` PKCS#7 / CMS signature structures, certificate chains, Authenticode PE image hash calculation (excluding checksum and security directory), and trailing EOF overlay data (`bsentinel sig-check`).
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

