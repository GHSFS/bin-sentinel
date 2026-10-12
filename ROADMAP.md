# BinSentinel Roadmap

This document tracks shipped capabilities and planned binary analysis, reverse-engineering triage, and forensic verification features for `bin-sentinel` (`bsentinel`).

---

## Shipped Capabilities

- [x] **Zero-Dependency PE32/PE32+ Header & Section Inspector (`src/pe.rs`)** — Checked bounds parsing for DOS, COFF, Optional, and Section headers, security mitigation verification (`ASLR`, `HighEntropyVA`, `DEP/NX`, `CFG`), `RWX` permission anomaly detection, and deterministic synthetic PE64 test binary generation (`bsentinel inspect`, `bsentinel synth-pe`).
- [x] **Statistical Entropy & Packer Heuristic Analyzer (`src/entropy.rs`)** — Full-file and sliding-window Shannon entropy ($0.0..=8.0$ bits/byte), Chi-square ($\chi^2$) uniformity testing, byte class ratios, and heuristic detection for UPX, VMProtect, Themida, and compressed/encrypted code sections (`bsentinel entropy`).
- [x] **Static ASCII / UTF-16LE String & IoC Extractor (`src/strings.rs`)** — Offset-indexed ASCII and UTF-16LE wide string extraction with automated classification of URLs, IPv4 addresses, Windows Registry persistence keys, and sensitive Win32 process injection/anti-debug APIs (`bsentinel strings`).
- [x] **Verified Declarative Byte-Patching Engine (`src/patch.rs`)** — Constant-time expected-byte verification, pre/post SHA-256 integrity digests, optional `.bak` backup creation, and `zeroize` buffer scrubbing (`bsentinel patch`).

---

## Planned Milestones

### Phase 1: Cross-Platform Executable Formats & Cryptographic Forensics
- [ ] **ELF64 Binary Header, Program/Section Header & Dynamic Symbol Parser (`src/elf.rs`)** — Zero-dependency Linux/BSD ELF64 parser extracting `Ehdr`, `Phdr`, `Shdr`, `.dynamic` tags, security hardening flags (`PIE`, `RELRO`, `NX`, `Stack Canary`), and symbol tables (`bsentinel inspect-elf`).
- [ ] **Cryptographic Constant & S-Box Scanner (`src/crypto_scan.rs`)** — Detect embedded cryptographic tables and constants in compiled binaries, including AES/Rijndael S-Boxes, ChaCha20/Salsa20 `"expand 32-byte k"` state constants, SHA-256/SHA-512 round constants, CRC32 lookup tables, and RSA public exponents (`bsentinel crypto-scan`).
- [ ] **PE Import/Export Table (IAT/EAT) & API Hash Resolver (`src/imports.rs`)** — Parse PE Data Directories for Import and Export tables, compute Import Hash (`imphash`), and resolve common shellcode/malware API hashes (`ROR13`, `CRC32`, `DJB2`, `FNV-1a`) against standard Windows DLL export names (`bsentinel imports`).
- [ ] **x86_64 Prologue/Epilogue & Control-Flow Pattern Scanner (`src/disasm.rs`)** — Lightweight instruction boundary scanner identifying function prologues, `SYSCALL`/`INT 2E` direct system call stubs, `RDTSC` timing checks, `CPUID` hypervisor checks, and indirect call gadgets (`bsentinel scan-code`).
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
