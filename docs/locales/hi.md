<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <strong>🇮🇳 हिन्दी</strong><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

<p align="center">
  <img src="../assets/locales/hi/banner.svg" alt="BinSentinel (bsentinel) banner" width="100%" />
</p>

<div align="center">

# 🛡️ BinSentinel (bsentinel)

**शून्य-निर्भरता बाइनरी फ़ोरेंसिक, PE/ELF स्टैटिक एनालाइज़र, पैकर एन्ट्रॉपी डिटेक्टर और बाइट-पैचिंग टूलकिट**

[![CI](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B_Safe-orange.svg)](../../SECURITY.md)
[![Roadmap](https://img.shields.io/badge/Roadmap-Active-10b981.svg)](../../ROADMAP.md)

</div>

---

## 🔍 अवलोकन

<details open>
<summary><b>🔍 अवलोकन</b></summary>
<br>

bin-sentinel (bsentinel) 100% सुरक्षित Rust में लिखा गया एकल-बाइनरी स्टैटिक निष्पादन योग्य विश्लेषण, रिवर्स-इंजीनियरिंग ट्राइएज और घोषणात्मक बाइट-पैचिंग CLI टूलकिट है।

</details>

---

## 🏛️ मुख्य आर्किटेक्चर और निरीक्षण पाइपलाइन

<details open>
<summary><b>🏛️ मुख्य आर्किटेक्चर और निरीक्षण पाइपलाइन</b></summary>
<br>

<p align="center">
  <img src="../assets/locales/hi/architecture.svg" alt="मुख्य आर्किटेक्चर और निरीक्षण पाइपलाइन" width="100%" />
</p>

| # | मॉड्यूल | स्रोत फ़ाइल | मुख्य क्षमता और सुरक्षा नियम |
|---|---|---|---|
| **01** | **PE32/PE32+ स्टैटिक पार्सर** | `src/pe.rs` | DOS/COFF/Optional हेडर, ASLR/DEP/CFG फ़्लैग और RWX विसंगतियों के लिए सीमा-जांच पार्सिंग |
| **02** | **एन्ट्रॉपी और पैकर ह्यूरिस्टिक्स** | `src/entropy.rs` | शैनन एन्ट्रॉपी (0..8 bits/B), काई-स्क्वायर एकरूपता और UPX/VMProtect/Themida पहचान |
| **03** | **स्ट्रिंग और IoC स्कैनर** | `src/strings.rs` | ASCII और UTF-16LE स्ट्रिंग्स निकालता है तथा URL, IPv4, रजिस्ट्री कुंजियों और Win32 API को वर्गीकृत करता है |
| **04** | **घोषणात्मक बाइट पैचर** | `src/patch.rs` | नियत-समय बाइट सत्यापन, पैच से पहले/बाद में SHA-256 डाइजेस्ट, .bak बैकअप और Zeroize |
| **05** | **संरचित CLI और JSON इंजन** | `src/cli.rs` | सिंथेटिक PE64 बिल्डर और स्वचालित पाइपलाइनों के लिए मशीन-पठनीय --json आउटपुट |

</details>

---

## ⚡ त्वरित शुरुआत और CLI उपयोग

<details open>
<summary><b>⚡ त्वरित शुरुआत और CLI उपयोग</b></summary>
<br>

```bash
# 1. Build release binary
cargo build --release

# 2. Generate a deterministic synthetic PE32+ (64-bit) test binary
bsentinel synth-pe sample.exe

# 3. Inspect PE headers, ASLR/DEP/CFG mitigations, section table & packer heuristics
bsentinel inspect sample.exe
bsentinel inspect sample.exe --json

# 4. Generate and inspect a deterministic synthetic Linux/BSD ELF64 binary
bsentinel synth-elf sample.elf
bsentinel inspect-elf sample.elf
bsentinel inspect-elf sample.elf --json

# 5. Run statistical Shannon entropy & Chi-square uniformity analysis
bsentinel entropy sample.exe --window 512
bsentinel entropy sample.exe --window 512 --json

# 6. Extract printable ASCII & UTF-16LE strings and filter Indicators of Compromise (IoCs)
bsentinel strings sample.exe --min-len 4
bsentinel strings sample.exe --ioc-only --json

# 7. Scan binary for embedded cryptographic constants, AES S-Boxes, SHA/ChaCha20 keys & CRC tables
bsentinel crypto-scan sample.exe
bsentinel crypto-scan sample.exe --json

# 8. Inspect PE Import/Export tables (IAT/EAT), compute imphash & resolve dynamic API hashes
bsentinel imports sample.exe
bsentinel imports sample.exe --resolve-hash 0x0726774C --json

# 9. Apply a verified declarative byte patch with expected-byte check and .bak backup
bsentinel patch sample.exe --offset 0x200 --expect 4883EC28 --replace 90909090 --backup --json

# 10. Scan x86_64 prologues, direct syscalls, RDTSC anti-debug & CPUID checks
bsentinel scan-code sample.exe
bsentinel scan-code sample.exe --json

# 11. Scan declarative YARA-style hex signatures with wildcards, byte jumps & JSON rules
bsentinel rule-scan sample.exe --pattern "48 83 EC ?? [2-6] E8"
bsentinel rule-scan sample.exe --rules rules.json --json

# 12. Compare two binaries structurally and export a declarative JSON patch recipe
bsentinel diff baseline.exe modified.exe --out-recipe patch.json
bsentinel diff baseline.exe modified.exe --json

# 13. Apply or reverse a declarative patch recipe with dry-run verification and backup
bsentinel apply-recipe baseline.exe patch.json --dry-run
bsentinel apply-recipe baseline.exe patch.json --backup
bsentinel apply-recipe baseline.exe patch.json --reverse

# 14. Decode PE Rich header, fingerprint Visual Studio toolchains & verify 32-bit checksum
bsentinel rich sample.exe
bsentinel rich sample.exe --json
```

</details>

---

## 📦 रिपॉजिटरी संरचना

<details open>
<summary><b>📦 रिपॉजिटरी संरचना</b></summary>
<br>

```text
bin-sentinel/
├── Cargo.toml                     # Pure-Rust package manifest (bsentinel binary + bin_sentinel lib)
├── README.md                      # Root English documentation with 10-language navigation
├── ROADMAP.md                     # Public engineering roadmap
├── CHANGELOG.md                   # Keep-a-Changelog release history
├── SECURITY.md                    # Binary parsing & memory safety policy
├── LICENSE                        # Apache License 2.0
├── NOTICE                         # Attribution notice owned by GHSFS
├── src/
│   ├── lib.rs                     # Library module exports
│   ├── main.rs                    # Streamlined CLI entry point dispatching to commands
│   ├── cli.rs                     # Clap derive subcommands (inspect, inspect-elf, imports, crypto-scan, scan-code, rule-scan, rich, etc.)
│   ├── commands/                  # Modular CLI subcommands (inspect, forensics, rules, diff, authenticode, macho, rich)
│   ├── error.rs                   # Unified SentinelError & Result<T>
│   ├── pe.rs                      # Zero-dependency PE32/PE32+ header & section parser + synthetic PE64 builder
│   ├── elf/                       # Zero-dependency Linux/BSD ELF64 parser (headers, mod, synthetic builder)
│   ├── imports/                   # PE Import/Export (IAT/EAT) parser, RFC 1321 MD5 imphash & dynamic API hash resolver
│   ├── crypto_scan/               # Embedded cryptographic primitives, AES/SM4 S-Boxes & hash constants scanner
│   ├── disasm/                    # x86_64 prologue/epilogue, direct syscalls & control-flow pattern scanner
│   ├── rules/                     # Declarative YARA-style hex signature, nibble wildcard & byte jump scanner
│   ├── rich/                      # PE Rich header decoder, MSVC compiler toolchain fingerprinter & checksum validator
│   ├── entropy.rs                 # Shannon entropy, Chi-Square uniformity & packer heuristic detector
│   ├── strings.rs                 # ASCII & UTF-16LE string extractor + IoC classifier
│   ├── patch.rs                   # Constant-time verified byte patching engine with SHA-256 & Zeroize
│   └── diff/                      # Structural binary diffing & declarative patch recipe engine
├── tests/
│   ├── pe_entropy_test.rs         # Integration tests for PE64 parsing, mitigations, entropy & CLI JSON
│   ├── patch_strings_test.rs      # Integration tests for IoC extraction, verified patching & backups
│   ├── elf_test.rs                # Integration tests for ELF64 parsing, PIE/RELRO/NX mitigations & dynamic symbols
│   ├── crypto_scan_test.rs        # Integration tests for cryptographic constants, S-Boxes & PE/ELF section mapping
│   ├── imports_test.rs            # Integration tests for PE IAT/EAT tables, imphash & dynamic API hash resolution
│   ├── disasm_test.rs             # Integration tests for x86_64 prologues, direct syscalls & anti-debug checks
│   ├── rules_test.rs              # Integration tests for YARA-style hex wildcards, jumps, strings & JSON rule sets
│   ├── diff_test.rs               # Integration tests for structural diffing, patch recipes & atomic reversal
│   └── rich_test.rs               # Integration tests for PE Rich header decoding, toolchain fingerprinting & checksums
└── docs/
    ├── locales/                   # Localized READMEs (ko, zh-CN, es, hi, ar, pt-BR, ru, fr, id)
    └── assets/locales/            # Localized self-hosted SVG banners & architecture diagrams
```

</details>

---

## 🔒 मेमोरी सुरक्षा और सुरक्षा सिद्धांत

<details open>
<summary><b>🔒 मेमोरी सुरक्षा और सुरक्षा सिद्धांत</b></summary>
<br>

- 🛡️ सभी बाइनरी हेडर पार्सर्स में शून्य unsafe कोड; प्रत्येक ऑफ़सेट और स्लाइस की सीमा जांची जाती है।
- 🛡️ किसी भी बाइनरी पैच को लागू करने से पहले नियत-समय (constant_time_eq) बाइट मिलान।
- 🛡️ वैकल्पिक .bak बैकअप के साथ प्री-पैच और पोस्ट-पैच SHA-256 डाइजेस्ट की गणना।
- 🛡️ zeroize के माध्यम से संवेदनशील बफ़र्स की मेमोरी सफ़ाई।

</details>

---

## 📄 लाइसेंस और श्रेय

<details open>
<summary><b>📄 लाइसेंस और श्रेय</b></summary>
<br>

NOTICE फ़ाइल के साथ Apache License 2.0 के अंतर्गत लाइसेंस प्राप्त। GHSFS के स्वामित्व में।

```text
Copyright 2026 GHSFS (https://github.com/GHSFS)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

</details>
