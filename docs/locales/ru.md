<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <strong>🇷🇺 Русский</strong> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

<p align="center">
  <img src="../assets/locales/ru/banner.svg" alt="BinSentinel (bsentinel) banner" width="100%" />
</p>

<div align="center">

# 🛡️ BinSentinel (bsentinel)

**Автономная бинарная криминалистика, статический анализатор PE/ELF, детектор энтропии упаковщиков и патчер байтов**

[![CI](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B_Safe-orange.svg)](../../SECURITY.md)
[![Roadmap](https://img.shields.io/badge/Roadmap-Active-10b981.svg)](../../ROADMAP.md)

</div>

---

## 🔍 Обзор

<details open>
<summary><b>🔍 Обзор</b></summary>
<br>

bin-sentinel (bsentinel) — это однофайловый консольный инструментарий на 100% безопасном Rust для статического анализа исполняемых файлов, первичного триажа в реверс-инжиниринге и декларативного байтового патчинга без внешних зависимостей.

</details>

---

## 🏛️ Архитектура и конвейер статического анализа

<details open>
<summary><b>🏛️ Архитектура и конвейер статического анализа</b></summary>
<br>

<p align="center">
  <img src="../assets/locales/ru/architecture.svg" alt="Архитектура и конвейер статического анализа" width="100%" />
</p>

| # | Модуль | Исходный файл | Ключевая функция и инвариант безопасности |
|---|---|---|---|
| **01** | **Статический парсер PE32/PE32+** | `src/pe.rs` | Парсинг заголовков DOS/COFF/Optional с проверкой границ, анализ флагов ASLR/DEP/CFG и секций RWX |
| **02** | **Энтропия и эвристика упаковщиков** | `src/entropy.rs` | Энтропия Шеннона (0..8 бит/байт), критерий Хи-квадрат и обнаружение UPX/VMProtect/Themida |
| **03** | **Сканер строк и индикаторов IoC** | `src/strings.rs` | Извлечение строк ASCII и UTF-16LE с классификацией URL, IPv4, ключей реестра и вызовов Win32 API |
| **04** | **Декларативный байтовый патчер** | `src/patch.rs` | Константно-временная сверка ожидаемых байтов, SHA-256 до/после патча, резервная копия .bak и Zeroize |
| **05** | **Структурированный CLI и JSON** | `src/cli.rs` | Детерминированный генератор тестовых PE64 (synth-pe) и машиночитаемый режим --json |

</details>

---

## ⚡ Быстрый старт и примеры использования

<details open>
<summary><b>⚡ Быстрый старт и примеры использования</b></summary>
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

# 15. Brute-force single/multi-byte XOR, ADD & ROL deobfuscation to uncover hidden IoCs and headers
bsentinel xor-scan sample.exe
bsentinel xor-scan sample.exe --json

# 16. Inspect PE Resource Directory (.rsrc), extract manifest, UAC execution levels & version info
bsentinel resources sample.exe
bsentinel resources sample.exe --json

# 17. Inspect PE TLS callbacks, pre-main execution hooks & x64 exception unwind (.pdata) tables
bsentinel callbacks sample.exe
bsentinel callbacks sample.exe --json
```

</details>

---

## 📦 Структура репозитория

<details open>
<summary><b>📦 Структура репозитория</b></summary>
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
│   ├── cli.rs                     # Clap derive subcommands (inspect, inspect-elf, imports, crypto-scan, scan-code, rule-scan, rich, xor-scan, etc.)
│   ├── commands/                  # Modular CLI subcommands (inspect, forensics, rules, diff, authenticode, macho, rich)
│   ├── error.rs                   # Unified SentinelError & Result<T>
│   ├── pe.rs                      # Zero-dependency PE32/PE32+ header & section parser + synthetic PE64 builder
│   ├── elf/                       # Zero-dependency Linux/BSD ELF64 parser (headers, mod, synthetic builder)
│   ├── imports/                   # PE Import/Export (IAT/EAT) parser, RFC 1321 MD5 imphash & dynamic API hash resolver
│   ├── crypto_scan/               # Embedded cryptographic primitives, AES/SM4 S-Boxes & hash constants scanner
│   ├── disasm/                    # x86_64 prologue/epilogue, direct syscalls & control-flow pattern scanner
│   ├── rules/                     # Declarative YARA-style hex signature, nibble wildcard & byte jump scanner
│   ├── rich/                      # PE Rich header decoder, MSVC compiler toolchain fingerprinter & checksum validator
│   ├── deobfuscate/               # Single/multi-byte XOR, ADD & ROL deobfuscation scanner & key recovery
│   ├── resources/                 # PE 3-level resource directory (.rsrc), application manifest & version info parser
│   ├── callbacks/                 # PE TLS callbacks, pre-main hooks & x64 .pdata exception unwind tables
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
│   ├── rich_test.rs               # Integration tests for PE Rich header decoding, toolchain fingerprinting & checksums
│   ├── deobfuscate_test.rs        # Integration tests for XOR/ADD/ROL deobfuscation, crib dragging & payload classifiers
│   ├── resources_test.rs          # Integration tests for PE resource directory tree, UAC manifest & version info
│   ├── callbacks_test.rs          # Integration tests for TLS callbacks, pre-main alerts, pdata tables & exception handlers
└── docs/
    ├── locales/                   # Localized READMEs (ko, zh-CN, es, hi, ar, pt-BR, ru, fr, id)
    └── assets/locales/            # Localized self-hosted SVG banners & architecture diagrams
```

</details>

---

## 🔒 Безопасность памяти и гарантии

<details open>
<summary><b>🔒 Безопасность памяти и гарантии</b></summary>
<br>

- 🛡️ Полное отсутствие блоков unsafe во всех парсерах; строгий контроль границ срезов и переполнений.
- 🛡️ Сравнение ожидаемых байтов за постоянное время (constant_time_eq) перед записью изменений.
- 🛡️ Расчет контрольных сумм SHA-256 до и после модификации файла с созданием резервной копии .bak.
- 🛡️ Принудительное затирание буферов в оперативной памяти через zeroize.

</details>

---

## 📄 Лицензия и авторство

<details open>
<summary><b>📄 Лицензия и авторство</b></summary>
<br>

Распространяется под лицензией Apache License 2.0 с файлом NOTICE. Правообладатель — GHSFS.

```text
Copyright 2026 GHSFS (https://github.com/GHSFS)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

</details>
