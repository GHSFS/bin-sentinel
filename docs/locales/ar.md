<div align="center">

[🇺🇸 English](../../README.md) · [🇰🇷 한국어](./ko.md) · [🇨🇳 中文](./zh-CN.md) · [🇪🇸 Español](./es.md) · [🇮🇳 हिन्दी](./hi.md) · **🇸🇦 العربية** · [🇧🇷 Português](./pt-BR.md) · [🇷🇺 Русский](./ru.md) · [🇫🇷 Français](./fr.md) · [🇮🇩 Bahasa Indonesia](./id.md)

</div>
<br>

<p align="center">
  <img src="../assets/locales/ar/banner.svg" alt="BinSentinel (bsentinel) banner" width="100%" />
</p>

<div align="center">

# 🛡️ BinSentinel (bsentinel)

**أداة التحليل الجنائي للملفات الثنائية، ومحلل PE/ELF الثابت، وكاشف الإنتروبيا وتعديل البايتات بلغة Rust**

[![CI](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B_Safe-orange.svg)](../../SECURITY.md)
[![Roadmap](https://img.shields.io/badge/Roadmap-Active-10b981.svg)](../../ROADMAP.md)

</div>

---

## 🔍 نظرة عامة

<details open>
<summary><b>🔍 نظرة عامة</b></summary>
<br>

أداة bin-sentinel (bsentinel) هي حزمة سطر أوامر مستقلة مكتوبة بالكامل بلغة Rust الآمنة لتحليل الملفات التنفيذية الثابتة، وفرز الهندسة العكسية، وتطبيق التعديلات الثنائية الموثقة بدقة عالية ودون أي اعتماديات خارجية.

</details>

---

## 🏛️ البنية الأساسية وخط أنابيب الفحص

<details open>
<summary><b>🏛️ البنية الأساسية وخط أنابيب الفحص</b></summary>
<br>

<p align="center">
  <img src="../assets/locales/ar/architecture.svg" alt="البنية الأساسية وخط أنابيب الفحص" width="100%" />
</p>

| # | الوحدة | ملف المصدر | القدرة الأساسية وضمانات الأمان |
|---|---|---|---|
| **01** | **محلل PE32/PE32+ الثابت** | `src/pe.rs` | تحليل موثوق الحدود لترويسات DOS/COFF/Optional وعلامات ASLR/DEP/CFG وكشف أقسام RWX الشاذة |
| **02** | **الإنتروبيا وكشف برامج الضغط** | `src/entropy.rs` | حساب إنتروبيا شانون واختبار مربع كاي وكشف توقيعات UPX وVMProtect وThemida |
| **03** | **ماسح النصوص ومؤشرات IoC** | `src/strings.rs` | استخراج نصوص ASCII وUTF-16LE وتصنيف الروابط وعناوين IPv4 ومفاتيح السجل وواجهات Win32 الحساسة |
| **04** | **محرك تعديل البايتات الموثق** | `src/patch.rs` | تحقق زمني ثابت من البايتات المتوقعة، وبصمات SHA-256 قبل وبعد التعديل مع نسخ احتياطي .bak ومسح الذاكرة |
| **05** | **واجهة CLI ومخرجات JSON** | `src/cli.rs` | مولد ملفات PE64 قياسية للاختبار ودعم مخرجات --json لخطوط التكامل المستمر |

</details>

---

## ⚡ البدء السريع واستخدام الأوامر

<details open>
<summary><b>⚡ البدء السريع واستخدام الأوامر</b></summary>
<br>

```bash
# 1. Build release binary
cargo build --release

# 2. Generate a deterministic synthetic PE32+ (64-bit) test binary
bsentinel synth-pe sample.exe

# 3. Inspect PE headers, ASLR/DEP/CFG mitigations, section table & packer heuristics
bsentinel inspect sample.exe
bsentinel inspect sample.exe --json

# 4. Run statistical Shannon entropy & Chi-square uniformity analysis
bsentinel entropy sample.exe --window 512
bsentinel entropy sample.exe --window 512 --json

# 5. Extract printable ASCII & UTF-16LE strings and filter Indicators of Compromise (IoCs)
bsentinel strings sample.exe --min-len 4
bsentinel strings sample.exe --ioc-only --json

# 6. Apply a verified declarative byte patch with expected-byte check and .bak backup
bsentinel patch sample.exe --offset 0x200 --expect 4883EC28 --replace 90909090 --backup --json
```

</details>

---

## 📦 هيكل المستودع

<details open>
<summary><b>📦 هيكل المستودع</b></summary>
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
│   ├── main.rs                    # CLI entry point & human/JSON output formatting
│   ├── cli.rs                     # Clap derive subcommands (inspect, entropy, strings, patch, synth-pe)
│   ├── error.rs                   # Unified SentinelError & Result<T>
│   ├── pe.rs                      # Zero-dependency PE32/PE32+ header & section parser + synthetic PE64 builder
│   ├── entropy.rs                 # Shannon entropy, Chi-Square uniformity & packer heuristic detector
│   ├── strings.rs                 # ASCII & UTF-16LE string extractor + IoC classifier
│   └── patch.rs                   # Constant-time verified byte patching engine with SHA-256 & Zeroize
├── tests/
│   ├── pe_entropy_test.rs         # Integration tests for PE64 parsing, mitigations, entropy & CLI JSON
│   └── patch_strings_test.rs      # Integration tests for IoC extraction, verified patching & backups
└── docs/
    ├── locales/                   # Localized READMEs (ko, zh-CN, es, hi, ar, pt-BR, ru, fr, id)
    └── assets/locales/            # Localized self-hosted SVG banners & architecture diagrams
```

</details>

---

## 🔒 سلامة الذاكرة وضمانات الأمان

<details open>
<summary><b>🔒 سلامة الذاكرة وضمانات الأمان</b></summary>
<br>

- 🛡️ خلو كامل من كتل unsafe في جميع محللات الترويسات مع فحص صارم للحدود.
- 🛡️ مقارنة البايتات المتوقعة بزمن ثابت (constant_time_eq) قبل كتابة أي تعديل.
- 🛡️ توثيق كامل عبر بصمات SHA-256 قبل التعديل وبعده مع دعم النسخ الاحتياطي التلقائي.
- 🛡️ تصفير المخازن المؤقتة الحساسة في الذاكرة فور انتهاء العملية باستخدام zeroize.

</details>

---

## 📄 الترخيص وحقوق الملكية

<details open>
<summary><b>📄 الترخيص وحقوق الملكية</b></summary>
<br>

مرخص بموجب Apache License 2.0 مع ملف NOTICE. مملوك لـ GHSFS.

```text
Copyright 2026 GHSFS (https://github.com/GHSFS)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

</details>
