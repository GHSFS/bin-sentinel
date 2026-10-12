<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <strong>🇨🇳 中文</strong> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

<p align="center">
  <img src="../assets/locales/zh-CN/banner.svg" alt="BinSentinel (bsentinel) banner" width="100%" />
</p>

<div align="center">

# 🛡️ BinSentinel (bsentinel)

**零依赖二进制取证、PE/ELF 静态分析器、加壳熵检测器与声明式字节补丁工具包**

[![CI](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B_Safe-orange.svg)](../../SECURITY.md)
[![Roadmap](https://img.shields.io/badge/Roadmap-Active-10b981.svg)](../../ROADMAP.md)

</div>

---

## 🔍 项目概述

<details open>
<summary><b>🔍 项目概述</b></summary>
<br>

bin-sentinel (bsentinel) 是一款采用 100% 安全 Rust 编写的单文件二进制静态分析、逆向工程初筛与声明式字节补丁命令行工具，无需任何外部运行时依赖即可对可执行文件进行快速、确定性的取证分析。

</details>

---

## 🏛️ 核心架构与静态分析流水线

<details open>
<summary><b>🏛️ 核心架构与静态分析流水线</b></summary>
<br>

<p align="center">
  <img src="../assets/locales/zh-CN/architecture.svg" alt="核心架构与静态分析流水线" width="100%" />
</p>

| # | 模块名称 | 源码路径 | 核心功能与安全约束 |
|---|---|---|---|
| **01** | **PE32/PE32+ 静态解析器** | `src/pe.rs` | 严格边界检查的 DOS/COFF/Optional 头部解析、ASLR/DEP/CFG 缓解标志与 RWX 异常节检测 |
| **02** | **统计熵与加壳启发式分析** | `src/entropy.rs` | 香农熵 (0..8 bits/B)、卡方均匀性检验以及 UPX/VMProtect/Themida 特征识别 |
| **03** | **静态字符串与 IoC 扫描器** | `src/strings.rs` | 提取 ASCII 与 UTF-16LE 字符串，自动归类 URL、IPv4、注册表路径与敏感 Win32 API |
| **04** | **声明式字节补丁引擎** | `src/patch.rs` | 常量时间预期字节比对、补丁前后 SHA-256 摘要计算、.bak 备份与 Zeroize 内存擦除 |
| **05** | **结构化 CLI 与 JSON 引擎** | `src/cli.rs` | 确定性测试 PE64 生成器 (synth-pe) 与面向自动化流水线的 --json 结构化输出 |

</details>

---

## ⚡ 快速上手与命令行示例

<details open>
<summary><b>⚡ 快速上手与命令行示例</b></summary>
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

# 8. Apply a verified declarative byte patch with expected-byte check and .bak backup
bsentinel patch sample.exe --offset 0x200 --expect 4883EC28 --replace 90909090 --backup --json
```

</details>

---

## 📦 仓库目录结构

<details open>
<summary><b>📦 仓库目录结构</b></summary>
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
│   ├── cli.rs                     # Clap derive subcommands (inspect, inspect-elf, crypto-scan, entropy, strings, patch)
│   ├── error.rs                   # Unified SentinelError & Result<T>
│   ├── pe.rs                      # Zero-dependency PE32/PE32+ header & section parser + synthetic PE64 builder
│   ├── elf/                       # Zero-dependency Linux/BSD ELF64 parser (headers, mod, synthetic builder)
│   ├── crypto_scan/               # Embedded cryptographic primitives, AES/SM4 S-Boxes & hash constants scanner
│   ├── entropy.rs                 # Shannon entropy, Chi-Square uniformity & packer heuristic detector
│   ├── strings.rs                 # ASCII & UTF-16LE string extractor + IoC classifier
│   └── patch.rs                   # Constant-time verified byte patching engine with SHA-256 & Zeroize
├── tests/
│   ├── pe_entropy_test.rs         # Integration tests for PE64 parsing, mitigations, entropy & CLI JSON
│   ├── patch_strings_test.rs      # Integration tests for IoC extraction, verified patching & backups
│   ├── elf_test.rs                # Integration tests for ELF64 parsing, PIE/RELRO/NX mitigations & dynamic symbols
│   └── crypto_scan_test.rs        # Integration tests for cryptographic constants, S-Boxes & PE/ELF section mapping
└── docs/
    ├── locales/                   # Localized READMEs (ko, zh-CN, es, hi, ar, pt-BR, ru, fr, id)
    └── assets/locales/            # Localized self-hosted SVG banners & architecture diagrams
```

</details>

---

## 🔒 内存安全与工程防线

<details open>
<summary><b>🔒 内存安全与工程防线</b></summary>
<br>

- 🛡️ 解析器全程零 unsafe 代码，所有偏移量与切片读取均经过溢出与边界校验。
- 🛡️ 应用字节补丁前执行常量时间比对 (constant_time_eq)，若目标字节不匹配则立即中止。
- 🛡️ 输出补丁前后的完整 SHA-256 哈希值，并提供可选的 .bak 原始文件备份。
- 🛡️ 补丁缓冲区在使用完毕后通过 zeroize 立即从内存中清零。

</details>

---

## 📄 许可证与归属声明

<details open>
<summary><b>📄 许可证与归属声明</b></summary>
<br>

基于 Apache License 2.0 与 NOTICE 声明发布，归 GHSFS 所有。

```text
Copyright 2026 GHSFS (https://github.com/GHSFS)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

</details>
