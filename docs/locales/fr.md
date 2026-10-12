<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <strong>🇫🇷 Français</strong> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

<p align="center">
  <img src="../assets/locales/fr/banner.svg" alt="BinSentinel (bsentinel) banner" width="100%" />
</p>

<div align="center">

# 🛡️ BinSentinel (bsentinel)

**Forensique Binaire Sans Dépendance, Analyseur Statique PE/ELF, Détecteur d’Entropie et Patching d’Octets**

[![CI](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B_Safe-orange.svg)](../../SECURITY.md)
[![Roadmap](https://img.shields.io/badge/Roadmap-Active-10b981.svg)](../../ROADMAP.md)

</div>

---

## 🔍 Présentation Générale

<details open>
<summary><b>🔍 Présentation Générale</b></summary>
<br>

bin-sentinel (bsentinel) est une boîte à outils en ligne de commande compilée en un seul binaire et écrite en Rust 100 % sûr, dédiée à l’analyse statique d’exécutables, au triage en rétro-ingénierie et à l’application déclarative de correctifs binaires.

</details>

---

## 🏛️ Architecture Principale et Pipeline d’Inspection

<details open>
<summary><b>🏛️ Architecture Principale et Pipeline d’Inspection</b></summary>
<br>

<p align="center">
  <img src="../assets/locales/fr/architecture.svg" alt="Architecture Principale et Pipeline d’Inspection" width="100%" />
</p>

| # | Module | Fichier Source | Capacité Clé et Invariant de Sécurité |
|---|---|---|---|
| **01** | **Analyseur Statique PE32/PE32+** | `src/pe.rs` | Analyse avec vérification stricte des bornes DOS/COFF/Optional, drapeaux ASLR/DEP/CFG et anomalies RWX |
| **02** | **Entropie et Heuristique de Packers** | `src/entropy.rs` | Entropie de Shannon (0..8 bits/o), test d’uniformité du Khi-Deux et détection UPX/VMProtect/Themida |
| **03** | **Extracteur de Chaînes et IoCs** | `src/strings.rs` | Extrait les chaînes ASCII et UTF-16LE et classe les URL, IPv4, clés de registre et API Win32 sensibles |
| **04** | **Moteur de Patch Déclaratif** | `src/patch.rs` | Vérification en temps constant des octets attendus, empreintes SHA-256 avant/après, sauvegarde .bak et Zeroize |
| **05** | **Interface CLI et Sortie JSON** | `src/cli.rs` | Générateur déterministe de binaires PE64 synthétiques et sortie structurée --json pour pipelines CI |

</details>

---

## ⚡ Démarrage Rapide et Utilisation CLI

<details open>
<summary><b>⚡ Démarrage Rapide et Utilisation CLI</b></summary>
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

# 7. Apply a verified declarative byte patch with expected-byte check and .bak backup
bsentinel patch sample.exe --offset 0x200 --expect 4883EC28 --replace 90909090 --backup --json
```

</details>

---

## 📦 Structure du Dépôt

<details open>
<summary><b>📦 Structure du Dépôt</b></summary>
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
│   ├── cli.rs                     # Clap derive subcommands (inspect, inspect-elf, entropy, strings, patch, synth-pe, synth-elf)
│   ├── error.rs                   # Unified SentinelError & Result<T>
│   ├── pe.rs                      # Zero-dependency PE32/PE32+ header & section parser + synthetic PE64 builder
│   ├── elf/                       # Zero-dependency Linux/BSD ELF64 parser (headers, mod, synthetic builder)
│   ├── entropy.rs                 # Shannon entropy, Chi-Square uniformity & packer heuristic detector
│   ├── strings.rs                 # ASCII & UTF-16LE string extractor + IoC classifier
│   └── patch.rs                   # Constant-time verified byte patching engine with SHA-256 & Zeroize
├── tests/
│   ├── pe_entropy_test.rs         # Integration tests for PE64 parsing, mitigations, entropy & CLI JSON
│   ├── patch_strings_test.rs      # Integration tests for IoC extraction, verified patching & backups
│   └── elf_test.rs                # Integration tests for ELF64 parsing, PIE/RELRO/NX mitigations & dynamic symbols
└── docs/
    ├── locales/                   # Localized READMEs (ko, zh-CN, es, hi, ar, pt-BR, ru, fr, id)
    └── assets/locales/            # Localized self-hosted SVG banners & architecture diagrams
```

</details>

---

## 🔒 Sécurité Mémoire et Invariants

<details open>
<summary><b>🔒 Sécurité Mémoire et Invariants</b></summary>
<br>

- 🛡️ Aucun bloc unsafe dans les analyseurs binaires ; chaque lecture vérifie les limites et les dépassements d’entiers.
- 🛡️ Comparaison en temps constant (constant_time_eq) des octets cibles avant toute modification du fichier.
- 🛡️ Calcul systématique des empreintes SHA-256 avant et après application du correctif avec option de sauvegarde .bak.
- 🛡️ Effacement proactif des tampons mémoire via zeroize.

</details>

---

## 📄 Licence et Attribution

<details open>
<summary><b>📄 Licence et Attribution</b></summary>
<br>

Publié sous licence Apache License 2.0 avec fichier NOTICE. Propriété de GHSFS.

```text
Copyright 2026 GHSFS (https://github.com/GHSFS)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

</details>
