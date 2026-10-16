<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <strong>🇫🇷 Français</strong> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

<p align="center">
  <img src="../assets/locales/fr/banner.svg" alt="Bannière BinSentinel (bsentinel)" width="100%" />
</p>

<div align="center">

# 🛡️ BinSentinel (bsentinel)

**Analyse forensique de binaires sans dépendance, analyseur statique PE/ELF, détecteur d'entropie de packers et kit de patch d'octets déclaratif**

[![CI](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B_Safe-orange.svg)](../../SECURITY.md)
[![Roadmap](https://img.shields.io/badge/Roadmap-Active-10b981.svg)](../../ROADMAP.md)

</div>

---

## 🔍 Aperçu

<details open>
<summary><b>🔍 Aperçu</b></summary>
<br>

bin-sentinel (bsentinel) est une boîte à outils en binaire unique pour l'analyse statique d'exécutables, le triage en rétro-ingénierie et l'application déclarative de correctifs d'octets, entièrement écrite en Rust 100 % sûr. Conçu pour les analystes en sécurité, les chercheurs en logiciels malveillants et les ingénieurs système nécessitant une inspection déterministe et ultra-rapide de binaires non fiables sans dépendances externes lourdes.

</details>

---

## 🏛️ Architecture centrale et pipeline d'inspection

<details open>
<summary><b>🏛️ Architecture centrale et pipeline d'inspection</b></summary>
<br>

<p align="center">
  <img src="../assets/locales/fr/architecture.svg" alt="Architecture centrale et pipeline d'inspection" width="100%" />
</p>

| # | Nom du module | Fichier source | Capacité principale et invariant de sécurité |
|---|---|---|---|
| **01** | **Analyseur statique PE32/PE32+** | `src/pe.rs` | Analyse sécurisée avec contrôle des limites des en-têtes DOS/COFF/Optionnels, des atténuations ASLR/DEP/CFG et des anomalies RWX |
| **02** | **Entropie et heuristiques de packers** | `src/entropy.rs` | Entropie de Shannon (0..8 bits/B), test d'uniformité du Chi-carré et détection de signatures UPX/VMProtect/Themida |
| **03** | **Scanner de chaînes statiques et IoC** | `src/strings.rs` | Extraction de chaînes ASCII et UTF-16LE avec classification des URL, IPv4, clés de registre et API critiques Win32 |
| **04** | **Applicateur déclaratif de patchs d'octets** | `src/patch.rs` | Vérification en temps constant des octets attendus, empreintes SHA-256 avant/après patch, sauvegarde .bak et effacement Zeroize |
| **05** | **CLI structurée et moteur JSON** | `src/cli.rs` | Générateur déterministe de PE64 de test (synth-pe) et sortie lisible par machine --json pour les pipelines CI |

</details>

---

## ⚡ Démarrage rapide et commandes CLI

<details open>
<summary><b>⚡ Démarrage rapide et commandes CLI</b></summary>
<br>

```bash
# 1. Compiler le binaire optimisé pour la production
cargo build --release

# 2. Générer un exécutable de test synthétique déterministe PE32+ (64 bits)
bsentinel synth-pe sample.exe

# 3. Inspecter les en-têtes PE, les atténuations ASLR/DEP/CFG, la table des sections et les heuristiques de packers
bsentinel inspect sample.exe
bsentinel inspect sample.exe --json

# 4. Générer et inspecter un binaire synthétique déterministe Linux/BSD ELF64
bsentinel synth-elf sample.elf
bsentinel inspect-elf sample.elf
bsentinel inspect-elf sample.elf --json

# 5. Exécuter l'analyse statistique d'entropie de Shannon et d'uniformité du Chi-carré
bsentinel entropy sample.exe --window 512
bsentinel entropy sample.exe --window 512 --json

# 6. Extraire les chaînes imprimables ASCII et UTF-16LE et filtrer les indicateurs de compromission (IoC)
bsentinel strings sample.exe --min-len 4
bsentinel strings sample.exe --ioc-only --json

# 7. Scanner le binaire pour détecter les constantes cryptographiques, les S-Boxes AES, les clés SHA/ChaCha20 et les tables CRC
bsentinel crypto-scan sample.exe
bsentinel crypto-scan sample.exe --json

# 8. Inspecter les tables d'import/export PE (IAT/EAT), calculer l'imphash et résoudre les hachages dynamiques d'API
bsentinel imports sample.exe
bsentinel imports sample.exe --resolve-hash 0x0726774C --json

# 9. Appliquer un correctif d'octets déclaratif vérifié avec contrôle des octets attendus et sauvegarde .bak
bsentinel patch sample.exe --offset 0x200 --expect 4883EC28 --replace 90909090 --backup --json

# 10. Scanner les prologues x86_64, les appels système directs (Direct Syscalls), les vérifications anti-débogage RDTSC et CPUID
bsentinel scan-code sample.exe
bsentinel scan-code sample.exe --json

# 11. Scanner des signatures hexadécimales déclaratives de style YARA avec jokers, sauts d'octets et règles JSON
bsentinel rule-scan sample.exe --pattern "48 83 EC ?? [2-6] E8"
bsentinel rule-scan sample.exe --rules rules.json --json

# 12. Comparer deux binaires structurellement et exporter une recette déclarative de patch en JSON
bsentinel diff baseline.exe modified.exe --out-recipe patch.json
bsentinel diff baseline.exe modified.exe --json

# 13. Appliquer ou inverser une recette de patch déclarative avec simulation préalable (dry-run) et sauvegarde
bsentinel apply-recipe baseline.exe patch.json --dry-run
bsentinel apply-recipe baseline.exe patch.json --backup
bsentinel apply-recipe baseline.exe patch.json --reverse

# 14. Décoder l'en-tête PE Rich, identifier les chaînes d'outils Visual Studio et vérifier la somme de contrôle 32 bits
bsentinel rich sample.exe
bsentinel rich sample.exe --json

# 15. Forcer par force brute la désanonymisation XOR, ADD et ROL d'un ou plusieurs octets pour révéler les IoC et en-têtes
bsentinel xor-scan sample.exe
bsentinel xor-scan sample.exe --json

# 16. Inspecter le répertoire de ressources PE (.rsrc), extraire le manifeste, les niveaux d'exécution UAC et les versions
bsentinel resources sample.exe
bsentinel resources sample.exe --json

# 17. Inspecter les rappels TLS de PE, les hooks d'exécution pré-main et les tables de déroulement d'exception x64 (.pdata)
bsentinel callbacks sample.exe
bsentinel callbacks sample.exe --json

# 18. Extraire et décoder en toute sécurité les charges utiles incorporées en Base64, URL-Safe Base64 et hexadécimal
bsentinel carve sample.exe
bsentinel carve sample.exe --extract-dir ./extracted_payloads --json

# 19. Calculer l'empreinte de similarité floue par blocs de hachage glissant (CTPH / SSDEEP) et les empreintes de sections
bsentinel fuzzy-hash sample.exe
bsentinel fuzzy-hash sample.exe --json

# 20. Comparer les artefacts binaires et corréler les scores de similarité floue section par section (0..=100)
bsentinel fuzzy-compare original.exe modified.exe
bsentinel fuzzy-compare original.exe modified.exe --json
```

</details>

---

## 📦 Structure du dépôt et arborescence des sources

<details open>
<summary><b>📦 Structure du dépôt et arborescence des sources</b></summary>
<br>

```text
bin-sentinel/
├── Cargo.toml                     # Manifeste de paquet en pur Rust (binaire bsentinel et bibliothèque bin_sentinel)
├── README.md                      # Documentation racine en anglais avec navigation en 10 langues
├── ROADMAP.md                     # Feuille de route technique publique
├── CHANGELOG.md                   # Historique des versions géré selon Keep-a-Changelog
├── SECURITY.md                    # Analyse de binaires et politique de sécurité de la mémoire
├── LICENSE                        # Licence Apache 2.0
├── NOTICE                         # Mention de droit d'auteur et d'attribution détenue par GHSFS
├── src/
│   ├── lib.rs                     # Exportations de l'interface publique de la bibliothèque
│   ├── main.rs                    # Point d'entrée concis de la CLI pour la distribution des commandes
│   ├── cli.rs                     # Définitions des sous-commandes et arguments avec Clap (inspect, imports, rich, carve, etc.)
│   ├── commands/                  # Gestionnaires modulaires des sous-commandes CLI (inspect, forensics, rules, diff, rich, etc.)
│   ├── error.rs                   # Modèle unifié d'erreurs SentinelError et Result<T>
│   ├── pe.rs                      # Analyseur sans dépendance d'en-têtes/sections PE32/PE32+ et générateur PE64
│   ├── elf/                       # Analyseur sans dépendance de binaires Linux/BSD ELF64 (en-têtes, modules, générateur)
│   ├── imports/                   # Analyseur d'import/export PE (IAT/EAT), imphash MD5 et résolution des hachages d'API
│   ├── crypto_scan/               # Scanner de primitives cryptographiques, S-Boxes AES/SM4 et constantes de hachage
│   ├── disasm/                    # Scanner de prologues/épilogues x86_64, appels système directs et flux de contrôle
│   ├── rules/                     # Scanner déclaratif style YARA de signatures hexadécimales, jokers et sauts
│   ├── rich/                      # Décodeur d'en-tête PE Rich, empreintes d'outils MSVC et validateur de somme de contrôle
│   ├── deobfuscate/               # Scanner de désobscurcissement XOR, ADD et ROL d'un/plusieurs octets et récupération de clés
│   ├── resources/                 # Analyseur de ressources PE à 3 niveaux (.rsrc), manifeste et métadonnées de version
│   ├── callbacks/                 # Callbacks TLS de PE, hooks pré-main et tables de déroulement d'exception x64 (.pdata)
│   ├── carve/                     # Extraction, décodage et classification de charges utiles Base64, URL-Safe Base64 et hex
│   ├── fuzzy_hash/                # Moteur de hachage glissant CTPH, mise à l'échelle double de bloc et comparaison de similarité
│   ├── entropy.rs                 # Entropie de Shannon, test du Chi-carré et détecteur de packers
│   ├── strings.rs                 # Extracteur de chaînes ASCII et UTF-16LE + classificateur automatique d'IoC
│   ├── patch.rs                   # Moteur de patchs d'octets vérifié en temps constant avec SHA-256 et Zeroize
│   └── diff/                      # Comparaison binaire structurelle et moteur de recettes déclaratives de patchs
├── tests/
│   ├── pe_entropy_test.rs         # Tests d'analyse PE64, atténuations, entropie et sortie JSON de la CLI
│   ├── patch_strings_test.rs      # Tests d'extraction d'IoC, application vérifiée de patchs et sauvegardes
│   ├── elf_test.rs                # Tests d'analyse ELF64, atténuations PIE/RELRO/NX et symboles dynamiques
│   ├── crypto_scan_test.rs        # Tests de constantes cryptographiques, S-Boxes et mappage de sections PE/ELF
│   ├── imports_test.rs            # Tests des tables PE IAT/EAT, calcul d'imphash et résolution de hachages d'API
│   ├── carve_test.rs              # Tests d'extraction Base64/Hex, charges PowerShell et vidage sécurisé
│   ├── disasm_test.rs             # Tests de prologues x86_64, appels système directs et contrôles anti-débogage
│   ├── rules_test.rs              # Tests de jokers hexadécimaux style YARA, sauts, chaînes et règles JSON
│   ├── diff_test.rs               # Tests de comparaison structurelle, recettes de patchs et retour atomique
│   ├── rich_test.rs               # Tests de décodage d'en-tête PE Rich, empreintes d'outils et somme de contrôle
│   ├── deobfuscate_test.rs        # Tests de désobscurcissement XOR/ADD/ROL, glissement de texte connu et classification
│   ├── resources_test.rs          # Tests de l'arborescence des ressources PE, manifeste UAC et informations de version
│   ├── callbacks_test.rs          # Tests de callbacks TLS, alertes pré-main, tables pdata et gestionnaires d'exception
│   ├── fuzzy_hash_test.rs         # Tests de hachage flou CTPH, distance de Levenshtein et comparaison de binaires
└── docs/
    ├── locales/                   # Documentation traduite en plusieurs langues (ko, zh-CN, es, hi, ar, pt-BR, ru, fr, id)
    └── assets/locales/            # Bannières SVG auto-hébergées et diagrammes d'architecture traduits
```

</details>

---

## 🔒 Sécurité de la mémoire et invariants de protection

<details open>
<summary><b>🔒 Sécurité de la mémoire et invariants de protection</b></summary>
<br>

- 🛡️ Zéro bloc `unsafe` dans l'ensemble des analyseurs d'en-têtes binaires : chaque lecture de décalage et de tranche utilise une arithmétique avec vérification des limites.
- 🛡️ Vérification des octets en temps constant (`constant_time_eq`) avant d'appliquer tout correctif binaire, avec annulation immédiate par `PatchMismatch` en cas d'écart.
- 🛡️ Piste d'audit cryptographique complète : calcule et rapporte les condensats SHA-256 pré et post-patch, avec génération optionnelle de sauvegardes `.bak`.
- 🛡️ Effacement proactif de la mémoire via `zeroize` sur les tampons de patchs binaires mutables lors de leur désallocation.

</details>

---

## 📄 Licence et attribution

<details open>
<summary><b>📄 Licence et attribution</b></summary>
<br>

Distribué sous la licence Apache, version 2.0 avec fichier d'attribution NOTICE. Détenu par GHSFS.

```text
Copyright 2026 GHSFS (https://github.com/GHSFS)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

</details>
