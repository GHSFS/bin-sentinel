<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <strong>🇮🇩 Bahasa Indonesia</strong>
</p>

<p align="center">
  <img src="../assets/locales/id/banner.svg" alt="BinSentinel (bsentinel) banner" width="100%" />
</p>

<div align="center">

# 🛡️ BinSentinel (bsentinel)

**Forensik Biner Tanpa Dependensi, Penganalisis Statis PE/ELF, Detektor Entropi Packer & Alat Patching Byte**

[![CI](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B_Safe-orange.svg)](../../SECURITY.md)
[![Roadmap](https://img.shields.io/badge/Roadmap-Active-10b981.svg)](../../ROADMAP.md)

</div>

---

## 🔍 Ringkasan

<details open>
<summary><b>🔍 Ringkasan</b></summary>
<br>

bin-sentinel (bsentinel) adalah perangkat baris perintah biner tunggal yang ditulis dalam 100% safe Rust untuk analisis statis file eksekusi, triase rekayasa balik (reverse engineering), dan penerapan patch byte deklaratif tanpa dependensi runtime eksternal.

</details>

---

## 🏛️ Arsitektur Inti & Alur Inspeksi

<details open>
<summary><b>🏛️ Arsitektur Inti & Alur Inspeksi</b></summary>
<br>

<p align="center">
  <img src="../assets/locales/id/architecture.svg" alt="Arsitektur Inti & Alur Inspeksi" width="100%" />
</p>

| # | Modul | File Sumber | Kemampuan Utama & Invarian Keamanan |
|---|---|---|---|
| **01** | **Parser Statis PE32/PE32+** | `src/pe.rs` | Parsing header DOS/COFF/Optional dengan pemeriksaan batas ketat, flag ASLR/DEP/CFG & deteksi anomali RWX |
| **02** | **Entropi & Heuristik Packer** | `src/entropy.rs` | Entropi Shannon (0..8 bit/B), keseragaman Chi-Square & deteksi tanda UPX/VMProtect/Themida |
| **03** | **Pemindai String & IoC Statis** | `src/strings.rs` | Ekstraksi string ASCII & UTF-16LE serta klasifikasi URL, IPv4, kunci Registri & API Win32 sensitif |
| **04** | **Mesin Patch Byte Deklaratif** | `src/patch.rs` | Verifikasi byte waktu-konstan, digest SHA-256 sebelum/sesudah patch, cadangan .bak & Zeroize |
| **05** | **CLI Terstruktur & Mesin JSON** | `src/cli.rs` | Pembuat PE64 sintetis deterministik (synth-pe) dan output --json yang dapat dibaca mesin |

</details>

---

## ⚡ Panduan Cepat & Penggunaan CLI

<details open>
<summary><b>⚡ Panduan Cepat & Penggunaan CLI</b></summary>
<br>

```bash
# 1. Bangun biner rilis
cargo build --release

# 2. Hasilkan biner uji PE32+ (64-bit) sintetis deterministik
bsentinel synth-pe sample.exe

# 3. Periksa header PE, mitigasi ASLR/DEP/CFG, tabel seksi & heuristik packer
bsentinel inspect sample.exe
bsentinel inspect sample.exe --json

# 4. Hasilkan dan periksa biner ELF64 Linux/BSD sintetis deterministik
bsentinel synth-elf sample.elf
bsentinel inspect-elf sample.elf
bsentinel inspect-elf sample.elf --json

# 5. Jalankan analisis entropi Shannon statistik & keseragaman Chi-square
bsentinel entropy sample.exe --window 512
bsentinel entropy sample.exe --window 512 --json

# 6. Ekstrak string ASCII & UTF-16LE yang dapat dicetak dan filter Indikator Kompromi (IoC)
bsentinel strings sample.exe --min-len 4
bsentinel strings sample.exe --ioc-only --json

# 7. Pindai konstanta kriptografi tertanam, S-Box AES, kunci SHA/ChaCha20 & tabel CRC pada biner
bsentinel crypto-scan sample.exe
bsentinel crypto-scan sample.exe --json

# 8. Periksa tabel Impor/Ekspor PE (IAT/EAT), hitung imphash & pecahkan hash API dinamis
bsentinel imports sample.exe
bsentinel imports sample.exe --resolve-hash 0x0726774C --json

# 9. Terapkan patch byte deklaratif terverifikasi dengan pemeriksaan byte yang diharapkan dan cadangan .bak
bsentinel patch sample.exe --offset 0x200 --expect 4883EC28 --replace 90909090 --backup --json

# 10. Pindai prolog x86_64, syscall langsung, anti-debug RDTSC & pemeriksaan CPUID
bsentinel scan-code sample.exe
bsentinel scan-code sample.exe --json

# 11. Pindai tanda tangan heksadesimal gaya YARA deklaratif dengan wildcard, lompatan byte & aturan JSON
bsentinel rule-scan sample.exe --pattern "48 83 EC ?? [2-6] E8"
bsentinel rule-scan sample.exe --rules rules.json --json

# 12. Bandingkan dua biner secara struktural dan ekspor resep patch JSON deklaratif
bsentinel diff baseline.exe modified.exe --out-recipe patch.json
bsentinel diff baseline.exe modified.exe --json

# 13. Terapkan atau pulihkan resep patch deklaratif dengan verifikasi uji coba (dry-run) dan cadangan
bsentinel apply-recipe baseline.exe patch.json --dry-run
bsentinel apply-recipe baseline.exe patch.json --backup
bsentinel apply-recipe baseline.exe patch.json --reverse

# 14. Dekode header Rich PE, sidik jari rantai alat Visual Studio & verifikasi checksum 32-bit
bsentinel rich sample.exe
bsentinel rich sample.exe --json

# 15. Deobfuskasi XOR, ADD & ROL byte tunggal/ganda secara brute-force untuk mengungkap IoC dan header tersembunyi
bsentinel xor-scan sample.exe
bsentinel xor-scan sample.exe --json

# 16. Periksa Direktori Sumber Daya PE (.rsrc), ekstrak manifes, tingkat eksekusi UAC & info versi
bsentinel resources sample.exe
bsentinel resources sample.exe --json

# 17. Periksa panggilan balik TLS PE, hook eksekusi pra-utama & tabel pelepasan eksepsi x64 (.pdata)
bsentinel callbacks sample.exe
bsentinel callbacks sample.exe --json

# 18. Gali dan dekode muatan Base64, URL-safe Base64 & heksadesimal tertanam dengan ekstraksi aman
bsentinel carve sample.exe
bsentinel carve sample.exe --extract-dir ./extracted_payloads --json

# 19. Hitung intisari kemiripan fuzzy bertahap rolling-hash (CTPH / SSDEEP) dan sidik jari seksi
bsentinel fuzzy-hash sample.exe
bsentinel fuzzy-hash sample.exe --json

# 20. Bandingkan artefak biner dan korelasi skor kemiripan fuzzy seksi demi seksi (0..=100)
bsentinel fuzzy-compare original.exe modified.exe
bsentinel fuzzy-compare original.exe modified.exe --json
```

</details>

---

## 📦 Struktur Repositori

<details open>
<summary><b>📦 Struktur Repositori</b></summary>
<br>

```text
bin-sentinel/
├── Cargo.toml                     # Manifes paket Pure-Rust (biner bsentinel + pustaka bin_sentinel)
├── README.md                      # Dokumentasi bahasa Inggris root dengan navigasi 10 bahasa
├── ROADMAP.md                     # Peta jalan rekayasa publik
├── CHANGELOG.md                   # Riwayat rilis Keep-a-Changelog
├── SECURITY.md                    # Kebijakan parsing biner & keamanan memori
├── LICENSE                        # Lisensi Apache 2.0
├── NOTICE                         # Pemberitahuan atribusi milik GHSFS
├── src/
│   ├── lib.rs                     # Ekspor modul pustaka
│   ├── main.rs                    # Titik masuk CLI ringkas yang mendistribusikan perintah
│   ├── cli.rs                     # Subperintah derive Clap (inspect, inspect-elf, imports, crypto-scan, scan-code, rule-scan, rich, xor-scan, carve, dll.)
│   ├── commands/                  # Subperintah CLI modular (inspect, forensics, rules, diff, authenticode, macho, rich, callbacks, carve, fuzzy)
│   ├── error.rs                   # SentinelError & Result<T> terpadu
│   ├── pe.rs                      # Parser header & seksi PE32/PE32+ tanpa dependensi + pembuat PE64 sintetis
│   ├── elf/                       # Parser ELF64 Linux/BSD tanpa dependensi (header, mod, pembuat sintetis)
│   ├── imports/                   # Parser Impor/Ekspor PE (IAT/EAT), imphash MD5 RFC 1321 & pemecah hash API dinamis
│   ├── crypto_scan/               # Pemindai primitif kriptografi tertanam, S-Box AES/SM4 & konstanta hash
│   ├── disasm/                    # Pemindai pola prolog/epilog x86_64, syscall langsung & alur kendali
│   ├── rules/                     # Pemindai tanda tangan heksadesimal gaya YARA deklaratif, wildcard nibble & lompatan byte
│   ├── rich/                      # Dekoder header Rich PE, pembuat sidik jari rantai alat kompilator MSVC & validator checksum
│   ├── deobfuscate/               # Pemindai deobfuskasi XOR, ADD & ROL byte tunggal/ganda serta pemulihan kunci
│   ├── resources/                 # Direktori sumber daya 3 tingkat PE (.rsrc), manifes aplikasi & parser info versi
│   ├── callbacks/                 # Panggilan balik TLS PE, hook pra-utama & tabel pelepasan eksepsi x64 .pdata
│   ├── carve/                     # Penggalian muatan Base64, URL-safe Base64 & heksadesimal, dekode & klasifikasi
│   ├── fuzzy_hash/                # Mesin rolling hash CTPH, penskalaan ukuran blok ganda & perbandingan kemiripan biner
│   ├── entropy.rs                 # Entropi Shannon, keseragaman Chi-Square & detektor heuristik packer
│   ├── strings.rs                 # Ekstraktor string ASCII & UTF-16LE + pengklasifikasi IoC
│   ├── patch.rs                   # Mesin patching byte terverifikasi waktu-konstan dengan SHA-256 & Zeroize
│   └── diff/                      # Mesin perbandingan biner struktural & resep patch deklaratif
├── tests/
│   ├── pe_entropy_test.rs         # Pengujian integrasi untuk parsing PE64, mitigasi, entropi & JSON CLI
│   ├── patch_strings_test.rs      # Pengujian integrasi untuk ekstraksi IoC, patching terverifikasi & cadangan
│   ├── elf_test.rs                # Pengujian integrasi untuk parsing ELF64, mitigasi PIE/RELRO/NX & simbol dinamis
│   ├── crypto_scan_test.rs        # Pengujian integrasi untuk konstanta kriptografi, S-Box & pemetaan seksi PE/ELF
│   ├── imports_test.rs            # Pengujian integrasi untuk tabel IAT/EAT PE, imphash & resolusi hash API dinamis
│   ├── carve_test.rs              # Pengujian integrasi untuk penggalian Base64/Hex, cradle PowerShell, ekstraksi aman & CLI
│   ├── disasm_test.rs             # Pengujian integrasi untuk prolog x86_64, syscall langsung & pemeriksaan anti-debug
│   ├── rules_test.rs              # Pengujian integrasi untuk wildcard heksadesimal gaya YARA, lompatan, string & set aturan JSON
│   ├── diff_test.rs               # Pengujian integrasi untuk perbandingan struktural, resep patch & pembalikan atomik
│   ├── rich_test.rs               # Pengujian integrasi untuk dekode header Rich PE, sidik jari rantai alat & checksum
│   ├── deobfuscate_test.rs        # Pengujian integrasi untuk deobfuskasi XOR/ADD/ROL, crib dragging & pengklasifikasi muatan
│   ├── resources_test.rs          # Pengujian integrasi untuk pohon direktori sumber daya PE, manifes UAC & info versi
│   ├── callbacks_test.rs          # Pengujian integrasi untuk panggilan balik TLS, peringatan pra-utama, tabel pdata & penangan eksepsi
│   ├── fuzzy_hash_test.rs         # Pengujian integrasi untuk fuzzy hashing CTPH, jarak Levenshtein & perbandingan biner
└── docs/
    ├── locales/                   # README terlokalisasi (ko, zh-CN, es, hi, ar, pt-BR, ru, fr, id)
    └── assets/locales/            # Spanduk SVG & diagram arsitektur mandiri terlokalisasi
```

</details>

---

## 🔒 Keamanan Memori & Invarian Keamanan

<details open>
<summary><b>🔒 Keamanan Memori & Invarian Keamanan</b></summary>
<br>

- 🛡️ Nol blok unsafe di seluruh parser header biner; setiap pembacaan offset memeriksa batas ukuran file.
- 🛡️ Verifikasi byte yang diharapkan dalam waktu-konstan (constant_time_eq) sebelum menerapkan patch.
- 🛡️ Jejak audit kriptografi lengkap dengan hash SHA-256 sebelum dan sesudah patch serta opsi file cadangan .bak.
- 🛡️ Pembersihan memori proaktif melalui zeroize pada buffer patch.

</details>

---

## 📄 Lisensi & Atribusi

<details open>
<summary><b>📄 Lisensi & Atribusi</b></summary>
<br>

Dilisensikan di bawah Apache License 2.0 dengan file atribusi NOTICE. Dimiliki oleh GHSFS.

```text
Copyright 2026 GHSFS (https://github.com/GHSFS)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

</details>
