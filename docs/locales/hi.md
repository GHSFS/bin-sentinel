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

**शून्य निर्भरता बाइनरी फोरेंसिक, PE/ELF स्थिर विश्लेषक, पैकर एंट्रॉपी संसूचक एवं घोषणात्मक बाइट पैचिंग टूलकिट**

[![CI](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B_Safe-orange.svg)](../../SECURITY.md)
[![Roadmap](https://img.shields.io/badge/Roadmap-Active-10b981.svg)](../../ROADMAP.md)

</div>

---

## 🔍 संक्षिप्त विवरण (Overview)

<details open>
<summary><b>🔍 संक्षिप्त विवरण (Overview)</b></summary>
<br>

bin-sentinel (bsentinel) 100% मेमोरी-सुरक्षित Rust में लिखा गया एकल-बाइनरी स्थिर निष्पादन योग्य विश्लेषण, रिवर्स इंजीनियरिंग ट्राइएज और घोषणात्मक बाइट पैचिंग टूलकिट है। यह सुरक्षा विश्लेषकों, मैलवेयर शोधकर्ताओं और सिस्टम इंजीनियरों के लिए बनाया गया है, जिन्हें भारी बाहरी रनटाइम निर्भरता के बिना तेज़ और सटीक बाइनरी निरीक्षण की आवश्यकता होती है।

</details>

---

## 🏛️ मुख्य वास्तुकला एवं निरीक्षण पाइपलाइन

<details open>
<summary><b>🏛️ मुख्य वास्तुकला एवं निरीक्षण पाइपलाइन</b></summary>
<br>

<p align="center">
  <img src="../assets/locales/hi/architecture.svg" alt="मुख्य वास्तुकला एवं निरीक्षण पाइपलाइन" width="100%" />
</p>

| # | मॉड्यूल नाम | स्रोत फ़ाइल | मुख्य क्षमता एवं सुरक्षा अपरिवर्तनीय नियम |
|---|---|---|---|
| **01** | **PE32/PE32+ स्थिर पार्सर** | `src/pe.rs` | DOS/COFF/वैकल्पिक हेडर, ASLR/DEP/CFG सुरक्षा तंत्र और RWX विसंगतियों के लिए सीमा-जाँच पार्सिंग |
| **02** | **एंट्रॉपी एवं पैकर अन्वेषण** | `src/entropy.rs` | शैनन एंट्रॉपी (0..8 bits/B), काई-वर्ग एकरूपता परीक्षण और UPX/VMProtect/Themida संसूचन |
| **03** | **स्थिर स्ट्रिंग एवं IoC स्कैनर** | `src/strings.rs` | ASCII और UTF-16LE स्ट्रिंग्स का निष्कर्षण और URL, IPv4, रजिस्ट्री कुंजियों तथा Win32 API का वर्गीकरण |
| **04** | **घोषणात्मक बाइट पैचर** | `src/patch.rs` | स्थिर-समय अपेक्षित बाइट सत्यापन, पैच-पूर्व/पश्चात SHA-256 डाइजेस्ट, .bak बैकअप और Zeroize मेमोरी मिटाना |
| **05** | **संरचित CLI एवं JSON इंजन** | `src/cli.rs` | CI पाइपलाइनों के लिए परीक्षण PE64 जनरेटर (synth-pe) और मशीन-पठनीय --json आउटपुट समर्थन |

</details>

---

## ⚡ त्वरित शुरुआत एवं CLI उपयोग

<details open>
<summary><b>⚡ त्वरित शुरुआत एवं CLI उपयोग</b></summary>
<br>

```bash
# 1. प्रोडक्शन रिलीज़ बाइनरी का निर्माण करें
cargo build --release

# 2. सटीक सिंथेटिक PE32+ (64-बिट) परीक्षण बाइनरी उत्पन्न करें
bsentinel synth-pe sample.exe

# 3. PE हेडर, ASLR/DEP/CFG शमन, सेक्शन तालिका और पैकर अन्वेषण का निरीक्षण करें
bsentinel inspect sample.exe
bsentinel inspect sample.exe --json

# 4. सटीक सिंथेटिक Linux/BSD ELF64 बाइनरी उत्पन्न करें और उसका निरीक्षण करें
bsentinel synth-elf sample.elf
bsentinel inspect-elf sample.elf
bsentinel inspect-elf sample.elf --json

# 5. सांख्यिकीय शैनन एंट्रॉपी और काई-वर्ग एकरूपता विश्लेषण चलाएं
bsentinel entropy sample.exe --window 512
bsentinel entropy sample.exe --window 512 --json

# 6. मुद्रण योग्य ASCII और UTF-16LE स्ट्रिंग्स निकालें और समझौते के संकेतक (IoC) फ़िल्टर करें
bsentinel strings sample.exe --min-len 4
bsentinel strings sample.exe --ioc-only --json

# 7. एम्बेडेड क्रिप्टोग्राफ़िक स्थिरांक, AES S-Box, SHA/ChaCha20 कुंजियों और CRC तालिकाओं के लिए स्कैन करें
bsentinel crypto-scan sample.exe
bsentinel crypto-scan sample.exe --json

# 8. PE आयात/निर्यात तालिकाओं (IAT/EAT) का निरीक्षण करें, imphash की गणना करें और गतिशील API हैश का समाधान करें
bsentinel imports sample.exe
bsentinel imports sample.exe --resolve-hash 0x0726774C --json

# 9. अपेक्षित-बाइट जाँच और .bak बैकअप के साथ सत्यापित घोषणात्मक बाइट पैच लागू करें
bsentinel patch sample.exe --offset 0x200 --expect 4883EC28 --replace 90909090 --backup --json

# 10. x86_64 प्रस्तावना (prologue), प्रत्यक्ष सिस्टम कॉल, RDTSC एंटी-डीबग और CPUID जाँच स्कैन करें
bsentinel scan-code sample.exe
bsentinel scan-code sample.exe --json

# 11. वाइल्डकार्ड, बाइट जंप और JSON नियमों के साथ घोषणात्मक YARA-शैली हेक्स हस्ताक्षर स्कैन करें
bsentinel rule-scan sample.exe --pattern "48 83 EC ?? [2-6] E8"
bsentinel rule-scan sample.exe --rules rules.json --json

# 12. दो बाइनरी की संरचनात्मक तुलना करें और घोषणात्मक JSON पैच रेसिपी निर्यात करें
bsentinel diff baseline.exe modified.exe --out-recipe patch.json
bsentinel diff baseline.exe modified.exe --json

# 13. ड्राई-रन सत्यापन और बैकअप के साथ घोषणात्मक पैच रेसिपी लागू करें या पूर्ववत (Reverse) करें
bsentinel apply-recipe baseline.exe patch.json --dry-run
bsentinel apply-recipe baseline.exe patch.json --backup
bsentinel apply-recipe baseline.exe patch.json --reverse

# 14. PE Rich हेडर डिकोड करें, Visual Studio टूलचेन फ़िंगरप्रिंट करें और 32-बिट चेकसम सत्यापित करें
bsentinel rich sample.exe
bsentinel rich sample.exe --json

# 15. छिपे हुए IoC और हेडर को खोजने के लिए एकल/मल्टी-बाइट XOR, ADD और ROL डी-ऑफ़स्केशन को ब्रूट-फ़ोर्स करें
bsentinel xor-scan sample.exe
bsentinel xor-scan sample.exe --json

# 16. PE संसाधन निर्देशिका (.rsrc) का निरीक्षण करें, मैनिफ़ेस्ट, UAC निष्पादन स्तर और संस्करण जानकारी निकालें
bsentinel resources sample.exe
bsentinel resources sample.exe --json

# 17. PE TLS कॉलबैक, मुख्य-पूर्व निष्पादन हुक और x64 अपवाद अनवाइंड (.pdata) तालिकाओं का निरीक्षण करें
bsentinel callbacks sample.exe
bsentinel callbacks sample.exe --json

# 18. सुरक्षित निष्कर्षण के साथ एम्बेडेड Base64, URL-Safe Base64 और हेक्स पेलोड को निकालें और डिकोड करें
bsentinel carve sample.exe
bsentinel carve sample.exe --extract-dir ./extracted_payloads --json

# 19. रोलिंग-हैश आंशिक फ़ज़ी समानता डाइजेस्ट (CTPH / SSDEEP) और सेक्शन फ़िंगरप्रिंट की गणना करें
bsentinel fuzzy-hash sample.exe
bsentinel fuzzy-hash sample.exe --json

# 20. बाइनरी आर्टिफ़ैक्ट्स की तुलना करें और सेक्शन-दर-सेक्शन फ़ज़ी समानता स्कोर (0..=100) का विश्लेषण करें
bsentinel fuzzy-compare original.exe modified.exe
bsentinel fuzzy-compare original.exe modified.exe --json
```

</details>

---

## 📦 रिपॉजिटरी संरचना एवं स्रोत ट्री

<details open>
<summary><b>📦 रिपॉजिटरी संरचना एवं स्रोत ट्री</b></summary>
<br>

```text
bin-sentinel/
├── Cargo.toml                     # शुद्ध-Rust पैकेज मैनिफ़ेस्ट (bsentinel बाइनरी + bin_sentinel लाइब्रेरी)
├── README.md                      # 10-भाषा नेविगेशन के साथ मुख्य अंग्रेजी दस्तावेज़
├── ROADMAP.md                     # सार्वजनिक इंजीनियरिंग विकास रोडमैप
├── CHANGELOG.md                   # Keep-a-Changelog रिलीज़ इतिहास
├── SECURITY.md                    # बाइनरी पार्सिंग एवं मेमोरी सुरक्षा नीति
├── LICENSE                        # Apache License 2.0
├── NOTICE                         # GHSFS के स्वामित्व वाला एट्रिब्यूशन नोटिस
├── src/
│   ├── lib.rs                     # लाइब्रेरी मॉड्यूल इंटरफ़ेस
│   ├── main.rs                    # कमांड डिस्पैच करने वाला सुव्यवस्थित CLI प्रवेश बिंदु
│   ├── cli.rs                     # Clap व्युत्पन्न सब-कमांड परिभाषाएँ (inspect, imports, rich, carve आदि)
│   ├── commands/                  # मॉड्यूलर CLI सब-कमांड हैंडलर (inspect, forensics, rules, diff, rich आदि)
│   ├── error.rs                   # एकीकृत SentinelError और Result<T>
│   ├── pe.rs                      # बिना निर्भरता वाला PE32/PE32+ हेडर/सेक्शन पार्सर + सिंथेटिक PE64 बिल्डर
│   ├── elf/                       # बिना निर्भरता वाला Linux/BSD ELF64 पार्सर (हेडर, मॉड्यूल, सिंथेटिक बिल्डर)
│   ├── imports/                   # PE आयात/निर्यात (IAT/EAT) पार्सर, MD5 imphash और गतिशील API हैश सॉल्वर
│   ├── crypto_scan/               # एम्बेडेड क्रिप्टोग्राफ़िक प्रिमिटिव, AES/SM4 S-Box और हैश स्थिरांक स्कैनर
│   ├── disasm/                    # x86_64 प्रोलॉग/एपिलॉग, प्रत्यक्ष सिस्टम कॉल और नियंत्रण-प्रवाह स्कैनर
│   ├── rules/                     # घोषणात्मक YARA-शैली हेक्स हस्ताक्षर, निबल वाइल्डकार्ड और बाइट जंप स्कैनर
│   ├── rich/                      # PE Rich हेडर डिकोडर, MSVC टूलचेन फ़िंगरप्रिंटर और चेकसम सत्यापनकर्ता
│   ├── deobfuscate/               # एकल/मल्टी-बाइट XOR, ADD और ROL डी-ऑफ़स्केशन स्कैनर और कुंजी रिकवरी
│   ├── resources/                 # PE 3-स्तरीय संसाधन निर्देशिका (.rsrc), मैनिफ़ेस्ट और संस्करण पार्सर
│   ├── callbacks/                 # PE TLS कॉलबैक, मुख्य-पूर्व हुक और x64 .pdata अपवाद अनवाइंड तालिकाएँ
│   ├── carve/                     # Base64, URL-Safe Base64 और हेक्स पेलोड नक्काशी, डिकोडिंग और वर्गीकरण
│   ├── fuzzy_hash/                # CTPH रोलिंग हैश इंजन, दोहरा ब्लॉक स्केलिंग और बाइनरी समानता तुलना
│   ├── entropy.rs                 # शैनन एंट्रॉपी, काई-वर्ग एकरूपता और पैकर संसूचक
│   ├── strings.rs                 # ASCII और UTF-16LE स्ट्रिंग निष्कर्षण + IoC वर्गीकरण
│   ├── patch.rs                   # SHA-256 और Zeroize के साथ स्थिर-समय सत्यापित बाइट पैचिंग इंजन
│   └── diff/                      # संरचनात्मक बाइनरी अंतर और घोषणात्मक पैच रेसिपी इंजन
├── tests/
│   ├── pe_entropy_test.rs         # PE64 पार्सिंग, सुरक्षा शमन, एंट्रॉपी और CLI JSON परीक्षण
│   ├── patch_strings_test.rs      # IoC निष्कर्षण, सत्यापित पैचिंग और बैकअप परीक्षण
│   ├── elf_test.rs                # ELF64 पार्सिंग, PIE/RELRO/NX शमन और गतिशील प्रतीक परीक्षण
│   ├── crypto_scan_test.rs        # क्रिप्टोग्राफ़िक स्थिरांक, S-Box और PE/ELF सेक्शन मैपिंग परीक्षण
│   ├── imports_test.rs            # PE IAT/EAT तालिकाएँ, imphash और गतिशील API हैश परीक्षण
│   ├── carve_test.rs              # Base64/Hex निष्कर्षण, PowerShell क्रैडल और सुरक्षित डंप परीक्षण
│   ├── disasm_test.rs             # x86_64 प्रोलॉग, प्रत्यक्ष सिस्टम कॉल और एंटी-डीबग परीक्षण
│   ├── rules_test.rs              # YARA-शैली हेक्स वाइल्डकार्ड, जंप, स्ट्रिंग्स और JSON नियम परीक्षण
│   ├── diff_test.rs               # संरचनात्मक अंतर, पैच रेसिपी और परमाणु रोलबैक परीक्षण
│   ├── rich_test.rs               # PE Rich हेडर डिकोडिंग, टूलचेन फ़िंगरप्रिंटिंग और चेकसम परीक्षण
│   ├── deobfuscate_test.rs        # XOR/ADD/ROL डी-ऑफ़स्केशन, क्रिब ड्रैगिंग और पेलोड वर्गीकरण परीक्षण
│   ├── resources_test.rs          # PE संसाधन निर्देशिका ट्री, UAC मैनिफ़ेस्ट और संस्करण परीक्षण
│   ├── callbacks_test.rs          # TLS कॉलबैक, मुख्य-पूर्व हुक, pdata तालिकाएँ और अपवाद परीक्षण
│   ├── fuzzy_hash_test.rs         # CTPH फ़ज़ी हैशिंग, लेवेनश्टाइन दूरी और बाइनरी तुलना परीक्षण
└── docs/
    ├── locales/                   # बहुभाषी अनुवादित README दस्तावेज़ (ko, zh-CN, es, hi, ar, pt-BR, ru, fr, id)
    └── assets/locales/            # स्थानीयकृत स्व-होस्ट किए गए SVG बैनर और वास्तुकला आरेख
```

</details>

---

## 🔒 मेमोरी सुरक्षा एवं अपरिवर्तनीय सुरक्षा नियम

<details open>
<summary><b>🔒 मेमोरी सुरक्षा एवं अपरिवर्तनीय सुरक्षा नियम</b></summary>
<br>

- 🛡️ सभी बाइनरी हेडर पार्सर्स में शून्य `unsafe` ब्लॉक: प्रत्येक ऑफ़सेट और स्लाइस रीड सीमा-जाँचे गए अंकगणित का उपयोग करता है।
- 🛡️ किसी भी बाइनरी पैच को लागू करने से पहले स्थिर-समय बाइट सत्यापन (`constant_time_eq`), विसंगति होने पर `PatchMismatch` के साथ तुरंत रद्द करना।
- 🛡️ पूर्ण क्रिप्टोग्राफ़िक ऑडिट ट्रेल: वैकल्पिक `.bak` बैकअप के साथ पैच-पूर्व और पैच-पश्चात SHA-256 डाइजेस्ट की गणना और रिपोर्ट।
- 🛡️ परिवर्तनीय बाइनरी पैच बफ़र्स पर ड्रॉप होने पर `zeroize` के माध्यम से सक्रिय मेमोरी का संपूर्ण सफाया।

</details>

---

## 📄 लाइसेंस एवं एट्रिब्यूशन

<details open>
<summary><b>📄 लाइसेंस एवं एट्रिब्यूशन</b></summary>
<br>

NOTICE एट्रिब्यूशन फ़ाइल के साथ Apache License, Version 2.0 के तहत लाइसेंस प्राप्त। GHSFS के स्वामित्व में।

```text
Copyright 2026 GHSFS (https://github.com/GHSFS)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

</details>
