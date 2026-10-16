<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <strong>🇸🇦 العربية</strong> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

<p align="center">
  <img src="../assets/locales/ar/banner.svg" alt="شعار BinSentinel (bsentinel)" width="100%" />
</p>

<div align="center">

# 🛡️ BinSentinel (bsentinel)

**مجموعة أدوات التحليل الجنائي للملفات الثنائية، ومحلل PE/ELF الساكن، وكاشف إنتروبيا حزم التغليف وتطبيق ترقيع البايتات دون أي تبعيات خارجية**

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

bin-sentinel (bsentinel) هي مجموعة أدوات متكاملة في ملف تنفيذي واحد للتحليل الساكن للملفات الثنائية وفرز الهندسة العكسية وتطبيق ترقيع البايتات التقريري، مبنية بلغة Rust الآمنة تمامًا في الذاكرة بنسبة 100%. صُممت لمحلي الأمن الرقمي وباحثي البرمجيات الخبيثة ومهندسي الأنظمة الذين يحتاجون إلى فحص حتمي وسريع للملفات الثنائية غير الموثوقة دون الحاجة إلى تبعيات تشغيل خارجية ثقيلة.

</details>

---

## 🏛️ البنية الأساسية ومسار الفحص والتحليل

<details open>
<summary><b>🏛️ البنية الأساسية ومسار الفحص والتحليل</b></summary>
<br>

<p align="center">
  <img src="../assets/locales/ar/architecture.svg" alt="البنية الأساسية ومسار الفحص والتحليل" width="100%" />
</p>

| # | اسم الوحدة | الملف المصدري | القدرة الوظيفية الأساسية ومحددات الأمان |
|---|---|---|---|
| **01** | **محلل PE32/PE32+ الساكن** | `src/pe.rs` | تحليل محمي الحدود لترويسات DOS و COFF والترويسات الاختيارية، وتخفيفات ASLR/DEP/CFG وشذوذ قطاعات RWX |
| **02** | **إنتروبيا وتحليلات حزم التغليف** | `src/entropy.rs` | حساب إنتروبيا شانون (0..8 bits/B)، واختبار تجانس كاي-تربيع وكشف أدوات التغليف UPX/VMProtect/Themida |
| **03** | **ماسح النصوص ومؤشرات الاختراق** | `src/strings.rs` | استخراج سلاسل نصوص ASCII و UTF-16LE وتصنيف الروابط وعناوين IPv4 ومفاتيح السجل ودوال Win32 الحساسة |
| **04** | **مرقع البايتات التقريري** | `src/patch.rs` | التحقق بزمن ثابت من البايتات الأصلية، وملخصات SHA-256 قبل وبعد الترقيع، والنسخ الاحتياطي .bak ومسح الذاكرة عبر Zeroize |
| **05** | **واجهة CLI ومحرك JSON الهيكلي** | `src/cli.rs` | منشئ حتمي لملفات PE64 التجريبية (synth-pe) ومخرجات بصيغة --json قابلة للقراءة آليًا لمسارات التكامل المستمر CI |

</details>

---

## ⚡ البدء السريع واستخدام سطر الأوامر

<details open>
<summary><b>⚡ البدء السريع واستخدام سطر الأوامر</b></summary>
<br>

```bash
# 1. بناء النسخة المحسنة للإنتاج
cargo build --release

# 2. إنشاء ملف تجريبي حتمي تركيبي بصيغة PE32+ (64 بت)
bsentinel synth-pe sample.exe

# 3. فحص ترويسات PE، وتخفيفات ASLR/DEP/CFG، وجدول القطاعات واستدلالات حزم التغليف
bsentinel inspect sample.exe
bsentinel inspect sample.exe --json

# 4. إنشاء وفحص ملف ثنائي حتمي تركيبي لنظام Linux/BSD بصيغة ELF64
bsentinel synth-elf sample.elf
bsentinel inspect-elf sample.elf
bsentinel inspect-elf sample.elf --json

# 5. تشغيل التحليل الإحصائي لإنتروبيا شانون وتجانس كاي-تربيع
bsentinel entropy sample.exe --window 512
bsentinel entropy sample.exe --window 512 --json

# 6. استخراج سلاسل نصوص ASCII و UTF-16LE وتصفية مؤشرات الاختراق (IoCs)
bsentinel strings sample.exe --min-len 4
bsentinel strings sample.exe --ioc-only --json

# 7. مسح الملف الثنائي بحثًا عن الثوابت التشفيرية المضمنة ومصفوفات AES S-Box ومفاتيح التجزئة وجداول CRC
bsentinel crypto-scan sample.exe
bsentinel crypto-scan sample.exe --json

# 8. فحص جداول استيراد وتصدير PE (IAT/EAT)، واحتساب imphash وحل تجزئات دوال API الديناميكية
bsentinel imports sample.exe
bsentinel imports sample.exe --resolve-hash 0x0726774C --json

# 9. تطبيق ترقيع بايتات تقريري تم التحقق منه مع مطابقة البايتات المتوقعة والنسخ الاحتياطي .bak
bsentinel patch sample.exe --offset 0x200 --expect 4883EC28 --replace 90909090 --backup --json

# 10. مسح مقدمات دوال x86_64، ونداءات النظام المباشرة (Direct Syscalls)، وفحوصات منع التنقيح RDTSC و CPUID
bsentinel scan-code sample.exe
bsentinel scan-code sample.exe --json

# 11. مسح التواقيع الست عشرية التقريرية بأسلوب YARA مع الرموز البديلة والقفزات وقواعد JSON
bsentinel rule-scan sample.exe --pattern "48 83 EC ?? [2-6] E8"
bsentinel rule-scan sample.exe --rules rules.json --json

# 12. مقارنة ملفين ثنائيين هيكليًا وتصدير وصفة ترقيع تقريرية بصيغة JSON
bsentinel diff baseline.exe modified.exe --out-recipe patch.json
bsentinel diff baseline.exe modified.exe --json

# 13. تطبيق أو التراجع عن وصفة ترقيع تقريرية مع الفحص المسبق (dry-run) والنسخ الاحتياطي
bsentinel apply-recipe baseline.exe patch.json --dry-run
bsentinel apply-recipe baseline.exe patch.json --backup
bsentinel apply-recipe baseline.exe patch.json --reverse

# 14. فك تشفير ترويسة PE Rich، وتحديد بصمة سلاسل أدوات Visual Studio والتحقق من المجموع الاختباري
bsentinel rich sample.exe
bsentinel rich sample.exe --json

# 15. كسر تشويش XOR و ADD و ROL للبايت الفردي والمتعدد بالقوة الغاشمة لكشف مؤشرات الاختراق والترويسات
bsentinel xor-scan sample.exe
bsentinel xor-scan sample.exe --json

# 16. فحص دليل موارد PE (.rsrc)، واستخراج ملفات البيان ومستويات تشغيل UAC ومعلومات الإصدار
bsentinel resources sample.exe
bsentinel resources sample.exe --json

# 17. فحص نداءات PE TLS الرجعية، وخطافات التنفيذ قبل main، وجداول استثناءات x64 (.pdata)
bsentinel callbacks sample.exe
bsentinel callbacks sample.exe --json

# 18. استخراج وفك تشفير حمولات Base64 و URL-Safe Base64 والترميز الست عشري المضمنة بأمان
bsentinel carve sample.exe
bsentinel carve sample.exe --extract-dir ./extracted_payloads --json

# 19. حساب ملخص التشابه الغامض المقطعي بالتجزئة المتدحرجة (CTPH / SSDEEP) وبصمات القطاعات
bsentinel fuzzy-hash sample.exe
bsentinel fuzzy-hash sample.exe --json

# 20. مقارنة الملفات الثنائية وربط درجات التشابه الغامض قطاعًا بقطاع (0..=100)
bsentinel fuzzy-compare original.exe modified.exe
bsentinel fuzzy-compare original.exe modified.exe --json
```

</details>

---

## 📦 بنية المستودع وشجرة الملفات المصدرية

<details open>
<summary><b>📦 بنية المستودع وشجرة الملفات المصدرية</b></summary>
<br>

```text
bin-sentinel/
├── Cargo.toml                     # ملف تعريف حزمة Rust الخالصة (أداة bsentinel التنفيذية ومكتبة bin_sentinel)
├── README.md                      # التوثيق الأساسي باللغة الإنجليزية مع شريط تنقل لـ 10 لغات
├── ROADMAP.md                     # خارطة طريق التطوير الهندسي العامة
├── CHANGELOG.md                   # سجل الإصدارات والتحديثات وفق Keep-a-Changelog
├── SECURITY.md                    # أمان الذاكرة وسياسة تحليل الملفات الثنائية
├── LICENSE                        # رخصة Apache 2.0
├── NOTICE                         # إشعار الإسناد وحقوق النشر المملوكة لـ GHSFS
├── src/
│   ├── lib.rs                     # واجهات المكتبة البرمجية العامة
│   ├── main.rs                    # نقطة الدخول الرئيسية للـ CLI لتوزيع الأوامر
│   ├── cli.rs                     # تعريفات الأوامر الفرعية عبر Clap (inspect, imports, rich, carve الخ)
│   ├── commands/                  # معالجات أوامر CLI المعيارية (inspect, forensics, rules, diff, rich الخ)
│   ├── error.rs                   # نموذج الأخطاء الموحد SentinelError و Result<T>
│   ├── pe.rs                      # محلل ترويسات وقطاعات PE32/PE32+ ومولد PE64 بدون تبعيات
│   ├── elf/                       # محلل ملفات Linux/BSD ELF64 (الترويسات، الوحدات، منشئ تركيبي)
│   ├── imports/                   # محلل جداول استيراد/تصدير PE (IAT/EAT) وبصمة imphash وحل تجزئات API
│   ├── crypto_scan/               # ماسح الثوابت التشفيرية المضمنة ومصفوفات AES/SM4 S-Box والتجزئة
│   ├── disasm/                    # ماسح مقدمات x86_64، ونداءات النظام المباشرة وأنماط التحكم
│   ├── rules/                     # ماسح التواقيع التقريرية بأسلوب YARA والرموز البديلة والقفزات
│   ├── rich/                      # مفكك ترويسة PE Rich وبصمات أدوات MSVC والتحقق من المجموع الاختباري
│   ├── deobfuscate/               # ماسح كسر تشويش XOR و ADD و ROL واستعادة مفاتيح التشفير
│   ├── resources/                 # محلل دليل موارد PE ثلاثي المستويات (.rsrc) وبيان التطبيق والإصدار
│   ├── callbacks/                 # نداءات TLS الرجعية وخطافات ما قبل main وجداول x64 .pdata
│   ├── carve/                     # مستخرج ومصنف حمولات Base64 و URL-Safe Base64 والترميز الست عشري
│   ├── fuzzy_hash/                # محرك التجزئة المتدحرجة CTPH ومقارنة التشابه بين الملفات الثنائية
│   ├── entropy.rs                 # إنتروبيا شانون، واختبار تجانس كاي-تربيع وكاشف أدوات التغليف
│   ├── strings.rs                 # مستخرج نصوص ASCII و UTF-16LE ومصنف مؤشرات الاختراق IoCs
│   ├── patch.rs                   # محرك ترقيع بايتات تم التحقق منه بزمن ثابت عبر SHA-256 و Zeroize
│   └── diff/                      # مقارنة الفروق الثنائية الهيكلية ومحرك وصفات الترقيع التقريرية
├── tests/
│   ├── pe_entropy_test.rs         # اختبارات تحليل PE64 والتخفيفات والإنتروبيا ومخرجات JSON
│   ├── patch_strings_test.rs      # اختبارات استخراج مؤشرات الاختراق والترقيع والنسخ الاحتياطي
│   ├── elf_test.rs                # اختبارات تحليل ELF64 وتخفيفات PIE/RELRO/NX والرموز الديناميكية
│   ├── crypto_scan_test.rs        # اختبارات الثوابت التشفيرية و S-Box وتعيين قطاعات PE/ELF
│   ├── imports_test.rs            # اختبارات جداول PE IAT/EAT وبصمة imphash وحل تجزئات API
│   ├── carve_test.rs              # اختبارات استخراج Base64/Hex ونصوص PowerShell والتفريغ الآمن
│   ├── disasm_test.rs             # اختبارات مقدمات x86_64 ونداءات النظام وفحوصات منع التنقيح
│   ├── rules_test.rs              # اختبارات تواقيع YARA الست عشرية والقفزات وقواعد JSON
│   ├── diff_test.rs               # اختبارات الفروق الهيكلية ووصفات الترقيع والتراجع الذري
│   ├── rich_test.rs               # اختبارات فك ترويسة PE Rich وبصمات أدوات البناء والمجموع الاختباري
│   ├── deobfuscate_test.rs        # اختبارات كسر تشويش XOR/ADD/ROL وسحب النصوص وتصنيف الحمولات
│   ├── resources_test.rs          # اختبارات شجرة دليل موارد PE وبيان UAC ومعلومات الإصدار
│   ├── callbacks_test.rs          # اختبارات نداءات TLS وخطافات التنفيذ وجداول pdata ومعالجة الاستثناءات
│   ├── fuzzy_hash_test.rs         # اختبارات التجزئة الغامضة CTPH ومسافة ليفنشتاين والمقارنة الثنائية
└── docs/
    ├── locales/                   # مجلد الترجمات متعدد اللغات (ko, zh-CN, es, hi, ar, pt-BR, ru, fr, id)
    └── assets/locales/            # لافتات SVG ورسوم بيانية مستضافة ذاتيًا لكل اللغات
```

</details>

---

## 🔒 أمان الذاكرة ومحددات الحماية البرمجية

<details open>
<summary><b>🔒 أمان الذاكرة ومحددات الحماية البرمجية</b></summary>
<br>

- 🛡️ صفر كتل `unsafe` عبر جميع محللات ترويسات الملفات الثنائية: يتم استخدام عمليات حسابية محكومة الحدود عند قراءة أي إزاحة أو شريحة بيانات.
- 🛡️ التحقق بزمن ثابت من البايتات (`constant_time_eq`) قبل تطبيق أي ترقيع ثنائي، مع الإلغاء الفوري برسالة `PatchMismatch` عند أي تباين.
- 🛡️ سجل تدقيق تشفيري متكامل: يتم حساب وتوثيق ملخصات SHA-256 قبل وبعد الترقيع مع دعم إنشاء نسخ احتياطية اختيارية `.bak`.
- 🛡️ مسح استباقي آمن للذاكرة المؤقتة عبر `zeroize` لحاويات البايتات المتغيرة عند تحريرها.

</details>

---

## 📄 الترخيص والإسناد

<details open>
<summary><b>📄 الترخيص والإسناد</b></summary>
<br>

مرخص بموجب رخصة Apache License 2.0 مع ملف إشعار الإسناد NOTICE. مملوك لـ GHSFS.

```text
Copyright 2026 GHSFS (https://github.com/GHSFS)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

</details>
