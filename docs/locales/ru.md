<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <strong>🇷🇺 Русский</strong> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

<p align="center">
  <img src="../assets/locales/ru/banner.svg" alt="Баннер BinSentinel (bsentinel)" width="100%" />
</p>

<div align="center">

# 🛡️ BinSentinel (bsentinel)

**Криминалистический анализ бинарных файлов без зависимостей, статический анализатор PE/ELF, детектор энтропии упаковщиков и набор декларативного байтового патчинга**

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

bin-sentinel (bsentinel) — это набор инструментов в едином бинарном файле для статического анализа исполняемых файлов, экспресс-сортировки при реверс-инжиниринге и декларативного байтового патчинга, написанный на 100% безопасном Rust. Инструмент создан для аналитиков безопасности, исследователей вредоносных программ и системных инженеров, которым требуется быстрая детерминированная проверка подозрительных бинарных файлов без тяжелых внешних зависимостей среды выполнения.

</details>

---

## 🏛️ Ключевая архитектура и конвейер анализа

<details open>
<summary><b>🏛️ Ключевая архитектура и конвейер анализа</b></summary>
<br>

<p align="center">
  <img src="../assets/locales/ru/architecture.svg" alt="Ключевая архитектура и конвейер анализа" width="100%" />
</p>

| # | Имя модуля | Исходный файл | Основные возможности и инварианты безопасности |
|---|---|---|---|
| **01** | **Статический парсер PE32/PE32+** | `src/pe.rs` | Разбор с проверкой границ для заголовков DOS/COFF/Опциональных, механизмов защиты ASLR/DEP/CFG и аномалий секций RWX |
| **02** | **Энтропия и эвристика упаковщиков** | `src/entropy.rs` | Энтропия Шеннона (0..8 bits/B), критерий равномерности Хи-квадрат и распознавание упаковщиков UPX/VMProtect/Themida |
| **03** | **Сканер статических строк и IoC** | `src/strings.rs` | Извлечение строк ASCII и UTF-16LE с классификацией URL, IPv4, ключей реестра и критических функций Win32 API |
| **04** | **Декларативный байтовый патчер** | `src/patch.rs` | Сравнение ожидаемых байтов за постоянное время, дайджесты SHA-256 до и после патча, бэкап .bak и затирание Zeroize |
| **05** | **Структурированный CLI и движок JSON** | `src/cli.rs` | Детерминированный генератор синтетических PE64 (synth-pe) и машиночитаемый вывод --json для пайплайнов CI |

</details>

---

## ⚡ Быстрый старт и примеры командной строки

<details open>
<summary><b>⚡ Быстрый старт и примеры командной строки</b></summary>
<br>

```bash
# 1. Сборка оптимизированного исполняемого файла
cargo build --release

# 2. Генерация детерминированного синтетического тестового файла PE32+ (64 бита)
bsentinel synth-pe sample.exe

# 3. Инспекция заголовков PE, механизмов защиты ASLR/DEP/CFG, таблицы секций и эвристик упаковщиков
bsentinel inspect sample.exe
bsentinel inspect sample.exe --json

# 4. Генерация и инспекция детерминированного синтетического бинарного файла Linux/BSD ELF64
bsentinel synth-elf sample.elf
bsentinel inspect-elf sample.elf
bsentinel inspect-elf sample.elf --json

# 5. Статистический анализ энтропии Шеннона и критерия равномерности Хи-квадрат
bsentinel entropy sample.exe --window 512
bsentinel entropy sample.exe --window 512 --json

# 6. Извлечение печатных строк ASCII и UTF-16LE и фильтрация индикаторов компрометации (IoC)
bsentinel strings sample.exe --min-len 4
bsentinel strings sample.exe --ioc-only --json

# 7. Сканирование на наличие встроенных криптографических констант, S-Box AES, ключей SHA/ChaCha20 и таблиц CRC
bsentinel crypto-scan sample.exe
bsentinel crypto-scan sample.exe --json

# 8. Инспекция таблиц импорта/экспорта PE (IAT/EAT), расчет imphash и разрешение динамических API-хэшей
bsentinel imports sample.exe
bsentinel imports sample.exe --resolve-hash 0x0726774C --json

# 9. Применение проверенного декларативного байтового патча с проверкой исходных байтов и бэкапом .bak
bsentinel patch sample.exe --offset 0x200 --expect 4883EC28 --replace 90909090 --backup --json

# 10. Сканирование прологов x86_64, прямых системных вызовов (Direct Syscalls), антиотладочных проверок RDTSC и CPUID
bsentinel scan-code sample.exe
bsentinel scan-code sample.exe --json

# 11. Сканирование декларативных шестнадцатеричных сигнатур в стиле YARA с масками, байтовыми переходами и JSON
bsentinel rule-scan sample.exe --pattern "48 83 EC ?? [2-6] E8"
bsentinel rule-scan sample.exe --rules rules.json --json

# 12. Структурное сравнение двух бинарных файлов и экспорт декларативного рецепта патча в JSON
bsentinel diff baseline.exe modified.exe --out-recipe patch.json
bsentinel diff baseline.exe modified.exe --json

# 13. Применение или откат декларативного рецепта патча с предварительной проверкой (dry-run) и бэкапом
bsentinel apply-recipe baseline.exe patch.json --dry-run
bsentinel apply-recipe baseline.exe patch.json --backup
bsentinel apply-recipe baseline.exe patch.json --reverse

# 14. Декодирование заголовка PE Rich, снятие отпечатков тулчейнов Visual Studio и проверка 32-битной контрольной суммы
bsentinel rich sample.exe
bsentinel rich sample.exe --json

# 15. Брутфорс деобфускации однобайтового и многобайтового XOR, ADD и ROL для раскрытия скрытых IoC и заголовков
bsentinel xor-scan sample.exe
bsentinel xor-scan sample.exe --json

# 16. Инспекция каталога ресурсов PE (.rsrc), извлечение манифеста, уровней выполнения UAC и информации о версии
bsentinel resources sample.exe
bsentinel resources sample.exe --json

# 17. Инспекция колбэков TLS в PE, хуков выполнения до main и таблиц раскрутки исключений x64 (.pdata)
bsentinel callbacks sample.exe
bsentinel callbacks sample.exe --json

# 18. Карвинг и безопасное декодирование встроенных полезных нагрузок Base64, URL-Safe Base64 и hex
bsentinel carve sample.exe
bsentinel carve sample.exe --extract-dir ./extracted_payloads --json

# 19. Расчет дайджеста нечеткого сходства скользящего хэша (CTPH / SSDEEP) и отпечатков секций
bsentinel fuzzy-hash sample.exe
bsentinel fuzzy-hash sample.exe --json

# 20. Сравнение бинарных артефактов и корреляция посекционных оценок нечеткого сходства (0..=100)
bsentinel fuzzy-compare original.exe modified.exe
bsentinel fuzzy-compare original.exe modified.exe --json
```

</details>

---

## 📦 Структура репозитория и дерево исходных файлов

<details open>
<summary><b>📦 Структура репозитория и дерево исходных файлов</b></summary>
<br>

```text
bin-sentinel/
├── Cargo.toml                     # Манифест пакета на чистом Rust (бинарный файл bsentinel и библиотека bin_sentinel)
├── README.md                      # Корневой англоязычный документ с навигацией по 10 языкам
├── ROADMAP.md                     # Публичный инженерный план развития проекта
├── CHANGELOG.md                   # История релизов в формате Keep-a-Changelog
├── SECURITY.md                    # Политика безопасности памяти и разбора бинарных структур
├── LICENSE                        # Лицензия Apache 2.0
├── NOTICE                         # Уведомление об авторских правах и принадлежности GHSFS
├── src/
│   ├── lib.rs                     # Экспорт публичных интерфейсов библиотеки
│   ├── main.rs                    # Лаконичная точка входа CLI для диспетчеризации команд
│   ├── cli.rs                     # Определение подкоманд и параметров Clap (inspect, imports, rich, carve и др.)
│   ├── commands/                  # Модульные обработчики подкоманд CLI (inspect, forensics, rules, diff, rich и др.)
│   ├── error.rs                   # Единая модель ошибок SentinelError и Result<T>
│   ├── pe.rs                      # Автономный парсер заголовков/секций PE32/PE32+ и генератор синтетических PE64
│   ├── elf/                       # Автономный парсер Linux/BSD ELF64 (заголовки, модули, синтетический билдер)
│   ├── imports/                   # Парсер таблиц импорта/экспорта PE (IAT/EAT), imphash MD5 и резолвер API-хэшей
│   ├── crypto_scan/               # Сканер криптографических примитивов, S-Box AES/SM4 и констант хэширования
│   ├── disasm/                    # Сканер прологов/эпилогов x86_64, прямых системных вызовов и потока управления
│   ├── rules/                     # Декларативный сканер шестнадцатеричных сигнатур YARA с масками и переходами
│   ├── rich/                      # Декодер заголовка PE Rich, фингерпринтинг тулчейнов MSVC и проверка чексумм
│   ├── deobfuscate/               # Сканер деобфускации XOR, ADD и ROL и инструмент восстановления ключей
│   ├── resources/                 # Парсер трехуровневого каталога ресурсов PE (.rsrc), манифеста и версии
│   ├── callbacks/                 # Колбэки TLS PE, хуки до main и таблицы раскрутки исключений x64 .pdata
│   ├── carve/                     # Извлечение, декодирование и классификация нагрузок Base64, URL-Safe Base64 и hex
│   ├── fuzzy_hash/                # Движок скользящего хэша CTPH, двойное масштабирование блоков и оценка сходства
│   ├── entropy.rs                 # Энтропия Шеннона, критерий Хи-квадрат и детектор эвристик упаковщиков
│   ├── strings.rs                 # Извлечение строк ASCII и UTF-16LE + автоматический классификатор IoC
│   ├── patch.rs                   # Проверенный движок байтового патчинга с постоянным временем, SHA-256 и Zeroize
│   └── diff/                      # Структурный diff исполняемых файлов и движок декларативных рецептов патчей
├── tests/
│   ├── pe_entropy_test.rs         # Тесты анализа PE64, механизмов защиты, энтропии и вывода JSON в CLI
│   ├── patch_strings_test.rs      # Тесты извлечения IoC, верифицированного патчинга и создания бэкапов
│   ├── elf_test.rs                # Тесты анализа ELF64, механизмов защиты PIE/RELRO/NX и динамических символов
│   ├── crypto_scan_test.rs        # Тесты криптографических констант, S-Box и сопоставления секций PE/ELF
│   ├── imports_test.rs            # Тесты таблиц PE IAT/EAT, расчета imphash и разрешения API-хэшей
│   ├── carve_test.rs              # Тесты карвинга Base64/Hex, колыбелей PowerShell и безопасной выгрузки
│   ├── disasm_test.rs             # Тесты прологов x86_64, прямых системных вызовов и антиотладочных проверок
│   ├── rules_test.rs              # Тесты шестнадцатеричных масок YARA, прыжков, строк и правил JSON
│   ├── diff_test.rs               # Тесты структурного diff, генерации рецептов патчей и атомарного отката
│   ├── rich_test.rs               # Тесты декодирования заголовка PE Rich, отпечатков тулчейнов и чексумм
│   ├── deobfuscate_test.rs        # Тесты деобфускации XOR/ADD/ROL, метода сдвига crib и классификации нагрузок
│   ├── resources_test.rs          # Тесты дерева каталога ресурсов PE, манифеста UAC и информации о версии
│   ├── callbacks_test.rs          # Тесты колбэков TLS, хуков до main, таблиц pdata и обработчиков исключений
│   ├── fuzzy_hash_test.rs         # Тесты нечеткого хэширования CTPH, расстояния Левенштейна и бинарного сходства
└── docs/
    ├── locales/                   # Локализованные документы README (ko, zh-CN, es, hi, ar, pt-BR, ru, fr, id)
    └── assets/locales/            # Локализованные SVG-баннеры и архитектурные схемы
```

</details>

---

## 🔒 Безопасность памяти и инварианты защиты

<details open>
<summary><b>🔒 Безопасность памяти и инварианты защиты</b></summary>
<br>

- 🛡️ Ноль блоков `unsafe` во всех парсерах бинарных заголовков: каждое чтение смещения и среза использует защищенную арифметику с проверкой границ.
- 🛡️ Сравнение байтов за постоянное время (`constant_time_eq`) перед применением любого патча, немедленно прерывающее операцию ошибкой `PatchMismatch` при любом несовпадении.
- 🛡️ Полный криптографический аудит: вычисление и фиксация дайджестов SHA-256 до и после наложения патча, а также опциональное создание резервных копий `.bak`.
- 🛡️ Упреждающее безопасное затирание памяти через `zeroize` для изменяемых буферов байтовых патчей при их освобождении.

</details>

---

## 📄 Лицензия и авторские права

<details open>
<summary><b>📄 Лицензия и авторские права</b></summary>
<br>

Распространяется на условиях лицензии Apache License, Version 2.0 с файлом атрибуции NOTICE. Принадлежит GHSFS.

```text
Copyright 2026 GHSFS (https://github.com/GHSFS)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

</details>
