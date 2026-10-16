<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <strong>🇪🇸 Español</strong> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

<p align="center">
  <img src="../assets/locales/es/banner.svg" alt="Banner de BinSentinel (bsentinel)" width="100%" />
</p>

<div align="center">

# 🛡️ BinSentinel (bsentinel)

**Análisis forense de binarios sin dependencias, analizador estático PE/ELF, detector de entropía de empaquetadores y kit de parches de bytes declarativos**

[![CI](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B_Safe-orange.svg)](../../SECURITY.md)
[![Roadmap](https://img.shields.io/badge/Roadmap-Active-10b981.svg)](../../ROADMAP.md)

</div>

---

## 🔍 Descripción general

<details open>
<summary><b>🔍 Descripción general</b></summary>
<br>

bin-sentinel (bsentinel) es un conjunto de herramientas de binario único para análisis estático de ejecutables, clasificación rápida de ingeniería inversa y aplicación declarativa de parches de bytes, escrito en Rust 100% seguro. Diseñado para analistas de seguridad, investigadores de malware e ingenieros de sistemas que necesitan inspeccionar binarios no confiables con rapidez, determinismo y sin dependencias pesadas de entornos externos.

</details>

---

## 🏛️ Arquitectura central y canalización de análisis

<details open>
<summary><b>🏛️ Arquitectura central y canalización de análisis</b></summary>
<br>

<p align="center">
  <img src="../assets/locales/es/architecture.svg" alt="Arquitectura central y canalización de análisis" width="100%" />
</p>

| # | Nombre del módulo | Archivo fuente | Capacidad clave e invariante de seguridad |
|---|---|---|---|
| **01** | **Analizador estático PE32/PE32+** | `src/pe.rs` | Análisis seguro con comprobación de límites para cabeceras DOS/COFF/Opcionales, mitigaciones ASLR/DEP/CFG y anomalías RWX |
| **02** | **Entropía y heurística de empaquetadores** | `src/entropy.rs` | Entropía de Shannon (0..8 bits/B), prueba de uniformidad de Chi-cuadrado y detección de UPX/VMProtect/Themida |
| **03** | **Escáner de cadenas estáticas e IoC** | `src/strings.rs` | Extracción de cadenas ASCII y UTF-16LE y clasificación de URLs, IPv4, claves de registro y APIs sensibles de Win32 |
| **04** | **Aplicador declarativo de parches de bytes** | `src/patch.rs` | Verificación en tiempo constante de bytes esperados, resúmenes SHA-256 pre/post parche, copia .bak y borrado seguro Zeroize |
| **05** | **Motor estructurado CLI y JSON** | `src/cli.rs` | Generador determinista de PE64 de prueba (synth-pe) y salida legible por máquina --json para flujos de integración continua (CI) |

</details>

---

## ⚡ Inicio rápido y uso de la línea de comandos

<details open>
<summary><b>⚡ Inicio rápido y uso de la línea de comandos</b></summary>
<br>

```bash
# 1. Compilar el binario optimizado para producción
cargo build --release

# 2. Generar un ejecutable de prueba sintético determinista PE32+ (64 bits)
bsentinel synth-pe sample.exe

# 3. Inspeccionar cabeceras PE, mitigaciones ASLR/DEP/CFG, tabla de secciones y heurística de empaquetadores
bsentinel inspect sample.exe
bsentinel inspect sample.exe --json

# 4. Generar e inspeccionar un binario sintético determinista Linux/BSD ELF64
bsentinel synth-elf sample.elf
bsentinel inspect-elf sample.elf
bsentinel inspect-elf sample.elf --json

# 5. Ejecutar análisis estadístico de entropía de Shannon y uniformidad Chi-cuadrado
bsentinel entropy sample.exe --window 512
bsentinel entropy sample.exe --window 512 --json

# 6. Extraer cadenas imprimibles ASCII y UTF-16LE y filtrar indicadores de compromiso (IoC)
bsentinel strings sample.exe --min-len 4
bsentinel strings sample.exe --ioc-only --json

# 7. Escanear el binario en busca de constantes criptográficas, S-Boxes de AES, claves SHA/ChaCha20 y tablas CRC
bsentinel crypto-scan sample.exe
bsentinel crypto-scan sample.exe --json

# 8. Inspeccionar tablas de importación/exportación PE (IAT/EAT), calcular imphash y resolver hashes dinámicos de API
bsentinel imports sample.exe
bsentinel imports sample.exe --resolve-hash 0x0726774C --json

# 9. Aplicar un parche de bytes declarativo verificado con comprobación de bytes esperados y respaldo .bak
bsentinel patch sample.exe --offset 0x200 --expect 4883EC28 --replace 90909090 --backup --json

# 10. Escanear prólogos x86_64, llamadas directas al sistema (Direct Syscalls), comprobaciones antidepuración RDTSC y CPUID
bsentinel scan-code sample.exe
bsentinel scan-code sample.exe --json

# 11. Escanear firmas hexadecimales declarativas estilo YARA con comodines, saltos de bytes y reglas JSON
bsentinel rule-scan sample.exe --pattern "48 83 EC ?? [2-6] E8"
bsentinel rule-scan sample.exe --rules rules.json --json

# 12. Comparar dos binarios estructuralmente y exportar una receta declarativa de parches en JSON
bsentinel diff baseline.exe modified.exe --out-recipe patch.json
bsentinel diff baseline.exe modified.exe --json

# 13. Aplicar o revertir una receta de parches declarativa con verificación previa (dry-run) y copia de seguridad
bsentinel apply-recipe baseline.exe patch.json --dry-run
bsentinel apply-recipe baseline.exe patch.json --backup
bsentinel apply-recipe baseline.exe patch.json --reverse

# 14. Decodificar la cabecera PE Rich, identificar herramientas de compilación de Visual Studio y verificar suma de control
bsentinel rich sample.exe
bsentinel rich sample.exe --json

# 15. Aplicar fuerza bruta para desofuscar XOR, ADD y ROL de uno o varios bytes para descubrir IoCs y cabeceras
bsentinel xor-scan sample.exe
bsentinel xor-scan sample.exe --json

# 16. Inspeccionar el directorio de recursos PE (.rsrc), extraer manifiesto, niveles de ejecución UAC y versión
bsentinel resources sample.exe
bsentinel resources sample.exe --json

# 17. Inspeccionar callbacks TLS de PE, ganchos de ejecución previos a main y tablas de desenrollado x64 (.pdata)
bsentinel callbacks sample.exe
bsentinel callbacks sample.exe --json

# 18. Extraer y decodificar cargas útiles incrustadas en Base64, URL-Safe Base64 y hexadecimal con volcado seguro
bsentinel carve sample.exe
bsentinel carve sample.exe --extract-dir ./extracted_payloads --json

# 19. Calcular el resumen de similitud difusa por bloques de hash rodante (CTPH / SSDEEP) y huellas de secciones
bsentinel fuzzy-hash sample.exe
bsentinel fuzzy-hash sample.exe --json

# 20. Comparar artefactos binarios y correlacionar puntuaciones de similitud difusa sección por sección (0..=100)
bsentinel fuzzy-compare original.exe modified.exe
bsentinel fuzzy-compare original.exe modified.exe --json
```

</details>

---

## 📦 Estructura del repositorio y árbol de fuentes

<details open>
<summary><b>📦 Estructura del repositorio y árbol de fuentes</b></summary>
<br>

```text
bin-sentinel/
├── Cargo.toml                     # Manifiesto de paquete en Rust puro (binario bsentinel y biblioteca bin_sentinel)
├── README.md                      # Documentación raíz en inglés con navegación en 10 idiomas
├── ROADMAP.md                     # Hoja de ruta de ingeniería pública
├── CHANGELOG.md                   # Historial de versiones publicado bajo Keep-a-Changelog
├── SECURITY.md                    # Análisis de binarios y política de seguridad de memoria
├── LICENSE                        # Licencia Apache 2.0
├── NOTICE                         # Aviso de atribución y copyright de GHSFS
├── src/
│   ├── lib.rs                     # Exportaciones de la interfaz pública de la biblioteca
│   ├── main.rs                    # Punto de entrada de la CLI con despacho conciso de comandos
│   ├── cli.rs                     # Definiciones de subcomandos y argumentos derivados con Clap (inspect, imports, etc.)
│   ├── commands/                  # Controladores modulares de subcomandos CLI (inspect, forensics, rules, diff, rich, etc.)
│   ├── error.rs                   # Modelo unificado de errores SentinelError y Result<T>
│   ├── pe.rs                      # Analizador sin dependencias de cabeceras/secciones PE32/PE32+ y generador PE64
│   ├── elf/                       # Analizador sin dependencias de ejecutables Linux/BSD ELF64 (cabeceras, módulos, generador)
│   ├── imports/                   # Analizador de importación/exportación PE (IAT/EAT), imphash MD5 y resolución de hashes de API
│   ├── crypto_scan/               # Escáner de primitivas criptográficas, S-Boxes de AES/SM4 y constantes de dispersión
│   ├── disasm/                    # Escáner de prólogos/epílogos x86_64, llamadas directas al sistema y patrones de flujo
│   ├── rules/                     # Escáner declarativo estilo YARA de firmas hexadecimales, comodines de nibble y saltos
│   ├── rich/                      # Decodificador de cabecera PE Rich, huellas de compilador MSVC y validador de checksum
│   ├── deobfuscate/               # Escáner de desofuscación XOR, ADD y ROL de uno/varios bytes y recuperación de claves
│   ├── resources/                 # Analizador de recursos PE de 3 niveles (.rsrc), manifiesto y metadatos de versión
│   ├── callbacks/                 # Callbacks TLS de PE, ganchos pre-main y tablas de excepción .pdata para x64
│   ├── carve/                     # Extracción, decodificación y clasificación de cargas Base64, URL-Safe Base64 y hexadecimal
│   ├── fuzzy_hash/                # Motor de hash rodante CTPH, escala de tamaño de bloque doble y comparación de similitud
│   ├── entropy.rs                 # Entropía de Shannon, prueba de uniformidad Chi-cuadrado y detector de empaquetadores
│   ├── strings.rs                 # Extractor de cadenas ASCII y UTF-16LE + clasificador automático de IoCs
│   ├── patch.rs                   # Motor de parches de bytes verificado en tiempo constante con SHA-256 y Zeroize
│   └── diff/                      # Comparación binaria estructural y motor de recetas declarativas de parches
├── tests/
│   ├── pe_entropy_test.rs         # Pruebas de análisis PE64, mitigaciones, entropía y salida JSON por CLI
│   ├── patch_strings_test.rs      # Pruebas de extracción de IoCs, aplicación verificada de parches y respaldos
│   ├── elf_test.rs                # Pruebas de análisis ELF64, mitigaciones PIE/RELRO/NX y símbolos dinámicos
│   ├── crypto_scan_test.rs        # Pruebas de constantes criptográficas, S-Boxes y mapeo de secciones PE/ELF
│   ├── imports_test.rs            # Pruebas de tablas IAT/EAT de PE, cálculo de imphash y resolución de hashes de API
│   ├── carve_test.rs              # Pruebas de extracción de Base64/Hex, trampas PowerShell y volcado seguro
│   ├── disasm_test.rs             # Pruebas de prólogos x86_64, llamadas directas al sistema y comprobaciones antidepuración
│   ├── rules_test.rs              # Pruebas de comodines hexadecimales estilo YARA, saltos, cadenas y reglas JSON
│   ├── diff_test.rs               # Pruebas de comparación estructural, recetas de parches y reversión atómica
│   ├── rich_test.rs               # Pruebas de decodificación de cabecera PE Rich, huellas de herramientas y suma de control
│   ├── deobfuscate_test.rs        # Pruebas de desofuscación XOR/ADD/ROL, arrastre de texto conocido y clasificación
│   ├── resources_test.rs          # Pruebas del árbol de recursos PE, manifiesto UAC e información de versión
│   ├── callbacks_test.rs          # Pruebas de callbacks TLS, alertas de pre-main, tablas pdata y manejadores de excepción
│   ├── fuzzy_hash_test.rs         # Pruebas de hash difuso CTPH, distancia Levenshtein y comparación de binarios
└── docs/
    ├── locales/                   # Documentación localizada en varios idiomas (ko, zh-CN, es, hi, ar, pt-BR, ru, fr, id)
    └── assets/locales/            # Banners SVG autoalojados y diagramas de arquitectura traducidos
```

</details>

---

## 🔒 Seguridad de memoria e invariantes de protección

<details open>
<summary><b>🔒 Seguridad de memoria e invariantes de protección</b></summary>
<br>

- 🛡️ Cero bloques `unsafe` en todos los analizadores de cabeceras binarias: cada lectura de desplazamiento y rebanada utiliza aritmética con comprobación de límites.
- 🛡️ Verificación de bytes en tiempo constante (`constant_time_eq`) antes de aplicar cualquier parche binario, cancelando inmediatamente con `PatchMismatch` en caso de discrepancia.
- 🛡️ Registro de auditoría criptográfica completo: calcula e informa los resúmenes SHA-256 previos y posteriores al parche, junto con copias de respaldo opcionales `.bak`.
- 🛡️ Borrado proactivo de memoria mediante `zeroize` en los búferes de parches binarios mutables al ser descartados.

</details>

---

## 📄 Licencia y atribución

<details open>
<summary><b>📄 Licencia y atribución</b></summary>
<br>

Distribuido bajo la Licencia Apache, Versión 2.0 con archivo de atribución NOTICE. Propiedad de GHSFS.

```text
Copyright 2026 GHSFS (https://github.com/GHSFS)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

</details>
