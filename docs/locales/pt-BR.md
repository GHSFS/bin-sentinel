<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <strong>🇧🇷 Português</strong> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

<p align="center">
  <img src="../assets/locales/pt-BR/banner.svg" alt="Banner do BinSentinel (bsentinel)" width="100%" />
</p>

<div align="center">

# 🛡️ BinSentinel (bsentinel)

**Análise forense de binários sem dependências, analisador estático PE/ELF, detector de entropia de empacotadores e kit declarativo de patches de bytes**

[![CI](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B_Safe-orange.svg)](../../SECURITY.md)
[![Roadmap](https://img.shields.io/badge/Roadmap-Active-10b981.svg)](../../ROADMAP.md)

</div>

---

## 🔍 Visão geral

<details open>
<summary><b>🔍 Visão geral</b></summary>
<br>

bin-sentinel (bsentinel) é um conjunto de ferramentas em binário único para análise estática de executáveis, triagem de engenharia reversa e aplicação declarativa de patches de bytes, escrito em Rust 100% seguro. Projetado para analistas de segurança, pesquisadores de malware e engenheiros de sistemas que necessitam de inspeção rápida e determinística de binários não confiáveis sem dependências externas de tempo de execução.

</details>

---

## 🏛️ Arquitetura central e pipeline de análise

<details open>
<summary><b>🏛️ Arquitetura central e pipeline de análise</b></summary>
<br>

<p align="center">
  <img src="../assets/locales/pt-BR/architecture.svg" alt="Arquitetura central e pipeline de análise" width="100%" />
</p>

| # | Nome do módulo | Arquivo fonte | Capacidade principal e invariante de segurança |
|---|---|---|---|
| **01** | **Analisador estático PE32/PE32+** | `src/pe.rs` | Análise com verificação rigorosa de limites para cabeçalhos DOS/COFF/Opcionais, mitigações ASLR/DEP/CFG e anomalias RWX |
| **02** | **Entropia e heurística de empacotadores** | `src/entropy.rs` | Entropia de Shannon (0..8 bits/B), teste de uniformidade Qui-quadrado e detecção de UPX/VMProtect/Themida |
| **03** | **Scanner de strings estáticas e IoC** | `src/strings.rs` | Extração de strings ASCII e UTF-16LE com classificação de URLs, IPv4, chaves de registro e APIs críticas do Win32 |
| **04** | **Aplicador declarativo de patches de bytes** | `src/patch.rs` | Verificação em tempo constante de bytes esperados, resumos SHA-256 pré/pós patch, backup .bak e limpeza Zeroize |
| **05** | **CLI estruturada e motor JSON** | `src/cli.rs` | Gerador determinístico de PE64 para testes (synth-pe) e saída legível por máquina --json para pipelines de CI |

</details>

---

## ⚡ Início rápido e comandos da CLI

<details open>
<summary><b>⚡ Início rápido e comandos da CLI</b></summary>
<br>

```bash
# 1. Compilar o binário otimizado para produção
cargo build --release

# 2. Gerar um executável de teste sintético determinístico PE32+ (64 bits)
bsentinel synth-pe sample.exe

# 3. Inspecionar cabeçalhos PE, mitigações ASLR/DEP/CFG, tabela de seções e heurística de empacotadores
bsentinel inspect sample.exe
bsentinel inspect sample.exe --json

# 4. Gerar e inspecionar um binário sintético determinístico Linux/BSD ELF64
bsentinel synth-elf sample.elf
bsentinel inspect-elf sample.elf
bsentinel inspect-elf sample.elf --json

# 5. Executar análise estatística de entropia de Shannon e uniformidade Qui-quadrado
bsentinel entropy sample.exe --window 512
bsentinel entropy sample.exe --window 512 --json

# 6. Extrair strings imprimíveis ASCII e UTF-16LE e filtrar indicadores de comprometimento (IoC)
bsentinel strings sample.exe --min-len 4
bsentinel strings sample.exe --ioc-only --json

# 7. Escanear o binário em busca de constantes criptográficas, S-Boxes AES, chaves SHA/ChaCha20 e tabelas CRC
bsentinel crypto-scan sample.exe
bsentinel crypto-scan sample.exe --json

# 8. Inspecionar tabelas de importação/exportação PE (IAT/EAT), calcular imphash e resolver hashes dinâmicos de API
bsentinel imports sample.exe
bsentinel imports sample.exe --resolve-hash 0x0726774C --json

# 9. Aplicar patch de bytes declarativo verificado com validação de bytes esperados e backup .bak
bsentinel patch sample.exe --offset 0x200 --expect 4883EC28 --replace 90909090 --backup --json

# 10. Escanear prólogos x86_64, chamadas diretas de sistema (Direct Syscalls), verificações antidebug RDTSC e CPUID
bsentinel scan-code sample.exe
bsentinel scan-code sample.exe --json

# 11. Escanear assinaturas hexadecimais declarativas no estilo YARA com curingas, saltos de bytes e regras JSON
bsentinel rule-scan sample.exe --pattern "48 83 EC ?? [2-6] E8"
bsentinel rule-scan sample.exe --rules rules.json --json

# 12. Comparar dois binários estruturalmente e exportar receita declarativa de patch em JSON
bsentinel diff baseline.exe modified.exe --out-recipe patch.json
bsentinel diff baseline.exe modified.exe --json

# 13. Aplicar ou reverter uma receita declarativa de patch com simulação prévia (dry-run) e backup
bsentinel apply-recipe baseline.exe patch.json --dry-run
bsentinel apply-recipe baseline.exe patch.json --backup
bsentinel apply-recipe baseline.exe patch.json --reverse

# 14. Decodificar cabeçalho PE Rich, identificar toolchains do Visual Studio e verificar checksum de 32 bits
bsentinel rich sample.exe
bsentinel rich sample.exe --json

# 15. Aplicar força bruta em desofuscação XOR, ADD e ROL de um ou múltiplos bytes para revelar IoCs e cabeçalhos
bsentinel xor-scan sample.exe
bsentinel xor-scan sample.exe --json

# 16. Inspecionar diretório de recursos PE (.rsrc), extrair manifesto, níveis de execução UAC e versão
bsentinel resources sample.exe
bsentinel resources sample.exe --json

# 17. Inspecionar callbacks TLS de PE, ganchos de execução pré-main e tabelas de desenrolamento x64 (.pdata)
bsentinel callbacks sample.exe
bsentinel callbacks sample.exe --json

# 18. Extrair e decodificar com segurança cargas úteis incorporadas em Base64, URL-Safe Base64 e hexadecimal
bsentinel carve sample.exe
bsentinel carve sample.exe --extract-dir ./extracted_payloads --json

# 19. Calcular resumo de similaridade difusa por blocos de hash rolante (CTPH / SSDEEP) e impressões de seções
bsentinel fuzzy-hash sample.exe
bsentinel fuzzy-hash sample.exe --json

# 20. Comparar artefatos binários e correlacionar pontuações de similaridade difusa seção por seção (0..=100)
bsentinel fuzzy-compare original.exe modified.exe
bsentinel fuzzy-compare original.exe modified.exe --json
```

</details>

---

## 📦 Estrutura do repositório e árvore de fontes

<details open>
<summary><b>📦 Estrutura do repositório e árvore de fontes</b></summary>
<br>

```text
bin-sentinel/
├── Cargo.toml                     # Manifesto do pacote em Rust puro (binário bsentinel e biblioteca bin_sentinel)
├── README.md                      # Documentação raiz em inglês com navegação em 10 idiomas
├── ROADMAP.md                     # Roteiro público de engenharia e desenvolvimento
├── CHANGELOG.md                   # Histórico de versões mantido sob padrão Keep-a-Changelog
├── SECURITY.md                    # Análise de binários e política de segurança de memória
├── LICENSE                        # Licença Apache 2.0
├── NOTICE                         # Aviso de atribuição e direitos autorais pertencente à GHSFS
├── src/
│   ├── lib.rs                     # Exportações da interface pública da biblioteca
│   ├── main.rs                    # Ponto de entrada enxuto da CLI com despacho de comandos
│   ├── cli.rs                     # Definições de subcomandos e argumentos derivados do Clap (inspect, imports, rich, etc.)
│   ├── commands/                  # Manipuladores modulares de subcomandos da CLI (inspect, forensics, rules, diff, rich, etc.)
│   ├── error.rs                   # Modelo unificado de erros SentinelError e Result<T>
│   ├── pe.rs                      # Analisador sem dependências de cabeçalhos/seções PE32/PE32+ e gerador PE64
│   ├── elf/                       # Analisador sem dependências de binários Linux/BSD ELF64 (cabeçalhos, módulos, gerador)
│   ├── imports/                   # Analisador de importação/exportação PE (IAT/EAT), imphash MD5 e resolução de hashes de API
│   ├── crypto_scan/               # Scanner de primitivas criptográficas, S-Boxes AES/SM4 e constantes de dispersão
│   ├── disasm/                    # Scanner de prólogos/epílogos x86_64, chamadas diretas ao sistema e padrões de controle
│   ├── rules/                     # Scanner declarativo estilo YARA de assinaturas hexadecimais, curingas e saltos
│   ├── rich/                      # Decodificador de cabeçalho PE Rich, identificador de toolchains MSVC e validador de checksum
│   ├── deobfuscate/               # Scanner de desofuscação XOR, ADD e ROL de um/múltiplos bytes e recuperação de chaves
│   ├── resources/                 # Analisador de recursos PE de 3 níveis (.rsrc), manifesto e informações de versão
│   ├── callbacks/                 # Callbacks TLS de PE, ganchos pré-main e tabelas .pdata de desenrolamento de exceções x64
│   ├── carve/                     # Extração, decodificação e classificação de cargas úteis Base64, URL-Safe Base64 e hex
│   ├── fuzzy_hash/                # Motor de hash rolante CTPH, escalonamento duplo de bloco e comparação de similaridade
│   ├── entropy.rs                 # Entropia de Shannon, teste de uniformidade Qui-quadrado e detector de empacotadores
│   ├── strings.rs                 # Extrator de strings ASCII e UTF-16LE + classificador automático de IoCs
│   ├── patch.rs                   # Motor de patches de bytes verificado em tempo constante com SHA-256 e Zeroize
│   └── diff/                      # Comparação estrutural de binários e motor de receitas declarativas de patches
├── tests/
│   ├── pe_entropy_test.rs         # Testes de análise PE64, mitigações, entropia e saída JSON da CLI
│   ├── patch_strings_test.rs      # Testes de extração de IoCs, aplicação verificada de patches e backups
│   ├── elf_test.rs                # Testes de análise ELF64, mitigações PIE/RELRO/NX e símbolos dinâmicos
│   ├── crypto_scan_test.rs        # Testes de constantes criptográficas, S-Boxes e mapeamento de seções PE/ELF
│   ├── imports_test.rs            # Testes de tabelas PE IAT/EAT, cálculo de imphash e resolução de hashes de API
│   ├── carve_test.rs              # Testes de extração Base64/Hex, armadilhas PowerShell e despejo seguro
│   ├── disasm_test.rs             # Testes de prólogos x86_64, chamadas diretas de sistema e testes antidebug
│   ├── rules_test.rs              # Testes de curingas hexadecimais estilo YARA, saltos, strings e regras JSON
│   ├── diff_test.rs               # Testes de comparação estrutural, receitas de patches e reversão atômica
│   ├── rich_test.rs               # Testes de decodificação de cabeçalho PE Rich, impressões de toolchains e checksum
│   ├── deobfuscate_test.rs        # Testes de desofuscação XOR/ADD/ROL, arrasto de texto conhecido e classificação
│   ├── resources_test.rs          # Testes da árvore de diretórios de recursos PE, manifesto UAC e metadados
│   ├── callbacks_test.rs          # Testes de callbacks TLS, alertas pré-main, tabelas pdata e tratadores de exceção
│   ├── fuzzy_hash_test.rs         # Testes de hash difuso CTPH, distância Levenshtein e comparação de binários
└── docs/
    ├── locales/                   # Documentação traduzida para vários idiomas (ko, zh-CN, es, hi, ar, pt-BR, ru, fr, id)
    └── assets/locales/            # Banners SVG auto-hospedados e diagramas de arquitetura localizados
```

</details>

---

## 🔒 Segurança de memória e invariantes de proteção

<details open>
<summary><b>🔒 Segurança de memória e invariantes de proteção</b></summary>
<br>

- 🛡️ Zero blocos `unsafe` em todos os analisadores de cabeçalhos binários: cada leitura de deslocamento e fatia utiliza aritmética com checagem de limites.
- 🛡️ Verificação de bytes em tempo constante (`constant_time_eq`) antes de aplicar qualquer patch binário, abortando imediatamente com `PatchMismatch` em caso de divergência.
- 🛡️ Rastreamento de auditoria criptográfica completo: calcula e relata resumos SHA-256 pré e pós-patch, além de gerar cópias de segurança opcionais `.bak`.
- 🛡️ Limpeza proativa de memória via `zeroize` em buffers mutáveis de patches binários ao serem desalocados.

</details>

---

## 📄 Licença e atribuição

<details open>
<summary><b>📄 Licença e atribuição</b></summary>
<br>

Distribuído sob a Licença Apache, Versão 2.0 com arquivo de atribuição NOTICE. De propriedade da GHSFS.

```text
Copyright 2026 GHSFS (https://github.com/GHSFS)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

</details>
