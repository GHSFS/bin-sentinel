<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <strong>🇰🇷 한국어</strong> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

<p align="center">
  <img src="../assets/locales/ko/banner.svg" alt="BinSentinel (bsentinel) banner" width="100%" />
</p>

<div align="center">

# 🛡️ BinSentinel (bsentinel)

**무의존성 바이너리 포렌식, PE/ELF 정적 분석기, 패커 엔트로피 탐지기 및 선언적 바이트 패칭 툴킷**

[![CI](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/GHSFS/bin-sentinel/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B_Safe-orange.svg)](../../SECURITY.md)
[![Roadmap](https://img.shields.io/badge/Roadmap-Active-10b981.svg)](../../ROADMAP.md)

</div>

---

## 🔍 개요

<details open>
<summary><b>🔍 개요</b></summary>
<br>

bin-sentinel(bsentinel)은 외부 런타임 의존성 없이 동작하는 100% 안전한 Rust 기반 단일 바이너리 정적 실행 파일 분석, 리버스 엔지니어링 초기 분류(Triage) 및 선언적 바이트 패칭 툴킷입니다. 무거운 외부 도구 없이 신속하고 결정론적인 바이너리 정밀 검사가 필요한 보안 분석가, 악성코드 연구원 및 시스템 엔지니어를 위해 설계되었습니다.

</details>

---

## 🏛️ 핵심 아키텍처 및 정적 분석 파이프라인

<details open>
<summary><b>🏛️ 핵심 아키텍처 및 정적 분석 파이프라인</b></summary>
<br>

<p align="center">
  <img src="../assets/locales/ko/architecture.svg" alt="핵심 아키텍처 및 정적 분석 파이프라인" width="100%" />
</p>

| # | 모듈명 | 소스 경로 | 핵심 기능 및 보안 불변식 |
|---|---|---|---|
| **01** | **PE32/PE32+ 정적 파서** | `src/pe.rs` | DOS/COFF/Optional 헤더 경계 검증 파싱, ASLR/DEP/CFG 보호 기법 및 RWX 이상 섹션 탐지 |
| **02** | **엔트로피 & 패커 휴리스틱** | `src/entropy.rs` | 섀넌 엔트로피(0..8 bits/B), 카이제곱 균일성 검정 및 UPX/VMProtect/Themida 시그니처 탐지 |
| **03** | **정적 문자열 & IoC 스캐너** | `src/strings.rs` | ASCII 및 UTF-16LE 문자열 추출과 URL, IPv4, 레지스트리 키, 주요 Win32 인젝션 API 자동 분류 |
| **04** | **선언적 바이트 패처** | `src/patch.rs` | 상수시간 원본 바이트 대조, 패치 전후 SHA-256 해시 산출, .bak 백업 생성 및 Zeroize 메모리 소거 |
| **05** | **구조화 CLI & JSON 출력** | `src/cli.rs` | 재현 가능한 테스트용 PE64 생성기(synth-pe) 및 CI 파이프라인 연동용 기계 판독 가능 --json 출력 모드 지원 |

</details>

---

## ⚡ 빠른 시작 및 CLI 사용법

<details open>
<summary><b>⚡ 빠른 시작 및 CLI 사용법</b></summary>
<br>

```bash
# 1. 릴리스 바이너리 빌드
cargo build --release

# 2. 결정론적 합성 PE32+ (64비트) 테스트 바이너리 생성
bsentinel synth-pe sample.exe

# 3. PE 헤더, ASLR/DEP/CFG 완화 기법, 섹션 테이블 및 패커 휴리스틱 검사
bsentinel inspect sample.exe
bsentinel inspect sample.exe --json

# 4. 결정론적 합성 Linux/BSD ELF64 바이너리 생성 및 검사
bsentinel synth-elf sample.elf
bsentinel inspect-elf sample.elf
bsentinel inspect-elf sample.elf --json

# 5. 통계적 섀넌 엔트로피 및 카이제곱 균일성 분석 실행
bsentinel entropy sample.exe --window 512
bsentinel entropy sample.exe --window 512 --json

# 6. 출력 가능한 ASCII 및 UTF-16LE 문자열 추출 및 침해 지표(IoC) 필터링
bsentinel strings sample.exe --min-len 4
bsentinel strings sample.exe --ioc-only --json

# 7. 바이너리 내 내장 암호화 상수, AES S-Box, SHA/ChaCha20 키 및 CRC 테이블 스캔
bsentinel crypto-scan sample.exe
bsentinel crypto-scan sample.exe --json

# 8. PE 임포트/익스포트 테이블(IAT/EAT) 검사, imphash 산출 및 동적 API 해시 해석
bsentinel imports sample.exe
bsentinel imports sample.exe --resolve-hash 0x0726774C --json

# 9. 원본 바이트 검증 및 .bak 백업을 포함한 검증된 선언적 바이트 패치 적용
bsentinel patch sample.exe --offset 0x200 --expect 4883EC28 --replace 90909090 --backup --json

# 10. x86_64 프롤로그, 직접 시스템 콜(Direct Syscall), RDTSC 안티디버깅 및 CPUID 검사 스캔
bsentinel scan-code sample.exe
bsentinel scan-code sample.exe --json

# 11. 와일드카드, 바이트 점프 및 JSON 규칙을 활용한 선언적 YARA 스타일 16진수 시그니처 스캔
bsentinel rule-scan sample.exe --pattern "48 83 EC ?? [2-6] E8"
bsentinel rule-scan sample.exe --rules rules.json --json

# 12. 두 바이너리를 구조적으로 비교하고 선언적 JSON 패치 레시피 내보내기
bsentinel diff baseline.exe modified.exe --out-recipe patch.json
bsentinel diff baseline.exe modified.exe --json

# 13. Dry-run 사전 검증 및 백업을 포함한 선언적 패치 레시피 적용 또는 원복(Reverse)
bsentinel apply-recipe baseline.exe patch.json --dry-run
bsentinel apply-recipe baseline.exe patch.json --backup
bsentinel apply-recipe baseline.exe patch.json --reverse

# 14. PE Rich 헤더 디코딩, Visual Studio 툴체인 핑거프린팅 및 32비트 체크섬 검증
bsentinel rich sample.exe
bsentinel rich sample.exe --json

# 15. 숨겨진 IoC 및 헤더를 식별하기 위한 단일/다중 바이트 XOR, ADD 및 ROL 난독화 해제 무차별 대입
bsentinel xor-scan sample.exe
bsentinel xor-scan sample.exe --json

# 16. PE 리소스 디렉터리(.rsrc) 검사, 매니페스트, UAC 실행 수준 및 버전 정보 추출
bsentinel resources sample.exe
bsentinel resources sample.exe --json

# 17. PE TLS 콜백, 메인 진입 이전 훅 및 x64 예외 언와인드(.pdata) 테이블 검사
bsentinel callbacks sample.exe
bsentinel callbacks sample.exe --json

# 18. 안전한 추출을 지원하는 내장 Base64, URL-Safe Base64 및 16진수 페이로드 카빙 및 디코딩
bsentinel carve sample.exe
bsentinel carve sample.exe --extract-dir ./extracted_payloads --json

# 19. 롤링 해시 부분 퍼지 유사도 다이제스트(CTPH / SSDEEP) 및 섹션 핑거프린트 산출
bsentinel fuzzy-hash sample.exe
bsentinel fuzzy-hash sample.exe --json

# 20. 바이너리 아티팩트 비교 및 섹션별 퍼지 유사도 점수(0..=100) 상관 분석
bsentinel fuzzy-compare original.exe modified.exe
bsentinel fuzzy-compare original.exe modified.exe --json
```

</details>

---

## 📦 저장소 구조 및 소스 트리

<details open>
<summary><b>📦 저장소 구조 및 소스 트리</b></summary>
<br>

```text
bin-sentinel/
├── Cargo.toml                     # 순수 Rust 패키지 매니페스트 (bsentinel 바이너리 및 bin_sentinel 라이브러리)
├── README.md                      # 10개 국어 네비게이션을 포함한 루트 영문 문서
├── ROADMAP.md                     # 공개 엔지니어링 개발 로드맵
├── CHANGELOG.md                   # 버전별 Keep-a-Changelog 릴리스 변경 이력
├── SECURITY.md                    # 바이너리 파싱 및 메모리 안전성 정책
├── LICENSE                        # Apache License 2.0
├── NOTICE                         # GHSFS 저작권 및 귀속 고지
├── src/
│   ├── lib.rs                     # 라이브러리 공개 모듈 인터페이스
│   ├── main.rs                    # 커맨드 디스패치를 수행하는 간결한 CLI 엔트리포인트
│   ├── cli.rs                     # Clap 파생 서브커맨드 정의 (inspect, inspect-elf, imports, crypto-scan, scan-code, rule-scan, rich, xor-scan, carve 등)
│   ├── commands/                  # 모듈형 CLI 서브커맨드 핸들러 (inspect, forensics, rules, diff, authenticode, macho, rich, callbacks, carve, fuzzy)
│   ├── error.rs                   # 통합 SentinelError 및 Result<T> 정의
│   ├── pe.rs                      # 외부 의존성 없는 PE32/PE32+ 헤더 및 섹션 파서 + 합성 PE64 빌더
│   ├── elf/                       # 외부 의존성 없는 Linux/BSD ELF64 파서 (헤더, 모듈, 합성 빌더)
│   ├── imports/                   # PE 임포트/익스포트(IAT/EAT) 파서, RFC 1321 MD5 imphash 및 동적 API 해시 해석기
│   ├── crypto_scan/               # 내장 암호화 원시값, AES/SM4 S-Box 및 해시 상수 스캐너
│   ├── disasm/                    # x86_64 프롤로그/에필로그, 직접 시스템 콜 및 제어 흐름 패턴 스캐너
│   ├── rules/                     # 선언적 YARA 스타일 16진수 시그니처, 니블 와일드카드 및 바이트 점프 스캐너
│   ├── rich/                      # PE Rich 헤더 디코더, MSVC 컴파일러 툴체인 핑거프린터 및 체크섬 검증기
│   ├── deobfuscate/               # 단일/다중 바이트 XOR, ADD 및 ROL 난독화 해제 스캐너 및 키 복구기
│   ├── resources/                 # PE 3단계 리소스 디렉터리(.rsrc), 애플리케이션 매니페스트 및 버전 정보 파서
│   ├── callbacks/                 # PE TLS 콜백, 메인 진입 이전 훅 및 x64 .pdata 예외 언와인드 테이블
│   ├── carve/                     # Base64, URL-Safe Base64 및 16진수 페이로드 카빙, 디코딩 및 분류기
│   ├── fuzzy_hash/                # CTPH 롤링 해시 엔진, 이중 블록 크기 스케일링 및 바이너리 유사도 비교기
│   ├── entropy.rs                 # 섀넌 엔트로피, 카이제곱 균일성 검정 및 패커 휴리스틱 탐지기
│   ├── strings.rs                 # ASCII 및 UTF-16LE 문자열 추출기 + 침해 지표(IoC) 분류기
│   ├── patch.rs                   # SHA-256 및 Zeroize 기반 상수시간 검증 바이트 패칭 엔진
│   └── diff/                      # 구조적 바이너리 비교 및 선언적 패치 레시피 엔진
├── tests/
│   ├── pe_entropy_test.rs         # PE64 파싱, 보호 기법, 엔트로피 및 CLI JSON 출력 통합 테스트
│   ├── patch_strings_test.rs      # IoC 문자열 추출, 검증된 패칭 및 백업 생성 통합 테스트
│   ├── elf_test.rs                # ELF64 파싱, PIE/RELRO/NX 완화 기법 및 동적 심볼 통합 테스트
│   ├── crypto_scan_test.rs        # 암호화 상수, S-Box 및 PE/ELF 섹션 매핑 통합 테스트
│   ├── imports_test.rs            # PE IAT/EAT 테이블, imphash 및 동적 API 해시 해석 통합 테스트
│   ├── carve_test.rs              # Base64/16진수 카빙, PowerShell 크래들, 안전 추출 및 CLI 통합 테스트
│   ├── disasm_test.rs             # x86_64 프롤로그, 직접 시스템 콜 및 안티디버깅 검사 통합 테스트
│   ├── rules_test.rs              # YARA 스타일 16진수 와일드카드, 점프, 문자열 및 JSON 규칙 통합 테스트
│   ├── diff_test.rs               # 구조적 바이너리 diff, 패치 레시피 및 원자적 롤백 통합 테스트
│   ├── rich_test.rs               # PE Rich 헤더 디코딩, 툴체인 핑거프린팅 및 체크섬 검증 통합 테스트
│   ├── deobfuscate_test.rs        # XOR/ADD/ROL 난독화 해제, 크립 드래깅 및 페이로드 분류 통합 테스트
│   ├── resources_test.rs          # PE 리소스 디렉터리 트리, UAC 매니페스트 및 버전 정보 통합 테스트
│   ├── callbacks_test.rs          # TLS 콜백, 메인 이전 훅, pdata 테이블 및 예외 핸들러 통합 테스트
│   ├── fuzzy_hash_test.rs         # CTPH 퍼지 해싱, 레벤슈타인 거리 및 바이너리 유사도 비교 통합 테스트
└── docs/
    ├── locales/                   # 다국어 README 문서 (ko, zh-CN, es, hi, ar, pt-BR, ru, fr, id)
    └── assets/locales/            # 언어별 자체 호스팅 SVG 배너 및 아키텍처 다이어그램
```

</details>

---

## 🔒 메모리 안전성 및 보안 불변식

<details open>
<summary><b>🔒 메모리 안전성 및 보안 불변식</b></summary>
<br>

- 🛡️ 모든 바이너리 헤더 파서 전반에 걸쳐 `unsafe` 블록을 일절 사용하지 않으며, 모든 오프셋 및 슬라이스 접근 시 경계 검사 연산을 적용합니다.
- 🛡️ 바이너리 패치 적용 전 상수시간 바이트 검증(`constant_time_eq`)을 거치며, 원본 데이터 불일치 시 `PatchMismatch` 에러로 작업을 즉시 중단합니다.
- 🛡️ 완벽한 암호화 감사 추적: 패치 적용 전후의 SHA-256 다이제스트를 계산하여 보고하며, 선택적 `.bak` 백업 파일을 생성합니다.
- 🛡️ 가변 바이너리 패치 버퍼에 대해 메모리 해제 시 `zeroize`를 통해 선제적인 메모리 완전 소거를 수행합니다.

</details>

---

## 📄 라이선스 및 저작권 안내

<details open>
<summary><b>📄 라이선스 및 저작권 안내</b></summary>
<br>

NOTICE 귀속 파일을 포함한 Apache License, Version 2.0 라이선스를 따릅니다. GHSFS 소유.

```text
Copyright 2026 GHSFS (https://github.com/GHSFS)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

</details>
