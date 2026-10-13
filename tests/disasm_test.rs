// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Integration tests for x86_64 prologue, epilogue, direct syscall, and control-flow pattern scanner.

use std::fs;
use std::process::Command;

use bin_sentinel::disasm::{scan_code_bytes, scan_code_file, CodePatternKind, CodeScanReport};
use bin_sentinel::elf::{build_synthetic_elf64, SHF_ALLOC, SHF_EXECINSTR, SHT_PROGBITS};
use tempfile::NamedTempFile;

#[test]
fn test_detect_prologues_and_epilogues() {
    let mut payload = Vec::new();
    // 1. Prologue: push rbp; mov rbp, rsp; sub rsp, 0x20
    payload.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20]);
    // 2. Epilogue: add rsp, 0x20; ret
    payload.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20, 0xC3]);
    // 3. Prologue: 40 55 48 83 EC 30 (push rbp; sub rsp, 0x30)
    payload.extend_from_slice(&[0x40, 0x55, 0x48, 0x83, 0xEC, 0x30]);
    // 4. Epilogue: mov rsp, rbp; pop rbp; ret
    payload.extend_from_slice(&[0x48, 0x89, 0xEC, 0x5D, 0xC3]);
    // 5. Epilogue: leave; ret
    payload.extend_from_slice(&[0xC9, 0xC3]);

    let (matches, summary) = scan_code_bytes(&payload);

    assert_eq!(summary.prologues, 2);
    assert_eq!(summary.epilogues, 3);
    assert_eq!(summary.total_patterns, 5);

    assert_eq!(matches[0].category, CodePatternKind::Prologue);
    assert!(matches[0]
        .mnemonic
        .contains("push rbp; mov rbp, rsp; sub rsp, 0x20"));

    assert_eq!(matches[1].category, CodePatternKind::Epilogue);
    assert!(matches[1].mnemonic.contains("add rsp, 0x20; ret"));

    assert_eq!(matches[2].category, CodePatternKind::Prologue);
    assert!(matches[2].mnemonic.contains("push rbp; sub rsp, 0x30"));

    assert_eq!(matches[3].category, CodePatternKind::Epilogue);
    assert!(matches[3].mnemonic.contains("mov rsp, rbp; pop rbp; ret"));

    assert_eq!(matches[4].category, CodePatternKind::Epilogue);
    assert_eq!(matches[4].mnemonic, "leave; ret");
}

#[test]
fn test_direct_syscall_stub_detection() {
    let mut payload = Vec::new();
    // Windows direct syscall stub (SysWhispers style, SSN = 0x0018 NtAllocateVirtualMemory):
    // 4C 8B D1 B8 18 00 00 00 0F 05 C3
    payload.extend_from_slice(&[
        0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    ]);
    // Linux direct syscall stub (sys_exit = 60 / 0x3C):
    // B8 3C 00 00 00 0F 05 C3
    payload.extend_from_slice(&[0xB8, 0x3C, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3]);
    // Standalone syscall:
    payload.extend_from_slice(&[0x0F, 0x05]);

    let (matches, summary) = scan_code_bytes(&payload);

    assert_eq!(summary.syscall_stubs, 3);
    assert!(summary.suspicious_alerts_count >= 2);

    let win_stub = &matches[0];
    assert_eq!(win_stub.pattern_id, "win64-direct-syscall-stub");
    assert!(win_stub.mnemonic.contains("mov eax, 0x18; syscall; ret"));
    assert!(win_stub
        .risk_alert
        .as_ref()
        .unwrap()
        .contains("EDR evasion"));

    let linux_stub = &matches[1];
    assert_eq!(linux_stub.pattern_id, "linux64-direct-syscall-stub");
    assert!(linux_stub.mnemonic.contains("mov eax, 60; syscall; ret"));

    let standalone = &matches[2];
    assert_eq!(standalone.pattern_id, "x64-syscall");
}

#[test]
fn test_anti_debug_rdtsc_and_cpuid_checks() {
    let mut payload = Vec::new();
    // 1. RDTSC: 0F 31
    payload.extend_from_slice(&[0x0F, 0x31]);
    // 2. RDTSCP: 0F 01 F9
    payload.extend_from_slice(&[0x0F, 0x01, 0xF9]);
    // 3. CPUID: 0F A2
    payload.extend_from_slice(&[0x0F, 0xA2]);
    // 4. SMSW: 0F 01 F0
    payload.extend_from_slice(&[0x0F, 0x01, 0xF0]);

    let (matches, summary) = scan_code_bytes(&payload);

    assert_eq!(summary.anti_debug_timing, 2);
    assert_eq!(summary.vm_checks, 2);
    assert_eq!(summary.suspicious_alerts_count, 4);

    assert_eq!(matches[0].category, CodePatternKind::AntiDebugTiming);
    assert_eq!(matches[0].mnemonic, "rdtsc");
    assert!(matches[0].risk_alert.is_some());

    assert_eq!(matches[1].category, CodePatternKind::AntiDebugTiming);
    assert_eq!(matches[1].mnemonic, "rdtscp");

    assert_eq!(matches[2].category, CodePatternKind::VmHypervisorCheck);
    assert_eq!(matches[2].mnemonic, "cpuid");

    assert_eq!(matches[3].category, CodePatternKind::VmHypervisorCheck);
    assert_eq!(matches[3].mnemonic, "smsw");
}

#[test]
fn test_traps_breakpoints_and_indirect_branches() {
    let mut payload = Vec::new();
    // 1. UD2 trap: 0F 0B
    payload.extend_from_slice(&[0x0F, 0x0B]);
    // 2. Isolated software breakpoint: CC (followed by NOP to separate from padding)
    payload.extend_from_slice(&[0xCC, 0x90]);
    // 3. Function padding run of CC (>= 4 bytes): CC CC CC CC CC
    payload.extend_from_slice(&[0xCC, 0xCC, 0xCC, 0xCC, 0xCC]);
    // 4. ICEBP / INT 1: F1
    payload.extend_from_slice(&[0xF1]);
    // 5. JMP RSP stack pivot / gadget: FF E4
    payload.extend_from_slice(&[0xFF, 0xE4]);
    // 6. JMP RAX: FF E0
    payload.extend_from_slice(&[0xFF, 0xE0]);

    let (matches, summary) = scan_code_bytes(&payload);

    assert_eq!(summary.traps, 4);
    assert_eq!(summary.indirect_branches, 2);

    assert_eq!(matches[0].pattern_id, "x86-ud2-trap");
    assert_eq!(matches[1].pattern_id, "x86-int3-trap");
    assert!(matches[1].risk_alert.is_some());

    assert_eq!(matches[2].pattern_id, "x86-int3-padding");
    assert!(matches[2].risk_alert.is_none()); // Alignment padding is benign

    assert_eq!(matches[3].pattern_id, "x86-icebp-trap");

    assert_eq!(matches[4].pattern_id, "x86-jmp-rsp-pivot");
    assert!(matches[4]
        .risk_alert
        .as_ref()
        .unwrap()
        .contains("stack pivot"));

    assert_eq!(matches[5].pattern_id, "x86-jmp-rax");
}

#[test]
fn test_synthetic_pe_and_elf_code_scanning() {
    // 1. Build synthetic PE with code sequence in .text
    let mut code_payload = Vec::new();
    // Prologue: push rbp; mov rbp, rsp; sub rsp, 0x20
    code_payload.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20]);
    // Direct syscall stub
    code_payload.extend_from_slice(&[
        0x4C, 0x8B, 0xD1, 0xB8, 0x25, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    ]);
    // RDTSC timing check
    code_payload.extend_from_slice(&[0x0F, 0x31]);
    // Ret
    code_payload.push(0xC3);

    use bin_sentinel::pe::{
        build_synthetic_pe64, IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
    };

    let pe_bytes = build_synthetic_pe64(&[(
        ".text",
        &code_payload,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE,
    )]);

    let temp_pe = NamedTempFile::new().expect("create temp pe");
    fs::write(temp_pe.path(), &pe_bytes).expect("write temp pe");

    let pe_report = scan_code_file(temp_pe.path()).expect("scan pe code");
    assert!(pe_report.binary_format.contains("PE"));
    assert!(pe_report.executable_sections.contains(&".text".to_string()));
    assert!(pe_report.summary.total_patterns >= 4);
    assert_eq!(pe_report.summary.prologues, 1);
    assert_eq!(pe_report.summary.syscall_stubs, 1);
    assert_eq!(pe_report.summary.anti_debug_timing, 1);

    // Verify section name and RVA resolution
    let syscall_match = pe_report
        .matches
        .iter()
        .find(|m| m.pattern_id == "win64-direct-syscall-stub")
        .expect("found syscall stub in pe");
    assert_eq!(syscall_match.section_name.as_deref(), Some(".text"));
    assert!(syscall_match.relative_virtual_address.is_some());

    // 2. Build synthetic ELF64 with code payload
    let elf_bytes = build_synthetic_elf64(&[(
        ".text",
        &code_payload,
        SHF_ALLOC | SHF_EXECINSTR,
        SHT_PROGBITS,
    )]);

    let temp_elf = NamedTempFile::new().expect("create temp elf");
    fs::write(temp_elf.path(), &elf_bytes).expect("write temp elf");

    let elf_report = scan_code_file(temp_elf.path()).expect("scan elf code");
    assert!(elf_report.binary_format.contains("ELF"));
    assert!(elf_report
        .executable_sections
        .contains(&".text".to_string()));
    assert!(elf_report.summary.total_patterns >= 4);

    let elf_syscall = elf_report
        .matches
        .iter()
        .find(|m| m.pattern_id == "win64-direct-syscall-stub")
        .expect("found syscall stub in elf");
    assert_eq!(elf_syscall.section_name.as_deref(), Some(".text"));
    assert!(elf_syscall.relative_virtual_address.is_some());
}

#[test]
fn test_cli_scan_code_json_and_table_output() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20]);
    payload.extend_from_slice(&[0x0F, 0x31]);
    payload.extend_from_slice(&[0x0F, 0xA2]);
    payload.extend_from_slice(&[0xC3]);

    let temp_file = NamedTempFile::new().expect("create temp file");
    fs::write(temp_file.path(), &payload).expect("write payload");

    // 1. Test CLI with --json
    let bin_path = env!("CARGO_BIN_EXE_bsentinel");
    let output_json = Command::new(bin_path)
        .arg("scan-code")
        .arg(temp_file.path())
        .arg("--json")
        .output()
        .expect("run bsentinel scan-code --json");

    assert!(output_json.status.success());
    let stdout_json = String::from_utf8_lossy(&output_json.stdout);
    let report: CodeScanReport =
        serde_json::from_str(&stdout_json).expect("deserialize json report");
    assert_eq!(report.summary.prologues, 1);
    assert_eq!(report.summary.anti_debug_timing, 1);
    assert_eq!(report.summary.vm_checks, 1);
    assert_eq!(report.summary.epilogues, 1);

    // 2. Test CLI human-readable table output
    let output_table = Command::new(bin_path)
        .arg("scan-code")
        .arg(temp_file.path())
        .output()
        .expect("run bsentinel scan-code");

    assert!(output_table.status.success());
    let stdout_table = String::from_utf8_lossy(&output_table.stdout);
    assert!(stdout_table.contains("x86_64 Code Pattern & Control-Flow Scan"));
    assert!(stdout_table.contains("Patterns Found"));
    assert!(stdout_table.contains("Detected Instructions & Control Flow"));
    assert!(stdout_table.contains("rdtsc"));
    assert!(stdout_table.contains("cpuid"));
}
