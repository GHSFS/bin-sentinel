// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fs;
use std::process::Command;

use bin_sentinel::elf::{
    build_synthetic_elf64, parse_elf, RelroLevel, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_PROGBITS,
};

#[test]
fn test_reject_malformed_and_truncated_elf() {
    let empty = b"";
    assert!(parse_elf(empty).is_err());

    let too_short = b"\x7FELF\x02\x01\x01\x00";
    assert!(parse_elf(too_short).is_err());

    let wrong_magic = vec![0u8; 64];
    assert!(parse_elf(&wrong_magic).is_err());

    // Valid magic but 32-bit class (1)
    let mut class_32 = vec![0u8; 64];
    class_32[0..4].copy_from_slice(b"\x7FELF");
    class_32[4] = 1; // 32-bit
    assert!(parse_elf(&class_32).is_err());

    // Valid magic, 64-bit class, but Big Endian (2)
    let mut be_data = vec![0u8; 64];
    be_data[0..4].copy_from_slice(b"\x7FELF");
    be_data[4] = 2;
    be_data[5] = 2; // Big endian
    assert!(parse_elf(&be_data).is_err());
}

#[test]
fn test_parse_synthetic_elf64_and_security_mitigations() {
    let code_bytes = b"\x48\x31\xC0\x48\xFF\xC0\xC3"; // xor rax, rax; inc rax; ret
    let rodata_bytes = b"BinSentinel ELF64 Verification String\0";
    let sections = [
        (
            ".text",
            &code_bytes[..],
            SHF_ALLOC | SHF_EXECINSTR,
            SHT_PROGBITS,
        ),
        (".rodata", &rodata_bytes[..], SHF_ALLOC, SHT_PROGBITS),
    ];

    let elf_bytes = build_synthetic_elf64(&sections);
    let info = parse_elf(&elf_bytes).expect("synthetic ELF64 must parse cleanly");

    assert_eq!(info.class, "ELF64");
    assert_eq!(info.endianness, "Little Endian (ELFDATA2LSB)");
    assert_eq!(info.os_abi, "Linux");
    assert_eq!(info.machine, "x86_64 (AMD64)");
    assert_eq!(info.entry_point, 0x1000);

    // Mitigations
    assert!(info.mitigations.pie, "ET_DYN should be detected as PIE");
    assert!(
        info.mitigations.nx,
        "PT_GNU_STACK without PF_X should be detected as NX enabled"
    );
    assert_eq!(
        info.mitigations.relro,
        RelroLevel::Partial,
        "PT_GNU_RELRO without BIND_NOW should be Partial RELRO"
    );
    assert!(
        info.mitigations.stack_canary,
        "__stack_chk_fail in dynsym must trigger canary detection"
    );

    // Sections
    let sec_names: Vec<&str> = info.sections.iter().map(|s| s.name.as_str()).collect();
    assert!(sec_names.contains(&".text"));
    assert!(sec_names.contains(&".rodata"));
    assert!(sec_names.contains(&".dynsym"));
    assert!(sec_names.contains(&".dynstr"));
    assert!(sec_names.contains(&".shstrtab"));

    // Program headers
    let seg_types: Vec<&str> = info
        .program_headers
        .iter()
        .map(|ph| ph.segment_type.as_str())
        .collect();
    assert!(seg_types.contains(&"PT_LOAD"));
    assert!(seg_types.contains(&"PT_GNU_STACK"));
    assert!(seg_types.contains(&"PT_GNU_RELRO"));

    // Symbols
    let sym_names: Vec<&str> = info.symbols.iter().map(|s| s.name.as_str()).collect();
    assert!(sym_names.contains(&"__stack_chk_fail"));
    assert!(sym_names.contains(&"main"));
}

#[test]
fn test_elf_rwx_anomaly_and_executable_stack_alerts() {
    let rwx_payload = b"\x90\x90\x90\x90";
    let sections = [(
        ".rwx_sec",
        &rwx_payload[..],
        SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR,
        SHT_PROGBITS,
    )];

    let mut elf_bytes = build_synthetic_elf64(&sections);

    // Invert PT_GNU_STACK to include PF_X (0x1) to simulate executable stack
    // Phdr 1 is PT_GNU_STACK at offset 64 + 56 = 120
    let pt_gnu_stack_flags_offset = 64 + 56 + 4;
    elf_bytes[pt_gnu_stack_flags_offset] |= 0x1; // Add PF_X

    let info = parse_elf(&elf_bytes).expect("ELF must parse");
    assert!(!info.mitigations.nx, "Stack is marked executable");

    let rwx_sec = info
        .sections
        .iter()
        .find(|s| s.name == ".rwx_sec")
        .expect("rwx section found");
    assert!(rwx_sec.rwx_anomaly, "RWX anomaly should be flagged");

    let alerts_text = info.alerts.join(" ");
    assert!(
        alerts_text.contains("Executable stack detected"),
        "Must alert on executable stack"
    );
    assert!(
        alerts_text.contains("RWX permissions"),
        "Must alert on RWX section"
    );
}

#[test]
fn test_cli_synth_elf_and_inspect_elf_json() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let elf_path = tmp.path().join("sample_test.elf");

    let cargo_bin = env!("CARGO_BIN_EXE_bsentinel");

    // 1. Generate synthetic ELF
    let synth_status = Command::new(cargo_bin)
        .arg("synth-elf")
        .arg(&elf_path)
        .status()
        .expect("run synth-elf");
    assert!(synth_status.success());
    assert!(elf_path.exists());

    // 2. Inspect ELF standard output
    let inspect_out = Command::new(cargo_bin)
        .arg("inspect-elf")
        .arg(&elf_path)
        .output()
        .expect("run inspect-elf");
    assert!(inspect_out.status.success());
    let stdout = String::from_utf8_lossy(&inspect_out.stdout);
    assert!(stdout.contains("=== ELF64 Static Inspection:"));
    assert!(stdout.contains("Machine           : 0x003E (x86_64 (AMD64))"));
    assert!(stdout.contains(".text"));

    // 3. Inspect ELF JSON output
    let json_out = Command::new(cargo_bin)
        .arg("inspect-elf")
        .arg(&elf_path)
        .arg("--json")
        .output()
        .expect("run inspect-elf --json");
    assert!(json_out.status.success());

    let json_val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse inspect-elf json output");
    assert_eq!(json_val["class"], "ELF64");
    assert_eq!(json_val["machine"], "x86_64 (AMD64)");
    assert_eq!(json_val["mitigations"]["pie"], true);
    assert_eq!(json_val["mitigations"]["nx"], true);
    assert_eq!(json_val["mitigations"]["stack_canary"], true);

    fs::remove_dir_all(tmp.path()).ok();
}
