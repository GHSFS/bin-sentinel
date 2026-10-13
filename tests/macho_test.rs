// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fs;
use std::process::Command;

use bin_sentinel::macho::{
    build_synthetic_macho64, build_synthetic_macho_universal, parse_macho, CPU_SUBTYPE_ARM64_ALL,
    CPU_SUBTYPE_X86_64_ALL, CPU_TYPE_ARM64, CPU_TYPE_X86_64, VM_PROT_EXECUTE, VM_PROT_READ,
    VM_PROT_WRITE,
};

#[test]
fn test_reject_malformed_and_truncated_macho() {
    let empty = b"";
    assert!(parse_macho(empty).is_err());

    let too_short = b"\xFE\xED\xFA";
    assert!(parse_macho(too_short).is_err());

    let wrong_magic = vec![0u8; 64];
    assert!(parse_macho(&wrong_magic).is_err());

    // 32-bit Mach-O magic (MH_MAGIC_32 little-endian: 0xFEEDFACE)
    let mut class_32 = vec![0u8; 64];
    class_32[0..4].copy_from_slice(&0xFEEDFACEu32.to_le_bytes());
    assert!(parse_macho(&class_32).is_err());

    // Universal fat binary with 0 architectures
    let mut fat_zero = vec![0u8; 32];
    fat_zero[0..4].copy_from_slice(&0xCAFEBABEu32.to_be_bytes());
    fat_zero[4..8].copy_from_slice(&0u32.to_be_bytes()); // nfat_arch = 0
    assert!(parse_macho(&fat_zero).is_err());
}

#[test]
fn test_parse_synthetic_macho64_and_load_commands() {
    let code_bytes = b"\x48\x31\xC0\x48\xFF\xC0\xC3"; // xor rax, rax; inc rax; ret
    let cstring_bytes = b"Mach-O 64-bit Forensic Target String\0";
    let sections = [
        ("__text", &code_bytes[..], 0x80000400u32),
        ("__cstring", &cstring_bytes[..], 0x02u32),
    ];

    let macho_bytes = build_synthetic_macho64(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, &sections);
    let info = parse_macho(&macho_bytes).expect("synthetic Mach-O 64-bit must parse cleanly");

    assert_eq!(info.format, "Mach-O 64-bit");
    assert_eq!(info.magic, "0xFEEDFACF");
    assert!(!info.is_universal);
    assert_eq!(info.architectures.len(), 1);

    let arch = &info.architectures[0];
    assert_eq!(arch.cpu_type, "x86_64");
    assert_eq!(arch.file_type, "MH_EXECUTE");
    assert_eq!(arch.entry_point, Some(0x500));
    assert!(arch.load_commands_count >= 4);

    // Security mitigations
    assert!(arch.mitigations.pie, "PIE flag must be detected");
    assert!(arch.mitigations.nx, "Stack execution must be prohibited");
    assert!(
        arch.mitigations.code_signature,
        "LC_CODE_SIGNATURE must be present"
    );
    assert!(
        arch.mitigations.two_level_namespace,
        "MH_TWOLEVEL flag must be detected"
    );

    // Segments and sections
    let seg_names: Vec<&str> = arch.segments.iter().map(|s| s.name.as_str()).collect();
    assert!(seg_names.contains(&"__PAGEZERO"));
    assert!(seg_names.contains(&"__TEXT"));

    let sec_names: Vec<&str> = arch.sections.iter().map(|s| s.sectname.as_str()).collect();
    assert!(sec_names.contains(&"__text"));
    assert!(sec_names.contains(&"__cstring"));

    // Entropy calculation
    let text_sec = arch
        .sections
        .iter()
        .find(|s| s.sectname == "__text")
        .expect("__text section must exist");
    assert!(text_sec.entropy > 0.0);

    // Dylibs and Code Signature
    assert_eq!(arch.dylibs, vec!["/usr/lib/libSystem.B.dylib".to_string()]);
    assert!(arch.code_signature.is_some());
}

#[test]
fn test_parse_synthetic_macho_universal_fat_binary() {
    let x86_code = b"\x48\x31\xC0\x48\xFF\xC0\xC3";
    let x86_slice = build_synthetic_macho64(
        CPU_TYPE_X86_64,
        CPU_SUBTYPE_X86_64_ALL,
        &[("__text", x86_code, 0x80000400)],
    );

    let arm64_code = b"\x00\x00\x80\xD2\xC0\x03\x5F\xD6";
    let arm64_slice = build_synthetic_macho64(
        CPU_TYPE_ARM64,
        CPU_SUBTYPE_ARM64_ALL,
        &[("__text", arm64_code, 0x80000400)],
    );

    let universal_bytes = build_synthetic_macho_universal(&[
        (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, &x86_slice),
        (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, &arm64_slice),
    ]);

    let info =
        parse_macho(&universal_bytes).expect("synthetic Universal binary must parse cleanly");

    assert_eq!(info.format, "Mach-O Universal (Fat Binary)");
    assert_eq!(info.magic, "0xCAFEBABE");
    assert!(info.is_universal);
    assert_eq!(info.architectures.len(), 2);

    assert_eq!(info.architectures[0].cpu_type, "x86_64");
    assert_eq!(info.architectures[1].cpu_type, "arm64");

    for arch in &info.architectures {
        assert_eq!(arch.file_type, "MH_EXECUTE");
        assert!(arch.mitigations.pie);
        assert!(arch.mitigations.nx);
        assert!(arch.mitigations.code_signature);
        assert!(!arch.sections.is_empty());
    }
}

#[test]
fn test_macho_rwx_anomaly_and_security_alerts() {
    let mut macho_bytes = build_synthetic_macho64(
        CPU_TYPE_X86_64,
        CPU_SUBTYPE_X86_64_ALL,
        &[("__text", b"\x90\x90\x90\x90", 0x80000400)],
    );

    // Modify __TEXT segment initprot to VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE (7)
    // __TEXT segment command starts after header (32 bytes) + __PAGEZERO (72 bytes) = 104 bytes
    // initprot is at offset 104 + 60 = 164
    let initprot_offset = 164;
    let rwx_prot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
    macho_bytes[initprot_offset..initprot_offset + 4].copy_from_slice(&rwx_prot.to_le_bytes());

    let info = parse_macho(&macho_bytes).expect("macho with RWX should parse with alerts");
    let has_rwx_alert = info
        .alerts
        .iter()
        .any(|a| a.contains("Writable and Executable (RWX)"));
    assert!(
        has_rwx_alert,
        "RWX anomaly must trigger alert in info.alerts"
    );
}

#[test]
fn test_cli_synth_macho_and_inspect_macho_json_and_table() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let macho_path = tmp.path().join("sample_test.macho");
    let universal_path = tmp.path().join("sample_universal.macho");

    let cargo_bin = env!("CARGO_BIN_EXE_bsentinel");

    // 1. Generate 64-bit Mach-O via CLI synth-macho
    let synth_status = Command::new(cargo_bin)
        .arg("synth-macho")
        .arg(&macho_path)
        .status()
        .expect("run synth-macho");
    assert!(synth_status.success());
    assert!(macho_path.exists());

    // 2. Inspect Mach-O human table output
    let inspect_out = Command::new(cargo_bin)
        .arg("inspect-macho")
        .arg(&macho_path)
        .output()
        .expect("run inspect-macho");
    assert!(inspect_out.status.success());
    let stdout = String::from_utf8_lossy(&inspect_out.stdout);
    assert!(stdout.contains("=== Mach-O Static Inspection:"));
    assert!(stdout.contains("Format            : Mach-O 64-bit"));
    assert!(stdout.contains("x86_64"));
    assert!(stdout.contains("__TEXT"));
    assert!(stdout.contains("__text"));
    assert!(stdout.contains("/usr/lib/libSystem.B.dylib"));

    // 3. Inspect Mach-O JSON output
    let json_out = Command::new(cargo_bin)
        .arg("inspect-macho")
        .arg(&macho_path)
        .arg("--json")
        .output()
        .expect("run inspect-macho --json");
    assert!(json_out.status.success());

    let json_val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse inspect-macho json output");
    assert_eq!(json_val["format"], "Mach-O 64-bit");
    assert_eq!(json_val["is_universal"], false);
    assert_eq!(json_val["architectures"][0]["cpu_type"], "x86_64");
    assert_eq!(json_val["architectures"][0]["mitigations"]["pie"], true);
    assert_eq!(json_val["architectures"][0]["mitigations"]["nx"], true);
    assert_eq!(
        json_val["architectures"][0]["mitigations"]["code_signature"],
        true
    );

    // 4. Generate Universal Fat Mach-O via CLI synth-macho --universal
    let synth_uni_status = Command::new(cargo_bin)
        .arg("synth-macho")
        .arg(&universal_path)
        .arg("--universal")
        .status()
        .expect("run synth-macho --universal");
    assert!(synth_uni_status.success());
    assert!(universal_path.exists());

    // 5. Inspect Universal Mach-O JSON output
    let uni_json_out = Command::new(cargo_bin)
        .arg("inspect-macho")
        .arg(&universal_path)
        .arg("--json")
        .output()
        .expect("run inspect-macho --universal --json");
    assert!(uni_json_out.status.success());

    let uni_val: serde_json::Value =
        serde_json::from_slice(&uni_json_out.stdout).expect("parse inspect universal json output");
    assert_eq!(uni_val["format"], "Mach-O Universal (Fat Binary)");
    assert_eq!(uni_val["is_universal"], true);
    let archs = uni_val["architectures"]
        .as_array()
        .expect("architectures array");
    assert_eq!(archs.len(), 2);
    assert_eq!(archs[0]["cpu_type"], "x86_64");
    assert_eq!(archs[1]["cpu_type"], "arm64");

    fs::remove_dir_all(tmp.path()).ok();
}
