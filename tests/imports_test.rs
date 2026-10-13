// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Integration tests for PE Import/Export tables, imphash, API hash resolver, and CLI.

use std::fs;
use std::process::Command;

use bin_sentinel::imports::{
    build_synthetic_pe, compute_imphash, hash_crc32, hash_djb2, hash_fnv1a, hash_ror13,
    inspect_imports, md5_hex, parse_exports, parse_hash_string, parse_imports, resolve_api_hash,
    ExportSpec, ImportSpec,
};
use bin_sentinel::pe::parse_pe;
use tempfile::tempdir;

#[test]
fn test_parse_pe64_imports_named_and_ordinal_and_imphash() {
    let imports_spec = [
        (
            "KERNEL32.DLL",
            &[
                ImportSpec::ByName("ExitProcess", 0),
                ImportSpec::ByName("CreateFileA", 1),
            ][..],
        ),
        ("WS2_32.dll", &[ImportSpec::ByOrdinal(115)][..]),
    ];

    let pe_bytes = build_synthetic_pe(true, &imports_spec, None);
    let pe = parse_pe(&pe_bytes).expect("synthetic PE64 must parse");

    assert_eq!(pe.format, "PE32+ (64-bit)");
    let descriptors = parse_imports(&pe_bytes, &pe).expect("imports must parse cleanly");
    assert_eq!(descriptors.len(), 2);

    // KERNEL32.DLL
    assert_eq!(descriptors[0].dll_name, "KERNEL32.DLL");
    assert_eq!(descriptors[0].functions.len(), 2);
    assert_eq!(
        descriptors[0].functions[0].name.as_deref(),
        Some("ExitProcess")
    );
    assert_eq!(descriptors[0].functions[0].hint, Some(0));
    assert_eq!(
        descriptors[0].functions[1].name.as_deref(),
        Some("CreateFileA")
    );
    assert_eq!(descriptors[0].functions[1].hint, Some(1));

    // WS2_32.dll
    assert_eq!(descriptors[1].dll_name, "WS2_32.dll");
    assert_eq!(descriptors[1].functions.len(), 1);
    assert_eq!(descriptors[1].functions[0].name, None);
    assert_eq!(descriptors[1].functions[0].ordinal, Some(115));

    // Mandiant imphash calculation verification
    let imphash = compute_imphash(&descriptors).expect("imphash must be generated");
    let expected_str = "kernel32.exitprocess,kernel32.createfilea,ws2_32.ord115";
    let expected_hash = md5_hex(expected_str.as_bytes());
    assert_eq!(imphash, expected_hash);
}

#[test]
fn test_parse_pe32_imports_and_exports_with_forwarders() {
    let imports_spec = [("USER32.dll", &[ImportSpec::ByName("MessageBoxA", 10)][..])];

    let exports_spec = (
        "my_library.dll",
        &[
            ExportSpec::ByName("InitEngine", 0x1000),
            ExportSpec::ByOrdinal(0x1010),
            ExportSpec::Forwarded("AllocMemory", "NTDLL.RtlAllocateHeap"),
        ][..],
    );

    let pe_bytes = build_synthetic_pe(false, &imports_spec, Some(exports_spec));
    let pe = parse_pe(&pe_bytes).expect("synthetic PE32 must parse");

    assert_eq!(pe.format, "PE32");

    // Verify imports
    let imports = parse_imports(&pe_bytes, &pe).expect("imports must parse cleanly");
    assert_eq!(imports.len(), 1);
    assert_eq!(imports[0].dll_name, "USER32.dll");
    assert_eq!(imports[0].functions[0].name.as_deref(), Some("MessageBoxA"));

    // Verify exports
    let export_info = parse_exports(&pe_bytes, &pe)
        .expect("exports must parse cleanly")
        .expect("export directory must be present");

    assert_eq!(export_info.dll_name, "my_library.dll");
    assert_eq!(export_info.base_ordinal, 1);
    assert_eq!(export_info.number_of_functions, 3);
    assert_eq!(export_info.number_of_names, 2);

    // Export 1: InitEngine
    assert_eq!(export_info.functions[0].ordinal, 1);
    assert_eq!(export_info.functions[0].rva, 0x1000);
    assert_eq!(export_info.functions[0].name.as_deref(), Some("InitEngine"));
    assert_eq!(export_info.functions[0].forwarder, None);

    // Export 2: Ordinal only
    assert_eq!(export_info.functions[1].ordinal, 2);
    assert_eq!(export_info.functions[1].rva, 0x1010);
    assert_eq!(export_info.functions[1].name, None);
    assert_eq!(export_info.functions[1].forwarder, None);

    // Export 3: Forwarded
    assert_eq!(export_info.functions[2].ordinal, 3);
    assert_eq!(
        export_info.functions[2].name.as_deref(),
        Some("AllocMemory")
    );
    assert_eq!(
        export_info.functions[2].forwarder.as_deref(),
        Some("NTDLL.RtlAllocateHeap")
    );
}

#[test]
fn test_dynamic_api_hash_resolver_algorithms() {
    let api = "VirtualAlloc";

    // 1. ROR13
    let ror13 = hash_ror13(api);
    let ror13_matches = resolve_api_hash(ror13, &[]);
    assert!(ror13_matches
        .iter()
        .any(|m| m.algorithm == "ROR13" && m.api_name == api && m.dll == "kernel32.dll"));

    // 2. CRC32
    let crc = hash_crc32(api);
    let crc_matches = resolve_api_hash(crc, &[]);
    assert!(crc_matches
        .iter()
        .any(|m| m.algorithm == "CRC32" && m.api_name == api));

    // 3. DJB2
    let djb2 = hash_djb2(api);
    let djb2_matches = resolve_api_hash(djb2, &[]);
    assert!(djb2_matches
        .iter()
        .any(|m| m.algorithm == "DJB2" && m.api_name == api));

    // 4. FNV-1a
    let fnv1a = hash_fnv1a(api);
    let fnv1a_matches = resolve_api_hash(fnv1a, &[]);
    assert!(fnv1a_matches
        .iter()
        .any(|m| m.algorithm == "FNV-1a" && m.api_name == api));

    // Extra custom exports resolution
    let custom_hash = hash_djb2("CustomForensicHook");
    let extra = [("custom.dll", "CustomForensicHook")];
    let custom_matches = resolve_api_hash(custom_hash, &extra);
    assert!(custom_matches
        .iter()
        .any(|m| m.algorithm == "DJB2" && m.api_name == "CustomForensicHook"));

    // Hash string parser
    assert_eq!(parse_hash_string("0x1234ABCD").unwrap(), 0x1234ABCD);
    assert_eq!(parse_hash_string("1234ABCD").unwrap(), 0x1234ABCD);
    assert_eq!(parse_hash_string("305419896").unwrap(), 305419896);
    assert!(parse_hash_string("invalid_hex").is_err());
}

#[test]
fn test_cli_imports_subcommand_and_json() {
    let dir = tempdir().expect("create temp dir");
    let pe_path = dir.path().join("sample_imports.exe");

    let imports_spec = [("kernel32.dll", &[ImportSpec::ByName("VirtualAlloc", 0)][..])];
    let exports_spec = (
        "sample.dll",
        &[ExportSpec::ByName("SampleEntry", 0x1000)][..],
    );

    let pe_bytes = build_synthetic_pe(true, &imports_spec, Some(exports_spec));
    fs::write(&pe_path, &pe_bytes).expect("write sample PE");

    // Test inspect_imports API directly
    let va_hash = hash_ror13("VirtualAlloc");
    let hex_arg = format!("0x{va_hash:08X}");
    let report = inspect_imports(&pe_bytes, Some(&hex_arg)).expect("inspect imports report");
    assert_eq!(report.total_imported_descriptors, 1);
    assert_eq!(report.total_imported_functions, 1);
    assert!(report.imphash.is_some());
    assert!(!report.resolved_api_hashes.is_empty());

    // Test CLI invocation
    let cargo = env!("CARGO");
    let output = Command::new(cargo)
        .args([
            "run",
            "--quiet",
            "--bin",
            "bsentinel",
            "--",
            "imports",
            pe_path.to_str().unwrap(),
            "--resolve-hash",
            &hex_arg,
            "--json",
        ])
        .output()
        .expect("execute bsentinel imports");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("output must be valid JSON");

    assert_eq!(parsed["format"], "PE32+ (64-bit)");
    assert_eq!(parsed["total_imported_descriptors"], 1);
    assert!(parsed["imphash"].is_string());
    assert_eq!(parsed["resolved_api_hashes"][0]["api_name"], "VirtualAlloc");
    assert_eq!(parsed["resolved_api_hashes"][0]["algorithm"], "ROR13");
}

#[test]
fn test_malformed_and_truncated_imports_and_exports_resilience() {
    let imports_spec = [("kernel32.dll", &[ImportSpec::ByName("ExitProcess", 0)][..])];
    let exports_spec = ("test.dll", &[ExportSpec::ByName("ExportedFn", 0x1000)][..]);
    let pe_bytes = build_synthetic_pe(true, &imports_spec, Some(exports_spec));

    // 1. Truncate at import directory boundary
    let truncated = &pe_bytes[..pe_bytes.len().min(0x200)];
    if let Ok(pe) = parse_pe(truncated) {
        // Must handle truncated thunk / name data without panicking
        let _ = parse_imports(truncated, &pe);
        let _ = parse_exports(truncated, &pe);
    }

    // 2. Corrupt import directory RVA to out-of-bounds
    let mut corrupt_pe = pe_bytes.clone();
    // Overwrite OptionalHeader DataDirectory[1] (Import Directory) VirtualAddress with 0xFFFFFFFF
    let opt_offset = 0x80 + 4 + 20; // e_lfanew + NT + COFF
    let import_dir_offset = opt_offset + 112 + 8; // PE32+ data dirs start at +112; Import is index 1
    if import_dir_offset + 8 <= corrupt_pe.len() {
        corrupt_pe[import_dir_offset..import_dir_offset + 4]
            .copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        corrupt_pe[import_dir_offset + 4..import_dir_offset + 8]
            .copy_from_slice(&0x1000u32.to_le_bytes());
        let pe = parse_pe(&corrupt_pe).expect("parse PE headers");
        let imports = parse_imports(&corrupt_pe, &pe).expect("out-of-bounds RVA returns empty");
        assert!(imports.is_empty());
    }

    // 3. Corrupt export directory RVA to point beyond file bounds
    let export_dir_offset = opt_offset + 112; // Export is index 0
    if export_dir_offset + 8 <= corrupt_pe.len() {
        corrupt_pe[export_dir_offset..export_dir_offset + 4]
            .copy_from_slice(&0x0000_1000u32.to_le_bytes()); // points inside .text, truncated for export dir
        corrupt_pe[export_dir_offset + 4..export_dir_offset + 8]
            .copy_from_slice(&0x0000_1000u32.to_le_bytes());
        let pe = parse_pe(&corrupt_pe).expect("parse PE headers");
        let exports = parse_exports(&corrupt_pe, &pe);
        assert!(exports.is_ok());
    }
}
