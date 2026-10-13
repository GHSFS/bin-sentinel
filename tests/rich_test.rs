// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fs;
use std::path::Path;
use std::process::Command;

use bin_sentinel::rich::{
    build_synthetic_rich_pe, parse_rich_bytes, parse_rich_file, RichReport, RichToolKind,
    SyntheticRichEntry,
};
use tempfile::NamedTempFile;

#[test]
fn test_parse_synthetic_pe_with_valid_rich_header() {
    let entries = vec![
        SyntheticRichEntry::new(0x0102, 27412, 1),  // Linker VS2019
        SyntheticRichEntry::new(0x0103, 27412, 5),  // C compiler VS2019
        SyntheticRichEntry::new(0x0104, 27412, 12), // C++ compiler VS2019
        SyntheticRichEntry::new(0x0101, 27412, 2),  // Cvtres VS2019
        SyntheticRichEntry::new(0x0001, 0, 42),     // Import0
    ];

    let pe_bytes = build_synthetic_rich_pe(&entries, false);
    let report = parse_rich_bytes(&pe_bytes, "synthetic_vs2019.exe").expect("parse rich header");

    assert_eq!(report.record_count, 5);
    assert_eq!(report.records.len(), 5);
    assert!(report.checksum.is_valid);
    assert_eq!(
        report.checksum.stored_xor_key,
        report.checksum.calculated_key
    );
    assert!(report.anomalies.is_empty());
    assert_eq!(report.hashes.md5.len(), 32);
    assert_eq!(report.hashes.sha256.len(), 64);
    assert!(report.primary_toolchain.contains("Visual Studio 2019"));

    // Check individual records
    let linker = &report.records[0];
    assert_eq!(linker.product_id, 0x0102);
    assert_eq!(linker.build_number, 27412);
    assert_eq!(linker.count, 1);
    assert_eq!(linker.tool_kind, RichToolKind::Linker);

    let cpp = &report.records[2];
    assert_eq!(cpp.product_id, 0x0104);
    assert_eq!(cpp.tool_kind, RichToolKind::CppCompiler);
    assert_eq!(cpp.count, 12);
}

#[test]
fn test_checksum_mismatch_and_tamper_detection() {
    let entries = vec![
        SyntheticRichEntry::new(0x0122, 31329, 1), // Linker VS2022
        SyntheticRichEntry::new(0x0124, 31329, 4), // C++ VS2022
    ];

    // Build with intentionally corrupted checksum
    let tampered_pe = build_synthetic_rich_pe(&entries, true);
    let report = parse_rich_bytes(&tampered_pe, "tampered.exe").expect("parse rich header");

    assert!(!report.checksum.is_valid);
    assert_ne!(
        report.checksum.stored_xor_key,
        report.checksum.calculated_key
    );
    assert!(report
        .anomalies
        .iter()
        .any(|a| a.contains("checksum mismatch")));
}

#[test]
fn test_fingerprint_visual_studio_toolchain_versions() {
    // Test Visual Studio 2015
    let vs2015_entries = vec![
        SyntheticRichEntry::new(0x00EE, 24215, 1),
        SyntheticRichEntry::new(0x00EB, 24215, 8),
    ];
    let pe_2015 = build_synthetic_rich_pe(&vs2015_entries, false);
    let rep_2015 = parse_rich_bytes(&pe_2015, "vs2015.exe").unwrap();
    assert!(rep_2015.primary_toolchain.contains("Visual Studio 2015"));

    // Test Visual Studio 2022
    let vs2022_entries = vec![
        SyntheticRichEntry::new(0x0122, 32532, 2),
        SyntheticRichEntry::new(0x0124, 32532, 15),
    ];
    let pe_2022 = build_synthetic_rich_pe(&vs2022_entries, false);
    let rep_2022 = parse_rich_bytes(&pe_2022, "vs2022.exe").unwrap();
    assert!(rep_2022.primary_toolchain.contains("Visual Studio 2022"));
}

#[test]
fn test_reject_pe_without_rich_header() {
    // Generate minimal PE with DOS header + stub directly pointing to PE without Rich
    let mut pe_no_rich = vec![0x4D, 0x5A]; // 'MZ'
    pe_no_rich.resize(0x3C, 0x00);
    pe_no_rich.extend_from_slice(&0x80u32.to_le_bytes()); // e_lfanew = 0x80
    pe_no_rich.resize(0x80, 0x90);
    pe_no_rich.extend_from_slice(b"PE\0\0");
    pe_no_rich.resize(0x200, 0x00);

    let err = parse_rich_bytes(&pe_no_rich, "no_rich.exe").unwrap_err();
    assert!(err.to_string().contains("No Rich header found"));
}

#[test]
fn test_reject_truncated_and_malformed_inputs() {
    // Truncated below minimum DOS header
    assert!(parse_rich_bytes(&[0x4D, 0x5A, 0x90], "small.bin").is_err());

    // Invalid magic
    assert!(parse_rich_bytes(&[0x00; 128], "zeros.bin").is_err());

    // Corrupted DanS zero padding
    let entries = vec![SyntheticRichEntry::new(0x0102, 27412, 1)];
    let mut pe = build_synthetic_rich_pe(&entries, false);
    // Find DanS offset in the generated PE
    let rich_idx = pe
        .windows(4)
        .position(|w| w == b"Rich")
        .expect("find Rich marker");
    let _xor_key = u32::from_le_bytes([
        pe[rich_idx + 4],
        pe[rich_idx + 5],
        pe[rich_idx + 6],
        pe[rich_idx + 7],
    ]);

    // Flip a byte in the zero padding
    let dans_candidate = rich_idx - 8 - 16;
    pe[dans_candidate + 4] ^= 0xFF; // Corrupt zero padding word

    let err = parse_rich_bytes(&pe, "corrupted_padding.exe").unwrap_err();
    assert!(err.to_string().contains("Corrupted Rich header"));
}

#[test]
fn test_hash_reproducibility_and_consistency() {
    let entries_a = vec![
        SyntheticRichEntry::new(0x0102, 27412, 1),
        SyntheticRichEntry::new(0x0103, 27412, 3),
    ];
    let pe_a1 = build_synthetic_rich_pe(&entries_a, false);
    let pe_a2 = build_synthetic_rich_pe(&entries_a, false);

    let rep_a1 = parse_rich_bytes(&pe_a1, "a1.exe").unwrap();
    let rep_a2 = parse_rich_bytes(&pe_a2, "a2.exe").unwrap();

    assert_eq!(rep_a1.hashes.md5, rep_a2.hashes.md5);
    assert_eq!(rep_a1.hashes.sha256, rep_a2.hashes.sha256);

    let entries_b = vec![
        SyntheticRichEntry::new(0x0102, 27412, 2), // Different count
        SyntheticRichEntry::new(0x0103, 27412, 3),
    ];
    let pe_b = build_synthetic_rich_pe(&entries_b, false);
    let rep_b = parse_rich_bytes(&pe_b, "b.exe").unwrap();

    assert_ne!(rep_a1.hashes.md5, rep_b.hashes.md5);
    assert_ne!(rep_a1.hashes.sha256, rep_b.hashes.sha256);
}

#[test]
fn test_cli_rich_subcommand_json_and_table() {
    let entries = vec![
        SyntheticRichEntry::new(0x0102, 27412, 1),
        SyntheticRichEntry::new(0x0103, 27412, 4),
        SyntheticRichEntry::new(0x0104, 27412, 8),
    ];
    let pe_bytes = build_synthetic_rich_pe(&entries, false);

    let tmp = NamedTempFile::new().expect("create temp file");
    fs::write(tmp.path(), &pe_bytes).expect("write temp pe");

    let bin_path = env!("CARGO_BIN_EXE_bsentinel");

    // 1. Test human-readable table output
    let output = Command::new(bin_path)
        .arg("rich")
        .arg(tmp.path())
        .output()
        .expect("execute bsentinel rich");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== PE Rich Header Forensic Inspection:"));
    assert!(stdout.contains("Primary Toolset"));
    assert!(stdout.contains("Checksum Status"));
    assert!(stdout.contains("VALID"));
    assert!(stdout.contains("Linker1420"));
    assert!(stdout.contains("Utc19_20_C"));

    // 2. Test structured JSON output
    let json_output = Command::new(bin_path)
        .arg("rich")
        .arg(tmp.path())
        .arg("--json")
        .output()
        .expect("execute bsentinel rich --json");

    assert!(json_output.status.success());
    let json_str = String::from_utf8_lossy(&json_output.stdout);
    let parsed: RichReport = serde_json::from_str(&json_str).expect("deserialize RichReport JSON");
    assert_eq!(parsed.record_count, 3);
    assert!(parsed.checksum.is_valid);
}

#[test]
fn test_real_system_binary_rich_header_if_available() {
    let target = Path::new(r"C:\Windows\System32\cmd.exe");
    if !target.exists() {
        return;
    }

    let report = parse_rich_file(target).expect("parse Windows cmd.exe rich header");
    assert!(report.record_count >= 5);
    assert!(
        report.checksum.is_valid,
        "System cmd.exe checksum should be mathematically authentic"
    );
    assert!(
        report.primary_toolchain.contains("Visual Studio 2019"),
        "Primary toolchain should detect modern MSVC build"
    );
}
