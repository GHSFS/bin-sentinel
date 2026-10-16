// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fs;
use std::process::Command;
use tempfile::NamedTempFile;

use bin_sentinel::elf::build_synthetic_elf64;
use bin_sentinel::fuzzy_hash::{
    compare_binary_files, compare_digests, compute_fuzzy_digest, hash_binary_bytes,
    hash_binary_file, score_strings, BinaryFormat, FuzzyDigest,
};
use bin_sentinel::pe::build_synthetic_pe64;

#[test]
fn test_empty_and_minimal_buffer_fuzzy_hash() {
    let empty = b"";
    let d_empty = compute_fuzzy_digest(empty);
    assert_eq!(d_empty.block_size, 3);
    assert_eq!(d_empty.to_digest_string(), "3::");

    let small = b"Hello, World!";
    let d_small = compute_fuzzy_digest(small);
    assert_eq!(d_small.block_size, 3);
    assert!(!d_small.hash1.is_empty());
    assert!(!d_small.hash2.is_empty());
}

#[test]
fn test_identical_buffers_score_100() {
    let mut data = vec![0u8; 8192];
    for (i, b) in data.iter_mut().enumerate() {
        *b = ((i * 31 + 17) % 256) as u8;
    }

    let d1 = compute_fuzzy_digest(&data);
    let d2 = compute_fuzzy_digest(&data);

    assert_eq!(d1, d2);
    let score = compare_digests(&d1, &d2);
    assert_eq!(score, 100);
}

#[test]
fn test_slightly_modified_buffers_high_similarity() {
    let mut buf1 = vec![0u8; 16384];
    for (i, b) in buf1.iter_mut().enumerate() {
        *b = ((i * 37 + 101) % 256) as u8;
    }

    let mut buf2 = buf1.clone();
    // Modify 16 bytes in the middle of 16KB
    for b in &mut buf2[8000..8016] {
        *b = b.wrapping_add(42);
    }

    let d1 = compute_fuzzy_digest(&buf1);
    let d2 = compute_fuzzy_digest(&buf2);

    let score = compare_digests(&d1, &d2);
    assert!(
        score >= 80,
        "Expected high similarity (>= 80), got score: {}",
        score
    );
}

#[test]
fn test_completely_different_buffers_zero_score() {
    let mut buf1 = vec![0u8; 8192];
    for (i, b) in buf1.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }

    let mut buf2 = vec![0u8; 8192];
    for (i, b) in buf2.iter_mut().enumerate() {
        *b = ((i * 127 + 53) % 239) as u8;
    }

    let d1 = compute_fuzzy_digest(&buf1);
    let d2 = compute_fuzzy_digest(&buf2);

    let score = compare_digests(&d1, &d2);
    assert!(
        score < 30,
        "Expected low or zero score for uncorrelated buffers, got: {}",
        score
    );
}

fn make_test_pe() -> Vec<u8> {
    let code = b"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x33\xC0\x48\x83\xC4\x20\x5F\xC3";
    let rdata = b"bin-sentinel static analyzer test payload\0";
    build_synthetic_pe64(&[(".text", code, 0x6000_0020), (".rdata", rdata, 0x4000_0040)])
}

fn make_test_elf() -> Vec<u8> {
    let code = b"\x48\x31\xC0\x48\xFF\xC0\xC3";
    let rodata = b"BinSentinel ELF64 Verification String\0";
    build_synthetic_elf64(&[(".text", code, 6, 1), (".rodata", rodata, 2, 1)])
}

#[test]
fn test_synthetic_pe_section_fuzzy_hashing() {
    let pe_bytes = make_test_pe();
    let report = hash_binary_bytes("sample.exe", &pe_bytes);

    assert_eq!(report.format, BinaryFormat::Pe);
    assert!(!report.fuzzy_hash.hash1.is_empty());
    assert!(!report.sections.is_empty());

    let text_sec = report.sections.iter().find(|s| s.name == ".text");
    assert!(text_sec.is_some(), "Expected .text section in synthetic PE");
    let text = text_sec.unwrap();
    assert!(text.raw_size > 0);
    assert!(!text.fuzzy_hash.hash1.is_empty());
}

#[test]
fn test_synthetic_elf_section_fuzzy_hashing() {
    let elf_bytes = make_test_elf();
    let report = hash_binary_bytes("sample.elf", &elf_bytes);

    assert_eq!(report.format, BinaryFormat::Elf);
    assert!(!report.fuzzy_hash.hash1.is_empty());
    assert!(!report.sections.is_empty());
}

#[test]
fn test_fuzzy_digest_serialization_and_parsing() {
    let digest_str = "48:aB3+/xYz:Cd456";
    let parsed = FuzzyDigest::parse(digest_str).expect("Valid digest string must parse");
    assert_eq!(parsed.block_size, 48);
    assert_eq!(parsed.hash1, "aB3+/xYz");
    assert_eq!(parsed.hash2, "Cd456");
    assert_eq!(parsed.to_digest_string(), digest_str);

    assert!(FuzzyDigest::parse("invalid").is_none());
    assert!(FuzzyDigest::parse("abc:def:ghi").is_none());
}

#[test]
fn test_score_strings_heuristics() {
    assert_eq!(score_strings("", ""), 100);
    assert_eq!(score_strings("ABCD", ""), 0);
    assert_eq!(score_strings("ABCDEF", "ABCDEF"), 100);

    // Below 3 char common substring should return 0
    assert_eq!(score_strings("abcdef", "uvwxyz"), 0);

    // 4 char shared prefix
    let s = score_strings("ABCDEF1234", "ABCDEF5678");
    assert!(s > 0 && s < 100);
}

#[test]
fn test_cli_fuzzy_hash_json_and_table() {
    let file = NamedTempFile::new().expect("Failed to create temp file");
    let data = b"A quick brown fox jumps over the lazy dog. Repeat this string to fill bytes! "
        .repeat(100);
    fs::write(file.path(), data).expect("Failed to write test data");

    let exe_path = env!("CARGO_BIN_EXE_bsentinel");

    // Table output
    let output = Command::new(exe_path)
        .arg("fuzzy-hash")
        .arg(file.path())
        .output()
        .expect("Failed to execute bsentinel fuzzy-hash");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== BinSentinel Fuzzy Hash (CTPH / SSDEEP) ==="));
    assert!(stdout.contains("Fuzzy Hash  :"));

    // JSON output
    let output_json = Command::new(exe_path)
        .arg("fuzzy-hash")
        .arg(file.path())
        .arg("--json")
        .output()
        .expect("Failed to execute bsentinel fuzzy-hash --json");

    assert!(output_json.status.success());
    let stdout_json = String::from_utf8_lossy(&output_json.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout_json).expect("Must produce valid JSON");
    assert_eq!(parsed["format"], "raw");
    assert!(parsed["fuzzy_hash"]["block_size"].is_number());
}

#[test]
fn test_cli_fuzzy_compare_json_and_table() {
    let file1 = NamedTempFile::new().expect("Failed to create temp file 1");
    let file2 = NamedTempFile::new().expect("Failed to create temp file 2");

    let mut data1 = vec![0u8; 16384];
    for (i, b) in data1.iter_mut().enumerate() {
        *b = ((i * 37 + 101) % 256) as u8;
    }
    let mut data2 = data1.clone();
    for b in &mut data2[8000..8016] {
        *b = b.wrapping_add(42);
    }

    fs::write(file1.path(), &data1).expect("Failed to write file1");
    fs::write(file2.path(), &data2).expect("Failed to write file2");

    let exe_path = env!("CARGO_BIN_EXE_bsentinel");

    // Table compare
    let output = Command::new(exe_path)
        .arg("fuzzy-compare")
        .arg(file1.path())
        .arg(file2.path())
        .output()
        .expect("Failed to execute bsentinel fuzzy-compare");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== BinSentinel Fuzzy Similarity Comparison ==="));
    assert!(stdout.contains("Overall Similarity :"));

    // JSON compare
    let output_json = Command::new(exe_path)
        .arg("fuzzy-compare")
        .arg(file1.path())
        .arg(file2.path())
        .arg("--json")
        .output()
        .expect("Failed to execute bsentinel fuzzy-compare --json");

    assert!(output_json.status.success());
    let stdout_json = String::from_utf8_lossy(&output_json.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout_json).expect("Must produce valid JSON");
    assert!(parsed["overall_score"].is_number());
    let score = parsed["overall_score"].as_u64().unwrap();
    assert!(score >= 80, "Expected high score, got: {}", score);
}

#[test]
fn test_programmatic_file_hashing_and_comparison() {
    let file1 = NamedTempFile::new().expect("Failed to create temp file 1");
    let file2 = NamedTempFile::new().expect("Failed to create temp file 2");

    let pe_data = make_test_pe();
    fs::write(file1.path(), &pe_data).expect("Failed to write pe file 1");
    fs::write(file2.path(), &pe_data).expect("Failed to write pe file 2");

    let report1 = hash_binary_file(file1.path()).expect("hash_binary_file should succeed");
    assert_eq!(report1.format, BinaryFormat::Pe);

    let compare_report = compare_binary_files(file1.path(), file2.path())
        .expect("compare_binary_files should succeed");
    assert_eq!(compare_report.overall_score, 100);
    assert!(!compare_report.section_comparisons.is_empty());
}
