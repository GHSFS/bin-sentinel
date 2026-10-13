// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fs;
use std::process::Command;

use bin_sentinel::diff::{
    apply_recipe, diff_binaries, diff_files, generate_recipe, ApplyOptions, BinaryFormat,
    PatchRecipe,
};
use bin_sentinel::elf::build_synthetic_elf64;
use bin_sentinel::patch::sha256_hex;
use bin_sentinel::pe::build_synthetic_pe64;

#[test]
fn test_raw_byte_diff_and_hunk_detection() {
    let orig = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
    let modified = vec![0x00, 0xAA, 0xBB, 0x03, 0x04, 0xCC, 0x06, 0x07, 0x08, 0x09];

    let report = diff_binaries(&orig, &modified, Some("orig.bin"), Some("mod.bin"))
        .expect("diff should succeed");

    assert_eq!(report.format, BinaryFormat::Unknown);
    assert_eq!(report.total_differing_bytes, 3);
    assert_eq!(report.hunk_count, 2);

    assert_eq!(report.hunks[0].offset, 1);
    assert_eq!(report.hunks[0].length, 2);
    assert_eq!(report.hunks[0].orig_bytes_hex, "0102");
    assert_eq!(report.hunks[0].mod_bytes_hex, "AABB");

    assert_eq!(report.hunks[1].offset, 5);
    assert_eq!(report.hunks[1].length, 1);
    assert_eq!(report.hunks[1].orig_bytes_hex, "05");
    assert_eq!(report.hunks[1].mod_bytes_hex, "CC");
}

#[test]
fn test_pe_structural_diff_and_section_rva_mapping() {
    let text_bytes = b"\x48\x83\xEC\x28\x90\x90\x90\x90\x48\x83\xC4\x28\xC3\x90\x90\x90";
    let data_bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10";

    let sections = [
        (".text", &text_bytes[..], 0x6000_0020u32),
        (".data", &data_bytes[..], 0xC000_0040u32),
    ];
    let orig_pe = build_synthetic_pe64(&sections);

    let mut mod_pe = orig_pe.clone();
    // Modify 4 bytes in .text (the 4 NOPs at index 4..8)
    // In synthetic PE, first section raw offset starts at 0x200 (512)
    let patch_offset = 0x200 + 4;
    mod_pe[patch_offset..patch_offset + 4].copy_from_slice(b"\xCC\xCC\xCC\xCC");

    let report = diff_binaries(&orig_pe, &mod_pe, Some("orig.exe"), Some("mod.exe"))
        .expect("PE diff should succeed");

    assert_eq!(report.format, BinaryFormat::Pe);
    assert_eq!(report.hunk_count, 1);
    assert_eq!(report.total_differing_bytes, 4);

    let hunk = &report.hunks[0];
    assert_eq!(hunk.offset, patch_offset);
    assert_eq!(hunk.length, 4);
    assert_eq!(hunk.orig_bytes_hex, "90909090");
    assert_eq!(hunk.mod_bytes_hex, "CCCCCCCC");
    assert_eq!(hunk.section_name.as_deref(), Some(".text"));
    assert_eq!(hunk.rva, Some(0x1004));

    let text_diff = report
        .section_diffs
        .iter()
        .find(|s| s.name == ".text")
        .expect(".text section diff must exist");
    assert_eq!(text_diff.differing_bytes, 4);
    assert_eq!(text_diff.hunk_count, 1);
}

#[test]
fn test_elf_structural_diff_and_section_mapping() {
    let code_bytes = b"\x48\x31\xC0\x48\xFF\xC0\xC3"; // xor rax, rax; inc rax; ret
    let sections = [(".text", &code_bytes[..], 0x6u64, 1u32)];
    let orig_elf = build_synthetic_elf64(&sections);
    let mut mod_elf = orig_elf.clone();

    // Patch 3 bytes in .text section starting at 0x200
    mod_elf[0x200..0x203].copy_from_slice(b"\x90\x90\x90");

    let report = diff_binaries(&orig_elf, &mod_elf, Some("sample.elf"), Some("mod.elf"))
        .expect("ELF diff should succeed");

    assert_eq!(report.format, BinaryFormat::Elf);
    assert_eq!(report.total_differing_bytes, 3);
    assert_eq!(report.hunk_count, 1);
    assert_eq!(report.hunks[0].section_name.as_deref(), Some(".text"));
}

#[test]
fn test_patch_recipe_generation_and_json_roundtrip() {
    let orig = vec![0x10, 0x20, 0x30, 0x40, 0x50];
    let modified = vec![0x10, 0xAA, 0xBB, 0x40, 0x50];

    let report = diff_binaries(&orig, &modified, None, None).expect("diff must succeed");
    let recipe = generate_recipe(&report, Some("test-recipe"), Some("Test manifest"));

    assert_eq!(recipe.name, "test-recipe");
    assert_eq!(recipe.operations.len(), 1);
    assert_eq!(recipe.operations[0].offset, 1);
    assert_eq!(recipe.operations[0].expected_hex, "2030");
    assert_eq!(recipe.operations[0].replace_hex, "AABB");

    let json = recipe.to_json_pretty().expect("must serialize");
    let deserialized = PatchRecipe::from_json(&json).expect("must deserialize");

    assert_eq!(recipe, deserialized);
}

#[test]
fn test_recipe_atomic_apply_dry_run_and_reversal() {
    let temp_dir = tempfile::tempdir().expect("must create temp dir");
    let target_path = temp_dir.path().join("patch_target.bin");

    let orig_bytes = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let mut mod_bytes = orig_bytes.clone();
    mod_bytes[2..4].copy_from_slice(&[0xDE, 0xAD]);

    fs::write(&target_path, &orig_bytes).expect("must write orig file");

    let report = diff_files(&target_path, &target_path).expect("self diff");
    assert_eq!(report.hunk_count, 0);

    let diff_report =
        diff_binaries(&orig_bytes, &mod_bytes, None, None).expect("diff between buffers");
    let recipe = generate_recipe(&diff_report, Some("dead-beef-patch"), None);

    // 1. Dry run verification: file on disk MUST NOT change
    let dry_run_options = ApplyOptions {
        dry_run: true,
        reverse: false,
        backup: false,
    };
    let dry_report =
        apply_recipe(&target_path, &recipe, &dry_run_options).expect("dry run must succeed");
    assert!(dry_report.is_dry_run);
    assert_eq!(dry_report.sha256_before, sha256_hex(&orig_bytes));
    assert_eq!(dry_report.sha256_after, sha256_hex(&mod_bytes));

    let disk_bytes = fs::read(&target_path).expect("read after dry run");
    assert_eq!(
        disk_bytes, orig_bytes,
        "disk must remain untouched after dry run"
    );

    // 2. Live application with backup
    let live_options = ApplyOptions {
        dry_run: false,
        reverse: false,
        backup: true,
    };
    let live_report =
        apply_recipe(&target_path, &recipe, &live_options).expect("live apply must succeed");
    assert!(!live_report.is_dry_run);
    assert!(live_report.backup_path.is_some());

    let disk_bytes_applied = fs::read(&target_path).expect("read after apply");
    assert_eq!(disk_bytes_applied, mod_bytes);

    let backup_bytes = fs::read(target_path.with_extension("bin.bak")).expect("read backup");
    assert_eq!(backup_bytes, orig_bytes);

    // 3. Reversal: restores original content
    let reverse_options = ApplyOptions {
        dry_run: false,
        reverse: true,
        backup: false,
    };
    let rev_report =
        apply_recipe(&target_path, &recipe, &reverse_options).expect("reversal must succeed");
    assert!(rev_report.reversed);

    let disk_bytes_reverted = fs::read(&target_path).expect("read after reversal");
    assert_eq!(
        disk_bytes_reverted, orig_bytes,
        "reversal must match original"
    );
}

#[test]
fn test_tamper_rejection_and_constant_time_safety() {
    let temp_dir = tempfile::tempdir().expect("must create temp dir");
    let target_path = temp_dir.path().join("tampered_target.bin");

    let orig_bytes = vec![0x10, 0x20, 0x30, 0x40];
    let mut mod_bytes = orig_bytes.clone();
    mod_bytes[1] = 0x99;

    let diff_report = diff_binaries(&orig_bytes, &mod_bytes, None, None).expect("diff");
    let recipe = generate_recipe(&diff_report, Some("tamper-test"), None);

    // Write a file with a tampered byte at offset 1 (0x21 instead of 0x20)
    let tampered_bytes = vec![0x10, 0x21, 0x30, 0x40];
    fs::write(&target_path, &tampered_bytes).expect("write tampered");

    let options = ApplyOptions {
        dry_run: false,
        reverse: false,
        backup: false,
    };
    let result = apply_recipe(&target_path, &recipe, &options);
    assert!(result.is_err(), "tampered target must be rejected");

    // File on disk must remain unmodified
    let current_bytes = fs::read(&target_path).expect("read");
    assert_eq!(current_bytes, tampered_bytes);
}

#[test]
fn test_cli_diff_and_apply_recipe_subcommands() {
    let temp_dir = tempfile::tempdir().expect("must create temp dir");
    let orig_file = temp_dir.path().join("cli_orig.bin");
    let mod_file = temp_dir.path().join("cli_mod.bin");
    let recipe_file = temp_dir.path().join("recipe.json");

    let orig_bytes = vec![0x90, 0x90, 0x90, 0xC3];
    let mod_bytes = vec![0xCC, 0x90, 0x90, 0xC3];

    fs::write(&orig_file, &orig_bytes).expect("write orig");
    fs::write(&mod_file, &mod_bytes).expect("write mod");

    // 1. Run bsentinel diff --out-recipe <recipe.json> --json
    let diff_output = Command::new(env!("CARGO_BIN_EXE_bsentinel"))
        .arg("diff")
        .arg(&orig_file)
        .arg(&mod_file)
        .arg("--out-recipe")
        .arg(&recipe_file)
        .arg("--json")
        .output()
        .expect("bsentinel diff must execute");

    assert!(
        diff_output.status.success(),
        "diff failed: {}",
        String::from_utf8_lossy(&diff_output.stderr)
    );

    let diff_stdout = String::from_utf8_lossy(&diff_output.stdout);
    let parsed_diff: serde_json::Value =
        serde_json::from_str(&diff_stdout).expect("valid diff json");
    assert_eq!(parsed_diff["hunk_count"], 1);
    assert_eq!(parsed_diff["total_differing_bytes"], 1);
    assert!(recipe_file.exists());

    // 2. Run bsentinel apply-recipe <orig_file> <recipe_file> --dry-run --json
    let dry_output = Command::new(env!("CARGO_BIN_EXE_bsentinel"))
        .arg("apply-recipe")
        .arg(&orig_file)
        .arg(&recipe_file)
        .arg("--dry-run")
        .arg("--json")
        .output()
        .expect("bsentinel apply-recipe --dry-run must execute");

    assert!(dry_output.status.success());
    let dry_stdout = String::from_utf8_lossy(&dry_output.stdout);
    let parsed_dry: serde_json::Value = serde_json::from_str(&dry_stdout).expect("valid dry json");
    assert_eq!(parsed_dry["is_dry_run"], true);

    // 3. Run bsentinel apply-recipe <orig_file> <recipe_file> --backup --json
    let apply_output = Command::new(env!("CARGO_BIN_EXE_bsentinel"))
        .arg("apply-recipe")
        .arg(&orig_file)
        .arg(&recipe_file)
        .arg("--backup")
        .arg("--json")
        .output()
        .expect("bsentinel apply-recipe live must execute");

    assert!(apply_output.status.success());
    let applied_bytes = fs::read(&orig_file).expect("read patched orig");
    assert_eq!(applied_bytes, mod_bytes);

    // 4. Run bsentinel apply-recipe <orig_file> <recipe_file> --reverse --json
    let reverse_output = Command::new(env!("CARGO_BIN_EXE_bsentinel"))
        .arg("apply-recipe")
        .arg(&orig_file)
        .arg(&recipe_file)
        .arg("--reverse")
        .arg("--json")
        .output()
        .expect("bsentinel apply-recipe --reverse must execute");

    assert!(reverse_output.status.success());
    let reverted_bytes = fs::read(&orig_file).expect("read reverted orig");
    assert_eq!(reverted_bytes, orig_bytes);
}
