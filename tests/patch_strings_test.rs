// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fs;
use std::process::Command;

use bin_sentinel::error::SentinelError;
use bin_sentinel::patch::{apply_patch, parse_hex_bytes, parse_offset};
use bin_sentinel::strings::{extract_strings, IocKind, StringEncoding};
use tempfile::tempdir;

#[test]
fn test_ascii_and_utf16le_ioc_extraction() {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"\x00\x00https://c2.diagnostic.example.com/gate\x00\x00");
    payload.extend_from_slice(b"VirtualAllocEx\x00WriteProcessMemory\x00");
    payload.extend_from_slice(b"connect_target=192.168.42.108:8443\x00");
    // UTF-16LE encoded "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
    for b in b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" {
        payload.push(*b);
        payload.push(0x00);
    }
    payload.extend_from_slice(b"\x00\x00normal_harmless_label\x00");

    let all_strings = extract_strings(&payload, 4, false);
    assert!(all_strings
        .iter()
        .any(|s| s.value.contains("normal_harmless_label")));

    let iocs = extract_strings(&payload, 4, true);
    assert!(iocs
        .iter()
        .any(|s| s.ioc == Some(IocKind::Url) && s.value.contains("https://c2.diagnostic")));
    assert!(iocs
        .iter()
        .any(|s| s.ioc == Some(IocKind::SensitiveApi) && s.value == "VirtualAllocEx"));
    assert!(iocs
        .iter()
        .any(|s| s.ioc == Some(IocKind::Ipv4) && s.value.contains("192.168.42.108")));
    assert!(iocs.iter().any(|s| {
        s.encoding == StringEncoding::Utf16Le
            && s.ioc == Some(IocKind::RegistryKey)
            && s.value.contains("HKCU\\Software")
    }));
}

#[test]
fn test_declarative_patch_and_backup_verification() {
    let dir = tempdir().expect("tempdir");
    let target = dir.path().join("patch_target.bin");
    let original = b"\x48\x83\xEC\x28\x74\x1A\x90\x90\xC3";
    fs::write(&target, original).expect("write target");

    let offset = parse_offset("0x04").unwrap();
    let expected = parse_hex_bytes("74 1A").unwrap();
    let replacement = parse_hex_bytes("90 90").unwrap();

    let report = apply_patch(&target, offset, &expected, &replacement, true)
        .expect("patch should succeed when expected bytes match");
    assert_eq!(report.offset, 4);
    assert_eq!(report.length, 2);
    assert_ne!(report.sha256_before, report.sha256_after);

    let patched_bytes = fs::read(&target).expect("read patched");
    assert_eq!(&patched_bytes[4..6], b"\x90\x90");

    let bak_path = report.backup_path.expect("backup path created");
    let bak_bytes = fs::read(bak_path).expect("read backup");
    assert_eq!(bak_bytes, original);

    // Repeating the same patch with original expected bytes must fail with PatchMismatch
    let err = apply_patch(&target, offset, &expected, &replacement, false)
        .expect_err("mismatch should be rejected");
    match err {
        SentinelError::PatchMismatch {
            offset: off,
            expected_hex,
            actual_hex,
        } => {
            assert_eq!(off, 4);
            assert_eq!(expected_hex, "741A");
            assert_eq!(actual_hex, "9090");
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn test_cli_strings_and_patch_subcommands() {
    let dir = tempdir().expect("tempdir");
    let sample = dir.path().join("cli_target.exe");
    let bin = env!("CARGO_BIN_EXE_bsentinel");

    let synth = Command::new(bin)
        .args(["synth-pe", sample.to_str().unwrap()])
        .output()
        .expect("synth-pe");
    assert!(synth.status.success());

    let str_out = Command::new(bin)
        .args(["strings", sample.to_str().unwrap(), "--ioc-only", "--json"])
        .output()
        .expect("strings --ioc-only --json");
    assert!(str_out.status.success());
    let arr: serde_json::Value = serde_json::from_slice(&str_out.stdout).expect("json array");
    assert!(!arr.as_array().unwrap().is_empty());

    let patch_out = Command::new(bin)
        .args([
            "patch",
            sample.to_str().unwrap(),
            "--offset",
            "0x200",
            "--expect",
            "4883EC28",
            "--replace",
            "90909090",
            "--backup",
            "--json",
        ])
        .output()
        .expect("patch --json");
    assert!(patch_out.status.success());
    let patch_json: serde_json::Value =
        serde_json::from_slice(&patch_out.stdout).expect("patch json");
    assert_eq!(patch_json["expected_hex"], "4883EC28");
    assert_eq!(patch_json["replaced_hex"], "90909090");
}
