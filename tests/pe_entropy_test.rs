// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fs;
use std::process::Command;

use bin_sentinel::entropy::{analyze_entropy_windows, chi_square_uniformity, shannon_entropy};
use bin_sentinel::pe::{
    build_synthetic_pe64, parse_pe, IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
use tempfile::tempdir;

#[test]
fn test_parse_pe64_headers_and_mitigations() {
    let code = b"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x33\xC0\x48\x83\xC4\x20\x5F\xC3";
    let rdata = b"bin-sentinel static analyzer test payload\0";
    let pe_bytes = build_synthetic_pe64(&[
        (
            ".text",
            code,
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
        ),
        (
            ".rdata",
            rdata,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        ),
    ]);

    let info = parse_pe(&pe_bytes).expect("valid synthetic PE64 should parse");
    assert_eq!(info.format, "PE32+ (64-bit)");
    assert_eq!(info.machine, 0x8664);
    assert_eq!(info.number_of_sections, 2);
    assert_eq!(info.entry_point, 0x1000);
    assert_eq!(info.image_base, 0x0000_0001_4000_0000);
    assert!(info.mitigations.aslr);
    assert!(info.mitigations.high_entropy_va);
    assert!(info.mitigations.dep_nx);
    assert!(info.mitigations.cfg);
    assert_eq!(info.sections[0].name, ".text");
    assert_eq!(info.sections[0].permissions, "R-X");
    assert!(!info.sections[0].rwx_anomaly);
    assert_eq!(info.sections[1].name, ".rdata");
    assert_eq!(info.sections[1].permissions, "R--");
}

#[test]
fn test_rwx_and_packer_heuristic_detection() {
    let mut high_entropy_payload = Vec::with_capacity(2048);
    for i in 0..2048usize {
        high_entropy_payload.push((i % 256) as u8);
    }

    let pe_bytes = build_synthetic_pe64(&[
        (
            "UPX0",
            b"\x00\x00\x00\x00",
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE,
        ),
        (
            "UPX1",
            &high_entropy_payload,
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
        ),
    ]);

    let info = parse_pe(&pe_bytes).expect("packed PE64 should parse");
    assert!(info.sections[0].rwx_anomaly);
    assert_eq!(info.sections[0].permissions, "RWX");
    assert!(
        info.sections[1].entropy > 7.9,
        "uniform 256-byte cycle should have ~8.0 entropy, got {}",
        info.sections[1].entropy
    );

    let joined_alerts = info.alerts.join(" | ");
    assert!(joined_alerts.contains("UPX section 'UPX0'"));
    assert!(joined_alerts.contains("RWX memory permission anomaly in section 'UPX0'"));
    assert!(joined_alerts.contains("High-entropy section 'UPX1'"));
}

#[test]
fn test_reject_malformed_pe_headers() {
    assert!(parse_pe(b"short").is_err());
    let mut bad_magic = vec![0u8; 128];
    bad_magic[0..2].copy_from_slice(b"NO");
    assert!(parse_pe(&bad_magic).is_err());

    let mut bad_lfanew = vec![0u8; 128];
    bad_lfanew[0..2].copy_from_slice(b"MZ");
    bad_lfanew[0x3C..0x40].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
    assert!(parse_pe(&bad_lfanew).is_err());
}

#[test]
fn test_entropy_and_chi_square_calculations() {
    let zeroes = vec![0u8; 1024];
    assert_eq!(shannon_entropy(&zeroes), 0.0);

    let mut uniform = Vec::with_capacity(4096);
    for i in 0..4096usize {
        uniform.push((i % 256) as u8);
    }
    let h = shannon_entropy(&uniform);
    assert!((h - 8.0).abs() < 1e-6);
    assert_eq!(chi_square_uniformity(&uniform), 0.0);

    let report = analyze_entropy_windows(&uniform, 1024);
    assert_eq!(report.windows.len(), 4);
    assert!(report.assessment.contains("High entropy"));
}

#[test]
fn test_cli_synth_pe_inspect_and_entropy_json() {
    let dir = tempdir().expect("tempdir");
    let sample_pe = dir.path().join("sample.exe");
    let bin = env!("CARGO_BIN_EXE_bsentinel");

    let synth_out = Command::new(bin)
        .args(["synth-pe", sample_pe.to_str().unwrap()])
        .output()
        .expect("run synth-pe");
    assert!(synth_out.status.success());
    assert!(fs::metadata(&sample_pe).unwrap().len() >= 1024);

    let inspect_out = Command::new(bin)
        .args(["inspect", sample_pe.to_str().unwrap(), "--json"])
        .output()
        .expect("run inspect --json");
    assert!(inspect_out.status.success());
    let json_val: serde_json::Value =
        serde_json::from_slice(&inspect_out.stdout).expect("valid inspect JSON");
    assert_eq!(json_val["format"], "PE32+ (64-bit)");
    assert_eq!(json_val["mitigations"]["aslr"], true);

    let ent_out = Command::new(bin)
        .args([
            "entropy",
            sample_pe.to_str().unwrap(),
            "--window",
            "512",
            "--json",
        ])
        .output()
        .expect("run entropy --json");
    assert!(ent_out.status.success());
    let ent_json: serde_json::Value =
        serde_json::from_slice(&ent_out.stdout).expect("valid entropy JSON");
    assert!(ent_json["windows"].as_array().unwrap().len() >= 2);
}
