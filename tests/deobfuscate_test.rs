// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fs;
use std::process::Command;

use bin_sentinel::deobfuscate::{
    crib_drag_xor, scan_deobfuscate_bytes, ArtifactKind, DeobfuscateMethod,
};

#[test]
fn test_xor_single_byte_url() {
    let plaintext = b"http://evil.com/payload";
    let key = 0x5Au8;
    let encoded: Vec<u8> = plaintext.iter().map(|&b| b ^ key).collect();

    let report = scan_deobfuscate_bytes(&encoded);
    assert!(
        report.total_matches >= 1,
        "Expected at least 1 artifact found"
    );
    let match_url = report
        .artifacts
        .iter()
        .find(|a| a.kind == ArtifactKind::Url)
        .expect("Decoded URL artifact not found");

    assert!(match_url.content.contains("http://evil.com/payload"));
    assert_eq!(match_url.method, DeobfuscateMethod::XorSingle { key });
    assert!(match_url.confidence >= 0.9);
}

#[test]
fn test_xor_single_byte_ipv4() {
    let plaintext = b"192.168.1.100";
    let key = 0xAAu8;
    let encoded: Vec<u8> = plaintext.iter().map(|&b| b ^ key).collect();

    let report = scan_deobfuscate_bytes(&encoded);
    assert!(
        report.total_matches >= 1,
        "Expected at least 1 artifact found"
    );
    let match_ip = report
        .artifacts
        .iter()
        .find(|a| a.kind == ArtifactKind::IPv4)
        .expect("Decoded IPv4 artifact not found");

    assert_eq!(match_ip.content, "192.168.1.100");
    assert_eq!(match_ip.method, DeobfuscateMethod::XorSingle { key });
    assert!(match_ip.confidence >= 0.8);
}

#[test]
fn test_add_single_byte_registry() {
    let plaintext = b"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    let key = 0x07u8;
    let encoded: Vec<u8> = plaintext.iter().map(|&b| b.wrapping_add(key)).collect();

    let report = scan_deobfuscate_bytes(&encoded);
    assert!(
        report.total_matches >= 1,
        "Expected at least 1 artifact found"
    );
    let match_reg = report
        .artifacts
        .iter()
        .find(|a| a.kind == ArtifactKind::RegistryKey)
        .expect("Decoded Registry artifact not found");

    assert!(match_reg
        .content
        .contains("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
    assert_eq!(match_reg.method, DeobfuscateMethod::AddSingle { key });
    assert!(match_reg.confidence >= 0.9);
}

#[test]
fn test_rol_single_byte() {
    let plaintext = b"https://c2.command-center.org/beacon";
    let shift = 3u8;
    let encoded: Vec<u8> = plaintext
        .iter()
        .map(|&b| b.rotate_left(shift as u32))
        .collect();

    let report = scan_deobfuscate_bytes(&encoded);
    assert!(
        report.total_matches >= 1,
        "Expected at least 1 artifact found"
    );
    let match_url = report
        .artifacts
        .iter()
        .find(|a| a.kind == ArtifactKind::Url)
        .expect("Decoded ROL URL artifact not found");

    assert!(match_url
        .content
        .contains("https://c2.command-center.org/beacon"));
    assert_eq!(match_url.method, DeobfuscateMethod::RolSingle { shift });
    assert!(match_url.confidence >= 0.9);
}

#[test]
fn test_xor_multi_byte() {
    let plaintext = b"http://attacker-controlled.net/dropper.bin";
    let key = [0xDE, 0xAD, 0xBE, 0xEF];
    let encoded: Vec<u8> = plaintext
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();

    let report = scan_deobfuscate_bytes(&encoded);
    assert!(
        report.total_matches >= 1,
        "Expected at least 1 artifact found"
    );
    let match_multi = report
        .artifacts
        .iter()
        .find(|a| a.kind == ArtifactKind::Url)
        .expect("Decoded multi-byte URL artifact not found");

    assert!(match_multi
        .content
        .contains("http://attacker-controlled.net/dropper.bin"));
    assert_eq!(
        match_multi.method,
        DeobfuscateMethod::XorMulti { key: key.to_vec() }
    );
}

#[test]
fn test_crib_drag_recovery() {
    let mut data = vec![0x11u8; 256];
    let payload = b"http://malware.c2/beacon";
    let key = 0x6Eu8;
    let offset = 100;
    for (i, &b) in payload.iter().enumerate() {
        data[offset + i] = b ^ key;
    }

    let cribs: &[&[u8]] = &[b"http://"];
    let recovered = crib_drag_xor(&data, cribs);
    assert!(
        !recovered.is_empty(),
        "Crib drag should recover key at offset 100"
    );
    let hit = recovered
        .iter()
        .find(|(pos, k, _)| *pos == offset && k == &[key])
        .expect("Expected key recovery at offset 100");
    assert_eq!(hit.0, 100);
    assert_eq!(hit.1, vec![key]);

    let report = scan_deobfuscate_bytes(&data);
    let match_artifact = report
        .artifacts
        .iter()
        .find(|a| a.offset == offset && a.kind == ArtifactKind::Url)
        .expect("Scanner should detect URL artifact at offset 100");
    assert!(match_artifact.content.contains("http://malware.c2/beacon"));
}

#[test]
fn test_pe_header_detection() {
    let mut pe_stub = vec![0u8; 256];
    pe_stub[0] = b'M';
    pe_stub[1] = b'Z';
    // Set e_lfanew = 0x80 at offset 0x3C
    pe_stub[0x3C] = 0x80;
    pe_stub[0x3D] = 0x00;
    pe_stub[0x3E] = 0x00;
    pe_stub[0x3F] = 0x00;
    // Set PE signature at 0x80
    pe_stub[0x80] = b'P';
    pe_stub[0x81] = b'E';
    pe_stub[0x82] = 0;
    pe_stub[0x83] = 0;
    // Embed DOS stub message
    let msg = b"This program cannot be run in DOS mode.";
    pe_stub[0x40..0x40 + msg.len()].copy_from_slice(msg);

    let key = 0x33u8;
    for b in pe_stub.iter_mut() {
        *b ^= key;
    }

    let report = scan_deobfuscate_bytes(&pe_stub);
    assert!(
        report.total_matches >= 1,
        "Expected at least 1 artifact found"
    );
    let match_pe = report
        .artifacts
        .iter()
        .find(|a| a.kind == ArtifactKind::PeHeader && a.offset == 0)
        .expect("PE header artifact not found at offset 0");

    assert_eq!(match_pe.method, DeobfuscateMethod::XorSingle { key });
    assert!(match_pe.confidence >= 0.95);
}

#[test]
fn test_cli_json_output() {
    let payload = b"http://malware-telemetry.org/gate.php";
    let key = 0x4Bu8;
    let encoded: Vec<u8> = payload.iter().map(|&b| b ^ key).collect();

    let tmp_dir = tempfile::tempdir().expect("Failed to create temporary directory");
    let bin_path = tmp_dir.path().join("obfuscated.bin");
    fs::write(&bin_path, &encoded).expect("Failed to write test binary");

    let exe = env!("CARGO_BIN_EXE_bsentinel");
    let output = Command::new(exe)
        .arg("xor-scan")
        .arg(&bin_path)
        .arg("--json")
        .output()
        .expect("Failed to execute bsentinel xor-scan --json");

    assert!(output.status.success(), "Command returned non-zero status");
    let stdout = String::from_utf8(output.stdout).expect("Stdout is not valid UTF-8");
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Failed to parse xor-scan JSON output");

    assert_eq!(json["file_size"], encoded.len());
    assert_eq!(json["binary_format"], "Raw Binary");
    assert!(json["total_matches"].as_u64().unwrap_or(0) >= 1);

    let artifacts = json["artifacts"]
        .as_array()
        .expect("artifacts should be an array");
    let has_url = artifacts.iter().any(|a| {
        a["kind"].as_str() == Some("Url")
            && a["content"]
                .as_str()
                .unwrap_or("")
                .contains("http://malware-telemetry.org/gate.php")
    });
    assert!(has_url, "Expected URL artifact in JSON output");
}

#[test]
fn test_no_false_positives_on_random() {
    let mut random_bytes = vec![0u8; 1024];
    let mut seed = 0x12345678u32;
    for b in random_bytes.iter_mut() {
        seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
        *b = (seed >> 16) as u8;
    }

    let report = scan_deobfuscate_bytes(&random_bytes);
    assert_eq!(
        report.total_matches, 0,
        "Random bytes should yield zero false positives"
    );
    assert!(report.artifacts.is_empty());
}
