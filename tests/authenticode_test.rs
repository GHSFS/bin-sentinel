// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fs;
use std::process::Command;

use bin_sentinel::authenticode::{
    build_synthetic_signed_pe64, constant_time_eq_hex, inspect_authenticode_bytes,
    inspect_authenticode_file, WIN_CERT_REVISION_2_0, WIN_CERT_TYPE_PKCS_SIGNED_DATA,
};
use bin_sentinel::pe::build_synthetic_pe64;

#[test]
fn test_unsigned_pe_inspection() {
    let code_bytes = b"\x48\x31\xC0\xC3"; // xor rax, rax; ret
    let sections = [(".text", &code_bytes[..], 0x60000020u32)];
    let unsigned_pe = build_synthetic_pe64(&sections);

    let report = inspect_authenticode_bytes(&unsigned_pe, Some("unsigned_sample.exe"))
        .expect("inspection must succeed on valid PE");

    assert_eq!(report.file_path, "unsigned_sample.exe");
    assert!(report.is_pe);
    assert_eq!(report.pe_format.as_deref(), Some("PE32+ (64-bit)"));
    assert!(!report.is_signed);
    assert!(!report.signature_verified);
    assert!(report.certificates.is_empty());
    assert!(!report.overlay.detected);
    assert_eq!(report.overlay.size, 0);

    // Two digests computed (SHA-256 and SHA-1), neither has embedded signature
    assert_eq!(report.digests.len(), 2);
    let sha256_dig = &report.digests[0];
    assert_eq!(sha256_dig.algorithm, "SHA-256");
    assert_eq!(sha256_dig.embedded_hex, None);
    assert_eq!(sha256_dig.verified, None);
    assert_eq!(sha256_dig.calculated_hex.len(), 64);

    let sha1_dig = &report.digests[1];
    assert_eq!(sha1_dig.algorithm, "SHA-1");
    assert_eq!(sha1_dig.embedded_hex, None);
    assert_eq!(sha1_dig.verified, None);
    assert_eq!(sha1_dig.calculated_hex.len(), 40);

    assert!(report.alerts.is_empty());
}

#[test]
fn test_synthetic_signed_pe64_verification_success() {
    let code_bytes = b"\x48\x83\xEC\x28\x48\x83\xC4\x28\xC3"; // sub rsp, 28h; add rsp, 28h; ret
    let sections = [
        (".text", &code_bytes[..], 0x60000020u32),
        (".rdata", b"Authenticode Forensic Target\0", 0x40000040u32),
    ];

    let signed_pe = build_synthetic_signed_pe64(&sections, None);
    let report = inspect_authenticode_bytes(&signed_pe, Some("signed_sample.exe"))
        .expect("signed PE inspection must succeed");

    assert!(report.is_signed);
    assert!(report.signature_verified);
    assert_eq!(report.certificates.len(), 1);

    let cert = &report.certificates[0];
    assert_eq!(cert.index, 0);
    assert_eq!(cert.revision, WIN_CERT_REVISION_2_0);
    assert_eq!(cert.certificate_type, WIN_CERT_TYPE_PKCS_SIGNED_DATA);
    assert_eq!(cert.digest_algorithm.as_deref(), Some("SHA-256"));
    assert!(cert.is_valid_format);
    assert!(cert.parse_error.is_none());

    let embedded_hex = cert.digest_hex.as_ref().expect("must have embedded digest");
    assert_eq!(embedded_hex.len(), 64);

    let sha256_info = report
        .digests
        .iter()
        .find(|d| d.algorithm == "SHA-256")
        .expect("SHA-256 info must exist");
    assert_eq!(sha256_info.calculated_hex, *embedded_hex);
    assert_eq!(sha256_info.verified, Some(true));

    assert!(!report.overlay.detected);
    assert!(!report
        .alerts
        .iter()
        .any(|a| a.contains("CRITICAL") || a.contains("mismatch")));
}

#[test]
fn test_tampered_pe_detection() {
    let code_bytes = b"\x90\x90\x90\x90\xC3"; // nop; nop; nop; nop; ret
    let sections = [(".text", &code_bytes[..], 0x60000020u32)];

    let mut tampered_pe = build_synthetic_signed_pe64(&sections, None);

    // Tamper with byte in .text section raw data (starts at 0x200)
    let tamper_offset = 0x200;
    tampered_pe[tamper_offset] ^= 0xFF;

    let report = inspect_authenticode_bytes(&tampered_pe, Some("tampered.exe"))
        .expect("inspection of tampered PE must succeed without crashing");

    assert!(report.is_signed);
    assert!(!report.signature_verified);

    let sha256_info = report
        .digests
        .iter()
        .find(|d| d.algorithm == "SHA-256")
        .expect("SHA-256 info must exist");
    assert_eq!(sha256_info.verified, Some(false));
    assert!(report
        .alerts
        .iter()
        .any(|a| a.contains("digest mismatch") || a.contains("modified")));
}

#[test]
fn test_pe_eof_overlay_detection() {
    let code_bytes = b"\xCC\xC3"; // int 3; ret
    let sections = [(".text", &code_bytes[..], 0x60000020u32)];

    // 1. ZIP Archive overlay
    let zip_overlay = b"PK\x03\x04\x14\x00\x00\x00\x08\x00embedded_zip_file_payload_data_here";
    let pe_with_zip = build_synthetic_signed_pe64(&sections, Some(zip_overlay));

    let report_zip = inspect_authenticode_bytes(&pe_with_zip, Some("zip_installer.exe"))
        .expect("inspection must succeed");

    assert!(report_zip.is_signed);
    assert!(report_zip.signature_verified);
    assert!(report_zip.overlay.detected);
    assert_eq!(report_zip.overlay.size, zip_overlay.len());
    assert!(report_zip.overlay.classification.contains("ZIP"));
    assert!(report_zip.overlay.ratio_percent > 0.0);
    assert!(report_zip
        .alerts
        .iter()
        .any(|a| a.contains("OVERLAY") && a.contains("ZIP")));

    // 2. High-entropy overlay (simulated encrypted payload)
    let mut high_entropy_bytes = Vec::with_capacity(1024);
    for i in 0..1024u32 {
        let val = i.wrapping_mul(1103515245).wrapping_add(12345);
        high_entropy_bytes.push((val >> 16) as u8);
    }

    let pe_with_enc = build_synthetic_signed_pe64(&sections, Some(&high_entropy_bytes));
    let report_enc = inspect_authenticode_bytes(&pe_with_enc, Some("dropper.exe"))
        .expect("inspection must succeed");

    assert!(report_enc.overlay.detected);
    assert_eq!(report_enc.overlay.size, high_entropy_bytes.len());
    assert!(
        report_enc.overlay.entropy >= 7.0,
        "Entropy was {}",
        report_enc.overlay.entropy
    );
    assert!(report_enc.overlay.classification.contains("High-Entropy"));
}

#[test]
fn test_malformed_and_truncated_cert_table() {
    let code_bytes = b"\xC3";
    let sections = [(".text", &code_bytes[..], 0x60000020u32)];
    let mut pe = build_synthetic_pe64(&sections);

    // Set Security Directory to point past end of file
    let sec_dir_offset = 0x80 + 4 + 20 + 144;
    pe[sec_dir_offset..sec_dir_offset + 4].copy_from_slice(&0x000F_0000u32.to_le_bytes()); // Offset 983,040
    pe[sec_dir_offset + 4..sec_dir_offset + 8].copy_from_slice(&0x1000u32.to_le_bytes()); // Size 4,096

    let report = inspect_authenticode_bytes(&pe, Some("corrupted_dir.exe"))
        .expect("must handle corrupted directory without panic");

    assert!(report.is_signed);
    assert!(report.certificates.is_empty());
    assert!(report
        .alerts
        .iter()
        .any(|a| a.contains("outside file bounds")));

    // Test truncated WIN_CERTIFICATE where dwLength is 4 (< 8)
    let cert_offset = pe.len();
    pe.extend_from_slice(&4u32.to_le_bytes()); // dwLength = 4 (< 8)
    pe.extend_from_slice(&0x0200u16.to_le_bytes());
    pe.extend_from_slice(&0x0002u16.to_le_bytes());

    pe[sec_dir_offset..sec_dir_offset + 4].copy_from_slice(&(cert_offset as u32).to_le_bytes());
    pe[sec_dir_offset + 4..sec_dir_offset + 8].copy_from_slice(&8u32.to_le_bytes());

    let report_dw = inspect_authenticode_bytes(&pe, Some("corrupted_dwlength.exe"))
        .expect("must handle invalid dwLength without panic");
    assert!(report_dw
        .alerts
        .iter()
        .any(|a| a.contains("dwLength 4 < 8")));
}

#[test]
fn test_cli_sig_check_subcommand_json() {
    let temp_dir = tempfile::tempdir().expect("must create temp dir");
    let target_file = temp_dir.path().join("cli_test_signed.exe");

    let code_bytes = b"\xB8\x01\x00\x00\x00\xC3"; // mov eax, 1; ret
    let sections = [(".text", &code_bytes[..], 0x60000020u32)];
    let signed_pe = build_synthetic_signed_pe64(&sections, None);

    fs::write(&target_file, &signed_pe).expect("must write target file");

    let report = inspect_authenticode_file(&target_file).expect("file inspection must succeed");
    assert!(report.is_signed);
    assert!(report.signature_verified);

    let output = Command::new(env!("CARGO_BIN_EXE_bsentinel"))
        .arg("sig-check")
        .arg(&target_file)
        .arg("--json")
        .output()
        .expect("bsentinel sig-check command must execute");

    assert!(
        output.status.success(),
        "CLI command failed with stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout_str).expect("CLI output must be valid JSON");

    assert_eq!(parsed["is_pe"], true);
    assert_eq!(parsed["is_signed"], true);
    assert_eq!(parsed["signature_verified"], true);
    assert_eq!(parsed["certificates"].as_array().map(|a| a.len()), Some(1));
    assert_eq!(parsed["overlay"]["detected"], false);
}

#[test]
fn test_constant_time_hex_comparison() {
    assert!(constant_time_eq_hex("aabbcc", "AABBCC"));
    assert!(constant_time_eq_hex("0123456789abcdef", "0123456789ABCDEF"));
    assert!(!constant_time_eq_hex("aabbcc", "aabbcd"));
    assert!(!constant_time_eq_hex("aabbcc", "aabbc"));
    assert!(!constant_time_eq_hex("aabbcc", "aabbccdd"));
    assert!(constant_time_eq_hex("", ""));
}
