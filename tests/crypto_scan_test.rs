// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fs;
use std::process::Command;

use bin_sentinel::crypto_scan::{
    scan_crypto_bytes, scan_crypto_file, ConfidenceLevel, CryptoPrimitiveKind, AES_FORWARD_SBOX,
    AES_INVERSE_SBOX, CHACHA20_SIGMA, CRC32_IEEE_FIRST16_LE, SHA256_INIT_LE, SM4_SBOX,
    TEA_DELTA_LE,
};
use bin_sentinel::elf::{build_synthetic_elf64, SHF_ALLOC, SHF_EXECINSTR, SHT_PROGBITS};
use bin_sentinel::pe::{
    build_synthetic_pe64, IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
};

#[test]
fn test_detect_isolated_crypto_tables_and_constants() {
    let mut buffer = Vec::new();
    // Prepend 128 bytes of padding
    buffer.extend_from_slice(&[0x90; 128]);

    let aes_fwd_offset = buffer.len();
    buffer.extend_from_slice(&AES_FORWARD_SBOX);

    buffer.extend_from_slice(&[0x00; 64]);
    let chacha_offset = buffer.len();
    buffer.extend_from_slice(&CHACHA20_SIGMA);

    buffer.extend_from_slice(&[0xCC; 32]);
    let sha256_offset = buffer.len();
    buffer.extend_from_slice(&SHA256_INIT_LE);

    buffer.extend_from_slice(&[0xAA; 16]);
    let crc32_offset = buffer.len();
    buffer.extend_from_slice(&CRC32_IEEE_FIRST16_LE);

    buffer.extend_from_slice(&[0x55; 8]);
    let tea_offset = buffer.len();
    buffer.extend_from_slice(&TEA_DELTA_LE);

    let (matches, tea_count) = scan_crypto_bytes(&buffer);
    assert!(tea_count >= 1);

    // Verify AES Forward S-Box match
    let aes_match = matches
        .iter()
        .find(|m| m.offset == aes_fwd_offset)
        .expect("AES Forward S-Box match not found");
    assert_eq!(aes_match.algorithm, "AES-128/192/256 (Rijndael)");
    assert_eq!(aes_match.kind, CryptoPrimitiveKind::SBox);
    assert_eq!(aes_match.length, 256);
    assert_eq!(aes_match.confidence, ConfidenceLevel::High);

    // Verify ChaCha20 Sigma match
    let chacha_match = matches
        .iter()
        .find(|m| m.offset == chacha_offset)
        .expect("ChaCha20 Sigma match not found");
    assert_eq!(chacha_match.algorithm, "ChaCha20 / Salsa20");
    assert_eq!(chacha_match.kind, CryptoPrimitiveKind::MagicString);
    assert_eq!(chacha_match.length, 16);
    assert_eq!(chacha_match.confidence, ConfidenceLevel::High);

    // Verify SHA-256 Initial State match
    let sha_match = matches
        .iter()
        .find(|m| m.offset == sha256_offset)
        .expect("SHA-256 initial state match not found");
    assert_eq!(sha_match.algorithm, "SHA-256");
    assert_eq!(sha_match.kind, CryptoPrimitiveKind::StateInitialization);
    assert_eq!(sha_match.length, 32);

    // Verify CRC32 match
    let crc_match = matches
        .iter()
        .find(|m| m.offset == crc32_offset)
        .expect("CRC-32 match not found");
    assert_eq!(crc_match.algorithm, "CRC-32 (IEEE 802.3)");
    assert_eq!(crc_match.kind, CryptoPrimitiveKind::LookupTable);
    assert_eq!(crc_match.length, 64);

    // Verify TEA Delta match
    let tea_match = matches
        .iter()
        .find(|m| m.offset == tea_offset)
        .expect("TEA delta match not found");
    assert_eq!(tea_match.algorithm, "TEA / XTEA");
    assert_eq!(tea_match.kind, CryptoPrimitiveKind::DeltaConstant);
    assert_eq!(tea_match.length, 4);
    assert_eq!(tea_match.confidence, ConfidenceLevel::Medium);
}

#[test]
fn test_scan_synthetic_pe_with_embedded_crypto_tables() {
    let mut code_section = Vec::new();
    code_section.extend_from_slice(b"\x55\x48\x89\xE5"); // push rbp; mov rbp, rsp
    code_section.extend_from_slice(&CHACHA20_SIGMA);
    code_section.extend_from_slice(&TEA_DELTA_LE);
    code_section.extend_from_slice(b"\x5D\xC3"); // pop rbp; ret

    let mut rdata_section = Vec::new();
    rdata_section.extend_from_slice(&[0x00; 16]);
    rdata_section.extend_from_slice(&AES_FORWARD_SBOX);
    rdata_section.extend_from_slice(&AES_INVERSE_SBOX);

    let custom_sections = [
        (
            ".text",
            code_section.as_slice(),
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        ),
        (
            ".rdata",
            rdata_section.as_slice(),
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        ),
    ];

    let pe_bytes = build_synthetic_pe64(&custom_sections);
    let tmp_dir = tempfile::tempdir().expect("Failed to create temporary directory");
    let pe_path = tmp_dir.path().join("crypto_sample.exe");
    fs::write(&pe_path, &pe_bytes).expect("Failed to write synthetic PE binary");

    let report = scan_crypto_file(&pe_path).expect("Failed to scan synthetic PE file");
    assert!(report.binary_format.starts_with("PE"));
    assert!(report.total_matches >= 3);
    assert!(report
        .detected_algorithms
        .contains(&"AES-128/192/256 (Rijndael)".to_string()));
    assert!(report
        .detected_algorithms
        .contains(&"ChaCha20 / Salsa20".to_string()));

    // Verify section correlation: AES tables must be mapped to .rdata with valid RVA
    let aes_fwd = report
        .matches
        .iter()
        .find(|m| m.name == "AES Forward S-Box")
        .expect("AES Forward S-Box not found in PE scan");
    assert_eq!(aes_fwd.section_name.as_deref(), Some(".rdata"));
    assert!(aes_fwd.relative_virtual_address.is_some());

    // Verify ChaCha20 sigma mapped to .text
    let chacha = report
        .matches
        .iter()
        .find(|m| m.name == "ChaCha20 Sigma Constant")
        .expect("ChaCha20 constant not found in PE scan");
    assert_eq!(chacha.section_name.as_deref(), Some(".text"));
    assert!(chacha.relative_virtual_address.is_some());
}

#[test]
fn test_scan_synthetic_elf_with_embedded_crypto_tables() {
    let mut code_bytes = Vec::new();
    code_bytes.extend_from_slice(b"\x48\x31\xC0"); // xor rax, rax
    code_bytes.extend_from_slice(&TEA_DELTA_LE);
    code_bytes.extend_from_slice(b"\xC3"); // ret

    let mut rodata_bytes = Vec::new();
    rodata_bytes.extend_from_slice(&SHA256_INIT_LE);
    rodata_bytes.extend_from_slice(&SM4_SBOX);

    let custom_sections = [
        (
            ".text",
            code_bytes.as_slice(),
            SHF_ALLOC | SHF_EXECINSTR,
            SHT_PROGBITS,
        ),
        (".rodata", rodata_bytes.as_slice(), SHF_ALLOC, SHT_PROGBITS),
    ];

    let elf_bytes = build_synthetic_elf64(&custom_sections);
    let tmp_dir = tempfile::tempdir().expect("Failed to create temporary directory");
    let elf_path = tmp_dir.path().join("crypto_sample.elf");
    fs::write(&elf_path, &elf_bytes).expect("Failed to write synthetic ELF binary");

    let report = scan_crypto_file(&elf_path).expect("Failed to scan synthetic ELF file");
    assert!(report.binary_format.starts_with("ELF"));
    assert!(report.detected_algorithms.contains(&"SHA-256".to_string()));
    assert!(report
        .detected_algorithms
        .contains(&"SM4 (GB/T 32907-2016)".to_string()));

    let sm4_match = report
        .matches
        .iter()
        .find(|m| m.name == "SM4 Block Cipher S-Box")
        .expect("SM4 S-Box not found in ELF scan");
    assert_eq!(sm4_match.section_name.as_deref(), Some(".rodata"));
    assert!(sm4_match.relative_virtual_address.is_some());
}

#[test]
fn test_cli_crypto_scan_json_output() {
    let mut test_bytes = Vec::new();
    test_bytes.extend_from_slice(&[0x41; 64]);
    test_bytes.extend_from_slice(&AES_FORWARD_SBOX);
    test_bytes.extend_from_slice(&CHACHA20_SIGMA);
    test_bytes.extend_from_slice(&TEA_DELTA_LE);

    let tmp_dir = tempfile::tempdir().expect("Failed to create temporary directory");
    let bin_path = tmp_dir.path().join("test_crypto.bin");
    fs::write(&bin_path, &test_bytes).expect("Failed to write test binary");

    let exe = env!("CARGO_BIN_EXE_bsentinel");
    let output = Command::new(exe)
        .arg("crypto-scan")
        .arg(&bin_path)
        .arg("--json")
        .output()
        .expect("Failed to execute bsentinel crypto-scan --json");

    assert!(output.status.success(), "Command returned non-zero status");
    let stdout = String::from_utf8(output.stdout).expect("Stdout is not valid UTF-8");
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Failed to parse crypto-scan JSON output");

    assert_eq!(json["file_size"], test_bytes.len());
    assert_eq!(json["binary_format"], "Raw Binary");
    assert!(json["total_matches"].as_u64().unwrap_or(0) >= 3);
    assert!(json["tea_delta_occurrences"].as_u64().unwrap_or(0) >= 1);

    let matches = json["matches"].as_array().expect("matches should be array");
    let has_aes = matches
        .iter()
        .any(|m| m["name"].as_str() == Some("AES Forward S-Box"));
    assert!(has_aes, "Expected AES Forward S-Box in matches JSON");
}

#[test]
fn test_empty_and_benign_buffers_zero_false_positives() {
    let empty_data: [u8; 0] = [];
    let (matches_empty, tea_count_empty) = scan_crypto_bytes(&empty_data);
    assert_eq!(matches_empty.len(), 0);
    assert_eq!(tea_count_empty, 0);

    let zeroes = vec![0u8; 1024];
    let (matches_zeroes, _) = scan_crypto_bytes(&zeroes);
    // Zeroes should never trigger any S-Box or hash state signature
    assert_eq!(matches_zeroes.len(), 0);
}
