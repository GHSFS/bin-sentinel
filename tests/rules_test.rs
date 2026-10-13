// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fs;
use std::process::Command;

use bin_sentinel::elf::{build_synthetic_elf64, SHF_ALLOC, SHF_EXECINSTR, SHT_PROGBITS};
use bin_sentinel::pe::{
    build_synthetic_pe64, IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE,
};
use bin_sentinel::rules::{
    compile_rule, parse_hex_pattern, parse_rules_json, scan_rules_bytes, ByteMatcher,
    PatternDefinition, PatternToken, PatternType, RuleCondition, RuleDefinition, RuleSeverity,
};
use tempfile::tempdir;

#[test]
fn test_hex_pattern_parsing_and_nibble_wildcards() {
    let tokens = parse_hex_pattern("48 8B ?? ?8 4? [2-5] E8 ?").expect("valid hex pattern");
    assert_eq!(tokens.len(), 8);

    assert_eq!(tokens[0], PatternToken::Byte(ByteMatcher::exact(0x48)));
    assert_eq!(tokens[1], PatternToken::Byte(ByteMatcher::exact(0x8B)));
    assert_eq!(tokens[2], PatternToken::Byte(ByteMatcher::any()));
    assert_eq!(tokens[3], PatternToken::Byte(ByteMatcher::low_nibble(0x08)));
    assert_eq!(
        tokens[4],
        PatternToken::Byte(ByteMatcher::high_nibble(0x04))
    );
    assert_eq!(tokens[5], PatternToken::Jump { min: 2, max: 5 });
    assert_eq!(tokens[6], PatternToken::Byte(ByteMatcher::exact(0xE8)));
    assert_eq!(tokens[7], PatternToken::Byte(ByteMatcher::any()));

    // Continuous hex and nibble wildcards
    let continuous = parse_hex_pattern("4889E5?0").expect("valid continuous hex");
    assert_eq!(continuous.len(), 4);
    assert_eq!(continuous[0], PatternToken::Byte(ByteMatcher::exact(0x48)));
    assert_eq!(continuous[1], PatternToken::Byte(ByteMatcher::exact(0x89)));
    assert_eq!(continuous[2], PatternToken::Byte(ByteMatcher::exact(0xE5)));
    assert_eq!(
        continuous[3],
        PatternToken::Byte(ByteMatcher::low_nibble(0x00))
    );

    // Reject malformed patterns
    assert!(parse_hex_pattern("48 8B [5-2] E8").is_err());
    assert!(parse_hex_pattern("48 8B [5000] E8").is_err());
    assert!(parse_hex_pattern("48 8B [2-4").is_err());
    assert!(parse_hex_pattern("48 8G").is_err());
    assert!(parse_hex_pattern("488").is_err());
}

#[test]
fn test_wildcard_and_byte_jump_matching() {
    // Target buffer with payload at offset 4
    let mut buffer = vec![0x90; 64];
    buffer[4] = 0x48;
    buffer[5] = 0x83;
    buffer[6] = 0xEC;
    buffer[7] = 0x20; // ?? matches 0x20
    buffer[8] = 0x90; // jump byte 1
    buffer[9] = 0x90; // jump byte 2
    buffer[10] = 0x90; // jump byte 3
    buffer[11] = 0xE8; // E8 call opcode
    buffer[12] = 0x10;
    buffer[13] = 0x00;

    let def = RuleDefinition {
        name: "Test_Jump_Pattern".to_string(),
        description: Some("Tests wildcard and jump matching".to_string()),
        tags: vec!["test".to_string()],
        severity: RuleSeverity::High,
        patterns: vec![PatternDefinition {
            id: "$p_jump".to_string(),
            pattern_type: PatternType::Hex,
            value: "48 83 EC ?? [2-4] E8".to_string(),
            nocase: false,
        }],
        condition: RuleCondition::All,
    };

    let compiled = compile_rule(&def).expect("compilation succeeded");
    let report = scan_rules_bytes(&buffer, &[compiled], None).expect("scan succeeded");

    assert_eq!(report.summary.rules_matched, 1);
    assert_eq!(report.summary.patterns_matched, 1);
    assert_eq!(report.matches[0].matched_patterns[0].offset, 4);
    assert_eq!(report.matches[0].matched_patterns[0].length, 8); // 48 83 EC 20 90 90 90 E8 = 8 bytes
}

#[test]
fn test_ascii_and_wide_string_patterns_with_nocase() {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(b"preamble...");
    buffer.extend_from_slice(b"cMd.ExE"); // Mixed-case ASCII
    buffer.extend_from_slice(b"...padding...");

    // UTF-16LE "KeRnEl32"
    let wide_str: Vec<u8> = "KeRnEl32"
        .encode_utf16()
        .flat_map(|u| vec![(u & 0xFF) as u8, ((u >> 8) & 0xFF) as u8])
        .collect();
    let wide_offset = buffer.len();
    buffer.extend_from_slice(&wide_str);

    let def = RuleDefinition {
        name: "Test_String_Patterns".to_string(),
        description: None,
        tags: vec!["strings".to_string()],
        severity: RuleSeverity::Medium,
        patterns: vec![
            PatternDefinition {
                id: "$ascii_cmd".to_string(),
                pattern_type: PatternType::Ascii,
                value: "cmd.exe".to_string(),
                nocase: true,
            },
            PatternDefinition {
                id: "$wide_kernel".to_string(),
                pattern_type: PatternType::Wide,
                value: "kernel32".to_string(),
                nocase: true,
            },
        ],
        condition: RuleCondition::All,
    };

    let compiled = compile_rule(&def).expect("compilation succeeded");
    let report = scan_rules_bytes(&buffer, &[compiled], None).expect("scan succeeded");

    assert_eq!(report.summary.rules_matched, 1);
    assert_eq!(report.summary.patterns_matched, 2);
    let p0 = &report.matches[0].matched_patterns[0];
    let p1 = &report.matches[0].matched_patterns[1];
    assert_eq!(p0.pattern_id, "$ascii_cmd");
    assert_eq!(p0.offset, 11);
    assert_eq!(p1.pattern_id, "$wide_kernel");
    assert_eq!(p1.offset, wide_offset);
}

#[test]
fn test_multi_pattern_conditions_and_json_parsing() {
    let json_rules = r#"
    [
        {
            "name": "Rule_Condition_Any",
            "severity": "Low",
            "condition": "any",
            "patterns": [
                { "id": "$hit", "type": "hex", "value": "AA BB CC" },
                { "id": "$miss", "type": "hex", "value": "11 22 33" }
            ]
        },
        {
            "name": "Rule_Condition_All",
            "severity": "Critical",
            "condition": "all",
            "patterns": [
                { "id": "$hit", "type": "hex", "value": "AA BB CC" },
                { "id": "$miss", "type": "hex", "value": "11 22 33" }
            ]
        }
    ]
    "#;

    let ruleset = parse_rules_json(json_rules).expect("valid json rules");
    assert_eq!(ruleset.rules.len(), 2);

    let data = vec![0x00, 0xAA, 0xBB, 0xCC, 0xFF];
    let compiled: Vec<_> = ruleset
        .rules
        .iter()
        .map(|r| compile_rule(r).unwrap())
        .collect();
    let report = scan_rules_bytes(&data, &compiled, None).expect("scan succeeded");

    assert_eq!(report.summary.total_rules_evaluated, 2);
    assert_eq!(report.summary.rules_matched, 1); // Only "any" should match
    assert_eq!(report.matches[0].rule_name, "Rule_Condition_Any");
}

#[test]
fn test_pe_and_elf_section_and_rwx_mapping() {
    // Build synthetic PE with signature inside RWX section
    let code = b"\x4C\x8B\xD1\xB8\x18\x00\x00\x00\x0F\x05\xC3"; // Direct syscall stub
    let pe_data = build_synthetic_pe64(&[(
        ".text",
        code,
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE,
    )]);

    let pat = PatternDefinition {
        id: "$syscall".to_string(),
        pattern_type: PatternType::Hex,
        value: "4C 8B D1 B8 [4] 0F 05".to_string(),
        nocase: false,
    };
    let rule = RuleDefinition {
        name: "Detect_Direct_Syscall".to_string(),
        description: Some("Detects direct syscall inside executable code".to_string()),
        tags: vec!["evasion".to_string()],
        severity: RuleSeverity::Critical,
        patterns: vec![pat],
        condition: RuleCondition::All,
    };

    let compiled = compile_rule(&rule).unwrap();
    let report = scan_rules_bytes(&pe_data, &[compiled], Some("sample.exe")).unwrap();

    assert_eq!(report.binary_format, "PE32+ (64-bit)");
    assert_eq!(report.summary.rules_matched, 1);
    let m = &report.matches[0].matched_patterns[0];
    assert_eq!(m.section_name.as_deref(), Some(".text"));
    assert!(m.relative_virtual_address.is_some());
    assert!(m.risk_alert.is_some()); // Should flag RWX anomaly

    // Build synthetic ELF and scan
    let elf_data =
        build_synthetic_elf64(&[(".text", code, SHF_ALLOC | SHF_EXECINSTR, SHT_PROGBITS)]);
    let elf_compiled = compile_rule(&rule).unwrap();
    let elf_report = scan_rules_bytes(&elf_data, &[elf_compiled], Some("sample.elf")).unwrap();

    assert_eq!(elf_report.binary_format, "ELF64");
    assert_eq!(elf_report.summary.rules_matched, 1);
    let em = &elf_report.matches[0].matched_patterns[0];
    assert_eq!(em.section_name.as_deref(), Some(".text"));
    assert!(em.virtual_address.is_some());
}

#[test]
fn test_cli_rule_scan_adhoc_and_json_file() {
    let dir = tempdir().expect("create tempdir");
    let bin_path = dir.path().join("target.bin");
    let rules_path = dir.path().join("rules.json");

    let payload = b"\x90\x90\x48\x8B\x05\x12\x34\x56\x78\x90\x90";
    fs::write(&bin_path, payload).expect("write target bin");

    let json_content = r#"{
        "name": "Test_Json_Rule",
        "description": "Rules file test",
        "tags": ["cli", "json"],
        "severity": "High",
        "patterns": [
            { "id": "$p_mov", "type": "hex", "value": "48 8B 05 ?? ?? ?? ??" }
        ],
        "condition": "all"
    }"#;
    fs::write(&rules_path, json_content).expect("write rules json");

    let exe = env!("CARGO_BIN_EXE_bsentinel");

    // 1. Scan with ad-hoc pattern --pattern
    let adhoc_out = Command::new(exe)
        .args([
            "rule-scan",
            bin_path.to_str().unwrap(),
            "--pattern",
            "48 8B 05 ?? [2-4]",
            "--json",
        ])
        .output()
        .expect("run rule-scan adhoc");
    assert!(adhoc_out.status.success());
    let adhoc_json: serde_json::Value =
        serde_json::from_slice(&adhoc_out.stdout).expect("valid json output");
    assert_eq!(adhoc_json["summary"]["rules_matched"], 1);

    // 2. Scan with --rules <file>
    let file_out = Command::new(exe)
        .args([
            "rule-scan",
            bin_path.to_str().unwrap(),
            "--rules",
            rules_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run rule-scan with rules file");
    assert!(file_out.status.success());
    let file_json: serde_json::Value =
        serde_json::from_slice(&file_out.stdout).expect("valid json output");
    assert_eq!(file_json["summary"]["rules_matched"], 1);
    assert_eq!(file_json["matches"][0]["rule_name"], "Test_Json_Rule");
}
