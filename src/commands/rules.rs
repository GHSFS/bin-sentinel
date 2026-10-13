// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::path::Path;

use crate::error::{Result, SentinelError};
use crate::rules::{
    compile_rule, load_rules_from_file, scan_rules_file, PatternDefinition, PatternType,
    RuleCondition, RuleDefinition, RuleSeverity,
};

pub fn handle_rule_scan(
    file: &Path,
    pattern: Option<&str>,
    rules_path: Option<&Path>,
    json: bool,
) -> Result<()> {
    if pattern.is_none() && rules_path.is_none() {
        return Err(SentinelError::InvalidArgument(
            "Please provide either --pattern \"<hex>\" or --rules <rules.json>".to_string(),
        ));
    }

    let mut rules = Vec::new();

    if let Some(rpath) = rules_path {
        let loaded = load_rules_from_file(rpath)?;
        rules.extend(loaded);
    }

    if let Some(pat_str) = pattern {
        let adhoc_def = RuleDefinition {
            name: "cli_adhoc_pattern".to_string(),
            description: Some(format!("Ad-hoc signature: {pat_str}")),
            tags: vec!["adhoc".to_string()],
            severity: RuleSeverity::High,
            patterns: vec![PatternDefinition {
                id: "$p0".to_string(),
                pattern_type: PatternType::Hex,
                value: pat_str.to_string(),
                nocase: false,
            }],
            condition: RuleCondition::All,
        };
        rules.push(compile_rule(&adhoc_def)?);
    }

    let report = scan_rules_file(file, &rules)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        println!("=== YARA-Style Pattern Rule Scan: {} ===", file.display());
        println!("Format            : {}", report.binary_format);
        println!("File Size         : {} bytes", report.file_size);
        println!(
            "Rules Evaluated   : {}",
            report.summary.total_rules_evaluated
        );
        println!(
            "Rules Matched     : {} (Critical: {}, High: {}, Medium: {}, Low: {})",
            report.summary.rules_matched,
            report.summary.critical_count,
            report.summary.high_count,
            report.summary.medium_count,
            report.summary.low_count
        );
        println!("Patterns Matched  : {}", report.summary.patterns_matched);

        if !report.matches.is_empty() {
            println!("\n[Matched Rules]");
            for r in &report.matches {
                let tags_str = if r.tags.is_empty() {
                    "-".to_string()
                } else {
                    r.tags.join(", ")
                };
                println!("  [{:?}] {}", r.severity, r.rule_name);
                if let Some(ref desc) = r.description {
                    println!("    Description   : {desc}");
                }
                println!("    Tags          : {tags_str}");
                println!("    Matches ({}):", r.matched_patterns.len());
                for m in &r.matched_patterns {
                    let sec_str = m.section_name.as_deref().unwrap_or("-");
                    let addr_str = if let Some(rva) = m.relative_virtual_address {
                        format!("RVA 0x{rva:08X}")
                    } else if let Some(va) = m.virtual_address {
                        format!("VA 0x{va:016X}")
                    } else {
                        format!("Offset 0x{:08X}", m.offset)
                    };
                    let alert_str = if let Some(ref alert) = m.risk_alert {
                        format!(" [ALERT: {alert}]")
                    } else {
                        String::new()
                    };
                    println!(
                        "      {:8} | {:16} | {:8} | Offset 0x{:08X} ({:3} B) | {}{}",
                        m.pattern_id,
                        addr_str,
                        sec_str,
                        m.offset,
                        m.length,
                        m.matched_bytes_hex,
                        alert_str
                    );
                }
            }
        }
    }

    Ok(())
}
