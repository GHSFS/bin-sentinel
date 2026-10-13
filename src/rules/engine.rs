// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::elf::parse_elf;
use crate::error::Result;
use crate::pe::parse_pe;
use crate::rules::matcher::{find_pattern_matches, format_matched_hex, DEFAULT_MAX_MATCHES};
use crate::rules::parser::{compile_pattern_definition, parse_rules_json};
use crate::rules::types::{
    PatternDefinition, PatternMatch, PatternToken, PatternType, RuleCondition, RuleDefinition,
    RuleMatch, RuleScanReport, RuleScanSummary, RuleSetDefinition, RuleSeverity,
};

/// A compiled, executable pattern.
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    pub id: String,
    pub pattern_type: PatternType,
    pub tokens: Vec<PatternToken>,
    pub raw_value: String,
    pub nocase: bool,
}

/// A compiled, executable rule containing one or more patterns.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub name: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub severity: RuleSeverity,
    pub condition: RuleCondition,
    pub patterns: Vec<CompiledPattern>,
}

/// Compiles a single pattern definition into executable tokens.
pub fn compile_pattern(def: &PatternDefinition) -> Result<CompiledPattern> {
    let tokens = compile_pattern_definition(def)?;
    Ok(CompiledPattern {
        id: def.id.clone(),
        pattern_type: def.pattern_type,
        tokens,
        raw_value: def.value.clone(),
        nocase: def.nocase,
    })
}

/// Compiles a rule definition into an executable rule.
pub fn compile_rule(def: &RuleDefinition) -> Result<CompiledRule> {
    let mut compiled_patterns = Vec::with_capacity(def.patterns.len());
    for p in &def.patterns {
        compiled_patterns.push(compile_pattern(p)?);
    }
    Ok(CompiledRule {
        name: def.name.clone(),
        description: def.description.clone(),
        tags: def.tags.clone(),
        severity: def.severity,
        condition: def.condition,
        patterns: compiled_patterns,
    })
}

/// Compiles an entire rule set.
pub fn compile_ruleset(set: &RuleSetDefinition) -> Result<Vec<CompiledRule>> {
    let mut rules = Vec::with_capacity(set.rules.len());
    for r in &set.rules {
        rules.push(compile_rule(r)?);
    }
    Ok(rules)
}

/// Loads and compiles rules directly from a JSON file.
pub fn load_rules_from_file(path: &Path) -> Result<Vec<CompiledRule>> {
    let content = fs::read_to_string(path)?;
    let rule_set = parse_rules_json(&content)?;
    compile_ruleset(&rule_set)
}

/// Scans raw binary buffer against a collection of compiled rules.
pub fn scan_rules_bytes(
    data: &[u8],
    rules: &[CompiledRule],
    target_file: Option<&str>,
) -> Result<RuleScanReport> {
    let file_path_str = target_file.unwrap_or("<in-memory>").to_string();
    let file_size = data.len();

    // Correlate with PE or ELF structures if valid
    let pe_info = parse_pe(data).ok();
    let elf_info = if pe_info.is_none() {
        parse_elf(data).ok()
    } else {
        None
    };

    let binary_format = if let Some(ref pe) = pe_info {
        pe.format.clone()
    } else if elf_info.is_some() {
        "ELF64".to_string()
    } else {
        "Raw Binary".to_string()
    };

    let mut matched_rules = Vec::new();
    let mut total_patterns_matched = 0;
    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;

    for rule in rules {
        let mut pattern_matches_for_rule = Vec::new();
        let mut matching_pattern_ids = HashSet::new();

        for pat in &rule.patterns {
            let hits = find_pattern_matches(&pat.tokens, data, DEFAULT_MAX_MATCHES);
            if !hits.is_empty() {
                matching_pattern_ids.insert(&pat.id);

                for (offset, length) in hits {
                    let end = (offset + length).min(data.len());
                    let matched_bytes = &data[offset..end];
                    let hex_str = format_matched_hex(matched_bytes, 16);

                    // Section & address resolution
                    let (sec_name, rva, va, risk_alert) = if let Some(ref pe) = pe_info {
                        resolve_pe_section(pe, offset)
                    } else if let Some(ref elf) = elf_info {
                        resolve_elf_section(elf, offset)
                    } else {
                        (None, None, None, None)
                    };

                    pattern_matches_for_rule.push(PatternMatch {
                        pattern_id: pat.id.clone(),
                        pattern_type: pat.pattern_type,
                        offset,
                        length,
                        matched_bytes_hex: hex_str,
                        section_name: sec_name,
                        relative_virtual_address: rva,
                        virtual_address: va,
                        risk_alert,
                    });
                }
            }
        }

        let condition_met = match rule.condition {
            RuleCondition::All => {
                !rule.patterns.is_empty() && matching_pattern_ids.len() == rule.patterns.len()
            }
            RuleCondition::Any => !matching_pattern_ids.is_empty(),
            RuleCondition::Count(k) => matching_pattern_ids.len() >= k,
        };

        if condition_met {
            total_patterns_matched += pattern_matches_for_rule.len();
            match rule.severity {
                RuleSeverity::Critical => critical_count += 1,
                RuleSeverity::High => high_count += 1,
                RuleSeverity::Medium => medium_count += 1,
                RuleSeverity::Low => low_count += 1,
            }

            matched_rules.push(RuleMatch {
                rule_name: rule.name.clone(),
                description: rule.description.clone(),
                tags: rule.tags.clone(),
                severity: rule.severity,
                matched_patterns: pattern_matches_for_rule,
            });
        }
    }

    let summary = RuleScanSummary {
        total_rules_evaluated: rules.len(),
        rules_matched: matched_rules.len(),
        patterns_matched: total_patterns_matched,
        critical_count,
        high_count,
        medium_count,
        low_count,
    };

    Ok(RuleScanReport {
        target_file: file_path_str,
        binary_format,
        file_size,
        summary,
        matches: matched_rules,
    })
}

/// Scans a file on disk against a collection of compiled rules.
pub fn scan_rules_file(path: &Path, rules: &[CompiledRule]) -> Result<RuleScanReport> {
    let data = fs::read(path)?;
    scan_rules_bytes(&data, rules, Some(&path.display().to_string()))
}

fn resolve_pe_section(
    pe: &crate::pe::PeInfo,
    offset: usize,
) -> (Option<String>, Option<u64>, Option<u64>, Option<String>) {
    let off_u32 = offset as u32;
    for sec in &pe.sections {
        let sec_end = sec.raw_offset.saturating_add(sec.raw_size);
        if off_u32 >= sec.raw_offset && off_u32 < sec_end {
            let delta = (off_u32 - sec.raw_offset) as u64;
            let rva = (sec.virtual_address as u64) + delta;
            let va = pe.image_base.saturating_add(rva);
            let alert = if sec.rwx_anomaly {
                Some("Pattern matched in RWX section".to_string())
            } else {
                None
            };
            return (Some(sec.name.clone()), Some(rva), Some(va), alert);
        }
    }
    (None, None, None, None)
}

fn resolve_elf_section(
    elf: &crate::elf::ElfInfo,
    offset: usize,
) -> (Option<String>, Option<u64>, Option<u64>, Option<String>) {
    let off_u64 = offset as u64;
    for sec in &elf.sections {
        let sec_end = sec.offset.saturating_add(sec.size);
        if off_u64 >= sec.offset && off_u64 < sec_end {
            let delta = off_u64 - sec.offset;
            let va = sec.addr.saturating_add(delta);
            let alert = if sec.rwx_anomaly {
                Some("Pattern matched in RWX section".to_string())
            } else {
                None
            };
            return (Some(sec.name.clone()), None, Some(va), alert);
        }
    }
    (None, None, None, None)
}
