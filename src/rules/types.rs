// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::{Deserialize, Serialize};

/// Matcher for a single byte with bitwise mask support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteMatcher {
    pub value: u8,
    pub mask: u8,
}

impl ByteMatcher {
    /// Tests if a candidate byte matches under the bitwise mask.
    #[inline]
    pub fn matches(&self, b: u8) -> bool {
        (b & self.mask) == (self.value & self.mask)
    }

    /// Creates an exact byte matcher (mask 0xFF).
    pub fn exact(b: u8) -> Self {
        Self {
            value: b,
            mask: 0xFF,
        }
    }

    /// Creates a full wildcard byte matcher matching any byte (mask 0x00).
    pub fn any() -> Self {
        Self {
            value: 0x00,
            mask: 0x00,
        }
    }

    /// Creates a high-nibble matcher with low nibble wildcard (mask 0xF0).
    pub fn high_nibble(high: u8) -> Self {
        Self {
            value: (high & 0x0F) << 4,
            mask: 0xF0,
        }
    }

    /// Creates a low-nibble matcher with high nibble wildcard (mask 0x0F).
    pub fn low_nibble(low: u8) -> Self {
        Self {
            value: low & 0x0F,
            mask: 0x0F,
        }
    }

    /// Creates a case-insensitive ASCII letter matcher (mask 0xDF).
    pub fn ascii_nocase(b: u8) -> Self {
        if b.is_ascii_alphabetic() {
            Self {
                value: b.to_ascii_uppercase(),
                mask: 0xDF,
            }
        } else {
            Self::exact(b)
        }
    }
}

/// Token in a compiled pattern sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternToken {
    /// Match a single byte with mask.
    Byte(ByteMatcher),
    /// Jump between `min` and `max` bytes inclusive.
    Jump { min: usize, max: usize },
}

/// Pattern data type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatternType {
    Hex,
    Ascii,
    Wide,
}

pub fn default_pattern_type() -> PatternType {
    PatternType::Hex
}

/// Declarative pattern definition inside a rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternDefinition {
    pub id: String,
    #[serde(rename = "type", default = "default_pattern_type")]
    pub pattern_type: PatternType,
    pub value: String,
    #[serde(default)]
    pub nocase: bool,
}

/// Evaluation condition for a multi-pattern rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleCondition {
    All,
    Any,
    #[serde(untagged)]
    Count(usize),
}

pub fn default_condition() -> RuleCondition {
    RuleCondition::All
}

/// Threat or classification severity of a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RuleSeverity {
    Low,
    Medium,
    High,
    Critical,
}

pub fn default_severity() -> RuleSeverity {
    RuleSeverity::Medium
}

/// Declarative rule definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleDefinition {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_severity")]
    pub severity: RuleSeverity,
    pub patterns: Vec<PatternDefinition>,
    #[serde(default = "default_condition")]
    pub condition: RuleCondition,
}

/// Collection of declarative rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSetDefinition {
    pub rules: Vec<RuleDefinition>,
}

/// Details of an individual pattern match within a binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternMatch {
    pub pattern_id: String,
    pub pattern_type: PatternType,
    pub offset: usize,
    pub length: usize,
    pub matched_bytes_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relative_virtual_address: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virtual_address: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_alert: Option<String>,
}

/// Summary of all patterns matching a rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub severity: RuleSeverity,
    pub matched_patterns: Vec<PatternMatch>,
}

/// Quantitative summary of rule evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleScanSummary {
    pub total_rules_evaluated: usize,
    pub rules_matched: usize,
    pub patterns_matched: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

/// Full rule scan report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleScanReport {
    pub target_file: String,
    pub binary_format: String,
    pub file_size: usize,
    pub summary: RuleScanSummary,
    pub matches: Vec<RuleMatch>,
}
