// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod engine;
pub mod matcher;
pub mod parser;
pub mod types;

pub use engine::{
    compile_pattern, compile_rule, compile_ruleset, load_rules_from_file, scan_rules_bytes,
    scan_rules_file, CompiledPattern, CompiledRule,
};
pub use matcher::{find_pattern_matches, format_matched_hex, match_tokens_at};
pub use parser::{
    compile_pattern_definition, parse_ascii_pattern, parse_hex_pattern, parse_rules_json,
    parse_wide_pattern, MAX_JUMP_LIMIT,
};
pub use types::{
    ByteMatcher, PatternDefinition, PatternMatch, PatternToken, PatternType, RuleCondition,
    RuleDefinition, RuleMatch, RuleScanReport, RuleScanSummary, RuleSetDefinition, RuleSeverity,
};
