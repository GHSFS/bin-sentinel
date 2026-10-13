// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::{Result, SentinelError};
use crate::rules::types::{
    ByteMatcher, PatternDefinition, PatternToken, PatternType, RuleDefinition, RuleSetDefinition,
};

/// Maximum allowed jump interval span to prevent excessive backtracking.
pub const MAX_JUMP_LIMIT: usize = 4096;

/// Parse a YARA-style hex pattern string with wildcards and jumps into tokens.
pub fn parse_hex_pattern(raw: &str) -> Result<Vec<PatternToken>> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = raw.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }

        if c == '[' {
            // Parse jump syntax: [min-max] or [count]
            let start_jump = i;
            i += 1;
            let mut inside = String::new();
            while i < chars.len() && chars[i] != ']' {
                inside.push(chars[i]);
                i += 1;
            }
            if i >= chars.len() {
                return Err(SentinelError::InvalidArgument(format!(
                    "Unclosed jump bracket starting at character index {start_jump}: '{raw}'"
                )));
            }
            // Skip the closing ']'
            i += 1;

            let (min, max) = parse_jump_bounds(&inside)?;
            if min > max {
                return Err(SentinelError::InvalidArgument(format!(
                    "Invalid jump range [{min}-{max}]: min cannot exceed max in '{raw}'"
                )));
            }
            if max > MAX_JUMP_LIMIT {
                return Err(SentinelError::InvalidArgument(format!(
                    "Jump range max {max} exceeds security ceiling of {MAX_JUMP_LIMIT} in '{raw}'"
                )));
            }
            tokens.push(PatternToken::Jump { min, max });
            continue;
        }

        // Collect consecutive non-whitespace and non-bracket characters
        let mut word = String::new();
        while i < chars.len() && !chars[i].is_whitespace() && chars[i] != '[' {
            word.push(chars[i]);
            i += 1;
        }

        // Word can be a single '?', or pairs of hex/wildcard characters
        let word_chars: Vec<char> = word.chars().collect();
        if word_chars.len() == 1 && word_chars[0] == '?' {
            tokens.push(PatternToken::Byte(ByteMatcher::any()));
            continue;
        }

        if word_chars.len() % 2 != 0 {
            return Err(SentinelError::InvalidArgument(format!(
                "Uneven nibble token '{word}' in hex pattern: '{raw}'. Bytes must be 2 hex digits or '??'"
            )));
        }

        for chunk in word_chars.chunks(2) {
            let high_char = chunk[0];
            let low_char = chunk[1];
            let matcher = parse_nibble_pair(high_char, low_char, &word)?;
            tokens.push(PatternToken::Byte(matcher));
        }
    }

    if tokens.is_empty() {
        return Err(SentinelError::InvalidArgument(format!(
            "Pattern contains zero valid tokens: '{raw}'"
        )));
    }

    Ok(tokens)
}

fn parse_jump_bounds(inside: &str) -> Result<(usize, usize)> {
    let trimmed = inside.trim();
    if let Some((min_str, max_str)) = trimmed.split_once('-') {
        let min: usize = min_str.trim().parse().map_err(|_| {
            SentinelError::InvalidArgument(format!("Invalid min jump: '{min_str}'"))
        })?;
        let max: usize = max_str.trim().parse().map_err(|_| {
            SentinelError::InvalidArgument(format!("Invalid max jump: '{max_str}'"))
        })?;
        Ok((min, max))
    } else {
        let count: usize = trimmed.parse().map_err(|_| {
            SentinelError::InvalidArgument(format!("Invalid fixed jump count: '{trimmed}'"))
        })?;
        Ok((count, count))
    }
}

fn parse_nibble_pair(high: char, low: char, full_token: &str) -> Result<ByteMatcher> {
    match (high, low) {
        ('?', '?') => Ok(ByteMatcher::any()),
        ('?', l) if l.is_ascii_hexdigit() => {
            let low_nibble = l.to_digit(16).unwrap_or(0) as u8;
            Ok(ByteMatcher::low_nibble(low_nibble))
        }
        (h, '?') if h.is_ascii_hexdigit() => {
            let high_nibble = h.to_digit(16).unwrap_or(0) as u8;
            Ok(ByteMatcher::high_nibble(high_nibble))
        }
        (h, l) if h.is_ascii_hexdigit() && l.is_ascii_hexdigit() => {
            let high_val = h.to_digit(16).unwrap_or(0) as u8;
            let low_val = l.to_digit(16).unwrap_or(0) as u8;
            let byte = (high_val << 4) | low_val;
            Ok(ByteMatcher::exact(byte))
        }
        _ => Err(SentinelError::InvalidArgument(format!(
            "Invalid hex or wildcard characters '{high}{low}' in token '{full_token}'"
        ))),
    }
}

/// Parse an ASCII string into pattern tokens.
pub fn parse_ascii_pattern(raw: &str, nocase: bool) -> Vec<PatternToken> {
    raw.bytes()
        .map(|b| {
            if nocase {
                PatternToken::Byte(ByteMatcher::ascii_nocase(b))
            } else {
                PatternToken::Byte(ByteMatcher::exact(b))
            }
        })
        .collect()
}

/// Parse a UTF-16LE wide string into pattern tokens.
pub fn parse_wide_pattern(raw: &str, nocase: bool) -> Vec<PatternToken> {
    let mut tokens = Vec::with_capacity(raw.len() * 2);
    for code_unit in raw.encode_utf16() {
        let low = (code_unit & 0xFF) as u8;
        let high = ((code_unit >> 8) & 0xFF) as u8;
        if nocase && high == 0 && (low as char).is_ascii_alphabetic() {
            tokens.push(PatternToken::Byte(ByteMatcher::ascii_nocase(low)));
            tokens.push(PatternToken::Byte(ByteMatcher::exact(0x00)));
        } else {
            tokens.push(PatternToken::Byte(ByteMatcher::exact(low)));
            tokens.push(PatternToken::Byte(ByteMatcher::exact(high)));
        }
    }
    tokens
}

/// Compile a pattern definition into token sequences.
pub fn compile_pattern_definition(def: &PatternDefinition) -> Result<Vec<PatternToken>> {
    match def.pattern_type {
        PatternType::Hex => parse_hex_pattern(&def.value),
        PatternType::Ascii => Ok(parse_ascii_pattern(&def.value, def.nocase)),
        PatternType::Wide => Ok(parse_wide_pattern(&def.value, def.nocase)),
    }
}

/// Parse and deserialize rules from JSON text supporting single-rule, array, and wrapped object forms.
pub fn parse_rules_json(json_str: &str) -> Result<RuleSetDefinition> {
    // 1. Try wrapped RuleSetDefinition: {"rules": [...]}
    if let Ok(rule_set) = serde_json::from_str::<RuleSetDefinition>(json_str) {
        return Ok(rule_set);
    }

    // 2. Try array: [...]
    if let Ok(rules) = serde_json::from_str::<Vec<RuleDefinition>>(json_str) {
        return Ok(RuleSetDefinition { rules });
    }

    // 3. Try single rule: {"name": ...}
    if let Ok(rule) = serde_json::from_str::<RuleDefinition>(json_str) {
        return Ok(RuleSetDefinition { rules: vec![rule] });
    }

    Err(SentinelError::InvalidArgument(
        "Failed to parse rule JSON: input must be a RuleDefinition, an array of RuleDefinitions, or a RuleSetDefinition object".to_string(),
    ))
}
