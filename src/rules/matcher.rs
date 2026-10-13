// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::rules::types::{ByteMatcher, PatternToken};

/// Maximum match byte span to prevent pathological regex-like expansions.
pub const MAX_MATCH_SPAN: usize = 65536;

/// Maximum recursion depth for jump resolution.
pub const MAX_DFS_DEPTH: usize = 64;

/// Default maximum matches recorded per pattern.
pub const DEFAULT_MAX_MATCHES: usize = 1000;

/// Searches for all occurrences of a token sequence within a buffer.
/// Returns a list of `(start_offset, match_length)`.
pub fn find_pattern_matches(
    tokens: &[PatternToken],
    data: &[u8],
    max_matches: usize,
) -> Vec<(usize, usize)> {
    if tokens.is_empty() || data.is_empty() {
        return Vec::new();
    }

    let has_jumps = tokens
        .iter()
        .any(|t| matches!(t, PatternToken::Jump { .. }));
    let mut results = Vec::new();

    if !has_jumps {
        // High-speed linear path for jump-free patterns
        let len = tokens.len();
        if data.len() < len {
            return Vec::new();
        }

        let first_matcher = match tokens[0] {
            PatternToken::Byte(m) => m,
            PatternToken::Jump { .. } => unreachable!(),
        };

        let end_bound = data.len().saturating_sub(len);
        for start in 0..=end_bound {
            // Fast candidate check on first byte
            if !first_matcher.matches(data[start]) {
                continue;
            }

            if match_fixed_tokens(tokens, &data[start..start + len]) {
                results.push((start, len));
                if results.len() >= max_matches {
                    break;
                }
            }
        }
    } else {
        // General DFS path supporting byte jumps [min-max]
        let first_matcher = find_initial_matcher(tokens);

        for start in 0..data.len() {
            if let Some(m) = first_matcher {
                if !m.matches(data[start]) {
                    continue;
                }
            }

            if let Some(matched_len) = match_tokens_at(tokens, data, start) {
                results.push((start, matched_len));
                if results.len() >= max_matches {
                    break;
                }
            }
        }
    }

    results
}

#[inline]
fn match_fixed_tokens(tokens: &[PatternToken], slice: &[u8]) -> bool {
    for (i, token) in tokens.iter().enumerate() {
        if let PatternToken::Byte(m) = token {
            if !m.matches(slice[i]) {
                return false;
            }
        }
    }
    true
}

fn find_initial_matcher(tokens: &[PatternToken]) -> Option<ByteMatcher> {
    for token in tokens {
        if let PatternToken::Byte(m) = token {
            return Some(*m);
        }
    }
    None
}

/// Evaluates if tokens match at `start_offset` in `data`. Returns matched length.
pub fn match_tokens_at(tokens: &[PatternToken], data: &[u8], start: usize) -> Option<usize> {
    dfs_match(tokens, 0, data, start, start, 0).map(|end| end.saturating_sub(start))
}

fn dfs_match(
    tokens: &[PatternToken],
    token_idx: usize,
    data: &[u8],
    current_data_idx: usize,
    start_idx: usize,
    depth: usize,
) -> Option<usize> {
    if depth > MAX_DFS_DEPTH {
        return None;
    }

    if current_data_idx.saturating_sub(start_idx) > MAX_MATCH_SPAN {
        return None;
    }

    if token_idx == tokens.len() {
        return Some(current_data_idx);
    }

    match &tokens[token_idx] {
        PatternToken::Byte(matcher) => {
            if current_data_idx >= data.len() {
                return None;
            }
            if !matcher.matches(data[current_data_idx]) {
                return None;
            }
            dfs_match(
                tokens,
                token_idx + 1,
                data,
                current_data_idx + 1,
                start_idx,
                depth + 1,
            )
        }
        PatternToken::Jump { min, max } => {
            // Try jumps in ascending order (shortest match first)
            for jump in *min..=*max {
                let next_data_idx = match current_data_idx.checked_add(jump) {
                    Some(idx) => idx,
                    None => break,
                };
                if next_data_idx > data.len() {
                    break;
                }

                if let Some(end) = dfs_match(
                    tokens,
                    token_idx + 1,
                    data,
                    next_data_idx,
                    start_idx,
                    depth + 1,
                ) {
                    return Some(end);
                }
            }
            None
        }
    }
}

/// Helper to format raw bytes into a readable hex preview.
pub fn format_matched_hex(bytes: &[u8], max_display_bytes: usize) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    let take_count = bytes.len().min(max_display_bytes);
    let hex_parts: Vec<String> = bytes[..take_count]
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();

    if bytes.len() > max_display_bytes {
        format!("{} ... ({} B)", hex_parts.join(" "), bytes.len())
    } else {
        hex_parts.join(" ")
    }
}
