// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::{FuzzyDigest, SectionComparison, SectionFuzzyHash};

/// Computes the Levenshtein edit distance between two ASCII/UTF-8 strings with O(min(M, N)) space.
pub fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let v1: Vec<char> = s1.chars().collect();
    let v2: Vec<char> = s2.chars().collect();

    if v1.is_empty() {
        return v2.len();
    }
    if v2.is_empty() {
        return v1.len();
    }

    let mut prev_row: Vec<usize> = (0..=v2.len()).collect();
    let mut curr_row: Vec<usize> = vec![0; v2.len() + 1];

    for (i, &c1) in v1.iter().enumerate() {
        curr_row[0] = i + 1;
        for (j, &c2) in v2.iter().enumerate() {
            let cost = if c1 == c2 { 0 } else { 1 };
            curr_row[j + 1] = (curr_row[j] + 1)
                .min(prev_row[j + 1] + 1)
                .min(prev_row[j] + cost);
        }
        prev_row.copy_from_slice(&curr_row);
    }

    prev_row[v2.len()]
}

/// Finds the length of the longest contiguous common substring between two strings.
pub fn longest_common_substring(s1: &str, s2: &str) -> usize {
    let b1 = s1.as_bytes();
    let b2 = s2.as_bytes();

    if b1.is_empty() || b2.is_empty() {
        return 0;
    }

    let mut max_len = 0;
    let mut dp = vec![vec![0usize; b2.len() + 1]; b1.len() + 1];

    for i in 1..=b1.len() {
        for j in 1..=b2.len() {
            if b1[i - 1] == b2[j - 1] {
                dp[i][j] = dp[i - 1][j - 1] + 1;
                if dp[i][j] > max_len {
                    max_len = dp[i][j];
                }
            } else {
                dp[i][j] = 0;
            }
        }
    }

    max_len
}

/// Scores similarity between two digest strings (0 to 100).
pub fn score_strings(s1: &str, s2: &str) -> u32 {
    if s1.is_empty() && s2.is_empty() {
        return 100;
    }
    if s1.is_empty() || s2.is_empty() {
        return 0;
    }
    if s1 == s2 {
        return 100;
    }

    let max_len = s1.len().max(s2.len());

    // Heuristic: require at least a common substring trigger proportional to length
    let lcs = longest_common_substring(s1, s2);
    let min_lcs = if max_len < 8 { 2 } else { 3 };
    if lcs < min_lcs {
        return 0;
    }

    let dist = levenshtein_distance(s1, s2);

    if dist >= max_len {
        0
    } else {
        let raw_score = 100.0 * (1.0 - (dist as f64 / max_len as f64));
        raw_score.clamp(0.0, 100.0).round() as u32
    }
}

/// Compares two fuzzy digests, verifying block size compatibility and returning similarity (0..=100).
pub fn compare_digests(h1: &FuzzyDigest, h2: &FuzzyDigest) -> u32 {
    if h1.block_size == h2.block_size {
        let s1 = score_strings(&h1.hash1, &h2.hash1);
        let s2 = score_strings(&h1.hash2, &h2.hash2);
        s1.max(s2)
    } else if h1.block_size.saturating_mul(2) == h2.block_size {
        score_strings(&h1.hash2, &h2.hash1)
    } else if h2.block_size.saturating_mul(2) == h1.block_size {
        score_strings(&h1.hash1, &h2.hash2)
    } else {
        0
    }
}

/// Formats a 0..100 similarity score into a human-readable status string.
pub fn score_to_status(score: u32) -> &'static str {
    match score {
        100 => "Identical",
        80..=99 => "High Match",
        50..=79 => "Moderate Match",
        20..=49 => "Low Match",
        1..=19 => "Divergent",
        0 => "No Commonality",
        _ => "Unknown",
    }
}

/// Compares section lists across two binaries, matching sections by name.
pub fn compare_sections(
    sec1: &[SectionFuzzyHash],
    sec2: &[SectionFuzzyHash],
) -> Vec<SectionComparison> {
    let mut comparisons = Vec::new();
    let mut matched_sec2 = vec![false; sec2.len()];

    for s1 in sec1 {
        let mut found = false;
        for (idx, s2) in sec2.iter().enumerate() {
            if s1.name == s2.name {
                let score = compare_digests(&s1.fuzzy_hash, &s2.fuzzy_hash);
                let status = format!("{} ({}%)", score_to_status(score), score);
                comparisons.push(SectionComparison {
                    name: s1.name.clone(),
                    score,
                    status,
                    hash1: s1.fuzzy_hash.to_digest_string(),
                    hash2: s2.fuzzy_hash.to_digest_string(),
                });
                matched_sec2[idx] = true;
                found = true;
                break;
            }
        }

        if !found {
            comparisons.push(SectionComparison {
                name: s1.name.clone(),
                score: 0,
                status: "Missing in Target (0%)".to_string(),
                hash1: s1.fuzzy_hash.to_digest_string(),
                hash2: String::from("-"),
            });
        }
    }

    for (idx, s2) in sec2.iter().enumerate() {
        if !matched_sec2[idx] {
            comparisons.push(SectionComparison {
                name: s2.name.clone(),
                score: 0,
                status: "Missing in Source (0%)".to_string(),
                hash1: String::from("-"),
                hash2: s2.fuzzy_hash.to_digest_string(),
            });
        }
    }

    comparisons
}
