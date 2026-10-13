// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Static x86_64 instruction and control-flow pattern definitions and matching rules.

use super::rules_control::match_control_pattern_at;
use super::rules_frame::match_frame_pattern_at;
use super::types::CodePatternMatch;

/// Formats a byte slice as uppercase space-separated hex pairs (e.g. "55 48 89 E5").
#[inline]
pub fn format_bytes_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Evaluates candidate instruction patterns at the given byte offset.
///
/// Priority 1: Direct system calls, anti-debugging, VM checks, software traps, and indirect branches.
/// Priority 2: Function prologues, stack frame allocations, and epilogues.
pub fn match_pattern_at(data: &[u8], offset: usize) -> Option<CodePatternMatch> {
    if let Some(m) = match_control_pattern_at(data, offset) {
        return Some(m);
    }
    match_frame_pattern_at(data, offset)
}
