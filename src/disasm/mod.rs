// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! x86_64 Instruction Prologue/Epilogue and Control-Flow Disassembly Scanner.
//!
//! Provides zero-dependency detection of x86/x86_64 function prologues, epilogues,
//! direct kernel system call stubs (SysWhispers / EDR bypasses), RDTSC timing checks,
//! CPUID VM fingerprinting, breakpoint traps (INT 3, UD2), and indirect branches.

pub mod patterns;
pub mod rules_control;
pub mod rules_frame;
pub mod scanner;
pub mod types;

pub use patterns::{format_bytes_hex, match_pattern_at};
pub use rules_control::match_control_pattern_at;
pub use rules_frame::match_frame_pattern_at;
pub use scanner::{scan_code_bytes, scan_code_file};
pub use types::{CodePatternKind, CodePatternMatch, CodeScanReport, CodeScanSummary};
