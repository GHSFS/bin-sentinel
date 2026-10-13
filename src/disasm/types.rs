// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Types and reporting data structures for x86_64 instruction and control-flow scanning.

use serde::{Deserialize, Serialize};

/// Classification of detected x86/x86_64 code patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodePatternKind {
    /// Function prologue or stack frame setup.
    Prologue,
    /// Function epilogue or exit sequence.
    Epilogue,
    /// Direct kernel syscall stub (e.g. EDR bypass indicator).
    DirectSyscall,
    /// Anti-debugging / timing measurement instructions (RDTSC, RDTSCP).
    AntiDebugTiming,
    /// Virtual machine / hypervisor fingerprinting instructions (CPUID, SMSW).
    VmHypervisorCheck,
    /// Software breakpoint traps and invalid opcodes (INT 3, UD2, INT 1).
    SoftwareTrap,
    /// Indirect branch or dispatch (register jumps/calls, stack pivots).
    IndirectBranch,
}

impl std::fmt::Display for CodePatternKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Prologue => write!(f, "Prologue"),
            Self::Epilogue => write!(f, "Epilogue"),
            Self::DirectSyscall => write!(f, "DirectSyscall"),
            Self::AntiDebugTiming => write!(f, "AntiDebugTiming"),
            Self::VmHypervisorCheck => write!(f, "VmCheck"),
            Self::SoftwareTrap => write!(f, "Trap"),
            Self::IndirectBranch => write!(f, "IndirectBranch"),
        }
    }
}

/// A detected x86/x86_64 instruction pattern in the binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodePatternMatch {
    /// Unique identifier for the matched pattern rule.
    pub pattern_id: String,
    /// Pattern category.
    pub category: CodePatternKind,
    /// Disassembled mnemonic or summary description.
    pub mnemonic: String,
    /// Raw byte offset in the target file.
    pub offset: usize,
    /// Length in bytes of the matched instruction sequence.
    pub length: usize,
    /// Hex-encoded instruction bytes (e.g. "55 48 89 E5").
    pub bytes_hex: String,
    /// Associated executable or data section name (if PE/ELF).
    pub section_name: Option<String>,
    /// Relative Virtual Address (RVA) or Virtual Address if inside a mapped section.
    pub relative_virtual_address: Option<u64>,
    /// Human-readable explanation of the pattern.
    pub description: String,
    /// Security or heuristic alert if the pattern indicates suspicious behavior.
    pub risk_alert: Option<String>,
}

/// Consolidated count and metric breakdown of detected code patterns.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CodeScanSummary {
    /// Total instruction patterns detected.
    pub total_patterns: usize,
    /// Total function prologue patterns detected.
    pub prologues: usize,
    /// Total function epilogue patterns detected.
    pub epilogues: usize,
    /// Total direct system call stubs detected.
    pub syscall_stubs: usize,
    /// Total anti-debugging timing instructions (RDTSC/RDTSCP).
    pub anti_debug_timing: usize,
    /// Total hypervisor / VM detection instructions (CPUID, SMSW).
    pub vm_checks: usize,
    /// Total software breakpoint traps and invalid opcodes (INT 3, UD2).
    pub traps: usize,
    /// Total indirect branches (JMP/CALL via register or displacement).
    pub indirect_branches: usize,
    /// Count of patterns triggering a security or evasion risk alert.
    pub suspicious_alerts_count: usize,
}

/// Comprehensive x86_64 code pattern scan report for a target binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeScanReport {
    /// File path of the inspected binary.
    pub file_path: String,
    /// File size in bytes.
    pub file_size: usize,
    /// Identified binary container format ("PE", "ELF", or "Raw Binary").
    pub binary_format: String,
    /// List of executable section names identified in the binary.
    pub executable_sections: Vec<String>,
    /// Summary counts and metric breakdown.
    pub summary: CodeScanSummary,
    /// Detailed list of all detected code patterns.
    pub matches: Vec<CodePatternMatch>,
}
