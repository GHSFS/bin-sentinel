// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{Result, SentinelError};

/// Detected binary file format for structural diffing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    Pe,
    Elf,
    Macho,
    Unknown,
}

impl fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pe => write!(f, "PE (Windows Portable Executable)"),
            Self::Elf => write!(f, "ELF (Executable and Linkable Format)"),
            Self::Macho => write!(f, "Mach-O (Apple Mach Object)"),
            Self::Unknown => write!(f, "Raw / Unknown"),
        }
    }
}

/// Change in a security mitigation between original and modified binaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitigationChange {
    pub mitigation: String,
    pub before: String,
    pub after: String,
}

/// Mitigation posture diff across PE/ELF/Mach-O binaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitigationsDiff {
    pub original_format: BinaryFormat,
    pub modified_format: BinaryFormat,
    pub changes: Vec<MitigationChange>,
}

/// Per-section statistical entropy delta and hunk count.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SectionDiff {
    pub name: String,
    pub orig_entropy: Option<f64>,
    pub mod_entropy: Option<f64>,
    pub entropy_delta: Option<f64>,
    pub differing_bytes: usize,
    pub hunk_count: usize,
}

/// A contiguous slice of differing bytes between two binaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffHunk {
    pub offset: usize,
    pub length: usize,
    pub orig_bytes_hex: String,
    pub mod_bytes_hex: String,
    pub section_name: Option<String>,
    pub rva: Option<u64>,
}

/// Complete structural binary diff report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiffReport {
    pub original_path: String,
    pub modified_path: String,
    pub original_size: usize,
    pub modified_size: usize,
    pub original_sha256: String,
    pub modified_sha256: String,
    pub format: BinaryFormat,
    pub total_differing_bytes: usize,
    pub hunk_count: usize,
    pub hunks: Vec<DiffHunk>,
    pub section_diffs: Vec<SectionDiff>,
    pub mitigations_diff: Option<MitigationsDiff>,
}

/// A single declarative patch operation inside a recipe manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchOperation {
    pub offset: usize,
    pub length: usize,
    pub expected_hex: String,
    pub replace_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rva: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Declarative multi-offset binary patch recipe manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchRecipe {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub target_format: BinaryFormat,
    pub source_sha256: String,
    pub target_sha256: String,
    pub operations: Vec<PatchOperation>,
}

impl PatchRecipe {
    /// Serializes the recipe manifest to formatted JSON.
    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| SentinelError::InvalidArgument(format!("JSON serialization error: {e}")))
    }

    /// Deserializes a recipe manifest from JSON string.
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s)
            .map_err(|e| SentinelError::InvalidArgument(format!("JSON deserialization error: {e}")))
    }

    /// Creates an inverse recipe swapping expected and replacement bytes and SHA-256 hashes.
    pub fn reverse(&self) -> Self {
        let reversed_ops: Vec<PatchOperation> = self
            .operations
            .iter()
            .map(|op| PatchOperation {
                offset: op.offset,
                length: op.length,
                expected_hex: op.replace_hex.clone(),
                replace_hex: op.expected_hex.clone(),
                section_name: op.section_name.clone(),
                rva: op.rva,
                comment: op.comment.as_ref().map(|c| format!("Reversed: {c}")),
            })
            .collect();

        Self {
            name: format!("{}-reversed", self.name),
            description: self
                .description
                .as_ref()
                .map(|d| format!("Reversal manifest: {d}")),
            target_format: self.target_format,
            source_sha256: self.target_sha256.clone(),
            target_sha256: self.source_sha256.clone(),
            operations: reversed_ops,
        }
    }
}

/// Summary report of an applied, dry-run, or reverted patch recipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyReport {
    pub target_path: String,
    pub recipe_name: String,
    pub operations_count: usize,
    pub sha256_before: String,
    pub sha256_after: String,
    pub is_dry_run: bool,
    pub backup_path: Option<String>,
    pub reversed: bool,
}
