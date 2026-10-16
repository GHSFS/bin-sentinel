// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::{Deserialize, Serialize};

/// Recognized executable binary container format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BinaryFormat {
    Pe,
    Elf,
    MachO,
    Raw,
}

impl std::fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryFormat::Pe => write!(f, "PE"),
            BinaryFormat::Elf => write!(f, "ELF"),
            BinaryFormat::MachO => write!(f, "Mach-O"),
            BinaryFormat::Raw => write!(f, "Raw"),
        }
    }
}

/// Structured Context Triggered Piecewise Hash (CTPH / SSDEEP-style digest).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzyDigest {
    /// Rolling hash trigger block size.
    pub block_size: u64,
    /// Primary block hash string (length <= 64).
    pub hash1: String,
    /// Secondary double-block hash string (length <= 64).
    pub hash2: String,
}

impl FuzzyDigest {
    /// Creates a new `FuzzyDigest`.
    pub fn new(block_size: u64, hash1: String, hash2: String) -> Self {
        Self {
            block_size,
            hash1,
            hash2,
        }
    }

    /// Formats the digest into standard `block_size:hash1:hash2` string representation.
    pub fn to_digest_string(&self) -> String {
        format!("{}:{}:{}", self.block_size, self.hash1, self.hash2)
    }

    /// Parses a standard `block_size:hash1:hash2` string into a `FuzzyDigest`.
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 3 {
            let block_size = parts[0].parse::<u64>().ok()?;
            Some(Self {
                block_size,
                hash1: parts[1].to_string(),
                hash2: parts[2].to_string(),
            })
        } else {
            None
        }
    }
}

impl std::fmt::Display for FuzzyDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.block_size, self.hash1, self.hash2)
    }
}

/// Section-level fuzzy hash and metadata for executable formats.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SectionFuzzyHash {
    /// Section name (e.g. `.text`, `.rdata`, `__TEXT`).
    pub name: String,
    /// Relative or virtual address.
    pub virtual_address: u64,
    /// Raw size in bytes on disk.
    pub raw_size: u64,
    /// Shannon entropy of the section bytes (0.0 to 8.0).
    pub entropy: f64,
    /// Piecewise fuzzy hash of the section.
    pub fuzzy_hash: FuzzyDigest,
}

/// Comprehensive report for single-file fuzzy hashing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FuzzyHashReport {
    /// Target file path.
    pub file_path: String,
    /// File size in bytes.
    pub file_size: u64,
    /// Detected binary format.
    pub format: BinaryFormat,
    /// Full-file fuzzy hash digest.
    pub fuzzy_hash: FuzzyDigest,
    /// Per-section fuzzy hashes (empty for raw non-executable files).
    pub sections: Vec<SectionFuzzyHash>,
}

/// Detailed comparison between two sections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionComparison {
    /// Section name.
    pub name: String,
    /// Similarity score (0 to 100).
    pub score: u32,
    /// Human-readable match classification.
    pub status: String,
    /// Fuzzy hash string for File 1.
    pub hash1: String,
    /// Fuzzy hash string for File 2.
    pub hash2: String,
}

/// Comprehensive report comparing two binary files.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FuzzyCompareReport {
    /// Path to first file.
    pub file1_path: String,
    /// Size of first file in bytes.
    pub file1_size: u64,
    /// Format of first file.
    pub file1_format: BinaryFormat,
    /// Fuzzy hash of first file.
    pub file1_hash: FuzzyDigest,
    /// Path to second file.
    pub file2_path: String,
    /// Size of second file in bytes.
    pub file2_size: u64,
    /// Format of second file.
    pub file2_format: BinaryFormat,
    /// Fuzzy hash of second file.
    pub file2_hash: FuzzyDigest,
    /// Overall file similarity score (0 to 100).
    pub overall_score: u32,
    /// Human-readable match classification.
    pub overall_status: String,
    /// Correlated section similarity comparisons.
    pub section_comparisons: Vec<SectionComparison>,
}
