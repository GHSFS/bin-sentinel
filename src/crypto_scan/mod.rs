// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Cryptographic primitive, S-Box, and constant scanner.
//!
//! Scans arbitrary binary files and memory buffers for precomputed cryptographic
//! tables, initial state vectors, round constants, and magic strings, with automated
//! PE and ELF section and RVA resolution.

pub mod constants;

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::elf::parse_elf;
use crate::error::Result;
use crate::pe::parse_pe;

pub use constants::*;

/// Cryptographic primitive category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoPrimitiveKind {
    /// Substitution box (e.g. AES, SM4).
    SBox,
    /// Key expansion or encryption round constants (e.g. AES Rcon, SHA-256 K).
    RoundConstants,
    /// Hash state initialization vectors (e.g. SHA-256 H0, MD5 IV).
    StateInitialization,
    /// Known cryptographic magic string (e.g. ChaCha20 sigma).
    MagicString,
    /// Golden-ratio or arithmetic delta constant (e.g. TEA 0x9E3779B9).
    DeltaConstant,
    /// Precomputed lookup table (e.g. CRC-32 IEEE 802.3).
    LookupTable,
}

impl std::fmt::Display for CryptoPrimitiveKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SBox => write!(f, "S-Box"),
            Self::RoundConstants => write!(f, "RoundConstants"),
            Self::StateInitialization => write!(f, "StateInit"),
            Self::MagicString => write!(f, "MagicString"),
            Self::DeltaConstant => write!(f, "DeltaConstant"),
            Self::LookupTable => write!(f, "LookupTable"),
        }
    }
}

/// Confidence rating for cryptographic signature detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    /// High confidence: lengthy or distinct cryptographic table (>16 bytes).
    High,
    /// Medium confidence: shorter constant or arithmetic delta.
    Medium,
}

impl std::fmt::Display for ConfidenceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
        }
    }
}

/// Internal definition for a static cryptographic pattern.
#[derive(Debug, Clone)]
pub struct CryptoSignature {
    pub name: &'static str,
    pub algorithm: &'static str,
    pub kind: CryptoPrimitiveKind,
    pub description: &'static str,
    pub pattern: &'static [u8],
    pub confidence: ConfidenceLevel,
}

/// A detected cryptographic constant in binary data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoMatch {
    /// Associated cryptographic algorithm (e.g. "AES-128/192/256", "ChaCha20").
    pub algorithm: String,
    /// Specific primitive identifier (e.g. "AES Forward S-Box").
    pub name: String,
    /// Primitive kind (SBox, StateInitialization, etc.).
    pub kind: CryptoPrimitiveKind,
    /// Human-readable explanation of the primitive.
    pub description: String,
    /// Raw byte offset in the target binary.
    pub offset: usize,
    /// Length in bytes of the matched signature.
    pub length: usize,
    /// Confidence assessment.
    pub confidence: ConfidenceLevel,
    /// Containing section name if inside a valid PE or ELF binary.
    pub section_name: Option<String>,
    /// Relative Virtual Address (RVA) or Virtual Address if inside a mapped section.
    pub relative_virtual_address: Option<u64>,
}

/// Consolidated cryptographic scan report for a target file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoScanReport {
    /// Path of the inspected binary.
    pub file_path: String,
    /// File size in bytes.
    pub file_size: usize,
    /// Classified executable binary format ("PE", "ELF", or "Raw Binary").
    pub binary_format: String,
    /// Total number of detected cryptographic constants.
    pub total_matches: usize,
    /// Total occurrences of the TEA/XTEA golden ratio delta (0x9E3779B9).
    pub tea_delta_occurrences: usize,
    /// List of unique cryptographic algorithms detected.
    pub detected_algorithms: Vec<String>,
    /// Detailed list of all detected cryptographic matches.
    pub matches: Vec<CryptoMatch>,
}

/// Fast search for all byte offsets of a needle within a haystack.
fn find_all_occurrences(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    let mut offsets = Vec::new();
    let max_idx = haystack.len() - needle.len();
    let first = needle[0];
    let mut i = 0;
    while i <= max_idx {
        if haystack[i] == first && &haystack[i..i + needle.len()] == needle {
            offsets.push(i);
            i += needle.len();
        } else {
            i += 1;
        }
    }
    offsets
}

/// Scan a raw byte buffer for all registered cryptographic tables and constants.
pub fn scan_crypto_bytes(data: &[u8]) -> (Vec<CryptoMatch>, usize) {
    let mut matches = Vec::new();

    // 1. Scan registered multi-byte tables and initial states
    for sig in CRYPTO_SIGNATURES {
        let occurrences = find_all_occurrences(data, sig.pattern);
        for off in occurrences {
            matches.push(CryptoMatch {
                algorithm: sig.algorithm.to_string(),
                name: sig.name.to_string(),
                kind: sig.kind,
                description: sig.description.to_string(),
                offset: off,
                length: sig.pattern.len(),
                confidence: sig.confidence,
                section_name: None,
                relative_virtual_address: None,
            });
        }
    }

    // 2. Scan TEA / XTEA golden ratio delta constant (0x9E3779B9)
    let tea_le_offsets = find_all_occurrences(data, &TEA_DELTA_LE);
    let tea_be_offsets = find_all_occurrences(data, &TEA_DELTA_BE);
    let total_tea_occurrences = tea_le_offsets.len() + tea_be_offsets.len();

    for off in tea_le_offsets {
        matches.push(CryptoMatch {
            algorithm: "TEA / XTEA".to_string(),
            name: "TEA Delta Constant (LE)".to_string(),
            kind: CryptoPrimitiveKind::DeltaConstant,
            description:
                "TEA/XTEA 0x9E3779B9 golden ratio key scheduling delta constant (Little-Endian)"
                    .to_string(),
            offset: off,
            length: 4,
            confidence: ConfidenceLevel::Medium,
            section_name: None,
            relative_virtual_address: None,
        });
    }

    for off in tea_be_offsets {
        matches.push(CryptoMatch {
            algorithm: "TEA / XTEA".to_string(),
            name: "TEA Delta Constant (BE)".to_string(),
            kind: CryptoPrimitiveKind::DeltaConstant,
            description:
                "TEA/XTEA 0x9E3779B9 golden ratio key scheduling delta constant (Big-Endian)"
                    .to_string(),
            offset: off,
            length: 4,
            confidence: ConfidenceLevel::Medium,
            section_name: None,
            relative_virtual_address: None,
        });
    }

    // Sort matches strictly by file offset
    matches.sort_by_key(|m| m.offset);

    (matches, total_tea_occurrences)
}

/// Scan a file on disk for cryptographic constants and correlate with executable sections.
pub fn scan_crypto_file(path: &Path) -> Result<CryptoScanReport> {
    let data = fs::read(path)?;
    let (mut matches, tea_delta_count) = scan_crypto_bytes(&data);

    let mut binary_format = "Raw Binary".to_string();

    // Correlate with PE sections if the target is a valid PE binary
    if let Ok(pe_info) = parse_pe(&data) {
        binary_format = format!("PE ({})", pe_info.format);
        for m in &mut matches {
            for sec in &pe_info.sections {
                let start = sec.raw_offset as usize;
                let end = start.saturating_add(sec.raw_size as usize);
                if m.offset >= start && m.offset < end {
                    m.section_name = Some(sec.name.clone());
                    let delta = (m.offset - start) as u64;
                    m.relative_virtual_address = Some(sec.virtual_address as u64 + delta);
                    break;
                }
            }
        }
    } else if let Ok(elf_info) = parse_elf(&data) {
        // Correlate with ELF sections if the target is a valid ELF binary
        binary_format = format!("ELF ({})", elf_info.os_abi);
        for m in &mut matches {
            for sec in &elf_info.sections {
                let start = sec.offset as usize;
                let end = start.saturating_add(sec.size as usize);
                if m.offset >= start && m.offset < end {
                    m.section_name = Some(sec.name.clone());
                    let delta = (m.offset - start) as u64;
                    m.relative_virtual_address = Some(sec.addr + delta);
                    break;
                }
            }
        }
    }

    let mut algo_set = BTreeSet::new();
    for m in &matches {
        algo_set.insert(m.algorithm.clone());
    }
    let detected_algorithms: Vec<String> = algo_set.into_iter().collect();

    Ok(CryptoScanReport {
        file_path: path.display().to_string(),
        file_size: data.len(),
        binary_format,
        total_matches: matches.len(),
        tea_delta_occurrences: tea_delta_count,
        detected_algorithms,
        matches,
    })
}
