// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Data types and report structures for binary deobfuscation analysis.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Deobfuscation encoding/transformation method applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeobfuscateMethod {
    /// Single-byte XOR cipher with 8-bit key.
    XorSingle { key: u8 },
    /// Multi-byte repeating XOR cipher with variable-length key.
    XorMulti { key: Vec<u8> },
    /// Single-byte additive cipher (byte addition with 8-bit key).
    AddSingle { key: u8 },
    /// Multi-byte repeating additive cipher.
    AddMulti { key: Vec<u8> },
    /// Bitwise rotate-left cipher with 1..=7 bit shift.
    RolSingle { shift: u8 },
}

impl fmt::Display for DeobfuscateMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XorSingle { key } => write!(f, "XOR (0x{key:02X})"),
            Self::XorMulti { key } => {
                write!(f, "XOR ({})", hex::encode(key).to_ascii_uppercase())
            }
            Self::AddSingle { key } => write!(f, "ADD (0x{key:02X})"),
            Self::AddMulti { key } => {
                write!(f, "ADD ({})", hex::encode(key).to_ascii_uppercase())
            }
            Self::RolSingle { shift } => write!(f, "ROL ({shift})"),
        }
    }
}

/// Classification of a decoded payload or recognized Indicator of Compromise (IoC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactKind {
    /// Network URL scheme (e.g. `http://`, `https://`, `ftp://`).
    Url,
    /// Dotted-decimal IPv4 address.
    IPv4,
    /// Windows Registry hive key path (e.g. `HKLM\`, `HKCU\`).
    RegistryKey,
    /// Windows Portable Executable (PE) DOS/PE header magic.
    PeHeader,
    /// Linux/BSD Executable and Linkable Format (ELF) header magic.
    ElfHeader,
    /// Apple macOS/iOS Mach-O header magic.
    MachOHeader,
    /// Contiguous printable ASCII string sequence.
    GenericString,
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Url => write!(f, "URL"),
            Self::IPv4 => write!(f, "IPv4"),
            Self::RegistryKey => write!(f, "RegistryKey"),
            Self::PeHeader => write!(f, "PE Header"),
            Self::ElfHeader => write!(f, "ELF Header"),
            Self::MachOHeader => write!(f, "Mach-O Header"),
            Self::GenericString => write!(f, "GenericString"),
        }
    }
}

/// A decoded artifact uncovered through brute-force or crib-drag deobfuscation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecodedArtifact {
    /// Raw byte offset within the original binary file.
    pub offset: usize,
    /// Length in bytes of the matched artifact.
    pub length: usize,
    /// Transformation method and key used to recover this artifact.
    pub method: DeobfuscateMethod,
    /// Semantic classification of the decoded payload.
    pub kind: ArtifactKind,
    /// Human-readable decoded string content or header description.
    pub content: String,
    /// Confidence score rating (0.0 to 1.0).
    pub confidence: f32,
    /// Containing section name if inside a valid PE or ELF binary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section_name: Option<String>,
    /// Relative Virtual Address (RVA) if mapped inside an executable section.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relative_virtual_address: Option<u64>,
}

/// Consolidated forensics report containing all discovered deobfuscated artifacts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeobfuscateReport {
    /// Target binary file path if inspected from filesystem.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    /// Total file or buffer size in bytes.
    pub file_size: usize,
    /// Detected binary container format (e.g. PE, ELF, Mach-O, Raw Binary).
    pub binary_format: String,
    /// Total count of unique decoded artifacts discovered.
    pub total_matches: usize,
    /// Detailed list of all decoded artifacts sorted by confidence descending.
    pub artifacts: Vec<DecodedArtifact>,
    /// Deobfuscation strategies and scanners applied during the inspection.
    pub scan_methods_applied: Vec<String>,
}
