// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Encoding scheme of an extracted payload candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CarveEncodingKind {
    /// RFC 4648 Standard Base64 (`[A-Za-z0-9+/]`).
    StandardBase64,
    /// RFC 4648 URL-safe Base64 (`[A-Za-z0-9-_]`).
    UrlSafeBase64,
    /// Contiguous hex string sequence (`4D5A90...`).
    ContiguousHex,
    /// Formatted hex sequence (`\x4d\x5a...`, `0x4d, 0x5a...`, or space-separated pairs).
    FormattedHex,
}

impl fmt::Display for CarveEncodingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StandardBase64 => write!(f, "Base64 (Standard)"),
            Self::UrlSafeBase64 => write!(f, "Base64 (URL-Safe)"),
            Self::ContiguousHex => write!(f, "Contiguous Hex"),
            Self::FormattedHex => write!(f, "Formatted Hex"),
        }
    }
}

/// Heuristic classification of a decoded binary or script payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DecodedPayloadKind {
    /// Embedded PE32/PE32+ executable or DLL.
    NestedPe { is_64bit: bool, is_dll: bool },
    /// Embedded Linux ELF executable or shared library.
    NestedElf { is_64bit: bool },
    /// Embedded Apple Mach-O binary.
    NestedMacho { is_64bit: bool, is_fat: bool },
    /// Embedded ZIP / APK / Office document container.
    ArchiveZip,
    /// Embedded GZIP compressed stream.
    ArchiveGzip,
    /// Embedded 7z archive.
    Archive7z,
    /// Embedded PDF document.
    DocumentPdf,
    /// PowerShell script or command cradle.
    ScriptPowerShell { triggers: Vec<String> },
    /// Unix Shell script or command execution.
    ScriptShell { triggers: Vec<String> },
    /// Windows Command / Batch script.
    ScriptBatch { triggers: Vec<String> },
    /// Network IoC indicators (URLs and IPv4 addresses).
    IocNetwork { urls: Vec<String>, ips: Vec<String> },
    /// High-entropy binary blob with possible shellcode or encryption.
    HighEntropyShellcode {
        entropy: f64,
        possible_prologue: bool,
    },
    /// Printable text, JSON, or configuration data.
    TextOrData { is_utf8: bool },
    /// Unknown raw binary data.
    UnknownBinary,
}

impl fmt::Display for DecodedPayloadKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NestedPe { is_64bit, is_dll } => {
                let arch = if *is_64bit { "64-bit" } else { "32-bit" };
                let kind = if *is_dll { "DLL" } else { "EXE" };
                write!(f, "Nested PE ({arch} {kind})")
            }
            Self::NestedElf { is_64bit } => {
                let arch = if *is_64bit { "64-bit" } else { "32-bit" };
                write!(f, "Nested ELF ({arch})")
            }
            Self::NestedMacho { is_64bit, is_fat } => {
                if *is_fat {
                    write!(f, "Nested Mach-O (Universal Fat)")
                } else {
                    let arch = if *is_64bit { "64-bit" } else { "32-bit" };
                    write!(f, "Nested Mach-O ({arch})")
                }
            }
            Self::ArchiveZip => write!(f, "ZIP Archive / Container"),
            Self::ArchiveGzip => write!(f, "GZIP Stream"),
            Self::Archive7z => write!(f, "7z Archive"),
            Self::DocumentPdf => write!(f, "PDF Document"),
            Self::ScriptPowerShell { triggers } => {
                write!(f, "PowerShell Script ({} triggers)", triggers.len())
            }
            Self::ScriptShell { triggers } => {
                write!(f, "Unix Shell Script ({} triggers)", triggers.len())
            }
            Self::ScriptBatch { triggers } => {
                write!(f, "Batch Script ({} triggers)", triggers.len())
            }
            Self::IocNetwork { urls, ips } => {
                write!(f, "Network IoCs ({} URLs, {} IPs)", urls.len(), ips.len())
            }
            Self::HighEntropyShellcode {
                entropy,
                possible_prologue,
            } => {
                let pro = if *possible_prologue {
                    " [Prologue Detected]"
                } else {
                    ""
                };
                write!(f, "High-Entropy Shellcode (entropy: {entropy:.2}{pro})")
            }
            Self::TextOrData { is_utf8 } => {
                let enc = if *is_utf8 { "UTF-8" } else { "ASCII/Data" };
                write!(f, "Text / Configuration ({enc})")
            }
            Self::UnknownBinary => write!(f, "Unknown Binary"),
        }
    }
}

/// Metadata and forensic attributes of a carved and decoded payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedPayload {
    /// 1-based index identifier.
    pub id: usize,
    /// Encoding scheme detected and decoded.
    pub encoding: CarveEncodingKind,
    /// Raw byte offset in the parent file where the encoded blob begins.
    pub file_offset: usize,
    /// Length of the encoded candidate string in the parent file.
    pub encoded_length: usize,
    /// Length of the decoded byte payload.
    pub decoded_length: usize,
    /// Executable section name containing this payload (e.g. `.rdata`, `.text`).
    pub section_name: Option<String>,
    /// Relative Virtual Address (RVA) if parent is PE/ELF/Mach-O.
    pub rva: Option<u64>,
    /// Whether the containing section has Read-Write-Execute permissions.
    pub is_rwx_section: bool,
    /// Shannon entropy of the decoded payload (0.00 .. 8.00).
    pub entropy: f64,
    /// SHA-256 hex digest of the decoded payload.
    pub sha256: String,
    /// Heuristic payload classification.
    pub payload_kind: DecodedPayloadKind,
    /// Confidence score of classification (0 .. 100).
    pub confidence_score: u8,
    /// High-level forensic summary.
    pub summary: String,
    /// Hexadecimal preview of the first 16 bytes.
    pub preview_hex: String,
    /// Printable text preview of the initial bytes.
    pub preview_text: String,
    /// Decoded raw bytes (excluded from default JSON for efficiency).
    #[serde(skip)]
    pub decoded_bytes: Vec<u8>,
}

/// Configuration options for the payload carving engine.
#[derive(Debug, Clone)]
pub struct CarveOptions {
    /// Minimum length of encoded string to carve (default: 16).
    pub min_length: usize,
    /// Maximum number of carved payloads to return (default: 500).
    pub max_payloads: usize,
    /// Optional directory to safely write decoded payload files.
    pub extract_dir: Option<PathBuf>,
    /// Enable Base64 candidate scanning.
    pub scan_base64: bool,
    /// Enable Hex candidate scanning.
    pub scan_hex: bool,
}

impl Default for CarveOptions {
    fn default() -> Self {
        Self {
            min_length: 16,
            max_payloads: 500,
            extract_dir: None,
            scan_base64: true,
            scan_hex: true,
        }
    }
}

/// Consolidated forensic report produced by the payload carving engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarveReport {
    /// Target file path analyzed.
    pub file_path: String,
    /// Target file size in bytes.
    pub file_size: usize,
    /// Total number of payloads carved and decoded.
    pub total_carved: usize,
    /// List of carved payload details.
    pub payloads: Vec<CarvedPayload>,
    /// Count of nested executable containers (PE, ELF, Mach-O).
    pub nested_executables_count: usize,
    /// Count of embedded scripts (PowerShell, Shell, Batch).
    pub scripts_count: usize,
    /// Count of payloads containing network IoCs.
    pub iocs_count: usize,
    /// Count of payloads residing in anomalous RWX sections.
    pub rwx_anomalies_count: usize,
}
