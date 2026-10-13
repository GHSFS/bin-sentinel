// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::{Deserialize, Serialize};

/// Classification of tools recorded in the PE Rich header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RichToolKind {
    /// C compiler (e.g. `cl.exe` compiling C source units).
    CCompiler,
    /// C++ compiler (e.g. `cl.exe` compiling C++ translation units).
    CppCompiler,
    /// Linker (e.g. `link.exe` linking object modules).
    Linker,
    /// Resource compiler/converter (e.g. `cvtres.exe` or `rc.exe`).
    ResourceCompiler,
    /// Macro Assembler (e.g. `ml.exe` or `ml64.exe`).
    Assembler,
    /// Import/Export table and import library generator.
    ImportExport,
    /// Other auxiliary MSVC tool or unknown toolchain component.
    Other,
}

impl std::fmt::Display for RichToolKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CCompiler => write!(f, "C Compiler"),
            Self::CppCompiler => write!(f, "C++ Compiler"),
            Self::Linker => write!(f, "Linker"),
            Self::ResourceCompiler => write!(f, "Resource Compiler"),
            Self::Assembler => write!(f, "Assembler"),
            Self::ImportExport => write!(f, "Import/Export"),
            Self::Other => write!(f, "Other"),
        }
    }
}

/// A single decrypted compilation or tool record (`@comp.id`) from the Rich header.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RichRecord {
    /// Raw combined 32-bit compilation identifier (`(prod_id << 16) | build_number`).
    pub raw_comp_id: u32,
    /// 16-bit Product Identifier indicating the specific compiler/tool type.
    pub product_id: u16,
    /// 16-bit toolchain internal build number.
    pub build_number: u16,
    /// Number of times this tool component was invoked or referenced.
    pub count: u32,
    /// Human-readable tool or component name resolved from known toolchain dictionaries.
    pub tool_name: String,
    /// Categorized functional tool kind.
    pub tool_kind: RichToolKind,
    /// Visual Studio product/toolset version associated with this build.
    pub vs_version: String,
}

/// Verification status of the Rich header checksum against the stored XOR key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RichChecksum {
    /// 32-bit XOR key stored immediately after the `"Rich"` marker.
    pub stored_xor_key: u32,
    /// 32-bit checksum computed from DOS header, DOS stub, and decrypted records.
    pub calculated_key: u32,
    /// Whether the calculated checksum matches the stored XOR key.
    pub is_valid: bool,
}

/// Cryptographic hashes computed across the decrypted Rich header clear data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RichHashes {
    /// 128-bit RFC 1321 MD5 hash of clear records (standard VirusTotal `rich_pe_header_hash`).
    pub md5: String,
    /// SHA-256 hash of clear records for high-assurance telemetry.
    pub sha256: String,
}

/// Complete forensic inspection report of a PE Rich header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichReport {
    /// Source binary file path or label.
    pub file_path: String,
    /// File offset where the decrypted `"DanS"` marker begins.
    pub dans_offset: usize,
    /// File offset where the `"Rich"` marker begins.
    pub rich_offset: usize,
    /// Total size in bytes of the Rich header block including markers and XOR key.
    pub header_size: usize,
    /// 32-bit XOR decryption key.
    pub xor_key: u32,
    /// Number of valid decoded `@comp.id` records.
    pub record_count: usize,
    /// Decoded records in the order they appear in the binary.
    pub records: Vec<RichRecord>,
    /// Checksum verification status.
    pub checksum: RichChecksum,
    /// Clear data cryptographic digests.
    pub hashes: RichHashes,
    /// Primary Visual Studio toolset identified across records.
    pub primary_toolchain: String,
    /// Detected anomalies (e.g. checksum mismatch, forged markers, invalid padding).
    pub anomalies: Vec<String>,
}
