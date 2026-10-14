// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Single resource item located in the 3-level PE resource directory tree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceEntry {
    /// Standard integer resource type ID (e.g. 24 for `RT_MANIFEST`, 16 for `RT_VERSION`).
    pub type_id: Option<u32>,
    /// Resolved resource type name (e.g. "RT_MANIFEST", "RT_VERSION", "RT_ICON", "CUSTOM_NAME").
    pub type_name: String,
    /// Resource instance integer ID if numeric.
    pub name_id: Option<u32>,
    /// Resource instance string identifier if named.
    pub name_str: Option<String>,
    /// Language code (e.g. 0x0409 for en-US, 0x0412 for ko-KR, 0 for neutral).
    pub language_id: u32,
    /// Human-readable language descriptor.
    pub language_name: String,
    /// Relative Virtual Address (RVA) of the resource payload.
    pub rva: u32,
    /// Raw file offset within the PE image if successfully resolved.
    pub file_offset: Option<usize>,
    /// Size of the resource data in bytes.
    pub size: usize,
    /// Shannon entropy of the resource payload (0.0 to 8.0).
    pub entropy: f64,
    /// Whether this resource payload exhibits suspiciously high entropy (e.g. packed/encrypted).
    pub is_high_entropy: bool,
}

/// Assembly identity attributes extracted from `RT_MANIFEST`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AssemblyIdentity {
    pub name: Option<String>,
    pub version: Option<String>,
    pub processor_architecture: Option<String>,
}

/// Metadata and privilege configuration extracted from an embedded application manifest (`RT_MANIFEST`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ManifestInfo {
    /// Full raw XML content of the application manifest.
    pub raw_xml: String,
    /// User Account Control (UAC) requested execution level (`asInvoker`, `requireAdministrator`, `highestAvailable`).
    pub requested_execution_level: Option<String>,
    /// Whether UI access bypass is requested for accessibility applications.
    pub ui_access: Option<bool>,
    /// Whether auto-elevation is declared (`<autoElevate>true</autoElevate>`).
    pub auto_elevate: Option<bool>,
    /// Extracted assembly identity metadata.
    pub assembly_identity: Option<AssemblyIdentity>,
}

/// Version information extracted from `RT_VERSION` (`VS_VERSIONINFO`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct VersionInfo {
    /// File version string (e.g. "1.0.0.0").
    pub file_version: Option<String>,
    /// Product version string (e.g. "1.0.0.0").
    pub product_version: Option<String>,
    /// Authoring organization or company name.
    pub company_name: Option<String>,
    /// Human-readable file description.
    pub file_description: Option<String>,
    /// Legal copyright notice.
    pub legal_copyright: Option<String>,
    /// Original binary file name.
    pub original_filename: Option<String>,
    /// Marketing or product title.
    pub product_name: Option<String>,
    /// Extracted key-value pairs from StringTable.
    pub string_table: BTreeMap<String, String>,
}

/// Flagged high-entropy resource blob indicating embedded shellcode, compressed data, or encrypted payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HighEntropyResource {
    pub type_name: String,
    pub resource_name: String,
    pub size: usize,
    pub entropy: f64,
    pub rva: u32,
    pub file_offset: Option<usize>,
    pub reason: String,
}

/// Comprehensive analysis report for a PE image's Resource Directory (`.rsrc`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceReport {
    /// Target file path if inspected from disk.
    pub file_path: Option<String>,
    /// Whether the binary contains a valid non-empty resource directory.
    pub has_resources: bool,
    /// Resource Directory Virtual Address (RVA).
    pub resource_rva: u32,
    /// Resource Directory total declared size in bytes.
    pub resource_size: u32,
    /// Total count of individual resource leaf items.
    pub total_resources: usize,
    /// Breakdown of resource counts indexed by resource type name.
    pub type_counts: BTreeMap<String, usize>,
    /// Individual resource leaf entries.
    pub resources: Vec<ResourceEntry>,
    /// Parsed application manifest if `RT_MANIFEST` is present.
    pub manifest: Option<ManifestInfo>,
    /// Parsed version info if `RT_VERSION` is present.
    pub version_info: Option<VersionInfo>,
    /// Detected high-entropy resource items.
    pub high_entropy_resources: Vec<HighEntropyResource>,
    /// High-assurance security and forensic alerts.
    pub alerts: Vec<String>,
}
