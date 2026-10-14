// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod manifest;
pub mod parser;
pub mod synthetic;
pub mod types;
pub mod version;

use crate::error::Result;
use crate::pe::parse_pe;
use std::fs;
use std::path::Path;

pub use manifest::{decode_manifest_string, parse_manifest};
pub use parser::{
    parse_resources, resolve_language_name, resolve_resource_type_name, HIGH_ENTROPY_THRESHOLD,
    MIN_HIGH_ENTROPY_SIZE,
};
pub use synthetic::{build_synthetic_resource_pe, SyntheticResourceSpec};
pub use types::{
    AssemblyIdentity, HighEntropyResource, ManifestInfo, ResourceEntry, ResourceReport, VersionInfo,
};
pub use version::parse_version_info;

/// Inspects the PE Resource Directory (`.rsrc`) and manifest from in-memory binary bytes.
pub fn inspect_resources_bytes(data: &[u8]) -> Result<ResourceReport> {
    let pe_info = parse_pe(data)?;
    let mut report = parse_resources(data, &pe_info)?;
    report.file_path = None;
    Ok(report)
}

/// Reads a PE binary from disk and performs full resource directory, manifest, and version inspection.
pub fn inspect_resources_file(path: &Path) -> Result<ResourceReport> {
    let data = fs::read(path)?;
    let mut report = inspect_resources_bytes(&data)?;
    report.file_path = Some(path.display().to_string());
    Ok(report)
}
