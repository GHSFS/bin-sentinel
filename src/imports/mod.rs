// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! PE Import/Export Directory (IAT/EAT), imphash, and dynamic API hash resolution module.

pub mod api_hash;
pub mod imphash;
pub mod parser;
pub mod synthetic;

use serde::Serialize;

use crate::error::Result;
use crate::pe::parse_pe;

pub use api_hash::*;
pub use imphash::*;
pub use parser::*;
pub use synthetic::*;

/// Consolidated report of PE imports, exports, imphash, and resolved API hashes.
#[derive(Debug, Clone, Serialize)]
pub struct ImportsReport {
    pub file_path: Option<String>,
    pub format: String,
    pub imphash: Option<String>,
    pub total_imported_descriptors: usize,
    pub total_imported_functions: usize,
    pub import_descriptors: Vec<ImportDescriptor>,
    pub export_info: Option<ExportInfo>,
    pub resolved_api_hashes: Vec<ApiHashMatch>,
}

/// Inspects a PE binary buffer, extracting import and export directory telemetry and resolving hashes.
pub fn inspect_imports(data: &[u8], resolve_hash_hex: Option<&str>) -> Result<ImportsReport> {
    let pe = parse_pe(data)?;
    let import_descriptors = parse_imports(data, &pe)?;
    let export_info = parse_exports(data, &pe)?;
    let imphash = compute_imphash(&import_descriptors);

    let mut total_imported_functions = 0;
    for desc in &import_descriptors {
        total_imported_functions += desc.functions.len();
    }

    let mut resolved_api_hashes = Vec::new();
    if let Some(hash_str) = resolve_hash_hex {
        let target_hash = parse_hash_string(hash_str)?;

        let mut extra_exports = Vec::new();
        if let Some(ref exp) = export_info {
            for func in &exp.functions {
                if let Some(ref name) = func.name {
                    extra_exports.push((exp.dll_name.as_str(), name.as_str()));
                }
            }
        }

        resolved_api_hashes = resolve_api_hash(target_hash, &extra_exports);
    }

    Ok(ImportsReport {
        file_path: None,
        format: pe.format,
        imphash,
        total_imported_descriptors: import_descriptors.len(),
        total_imported_functions,
        import_descriptors,
        export_info,
        resolved_api_hashes,
    })
}
