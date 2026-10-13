// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fs;
use std::path::{Path, PathBuf};

use zeroize::Zeroize;

use crate::diff::types::{ApplyReport, DiffReport, PatchOperation, PatchRecipe};
use crate::error::{Result, SentinelError};
use crate::patch::{constant_time_eq, parse_hex_bytes, sha256_hex};

/// Configuration options for applying or reverting a patch recipe.
#[derive(Debug, Clone, Default)]
pub struct ApplyOptions {
    /// Validate all patch operations and compute post-patch hash without writing to disk.
    pub dry_run: bool,
    /// Invert expected and replacement bytes to revert a previously applied patch.
    pub reverse: bool,
    /// Create a `.bak` backup file before applying changes to disk.
    pub backup: bool,
}

/// Generates a declarative patch recipe manifest from a binary diff report.
pub fn generate_recipe(
    diff_report: &DiffReport,
    name: Option<&str>,
    description: Option<&str>,
) -> PatchRecipe {
    let recipe_name = name.map(|s| s.to_string()).unwrap_or_else(|| {
        let o_short = if diff_report.original_sha256.len() >= 8 {
            &diff_report.original_sha256[..8]
        } else {
            "orig"
        };
        let m_short = if diff_report.modified_sha256.len() >= 8 {
            &diff_report.modified_sha256[..8]
        } else {
            "mod"
        };
        format!("patch-{o_short}-to-{m_short}")
    });

    let operations: Vec<PatchOperation> = diff_report
        .hunks
        .iter()
        .map(|h| PatchOperation {
            offset: h.offset,
            length: h.length,
            expected_hex: h.orig_bytes_hex.clone(),
            replace_hex: h.mod_bytes_hex.clone(),
            section_name: h.section_name.clone(),
            rva: h.rva,
            comment: h.section_name.as_ref().map(|s| format!("Section {s}")),
        })
        .collect();

    PatchRecipe {
        name: recipe_name,
        description: description.map(|s| s.to_string()),
        target_format: diff_report.format,
        source_sha256: diff_report.original_sha256.clone(),
        target_sha256: diff_report.modified_sha256.clone(),
        operations,
    }
}

/// Saves a patch recipe manifest to a JSON file.
pub fn save_recipe_to_file(recipe: &PatchRecipe, path: &Path) -> Result<()> {
    let json = recipe.to_json_pretty()?;
    fs::write(path, json)?;
    Ok(())
}

/// Loads a patch recipe manifest from a JSON file.
pub fn load_recipe_from_file(path: &Path) -> Result<PatchRecipe> {
    let json = fs::read_to_string(path)?;
    PatchRecipe::from_json(&json)
}

/// Atomically verifies and applies (or reverts) a patch recipe against a target binary file.
pub fn apply_recipe(
    target_path: &Path,
    recipe: &PatchRecipe,
    options: &ApplyOptions,
) -> Result<ApplyReport> {
    let mut data = fs::read(target_path)?;
    let sha256_before = sha256_hex(&data);

    let expected_initial_sha = if options.reverse {
        &recipe.target_sha256
    } else {
        &recipe.source_sha256
    };

    if !expected_initial_sha.is_empty()
        && !constant_time_eq(sha256_before.as_bytes(), expected_initial_sha.as_bytes())
    {
        data.zeroize();
        return Err(SentinelError::InvalidArgument(format!(
            "Target file SHA-256 mismatch before patching: expected {expected_initial_sha}, found {sha256_before}"
        )));
    }

    // Phase 1: Constant-time pre-verification of all operations
    let mut decoded_ops = Vec::with_capacity(recipe.operations.len());
    for op in &recipe.operations {
        let (exp_hex, rep_hex) = if options.reverse {
            (&op.replace_hex, &op.expected_hex)
        } else {
            (&op.expected_hex, &op.replace_hex)
        };

        let expected_bytes = parse_hex_bytes(exp_hex)?;
        let replacement_bytes = parse_hex_bytes(rep_hex)?;

        if expected_bytes.len() != replacement_bytes.len() {
            data.zeroize();
            return Err(SentinelError::InvalidArgument(format!(
                "Patch operation at offset 0x{:X} has unequal expected ({}) and replacement ({}) lengths",
                op.offset,
                expected_bytes.len(),
                replacement_bytes.len()
            )));
        }

        let end = op.offset.checked_add(expected_bytes.len()).ok_or_else(|| {
            data.zeroize();
            SentinelError::BoundsError(format!("Patch offset 0x{:X} overflow", op.offset))
        })?;

        if end > data.len() {
            data.zeroize();
            return Err(SentinelError::BoundsError(format!(
                "Patch operation range 0x{:X}..0x{:X} exceeds file size ({} bytes)",
                op.offset,
                end,
                data.len()
            )));
        }

        let actual_slice = &data[op.offset..end];
        if !constant_time_eq(actual_slice, &expected_bytes) {
            let mismatch = SentinelError::PatchMismatch {
                offset: op.offset,
                expected_hex: hex::encode_upper(&expected_bytes),
                actual_hex: hex::encode_upper(actual_slice),
            };
            data.zeroize();
            return Err(mismatch);
        }

        decoded_ops.push((op.offset, end, replacement_bytes));
    }

    // Phase 2: Execution (Dry-run or Live)
    if options.dry_run {
        for (offset, end, rep_bytes) in &decoded_ops {
            data[*offset..*end].copy_from_slice(rep_bytes);
        }
        let sha256_after = sha256_hex(&data);
        data.zeroize();

        return Ok(ApplyReport {
            target_path: target_path.to_string_lossy().to_string(),
            recipe_name: recipe.name.clone(),
            operations_count: recipe.operations.len(),
            sha256_before,
            sha256_after,
            is_dry_run: true,
            backup_path: None,
            reversed: options.reverse,
        });
    }

    let backup_path = if options.backup {
        let mut bak = PathBuf::from(target_path);
        let new_ext = match target_path.extension().and_then(|e| e.to_str()) {
            Some(ext) => format!("{ext}.bak"),
            None => "bak".to_string(),
        };
        bak.set_extension(new_ext);
        fs::write(&bak, &data)?;
        Some(bak.to_string_lossy().to_string())
    } else {
        None
    };

    for (offset, end, rep_bytes) in &decoded_ops {
        data[*offset..*end].copy_from_slice(rep_bytes);
    }
    let sha256_after = sha256_hex(&data);

    let expected_final_sha = if options.reverse {
        &recipe.source_sha256
    } else {
        &recipe.target_sha256
    };

    if !expected_final_sha.is_empty()
        && !constant_time_eq(sha256_after.as_bytes(), expected_final_sha.as_bytes())
    {
        data.zeroize();
        return Err(SentinelError::InvalidArgument(format!(
            "Target file SHA-256 post-verification failed: expected {expected_final_sha}, found {sha256_after}"
        )));
    }

    fs::write(target_path, &data)?;
    data.zeroize();

    Ok(ApplyReport {
        target_path: target_path.to_string_lossy().to_string(),
        recipe_name: recipe.name.clone(),
        operations_count: recipe.operations.len(),
        sha256_before,
        sha256_after,
        is_dry_run: false,
        backup_path,
        reversed: options.reverse,
    })
}
