// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::{Result, SentinelError};

/// Summary of an applied declarative binary byte patch.
#[derive(Debug, Clone, Serialize)]
pub struct PatchReport {
    pub path: String,
    pub offset: usize,
    pub length: usize,
    pub expected_hex: String,
    pub replaced_hex: String,
    pub sha256_before: String,
    pub sha256_after: String,
    pub backup_path: Option<String>,
}

/// Branchless constant-time byte slice equality check.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Computes the lower-hex SHA-256 digest of a byte slice.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Parses a hexadecimal string (allowing spaces or `0x` prefixes) into raw bytes.
pub fn parse_hex_bytes(input: &str) -> Result<Vec<u8>> {
    let cleaned: String = input
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_' && *c != ':')
        .collect();

    if cleaned.is_empty() {
        return Err(SentinelError::InvalidArgument(
            "Hex byte string cannot be empty".into(),
        ));
    }
    hex::decode(&cleaned)
        .map_err(|e| SentinelError::InvalidArgument(format!("Invalid hex string '{input}': {e}")))
}

/// Parses a decimal or `0x`-prefixed hexadecimal offset string into `usize`.
pub fn parse_offset(input: &str) -> Result<usize> {
    let trimmed = input.trim();
    if let Some(hex_part) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        usize::from_str_radix(hex_part, 16).map_err(|e| {
            SentinelError::InvalidArgument(format!("Invalid hex offset '{input}': {e}"))
        })
    } else {
        trimmed.parse::<usize>().map_err(|e| {
            SentinelError::InvalidArgument(format!("Invalid decimal offset '{input}': {e}"))
        })
    }
}

/// Verifies `expected_bytes` at `offset` in constant time, optionally writes a `.bak` backup,
/// and applies `replacement_bytes` atomically with pre/post SHA-256 verification.
pub fn apply_patch(
    path: &Path,
    offset: usize,
    expected_bytes: &[u8],
    replacement_bytes: &[u8],
    create_backup: bool,
) -> Result<PatchReport> {
    if expected_bytes.is_empty() {
        return Err(SentinelError::InvalidArgument(
            "expected_bytes cannot be empty".into(),
        ));
    }
    if expected_bytes.len() != replacement_bytes.len() {
        return Err(SentinelError::InvalidArgument(format!(
            "Expected bytes length ({}) must match replacement bytes length ({})",
            expected_bytes.len(),
            replacement_bytes.len()
        )));
    }

    let mut data = fs::read(path)?;
    let patch_len = expected_bytes.len();
    let end = offset
        .checked_add(patch_len)
        .ok_or_else(|| SentinelError::BoundsError("Patch offset overflow".into()))?;

    if end > data.len() {
        data.zeroize();
        return Err(SentinelError::BoundsError(format!(
            "Patch range 0x{offset:X}..0x{end:X} exceeds file size ({} bytes)",
            data.len()
        )));
    }

    let actual_slice = &data[offset..end];
    if !constant_time_eq(actual_slice, expected_bytes) {
        let mismatch = SentinelError::PatchMismatch {
            offset,
            expected_hex: hex::encode_upper(expected_bytes),
            actual_hex: hex::encode_upper(actual_slice),
        };
        data.zeroize();
        return Err(mismatch);
    }

    let sha256_before = sha256_hex(&data);

    let backup_path = if create_backup {
        let mut bak = PathBuf::from(path);
        let new_ext = match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => format!("{ext}.bak"),
            None => "bak".to_string(),
        };
        bak.set_extension(new_ext);
        fs::write(&bak, &data)?;
        Some(bak.to_string_lossy().to_string())
    } else {
        None
    };

    data[offset..end].copy_from_slice(replacement_bytes);
    let sha256_after = sha256_hex(&data);

    fs::write(path, &data)?;
    data.zeroize();

    Ok(PatchReport {
        path: path.to_string_lossy().to_string(),
        offset,
        length: patch_len,
        expected_hex: hex::encode_upper(expected_bytes),
        replaced_hex: hex::encode_upper(replacement_bytes),
        sha256_before,
        sha256_after,
        backup_path,
    })
}
