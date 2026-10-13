// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fs;
use std::path::Path;

use super::database::{determine_primary_toolchain, lookup_tool, resolve_vs_version};
use super::types::{RichChecksum, RichHashes, RichRecord, RichReport};
use crate::error::{Result, SentinelError};
use crate::imports::imphash::md5_hex;
use crate::patch::sha256_hex;

const DOS_MAGIC: u16 = 0x5A4D; // "MZ"
const RICH_MARKER: u32 = 0x6863_6952; // "Rich" in LE
const DANS_MARKER: u32 = 0x536E_6144; // "DanS" in LE

fn read_u16_le(slice: &[u8], offset: usize) -> Result<u16> {
    let bytes = slice.get(offset..offset + 2).ok_or_else(|| {
        SentinelError::BoundsError(format!("Read u16 out of bounds at 0x{offset:X}"))
    })?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(slice: &[u8], offset: usize) -> Result<u32> {
    let bytes = slice.get(offset..offset + 4).ok_or_else(|| {
        SentinelError::BoundsError(format!("Read u32 out of bounds at 0x{offset:X}"))
    })?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Computes the authentic 32-bit Microsoft Rich header checksum over the DOS stub and decoded entries.
pub fn calculate_rich_checksum(data: &[u8], dans_offset: usize, entries: &[(u32, u32)]) -> u32 {
    let mut csum = dans_offset as u32;

    for i in 0..dans_offset {
        // Offset 0x3C..0x40 holds e_lfanew and is cleared to 0 by the linker during checksum calculation
        let b = if (0x3C..0x40).contains(&i) {
            0u32
        } else {
            data.get(i).copied().unwrap_or(0) as u32
        };
        csum = csum.wrapping_add(b.rotate_left((i & 31) as u32));
    }

    for &(comp_id, count) in entries {
        csum = csum.wrapping_add(comp_id.rotate_left(count & 31));
    }

    csum
}

/// Locates the `"Rich"` end-marker and XOR key within the DOS stub area of a PE binary.
fn find_rich_marker(data: &[u8], search_limit: usize) -> Result<(usize, u32)> {
    if data.len() < 0x48 {
        return Err(SentinelError::InvalidFormat(
            "File too small to contain a PE Rich header".into(),
        ));
    }

    let limit = search_limit.min(data.len().saturating_sub(8));
    if limit < 0x40 {
        return Err(SentinelError::BoundsError(
            "DOS stub region too small for Rich header search".into(),
        ));
    }

    // Search 4-byte aligned boundaries from 0x40 up to limit
    let mut offset = 0x40;
    while offset <= limit {
        if let Ok(val) = read_u32_le(data, offset) {
            if val == RICH_MARKER {
                let xor_key = read_u32_le(data, offset + 4)?;
                return Ok((offset, xor_key));
            }
        }
        offset += 4;
    }

    Err(SentinelError::InvalidFormat(
        "No Rich header found in DOS stub (marker 'Rich' absent)".into(),
    ))
}

/// Locates the `"DanS"` entry point marker and confirms the three zero padding DWORDs.
fn find_dans_marker(data: &[u8], rich_offset: usize, xor_key: u32) -> Result<usize> {
    if rich_offset < 0x50 {
        return Err(SentinelError::InvalidFormat(
            "Rich marker located too early in DOS stub for valid DanS preamble".into(),
        ));
    }

    // Step backwards by 4 bytes looking for DanS ^ xor_key
    let min_offset = 0x40;
    let mut p = rich_offset.saturating_sub(16);

    while p >= min_offset {
        if let Ok(raw) = read_u32_le(data, p) {
            if (raw ^ xor_key) == DANS_MARKER {
                // Verify the 3 padding DWORDs decrypt to 0
                let z1 = read_u32_le(data, p + 4)? ^ xor_key;
                let z2 = read_u32_le(data, p + 8)? ^ xor_key;
                let z3 = read_u32_le(data, p + 12)? ^ xor_key;

                if z1 == 0 && z2 == 0 && z3 == 0 {
                    return Ok(p);
                }
            }
        }
        if p < 4 {
            break;
        }
        p -= 4;
    }

    Err(SentinelError::InvalidFormat(
        "Corrupted Rich header: 'DanS' entry point with zero padding not found".into(),
    ))
}

/// Decodes and audits the PE Rich header from raw binary bytes.
pub fn parse_rich_bytes(data: &[u8], file_label: &str) -> Result<RichReport> {
    if data.len() < 0x40 {
        return Err(SentinelError::InvalidFormat(
            "File smaller than minimum 64-byte DOS header".into(),
        ));
    }

    let dos_magic = read_u16_le(data, 0)?;
    if dos_magic != DOS_MAGIC {
        return Err(SentinelError::InvalidFormat(format!(
            "Invalid DOS MZ magic: 0x{dos_magic:04X}"
        )));
    }

    let e_lfanew = read_u32_le(data, 0x3C)? as usize;
    let search_limit = if e_lfanew >= 0x48 && e_lfanew <= data.len() {
        e_lfanew
    } else {
        data.len().min(4096)
    };

    let (rich_offset, xor_key) = find_rich_marker(data, search_limit)?;
    let dans_offset = find_dans_marker(data, rich_offset, xor_key)?;

    let records_start = dans_offset + 16;
    if records_start > rich_offset {
        return Err(SentinelError::InvalidFormat(
            "Invalid Rich header: record start exceeds Rich marker offset".into(),
        ));
    }

    let records_bytes_len = rich_offset - records_start;
    if (records_bytes_len % 8) != 0 {
        return Err(SentinelError::InvalidFormat(format!(
            "Invalid Rich header: entries payload size ({records_bytes_len} bytes) not divisible by 8"
        )));
    }

    let mut records = Vec::new();
    let mut raw_entries = Vec::new();
    let mut clear_data = Vec::with_capacity(records_bytes_len);
    let mut anomalies = Vec::new();

    let entry_count = records_bytes_len / 8;
    for i in 0..entry_count {
        let entry_offset = records_start + (i * 8);
        let raw_comp_id = read_u32_le(data, entry_offset)? ^ xor_key;
        let count = read_u32_le(data, entry_offset + 4)? ^ xor_key;

        raw_entries.push((raw_comp_id, count));
        clear_data.extend_from_slice(&raw_comp_id.to_le_bytes());
        clear_data.extend_from_slice(&count.to_le_bytes());

        let product_id = (raw_comp_id >> 16) as u16;
        let build_number = (raw_comp_id & 0xFFFF) as u16;

        let (tool_name, tool_kind) = lookup_tool(product_id);
        let vs_version = resolve_vs_version(product_id, build_number);

        if count == 0 {
            anomalies.push(format!(
                "Anomalous zero invocation count for product ID 0x{product_id:04X} at record #{i}"
            ));
        }

        records.push(RichRecord {
            raw_comp_id,
            product_id,
            build_number,
            count,
            tool_name: tool_name.to_string(),
            tool_kind,
            vs_version: vs_version.to_string(),
        });
    }

    if records.is_empty() {
        anomalies.push("Rich header contains zero @comp.id records".to_string());
    }

    // Checksum verification
    let calculated_key = calculate_rich_checksum(data, dans_offset, &raw_entries);
    let is_valid = calculated_key == xor_key;

    if !is_valid {
        anomalies.push(format!(
            "Rich header checksum mismatch: stored XOR key 0x{xor_key:08X} does not match computed checksum 0x{calculated_key:08X}"
        ));
    }

    let md5_hash = md5_hex(&clear_data);
    let sha256_hash = sha256_hex(&clear_data);
    let primary_toolchain = determine_primary_toolchain(&records);
    let header_size = (rich_offset + 8) - dans_offset;

    Ok(RichReport {
        file_path: file_label.to_string(),
        dans_offset,
        rich_offset,
        header_size,
        xor_key,
        record_count: records.len(),
        records,
        checksum: RichChecksum {
            stored_xor_key: xor_key,
            calculated_key,
            is_valid,
        },
        hashes: RichHashes {
            md5: md5_hash,
            sha256: sha256_hash,
        },
        primary_toolchain,
        anomalies,
    })
}

/// Decodes and audits the PE Rich header of a file from disk.
pub fn parse_rich_file(path: &Path) -> Result<RichReport> {
    let bytes = fs::read(path)?;
    parse_rich_bytes(&bytes, &path.display().to_string())
}
