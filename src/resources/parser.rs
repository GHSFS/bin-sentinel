// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::manifest::parse_manifest;
use super::types::{HighEntropyResource, ResourceEntry, ResourceReport};
use super::version::parse_version_info;
use crate::entropy::shannon_entropy;
use crate::error::{Result, SentinelError};
use crate::pe::{PeInfo, IMAGE_DIRECTORY_ENTRY_RESOURCE};
use std::collections::{BTreeMap, HashSet};

/// High entropy threshold for potential compressed, encrypted, or packed resource payloads.
pub const HIGH_ENTROPY_THRESHOLD: f64 = 7.20;
pub const MIN_HIGH_ENTROPY_SIZE: usize = 512;

/// Resolves standard Windows PE resource type identifiers into canonical strings.
pub fn resolve_resource_type_name(type_id: u32) -> &'static str {
    match type_id {
        1 => "RT_CURSOR",
        2 => "RT_BITMAP",
        3 => "RT_ICON",
        4 => "RT_MENU",
        5 => "RT_DIALOG",
        6 => "RT_STRING",
        7 => "RT_FONTDIR",
        8 => "RT_FONT",
        9 => "RT_ACCELERATOR",
        10 => "RT_RCDATA",
        11 => "RT_MESSAGETABLE",
        12 => "RT_GROUP_CURSOR",
        14 => "RT_GROUP_ICON",
        16 => "RT_VERSION",
        17 => "RT_DLGINCLUDE",
        19 => "RT_PLUGPLAY",
        20 => "RT_VXD",
        21 => "RT_ANICURSOR",
        22 => "RT_ANIICON",
        23 => "RT_HTML",
        24 => "RT_MANIFEST",
        _ => "RT_UNKNOWN",
    }
}

/// Resolves standard Windows language IDs into human-readable locale descriptors.
pub fn resolve_language_name(lang_id: u32) -> String {
    match lang_id {
        0x0000 => "Neutral (0x0000)".to_string(),
        0x0409 => "en-US (English United States)".to_string(),
        0x0809 => "en-GB (English United Kingdom)".to_string(),
        0x0412 => "ko-KR (Korean)".to_string(),
        0x0411 => "ja-JP (Japanese)".to_string(),
        0x0804 => "zh-CN (Chinese Simplified)".to_string(),
        0x0404 => "zh-TW (Chinese Traditional)".to_string(),
        0x0407 => "de-DE (German)".to_string(),
        0x040c => "fr-FR (French)".to_string(),
        0x0410 => "it-IT (Italian)".to_string(),
        0x0c0a => "es-ES (Spanish)".to_string(),
        0x0419 => "ru-RU (Russian)".to_string(),
        0x0416 => "pt-BR (Portuguese Brazil)".to_string(),
        other => format!("0x{other:04X}"),
    }
}

fn read_u16(slice: &[u8], offset: usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| SentinelError::BoundsError("u16 offset overflow".into()))?;
    let b = slice.get(offset..end).ok_or_else(|| {
        SentinelError::BoundsError("Truncated read for u16 in resource table".into())
    })?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(slice: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| SentinelError::BoundsError("u32 offset overflow".into()))?;
    let b = slice.get(offset..end).ok_or_else(|| {
        SentinelError::BoundsError("Truncated read for u32 in resource table".into())
    })?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Reads a UTF-16LE `IMAGE_RESOURCE_DIR_STRING_U` from the resource section.
fn read_resource_string(rsrc_slice: &[u8], offset: usize) -> Result<String> {
    let len = read_u16(rsrc_slice, offset)? as usize;
    let str_start = offset
        .checked_add(2)
        .ok_or_else(|| SentinelError::BoundsError("Resource string start overflow".into()))?;
    let str_end = str_start
        .checked_add(len.checked_mul(2).ok_or_else(|| {
            SentinelError::BoundsError("Resource string byte length overflow".into())
        })?)
        .ok_or_else(|| SentinelError::BoundsError("Resource string end overflow".into()))?;

    let str_bytes = rsrc_slice
        .get(str_start..str_end)
        .ok_or_else(|| SentinelError::BoundsError("Truncated resource string bytes".into()))?;

    let mut u16_chars = Vec::with_capacity(len);
    for chunk in str_bytes.chunks_exact(2) {
        u16_chars.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    Ok(String::from_utf16_lossy(&u16_chars))
}

/// Complete static inspection of the PE resource directory tree (`.rsrc`).
pub fn parse_resources(data: &[u8], pe_info: &PeInfo) -> Result<ResourceReport> {
    let mut report = ResourceReport {
        file_path: None,
        has_resources: false,
        resource_rva: 0,
        resource_size: 0,
        total_resources: 0,
        type_counts: BTreeMap::new(),
        resources: Vec::new(),
        manifest: None,
        version_info: None,
        high_entropy_resources: Vec::new(),
        alerts: Vec::new(),
    };

    let rsrc_dir = match pe_info.data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE) {
        Some(d) if d.virtual_address != 0 && d.size != 0 => *d,
        _ => return Ok(report),
    };

    report.resource_rva = rsrc_dir.virtual_address;
    report.resource_size = rsrc_dir.size;

    let rsrc_base_offset = match pe_info.rva_to_offset(rsrc_dir.virtual_address) {
        Some(off) if off < data.len() => off,
        _ => return Ok(report),
    };

    let rsrc_end = (rsrc_base_offset.saturating_add(rsrc_dir.size as usize)).min(data.len());
    let rsrc_slice = &data[rsrc_base_offset..rsrc_end];
    if rsrc_slice.len() < 16 {
        return Ok(report);
    }

    report.has_resources = true;
    let mut visited_dirs = HashSet::new();

    // Traverse 3-level tree starting from Root (Level 1: Types)
    walk_directory_level1(data, rsrc_slice, pe_info, 0, &mut visited_dirs, &mut report)?;

    report.total_resources = report.resources.len();

    // Check for high entropy alerts and summarize
    if !report.high_entropy_resources.is_empty() {
        report.alerts.push(format!(
            "Detected {} resource blob(s) with Shannon entropy >= {:.2} (potential encrypted or packed payload)",
            report.high_entropy_resources.len(),
            HIGH_ENTROPY_THRESHOLD
        ));
    }

    Ok(report)
}

/// Level 1: Resource Type directory
fn walk_directory_level1(
    raw_data: &[u8],
    rsrc_slice: &[u8],
    pe_info: &PeInfo,
    dir_offset: usize,
    visited: &mut HashSet<usize>,
    report: &mut ResourceReport,
) -> Result<()> {
    if !visited.insert(dir_offset) || dir_offset + 16 > rsrc_slice.len() {
        return Ok(());
    }

    let named_entries = read_u16(rsrc_slice, dir_offset + 12)? as usize;
    let id_entries = read_u16(rsrc_slice, dir_offset + 14)? as usize;
    let total_entries = named_entries.saturating_add(id_entries);

    for i in 0..total_entries {
        let entry_offset = dir_offset + 16 + (i * 8);
        if entry_offset + 8 > rsrc_slice.len() {
            break;
        }

        let name_field = read_u32(rsrc_slice, entry_offset)?;
        let offset_field = read_u32(rsrc_slice, entry_offset + 4)?;

        let (type_id, type_name) = if (name_field & 0x8000_0000) != 0 {
            let str_off = (name_field & 0x7FFF_FFFF) as usize;
            let name_str =
                read_resource_string(rsrc_slice, str_off).unwrap_or_else(|_| "INVALID_NAME".into());
            (None, name_str)
        } else {
            let id = name_field;
            let std_name = resolve_resource_type_name(id);
            if std_name == "RT_UNKNOWN" {
                (Some(id), format!("TYPE_{id}"))
            } else {
                (Some(id), std_name.to_string())
            }
        };

        if (offset_field & 0x8000_0000) != 0 {
            let sub_dir_off = (offset_field & 0x7FFF_FFFF) as usize;
            walk_directory_level2(
                raw_data,
                rsrc_slice,
                pe_info,
                sub_dir_off,
                type_id,
                &type_name,
                visited,
                report,
            )?;
        }
    }

    Ok(())
}

/// Level 2: Resource Name / ID directory
#[allow(clippy::too_many_arguments)]
fn walk_directory_level2(
    raw_data: &[u8],
    rsrc_slice: &[u8],
    pe_info: &PeInfo,
    dir_offset: usize,
    type_id: Option<u32>,
    type_name: &str,
    visited: &mut HashSet<usize>,
    report: &mut ResourceReport,
) -> Result<()> {
    if !visited.insert(dir_offset) || dir_offset + 16 > rsrc_slice.len() {
        return Ok(());
    }

    let named_entries = read_u16(rsrc_slice, dir_offset + 12)? as usize;
    let id_entries = read_u16(rsrc_slice, dir_offset + 14)? as usize;
    let total_entries = named_entries.saturating_add(id_entries);

    for i in 0..total_entries {
        let entry_offset = dir_offset + 16 + (i * 8);
        if entry_offset + 8 > rsrc_slice.len() {
            break;
        }

        let name_field = read_u32(rsrc_slice, entry_offset)?;
        let offset_field = read_u32(rsrc_slice, entry_offset + 4)?;

        let (name_id, name_str) = if (name_field & 0x8000_0000) != 0 {
            let str_off = (name_field & 0x7FFF_FFFF) as usize;
            let s = read_resource_string(rsrc_slice, str_off)
                .unwrap_or_else(|_| "NAMED_RESOURCE".into());
            (None, Some(s))
        } else {
            (Some(name_field), None)
        };

        if (offset_field & 0x8000_0000) != 0 {
            let sub_dir_off = (offset_field & 0x7FFF_FFFF) as usize;
            walk_directory_level3(
                raw_data,
                rsrc_slice,
                pe_info,
                sub_dir_off,
                type_id,
                type_name,
                name_id,
                name_str.as_deref(),
                visited,
                report,
            )?;
        } else {
            // Leaf directly attached to Level 2
            let data_entry_off = offset_field as usize;
            process_leaf_entry(
                raw_data,
                rsrc_slice,
                pe_info,
                data_entry_off,
                type_id,
                type_name,
                name_id,
                name_str.as_deref(),
                0, // Default neutral language
                report,
            )?;
        }
    }

    Ok(())
}

/// Level 3: Resource Language directory
#[allow(clippy::too_many_arguments)]
fn walk_directory_level3(
    raw_data: &[u8],
    rsrc_slice: &[u8],
    pe_info: &PeInfo,
    dir_offset: usize,
    type_id: Option<u32>,
    type_name: &str,
    name_id: Option<u32>,
    name_str: Option<&str>,
    visited: &mut HashSet<usize>,
    report: &mut ResourceReport,
) -> Result<()> {
    if !visited.insert(dir_offset) || dir_offset + 16 > rsrc_slice.len() {
        return Ok(());
    }

    let named_entries = read_u16(rsrc_slice, dir_offset + 12)? as usize;
    let id_entries = read_u16(rsrc_slice, dir_offset + 14)? as usize;
    let total_entries = named_entries.saturating_add(id_entries);

    for i in 0..total_entries {
        let entry_offset = dir_offset + 16 + (i * 8);
        if entry_offset + 8 > rsrc_slice.len() {
            break;
        }

        let lang_id = read_u32(rsrc_slice, entry_offset)?;
        let offset_field = read_u32(rsrc_slice, entry_offset + 4)?;

        // Top bit must be 0 for leaf Data Entry
        let data_entry_off = (offset_field & 0x7FFF_FFFF) as usize;
        process_leaf_entry(
            raw_data,
            rsrc_slice,
            pe_info,
            data_entry_off,
            type_id,
            type_name,
            name_id,
            name_str,
            lang_id,
            report,
        )?;
    }

    Ok(())
}

/// Processes an `IMAGE_RESOURCE_DATA_ENTRY` leaf.
#[allow(clippy::too_many_arguments)]
fn process_leaf_entry(
    raw_data: &[u8],
    rsrc_slice: &[u8],
    pe_info: &PeInfo,
    data_entry_off: usize,
    type_id: Option<u32>,
    type_name: &str,
    name_id: Option<u32>,
    name_str: Option<&str>,
    language_id: u32,
    report: &mut ResourceReport,
) -> Result<()> {
    if data_entry_off + 16 > rsrc_slice.len() {
        return Ok(());
    }

    let data_rva = read_u32(rsrc_slice, data_entry_off)?;
    let size = read_u32(rsrc_slice, data_entry_off + 4)? as usize;

    let file_offset = pe_info.rva_to_offset(data_rva);
    let payload = if let Some(off) = file_offset {
        if off < raw_data.len() {
            let end = (off.saturating_add(size)).min(raw_data.len());
            &raw_data[off..end]
        } else {
            &[]
        }
    } else {
        &[]
    };

    let entropy = if !payload.is_empty() {
        shannon_entropy(payload)
    } else {
        0.0
    };

    let is_high_entropy =
        payload.len() >= MIN_HIGH_ENTROPY_SIZE && entropy >= HIGH_ENTROPY_THRESHOLD;
    let res_name = name_str
        .map(|s| s.to_string())
        .or_else(|| name_id.map(|id| format!("#{id}")))
        .unwrap_or_else(|| "1".to_string());

    if is_high_entropy {
        report.high_entropy_resources.push(HighEntropyResource {
            type_name: type_name.to_string(),
            resource_name: res_name.clone(),
            size: payload.len(),
            entropy,
            rva: data_rva,
            file_offset,
            reason: format!(
                "Shannon entropy {:.2}/8.00 in {} bytes indicates compression or encryption",
                entropy,
                payload.len()
            ),
        });
    }

    // Special type: RT_MANIFEST (24)
    if (type_id == Some(24) || type_name == "RT_MANIFEST")
        && report.manifest.is_none()
        && !payload.is_empty()
    {
        let manifest = parse_manifest(payload);
        if let Some(ref level) = manifest.requested_execution_level {
            if level == "requireAdministrator" {
                report.alerts.push(
                    "UAC Privilege Escalation: 'requireAdministrator' declared in application manifest".to_string(),
                );
            } else if level == "highestAvailable" {
                report.alerts.push(
                    "UAC Privilege Escalation: 'highestAvailable' declared in application manifest"
                        .to_string(),
                );
            }
        }
        if manifest.auto_elevate == Some(true) {
            report.alerts.push(
                "UAC Auto-Elevation: 'autoElevate' attribute enabled in application manifest"
                    .to_string(),
            );
        }
        report.manifest = Some(manifest);
    }

    // Special type: RT_VERSION (16)
    if (type_id == Some(16) || type_name == "RT_VERSION")
        && report.version_info.is_none()
        && !payload.is_empty()
    {
        let ver = parse_version_info(payload);
        report.version_info = Some(ver);
    }

    *report.type_counts.entry(type_name.to_string()).or_insert(0) += 1;

    report.resources.push(ResourceEntry {
        type_id,
        type_name: type_name.to_string(),
        name_id,
        name_str: name_str.map(|s| s.to_string()),
        language_id,
        language_name: resolve_language_name(language_id),
        rva: data_rva,
        file_offset,
        size: payload.len(),
        entropy,
        is_high_entropy,
    });

    Ok(())
}
