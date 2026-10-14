// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::VersionInfo;

const VS_FFI_SIGNATURE: u32 = 0xFEEF_04BD;

/// Parses `RT_VERSION` resource payload (`VS_VERSIONINFO`).
pub fn parse_version_info(data: &[u8]) -> VersionInfo {
    let mut info = VersionInfo::default();
    if data.len() < 40 {
        return info;
    }

    // Try structured parsing first
    let _ = parse_vs_version_info_struct(data, &mut info);

    // Complement / fallback with robust UTF-16 string scanner
    extract_known_version_strings(data, &mut info);

    // Promote standard keys to top-level fields
    if info.file_version.is_none() {
        info.file_version = info.string_table.get("FileVersion").cloned();
    }
    if info.product_version.is_none() {
        info.product_version = info.string_table.get("ProductVersion").cloned();
    }
    if info.company_name.is_none() {
        info.company_name = info.string_table.get("CompanyName").cloned();
    }
    if info.file_description.is_none() {
        info.file_description = info.string_table.get("FileDescription").cloned();
    }
    if info.legal_copyright.is_none() {
        info.legal_copyright = info.string_table.get("LegalCopyright").cloned();
    }
    if info.original_filename.is_none() {
        info.original_filename = info.string_table.get("OriginalFilename").cloned();
    }
    if info.product_name.is_none() {
        info.product_name = info.string_table.get("ProductName").cloned();
    }

    info
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let slice = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let slice = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn align_4(offset: usize) -> usize {
    (offset + 3) & !3
}

/// Parses the standard VS_VERSIONINFO binary structure including VS_FIXEDFILEINFO.
fn parse_vs_version_info_struct(data: &[u8], info: &mut VersionInfo) -> Option<()> {
    let _w_length = read_u16(data, 0)? as usize;
    let w_value_length = read_u16(data, 2)? as usize;
    let _w_type = read_u16(data, 4)?;

    // Read key: "VS_VERSION_INFO" in UTF-16LE
    let mut key_end = 6;
    while key_end + 1 < data.len() {
        if data[key_end] == 0 && data[key_end + 1] == 0 {
            key_end += 2;
            break;
        }
        key_end += 2;
    }

    let value_offset = align_4(key_end);
    if w_value_length >= 52 && value_offset + 52 <= data.len() {
        let sig = read_u32(data, value_offset)?;
        if sig == VS_FFI_SIGNATURE {
            let file_ver_ms = read_u32(data, value_offset + 8)?;
            let file_ver_ls = read_u32(data, value_offset + 12)?;
            let prod_ver_ms = read_u32(data, value_offset + 16)?;
            let prod_ver_ls = read_u32(data, value_offset + 20)?;

            info.file_version = Some(format!(
                "{}.{}.{}.{}",
                file_ver_ms >> 16,
                file_ver_ms & 0xFFFF,
                file_ver_ls >> 16,
                file_ver_ls & 0xFFFF
            ));

            info.product_version = Some(format!(
                "{}.{}.{}.{}",
                prod_ver_ms >> 16,
                prod_ver_ms & 0xFFFF,
                prod_ver_ls >> 16,
                prod_ver_ls & 0xFFFF
            ));
        }
    }

    Some(())
}

/// Scans the entire raw byte buffer for well-known UTF-16LE Windows version resource keys.
fn extract_known_version_strings(data: &[u8], info: &mut VersionInfo) {
    const KNOWN_KEYS: &[&str] = &[
        "CompanyName",
        "FileDescription",
        "FileVersion",
        "InternalName",
        "LegalCopyright",
        "LegalTrademarks",
        "OriginalFilename",
        "ProductName",
        "ProductVersion",
        "Comments",
        "Assembly Version",
    ];

    for &key in KNOWN_KEYS {
        let key_utf16 = encode_utf16_le(key);
        let mut search_idx = 0;
        while let Some(pos) = find_subsequence(&data[search_idx..], &key_utf16) {
            let key_pos = search_idx + pos;
            let after_key = key_pos + key_utf16.len();

            // Skip null terminator for key if present
            let mut val_scan = after_key;
            if val_scan + 1 < data.len() && data[val_scan] == 0 && data[val_scan + 1] == 0 {
                val_scan += 2;
            }
            val_scan = align_4(val_scan);

            // Read value as UTF-16LE string
            if let Some(val) = read_utf16_string_at(data, val_scan) {
                if !val.is_empty() {
                    info.string_table
                        .entry(key.to_string())
                        .or_insert_with(|| val);
                    break;
                }
            }

            search_idx = key_pos + 2;
            if search_idx >= data.len() {
                break;
            }
        }
    }
}

fn encode_utf16_le(s: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    bytes
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn read_utf16_string_at(data: &[u8], start: usize) -> Option<String> {
    if start >= data.len() {
        return None;
    }

    let mut u16_chars = Vec::new();
    let mut curr = start;

    // Scan until null terminator or max 256 code points
    while curr + 1 < data.len() && u16_chars.len() < 256 {
        let code = u16::from_le_bytes([data[curr], data[curr + 1]]);
        if code == 0 {
            break;
        }
        // Printable ASCII or unicode
        if code < 0x20 && code != 0x09 && code != 0x0A && code != 0x0D {
            // Non-printable control char outside whitespace
            break;
        }
        u16_chars.push(code);
        curr += 2;
    }

    if u16_chars.is_empty() {
        return None;
    }

    let result = String::from_utf16_lossy(&u16_chars).trim().to_string();
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}
