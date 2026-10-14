// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::{AssemblyIdentity, ManifestInfo};

/// Decodes raw resource bytes into a string, transparently handling UTF-8, UTF-16LE, UTF-16BE, and BOMs.
pub fn decode_manifest_string(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    // 1. Check for standard Byte Order Marks (BOM)
    if data.starts_with(&[0xEF, 0xBB, 0xBF]) {
        // UTF-8 with BOM
        return String::from_utf8_lossy(&data[3..])
            .trim_matches('\0')
            .trim()
            .to_string();
    }

    if data.starts_with(&[0xFF, 0xFE]) {
        // UTF-16LE with BOM
        return decode_utf16_le(&data[2..]);
    }

    if data.starts_with(&[0xFE, 0xFF]) {
        // UTF-16BE with BOM
        return decode_utf16_be(&data[2..]);
    }

    // 2. Heuristic check for UTF-16LE without BOM (e.g. ASCII characters interleaved with null bytes: '<', 0, '?', 0, 'x', 0)
    if data.len() >= 4 && data[1] == 0 && data[3] == 0 && data[0] == b'<' {
        return decode_utf16_le(data);
    }

    // 3. Fallback to standard UTF-8 / ASCII lossy decoding
    String::from_utf8_lossy(data)
        .trim_matches('\0')
        .trim()
        .to_string()
}

fn decode_utf16_le(data: &[u8]) -> String {
    let u16_count = data.len() / 2;
    let mut u16_vec = Vec::with_capacity(u16_count);
    for chunk in data.chunks_exact(2) {
        u16_vec.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16_lossy(&u16_vec)
        .trim_matches('\0')
        .trim()
        .to_string()
}

fn decode_utf16_be(data: &[u8]) -> String {
    let u16_count = data.len() / 2;
    let mut u16_vec = Vec::with_capacity(u16_count);
    for chunk in data.chunks_exact(2) {
        u16_vec.push(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16_lossy(&u16_vec)
        .trim_matches('\0')
        .trim()
        .to_string()
}

/// Parses an embedded application manifest XML payload and extracts security-relevant UAC configurations.
pub fn parse_manifest(raw_bytes: &[u8]) -> ManifestInfo {
    let xml = decode_manifest_string(raw_bytes);
    if xml.is_empty() {
        return ManifestInfo::default();
    }

    let requested_execution_level =
        extract_attribute_value(&xml, "requestedExecutionLevel", "level");
    let ui_access = extract_attribute_value(&xml, "requestedExecutionLevel", "uiAccess")
        .map(|v| v.eq_ignore_ascii_case("true"));

    let auto_elevate = if xml.contains("<autoElevate>true</autoElevate>")
        || xml.contains("<autoElevate>True</autoElevate>")
        || xml.contains("autoElevate=\"true\"")
    {
        Some(true)
    } else if xml.contains("<autoElevate>false</autoElevate>")
        || xml.contains("<autoElevate>False</autoElevate>")
        || xml.contains("autoElevate=\"false\"")
    {
        Some(false)
    } else {
        None
    };

    let assembly_identity = extract_assembly_identity(&xml);

    ManifestInfo {
        raw_xml: xml,
        requested_execution_level,
        ui_access,
        auto_elevate,
        assembly_identity,
    }
}

/// Helper to extract attribute values from an XML element without requiring heavy external dependencies.
fn extract_attribute_value(xml: &str, element_tag: &str, attribute_name: &str) -> Option<String> {
    let elem_idx = xml.find(element_tag)?;
    let slice = &xml[elem_idx..];
    let end_elem = slice.find('>').unwrap_or(slice.len());
    let elem_content = &slice[..end_elem];

    let pattern_double = format!("{attribute_name}=\"");
    let pattern_single = format!("{attribute_name}='");

    if let Some(start) = elem_content.find(&pattern_double) {
        let value_start = start + pattern_double.len();
        let value_slice = &elem_content[value_start..];
        if let Some(end) = value_slice.find('"') {
            return Some(value_slice[..end].trim().to_string());
        }
    }

    if let Some(start) = elem_content.find(&pattern_single) {
        let value_start = start + pattern_single.len();
        let value_slice = &elem_content[value_start..];
        if let Some(end) = value_slice.find('\'') {
            return Some(value_slice[..end].trim().to_string());
        }
    }

    None
}

/// Extracts assembly identity metadata (name, version, processorArchitecture).
fn extract_assembly_identity(xml: &str) -> Option<AssemblyIdentity> {
    let elem_idx = xml.find("assemblyIdentity")?;
    let slice = &xml[elem_idx..];
    let end_elem = slice.find('>').unwrap_or(slice.len());
    let elem_content = &slice[..end_elem];

    let name = extract_attr_from_str(elem_content, "name");
    let version = extract_attr_from_str(elem_content, "version");
    let processor_architecture = extract_attr_from_str(elem_content, "processorArchitecture");

    if name.is_none() && version.is_none() && processor_architecture.is_none() {
        None
    } else {
        Some(AssemblyIdentity {
            name,
            version,
            processor_architecture,
        })
    }
}

fn extract_attr_from_str(content: &str, attr: &str) -> Option<String> {
    let pattern_double = format!("{attr}=\"");
    let pattern_single = format!("{attr}='");

    if let Some(start) = content.find(&pattern_double) {
        let value_start = start + pattern_double.len();
        let value_slice = &content[value_start..];
        if let Some(end) = value_slice.find('"') {
            return Some(value_slice[..end].trim().to_string());
        }
    }

    if let Some(start) = content.find(&pattern_single) {
        let value_start = start + pattern_single.len();
        let value_slice = &content[value_start..];
        if let Some(end) = value_slice.find('\'') {
            return Some(value_slice[..end].trim().to_string());
        }
    }

    None
}
