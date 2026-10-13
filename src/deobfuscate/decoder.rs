// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Core decoding algorithms, artifact classifiers, and crib-drag primitives.

use crate::deobfuscate::types::ArtifactKind;

/// Decodes a byte slice by applying a single-byte XOR key to each byte.
pub fn xor_decode_single(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|&b| b ^ key).collect()
}

/// Decodes a byte slice by applying a repeating multi-byte XOR key.
pub fn xor_decode_multi(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

/// Decodes a byte slice by subtracting a single key byte from each byte (reverses ADD encoding).
pub fn add_decode_single(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|&b| b.wrapping_sub(key)).collect()
}

/// Decodes a byte slice by subtracting a repeating multi-byte key sequence.
pub fn add_decode_multi(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, &b)| b.wrapping_sub(key[i % key.len()]))
        .collect()
}

/// Decodes a byte slice by rotating each byte right by `shift` bits (reverses ROL encoding).
pub fn rol_decode_single(data: &[u8], shift: u8) -> Vec<u8> {
    let s = (shift % 8) as u32;
    data.iter().map(|&b| b.rotate_right(s)).collect()
}

/// Check if a byte is within the printable ASCII range.
#[inline]
fn is_printable(b: u8) -> bool {
    (0x20..=0x7E).contains(&b)
}

/// Check if a byte is a valid character within a network URL.
#[inline]
fn is_url_char(b: u8) -> bool {
    is_printable(b)
        && b != b'"'
        && b != b'\''
        && b != b'<'
        && b != b'>'
        && b != b'`'
        && b != b' '
        && b != b'\\'
        && b != b'{'
        && b != b'}'
        && b != b'|'
        && b != b'^'
}

/// Inspect `decoded` starting at `offset` for a URL pattern.
fn check_url(decoded: &[u8], offset: usize) -> Option<(usize, ArtifactKind, String)> {
    let schemes: &[&[u8]] = &[b"http://", b"https://", b"ftp://"];
    for scheme in schemes {
        if decoded[offset..].starts_with(scheme) {
            let mut end = offset + scheme.len();
            while end < decoded.len() && is_url_char(decoded[end]) {
                end += 1;
            }
            // Trim trailing punctuation marks commonly attached to text boundaries
            while end > offset + scheme.len() {
                let last = decoded[end - 1];
                if last == b'.' || last == b',' || last == b';' || last == b')' || last == b']' {
                    end -= 1;
                } else {
                    break;
                }
            }
            if end - offset >= scheme.len() + 3 {
                if let Ok(url_str) = std::str::from_utf8(&decoded[offset..end]) {
                    return Some((offset, ArtifactKind::Url, url_str.to_string()));
                }
            }
        }
    }
    None
}

/// Inspect `decoded` starting at `offset` for a Windows Registry key pattern.
fn check_registry_key(decoded: &[u8], offset: usize) -> Option<(usize, ArtifactKind, String)> {
    let prefixes: &[&[u8]] = &[
        b"HKLM\\",
        b"HKCU\\",
        b"HKEY_LOCAL_MACHINE\\",
        b"HKEY_CURRENT_USER\\",
        b"HKEY_CLASSES_ROOT\\",
        b"HKEY_USERS\\",
        b"HKEY_CURRENT_CONFIG\\",
        b"Software\\Microsoft\\",
        b"SOFTWARE\\MICROSOFT\\",
    ];
    for prefix in prefixes {
        if decoded[offset..].starts_with(prefix) {
            let mut end = offset + prefix.len();
            while end < decoded.len() {
                let b = decoded[end];
                if is_printable(b) && b != b'"' && b != b'\'' && b != b'`' && b != b'<' && b != b'>'
                {
                    end += 1;
                } else {
                    break;
                }
            }
            while end > offset + prefix.len() && decoded[end - 1] == b' ' {
                end -= 1;
            }
            if let Ok(reg_str) = std::str::from_utf8(&decoded[offset..end]) {
                return Some((offset, ArtifactKind::RegistryKey, reg_str.to_string()));
            }
        }
    }
    None
}

/// Inspect `decoded` starting at `offset` for a dotted-decimal IPv4 address.
fn check_ipv4(decoded: &[u8], offset: usize) -> Option<(usize, ArtifactKind, String)> {
    if offset > 0 && (decoded[offset - 1].is_ascii_digit() || decoded[offset - 1] == b'.') {
        return None;
    }
    let mut pos = offset;
    let mut octets = 0;
    while octets < 4 && pos < decoded.len() {
        let start_num = pos;
        while pos < decoded.len() && decoded[pos].is_ascii_digit() {
            pos += 1;
        }
        let len = pos - start_num;
        if len == 0 || len > 3 {
            return None;
        }
        let num_str = std::str::from_utf8(&decoded[start_num..pos]).ok()?;
        let val: u32 = num_str.parse().ok()?;
        if val > 255 {
            return None;
        }
        octets += 1;
        if octets < 4 {
            if pos < decoded.len() && decoded[pos] == b'.' {
                pos += 1;
            } else {
                return None;
            }
        }
    }
    if octets == 4 {
        if pos < decoded.len() && (decoded[pos].is_ascii_digit() || decoded[pos] == b'.') {
            return None;
        }
        let ip_str = std::str::from_utf8(&decoded[offset..pos]).ok()?.to_string();
        return Some((offset, ArtifactKind::IPv4, ip_str));
    }
    None
}

/// Inspect `decoded` at `offset` for a Windows PE DOS/Executable header.
fn check_pe_header(decoded: &[u8], offset: usize) -> Option<(usize, ArtifactKind, String)> {
    if offset % 2 != 0 || offset + 2 > decoded.len() {
        return None;
    }
    if decoded[offset..offset + 2] != *b"MZ" {
        return None;
    }
    if offset + 64 <= decoded.len() {
        let e_lfanew = u32::from_le_bytes([
            decoded[offset + 0x3C],
            decoded[offset + 0x3D],
            decoded[offset + 0x3E],
            decoded[offset + 0x3F],
        ]) as usize;
        if (0x40..=0x1000).contains(&e_lfanew) {
            if offset + e_lfanew + 4 <= decoded.len() {
                if &decoded[offset + e_lfanew..offset + e_lfanew + 4] == b"PE\0\0" {
                    return Some((
                        offset,
                        ArtifactKind::PeHeader,
                        format!("PE Executable Header (e_lfanew=0x{e_lfanew:X})"),
                    ));
                }
            } else {
                return Some((
                    offset,
                    ArtifactKind::PeHeader,
                    format!("PE DOS Header (e_lfanew=0x{e_lfanew:X})"),
                ));
            }
        }
    } else if offset == 0 && decoded.len() >= 2 {
        return Some((
            offset,
            ArtifactKind::PeHeader,
            "PE DOS Header Magic (MZ)".to_string(),
        ));
    }
    None
}

/// Inspect `decoded` at `offset` for an ELF header magic sequence (`\x7FELF`).
fn check_elf_header(decoded: &[u8], offset: usize) -> Option<(usize, ArtifactKind, String)> {
    if offset + 4 <= decoded.len() && &decoded[offset..offset + 4] == b"\x7FELF" {
        let desc = if offset + 5 <= decoded.len() && decoded[offset + 4] == 2 {
            "ELF64 Executable Header Magic (\\x7FELF)".to_string()
        } else {
            "ELF Executable Header Magic (\\x7FELF)".to_string()
        };
        Some((offset, ArtifactKind::ElfHeader, desc))
    } else {
        None
    }
}

/// Inspect `decoded` at `offset` for Apple Mach-O header magic values.
fn check_macho_header(decoded: &[u8], offset: usize) -> Option<(usize, ArtifactKind, String)> {
    if offset + 4 <= decoded.len() {
        let magic = &decoded[offset..offset + 4];
        if magic == [0xCF, 0xFA, 0xED, 0xFE] || magic == [0xFE, 0xED, 0xFA, 0xCF] {
            return Some((
                offset,
                ArtifactKind::MachOHeader,
                "Mach-O 64-bit Header (0xFEEDFACF)".to_string(),
            ));
        }
        if magic == [0xCE, 0xFA, 0xED, 0xFE] || magic == [0xFE, 0xED, 0xFA, 0xCE] {
            return Some((
                offset,
                ArtifactKind::MachOHeader,
                "Mach-O 32-bit Header (0xFEEDFACE)".to_string(),
            ));
        }
        if magic == [0xCA, 0xFE, 0xBA, 0xBE] || magic == [0xBE, 0xBA, 0xFE, 0xCA] {
            return Some((
                offset,
                ArtifactKind::MachOHeader,
                "Mach-O Universal FAT Binary Header (0xCAFEBABE)".to_string(),
            ));
        }
    }
    None
}

/// Inspect `decoded` starting at `offset` for contiguous printable ASCII strings.
fn check_generic_string(decoded: &[u8], offset: usize) -> Option<(usize, ArtifactKind, String)> {
    if offset > 0 && is_printable(decoded[offset - 1]) {
        return None;
    }
    let mut end = offset;
    while end < decoded.len() && is_printable(decoded[end]) {
        end += 1;
    }
    let len = end - offset;
    if len >= 28 {
        let slice = &decoded[offset..end];
        let has_separator = slice
            .iter()
            .any(|&b| b == b' ' || b == b'\\' || b == b'/' || b == b'-');
        if has_separator {
            if let Ok(s) = std::str::from_utf8(slice) {
                return Some((offset, ArtifactKind::GenericString, s.to_string()));
            }
        }
    }
    None
}

/// Scans a decoded buffer for known Indicators of Compromise (URLs, IPv4, Registry keys)
/// and binary executable headers (PE, ELF, Mach-O).
pub fn classify_decoded(decoded: &[u8]) -> Vec<(usize, ArtifactKind, String)> {
    let mut results = Vec::new();
    let mut i = 0;

    while i < decoded.len() {
        if let Some((off, kind, val)) = check_pe_header(decoded, i) {
            let span = val.len().max(2);
            results.push((off, kind, val));
            i += span;
            continue;
        }
        if let Some((off, kind, val)) = check_elf_header(decoded, i) {
            results.push((off, kind, val));
            i += 4;
            continue;
        }
        if let Some((off, kind, val)) = check_macho_header(decoded, i) {
            results.push((off, kind, val));
            i += 4;
            continue;
        }
        if let Some((off, kind, val)) = check_url(decoded, i) {
            let span = val.len();
            results.push((off, kind, val));
            i += span;
            continue;
        }
        if let Some((off, kind, val)) = check_registry_key(decoded, i) {
            let span = val.len();
            results.push((off, kind, val));
            i += span;
            continue;
        }
        if let Some((off, kind, val)) = check_ipv4(decoded, i) {
            let span = val.len();
            results.push((off, kind, val));
            i += span;
            continue;
        }
        if let Some((off, kind, val)) = check_generic_string(decoded, i) {
            let span = val.len();
            results.push((off, kind, val));
            i += span;
            continue;
        }
        i += 1;
    }

    results
}

/// For each known plaintext crib, finds positions in `data` where XORing with the crib
/// yields a consistent repeating key (single-byte or multi-byte lengths 2, 4, 8, 16).
pub fn crib_drag_xor(data: &[u8], cribs: &[&[u8]]) -> Vec<(usize, Vec<u8>, String)> {
    let mut results = Vec::new();

    for &crib in cribs {
        if crib.is_empty() || data.len() < crib.len() {
            continue;
        }
        let crib_name = String::from_utf8_lossy(crib).to_string();
        let max_pos = data.len() - crib.len();

        for pos in 0..=max_pos {
            let keystream: Vec<u8> = (0..crib.len()).map(|k| data[pos + k] ^ crib[k]).collect();

            // 1. Single-byte key (L=1): all bytes match keystream[0], key != 0
            if crib.len() >= 2 && keystream.iter().all(|&b| b == keystream[0]) {
                if keystream[0] != 0 {
                    results.push((pos, vec![keystream[0]], crib_name.clone()));
                }
                continue;
            }

            // 2. 2-byte key (L=2): requires crib.len() >= 4
            if crib.len() >= 4 && (0..crib.len()).all(|k| keystream[k] == keystream[k % 2]) {
                let key2 = keystream[0..2].to_vec();
                if key2[0] != key2[1] && !key2.iter().all(|&b| b == 0) {
                    results.push((pos, key2, crib_name.clone()));
                    continue;
                }
            }

            // 3. 4-byte key (L=4): requires crib.len() >= 7
            if crib.len() >= 7 && (4..crib.len()).all(|k| keystream[k] == keystream[k % 4]) {
                let key4 = keystream[0..4].to_vec();
                if !key4.iter().all(|&b| b == 0) {
                    let is_p1 = key4.iter().all(|&b| b == key4[0]);
                    let is_p2 = key4[0] == key4[2] && key4[1] == key4[3];
                    if !is_p1 && !is_p2 {
                        results.push((pos, key4, crib_name.clone()));
                        continue;
                    }
                }
            }

            // 4. 8-byte key (L=8): requires crib.len() >= 12
            if crib.len() >= 12 && (8..crib.len()).all(|k| keystream[k] == keystream[k % 8]) {
                let key8 = keystream[0..8].to_vec();
                if !key8.iter().all(|&b| b == 0) {
                    let is_p1 = key8.iter().all(|&b| b == key8[0]);
                    let is_p2 = (0..8).all(|k| key8[k] == key8[k % 2]);
                    let is_p4 = (0..8).all(|k| key8[k] == key8[k % 4]);
                    if !is_p1 && !is_p2 && !is_p4 {
                        results.push((pos, key8, crib_name.clone()));
                        continue;
                    }
                }
            }

            // 5. 16-byte key (L=16): requires crib.len() >= 20
            if crib.len() >= 20 && (16..crib.len()).all(|k| keystream[k] == keystream[k % 16]) {
                let key16 = keystream[0..16].to_vec();
                if !key16.iter().all(|&b| b == 0) {
                    let is_p1 = key16.iter().all(|&b| b == key16[0]);
                    let is_p2 = (0..16).all(|k| key16[k] == key16[k % 2]);
                    let is_p4 = (0..16).all(|k| key16[k] == key16[k % 4]);
                    let is_p8 = (0..16).all(|k| key16[k] == key16[k % 8]);
                    if !is_p1 && !is_p2 && !is_p4 && !is_p8 {
                        results.push((pos, key16, crib_name.clone()));
                    }
                }
            }
        }
    }

    // Deduplicate identical (pos, key) occurrences
    let mut deduped: Vec<(usize, Vec<u8>, String)> = Vec::new();
    for item in results {
        if !deduped.iter().any(|d| d.0 == item.0 && d.1 == item.1) {
            deduped.push(item);
        }
    }
    deduped
}
