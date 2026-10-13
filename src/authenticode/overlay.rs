// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::OverlayInfo;
use crate::entropy::shannon_entropy;
use crate::pe::{DataDirectory, SectionInfo};

/// Computes the legitimate physical boundary of a PE image and detects appended EOF overlay data.
///
/// In valid PE files, the legitimate image terminates either at the end of the highest raw section,
/// or at the end of the Certificate Table if present. Any data appended beyond this boundary is an
/// EOF overlay, frequently used by installers (NSIS/Inno Setup), self-extracting archives, or malware.
pub fn detect_overlay(
    data: &[u8],
    sections: &[SectionInfo],
    sec_dir: Option<&DataDirectory>,
) -> (OverlayInfo, usize) {
    let max_section_end = sections
        .iter()
        .map(|s| (s.raw_offset as usize).saturating_add(s.raw_size as usize))
        .max()
        .unwrap_or(0);

    let cert_end = if let Some(dir) = sec_dir {
        if dir.virtual_address > 0 && dir.size > 0 {
            (dir.virtual_address as usize).saturating_add(dir.size as usize)
        } else {
            0
        }
    } else {
        0
    };

    let expected_image_size = max_section_end.max(cert_end);

    if data.len() > expected_image_size && expected_image_size > 0 {
        let overlay_offset = expected_image_size;
        let overlay_slice = &data[overlay_offset..];
        let overlay_size = overlay_slice.len();
        let raw_entropy = shannon_entropy(overlay_slice);
        let entropy = (raw_entropy * 10000.0).round() / 10000.0;
        let ratio_percent = ((overlay_size as f64 / data.len() as f64) * 10000.0).round() / 100.0;
        let classification = classify_overlay(overlay_slice, entropy);

        (
            OverlayInfo {
                detected: true,
                offset: overlay_offset,
                size: overlay_size,
                entropy,
                ratio_percent,
                classification,
            },
            expected_image_size,
        )
    } else {
        (
            OverlayInfo {
                detected: false,
                offset: expected_image_size,
                size: 0,
                entropy: 0.0,
                ratio_percent: 0.0,
                classification: "None".to_string(),
            },
            expected_image_size,
        )
    }
}

fn classify_overlay(slice: &[u8], entropy: f64) -> String {
    if slice.len() >= 4 && (&slice[..4] == b"PK\x03\x04" || &slice[..4] == b"PK\x05\x06") {
        return "ZIP Archive (PK)".to_string();
    }
    if slice.len() >= 6 && &slice[..6] == b"7z\xBC\xAF\x27\x1C" {
        return "7-Zip Archive (7z)".to_string();
    }
    if slice.len() >= 7 && &slice[..7] == b"Rar!\x1A\x07\x00" {
        return "RAR Archive (RAR 4.x)".to_string();
    }
    if slice.len() >= 8 && &slice[..8] == b"Rar!\x1A\x07\x01\x00" {
        return "RAR Archive (RAR 5.x)".to_string();
    }
    if slice.len() >= 3 && &slice[..2] == b"\x1F\x8B" {
        return "GZIP Compressed Data".to_string();
    }
    if slice.len() >= 3 && &slice[..3] == b"BZh" {
        return "BZIP2 Compressed Data".to_string();
    }
    if slice.len() >= 6 && &slice[..6] == b"\xFD7zXZ\x00" {
        return "XZ Compressed Data".to_string();
    }
    if slice.len() >= 2 && &slice[..2] == b"MZ" {
        return "Nested PE Executable (MZ)".to_string();
    }
    if slice.len() >= 4 && &slice[..4] == b"\x7FELF" {
        return "Nested ELF Binary".to_string();
    }
    if slice.len() >= 4
        && (&slice[..4] == b"\xCA\xFE\xBA\xBE" || &slice[..4] == b"\xFE\xED\xFA\xCF")
    {
        return "Nested Mach-O Binary".to_string();
    }
    if slice.len() >= 4 && &slice[..4] == b"%PDF" {
        return "Nested PDF Document".to_string();
    }
    if slice.len() >= 8 && &slice[..8] == b"\x89PNG\r\n\x1a\n" {
        return "Nested PNG Image".to_string();
    }

    if entropy >= 7.2 {
        "High-Entropy (Encrypted / Compressed Payload)".to_string()
    } else if entropy < 2.0 {
        "Low-Entropy (Null-Padding / Structured Data)".to_string()
    } else {
        "Binary Data Overlay".to_string()
    }
}
