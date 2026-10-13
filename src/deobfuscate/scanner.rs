// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! High-level scanner orchestrator for single-byte, multi-byte, ADD, and ROL deobfuscation.

use std::fs;
use std::path::Path;

use zeroize::Zeroize;

use crate::deobfuscate::decoder::{classify_decoded, crib_drag_xor, xor_decode_single};
use crate::deobfuscate::types::{
    ArtifactKind, DecodedArtifact, DeobfuscateMethod, DeobfuscateReport,
};
use crate::elf::parse_elf;
use crate::error::Result;
use crate::macho::parse_macho;
use crate::pe::parse_pe;

/// Known plaintext cribs for automated XOR key recovery.
pub const DEFAULT_CRIBS: &[&[u8]] = &[
    b"http://",
    b"https://",
    b"MZ",
    b"\x7FELF",
    b"HKLM\\",
    b"HKCU\\",
    b"Software\\",
];

/// Returns a default confidence score based on the semantic payload classification.
fn confidence_for_kind(kind: ArtifactKind) -> f32 {
    match kind {
        ArtifactKind::PeHeader | ArtifactKind::ElfHeader | ArtifactKind::MachOHeader => 0.98,
        ArtifactKind::Url => 0.95,
        ArtifactKind::RegistryKey => 0.92,
        ArtifactKind::IPv4 => 0.85,
        ArtifactKind::GenericString => 0.70,
    }
}

/// Deduplicate overlapping findings, preserving higher-confidence and longer matches.
fn deduplicate_artifacts(artifacts: Vec<DecodedArtifact>) -> Vec<DecodedArtifact> {
    let mut deduped: Vec<DecodedArtifact> = Vec::new();

    for item in artifacts {
        if let Some(pos) = deduped.iter().position(|existing| {
            existing.method == item.method
                && existing.kind == item.kind
                && (existing.offset == item.offset
                    || (item.offset < existing.offset + existing.length
                        && existing.offset < item.offset + item.length
                        && (existing.content.contains(&item.content)
                            || item.content.contains(&existing.content))))
        }) {
            if item.content.len() > deduped[pos].content.len()
                || item.confidence > deduped[pos].confidence
            {
                deduped[pos] = item;
            }
        } else {
            deduped.push(item);
        }
    }

    // Sort descending by confidence, then ascending by file offset
    deduped.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.offset.cmp(&b.offset))
    });

    deduped
}

/// Scans arbitrary binary bytes using brute-force single-byte XOR, ADD, ROL,
/// known-plaintext crib dragging, and derived multi-byte XOR deobfuscation.
pub fn scan_deobfuscate_bytes(data: &[u8]) -> DeobfuscateReport {
    let mut artifacts: Vec<DecodedArtifact> = Vec::new();

    let window_size = 256usize;
    let stride = 64usize;

    // 1. Sliding window brute-force: Single-byte XOR, ADD, and ROL
    let mut win_start = 0;
    while win_start < data.len() {
        let win_end = (win_start + window_size).min(data.len());
        let window = &data[win_start..win_end];
        let win_len = window.len();

        let mut scratch = vec![0u8; win_len];

        // 1a. Single-byte XOR brute-force (keys 0x01..=0xFF)
        for key in 1u8..=255 {
            let mut printable_count = 0;
            for (i, &b) in window.iter().enumerate() {
                let d = b ^ key;
                scratch[i] = d;
                if (0x20..=0x7E).contains(&d) || d == b'\r' || d == b'\n' || d == b'\t' {
                    printable_count += 1;
                }
            }
            let printable_pct = (printable_count * 100) / win_len;
            let has_magic = scratch.starts_with(b"MZ") || scratch.starts_with(b"\x7FELF");

            if printable_pct >= 30 || has_magic {
                let hits = classify_decoded(&scratch);
                for (local_off, kind, content) in hits {
                    let global_off = win_start + local_off;
                    let conf = confidence_for_kind(kind);
                    artifacts.push(DecodedArtifact {
                        offset: global_off,
                        length: content.len(),
                        method: DeobfuscateMethod::XorSingle { key },
                        kind,
                        content,
                        confidence: conf,
                        section_name: None,
                        relative_virtual_address: None,
                    });
                }
            }
        }

        // 1b. Single-byte ADD brute-force (keys 0x01..=0xFF)
        for key in 1u8..=255 {
            let mut printable_count = 0;
            for (i, &b) in window.iter().enumerate() {
                let d = b.wrapping_sub(key);
                scratch[i] = d;
                if (0x20..=0x7E).contains(&d) || d == b'\r' || d == b'\n' || d == b'\t' {
                    printable_count += 1;
                }
            }
            let printable_pct = (printable_count * 100) / win_len;
            let has_magic = scratch.starts_with(b"MZ") || scratch.starts_with(b"\x7FELF");

            if printable_pct >= 30 || has_magic {
                let hits = classify_decoded(&scratch);
                for (local_off, kind, content) in hits {
                    let global_off = win_start + local_off;
                    let conf = confidence_for_kind(kind);
                    artifacts.push(DecodedArtifact {
                        offset: global_off,
                        length: content.len(),
                        method: DeobfuscateMethod::AddSingle { key },
                        kind,
                        content,
                        confidence: conf,
                        section_name: None,
                        relative_virtual_address: None,
                    });
                }
            }
        }

        // 1c. ROL brute-force (shifts 1..=7)
        for shift in 1u8..=7 {
            let mut printable_count = 0;
            for (i, &b) in window.iter().enumerate() {
                let d = b.rotate_right(shift as u32);
                scratch[i] = d;
                if (0x20..=0x7E).contains(&d) || d == b'\r' || d == b'\n' || d == b'\t' {
                    printable_count += 1;
                }
            }
            let printable_pct = (printable_count * 100) / win_len;
            let has_magic = scratch.starts_with(b"MZ") || scratch.starts_with(b"\x7FELF");

            if printable_pct >= 30 || has_magic {
                let hits = classify_decoded(&scratch);
                for (local_off, kind, content) in hits {
                    let global_off = win_start + local_off;
                    let conf = confidence_for_kind(kind);
                    artifacts.push(DecodedArtifact {
                        offset: global_off,
                        length: content.len(),
                        method: DeobfuscateMethod::RolSingle { shift },
                        kind,
                        content,
                        confidence: conf,
                        section_name: None,
                        relative_virtual_address: None,
                    });
                }
            }
        }
        scratch.as_mut_slice().zeroize();

        if win_end == data.len() {
            break;
        }
        win_start += stride;
    }

    // 2. Crib-drag XOR and Multi-byte XOR key recovery
    let crib_hits = crib_drag_xor(data, DEFAULT_CRIBS);
    for (crib_off, cand_key, _crib_name) in crib_hits {
        if cand_key.len() == 1 {
            let key = cand_key[0];
            let span_start = crib_off.saturating_sub(64);
            let span_end = (crib_off + 256).min(data.len());
            let slice = &data[span_start..span_end];
            let mut decoded = xor_decode_single(slice, key);
            let hits = classify_decoded(&decoded);
            for (local_off, kind, content) in hits {
                let global_off = span_start + local_off;
                let conf = confidence_for_kind(kind);
                artifacts.push(DecodedArtifact {
                    offset: global_off,
                    length: content.len(),
                    method: DeobfuscateMethod::XorSingle { key },
                    kind,
                    content,
                    confidence: conf,
                    section_name: None,
                    relative_virtual_address: None,
                });
            }
            decoded.zeroize();
        } else {
            // Multi-byte key: decode surrounding span aligned to crib_off phase
            let span_start = crib_off.saturating_sub(128);
            let span_end = (crib_off + 512).min(data.len());
            let slice = &data[span_start..span_end];

            let mut decoded = Vec::with_capacity(slice.len());
            for (idx, &b) in slice.iter().enumerate() {
                let global_i = span_start + idx;
                let phase = (global_i as isize - crib_off as isize)
                    .rem_euclid(cand_key.len() as isize) as usize;
                decoded.push(b ^ cand_key[phase]);
            }

            let hits = classify_decoded(&decoded);
            for (local_off, kind, content) in hits {
                let global_off = span_start + local_off;
                let conf = confidence_for_kind(kind);
                artifacts.push(DecodedArtifact {
                    offset: global_off,
                    length: content.len(),
                    method: DeobfuscateMethod::XorMulti {
                        key: cand_key.clone(),
                    },
                    kind,
                    content,
                    confidence: conf,
                    section_name: None,
                    relative_virtual_address: None,
                });
            }
            decoded.zeroize();
        }
    }

    // Correlate artifacts with PE/ELF/Mach-O sections and relative virtual addresses
    let mut binary_format = "Raw Binary".to_string();

    if let Ok(pe_info) = parse_pe(data) {
        binary_format = format!("PE ({})", pe_info.format);
        for art in &mut artifacts {
            for sec in &pe_info.sections {
                let start = sec.raw_offset as usize;
                let end = start.saturating_add(sec.raw_size as usize);
                if art.offset >= start && art.offset < end {
                    art.section_name = Some(sec.name.clone());
                    let delta = (art.offset - start) as u64;
                    art.relative_virtual_address = Some(sec.virtual_address as u64 + delta);
                    break;
                }
            }
        }
    } else if let Ok(elf_info) = parse_elf(data) {
        binary_format = format!("ELF ({})", elf_info.os_abi);
        for art in &mut artifacts {
            for sec in &elf_info.sections {
                let start = sec.offset as usize;
                let end = start.saturating_add(sec.size as usize);
                if art.offset >= start && art.offset < end {
                    art.section_name = Some(sec.name.clone());
                    let delta = (art.offset - start) as u64;
                    art.relative_virtual_address = Some(sec.addr + delta);
                    break;
                }
            }
        }
    } else if let Ok(macho_info) = parse_macho(data) {
        binary_format = macho_info.format;
        for art in &mut artifacts {
            for arch in &macho_info.architectures {
                for sec in &arch.sections {
                    let start = sec.offset as usize;
                    let end = start.saturating_add(sec.size as usize);
                    if art.offset >= start && art.offset < end {
                        art.section_name = Some(format!("{}/{}", sec.segname, sec.sectname));
                        let delta = (art.offset - start) as u64;
                        art.relative_virtual_address = Some(sec.addr + delta);
                        break;
                    }
                }
            }
        }
    }

    let deduped = deduplicate_artifacts(artifacts);

    DeobfuscateReport {
        file_path: None,
        file_size: data.len(),
        binary_format,
        total_matches: deduped.len(),
        artifacts: deduped,
        scan_methods_applied: vec![
            "SingleByteXor".to_string(),
            "SingleByteAdd".to_string(),
            "SingleByteRol".to_string(),
            "CribDragXor".to_string(),
            "MultiByteXor".to_string(),
        ],
    }
}

/// Reads a binary file from `path` and performs comprehensive deobfuscation scanning.
pub fn scan_deobfuscate_file(path: &Path) -> Result<DeobfuscateReport> {
    let data = fs::read(path)?;
    let mut report = scan_deobfuscate_bytes(&data);
    report.file_path = Some(path.display().to_string());
    Ok(report)
}
