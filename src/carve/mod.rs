// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod base64;
pub mod classifier;
pub mod hex;
pub mod types;

pub use types::{CarveEncodingKind, CarveOptions, CarveReport, CarvedPayload, DecodedPayloadKind};

use std::fs;
use std::path::{Path, PathBuf};

use crate::elf::parse_elf;
use crate::error::{Result, SentinelError};
use crate::macho::parse_macho;
use crate::pe::parse_pe;

/// Carves and decodes embedded payloads from a byte slice with section and RVA resolution.
pub fn carve_payloads_bytes(
    data: &[u8],
    options: &CarveOptions,
    path: Option<&Path>,
) -> Result<CarveReport> {
    let file_path = path
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<memory>".to_string());
    let file_size = data.len();

    let mut raw_candidates = Vec::new();

    // 1. Gather Base64 candidates
    if options.scan_base64 {
        let b64_candidates =
            base64::scan_base64_candidates(data, options.min_length, options.max_payloads);
        raw_candidates.extend(b64_candidates);
    }

    // 2. Gather Hex candidates
    if options.scan_hex && raw_candidates.len() < options.max_payloads {
        let remaining = options.max_payloads.saturating_sub(raw_candidates.len());
        let hex_candidates = hex::scan_hex_candidates(data, options.min_length, remaining);
        raw_candidates.extend(hex_candidates);
    }

    // Classify each candidate before deduplication to evaluate semantic confidence
    let mut classified = Vec::with_capacity(raw_candidates.len());
    for (idx, raw) in raw_candidates.into_iter().enumerate() {
        let mut carved = classifier::classify_payload(
            idx + 1,
            raw.encoding,
            raw.file_offset,
            raw.encoded_length,
            raw.decoded_bytes,
        );

        // Section & RVA mapping
        resolve_container_section(data, &mut carved);
        classified.push(carved);
    }

    // Sort by file_offset ascending, and then by confidence_score descending
    classified.sort_by(|a, b| {
        a.file_offset
            .cmp(&b.file_offset)
            .then_with(|| b.confidence_score.cmp(&a.confidence_score))
    });

    // Deduplicate candidates that start at identical offsets and lengths, keeping the higher-confidence interpretation
    classified
        .dedup_by(|a, b| a.file_offset == b.file_offset && a.encoded_length == b.encoded_length);

    // Limit to max_payloads and re-assign 1-based sequential IDs
    if classified.len() > options.max_payloads {
        classified.truncate(options.max_payloads);
    }
    for (i, p) in classified.iter_mut().enumerate() {
        p.id = i + 1;
    }
    let payloads = classified;

    // Extract payloads to disk if extract_dir is specified
    if let Some(ref out_dir) = options.extract_dir {
        extract_payloads_to_dir(&payloads, out_dir)?;
    }

    // Compute summary counts
    let mut nested_executables_count = 0;
    let mut scripts_count = 0;
    let mut iocs_count = 0;
    let mut rwx_anomalies_count = 0;

    for p in &payloads {
        match p.payload_kind {
            DecodedPayloadKind::NestedPe { .. }
            | DecodedPayloadKind::NestedElf { .. }
            | DecodedPayloadKind::NestedMacho { .. } => {
                nested_executables_count += 1;
            }
            DecodedPayloadKind::ScriptPowerShell { .. }
            | DecodedPayloadKind::ScriptShell { .. }
            | DecodedPayloadKind::ScriptBatch { .. } => {
                scripts_count += 1;
            }
            DecodedPayloadKind::IocNetwork { .. } => {
                iocs_count += 1;
            }
            _ => {}
        }
        if p.is_rwx_section {
            rwx_anomalies_count += 1;
        }
    }

    let total_carved = payloads.len();
    Ok(CarveReport {
        file_path,
        file_size,
        total_carved,
        payloads,
        nested_executables_count,
        scripts_count,
        iocs_count,
        rwx_anomalies_count,
    })
}

/// Carves and decodes embedded payloads from a target file on disk.
pub fn carve_payloads_file(file_path: &Path, options: &CarveOptions) -> Result<CarveReport> {
    let bytes = fs::read(file_path)?;
    carve_payloads_bytes(&bytes, options, Some(file_path))
}

/// Resolves whether a file offset falls within a known PE, ELF, or Mach-O section and maps RVA.
fn resolve_container_section(data: &[u8], payload: &mut CarvedPayload) {
    let offset = payload.file_offset as u64;

    // Check PE
    if let Ok(pe) = parse_pe(data) {
        for s in &pe.sections {
            let start = s.raw_offset as u64;
            let end = start + s.raw_size as u64;
            if offset >= start && offset < end {
                payload.section_name = Some(s.name.clone());
                payload.rva = Some(s.virtual_address as u64 + (offset - start));
                payload.is_rwx_section = s.rwx_anomaly;
                return;
            }
        }
    }

    // Check ELF
    if let Ok(elf) = parse_elf(data) {
        for s in &elf.sections {
            let start = s.offset;
            let end = start + s.size;
            if offset >= start && offset < end {
                payload.section_name = Some(s.name.clone());
                payload.rva = Some(s.addr + (offset - start));
                payload.is_rwx_section = s.rwx_anomaly;
                return;
            }
        }
    }

    // Check Mach-O
    if let Ok(macho) = parse_macho(data) {
        for arch in &macho.architectures {
            for sec in &arch.sections {
                let start = sec.offset as u64;
                let end = start + sec.size;
                if offset >= start && offset < end {
                    payload.section_name = Some(format!("{}/{}", sec.segname, sec.sectname));
                    payload.rva = Some(sec.addr + (offset - start));
                    payload.is_rwx_section = sec.rwx_anomaly;
                    return;
                }
            }
        }
    }
}

/// Safely extracts carved payloads to a destination directory with path traversal guards.
pub fn extract_payloads_to_dir(payloads: &[CarvedPayload], out_dir: &Path) -> Result<Vec<PathBuf>> {
    fs::create_dir_all(out_dir)?;

    let mut written = Vec::new();
    for p in payloads {
        let ext = match p.payload_kind {
            DecodedPayloadKind::NestedPe { is_dll, .. } => {
                if is_dll {
                    "dll"
                } else {
                    "exe"
                }
            }
            DecodedPayloadKind::NestedElf { .. } => "elf",
            DecodedPayloadKind::NestedMacho { .. } => "macho",
            DecodedPayloadKind::ArchiveZip => "zip",
            DecodedPayloadKind::ArchiveGzip => "gz",
            DecodedPayloadKind::Archive7z => "7z",
            DecodedPayloadKind::DocumentPdf => "pdf",
            DecodedPayloadKind::ScriptPowerShell { .. } => "ps1",
            DecodedPayloadKind::ScriptShell { .. } => "sh",
            DecodedPayloadKind::ScriptBatch { .. } => "bat",
            DecodedPayloadKind::TextOrData { .. } => "txt",
            _ => "bin",
        };

        let file_name = format!("payload_{:04}_offset_0x{:X}.{}", p.id, p.file_offset, ext);
        let dest = out_dir.join(&file_name);

        // Security check: ensure path does not escape destination directory
        if !dest.starts_with(out_dir) {
            return Err(SentinelError::BoundsError(
                "Path traversal attempt detected in payload extraction destination".to_string(),
            ));
        }

        fs::write(&dest, &p.decoded_bytes)?;
        written.push(dest);
    }

    Ok(written)
}
