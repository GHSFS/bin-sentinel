// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod compare;
pub mod engine;
pub mod types;

use std::fs;
use std::path::Path;

use crate::error::{Result, SentinelError};

pub use compare::{
    compare_digests, compare_sections, levenshtein_distance, longest_common_substring,
    score_strings, score_to_status,
};
pub use engine::{compute_fuzzy_digest, select_block_size, RollingHash};
pub use types::{
    BinaryFormat, FuzzyCompareReport, FuzzyDigest, FuzzyHashReport, SectionComparison,
    SectionFuzzyHash,
};

/// Inspects bytes to detect executable format and extract section-level fuzzy hashes.
pub fn inspect_sections_and_format(bytes: &[u8]) -> (BinaryFormat, Vec<SectionFuzzyHash>) {
    // 1. Try PE parsing
    if let Ok(pe) = crate::pe::parse_pe(bytes) {
        let mut sections = Vec::new();
        for sec in &pe.sections {
            let offset = sec.raw_offset as usize;
            let size = sec.raw_size as usize;
            if size > 0 && offset.saturating_add(size) <= bytes.len() {
                let sec_bytes = &bytes[offset..offset + size];
                let fuzzy_hash = compute_fuzzy_digest(sec_bytes);
                sections.push(SectionFuzzyHash {
                    name: sec.name.clone(),
                    virtual_address: sec.virtual_address as u64,
                    raw_size: sec.raw_size as u64,
                    entropy: sec.entropy,
                    fuzzy_hash,
                });
            }
        }
        return (BinaryFormat::Pe, sections);
    }

    // 2. Try ELF parsing
    if let Ok(elf) = crate::elf::parse_elf(bytes) {
        let mut sections = Vec::new();
        for sec in &elf.sections {
            let offset = sec.offset as usize;
            let size = sec.size as usize;
            if size > 0 && offset.saturating_add(size) <= bytes.len() {
                let sec_bytes = &bytes[offset..offset + size];
                let fuzzy_hash = compute_fuzzy_digest(sec_bytes);
                sections.push(SectionFuzzyHash {
                    name: sec.name.clone(),
                    virtual_address: sec.addr,
                    raw_size: sec.size,
                    entropy: sec.entropy,
                    fuzzy_hash,
                });
            }
        }
        return (BinaryFormat::Elf, sections);
    }

    // 3. Try Mach-O parsing
    if let Ok(macho) = crate::macho::parse_macho(bytes) {
        let mut sections = Vec::new();
        if let Some(arch) = macho.architectures.first() {
            for sec in &arch.sections {
                let offset = sec.offset as usize;
                let size = sec.size as usize;
                if size > 0 && offset.saturating_add(size) <= bytes.len() {
                    let sec_bytes = &bytes[offset..offset + size];
                    let fuzzy_hash = compute_fuzzy_digest(sec_bytes);
                    sections.push(SectionFuzzyHash {
                        name: format!("{}/{}", sec.segname, sec.sectname),
                        virtual_address: sec.addr,
                        raw_size: sec.size,
                        entropy: sec.entropy,
                        fuzzy_hash,
                    });
                }
            }
        }
        return (BinaryFormat::MachO, sections);
    }

    // 4. Default raw format
    (BinaryFormat::Raw, Vec::new())
}

/// Computes a comprehensive fuzzy hash report for an in-memory byte buffer.
pub fn hash_binary_bytes(file_path: &str, bytes: &[u8]) -> FuzzyHashReport {
    let (format, sections) = inspect_sections_and_format(bytes);
    let fuzzy_hash = compute_fuzzy_digest(bytes);

    FuzzyHashReport {
        file_path: file_path.to_string(),
        file_size: bytes.len() as u64,
        format,
        fuzzy_hash,
        sections,
    }
}

/// Reads a binary file from disk and computes its complete fuzzy hash report.
pub fn hash_binary_file(path: &Path) -> Result<FuzzyHashReport> {
    let bytes = fs::read(path).map_err(|e| {
        SentinelError::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to read target file '{}': {}", path.display(), e),
        ))
    })?;
    Ok(hash_binary_bytes(&path.to_string_lossy(), &bytes))
}

/// Reads two files from disk, computes their fuzzy hashes and evaluates full similarity.
pub fn compare_binary_files(path1: &Path, path2: &Path) -> Result<FuzzyCompareReport> {
    let r1 = hash_binary_file(path1)?;
    let r2 = hash_binary_file(path2)?;

    let overall_score = compare_digests(&r1.fuzzy_hash, &r2.fuzzy_hash);
    let overall_status = format!("{} ({}%)", score_to_status(overall_score), overall_score);

    let section_comparisons = compare_sections(&r1.sections, &r2.sections);

    Ok(FuzzyCompareReport {
        file1_path: r1.file_path,
        file1_size: r1.file_size,
        file1_format: r1.format,
        file1_hash: r1.fuzzy_hash,
        file2_path: r2.file_path,
        file2_size: r2.file_size,
        file2_format: r2.format,
        file2_hash: r2.fuzzy_hash,
        overall_score,
        overall_status,
        section_comparisons,
    })
}
