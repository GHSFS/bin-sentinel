// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fs;
use std::path::Path;

use crate::diff::types::{
    BinaryFormat, DiffHunk, DiffReport, MitigationChange, MitigationsDiff, SectionDiff,
};
use crate::elf::parse_elf;
use crate::error::Result;
use crate::macho::parser::parse_macho;
use crate::patch::sha256_hex;
use crate::pe::parse_pe;

/// Compares two binary buffers and builds a complete structural diff report.
pub fn diff_binaries(
    orig_data: &[u8],
    mod_data: &[u8],
    orig_name: Option<&str>,
    mod_name: Option<&str>,
) -> Result<DiffReport> {
    let orig_sha = sha256_hex(orig_data);
    let mod_sha = sha256_hex(mod_data);

    let format = detect_format(orig_data, mod_data);
    let raw_hunks = find_differing_hunks(orig_data, mod_data);
    let total_differing: usize = raw_hunks.iter().map(|h| h.length).sum();

    let (hunks, section_diffs, mitigations_diff) = match format {
        BinaryFormat::Pe => resolve_pe_diff(orig_data, mod_data, &raw_hunks),
        BinaryFormat::Elf => resolve_elf_diff(orig_data, mod_data, &raw_hunks),
        BinaryFormat::Macho => resolve_macho_diff(orig_data, mod_data, &raw_hunks),
        BinaryFormat::Unknown => {
            let simple_hunks = raw_hunks
                .into_iter()
                .map(|h| DiffHunk {
                    offset: h.offset,
                    length: h.length,
                    orig_bytes_hex: h.orig_bytes_hex,
                    mod_bytes_hex: h.mod_bytes_hex,
                    section_name: None,
                    rva: None,
                })
                .collect();
            (simple_hunks, Vec::new(), None)
        }
    };

    Ok(DiffReport {
        original_path: orig_name.unwrap_or("<original>").to_string(),
        modified_path: mod_name.unwrap_or("<modified>").to_string(),
        original_size: orig_data.len(),
        modified_size: mod_data.len(),
        original_sha256: orig_sha,
        modified_sha256: mod_sha,
        format,
        total_differing_bytes: total_differing,
        hunk_count: hunks.len(),
        hunks,
        section_diffs,
        mitigations_diff,
    })
}

/// Reads two files from disk and performs structural binary diffing.
pub fn diff_files(orig_path: &Path, mod_path: &Path) -> Result<DiffReport> {
    let orig_data = fs::read(orig_path)?;
    let mod_data = fs::read(mod_path)?;
    diff_binaries(
        &orig_data,
        &mod_data,
        Some(&orig_path.to_string_lossy()),
        Some(&mod_path.to_string_lossy()),
    )
}

struct RawHunk {
    offset: usize,
    length: usize,
    orig_bytes_hex: String,
    mod_bytes_hex: String,
}

#[derive(Clone)]
struct SectionSpan {
    name: String,
    file_offset: usize,
    file_size: usize,
    rva_base: u64,
    entropy: f64,
}

fn find_differing_hunks(orig: &[u8], modified: &[u8]) -> Vec<RawHunk> {
    let max_len = orig.len().max(modified.len());
    let mut hunks = Vec::new();
    let mut in_diff = false;
    let mut start_idx = 0;

    for i in 0..max_len {
        let b_orig = orig.get(i);
        let b_mod = modified.get(i);
        let differs = b_orig != b_mod;

        if differs {
            if !in_diff {
                in_diff = true;
                start_idx = i;
            }
        } else if in_diff {
            in_diff = false;
            let len = i - start_idx;
            let o_slice = if start_idx < orig.len() {
                &orig[start_idx..i.min(orig.len())]
            } else {
                &[]
            };
            let m_slice = if start_idx < modified.len() {
                &modified[start_idx..i.min(modified.len())]
            } else {
                &[]
            };
            hunks.push(RawHunk {
                offset: start_idx,
                length: len,
                orig_bytes_hex: hex::encode_upper(o_slice),
                mod_bytes_hex: hex::encode_upper(m_slice),
            });
        }
    }

    if in_diff {
        let len = max_len - start_idx;
        let o_slice = if start_idx < orig.len() {
            &orig[start_idx..orig.len()]
        } else {
            &[]
        };
        let m_slice = if start_idx < modified.len() {
            &modified[start_idx..modified.len()]
        } else {
            &[]
        };
        hunks.push(RawHunk {
            offset: start_idx,
            length: len,
            orig_bytes_hex: hex::encode_upper(o_slice),
            mod_bytes_hex: hex::encode_upper(m_slice),
        });
    }

    hunks
}

fn detect_format(orig: &[u8], modified: &[u8]) -> BinaryFormat {
    if parse_pe(orig).is_ok() || parse_pe(modified).is_ok() {
        return BinaryFormat::Pe;
    }
    if parse_elf(orig).is_ok() || parse_elf(modified).is_ok() {
        return BinaryFormat::Elf;
    }
    if parse_macho(orig).is_ok() || parse_macho(modified).is_ok() {
        return BinaryFormat::Macho;
    }
    BinaryFormat::Unknown
}

fn correlate_sections(
    raw_hunks: &[RawHunk],
    orig_spans: &[SectionSpan],
    mod_spans: &[SectionSpan],
) -> (Vec<DiffHunk>, Vec<SectionDiff>) {
    let ref_spans = if !orig_spans.is_empty() {
        orig_spans
    } else {
        mod_spans
    };

    let hunks = raw_hunks
        .iter()
        .map(|h| {
            let mut sec_name = None;
            let mut rva = None;
            for s in ref_spans {
                let s_end = s.file_offset.saturating_add(s.file_size);
                if h.offset >= s.file_offset && h.offset < s_end {
                    sec_name = Some(s.name.clone());
                    let delta = (h.offset - s.file_offset) as u64;
                    rva = Some(s.rva_base + delta);
                    break;
                }
            }
            DiffHunk {
                offset: h.offset,
                length: h.length,
                orig_bytes_hex: h.orig_bytes_hex.clone(),
                mod_bytes_hex: h.mod_bytes_hex.clone(),
                section_name: sec_name,
                rva,
            }
        })
        .collect();

    let mut section_diffs = Vec::new();
    for s in orig_spans {
        let mod_s = mod_spans.iter().find(|m| m.name == s.name);
        let o_ent = s.entropy;
        let m_ent = mod_s.map(|m| m.entropy);
        let delta = m_ent.map(|m| ((m - o_ent) * 10000.0).round() / 10000.0);
        let s_end = s.file_offset.saturating_add(s.file_size);

        let diff_bytes: usize = raw_hunks
            .iter()
            .filter(|h| h.offset >= s.file_offset && h.offset < s_end)
            .map(|h| h.length)
            .sum();
        let hunk_count = raw_hunks
            .iter()
            .filter(|h| h.offset >= s.file_offset && h.offset < s_end)
            .count();

        section_diffs.push(SectionDiff {
            name: s.name.clone(),
            orig_entropy: Some(o_ent),
            mod_entropy: m_ent,
            entropy_delta: delta,
            differing_bytes: diff_bytes,
            hunk_count,
        });
    }

    (hunks, section_diffs)
}

fn pe_to_spans(pe: Option<&crate::pe::PeInfo>) -> Vec<SectionSpan> {
    pe.map(|p| {
        p.sections
            .iter()
            .map(|s| SectionSpan {
                name: s.name.clone(),
                file_offset: s.raw_offset as usize,
                file_size: s.raw_size as usize,
                rva_base: s.virtual_address as u64,
                entropy: s.entropy,
            })
            .collect()
    })
    .unwrap_or_default()
}

fn resolve_pe_diff(
    orig: &[u8],
    modified: &[u8],
    raw_hunks: &[RawHunk],
) -> (Vec<DiffHunk>, Vec<SectionDiff>, Option<MitigationsDiff>) {
    let pe_orig = parse_pe(orig).ok();
    let pe_mod = parse_pe(modified).ok();

    let o_spans = pe_to_spans(pe_orig.as_ref());
    let m_spans = pe_to_spans(pe_mod.as_ref());

    let (hunks, section_diffs) = correlate_sections(raw_hunks, &o_spans, &m_spans);

    let mitigations_diff = pe_orig.as_ref().and_then(|o| {
        pe_mod.as_ref().and_then(|m| {
            let mut changes = Vec::new();
            if o.mitigations.aslr != m.mitigations.aslr {
                changes.push(MitigationChange {
                    mitigation: "ASLR (Dynamic Base)".into(),
                    before: o.mitigations.aslr.to_string(),
                    after: m.mitigations.aslr.to_string(),
                });
            }
            if o.mitigations.high_entropy_va != m.mitigations.high_entropy_va {
                changes.push(MitigationChange {
                    mitigation: "High Entropy VA (64-bit ASLR)".into(),
                    before: o.mitigations.high_entropy_va.to_string(),
                    after: m.mitigations.high_entropy_va.to_string(),
                });
            }
            if o.mitigations.dep_nx != m.mitigations.dep_nx {
                changes.push(MitigationChange {
                    mitigation: "DEP / NX Compat".into(),
                    before: o.mitigations.dep_nx.to_string(),
                    after: m.mitigations.dep_nx.to_string(),
                });
            }
            if o.mitigations.cfg != m.mitigations.cfg {
                changes.push(MitigationChange {
                    mitigation: "Control Flow Guard (CFG)".into(),
                    before: o.mitigations.cfg.to_string(),
                    after: m.mitigations.cfg.to_string(),
                });
            }
            if changes.is_empty() {
                None
            } else {
                Some(MitigationsDiff {
                    original_format: BinaryFormat::Pe,
                    modified_format: BinaryFormat::Pe,
                    changes,
                })
            }
        })
    });

    (hunks, section_diffs, mitigations_diff)
}

fn resolve_elf_diff(
    orig: &[u8],
    modified: &[u8],
    raw_hunks: &[RawHunk],
) -> (Vec<DiffHunk>, Vec<SectionDiff>, Option<MitigationsDiff>) {
    let elf_orig = parse_elf(orig).ok();
    let elf_mod = parse_elf(modified).ok();

    let o_spans: Vec<SectionSpan> = elf_orig
        .as_ref()
        .map(|elf| {
            elf.sections
                .iter()
                .filter(|s| !s.name.is_empty())
                .map(|s| SectionSpan {
                    name: s.name.clone(),
                    file_offset: s.offset as usize,
                    file_size: s.size as usize,
                    rva_base: s.addr,
                    entropy: s.entropy,
                })
                .collect()
        })
        .unwrap_or_default();

    let m_spans: Vec<SectionSpan> = elf_mod
        .as_ref()
        .map(|elf| {
            elf.sections
                .iter()
                .filter(|s| !s.name.is_empty())
                .map(|s| SectionSpan {
                    name: s.name.clone(),
                    file_offset: s.offset as usize,
                    file_size: s.size as usize,
                    rva_base: s.addr,
                    entropy: s.entropy,
                })
                .collect()
        })
        .unwrap_or_default();

    let (hunks, section_diffs) = correlate_sections(raw_hunks, &o_spans, &m_spans);

    let mitigations_diff = elf_orig.as_ref().and_then(|o| {
        elf_mod.as_ref().and_then(|m| {
            let mut changes = Vec::new();
            if o.mitigations.pie != m.mitigations.pie {
                changes.push(MitigationChange {
                    mitigation: "PIE (Position Independent Executable)".into(),
                    before: o.mitigations.pie.to_string(),
                    after: m.mitigations.pie.to_string(),
                });
            }
            if o.mitigations.relro != m.mitigations.relro {
                changes.push(MitigationChange {
                    mitigation: "RELRO (Relocation Read-Only)".into(),
                    before: format!("{:?}", o.mitigations.relro),
                    after: format!("{:?}", m.mitigations.relro),
                });
            }
            if o.mitigations.nx != m.mitigations.nx {
                changes.push(MitigationChange {
                    mitigation: "NX (No-Execute Stack)".into(),
                    before: o.mitigations.nx.to_string(),
                    after: m.mitigations.nx.to_string(),
                });
            }
            if o.mitigations.stack_canary != m.mitigations.stack_canary {
                changes.push(MitigationChange {
                    mitigation: "Stack Canary".into(),
                    before: o.mitigations.stack_canary.to_string(),
                    after: m.mitigations.stack_canary.to_string(),
                });
            }
            if changes.is_empty() {
                None
            } else {
                Some(MitigationsDiff {
                    original_format: BinaryFormat::Elf,
                    modified_format: BinaryFormat::Elf,
                    changes,
                })
            }
        })
    });

    (hunks, section_diffs, mitigations_diff)
}

fn resolve_macho_diff(
    orig: &[u8],
    modified: &[u8],
    raw_hunks: &[RawHunk],
) -> (Vec<DiffHunk>, Vec<SectionDiff>, Option<MitigationsDiff>) {
    let macho_orig = parse_macho(orig).ok();
    let macho_mod = parse_macho(modified).ok();

    let (o_spans, o_miti) = match &macho_orig {
        Some(info) => {
            if let Some(arch) = info.architectures.first() {
                let spans = arch
                    .sections
                    .iter()
                    .map(|s| SectionSpan {
                        name: s.sectname.clone(),
                        file_offset: s.offset as usize,
                        file_size: s.size as usize,
                        rva_base: s.addr,
                        entropy: s.entropy,
                    })
                    .collect();
                (spans, Some(arch.mitigations.clone()))
            } else {
                (Vec::new(), None)
            }
        }
        None => (Vec::new(), None),
    };

    let (m_spans, m_miti) = match &macho_mod {
        Some(info) => {
            if let Some(arch) = info.architectures.first() {
                let spans = arch
                    .sections
                    .iter()
                    .map(|s| SectionSpan {
                        name: s.sectname.clone(),
                        file_offset: s.offset as usize,
                        file_size: s.size as usize,
                        rva_base: s.addr,
                        entropy: s.entropy,
                    })
                    .collect();
                (spans, Some(arch.mitigations.clone()))
            } else {
                (Vec::new(), None)
            }
        }
        None => (Vec::new(), None),
    };

    let (hunks, section_diffs) = correlate_sections(raw_hunks, &o_spans, &m_spans);

    let mitigations_diff = o_miti.and_then(|o| {
        m_miti.and_then(|m| {
            let mut changes = Vec::new();
            if o.pie != m.pie {
                changes.push(MitigationChange {
                    mitigation: "PIE (Position Independent Executable)".into(),
                    before: o.pie.to_string(),
                    after: m.pie.to_string(),
                });
            }
            if o.nx != m.nx {
                changes.push(MitigationChange {
                    mitigation: "NX (No-Execute Stack)".into(),
                    before: o.nx.to_string(),
                    after: m.nx.to_string(),
                });
            }
            if o.code_signature != m.code_signature {
                changes.push(MitigationChange {
                    mitigation: "Code Signature (LC_CODE_SIGNATURE)".into(),
                    before: o.code_signature.to_string(),
                    after: m.code_signature.to_string(),
                });
            }
            if changes.is_empty() {
                None
            } else {
                Some(MitigationsDiff {
                    original_format: BinaryFormat::Macho,
                    modified_format: BinaryFormat::Macho,
                    changes,
                })
            }
        })
    });

    (hunks, section_diffs, mitigations_diff)
}
