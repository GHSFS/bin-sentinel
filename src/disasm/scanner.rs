// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Binary byte scanner and PE/ELF section correlator for x86_64 code patterns.

use std::fs;
use std::path::Path;

use crate::elf::{parse_elf, SHF_EXECINSTR};
use crate::error::Result;
use crate::pe::{parse_pe, IMAGE_SCN_MEM_EXECUTE};

use super::patterns::match_pattern_at;
use super::types::{CodePatternKind, CodePatternMatch, CodeScanReport, CodeScanSummary};

/// Scans raw byte slices for x86_64 instruction sequences, function prologues/epilogues,
/// direct system calls, anti-debug hooks, VM checks, and software traps.
pub fn scan_code_bytes(data: &[u8]) -> (Vec<CodePatternMatch>, CodeScanSummary) {
    let mut matches = Vec::new();
    let mut summary = CodeScanSummary::default();

    let mut offset = 0;
    while offset < data.len() {
        if let Some(m) = match_pattern_at(data, offset) {
            summary.total_patterns += 1;
            match m.category {
                CodePatternKind::Prologue => summary.prologues += 1,
                CodePatternKind::Epilogue => summary.epilogues += 1,
                CodePatternKind::DirectSyscall => summary.syscall_stubs += 1,
                CodePatternKind::AntiDebugTiming => summary.anti_debug_timing += 1,
                CodePatternKind::VmHypervisorCheck => summary.vm_checks += 1,
                CodePatternKind::SoftwareTrap => summary.traps += 1,
                CodePatternKind::IndirectBranch => summary.indirect_branches += 1,
            }
            if m.risk_alert.is_some() {
                summary.suspicious_alerts_count += 1;
            }

            let next_offset = offset.saturating_add(m.length.max(1));
            matches.push(m);
            offset = next_offset;
        } else {
            offset += 1;
        }
    }

    (matches, summary)
}

/// Scans a binary file on disk, correlating detected instructions with PE/ELF sections
/// and virtual addresses.
pub fn scan_code_file(path: &Path) -> Result<CodeScanReport> {
    let data = fs::read(path)?;
    let (mut matches, mut summary) = scan_code_bytes(&data);

    let mut binary_format = "Raw Binary".to_string();
    let mut executable_sections = Vec::new();

    if let Ok(pe_info) = parse_pe(&data) {
        binary_format = format!("PE ({})", pe_info.format);
        for sec in &pe_info.sections {
            if (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 || sec.permissions.contains('X') {
                executable_sections.push(sec.name.clone());
            }
        }

        for m in &mut matches {
            for sec in &pe_info.sections {
                let start = sec.raw_offset as usize;
                let end = start.saturating_add(sec.raw_size as usize);
                if m.offset >= start && m.offset < end {
                    m.section_name = Some(sec.name.clone());
                    let delta = (m.offset - start) as u64;
                    m.relative_virtual_address = Some(sec.virtual_address as u64 + delta);

                    if sec.rwx_anomaly {
                        let alert = m
                            .risk_alert
                            .take()
                            .unwrap_or_else(|| "Instruction located in RWX section".to_string());
                        m.risk_alert =
                            Some(format!("{alert} [Located in RWX section {}]", sec.name));
                    }
                    break;
                }
            }
        }
    } else if let Ok(elf_info) = parse_elf(&data) {
        binary_format = format!("ELF ({})", elf_info.os_abi);
        for sec in &elf_info.sections {
            if (sec.flags_raw & SHF_EXECINSTR) != 0 || sec.flags.contains('X') {
                executable_sections.push(sec.name.clone());
            }
        }

        for m in &mut matches {
            for sec in &elf_info.sections {
                let start = sec.offset as usize;
                let end = start.saturating_add(sec.size as usize);
                if m.offset >= start && m.offset < end {
                    m.section_name = Some(sec.name.clone());
                    let delta = (m.offset - start) as u64;
                    m.relative_virtual_address = Some(sec.addr + delta);

                    if sec.rwx_anomaly {
                        let alert = m
                            .risk_alert
                            .take()
                            .unwrap_or_else(|| "Instruction located in RWX segment".to_string());
                        m.risk_alert =
                            Some(format!("{alert} [Located in RWX segment {}]", sec.name));
                    }
                    break;
                }
            }
        }
    }

    // Recount suspicious alerts if RWX annotations added alerts
    let updated_suspicious = matches.iter().filter(|m| m.risk_alert.is_some()).count();
    summary.suspicious_alerts_count = updated_suspicious;

    Ok(CodeScanReport {
        file_path: path.display().to_string(),
        file_size: data.len(),
        binary_format,
        executable_sections,
        summary,
        matches,
    })
}
