// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fs;
use std::path::Path;

use crate::crypto_scan::scan_crypto_file;
use crate::deobfuscate::scan_deobfuscate_file;
use crate::disasm::scan_code_file;
use crate::error::Result;
use crate::imports::inspect_imports;

pub fn handle_crypto_scan(file: &Path, json: bool) -> Result<()> {
    let report = scan_crypto_file(file)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        println!("=== Cryptographic Primitive Scan: {} ===", file.display());
        println!("Format            : {}", report.binary_format);
        println!("File Size         : {} bytes", report.file_size);
        println!(
            "Primitives Found  : {} (Unique algorithms: {})",
            report.total_matches,
            report.detected_algorithms.len()
        );

        if !report.matches.is_empty() {
            println!("\n[Identified Cryptographic Constants & Tables]");
            for m in &report.matches {
                let sec_str = m.section_name.as_deref().unwrap_or("-");
                let rva_str = if let Some(rva) = m.relative_virtual_address {
                    format!("RVA 0x{rva:08X}")
                } else {
                    format!("Offset 0x{:08X}", m.offset)
                };
                println!(
                    "  {:16} | {:7} | {:16} | {:20} | {:6} | {}",
                    rva_str, sec_str, m.algorithm, m.name, m.confidence, m.description
                );
            }
        }
    }
    Ok(())
}

pub fn handle_imports(file: &Path, resolve_hash: Option<&str>, json: bool) -> Result<()> {
    let data = fs::read(file)?;
    let report = inspect_imports(&data, resolve_hash)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        println!("=== PE Import & Export Forensics: {} ===", file.display());
        println!("Format            : {}", report.format);
        println!(
            "Imphash (MD5)     : {}",
            report.imphash.as_deref().unwrap_or("N/A")
        );
        println!(
            "Import Modules    : {} DLLs (Total functions: {})",
            report.import_descriptors.len(),
            report.total_imported_functions
        );

        println!("\n[Import Descriptors & Functions]");
        for desc in &report.import_descriptors {
            println!("  {} | Functions: {}", desc.dll_name, desc.functions.len());
            for func in &desc.functions {
                let hint_str = if let Some(h) = func.hint {
                    format!("Hint {h:4}")
                } else {
                    format!("Ord  {:4}", func.ordinal.unwrap_or(0))
                };
                let name_str = func.name.as_deref().unwrap_or("<by-ordinal>");
                println!(
                    "    {} | RVA 0x{:08X} | {}",
                    hint_str, func.iat_rva, name_str
                );
            }
        }

        if let Some(exp) = &report.export_info {
            println!("\n[Export Directory]");
            println!("  DLL Name        : {}", exp.dll_name);
            println!("  Base Ordinal    : {}", exp.base_ordinal);
            println!(
                "  Total Functions : {} (Names: {})",
                exp.number_of_functions, exp.number_of_names
            );
            println!("  Functions:");
            for f in &exp.functions {
                let name_str = f.name.as_deref().unwrap_or("<by-ordinal>");
                let fwd_str = if let Some(fwd) = &f.forwarder {
                    format!(" -> {fwd}")
                } else {
                    String::new()
                };
                println!(
                    "    Ord {:4} | RVA 0x{:08X} | {}{}",
                    f.ordinal, f.rva, name_str, fwd_str
                );
            }
        }

        if !report.resolved_api_hashes.is_empty() {
            println!("\n[Resolved API Hashes]");
            for m in &report.resolved_api_hashes {
                println!(
                    "  {} | {:6} | {} ({})",
                    m.hash_hex, m.algorithm, m.api_name, m.dll
                );
            }
        }
    }
    Ok(())
}

pub fn handle_scan_code(file: &Path, json: bool) -> Result<()> {
    let report = scan_code_file(file)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        println!(
            "=== x86_64 Code Pattern & Control-Flow Scan: {} ===",
            file.display()
        );
        println!("Format            : {}", report.binary_format);
        println!("File Size         : {} bytes", report.file_size);
        println!(
            "Exec Sections     : {}",
            if report.executable_sections.is_empty() {
                "(none / raw binary)".to_string()
            } else {
                report.executable_sections.join(", ")
            }
        );
        println!(
            "Patterns Found    : {} (Prologues: {}, Epilogues: {}, Syscalls: {}, Timing: {}, VM: {}, Traps: {}, Indirect: {})",
            report.summary.total_patterns,
            report.summary.prologues,
            report.summary.epilogues,
            report.summary.syscall_stubs,
            report.summary.anti_debug_timing,
            report.summary.vm_checks,
            report.summary.traps,
            report.summary.indirect_branches
        );
        if report.summary.suspicious_alerts_count > 0 {
            println!(
                "Security Alerts   : {} suspicious indicators detected",
                report.summary.suspicious_alerts_count
            );
        }

        if !report.matches.is_empty() {
            println!("\n[Detected Instructions & Control Flow]");
            for m in &report.matches {
                let sec_str = m.section_name.as_deref().unwrap_or("-");
                let rva_str = if let Some(rva) = m.relative_virtual_address {
                    format!("RVA 0x{rva:08X}")
                } else {
                    format!("Offset 0x{:08X}", m.offset)
                };
                let alert_str = if let Some(ref alert) = m.risk_alert {
                    format!(" [ALERT: {alert}]")
                } else {
                    String::new()
                };
                println!(
                    "  {:16} | {:7} | {:18} | {:24} | {}{}",
                    rva_str, sec_str, m.category, m.mnemonic, m.bytes_hex, alert_str
                );
            }
        }
    }
    Ok(())
}

pub fn handle_xor_scan(file: &Path, json: bool) -> Result<()> {
    let report = scan_deobfuscate_file(file)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        println!("=== Deobfuscation Scan: {} ===", file.display());
        println!("Format            : {}", report.binary_format);
        println!("File Size         : {} bytes", report.file_size);
        println!("Artifacts Found   : {}", report.total_matches);
        println!(
            "Methods Applied   : {}",
            report.scan_methods_applied.join(", ")
        );

        if !report.artifacts.is_empty() {
            println!("\n[Identified Deobfuscated Artifacts]");
            for a in &report.artifacts {
                let sec_str = a.section_name.as_deref().unwrap_or("-");
                let rva_str = if let Some(rva) = a.relative_virtual_address {
                    format!("RVA 0x{rva:08X}")
                } else {
                    format!("Offset 0x{:08X}", a.offset)
                };
                println!(
                    "  {:16} | {:7} | {:16} | {:14} | Conf {:.2} | {}",
                    rva_str, sec_str, a.method, a.kind, a.confidence, a.content
                );
            }
        }
    }
    Ok(())
}
