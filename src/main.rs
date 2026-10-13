// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fs;
use std::process;

use clap::Parser;

use bin_sentinel::cli::{Cli, Commands};
use bin_sentinel::crypto_scan::scan_crypto_file;
use bin_sentinel::disasm::scan_code_file;
use bin_sentinel::elf::{build_synthetic_elf64, parse_elf, SHF_ALLOC, SHF_EXECINSTR, SHT_PROGBITS};
use bin_sentinel::entropy::analyze_entropy_windows;
use bin_sentinel::error::Result;
use bin_sentinel::imports::inspect_imports;
use bin_sentinel::patch::{apply_patch, parse_hex_bytes, parse_offset};
use bin_sentinel::pe::{
    build_synthetic_pe64, parse_pe, IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
};
use bin_sentinel::strings::extract_strings;

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Inspect { file, json } => {
            let data = fs::read(&file)?;
            let info = parse_pe(&data)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&info).unwrap_or_default()
                );
            } else {
                println!("=== PE Static Inspection: {} ===", file.display());
                println!("Format            : {}", info.format);
                println!(
                    "Machine           : 0x{:04X} ({})",
                    info.machine, info.machine_name
                );
                println!("Sections          : {}", info.number_of_sections);
                println!("Entry Point (RVA) : 0x{:08X}", info.entry_point);
                println!("Image Base        : 0x{:016X}", info.image_base);
                println!("Overall Entropy   : {:.4} bits/byte", info.overall_entropy);
                println!(
                    "Mitigations       : ASLR={} | HighEntropyVA={} | DEP/NX={} | CFG={}",
                    info.mitigations.aslr,
                    info.mitigations.high_entropy_va,
                    info.mitigations.dep_nx,
                    info.mitigations.cfg
                );
                println!("\n[Sections]");
                for sec in &info.sections {
                    println!(
                        "  {:8} | RVA 0x{:08X} | Raw 0x{:08X} ({:6} B) | {} | H={:.4}{}",
                        sec.name,
                        sec.virtual_address,
                        sec.raw_offset,
                        sec.raw_size,
                        sec.permissions,
                        sec.entropy,
                        if sec.rwx_anomaly {
                            " [RWX ANOMALY]"
                        } else {
                            ""
                        }
                    );
                }
                if !info.alerts.is_empty() {
                    println!("\n[Heuristic & Security Alerts]");
                    for alert in &info.alerts {
                        println!("  ! {alert}");
                    }
                }
            }
        }
        Commands::Entropy { file, window, json } => {
            let data = fs::read(&file)?;
            let report = analyze_entropy_windows(&data, window);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_default()
                );
            } else {
                println!("=== Statistical Entropy Analysis: {} ===", file.display());
                println!("Total Bytes       : {}", report.classification.total_bytes);
                println!(
                    "Overall Entropy   : {:.4} bits/byte",
                    report.overall_entropy
                );
                println!("Chi-Square (df255): {:.2}", report.chi_square);
                println!("Assessment        : {}", report.assessment);
                println!(
                    "Byte Ratios       : Null={:.2}% | PrintableASCII={:.2}% | HighBytes={:.2}%",
                    report.classification.null_ratio * 100.0,
                    report.classification.ascii_printable_ratio * 100.0,
                    report.classification.high_byte_ratio * 100.0
                );
                println!("\n[Sliding Windows (window = {} B)]", window.max(64));
                for w in &report.windows {
                    println!(
                        "  0x{:08X}..0x{:08X} ({:5} B) -> {:.4} bits/byte",
                        w.offset,
                        w.offset + w.length,
                        w.length,
                        w.entropy
                    );
                }
            }
        }
        Commands::Strings {
            file,
            min_len,
            ioc_only,
            json,
        } => {
            let data = fs::read(&file)?;
            let extracted = extract_strings(&data, min_len, ioc_only);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&extracted).unwrap_or_default()
                );
            } else {
                for item in &extracted {
                    let tag = match &item.ioc {
                        Some(kind) => format!(" [IoC:{kind:?}]"),
                        None => String::new(),
                    };
                    println!(
                        "0x{:08X} ({:?}){}: {}",
                        item.offset, item.encoding, tag, item.value
                    );
                }
            }
        }
        Commands::Patch {
            file,
            offset,
            expect,
            replace,
            backup,
            json,
        } => {
            let off = parse_offset(&offset)?;
            let exp_bytes = parse_hex_bytes(&expect)?;
            let rep_bytes = parse_hex_bytes(&replace)?;
            let report = apply_patch(&file, off, &exp_bytes, &rep_bytes, backup)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_default()
                );
            } else {
                println!(
                    "Patched {} at 0x{:X} ({} bytes): {} -> {}",
                    report.path,
                    report.offset,
                    report.length,
                    report.expected_hex,
                    report.replaced_hex
                );
                println!("SHA-256 (before): {}", report.sha256_before);
                println!("SHA-256 (after) : {}", report.sha256_after);
                if let Some(bak) = &report.backup_path {
                    println!("Backup created  : {bak}");
                }
            }
        }
        Commands::SynthPe { output } => {
            let code_bytes = b"\x48\x83\xEC\x28\xE8\x00\x00\x00\x00\x48\x83\xC4\x28\xC3";
            let rdata_bytes = b"https://telemetry.example.org/v1/beacon\0VirtualAllocEx\0WriteProcessMemory\0HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\0";
            let sections = [
                (
                    ".text",
                    &code_bytes[..],
                    IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
                ),
                (
                    ".rdata",
                    &rdata_bytes[..],
                    IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
                ),
            ];
            let pe_bytes = build_synthetic_pe64(&sections);
            fs::write(&output, &pe_bytes)?;
            println!(
                "Generated synthetic PE32+ (64-bit) binary at {} ({} bytes)",
                output.display(),
                pe_bytes.len()
            );
        }
        Commands::InspectElf { file, json } => {
            let data = fs::read(&file)?;
            let info = parse_elf(&data)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&info).unwrap_or_default()
                );
            } else {
                println!("=== ELF64 Static Inspection: {} ===", file.display());
                println!("Class             : {}", info.class);
                println!("Endianness        : {}", info.endianness);
                println!("OS/ABI            : {}", info.os_abi);
                println!(
                    "Type              : 0x{:04X} ({})",
                    info.type_raw, info.elf_type
                );
                println!(
                    "Machine           : 0x{:04X} ({})",
                    info.machine_raw, info.machine
                );
                println!("Entry Point       : 0x{:016X}", info.entry_point);
                println!("Overall Entropy   : {:.4} bits/byte", info.overall_entropy);
                println!(
                    "Mitigations       : PIE={} | RELRO={:?} | NX={} | Canary={}",
                    info.mitigations.pie,
                    info.mitigations.relro,
                    info.mitigations.nx,
                    info.mitigations.stack_canary
                );
                println!("\n[Program Headers (Segments)]");
                for ph in &info.program_headers {
                    println!(
                        "  {:16} | {} | Off 0x{:08X} | VAddr 0x{:016X} | FileSz {:6} B | MemSz {:6} B",
                        ph.segment_type, ph.flags, ph.offset, ph.vaddr, ph.filesz, ph.memsz
                    );
                }
                println!("\n[Section Headers]");
                for sec in &info.sections {
                    println!(
                        "  {:12} | {:12} | {:5} | Addr 0x{:016X} | Off 0x{:08X} ({:6} B) | H={:.4}{}",
                        sec.name,
                        sec.section_type,
                        sec.flags,
                        sec.addr,
                        sec.offset,
                        sec.size,
                        sec.entropy,
                        if sec.rwx_anomaly {
                            " [RWX ANOMALY]"
                        } else {
                            ""
                        }
                    );
                }
                if !info.dynamic_tags.is_empty() {
                    println!("\n[Dynamic Tags]");
                    for dyn_entry in &info.dynamic_tags {
                        let extra = match &dyn_entry.parsed_string {
                            Some(s) => format!(" ({s})"),
                            None => String::new(),
                        };
                        println!(
                            "  {:16} (0x{:X}) -> 0x{:016X}{extra}",
                            dyn_entry.tag_name, dyn_entry.tag, dyn_entry.val
                        );
                    }
                }
                if !info.symbols.is_empty() {
                    println!("\n[Symbols]");
                    for sym in &info.symbols {
                        println!(
                            "  {:24} | {:6} | {:6} | 0x{:016X} ({:4} B)",
                            sym.name, sym.binding, sym.symbol_type, sym.value, sym.size
                        );
                    }
                }
                if !info.alerts.is_empty() {
                    println!("\n[Security & Heuristic Alerts]");
                    for alert in &info.alerts {
                        println!("  ! {alert}");
                    }
                }
            }
        }
        Commands::SynthElf { output } => {
            let code_bytes = b"\x48\x31\xC0\x48\xFF\xC0\xC3"; // xor rax, rax; inc rax; ret
            let rodata_bytes = b"Hello from synthetic ELF64\0";
            let custom_sections = [
                (
                    ".text",
                    &code_bytes[..],
                    SHF_ALLOC | SHF_EXECINSTR,
                    SHT_PROGBITS,
                ),
                (".rodata", &rodata_bytes[..], SHF_ALLOC, SHT_PROGBITS),
            ];
            let elf_bytes = build_synthetic_elf64(&custom_sections);
            fs::write(&output, &elf_bytes)?;
            println!(
                "Generated synthetic ELF64 binary at {} ({} bytes)",
                output.display(),
                elf_bytes.len()
            );
        }
        Commands::CryptoScan { file, json } => {
            let report = scan_crypto_file(&file)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_default()
                );
            } else {
                println!(
                    "=== Cryptographic Primitive & S-Box Scan: {} ===",
                    file.display()
                );
                println!("File Size         : {} bytes", report.file_size);
                println!("Detected Format   : {}", report.binary_format);
                println!("Total Matches     : {}", report.total_matches);
                if report.tea_delta_occurrences > 0 {
                    println!(
                        "TEA Delta Hits    : {} occurrences",
                        report.tea_delta_occurrences
                    );
                }
                if !report.detected_algorithms.is_empty() {
                    println!(
                        "Algorithms Found  : {}",
                        report.detected_algorithms.join(", ")
                    );
                }
                println!("\n[Detected Cryptographic Primitives]");
                if report.matches.is_empty() {
                    println!("  (No known cryptographic constants or S-Boxes detected)");
                } else {
                    for m in &report.matches {
                        let sec_str = match (&m.section_name, m.relative_virtual_address) {
                            (Some(sec), Some(rva)) => format!(" [{sec} | RVA 0x{rva:08X}]"),
                            (Some(sec), None) => format!(" [{sec}]"),
                            _ => String::new(),
                        };
                        println!(
                            "  0x{:08X} | {:26} | {:24} | {:6} | {}{sec_str}",
                            m.offset, m.name, m.algorithm, m.confidence, m.description
                        );
                    }
                }
            }
        }
        Commands::Imports {
            file,
            resolve_hash,
            json,
        } => {
            let data = fs::read(&file)?;
            let mut report = inspect_imports(&data, resolve_hash.as_deref())?;
            report.file_path = Some(file.display().to_string());
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_default()
                );
            } else {
                println!("=== PE Imports & Exports Analysis: {} ===", file.display());
                println!("Format            : {}", report.format);
                println!(
                    "Imphash (MD5)     : {}",
                    report.imphash.as_deref().unwrap_or("(none)")
                );
                println!("Imported DLLs     : {}", report.total_imported_descriptors);
                println!("Total Functions   : {}", report.total_imported_functions);

                if !report.import_descriptors.is_empty() {
                    println!("\n[Import Descriptors]");
                    for desc in &report.import_descriptors {
                        println!(
                            "  {} (IAT: 0x{:08X}, {} functions):",
                            desc.dll_name,
                            desc.first_thunk,
                            desc.functions.len()
                        );
                        for f in &desc.functions {
                            let sym = if let Some(ref name) = f.name {
                                name.clone()
                            } else if let Some(ord) = f.ordinal {
                                format!("Ordinal #{ord}")
                            } else {
                                "Unknown".to_string()
                            };
                            println!("    0x{:08X} | {}", f.iat_rva, sym);
                        }
                    }
                }

                if let Some(ref exp) = report.export_info {
                    println!("\n[Export Directory: {}]", exp.dll_name);
                    println!(
                        "  Functions: {} | Names: {} | Base Ordinal: {}",
                        exp.number_of_functions, exp.number_of_names, exp.base_ordinal
                    );
                    for f in &exp.functions {
                        let name_str = f.name.as_deref().unwrap_or("(by ordinal)");
                        let fwd_str = if let Some(ref fwd) = f.forwarder {
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
        }
        Commands::ScanCode { file, json } => {
            let report = scan_code_file(&file)?;
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
        }
    }

    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err}");
        process::exit(1);
    }
}
