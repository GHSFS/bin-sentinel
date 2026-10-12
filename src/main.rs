// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fs;
use std::process;

use clap::Parser;

use bin_sentinel::cli::{Cli, Commands};
use bin_sentinel::entropy::analyze_entropy_windows;
use bin_sentinel::error::Result;
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
    }

    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err}");
        process::exit(1);
    }
}
