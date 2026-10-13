// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fs;
use std::path::Path;

use crate::elf::{build_synthetic_elf64, parse_elf, SHF_ALLOC, SHF_EXECINSTR, SHT_PROGBITS};
use crate::entropy::analyze_entropy_windows;
use crate::error::Result;
use crate::patch::{apply_patch, parse_hex_bytes, parse_offset};
use crate::pe::{
    build_synthetic_pe64, parse_pe, IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
};
use crate::strings::extract_strings;

pub fn handle_inspect(file: &Path, json: bool) -> Result<()> {
    let data = fs::read(file)?;
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
    Ok(())
}

pub fn handle_entropy(file: &Path, window: usize, json: bool) -> Result<()> {
    let data = fs::read(file)?;
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
        println!("\n[Entropy Sliding Windows (size={window})]");
        for w in &report.windows {
            println!(
                "  Offset 0x{:08X}..0x{:08X} | H={:.4} bits/byte",
                w.offset,
                w.offset + w.length,
                w.entropy
            );
        }
    }
    Ok(())
}

pub fn handle_strings(file: &Path, min_len: usize, ioc_only: bool, json: bool) -> Result<()> {
    let data = fs::read(file)?;
    let strings = extract_strings(&data, min_len, ioc_only);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&strings).unwrap_or_default()
        );
    } else {
        println!("=== Extracted IoC & Binary Strings: {} ===", file.display());
        println!("Extracted Count   : {}", strings.len());
        println!();
        for s in &strings {
            let ioc_tag = match &s.ioc {
                Some(ioc) => format!(" [{ioc:?}]"),
                None => String::new(),
            };
            println!(
                "  0x{:08X} | {:?} | {}{}",
                s.offset, s.encoding, s.value, ioc_tag
            );
        }
    }
    Ok(())
}

pub fn handle_patch(
    file: &Path,
    offset: &str,
    expect: &str,
    replace: &str,
    backup: bool,
    json: bool,
) -> Result<()> {
    let off = parse_offset(offset)?;
    let exp_bytes = parse_hex_bytes(expect)?;
    let rep_bytes = parse_hex_bytes(replace)?;

    let report = apply_patch(file, off, &exp_bytes, &rep_bytes, backup)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        println!("=== Byte Patch Applied: {} ===", file.display());
        println!("Offset            : 0x{:08X}", report.offset);
        println!("Bytes Patched     : {}", report.length);
        println!("Pre-Patch SHA256  : {}", report.sha256_before);
        println!("Post-Patch SHA256 : {}", report.sha256_after);
        if let Some(bak) = report.backup_path {
            println!("Backup Created    : {bak}");
        }
    }
    Ok(())
}

pub fn handle_synth_pe(output: &Path) -> Result<()> {
    let code_payload = b"\x48\x83\xEC\x28\x48\x8D\x0D\x10\x00\x00\x00\x90\x48\x83\xC4\x28\xC3";
    let data_payload =
        b"https://update.microsoft-security.test/payload\0VirtualAllocEx\0HKLM\\Software\\Test\0";

    let pe_data = build_synthetic_pe64(&[
        (
            ".text",
            code_payload,
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
        ),
        (
            ".rdata",
            data_payload,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        ),
    ]);

    fs::write(output, &pe_data)?;
    println!(
        "Generated synthetic PE64 binary at {} ({} bytes)",
        output.display(),
        pe_data.len()
    );
    Ok(())
}

pub fn handle_inspect_elf(file: &Path, json: bool) -> Result<()> {
    let data = fs::read(file)?;
    let elf = parse_elf(&data)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&elf).unwrap_or_default());
    } else {
        println!("=== ELF64 Static Inspection: {} ===", file.display());
        println!("Class             : {}", elf.class);
        println!("Endianness        : {}", elf.endianness);
        println!("Type              : {}", elf.elf_type);
        println!(
            "Machine           : 0x{:04X} ({})",
            elf.machine_raw, elf.machine
        );
        println!("Entry Point       : 0x{:016X}", elf.entry_point);
        println!("Program Headers   : {}", elf.program_headers.len());
        println!("Section Headers   : {}", elf.sections.len());
        println!(
            "Mitigations       : PIE={} | RELRO={:?} | NX={} | Canary={}",
            elf.mitigations.pie,
            elf.mitigations.relro,
            elf.mitigations.nx,
            elf.mitigations.stack_canary
        );
        println!("\n[Sections]");
        for sec in &elf.sections {
            println!(
                "  {:12} | Addr 0x{:016X} | Off 0x{:08X} ({:6} B) | {} | H={:.4}{}",
                sec.name,
                sec.addr,
                sec.offset,
                sec.size,
                sec.flags,
                sec.entropy,
                if sec.rwx_anomaly {
                    " [RWX ANOMALY]"
                } else {
                    ""
                }
            );
        }
        if !elf.alerts.is_empty() {
            println!("\n[Heuristic & Security Alerts]");
            for alert in &elf.alerts {
                println!("  ! {alert}");
            }
        }
    }
    Ok(())
}

pub fn handle_synth_elf(output: &Path) -> Result<()> {
    let code = b"\x48\x31\xc0\x48\xff\xc0\xc3"; // xor rax, rax; inc rax; ret
    let elf_data =
        build_synthetic_elf64(&[(".text", code, SHF_ALLOC | SHF_EXECINSTR, SHT_PROGBITS)]);

    fs::write(output, &elf_data)?;
    println!(
        "Generated synthetic ELF64 binary at {} ({} bytes)",
        output.display(),
        elf_data.len()
    );
    Ok(())
}
