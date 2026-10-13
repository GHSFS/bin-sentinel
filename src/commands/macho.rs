// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fs;
use std::path::Path;

use crate::error::Result;
use crate::macho::{
    build_synthetic_macho64, build_synthetic_macho_universal, parse_macho, CPU_SUBTYPE_ARM64_ALL,
    CPU_SUBTYPE_X86_64_ALL, CPU_TYPE_ARM64, CPU_TYPE_X86_64,
};

pub fn handle_inspect_macho(file: &Path, json: bool) -> Result<()> {
    let data = fs::read(file)?;
    let info = parse_macho(&data)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&info).unwrap_or_default()
        );
    } else {
        println!("=== Mach-O Static Inspection: {} ===", file.display());
        println!("Format            : {}", info.format);
        println!("Magic             : {}", info.magic);
        println!("Universal         : {}", info.is_universal);
        println!("Architectures     : {}", info.architectures.len());
        println!("Overall Entropy   : {:.4} bits/byte", info.overall_entropy);

        for (idx, arch) in info.architectures.iter().enumerate() {
            println!(
                "\n[Architecture {}/{}: {} ({})]",
                idx + 1,
                info.architectures.len(),
                arch.cpu_type,
                arch.cpu_subtype
            );
            println!(
                "  File Type       : {} (0x{:08X})",
                arch.file_type, arch.file_type_raw
            );
            println!(
                "  Offset & Size   : 0x{:08X} ({} B)",
                arch.offset, arch.size
            );
            if let Some(ep) = arch.entry_point {
                println!("  Entry Point     : 0x{ep:016X}");
            }
            println!(
                "  Load Commands   : {} (size: {} B)",
                arch.load_commands_count, arch.sizeofcmds
            );
            println!(
                "  Mitigations     : PIE={} | NX={} | CodeSignature={} | TwoLevel={}",
                arch.mitigations.pie,
                arch.mitigations.nx,
                arch.mitigations.code_signature,
                arch.mitigations.two_level_namespace
            );

            if !arch.segments.is_empty() {
                println!("\n  [Segments]");
                for seg in &arch.segments {
                    println!(
                        "    Segment {:12} | VM 0x{:016X}..0x{:016X} | File 0x{:08X} ({:6} B) | {}{}",
                        seg.name,
                        seg.vmaddr,
                        seg.vmaddr.saturating_add(seg.vmsize),
                        seg.fileoff,
                        seg.filesize,
                        seg.permissions,
                        if seg.rwx_anomaly {
                            " [RWX ANOMALY]"
                        } else {
                            ""
                        }
                    );
                }
            }

            if !arch.sections.is_empty() {
                println!("\n  [Sections]");
                for sec in &arch.sections {
                    println!(
                        "    {:16} | Addr 0x{:016X} | Off 0x{:08X} ({:6} B) | {} | H={:.4}{}",
                        sec.sectname,
                        sec.addr,
                        sec.offset,
                        sec.size,
                        sec.permissions,
                        sec.entropy,
                        if sec.rwx_anomaly {
                            " [RWX ANOMALY]"
                        } else {
                            ""
                        }
                    );
                }
            }

            if !arch.dylibs.is_empty() {
                println!("\n  [Linked Dylibs]");
                for dylib in &arch.dylibs {
                    println!("    * {dylib}");
                }
            }

            if let Some(cs) = &arch.code_signature {
                println!("\n  [Code Signature]");
                println!("    Offset 0x{:08X} ({} bytes)", cs.dataoff, cs.datasize);
            }
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

pub fn handle_synth_macho(output: &Path, universal: bool) -> Result<()> {
    let x86_code = b"\x48\x31\xC0\x48\xFF\xC0\xC3"; // xor rax, rax; inc rax; ret
    let x86_cstring = b"BinSentinel Mach-O x86_64 sample binary\0";
    let x86_slice = build_synthetic_macho64(
        CPU_TYPE_X86_64,
        CPU_SUBTYPE_X86_64_ALL,
        &[
            ("__text", x86_code, 0x80000400),
            ("__cstring", x86_cstring, 0x02),
        ],
    );

    let macho_data = if universal {
        let arm64_code = b"\x00\x00\x80\xD2\xC0\x03\x5F\xD6"; // mov x0, #0; ret
        let arm64_cstring = b"BinSentinel Mach-O arm64 sample binary\0";
        let arm64_slice = build_synthetic_macho64(
            CPU_TYPE_ARM64,
            CPU_SUBTYPE_ARM64_ALL,
            &[
                ("__text", arm64_code, 0x80000400),
                ("__cstring", arm64_cstring, 0x02),
            ],
        );

        build_synthetic_macho_universal(&[
            (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, &x86_slice),
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, &arm64_slice),
        ])
    } else {
        x86_slice
    };

    fs::write(output, &macho_data)?;
    println!(
        "Generated synthetic {} binary at {} ({} bytes)",
        if universal {
            "Mach-O Universal"
        } else {
            "Mach-O 64-bit"
        },
        output.display(),
        macho_data.len()
    );

    Ok(())
}
