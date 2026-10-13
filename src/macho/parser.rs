// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::headers::*;
use crate::entropy::shannon_entropy;
use crate::error::{Result, SentinelError};

/// Parse a Mach-O binary (either 64-bit single-arch or Universal Fat binary).
pub fn parse_macho(data: &[u8]) -> Result<MachoInfo> {
    if data.len() < 4 {
        return Err(SentinelError::InvalidFormat(
            "Mach-O binary too small: less than 4 bytes".into(),
        ));
    }

    let magic_le = read_u32_le(data, 0)?;
    let magic_be = read_u32_be(data, 0)?;

    if magic_be == FAT_MAGIC || magic_le == FAT_CIGAM {
        parse_universal_macho(data, magic_be == FAT_MAGIC)
    } else if magic_le == MH_MAGIC_64 || magic_be == MH_MAGIC_64 {
        let is_be = magic_be == MH_MAGIC_64 && magic_le != MH_MAGIC_64;
        let mut alerts = Vec::new();
        let arch = parse_single_macho_64(data, 0, is_be, &mut alerts)?;
        let overall_entropy = shannon_entropy(data);

        Ok(MachoInfo {
            format: "Mach-O 64-bit".to_string(),
            magic: "0xFEEDFACF".to_string(),
            is_universal: false,
            architectures: vec![arch],
            overall_entropy,
            alerts,
        })
    } else if magic_le == MH_MAGIC_32 || magic_be == MH_MAGIC_32 || magic_le == MH_CIGAM_32 {
        Err(SentinelError::InvalidFormat(
            "Unsupported 32-bit Mach-O binary (only 64-bit and Universal are supported)".into(),
        ))
    } else {
        Err(SentinelError::InvalidFormat(
            "Missing Mach-O magic signature (expected 0xFEEDFACF or 0xCAFEBABE)".into(),
        ))
    }
}

/// Parse a Universal (Fat) Mach-O binary container.
fn parse_universal_macho(data: &[u8], is_be: bool) -> Result<MachoInfo> {
    if data.len() < 8 {
        return Err(SentinelError::InvalidFormat(
            "Universal Mach-O header truncated".into(),
        ));
    }

    let nfat_arch = if is_be {
        read_u32_be(data, 4)?
    } else {
        read_u32_le(data, 4)?
    };

    if nfat_arch == 0 || nfat_arch > 64 {
        return Err(SentinelError::InvalidFormat(format!(
            "Invalid Universal binary architecture count: {nfat_arch}"
        )));
    }

    let header_size = 8usize.saturating_add((nfat_arch as usize).saturating_mul(20));
    if header_size > data.len() {
        return Err(SentinelError::BoundsError(
            "Universal fat_arch descriptors extend beyond file bounds".into(),
        ));
    }

    let mut architectures = Vec::with_capacity(nfat_arch as usize);
    let mut alerts = Vec::new();

    for i in 0..nfat_arch {
        let arch_off = 8usize + (i as usize) * 20;
        let cputype = if is_be {
            read_u32_be(data, arch_off)?
        } else {
            read_u32_le(data, arch_off)?
        };
        let cpusubtype = if is_be {
            read_u32_be(data, arch_off + 4)?
        } else {
            read_u32_le(data, arch_off + 4)?
        };
        let slice_off = if is_be {
            read_u32_be(data, arch_off + 8)?
        } else {
            read_u32_le(data, arch_off + 8)?
        } as usize;
        let slice_size = if is_be {
            read_u32_be(data, arch_off + 12)?
        } else {
            read_u32_le(data, arch_off + 12)?
        } as usize;

        if slice_off.saturating_add(slice_size) > data.len() {
            alerts.push(format!(
                "Architecture slice {i} (0x{cputype:08X}) points outside file boundary"
            ));
            continue;
        }

        let slice = &data[slice_off..slice_off + slice_size];
        if slice.len() >= 4 {
            let inner_magic_le = read_u32_le(slice, 0)?;
            let inner_magic_be = read_u32_be(slice, 0)?;
            if inner_magic_le == MH_MAGIC_64 || inner_magic_be == MH_MAGIC_64 {
                let inner_is_be = inner_magic_be == MH_MAGIC_64 && inner_magic_le != MH_MAGIC_64;
                let arch_info =
                    parse_single_macho_64(slice, slice_off as u64, inner_is_be, &mut alerts)?;
                architectures.push(arch_info);
                continue;
            }
        }

        // Non-64-bit or unparsed arch slice record
        architectures.push(MachoArchInfo {
            cpu_type: cputype_to_name(cputype).to_string(),
            cpu_type_raw: cputype,
            cpu_subtype: cpusubtype_to_name(cputype, cpusubtype).to_string(),
            cpu_subtype_raw: cpusubtype,
            file_type: "MH_UNKNOWN".to_string(),
            file_type_raw: 0,
            offset: slice_off as u64,
            size: slice_size as u64,
            entry_point: None,
            stack_size: None,
            segments: Vec::new(),
            sections: Vec::new(),
            dylibs: Vec::new(),
            code_signature: None,
            mitigations: MachoSecurityMitigations {
                pie: false,
                nx: false,
                code_signature: false,
                two_level_namespace: false,
            },
            load_commands_count: 0,
            sizeofcmds: 0,
            flags_raw: 0,
        });
    }

    let overall_entropy = shannon_entropy(data);

    Ok(MachoInfo {
        format: "Mach-O Universal (Fat Binary)".to_string(),
        magic: "0xCAFEBABE".to_string(),
        is_universal: true,
        architectures,
        overall_entropy,
        alerts,
    })
}

/// Parse a single 64-bit Mach-O binary slice.
pub fn parse_single_macho_64(
    slice: &[u8],
    base_offset: u64,
    _is_be: bool,
    alerts: &mut Vec<String>,
) -> Result<MachoArchInfo> {
    if slice.len() < 32 {
        return Err(SentinelError::InvalidFormat(
            "64-bit Mach-O header too small: expected at least 32 bytes".into(),
        ));
    }

    let cputype = read_u32_le(slice, 4)?;
    let cpusubtype = read_u32_le(slice, 8)?;
    let filetype = read_u32_le(slice, 12)?;
    let ncmds = read_u32_le(slice, 16)?;
    let sizeofcmds = read_u32_le(slice, 20)?;
    let flags = read_u32_le(slice, 24)?;

    let end_of_cmds = 32usize.saturating_add(sizeofcmds as usize);
    if end_of_cmds > slice.len() {
        alerts.push(format!(
            "Load commands total size ({} B) extends beyond binary boundaries",
            sizeofcmds
        ));
    }

    let mut segments = Vec::new();
    let mut sections = Vec::new();
    let mut dylibs = Vec::new();
    let mut code_signature = None;
    let mut entry_point = None;
    let mut stack_size = None;

    let mut cursor = 32usize;
    for cmd_idx in 0..ncmds {
        if cursor.saturating_add(8) > slice.len() {
            alerts.push(format!(
                "Load command index {cmd_idx} header truncated at offset 0x{cursor:X}"
            ));
            break;
        }

        let cmd = read_u32_le(slice, cursor)?;
        let cmdsize = read_u32_le(slice, cursor + 4)? as usize;

        if cmdsize < 8 || cursor.saturating_add(cmdsize) > slice.len() {
            alerts.push(format!(
                "Load command 0x{cmd:08X} at 0x{cursor:X} has invalid size {cmdsize}"
            ));
            break;
        }

        match cmd {
            LC_SEGMENT_64 if cmdsize >= 72 => {
                let segname = parse_fixed_str(&slice[cursor + 8..cursor + 24]);
                let vmaddr = read_u64_le(slice, cursor + 24)?;
                let vmsize = read_u64_le(slice, cursor + 32)?;
                let fileoff = read_u64_le(slice, cursor + 40)?;
                let filesize = read_u64_le(slice, cursor + 48)?;
                let maxprot = read_u32_le(slice, cursor + 56)?;
                let initprot = read_u32_le(slice, cursor + 60)?;
                let nsects = read_u32_le(slice, cursor + 64)?;
                let segflags = read_u32_le(slice, cursor + 68)?;

                let rwx = (initprot & (VM_PROT_WRITE | VM_PROT_EXECUTE))
                    == (VM_PROT_WRITE | VM_PROT_EXECUTE);
                if rwx {
                    alerts.push(format!(
                        "Writable and Executable (RWX) segment detected: '{segname}'"
                    ));
                }

                segments.push(MachoSegment {
                    name: segname.clone(),
                    vmaddr,
                    vmsize,
                    fileoff,
                    filesize,
                    maxprot,
                    initprot,
                    permissions: format_vm_prot(initprot),
                    nsects,
                    flags: segflags,
                    rwx_anomaly: rwx,
                });

                // Parse embedded section_64 structs (80 bytes each)
                let sect_base = cursor + 72;
                for s in 0..nsects as usize {
                    let sect_off = sect_base + s * 80;
                    if sect_off + 80 > cursor + cmdsize {
                        alerts.push(format!(
                            "Section header {s} in segment '{segname}' overflows command"
                        ));
                        break;
                    }

                    let sname = parse_fixed_str(&slice[sect_off..sect_off + 16]);
                    let sm_segname = parse_fixed_str(&slice[sect_off + 16..sect_off + 32]);
                    let s_addr = read_u64_le(slice, sect_off + 32)?;
                    let s_size = read_u64_le(slice, sect_off + 40)?;
                    let s_offset = read_u32_le(slice, sect_off + 48)?;
                    let s_align = read_u32_le(slice, sect_off + 52)?;
                    let s_reloff = read_u32_le(slice, sect_off + 56)?;
                    let s_nreloc = read_u32_le(slice, sect_off + 60)?;
                    let s_flags = read_u32_le(slice, sect_off + 64)?;

                    let s_off_usize = s_offset as usize;
                    let s_sz_usize = s_size as usize;
                    let s_entropy = if s_sz_usize > 0
                        && s_off_usize.saturating_add(s_sz_usize) <= slice.len()
                    {
                        shannon_entropy(&slice[s_off_usize..s_off_usize + s_sz_usize])
                    } else {
                        0.0
                    };

                    if s_entropy > 7.2 {
                        alerts.push(format!(
                            "High entropy section '{sname}' (H={s_entropy:.4}) - possibly packed"
                        ));
                    }

                    sections.push(MachoSection {
                        sectname: sname,
                        segname: sm_segname,
                        addr: s_addr,
                        size: s_size,
                        offset: s_offset,
                        align: s_align,
                        reloff: s_reloff,
                        nreloc: s_nreloc,
                        flags: s_flags,
                        permissions: format_vm_prot(initprot),
                        entropy: s_entropy,
                        rwx_anomaly: rwx,
                    });
                }
            }
            LC_MAIN if cmdsize >= 24 => {
                entry_point = Some(read_u64_le(slice, cursor + 8)?);
                stack_size = Some(read_u64_le(slice, cursor + 16)?);
            }
            LC_LOAD_DYLIB if cmdsize >= 24 => {
                let str_off = read_u32_le(slice, cursor + 8)? as usize;
                if str_off >= 24 && str_off < cmdsize {
                    let path = parse_fixed_str(&slice[cursor + str_off..cursor + cmdsize]);
                    if !path.is_empty() {
                        dylibs.push(path);
                    }
                }
            }
            LC_CODE_SIGNATURE if cmdsize >= 16 => {
                code_signature = Some(MachoCodeSignature {
                    dataoff: read_u32_le(slice, cursor + 8)?,
                    datasize: read_u32_le(slice, cursor + 12)?,
                });
            }
            _ => {}
        }

        cursor += cmdsize;
    }

    let pie = (flags & MH_PIE) != 0;
    let nx = (flags & MH_ALLOW_STACK_EXECUTION) == 0;
    let cs = code_signature.is_some();
    let two_level = (flags & MH_TWOLEVEL) != 0;

    if !pie {
        alerts.push("Position Independent Executable (PIE) mitigation disabled".into());
    }
    if !nx {
        alerts.push("Executable stack allowed (MH_ALLOW_STACK_EXECUTION enabled)".into());
    }
    if !cs {
        alerts.push("Unsigned Mach-O binary (no LC_CODE_SIGNATURE load command)".into());
    }

    Ok(MachoArchInfo {
        cpu_type: cputype_to_name(cputype).to_string(),
        cpu_type_raw: cputype,
        cpu_subtype: cpusubtype_to_name(cputype, cpusubtype).to_string(),
        cpu_subtype_raw: cpusubtype,
        file_type: filetype_to_name(filetype).to_string(),
        file_type_raw: filetype,
        offset: base_offset,
        size: slice.len() as u64,
        entry_point,
        stack_size,
        segments,
        sections,
        dylibs,
        code_signature,
        mitigations: MachoSecurityMitigations {
            pie,
            nx,
            code_signature: cs,
            two_level_namespace: two_level,
        },
        load_commands_count: ncmds,
        sizeofcmds,
        flags_raw: flags,
    })
}
