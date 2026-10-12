// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod headers;
pub mod synthetic;

pub use headers::*;
pub use synthetic::build_synthetic_elf64;

use crate::entropy::shannon_entropy;
use crate::error::{Result, SentinelError};

/// Parse an ELF64 binary image into a structured `ElfInfo` report.
pub fn parse_elf(data: &[u8]) -> Result<ElfInfo> {
    if data.len() < 64 {
        return Err(SentinelError::InvalidFormat(format!(
            "ELF image too small: {} bytes (minimum header is 64 bytes)",
            data.len()
        )));
    }

    if data[0..4] != ELF_MAGIC {
        return Err(SentinelError::InvalidFormat(
            "Missing ELF magic signature (expected \\x7FELF)".into(),
        ));
    }

    let class_byte = data[4];
    if class_byte != ELFCLASS64 {
        return Err(SentinelError::InvalidFormat(format!(
            "Unsupported ELF class {class_byte}: currently only 64-bit ELF images are supported"
        )));
    }

    let data_byte = data[5];
    if data_byte != ELFDATA2LSB {
        return Err(SentinelError::InvalidFormat(format!(
            "Unsupported endianness {data_byte}: currently only Little-Endian (ELFDATA2LSB) is supported"
        )));
    }

    let os_abi = osabi_to_name(data[7]).to_string();
    let type_raw = read_u16_le(data, 16)?;
    let machine_raw = read_u16_le(data, 18)?;
    let entry_point = read_u64_le(data, 24)?;
    let phoff = read_u64_le(data, 32)? as usize;
    let shoff = read_u64_le(data, 40)? as usize;
    let phentsize = read_u16_le(data, 54)? as usize;
    let phnum = read_u16_le(data, 56)? as usize;
    let shentsize = read_u16_le(data, 58)? as usize;
    let shnum = read_u16_le(data, 60)? as usize;
    let shstrndx = read_u16_le(data, 62)? as usize;

    // 1. Parse Program Headers
    let mut program_headers = Vec::with_capacity(phnum);
    let mut has_relro = false;
    let mut gnu_stack_flags = None;
    let mut alerts = Vec::new();

    for i in 0..phnum {
        let entry_off =
            phoff
                .checked_add(i.checked_mul(phentsize).ok_or_else(|| {
                    SentinelError::BoundsError("phoff arithmetic overflow".into())
                })?)
                .ok_or_else(|| SentinelError::BoundsError("phoff entry overflow".into()))?;

        if entry_off.saturating_add(56) > data.len() {
            alerts.push(format!(
                "Program header index {i} points outside file boundaries (offset 0x{entry_off:X})"
            ));
            break;
        }

        let p_type = read_u32_le(data, entry_off)?;
        let p_flags = read_u32_le(data, entry_off + 4)?;
        let p_offset = read_u64_le(data, entry_off + 8)?;
        let p_vaddr = read_u64_le(data, entry_off + 16)?;
        let p_paddr = read_u64_le(data, entry_off + 24)?;
        let p_filesz = read_u64_le(data, entry_off + 32)?;
        let p_memsz = read_u64_le(data, entry_off + 40)?;
        let p_align = read_u64_le(data, entry_off + 48)?;

        if p_type == PT_GNU_RELRO {
            has_relro = true;
        } else if p_type == PT_GNU_STACK {
            gnu_stack_flags = Some(p_flags);
        }

        if p_type == PT_LOAD && (p_flags & PF_W) != 0 && (p_flags & PF_X) != 0 {
            alerts.push(format!(
                "Writable and Executable (RWX) PT_LOAD segment detected at 0x{p_vaddr:016X}"
            ));
        }

        program_headers.push(ElfProgramHeaderInfo {
            segment_type: parse_segment_type(p_type),
            type_raw: p_type,
            flags: parse_segment_flags(p_flags),
            offset: p_offset,
            vaddr: p_vaddr,
            paddr: p_paddr,
            filesz: p_filesz,
            memsz: p_memsz,
            align: p_align,
        });
    }

    // 2. Parse Section Headers & locate section names string table
    let mut shstrtab_slice: &[u8] = &[];

    // Extract shstrtab offset first if available
    if shstrndx < shnum {
        let strtab_off = shoff + shstrndx * shentsize;
        if strtab_off + 64 <= data.len() {
            let offset = read_u64_le(data, strtab_off + 24)? as usize;
            let size = read_u64_le(data, strtab_off + 32)? as usize;
            if let Some(slice) = data.get(offset..offset.saturating_add(size)) {
                shstrtab_slice = slice;
            }
        }
    }

    let mut sections = Vec::with_capacity(shnum);
    let mut dynstr_slice: &[u8] = &[];
    let mut strtab_slice: &[u8] = &[];
    let mut symtab_meta = None;
    let mut dynsym_meta = None;
    let mut dynamic_meta = None;

    for i in 0..shnum {
        let entry_off =
            shoff
                .checked_add(i.checked_mul(shentsize).ok_or_else(|| {
                    SentinelError::BoundsError("shoff arithmetic overflow".into())
                })?)
                .ok_or_else(|| SentinelError::BoundsError("shoff entry overflow".into()))?;

        if entry_off.saturating_add(64) > data.len() {
            alerts.push(format!(
                "Section header index {i} points outside file boundaries (offset 0x{entry_off:X})"
            ));
            break;
        }

        let sh_name = read_u32_le(data, entry_off)?;
        let sh_type = read_u32_le(data, entry_off + 4)?;
        let sh_flags = read_u64_le(data, entry_off + 8)?;
        let sh_addr = read_u64_le(data, entry_off + 16)?;
        let sh_offset = read_u64_le(data, entry_off + 24)?;
        let sh_size = read_u64_le(data, entry_off + 32)?;
        let sh_link = read_u32_le(data, entry_off + 40)?;
        let sh_info = read_u32_le(data, entry_off + 44)?;
        let sh_addralign = read_u64_le(data, entry_off + 48)?;
        let sh_entsize = read_u64_le(data, entry_off + 56)?;

        let name = if (sh_name as usize) < shstrtab_slice.len() {
            read_cstring(shstrtab_slice, sh_name as usize)
        } else {
            format!("sec_{i}")
        };

        let raw_off = sh_offset as usize;
        let raw_sz = sh_size as usize;
        let sec_data = if sh_type != SHT_NOBITS {
            data.get(raw_off..raw_off.saturating_add(raw_sz))
                .unwrap_or(&[])
        } else {
            &[]
        };

        if name == ".dynstr" {
            dynstr_slice = sec_data;
        } else if name == ".strtab" {
            strtab_slice = sec_data;
        }

        if sh_type == SHT_SYMTAB {
            symtab_meta = Some((raw_off, raw_sz, sh_entsize, sh_link));
        } else if sh_type == SHT_DYNSYM {
            dynsym_meta = Some((raw_off, raw_sz, sh_entsize, sh_link));
        } else if sh_type == SHT_DYNAMIC {
            dynamic_meta = Some((raw_off, raw_sz));
        }

        let entropy = if !sec_data.is_empty() {
            shannon_entropy(sec_data)
        } else {
            0.0
        };

        let is_write = (sh_flags & SHF_WRITE) != 0;
        let is_exec = (sh_flags & SHF_EXECINSTR) != 0;
        let rwx_anomaly = is_write && is_exec;

        if rwx_anomaly {
            alerts.push(format!(
                "Section '{name}' has RWX permissions (writable and executable)"
            ));
        }

        if entropy >= 7.2 && (sh_flags & SHF_EXECINSTR) != 0 {
            alerts.push(format!(
                "Code section '{name}' exhibits high entropy ({entropy:.4} bits/byte), suggesting packing or encryption"
            ));
        }

        sections.push(ElfSectionHeaderInfo {
            name,
            section_type: parse_section_type(sh_type),
            type_raw: sh_type,
            flags: parse_section_flags(sh_flags),
            flags_raw: sh_flags,
            addr: sh_addr,
            offset: sh_offset,
            size: sh_size,
            link: sh_link,
            info: sh_info,
            align: sh_addralign,
            entsize: sh_entsize,
            entropy,
            rwx_anomaly,
        });
    }

    // 3. Parse Dynamic Tags
    let mut dynamic_tags = Vec::new();
    let mut bind_now = false;
    let mut flags_1_pie = false;

    if let Some((dyn_off, dyn_sz)) = dynamic_meta {
        let mut curr = dyn_off;
        let dyn_end = dyn_off.saturating_add(dyn_sz).min(data.len());
        while curr + 16 <= dyn_end {
            let tag = read_i64_le(data, curr)?;
            let val = read_u64_le(data, curr + 8)?;
            curr += 16;
            if tag == DT_NULL {
                break;
            }

            let mut parsed_string = None;
            if matches!(tag, DT_NEEDED | DT_SONAME | DT_RPATH | DT_RUNPATH) {
                let str_off = val as usize;
                if str_off < dynstr_slice.len() {
                    parsed_string = Some(read_cstring(dynstr_slice, str_off));
                }
            }

            if tag == DT_BIND_NOW || (tag == DT_FLAGS && (val & DF_BIND_NOW) != 0) {
                bind_now = true;
            } else if tag == DT_FLAGS_1 {
                if (val & DF_1_NOW) != 0 {
                    bind_now = true;
                }
                if (val & DF_1_PIE) != 0 {
                    flags_1_pie = true;
                }
            }

            dynamic_tags.push(ElfDynamicEntry {
                tag,
                tag_name: parse_dynamic_tag_name(tag),
                val,
                parsed_string,
            });
        }
    }

    // 4. Parse Symbols (.symtab or .dynsym)
    let mut symbols = Vec::new();
    let mut stack_canary = false;

    let target_syms = [
        symtab_meta.map(|m| (m, strtab_slice)),
        dynsym_meta.map(|m| (m, dynstr_slice)),
    ];

    for (meta, strings) in target_syms.into_iter().flatten() {
        let (raw_off, raw_sz, entsize, _) = meta;
        let ent = if entsize > 0 { entsize as usize } else { 24 };
        let count = raw_sz / ent;
        for j in 0..count {
            let sym_off = raw_off + j * ent;
            if sym_off + 24 > data.len() {
                break;
            }

            let st_name = read_u32_le(data, sym_off)? as usize;
            let st_info = data[sym_off + 4];
            let st_other = data[sym_off + 5];
            let st_shndx = read_u16_le(data, sym_off + 6)?;
            let st_value = read_u64_le(data, sym_off + 8)?;
            let st_size = read_u64_le(data, sym_off + 16)?;

            let name = if st_name < strings.len() {
                read_cstring(strings, st_name)
            } else {
                String::new()
            };

            if name.contains("__stack_chk_fail")
                || name.contains("__stack_chk_guard")
                || name.contains("__intel_security_cookie")
            {
                stack_canary = true;
            }

            let bind = match st_info >> 4 {
                0 => "LOCAL",
                1 => "GLOBAL",
                2 => "WEAK",
                _ => "OTHER",
            };

            let sym_type = match st_info & 0x0F {
                0 => "NOTYPE",
                1 => "OBJECT",
                2 => "FUNC",
                3 => "SECTION",
                4 => "FILE",
                _ => "OTHER",
            };

            let visibility = match st_other & 0x03 {
                0 => "DEFAULT",
                1 => "INTERNAL",
                2 => "HIDDEN",
                3 => "PROTECTED",
                _ => "OTHER",
            };

            if !name.is_empty() {
                symbols.push(ElfSymbolInfo {
                    name,
                    binding: bind.into(),
                    symbol_type: sym_type.into(),
                    visibility: visibility.into(),
                    shndx: st_shndx,
                    value: st_value,
                    size: st_size,
                });
            }
        }
    }

    // 5. Evaluate Mitigations
    let pie = type_raw == ET_DYN || flags_1_pie;
    let relro = if has_relro {
        if bind_now {
            RelroLevel::Full
        } else {
            RelroLevel::Partial
        }
    } else {
        RelroLevel::None
    };

    let nx = match gnu_stack_flags {
        Some(flags) => {
            let is_exec = (flags & PF_X) != 0;
            if is_exec {
                alerts.push(
                    "Executable stack detected (PT_GNU_STACK has PF_X set, NX disabled)".into(),
                );
                false
            } else {
                true
            }
        }
        None => {
            alerts.push("No PT_GNU_STACK segment found; legacy executable stack implied".into());
            false
        }
    };

    let overall_entropy = shannon_entropy(data);

    Ok(ElfInfo {
        class: "ELF64".into(),
        endianness: "Little Endian (ELFDATA2LSB)".into(),
        os_abi,
        elf_type: type_to_name(type_raw).into(),
        type_raw,
        machine: machine_to_name(machine_raw).into(),
        machine_raw,
        entry_point,
        program_headers,
        sections,
        dynamic_tags,
        symbols,
        mitigations: ElfSecurityMitigations {
            pie,
            relro,
            nx,
            stack_canary,
        },
        overall_entropy,
        alerts,
    })
}
