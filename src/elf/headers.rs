// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::Serialize;

use crate::error::{Result, SentinelError};

pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;

// ELF File Types (e_type)
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;

// Machine Architectures (e_machine)
pub const EM_386: u16 = 3;
pub const EM_X86_64: u16 = 62;
pub const EM_ARM: u16 = 40;
pub const EM_AARCH64: u16 = 183;
pub const EM_RISCV: u16 = 243;

// Program Header Types (p_type)
pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_SHLIB: u32 = 5;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
pub const PT_GNU_STACK: u32 = 0x6474_e551;
pub const PT_GNU_RELRO: u32 = 0x6474_e552;
pub const PT_GNU_PROPERTY: u32 = 0x6474_e553;

// Program Header Flags (p_flags)
pub const PF_X: u32 = 0x1;
pub const PF_W: u32 = 0x2;
pub const PF_R: u32 = 0x4;

// Section Header Types (sh_type)
pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_HASH: u32 = 5;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOTE: u32 = 7;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_SHLIB: u32 = 10;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_INIT_ARRAY: u32 = 14;
pub const SHT_FINI_ARRAY: u32 = 15;
pub const SHT_GNU_HASH: u32 = 0x6fff_fff6;

// Section Header Flags (sh_flags)
pub const SHF_WRITE: u64 = 0x1;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;
pub const SHF_MERGE: u64 = 0x10;
pub const SHF_STRINGS: u64 = 0x20;
pub const SHF_INFO_LINK: u64 = 0x40;
pub const SHF_LINK_ORDER: u64 = 0x80;
pub const SHF_TLS: u64 = 0x400;

// Dynamic Array Tags (d_tag)
pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_PLTGOT: i64 = 3;
pub const DT_HASH: i64 = 4;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_SONAME: i64 = 14;
pub const DT_RPATH: i64 = 15;
pub const DT_BIND_NOW: i64 = 24;
pub const DT_RUNPATH: i64 = 29;
pub const DT_FLAGS: i64 = 30;
pub const DT_FLAGS_1: i64 = 0x6fff_fffb;

// Dynamic Flags
pub const DF_BIND_NOW: u64 = 0x8;
pub const DF_1_NOW: u64 = 0x1;
pub const DF_1_PIE: u64 = 0x800_0000;

/// Relocation Read-Only (RELRO) security mitigation level.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum RelroLevel {
    None,
    Partial,
    Full,
}

/// Linux/BSD binary security mitigation flags.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ElfSecurityMitigations {
    pub pie: bool,
    pub relro: RelroLevel,
    pub nx: bool,
    pub stack_canary: bool,
}

/// Parsed ELF64 Program Header (Segment) entry.
#[derive(Debug, Clone, Serialize)]
pub struct ElfProgramHeaderInfo {
    pub segment_type: String,
    pub type_raw: u32,
    pub flags: String,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

/// Parsed ELF64 Section Header entry with Shannon entropy.
#[derive(Debug, Clone, Serialize)]
pub struct ElfSectionHeaderInfo {
    pub name: String,
    pub section_type: String,
    pub type_raw: u32,
    pub flags: String,
    pub flags_raw: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub align: u64,
    pub entsize: u64,
    pub entropy: f64,
    pub rwx_anomaly: bool,
}

/// Dynamic array entry (`.dynamic` / `PT_DYNAMIC`).
#[derive(Debug, Clone, Serialize)]
pub struct ElfDynamicEntry {
    pub tag: i64,
    pub tag_name: String,
    pub val: u64,
    pub parsed_string: Option<String>,
}

/// Parsed symbol from `.symtab` or `.dynsym`.
#[derive(Debug, Clone, Serialize)]
pub struct ElfSymbolInfo {
    pub name: String,
    pub binding: String,
    pub symbol_type: String,
    pub visibility: String,
    pub shndx: u16,
    pub value: u64,
    pub size: u64,
}

/// Comprehensive static forensic summary of an ELF64 image.
#[derive(Debug, Clone, Serialize)]
pub struct ElfInfo {
    pub class: String,
    pub endianness: String,
    pub os_abi: String,
    pub elf_type: String,
    pub type_raw: u16,
    pub machine: String,
    pub machine_raw: u16,
    pub entry_point: u64,
    pub program_headers: Vec<ElfProgramHeaderInfo>,
    pub sections: Vec<ElfSectionHeaderInfo>,
    pub dynamic_tags: Vec<ElfDynamicEntry>,
    pub symbols: Vec<ElfSymbolInfo>,
    pub mitigations: ElfSecurityMitigations,
    pub overall_entropy: f64,
    pub alerts: Vec<String>,
}

pub fn read_u16_le(data: &[u8], offset: usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| SentinelError::BoundsError("u16 offset overflow".into()))?;
    let slice = data.get(offset..end).ok_or_else(|| {
        SentinelError::BoundsError(format!("Truncated read for u16 at 0x{offset:X}"))
    })?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

pub fn read_u32_le(data: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| SentinelError::BoundsError("u32 offset overflow".into()))?;
    let slice = data.get(offset..end).ok_or_else(|| {
        SentinelError::BoundsError(format!("Truncated read for u32 at 0x{offset:X}"))
    })?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub fn read_u64_le(data: &[u8], offset: usize) -> Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| SentinelError::BoundsError("u64 offset overflow".into()))?;
    let slice = data.get(offset..end).ok_or_else(|| {
        SentinelError::BoundsError(format!("Truncated read for u64 at 0x{offset:X}"))
    })?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

pub fn read_i64_le(data: &[u8], offset: usize) -> Result<i64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| SentinelError::BoundsError("i64 offset overflow".into()))?;
    let slice = data.get(offset..end).ok_or_else(|| {
        SentinelError::BoundsError(format!("Truncated read for i64 at 0x{offset:X}"))
    })?;
    Ok(i64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

pub fn read_cstring(data: &[u8], offset: usize) -> String {
    let mut end = offset;
    while end < data.len() && data[end] != 0 && (end - offset) < 4096 {
        end += 1;
    }
    String::from_utf8_lossy(&data[offset..end]).into_owned()
}

pub fn parse_segment_type(p_type: u32) -> String {
    match p_type {
        PT_NULL => "PT_NULL".into(),
        PT_LOAD => "PT_LOAD".into(),
        PT_DYNAMIC => "PT_DYNAMIC".into(),
        PT_INTERP => "PT_INTERP".into(),
        PT_NOTE => "PT_NOTE".into(),
        PT_SHLIB => "PT_SHLIB".into(),
        PT_PHDR => "PT_PHDR".into(),
        PT_TLS => "PT_TLS".into(),
        PT_GNU_EH_FRAME => "PT_GNU_EH_FRAME".into(),
        PT_GNU_STACK => "PT_GNU_STACK".into(),
        PT_GNU_RELRO => "PT_GNU_RELRO".into(),
        PT_GNU_PROPERTY => "PT_GNU_PROPERTY".into(),
        other => format!("PT_0x{other:08X}"),
    }
}

pub fn parse_segment_flags(flags: u32) -> String {
    let r = if (flags & PF_R) != 0 { 'R' } else { '-' };
    let w = if (flags & PF_W) != 0 { 'W' } else { '-' };
    let x = if (flags & PF_X) != 0 { 'X' } else { '-' };
    format!("{r}{w}{x}")
}

pub fn parse_section_type(sh_type: u32) -> String {
    match sh_type {
        SHT_NULL => "SHT_NULL".into(),
        SHT_PROGBITS => "SHT_PROGBITS".into(),
        SHT_SYMTAB => "SHT_SYMTAB".into(),
        SHT_STRTAB => "SHT_STRTAB".into(),
        SHT_RELA => "SHT_RELA".into(),
        SHT_HASH => "SHT_HASH".into(),
        SHT_DYNAMIC => "SHT_DYNAMIC".into(),
        SHT_NOTE => "SHT_NOTE".into(),
        SHT_NOBITS => "SHT_NOBITS".into(),
        SHT_REL => "SHT_REL".into(),
        SHT_SHLIB => "SHT_SHLIB".into(),
        SHT_DYNSYM => "SHT_DYNSYM".into(),
        SHT_INIT_ARRAY => "SHT_INIT_ARRAY".into(),
        SHT_FINI_ARRAY => "SHT_FINI_ARRAY".into(),
        SHT_GNU_HASH => "SHT_GNU_HASH".into(),
        other => format!("SHT_0x{other:08X}"),
    }
}

pub fn parse_section_flags(flags: u64) -> String {
    let mut parts = Vec::new();
    if (flags & SHF_WRITE) != 0 {
        parts.push("W");
    }
    if (flags & SHF_ALLOC) != 0 {
        parts.push("A");
    }
    if (flags & SHF_EXECINSTR) != 0 {
        parts.push("X");
    }
    if (flags & SHF_STRINGS) != 0 {
        parts.push("S");
    }
    if (flags & SHF_TLS) != 0 {
        parts.push("T");
    }
    if parts.is_empty() {
        "-".into()
    } else {
        parts.join("")
    }
}

pub fn parse_dynamic_tag_name(tag: i64) -> String {
    match tag {
        DT_NULL => "DT_NULL".into(),
        DT_NEEDED => "DT_NEEDED".into(),
        DT_PLTGOT => "DT_PLTGOT".into(),
        DT_HASH => "DT_HASH".into(),
        DT_STRTAB => "DT_STRTAB".into(),
        DT_SYMTAB => "DT_SYMTAB".into(),
        DT_SONAME => "DT_SONAME".into(),
        DT_RPATH => "DT_RPATH".into(),
        DT_BIND_NOW => "DT_BIND_NOW".into(),
        DT_RUNPATH => "DT_RUNPATH".into(),
        DT_FLAGS => "DT_FLAGS".into(),
        DT_FLAGS_1 => "DT_FLAGS_1".into(),
        other => format!("DT_{other}"),
    }
}

pub fn machine_to_name(m: u16) -> &'static str {
    match m {
        EM_386 => "x86 (i386)",
        EM_X86_64 => "x86_64 (AMD64)",
        EM_ARM => "ARM (32-bit)",
        EM_AARCH64 => "AArch64 (ARM64)",
        EM_RISCV => "RISC-V",
        _ => "Unknown Architecture",
    }
}

pub fn osabi_to_name(abi: u8) -> &'static str {
    match abi {
        0 => "UNIX System V",
        1 => "HP-UX",
        2 => "NetBSD",
        3 => "Linux",
        6 => "Solaris",
        7 => "AIX",
        8 => "IRIX",
        9 => "FreeBSD",
        12 => "OpenBSD",
        _ => "Other / Architecture-specific",
    }
}

pub fn type_to_name(t: u16) -> &'static str {
    match t {
        ET_REL => "Relocatable (ET_REL)",
        ET_EXEC => "Executable (ET_EXEC)",
        ET_DYN => "Shared object / PIE (ET_DYN)",
        ET_CORE => "Core dump (ET_CORE)",
        _ => "Unknown type",
    }
}
