// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::Serialize;

use crate::error::{Result, SentinelError};

// Mach-O Magic Signatures
pub const MH_MAGIC_64: u32 = 0xFEEDFACF; // 64-bit Mach-O (host / BE)
pub const MH_CIGAM_64: u32 = 0xCFFAEDFE; // 64-bit Mach-O (byte-swapped)
pub const FAT_MAGIC: u32 = 0xCAFEBABE; // Universal Fat Binary (Big-Endian)
pub const FAT_CIGAM: u32 = 0xBEBAFECA; // Universal Fat Binary (byte-swapped)
pub const MH_MAGIC_32: u32 = 0xFEEDFACE; // 32-bit Mach-O
pub const MH_CIGAM_32: u32 = 0xCEFAEDFE; // 32-bit Mach-O (byte-swapped)

// CPU Types (cputype)
pub const CPU_TYPE_X86: u32 = 7;
pub const CPU_TYPE_ARM: u32 = 12;
pub const CPU_TYPE_POWERPC: u32 = 18;
pub const CPU_ARCH_ABI64: u32 = 0x01000000;
pub const CPU_TYPE_X86_64: u32 = CPU_ARCH_ABI64 | CPU_TYPE_X86; // 0x01000007
pub const CPU_TYPE_ARM64: u32 = CPU_ARCH_ABI64 | CPU_TYPE_ARM; // 0x0100000C
pub const CPU_ARCH_ABI64_32: u32 = 0x02000000;
pub const CPU_TYPE_ARM64_32: u32 = CPU_ARCH_ABI64_32 | CPU_TYPE_ARM;

// CPU Subtypes (cpusubtype)
pub const CPU_SUBTYPE_X86_64_ALL: u32 = 3;
pub const CPU_SUBTYPE_X86_64_H: u32 = 8;
pub const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
pub const CPU_SUBTYPE_ARM64_V8: u32 = 1;
pub const CPU_SUBTYPE_ARM64E: u32 = 2;

// File Types (filetype)
pub const MH_OBJECT: u32 = 1;
pub const MH_EXECUTE: u32 = 2;
pub const MH_FVMLIB: u32 = 3;
pub const MH_CORE: u32 = 4;
pub const MH_PREBOUND: u32 = 5;
pub const MH_DYLIB: u32 = 6;
pub const MH_DYLINKER: u32 = 7;
pub const MH_BUNDLE: u32 = 8;
pub const MH_DYLIB_STUB: u32 = 9;
pub const MH_DSYM: u32 = 10;
pub const MH_KEXT_BUNDLE: u32 = 11;

// Mach-O Header Flags (flags)
pub const MH_NOUNDEFS: u32 = 0x00000001;
pub const MH_DYLDLINK: u32 = 0x00000004;
pub const MH_TWOLEVEL: u32 = 0x00000080;
pub const MH_ALLOW_STACK_EXECUTION: u32 = 0x00020000;
pub const MH_PIE: u32 = 0x00200000;
pub const MH_NO_HEAP_EXECUTION: u32 = 0x01000000;

// Load Commands (cmd)
pub const LC_SEGMENT: u32 = 0x01;
pub const LC_SYMTAB: u32 = 0x02;
pub const LC_UNIXTHREAD: u32 = 0x05;
pub const LC_LOAD_DYLIB: u32 = 0x0C;
pub const LC_ID_DYLIB: u32 = 0x0D;
pub const LC_LOAD_DYLINKER: u32 = 0x0E;
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_UUID: u32 = 0x1B;
pub const LC_RPATH: u32 = 0x8000001C;
pub const LC_CODE_SIGNATURE: u32 = 0x1D;
pub const LC_SEGMENT_SPLIT_INFO: u32 = 0x1E;
pub const LC_REEXPORT_DYLIB: u32 = 0x8000001F;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_MAIN: u32 = 0x80000028;
pub const LC_DATA_IN_CODE: u32 = 0x29;
pub const LC_SOURCE_VERSION: u32 = 0x2A;
pub const LC_BUILD_VERSION: u32 = 0x32;

// VM Protection Constants
pub const VM_PROT_NONE: u32 = 0x00;
pub const VM_PROT_READ: u32 = 0x01;
pub const VM_PROT_WRITE: u32 = 0x02;
pub const VM_PROT_EXECUTE: u32 = 0x04;

/// Mach-O security mitigation posture.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MachoSecurityMitigations {
    pub pie: bool,
    pub nx: bool,
    pub code_signature: bool,
    pub two_level_namespace: bool,
}

/// Parsed LC_CODE_SIGNATURE data descriptor.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MachoCodeSignature {
    pub dataoff: u32,
    pub datasize: u32,
}

/// Parsed Mach-O 64-bit Section (section_64).
#[derive(Debug, Clone, Serialize)]
pub struct MachoSection {
    pub sectname: String,
    pub segname: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub permissions: String,
    pub entropy: f64,
    pub rwx_anomaly: bool,
}

/// Parsed Mach-O 64-bit Segment (segment_command_64).
#[derive(Debug, Clone, Serialize)]
pub struct MachoSegment {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub permissions: String,
    pub nsects: u32,
    pub flags: u32,
    pub rwx_anomaly: bool,
}

/// Forensic summary of a single Mach-O architecture slice.
#[derive(Debug, Clone, Serialize)]
pub struct MachoArchInfo {
    pub cpu_type: String,
    pub cpu_type_raw: u32,
    pub cpu_subtype: String,
    pub cpu_subtype_raw: u32,
    pub file_type: String,
    pub file_type_raw: u32,
    pub offset: u64,
    pub size: u64,
    pub entry_point: Option<u64>,
    pub stack_size: Option<u64>,
    pub segments: Vec<MachoSegment>,
    pub sections: Vec<MachoSection>,
    pub dylibs: Vec<String>,
    pub code_signature: Option<MachoCodeSignature>,
    pub mitigations: MachoSecurityMitigations,
    pub load_commands_count: u32,
    pub sizeofcmds: u32,
    pub flags_raw: u32,
}

/// Top-level forensic report for a Mach-O binary (Single or Universal Fat).
#[derive(Debug, Clone, Serialize)]
pub struct MachoInfo {
    pub format: String,
    pub magic: String,
    pub is_universal: bool,
    pub architectures: Vec<MachoArchInfo>,
    pub overall_entropy: f64,
    pub alerts: Vec<String>,
}

/// Map numeric cputype to architecture identifier.
pub fn cputype_to_name(cputype: u32) -> &'static str {
    match cputype {
        CPU_TYPE_X86_64 => "x86_64",
        CPU_TYPE_ARM64 => "arm64",
        CPU_TYPE_ARM64_32 => "arm64_32",
        CPU_TYPE_X86 => "i386",
        CPU_TYPE_ARM => "arm",
        CPU_TYPE_POWERPC => "ppc",
        _ => "unknown",
    }
}

/// Map numeric cpusubtype to subtype name.
pub fn cpusubtype_to_name(cputype: u32, subtype: u32) -> &'static str {
    let clean = subtype & 0x00FFFFFF;
    match cputype {
        CPU_TYPE_X86_64 => match clean {
            CPU_SUBTYPE_X86_64_ALL => "x86_64_all",
            CPU_SUBTYPE_X86_64_H => "x86_64_haswell",
            _ => "x86_64_unknown",
        },
        CPU_TYPE_ARM64 => match clean {
            CPU_SUBTYPE_ARM64_ALL => "arm64_all",
            CPU_SUBTYPE_ARM64_V8 => "arm64_v8",
            CPU_SUBTYPE_ARM64E => "arm64e",
            _ => "arm64_unknown",
        },
        _ => "all",
    }
}

/// Map numeric filetype to Mach-O file type description.
pub fn filetype_to_name(filetype: u32) -> &'static str {
    match filetype {
        MH_OBJECT => "MH_OBJECT",
        MH_EXECUTE => "MH_EXECUTE",
        MH_FVMLIB => "MH_FVMLIB",
        MH_CORE => "MH_CORE",
        MH_PREBOUND => "MH_PREBOUND",
        MH_DYLIB => "MH_DYLIB",
        MH_DYLINKER => "MH_DYLINKER",
        MH_BUNDLE => "MH_BUNDLE",
        MH_DYLIB_STUB => "MH_DYLIB_STUB",
        MH_DSYM => "MH_DSYM",
        MH_KEXT_BUNDLE => "MH_KEXT_BUNDLE",
        _ => "MH_UNKNOWN",
    }
}

/// Format VM protection bitmask as POSIX-style permission string (`rwx`).
pub fn format_vm_prot(prot: u32) -> String {
    let r = if (prot & VM_PROT_READ) != 0 { 'r' } else { '-' };
    let w = if (prot & VM_PROT_WRITE) != 0 {
        'w'
    } else {
        '-'
    };
    let x = if (prot & VM_PROT_EXECUTE) != 0 {
        'x'
    } else {
        '-'
    };
    format!("{r}{w}{x}")
}

/// Safely decode fixed-length null-padded byte slices into UTF-8 strings.
pub fn parse_fixed_str(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).to_string()
}

// Byte reader helpers
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

pub fn read_u32_be(data: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| SentinelError::BoundsError("u32 offset overflow".into()))?;
    let slice = data.get(offset..end).ok_or_else(|| {
        SentinelError::BoundsError(format!("Truncated read for u32_be at 0x{offset:X}"))
    })?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}
