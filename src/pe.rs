// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::Serialize;

use crate::entropy::{detect_packer_signatures, shannon_entropy};
use crate::error::{Result, SentinelError};

pub const DOS_MAGIC: u16 = 0x5A4D; // "MZ"
pub const NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
pub const PE32_MAGIC: u16 = 0x010B;
pub const PE32_PLUS_MAGIC: u16 = 0x020B;

pub const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
pub const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
pub const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;

pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

/// Data directory entry specifying the RVA and size of an image table.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Default)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// Exploit mitigation flags extracted from the Optional Header `DllCharacteristics`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SecurityMitigations {
    pub aslr: bool,
    pub high_entropy_va: bool,
    pub dep_nx: bool,
    pub cfg: bool,
}

/// Parsed metadata and entropy profile for an individual PE section.
#[derive(Debug, Clone, Serialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
    pub characteristics: u32,
    pub permissions: String,
    pub entropy: f64,
    pub rwx_anomaly: bool,
}

/// Complete static inspection summary of a PE32 or PE32+ image.
#[derive(Debug, Clone, Serialize)]
pub struct PeInfo {
    pub format: String,
    pub machine: u16,
    pub machine_name: String,
    pub number_of_sections: u16,
    pub timestamp: u32,
    pub characteristics: u16,
    pub entry_point: u32,
    pub image_base: u64,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub mitigations: SecurityMitigations,
    pub overall_entropy: f64,
    pub data_directories: Vec<DataDirectory>,
    pub sections: Vec<SectionInfo>,
    pub alerts: Vec<String>,
}

impl PeInfo {
    /// Translates a Relative Virtual Address (RVA) to a raw file offset using the image sections.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        rva_to_file_offset(&self.sections, rva)
    }

    /// Retrieves a data directory by entry index if present.
    pub fn data_directory(&self, index: usize) -> Option<&DataDirectory> {
        self.data_directories.get(index)
    }
}

fn read_u16_le(data: &[u8], offset: usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| SentinelError::BoundsError("u16 offset overflow".into()))?;
    let slice = data.get(offset..end).ok_or_else(|| {
        SentinelError::BoundsError(format!("Truncated read for u16 at 0x{offset:X}"))
    })?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| SentinelError::BoundsError("u32 offset overflow".into()))?;
    let slice = data.get(offset..end).ok_or_else(|| {
        SentinelError::BoundsError(format!("Truncated read for u32 at 0x{offset:X}"))
    })?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64_le(data: &[u8], offset: usize) -> Result<u64> {
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

fn machine_to_name(machine: u16) -> &'static str {
    match machine {
        0x014C => "x86 (I386)",
        0x8664 => "x86_64 (AMD64)",
        0xAA64 => "ARM64 (AArch64)",
        0x01C4 => "ARMv7 (Thumb-2)",
        _ => "Unknown",
    }
}

fn format_permissions(chars: u32) -> String {
    let r = if (chars & IMAGE_SCN_MEM_READ) != 0 {
        'R'
    } else {
        '-'
    };
    let w = if (chars & IMAGE_SCN_MEM_WRITE) != 0 {
        'W'
    } else {
        '-'
    };
    let x = if (chars & IMAGE_SCN_MEM_EXECUTE) != 0 {
        'X'
    } else {
        '-'
    };
    format!("{r}{w}{x}")
}

/// Translates a Relative Virtual Address (RVA) to a raw file offset within the PE image.
pub fn rva_to_file_offset(sections: &[SectionInfo], rva: u32) -> Option<usize> {
    if rva == 0 {
        return None;
    }
    for sec in sections {
        let sec_len = if sec.virtual_size > 0 {
            sec.virtual_size
        } else {
            sec.raw_size
        };
        if rva >= sec.virtual_address && rva < sec.virtual_address.saturating_add(sec_len) {
            let offset_into_sec = rva - sec.virtual_address;
            if offset_into_sec < sec.raw_size {
                return (sec.raw_offset as usize).checked_add(offset_into_sec as usize);
            }
        }
    }
    let first_sec_va = sections
        .iter()
        .map(|s| s.virtual_address)
        .min()
        .unwrap_or(0x1000);
    if rva < first_sec_va {
        return Some(rva as usize);
    }
    None
}

/// Parses a Windows PE32 or PE32+ executable buffer with strict bounds validation.
pub fn parse_pe(data: &[u8]) -> Result<PeInfo> {
    if data.len() < 0x40 {
        return Err(SentinelError::InvalidFormat(
            "File smaller than minimum 64-byte DOS header".into(),
        ));
    }

    let dos_magic = read_u16_le(data, 0)?;
    if dos_magic != DOS_MAGIC {
        return Err(SentinelError::InvalidFormat(format!(
            "Invalid DOS MZ magic: 0x{dos_magic:04X}"
        )));
    }

    let e_lfanew = read_u32_le(data, 0x3C)? as usize;
    let coff_offset = e_lfanew
        .checked_add(4)
        .ok_or_else(|| SentinelError::BoundsError("e_lfanew overflow".into()))?;
    let opt_offset = coff_offset
        .checked_add(20)
        .ok_or_else(|| SentinelError::BoundsError("COFF header overflow".into()))?;

    if opt_offset > data.len() {
        return Err(SentinelError::BoundsError(format!(
            "e_lfanew (0x{e_lfanew:X}) points outside file bounds ({} bytes)",
            data.len()
        )));
    }

    let nt_sig = read_u32_le(data, e_lfanew)?;
    if nt_sig != NT_SIGNATURE {
        return Err(SentinelError::InvalidFormat(format!(
            "Invalid PE NT signature: 0x{nt_sig:08X}"
        )));
    }

    let machine = read_u16_le(data, coff_offset)?;
    let number_of_sections = read_u16_le(data, coff_offset + 2)?;
    let timestamp = read_u32_le(data, coff_offset + 4)?;
    let size_of_optional_header = read_u16_le(data, coff_offset + 16)? as usize;
    let characteristics = read_u16_le(data, coff_offset + 18)?;

    if number_of_sections > 96 {
        return Err(SentinelError::InvalidFormat(format!(
            "Excessive section count ({number_of_sections} > 96)"
        )));
    }

    if size_of_optional_header < 0x48 {
        return Err(SentinelError::InvalidFormat(format!(
            "Optional header too small ({size_of_optional_header} bytes)"
        )));
    }

    let section_table_offset = opt_offset
        .checked_add(size_of_optional_header)
        .ok_or_else(|| SentinelError::BoundsError("Section table offset overflow".into()))?;

    if section_table_offset > data.len() {
        return Err(SentinelError::BoundsError(
            "Optional header extends past end of file".into(),
        ));
    }

    let opt_magic = read_u16_le(data, opt_offset)?;
    let entry_point = read_u32_le(data, opt_offset + 16)?;

    let (format_name, image_base, subsystem, dll_characteristics, data_dir_start, num_rva_sizes) =
        match opt_magic {
            PE32_MAGIC => {
                let base = u64::from(read_u32_le(data, opt_offset + 28)?);
                let subsys = read_u16_le(data, opt_offset + 68)?;
                let dll_chars = read_u16_le(data, opt_offset + 70)?;
                let num_rva = if size_of_optional_header >= 96 {
                    read_u32_le(data, opt_offset + 92).unwrap_or(0)
                } else {
                    0
                };
                (
                    "PE32".to_string(),
                    base,
                    subsys,
                    dll_chars,
                    opt_offset + 96,
                    num_rva,
                )
            }
            PE32_PLUS_MAGIC => {
                let base = read_u64_le(data, opt_offset + 24)?;
                let subsys = read_u16_le(data, opt_offset + 68)?;
                let dll_chars = read_u16_le(data, opt_offset + 70)?;
                let num_rva = if size_of_optional_header >= 112 {
                    read_u32_le(data, opt_offset + 108).unwrap_or(0)
                } else {
                    0
                };
                (
                    "PE32+ (64-bit)".to_string(),
                    base,
                    subsys,
                    dll_chars,
                    opt_offset + 112,
                    num_rva,
                )
            }
            other => {
                return Err(SentinelError::InvalidFormat(format!(
                    "Unsupported Optional Header magic: 0x{other:04X}"
                )));
            }
        };

    let mut data_directories = Vec::new();
    let max_dirs = (num_rva_sizes as usize).min(16);
    for idx in 0..max_dirs {
        let entry_off = data_dir_start + (idx * 8);
        if entry_off + 8 <= opt_offset + size_of_optional_header && entry_off + 8 <= data.len() {
            let va = read_u32_le(data, entry_off)?;
            let sz = read_u32_le(data, entry_off + 4)?;
            data_directories.push(DataDirectory {
                virtual_address: va,
                size: sz,
            });
        }
    }

    let mitigations = SecurityMitigations {
        aslr: (dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0,
        high_entropy_va: (dll_characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0,
        dep_nx: (dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0,
        cfg: (dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0,
    };

    let mut sections = Vec::with_capacity(number_of_sections as usize);
    for idx in 0..(number_of_sections as usize) {
        let sec_off = section_table_offset
            .checked_add(idx * 40)
            .ok_or_else(|| SentinelError::BoundsError("Section offset overflow".into()))?;
        let sec_end = sec_off
            .checked_add(40)
            .ok_or_else(|| SentinelError::BoundsError("Section end overflow".into()))?;
        if sec_end > data.len() {
            return Err(SentinelError::BoundsError(format!(
                "Section header #{idx} truncated at 0x{sec_off:X}"
            )));
        }

        let raw_name = &data[sec_off..sec_off + 8];
        let name_end = raw_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(raw_name.len());
        let name = String::from_utf8_lossy(&raw_name[..name_end]).to_string();

        let virtual_size = read_u32_le(data, sec_off + 8)?;
        let virtual_address = read_u32_le(data, sec_off + 12)?;
        let raw_size = read_u32_le(data, sec_off + 16)?;
        let raw_offset = read_u32_le(data, sec_off + 20)?;
        let sec_chars = read_u32_le(data, sec_off + 36)?;

        let slice_entropy = if raw_size > 0 {
            let start = raw_offset as usize;
            let end = start.saturating_add(raw_size as usize).min(data.len());
            if start < data.len() && start < end {
                shannon_entropy(&data[start..end])
            } else {
                0.0
            }
        } else {
            0.0
        };

        let rwx_anomaly =
            (sec_chars & IMAGE_SCN_MEM_WRITE) != 0 && (sec_chars & IMAGE_SCN_MEM_EXECUTE) != 0;

        sections.push(SectionInfo {
            name,
            virtual_size,
            virtual_address,
            raw_size,
            raw_offset,
            characteristics: sec_chars,
            permissions: format_permissions(sec_chars),
            entropy: (slice_entropy * 10000.0).round() / 10000.0,
            rwx_anomaly,
        });
    }

    let overall_entropy = (shannon_entropy(data) * 10000.0).round() / 10000.0;

    let mut info = PeInfo {
        format: format_name,
        machine,
        machine_name: machine_to_name(machine).to_string(),
        number_of_sections,
        timestamp,
        characteristics,
        entry_point,
        image_base,
        subsystem,
        dll_characteristics,
        mitigations,
        overall_entropy,
        data_directories,
        sections,
        alerts: Vec::new(),
    };

    info.alerts = detect_packer_signatures(&info, data);
    Ok(info)
}

/// Builds a deterministic synthetic PE32+ (64-bit) binary in memory for testing and CLI reproduction.
/// Each section tuple is `(name, raw_bytes, characteristics)`.
pub fn build_synthetic_pe64(sections: &[(&str, &[u8], u32)]) -> Vec<u8> {
    let e_lfanew: usize = 0x80;
    let opt_header_size: usize = 0xF0; // Standard 240-byte PE32+ optional header
    let section_table_offset = e_lfanew + 4 + 20 + opt_header_size;
    let headers_end = section_table_offset + (sections.len() * 40);
    let first_raw_offset = (headers_end + 0x1FF) & !0x1FF; // Align to 512 bytes

    let mut buf = vec![0u8; first_raw_offset];

    // 1. DOS Header
    buf[0..2].copy_from_slice(&DOS_MAGIC.to_le_bytes());
    buf[0x3C..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());

    // 2. NT Signature ("PE\0\0")
    buf[e_lfanew..e_lfanew + 4].copy_from_slice(&NT_SIGNATURE.to_le_bytes());

    // 3. COFF File Header (20 bytes)
    let coff = e_lfanew + 4;
    buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
    buf[coff + 2..coff + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
    buf[coff + 4..coff + 8].copy_from_slice(&0x6700_0000u32.to_le_bytes()); // Timestamp
    buf[coff + 16..coff + 18].copy_from_slice(&(opt_header_size as u16).to_le_bytes());
    buf[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes()); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // 4. Optional Header PE32+
    let opt = coff + 20;
    buf[opt..opt + 2].copy_from_slice(&PE32_PLUS_MAGIC.to_le_bytes());
    buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
    buf[opt + 24..opt + 32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes()); // ImageBase
    buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    buf[opt + 36..opt + 40].copy_from_slice(&0x0200u32.to_le_bytes()); // FileAlignment
    buf[opt + 68..opt + 70].copy_from_slice(&0x0003u16.to_le_bytes()); // IMAGE_SUBSYSTEM_WINDOWS_CUI
    let dll_chars: u16 = IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
        | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        | IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        | IMAGE_DLLCHARACTERISTICS_GUARD_CF;
    buf[opt + 70..opt + 72].copy_from_slice(&dll_chars.to_le_bytes());
    buf[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes (16 data directories)

    // 5. Section Headers & Raw Data
    let mut current_rva: u32 = 0x1000;
    for (idx, (name, raw_bytes, chars)) in sections.iter().enumerate() {
        let sec_off = section_table_offset + idx * 40;
        let mut name_buf = [0u8; 8];
        let copy_len = name.len().min(8);
        name_buf[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);
        buf[sec_off..sec_off + 8].copy_from_slice(&name_buf);

        let raw_offset = buf.len() as u32;
        let aligned_raw_size = ((raw_bytes.len() + 0x1FF) & !0x1FF).max(0x200);
        let virtual_size = raw_bytes.len() as u32;

        buf[sec_off + 8..sec_off + 12].copy_from_slice(&virtual_size.to_le_bytes());
        buf[sec_off + 12..sec_off + 16].copy_from_slice(&current_rva.to_le_bytes());
        buf[sec_off + 16..sec_off + 20].copy_from_slice(&(aligned_raw_size as u32).to_le_bytes());
        buf[sec_off + 20..sec_off + 24].copy_from_slice(&raw_offset.to_le_bytes());
        buf[sec_off + 36..sec_off + 40].copy_from_slice(&chars.to_le_bytes());

        let mut sec_data = vec![0u8; aligned_raw_size];
        sec_data[..raw_bytes.len()].copy_from_slice(raw_bytes);
        buf.extend_from_slice(&sec_data);

        let rva_step = ((virtual_size as usize + 0xFFF) & !0xFFF).max(0x1000) as u32;
        current_rva = current_rva.saturating_add(rva_step);
    }

    buf
}
