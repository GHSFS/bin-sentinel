// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! PE Import Directory (IAT/ILT) and Export Directory (EAT) parser.
//!
//! Provides strict bounds validation and parsing for 32-bit and 64-bit PE import descriptors,
//! thunk tables, ordinal/named imports, and export directory structures.

use std::collections::HashMap;

use serde::Serialize;

use crate::error::{Result, SentinelError};
use crate::pe::{PeInfo, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT};

/// An individual function imported from a dynamic link library.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ImportedFunction {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub hint: Option<u16>,
    pub iat_rva: u32,
}

/// An imported module descriptor corresponding to `IMAGE_IMPORT_DESCRIPTOR`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ImportDescriptor {
    pub dll_name: String,
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub first_thunk: u32,
    pub functions: Vec<ImportedFunction>,
}

/// An individual function exported by the binary.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExportedFunction {
    pub name: Option<String>,
    pub ordinal: u32,
    pub rva: u32,
    pub forwarder: Option<String>,
}

/// Export directory table metadata corresponding to `IMAGE_EXPORT_DIRECTORY`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExportInfo {
    pub dll_name: String,
    pub characteristics: u32,
    pub timestamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub base_ordinal: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub functions: Vec<ExportedFunction>,
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

fn read_ascii_string(data: &[u8], offset: usize, max_len: usize) -> String {
    let mut bytes = Vec::new();
    let max = max_len.min(data.len().saturating_sub(offset));
    for i in 0..max {
        let read_pos = offset.saturating_add(i);
        if let Some(&b) = data.get(read_pos) {
            if b == 0 {
                break;
            }
            bytes.push(b);
        } else {
            break;
        }
    }
    String::from_utf8_lossy(&bytes).to_string()
}

/// Parses all PE import descriptors, ILT/IAT lookup tables, and imported symbols.
pub fn parse_imports(data: &[u8], pe: &PeInfo) -> Result<Vec<ImportDescriptor>> {
    let dir = match pe.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT) {
        Some(d) if d.virtual_address != 0 && d.size != 0 => d,
        _ => return Ok(Vec::new()),
    };

    let dir_offset = match pe.rva_to_offset(dir.virtual_address) {
        Some(off) => off,
        None => return Ok(Vec::new()),
    };

    let is_64bit = pe.format.contains("64");
    let mut descriptors = Vec::new();
    let mut current_desc_off = dir_offset;

    // Safety limit to avoid infinite loops on malformed binaries
    for _ in 0..1024 {
        let Some(desc_end) = current_desc_off.checked_add(20) else {
            break;
        };
        if desc_end > data.len() {
            break;
        }

        let orig_first_thunk = read_u32_le(data, current_desc_off)?;
        let time_date_stamp = read_u32_le(data, current_desc_off + 4)?;
        let forwarder_chain = read_u32_le(data, current_desc_off + 8)?;
        let name_rva = read_u32_le(data, current_desc_off + 12)?;
        let first_thunk = read_u32_le(data, current_desc_off + 16)?;

        // Null descriptor indicates end of the array
        if orig_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        let dll_name = if name_rva != 0 {
            pe.rva_to_offset(name_rva)
                .map(|off| read_ascii_string(data, off, 256))
                .unwrap_or_else(|| format!("Unknown_RVA_0x{name_rva:08X}"))
        } else {
            "Unnamed".to_string()
        };

        let thunk_rva = if orig_first_thunk != 0 {
            orig_first_thunk
        } else {
            first_thunk
        };

        let mut functions = Vec::new();
        if thunk_rva != 0 {
            if let Some(thunk_offset) = pe.rva_to_offset(thunk_rva) {
                let entry_size = if is_64bit { 8 } else { 4 };
                let mut entry_idx: usize = 0;

                while let Some(stride) = entry_idx.checked_mul(entry_size) {
                    let Some(off) = thunk_offset.checked_add(stride) else {
                        break;
                    };
                    let Some(off_end) = off.checked_add(entry_size) else {
                        break;
                    };
                    if off_end > data.len() || entry_idx > 4096 {
                        break;
                    }

                    let (is_ordinal, ordinal_val, name_rva) = if is_64bit {
                        let entry = read_u64_le(data, off)?;
                        if entry == 0 {
                            break;
                        }
                        if (entry & 0x8000_0000_0000_0000) != 0 {
                            (true, Some((entry & 0xFFFF) as u16), None)
                        } else {
                            (false, None, Some((entry & 0x7FFF_FFFF) as u32))
                        }
                    } else {
                        let entry = read_u32_le(data, off)?;
                        if entry == 0 {
                            break;
                        }
                        if (entry & 0x8000_0000) != 0 {
                            (true, Some((entry & 0xFFFF) as u16), None)
                        } else {
                            (false, None, Some(entry & 0x7FFF_FFFF))
                        }
                    };

                    let iat_rva =
                        first_thunk.saturating_add((entry_idx as u32) * (entry_size as u32));

                    if is_ordinal {
                        functions.push(ImportedFunction {
                            name: None,
                            ordinal: ordinal_val,
                            hint: None,
                            iat_rva,
                        });
                    } else if let Some(nrva) = name_rva {
                        let (hint, name) = if let Some(noff) = pe.rva_to_offset(nrva) {
                            if noff.checked_add(2).is_some_and(|end| end <= data.len()) {
                                let h = read_u16_le(data, noff).ok();
                                let s = read_ascii_string(data, noff + 2, 256);
                                (h, Some(s))
                            } else {
                                (None, None)
                            }
                        } else {
                            (None, None)
                        };

                        functions.push(ImportedFunction {
                            name,
                            ordinal: None,
                            hint,
                            iat_rva,
                        });
                    }

                    entry_idx += 1;
                }
            }
        }

        descriptors.push(ImportDescriptor {
            dll_name,
            original_first_thunk: orig_first_thunk,
            time_date_stamp,
            forwarder_chain,
            first_thunk,
            functions,
        });

        let Some(next_off) = current_desc_off.checked_add(20) else {
            break;
        };
        current_desc_off = next_off;
    }

    Ok(descriptors)
}

/// Parses the PE Export Directory (EAT) and exported function symbols.
pub fn parse_exports(data: &[u8], pe: &PeInfo) -> Result<Option<ExportInfo>> {
    let dir = match pe.data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT) {
        Some(d) if d.virtual_address != 0 && d.size != 0 => d,
        _ => return Ok(None),
    };

    let dir_offset = match pe.rva_to_offset(dir.virtual_address) {
        Some(off) => off,
        None => return Ok(None),
    };

    let Some(dir_end) = dir_offset.checked_add(40) else {
        return Err(SentinelError::BoundsError(
            "Export directory offset overflow".into(),
        ));
    };

    if dir_end > data.len() {
        return Err(SentinelError::BoundsError(
            "Export directory extends past file bounds".into(),
        ));
    }

    let characteristics = read_u32_le(data, dir_offset)?;
    let timestamp = read_u32_le(data, dir_offset + 4)?;
    let major_version = read_u16_le(data, dir_offset + 8)?;
    let minor_version = read_u16_le(data, dir_offset + 10)?;
    let name_rva = read_u32_le(data, dir_offset + 12)?;
    let base_ordinal = read_u32_le(data, dir_offset + 16)?;
    let number_of_functions = read_u32_le(data, dir_offset + 20)?;
    let number_of_names = read_u32_le(data, dir_offset + 24)?;
    let addr_functions_rva = read_u32_le(data, dir_offset + 28)?;
    let addr_names_rva = read_u32_le(data, dir_offset + 32)?;
    let addr_ordinals_rva = read_u32_le(data, dir_offset + 36)?;

    let dll_name = if name_rva != 0 {
        pe.rva_to_offset(name_rva)
            .map(|off| read_ascii_string(data, off, 256))
            .unwrap_or_else(|| "ExportDll".to_string())
    } else {
        "ExportDll".to_string()
    };

    let mut name_map: HashMap<usize, String> = HashMap::new();
    if addr_names_rva != 0 && addr_ordinals_rva != 0 {
        let names_offset = pe.rva_to_offset(addr_names_rva);
        let ords_offset = pe.rva_to_offset(addr_ordinals_rva);

        if let (Some(noff), Some(ooff)) = (names_offset, ords_offset) {
            let count = (number_of_names as usize).min(65536);
            for i in 0..count {
                let Some(name_stride) = i.checked_mul(4) else {
                    break;
                };
                let Some(ord_stride) = i.checked_mul(2) else {
                    break;
                };
                let Some(name_entry_off) = noff.checked_add(name_stride) else {
                    break;
                };
                let Some(ord_entry_off) = ooff.checked_add(ord_stride) else {
                    break;
                };
                if name_entry_off
                    .checked_add(4)
                    .is_some_and(|end| end <= data.len())
                    && ord_entry_off
                        .checked_add(2)
                        .is_some_and(|end| end <= data.len())
                {
                    let nrva = read_u32_le(data, name_entry_off)?;
                    let ord_idx = read_u16_le(data, ord_entry_off)? as usize;
                    if let Some(str_off) = pe.rva_to_offset(nrva) {
                        let name_str = read_ascii_string(data, str_off, 256);
                        name_map.insert(ord_idx, name_str);
                    }
                }
            }
        }
    }

    let mut functions = Vec::new();
    if addr_functions_rva != 0 {
        if let Some(foff) = pe.rva_to_offset(addr_functions_rva) {
            let count = (number_of_functions as usize).min(65536);
            for i in 0..count {
                let Some(entry_stride) = i.checked_mul(4) else {
                    break;
                };
                let Some(entry_off) = foff.checked_add(entry_stride) else {
                    break;
                };
                let Some(entry_end) = entry_off.checked_add(4) else {
                    break;
                };
                if entry_end > data.len() {
                    break;
                }
                let func_rva = read_u32_le(data, entry_off)?;
                if func_rva == 0 {
                    continue;
                }

                let ordinal = base_ordinal.saturating_add(i as u32);
                let name = name_map.remove(&i);

                // Check forwarder: RVA is within the Export Directory bounds
                let is_forwarder = dir.virtual_address <= func_rva
                    && func_rva < dir.virtual_address.saturating_add(dir.size);

                let forwarder = if is_forwarder {
                    pe.rva_to_offset(func_rva)
                        .map(|off| read_ascii_string(data, off, 256))
                } else {
                    None
                };

                functions.push(ExportedFunction {
                    name,
                    ordinal,
                    rva: func_rva,
                    forwarder,
                });
            }
        }
    }

    Ok(Some(ExportInfo {
        dll_name,
        characteristics,
        timestamp,
        major_version,
        minor_version,
        base_ordinal,
        number_of_functions,
        number_of_names,
        functions,
    }))
}
