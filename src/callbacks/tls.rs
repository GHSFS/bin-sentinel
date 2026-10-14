// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::callbacks::types::{TlsCallbackEntry, TlsDirectoryInfo};
use crate::error::{Result, SentinelError};
use crate::pe::{
    PeInfo, SectionInfo, IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE,
};

/// Maximum number of TLS callbacks parsed to protect against maliciously cyclic structures.
const MAX_TLS_CALLBACKS: usize = 256;

/// Parses the PE TLS Directory (`IMAGE_DIRECTORY_ENTRY_TLS`) and extracts the array of TLS callbacks.
pub fn parse_tls_directory(
    data: &[u8],
    pe: &PeInfo,
    alerts: &mut Vec<String>,
) -> Result<TlsDirectoryInfo> {
    let dir = match pe.data_directory(IMAGE_DIRECTORY_ENTRY_TLS) {
        Some(d) if d.virtual_address != 0 && d.size != 0 => *d,
        _ => return Ok(TlsDirectoryInfo::default()),
    };

    let dir_rva = dir.virtual_address;
    let dir_size = dir.size;

    let dir_offset = match pe.rva_to_offset(dir_rva) {
        Some(off) => off,
        None => {
            alerts.push(format!(
                "TLS Directory RVA 0x{dir_rva:08X} cannot be resolved to any mapped PE section"
            ));
            return Ok(TlsDirectoryInfo {
                present: true,
                directory_rva: dir_rva,
                directory_size: dir_size,
                ..Default::default()
            });
        }
    };

    let is_64bit = pe.format.starts_with("PE32+");
    let (raw_start, raw_end, idx_addr, cb_addr, zero_fill, chars) = if is_64bit {
        // IMAGE_TLS_DIRECTORY64 (40 bytes)
        let end_struct = dir_offset
            .checked_add(40)
            .ok_or_else(|| SentinelError::BoundsError("TLS directory offset overflow".into()))?;
        let slice = data.get(dir_offset..end_struct).ok_or_else(|| {
            SentinelError::BoundsError(format!(
                "Truncated TLS directory header at offset 0x{dir_offset:X}"
            ))
        })?;
        let raw_start = u64::from_le_bytes(slice[0..8].try_into().unwrap());
        let raw_end = u64::from_le_bytes(slice[8..16].try_into().unwrap());
        let idx_addr = u64::from_le_bytes(slice[16..24].try_into().unwrap());
        let cb_addr = u64::from_le_bytes(slice[24..32].try_into().unwrap());
        let zero_fill = u32::from_le_bytes(slice[32..36].try_into().unwrap());
        let chars = u32::from_le_bytes(slice[36..40].try_into().unwrap());
        (raw_start, raw_end, idx_addr, cb_addr, zero_fill, chars)
    } else {
        // IMAGE_TLS_DIRECTORY32 (24 bytes)
        let end_struct = dir_offset
            .checked_add(24)
            .ok_or_else(|| SentinelError::BoundsError("TLS directory offset overflow".into()))?;
        let slice = data.get(dir_offset..end_struct).ok_or_else(|| {
            SentinelError::BoundsError(format!(
                "Truncated TLS directory header at offset 0x{dir_offset:X}"
            ))
        })?;
        let raw_start = u32::from_le_bytes(slice[0..4].try_into().unwrap()) as u64;
        let raw_end = u32::from_le_bytes(slice[4..8].try_into().unwrap()) as u64;
        let idx_addr = u32::from_le_bytes(slice[8..12].try_into().unwrap()) as u64;
        let cb_addr = u32::from_le_bytes(slice[12..16].try_into().unwrap()) as u64;
        let zero_fill = u32::from_le_bytes(slice[16..20].try_into().unwrap());
        let chars = u32::from_le_bytes(slice[20..24].try_into().unwrap());
        (raw_start, raw_end, idx_addr, cb_addr, zero_fill, chars)
    };

    let mut callbacks = Vec::new();
    let mut callbacks_rva = None;

    if cb_addr != 0 {
        // Convert AddressOfCallBacks VA to RVA
        let resolved_rva = if cb_addr >= pe.image_base {
            let delta = cb_addr.saturating_sub(pe.image_base);
            if delta <= u32::MAX as u64 {
                Some(delta as u32)
            } else {
                None
            }
        } else if cb_addr <= u32::MAX as u64 && pe.rva_to_offset(cb_addr as u32).is_some() {
            Some(cb_addr as u32)
        } else {
            None
        };

        callbacks_rva = resolved_rva;

        match resolved_rva {
            Some(cb_rva) => {
                match pe.rva_to_offset(cb_rva) {
                    Some(mut cb_file_offset) => {
                        let ptr_size = if is_64bit { 8 } else { 4 };
                        let mut index = 0;

                        while index < MAX_TLS_CALLBACKS {
                            let end_ptr = cb_file_offset.checked_add(ptr_size);
                            let ptr_slice = match end_ptr.and_then(|e| data.get(cb_file_offset..e))
                            {
                                Some(s) => s,
                                None => break,
                            };

                            let fn_va = if is_64bit {
                                u64::from_le_bytes(ptr_slice.try_into().unwrap())
                            } else {
                                u32::from_le_bytes(ptr_slice.try_into().unwrap()) as u64
                            };

                            // Null pointer terminates the callback array
                            if fn_va == 0 {
                                break;
                            }

                            // Convert callback VA to RVA
                            let fn_rva = if fn_va >= pe.image_base {
                                let delta = fn_va.saturating_sub(pe.image_base);
                                if delta <= u32::MAX as u64 {
                                    delta as u32
                                } else {
                                    (fn_va & 0xFFFF_FFFF) as u32
                                }
                            } else if fn_va <= u32::MAX as u64
                                && pe.rva_to_offset(fn_va as u32).is_some()
                            {
                                fn_va as u32
                            } else {
                                (fn_va & 0xFFFF_FFFF) as u32
                            };

                            let fn_offset = pe.rva_to_offset(fn_rva);
                            let containing_sec = find_section(&pe.sections, fn_rva);

                            let (is_exec, is_write, is_rwx, sec_name) = match containing_sec {
                                Some(sec) => {
                                    let exec = (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
                                    let write = (sec.characteristics & IMAGE_SCN_MEM_WRITE) != 0;
                                    (exec, write, exec && write, Some(sec.name.clone()))
                                }
                                None => (false, false, false, None),
                            };

                            let mut anomaly = None;
                            if containing_sec.is_none() {
                                anomaly = Some(
                                    "Target points to unmapped memory outside sections".into(),
                                );
                                alerts.push(format!(
                                    "TLS Callback #{index} points to unmapped RVA 0x{fn_rva:08X}"
                                ));
                            } else if is_rwx {
                                anomaly = Some(format!(
                                    "Targets RWX section '{}' (potential stealth code hook)",
                                    sec_name.as_deref().unwrap_or("unknown")
                                ));
                                alerts.push(format!(
                                    "TLS Callback #{index} targets RWX section '{}' at RVA 0x{fn_rva:08X} (stealth hook warning)",
                                    sec_name.as_deref().unwrap_or("unknown")
                                ));
                            } else if !is_exec {
                                anomaly = Some(format!(
                                    "Targets non-executable section '{}'",
                                    sec_name.as_deref().unwrap_or("unknown")
                                ));
                                alerts.push(format!(
                                    "TLS Callback #{index} targets non-executable section '{}' at RVA 0x{fn_rva:08X}",
                                    sec_name.as_deref().unwrap_or("unknown")
                                ));
                            } else if sec_name.as_deref() != Some(".text") {
                                anomaly = Some(format!(
                                    "Non-standard code section '{}'",
                                    sec_name.as_deref().unwrap_or("unknown")
                                ));
                                alerts.push(format!(
                                    "TLS Callback #{index} targets non-standard section '{}' rather than .text",
                                    sec_name.as_deref().unwrap_or("unknown")
                                ));
                            }

                            alerts.push(format!(
                                "Pre-main execution hook: TLS Callback #{index} at RVA 0x{fn_rva:08X} executes before AddressOfEntryPoint (0x{:08X})",
                                pe.entry_point
                            ));

                            callbacks.push(TlsCallbackEntry {
                                index,
                                callback_va: fn_va,
                                callback_rva: fn_rva,
                                file_offset: fn_offset,
                                section_name: sec_name,
                                is_executable: is_exec,
                                is_writable: is_write,
                                is_rwx,
                                anomaly,
                            });

                            index += 1;
                            cb_file_offset = match cb_file_offset.checked_add(ptr_size) {
                                Some(next) => next,
                                None => break,
                            };
                        }
                    }
                    None => {
                        alerts.push(format!(
                            "TLS AddressOfCallBacks RVA 0x{cb_rva:08X} cannot be resolved to any mapped PE section"
                        ));
                    }
                }
            }
            None => {
                alerts.push(format!(
                    "TLS AddressOfCallBacks VA 0x{cb_addr:016X} is outside valid PE address space (ImageBase: 0x{:016X})",
                    pe.image_base
                ));
            }
        }
    }

    Ok(TlsDirectoryInfo {
        present: true,
        directory_rva: dir_rva,
        directory_size: dir_size,
        start_address_of_raw_data: raw_start,
        end_address_of_raw_data: raw_end,
        address_of_index: idx_addr,
        address_of_callbacks: cb_addr,
        callbacks_rva,
        size_of_zero_fill: zero_fill,
        characteristics: chars,
        callbacks,
    })
}

fn find_section(sections: &[SectionInfo], rva: u32) -> Option<&SectionInfo> {
    sections.iter().find(|sec| {
        let span = sec.virtual_size.max(sec.raw_size);
        let end = sec.virtual_address.saturating_add(span);
        rva >= sec.virtual_address && rva < end
    })
}
