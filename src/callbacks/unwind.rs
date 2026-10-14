// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::callbacks::types::{ExceptionDirectoryInfo, RuntimeFunctionEntry, UnwindInfoSummary};
use crate::error::Result;
use crate::pe::{
    PeInfo, SectionInfo, IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_WRITE,
};

/// Maximum runtime functions to parse in detail to prevent DoS on malformed binaries.
const MAX_PARSED_FUNCTIONS: usize = 4096;

pub const UNW_FLAG_NHANDLER: u8 = 0x00;
pub const UNW_FLAG_EHANDLER: u8 = 0x01;
pub const UNW_FLAG_UHANDLER: u8 = 0x02;
pub const UNW_FLAG_CHAININFO: u8 = 0x04;

/// Parses the PE Exception Directory (`IMAGE_DIRECTORY_ENTRY_EXCEPTION` / `.pdata`) and extracts x64 unwind entries.
pub fn parse_exception_directory(
    data: &[u8],
    pe: &PeInfo,
    alerts: &mut Vec<String>,
) -> Result<ExceptionDirectoryInfo> {
    let dir = match pe.data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
        Some(d) if d.virtual_address != 0 && d.size != 0 => *d,
        _ => return Ok(ExceptionDirectoryInfo::default()),
    };

    let dir_rva = dir.virtual_address;
    let dir_size = dir.size;

    if dir_size < 12 {
        alerts.push(format!(
            "Exception directory size {dir_size} is less than a single 12-byte RUNTIME_FUNCTION entry"
        ));
        return Ok(ExceptionDirectoryInfo {
            present: true,
            directory_rva: dir_rva,
            directory_size: dir_size,
            ..Default::default()
        });
    }

    let file_offset = match pe.rva_to_offset(dir_rva) {
        Some(off) => off,
        None => {
            alerts.push(format!(
                "Exception Directory (.pdata) RVA 0x{dir_rva:08X} cannot be resolved to any mapped PE section"
            ));
            return Ok(ExceptionDirectoryInfo {
                present: true,
                directory_rva: dir_rva,
                directory_size: dir_size,
                ..Default::default()
            });
        }
    };

    let total_functions = (dir_size / 12) as usize;
    let count_to_parse = total_functions.min(MAX_PARSED_FUNCTIONS);

    let mut functions = Vec::with_capacity(count_to_parse);
    let mut functions_with_handlers = 0;

    for i in 0..count_to_parse {
        let entry_off = match file_offset.checked_add(i * 12) {
            Some(off) => off,
            None => break,
        };

        let end_off = match entry_off.checked_add(12) {
            Some(off) => off,
            None => break,
        };

        let entry_slice = match data.get(entry_off..end_off) {
            Some(s) => s,
            None => {
                alerts.push(format!(
                    "Exception table truncated at entry #{i} (offset 0x{entry_off:X})"
                ));
                break;
            }
        };

        let begin_rva = u32::from_le_bytes(entry_slice[0..4].try_into().unwrap());
        let end_rva = u32::from_le_bytes(entry_slice[4..8].try_into().unwrap());
        let unwind_rva = u32::from_le_bytes(entry_slice[8..12].try_into().unwrap());

        let length = end_rva.saturating_sub(begin_rva);
        let mut anomaly = None;

        if end_rva <= begin_rva {
            anomaly = Some(format!(
                "Inverted or zero function bounds: Begin 0x{begin_rva:08X} >= End 0x{end_rva:08X}"
            ));
            alerts.push(format!(
                "RUNTIME_FUNCTION #{i} has inverted/zero span (0x{begin_rva:08X}..0x{end_rva:08X})"
            ));
        }

        let func_sec = find_section(&pe.sections, begin_rva);
        let sec_name = func_sec.map(|s| s.name.clone());

        if func_sec.is_none() && anomaly.is_none() {
            anomaly =
                Some("Function BeginAddress points to unmapped memory outside sections".into());
            alerts.push(format!(
                "RUNTIME_FUNCTION #{i} BeginAddress 0x{begin_rva:08X} outside mapped sections"
            ));
        }

        // Parse UNWIND_INFO
        let unwind_info = parse_unwind_info(data, pe, unwind_rva, i, alerts);
        if let Some(ref u) = unwind_info {
            if u.has_handler {
                functions_with_handlers += 1;
            }
        }

        functions.push(RuntimeFunctionEntry {
            index: i,
            begin_rva,
            end_rva,
            length,
            unwind_info_rva: unwind_rva,
            section_name: sec_name,
            unwind_info,
            anomaly,
        });
    }

    Ok(ExceptionDirectoryInfo {
        present: true,
        directory_rva: dir_rva,
        directory_size: dir_size,
        total_functions,
        parsed_functions: functions.len(),
        functions_with_handlers,
        functions,
    })
}

fn parse_unwind_info(
    data: &[u8],
    pe: &PeInfo,
    unwind_rva: u32,
    fn_index: usize,
    alerts: &mut Vec<String>,
) -> Option<UnwindInfoSummary> {
    if unwind_rva == 0 {
        return None;
    }

    let unwind_off = match pe.rva_to_offset(unwind_rva) {
        Some(off) => off,
        None => {
            alerts.push(format!(
                "RUNTIME_FUNCTION #{fn_index} UnwindInfo RVA 0x{unwind_rva:08X} cannot be resolved to file offset"
            ));
            return None;
        }
    };

    let header_end = unwind_off.checked_add(4)?;
    let header = data.get(unwind_off..header_end)?;

    let ver_flags = header[0];
    let version = ver_flags & 0x07;
    let flags = (ver_flags >> 3) & 0x1F;
    let prolog_size = header[1];
    let code_count = header[2];
    let frame_byte = header[3];
    let frame_register = frame_byte & 0x0F;
    let frame_offset = (frame_byte >> 4) & 0x0F;

    let mut flag_names = Vec::new();
    if flags == UNW_FLAG_NHANDLER {
        flag_names.push("NHANDLER".into());
    } else {
        if (flags & UNW_FLAG_EHANDLER) != 0 {
            flag_names.push("EHANDLER".into());
        }
        if (flags & UNW_FLAG_UHANDLER) != 0 {
            flag_names.push("UHANDLER".into());
        }
        if (flags & UNW_FLAG_CHAININFO) != 0 {
            flag_names.push("CHAININFO".into());
        }
    }

    let has_handler = (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) != 0;
    let is_chained = (flags & UNW_FLAG_CHAININFO) != 0;

    let mut handler_rva = None;
    let mut handler_section = None;
    let mut handler_executable = false;
    let mut handler_writable = false;

    if has_handler {
        // Unwind codes take count * 2 bytes, aligned to 4-byte boundary if odd
        let code_bytes = if code_count % 2 == 1 {
            ((code_count as usize) + 1) * 2
        } else {
            (code_count as usize) * 2
        };

        let handler_off = unwind_off.checked_add(4)?.checked_add(code_bytes)?;
        let handler_end = handler_off.checked_add(4)?;

        if let Some(h_slice) = data.get(handler_off..handler_end) {
            let hrva = u32::from_le_bytes(h_slice.try_into().unwrap());
            handler_rva = Some(hrva);

            let h_sec = find_section(&pe.sections, hrva);
            if let Some(sec) = h_sec {
                handler_section = Some(sec.name.clone());
                handler_executable = (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
                handler_writable = (sec.characteristics & IMAGE_SCN_MEM_WRITE) != 0;

                if handler_executable && handler_writable {
                    alerts.push(format!(
                        "RUNTIME_FUNCTION #{fn_index} exception handler points to RWX section '{}' at RVA 0x{hrva:08X} (stealth handler warning)",
                        sec.name
                    ));
                } else if !handler_executable {
                    alerts.push(format!(
                        "RUNTIME_FUNCTION #{fn_index} exception handler points to non-executable section '{}' at RVA 0x{hrva:08X}",
                        sec.name
                    ));
                }
            } else {
                alerts.push(format!(
                    "RUNTIME_FUNCTION #{fn_index} exception handler targets unmapped RVA 0x{hrva:08X}"
                ));
            }
        }
    }

    Some(UnwindInfoSummary {
        version,
        flags,
        flag_names,
        prolog_size,
        code_count,
        frame_register,
        frame_offset,
        has_handler,
        handler_rva,
        handler_section,
        handler_executable,
        handler_writable,
        is_chained,
    })
}

fn find_section(sections: &[SectionInfo], rva: u32) -> Option<&SectionInfo> {
    sections.iter().find(|sec| {
        let span = sec.virtual_size.max(sec.raw_size);
        let end = sec.virtual_address.saturating_add(span);
        rva >= sec.virtual_address && rva < end
    })
}
