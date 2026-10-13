// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Deterministic synthetic PE generator with valid Import and Export Directories.
//!
//! Generates well-formed 32-bit (PE32) and 64-bit (PE32+) executables containing
//! valid `IMAGE_IMPORT_DESCRIPTOR`, ILT/IAT tables, and `IMAGE_EXPORT_DIRECTORY`
//! structures for testing and forensic verification.

use crate::pe::{
    DOS_MAGIC, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, IMAGE_DLLCHARACTERISTICS_GUARD_CF,
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
    IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
    NT_SIGNATURE, PE32_MAGIC, PE32_PLUS_MAGIC,
};

/// Specification for an individual synthetic imported function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportSpec<'a> {
    /// Import by function name with an optional hint.
    ByName(&'a str, u16),
    /// Import by ordinal number.
    ByOrdinal(u16),
}

/// Specification for an individual synthetic exported function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportSpec<'a> {
    /// Export by name with code RVA.
    ByName(&'a str, u32),
    /// Export by ordinal only with code RVA.
    ByOrdinal(u32),
    /// Forwarded export to external module (name, target forwarder string).
    Forwarded(&'a str, &'a str),
}

/// Builds a deterministic synthetic PE executable (PE32 or PE32+) with valid imports and exports.
pub fn build_synthetic_pe(
    is_64bit: bool,
    imports: &[(&str, &[ImportSpec])],
    exports: Option<(&str, &[ExportSpec])>,
) -> Vec<u8> {
    let e_lfanew: usize = 0x80;
    let opt_size: usize = if is_64bit { 0xF0 } else { 0xE0 };
    let sec_table_off = e_lfanew + 4 + 20 + opt_size;

    // We will have 3 sections: .text, .rdata (imports), .edata (exports)
    let num_sections = if exports.is_some() { 3 } else { 2 };
    let headers_end = sec_table_off + (num_sections * 40);
    let first_raw_offset = (headers_end + 0x1FF) & !0x1FF;

    let mut buf = vec![0u8; first_raw_offset];

    // 1. DOS Header
    buf[0..2].copy_from_slice(&DOS_MAGIC.to_le_bytes());
    buf[0x3C..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());

    // 2. NT Signature
    buf[e_lfanew..e_lfanew + 4].copy_from_slice(&NT_SIGNATURE.to_le_bytes());

    // 3. COFF Header
    let coff = e_lfanew + 4;
    let machine: u16 = if is_64bit { 0x8664 } else { 0x014C };
    buf[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
    buf[coff + 2..coff + 4].copy_from_slice(&(num_sections as u16).to_le_bytes());
    buf[coff + 4..coff + 8].copy_from_slice(&0x6700_0000u32.to_le_bytes());
    buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
    buf[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());

    // 4. Optional Header
    let opt = coff + 20;
    let magic: u16 = if is_64bit {
        PE32_PLUS_MAGIC
    } else {
        PE32_MAGIC
    };
    buf[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
    buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // EntryPoint

    if is_64bit {
        buf[opt + 24..opt + 32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
        buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt + 36..opt + 40].copy_from_slice(&0x0200u32.to_le_bytes());
        buf[opt + 68..opt + 70].copy_from_slice(&0x0003u16.to_le_bytes());
        let dll_chars = IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
            | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            | IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            | IMAGE_DLLCHARACTERISTICS_GUARD_CF;
        buf[opt + 70..opt + 72].copy_from_slice(&dll_chars.to_le_bytes());
        buf[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
    } else {
        buf[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt + 36..opt + 40].copy_from_slice(&0x0200u32.to_le_bytes());
        buf[opt + 68..opt + 70].copy_from_slice(&0x0003u16.to_le_bytes());
        let dll_chars = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            | IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            | IMAGE_DLLCHARACTERISTICS_GUARD_CF;
        buf[opt + 70..opt + 72].copy_from_slice(&dll_chars.to_le_bytes());
        buf[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());
    }

    // Prepare .text section at RVA 0x1000
    let text_code = vec![0xC3u8; 16]; // RET stub

    // Prepare .rdata section (Imports) at RVA 0x2000
    let rdata_rva = 0x2000u32;
    let mut rdata_buf = Vec::new();

    let rdata_dir_size = if !imports.is_empty() {
        let desc_count = imports.len() + 1; // +1 null terminator
        rdata_buf.resize(desc_count * 20, 0);

        let entry_size = if is_64bit { 8 } else { 4 };

        for (idx, (dll_name, funcs)) in imports.iter().enumerate() {
            // Write DLL Name
            let name_rva = rdata_rva + rdata_buf.len() as u32;
            rdata_buf.extend_from_slice(dll_name.as_bytes());
            rdata_buf.push(0x00);
            if (rdata_buf.len() % 2) != 0 {
                rdata_buf.push(0x00);
            }

            // Write IMAGE_IMPORT_BY_NAME records
            let mut ibn_rvas = Vec::new();
            for func in *funcs {
                match func {
                    ImportSpec::ByName(name, hint) => {
                        let ibn_rva = rdata_rva + rdata_buf.len() as u32;
                        rdata_buf.extend_from_slice(&hint.to_le_bytes());
                        rdata_buf.extend_from_slice(name.as_bytes());
                        rdata_buf.push(0x00);
                        if (rdata_buf.len() % 2) != 0 {
                            rdata_buf.push(0x00);
                        }
                        ibn_rvas.push(Some(ibn_rva));
                    }
                    ImportSpec::ByOrdinal(_) => {
                        ibn_rvas.push(None);
                    }
                }
            }

            // Align to 8 bytes for thunk table
            while (rdata_buf.len() % 8) != 0 {
                rdata_buf.push(0x00);
            }

            // Write ILT (OriginalFirstThunk)
            let ilt_rva = rdata_rva + rdata_buf.len() as u32;
            for (f_idx, func) in funcs.iter().enumerate() {
                match func {
                    ImportSpec::ByName(_, _) => {
                        let rva = ibn_rvas[f_idx].unwrap();
                        if is_64bit {
                            rdata_buf.extend_from_slice(&(rva as u64).to_le_bytes());
                        } else {
                            rdata_buf.extend_from_slice(&rva.to_le_bytes());
                        }
                    }
                    ImportSpec::ByOrdinal(ord) => {
                        if is_64bit {
                            let val = 0x8000_0000_0000_0000u64 | (*ord as u64);
                            rdata_buf.extend_from_slice(&val.to_le_bytes());
                        } else {
                            let val = 0x8000_0000u32 | (*ord as u32);
                            rdata_buf.extend_from_slice(&val.to_le_bytes());
                        }
                    }
                }
            }
            // ILT null terminator
            rdata_buf.resize(rdata_buf.len() + entry_size, 0);

            // Write IAT (FirstThunk)
            let iat_rva = rdata_rva + rdata_buf.len() as u32;
            let ilt_len = (funcs.len() + 1) * entry_size;
            let ilt_start = (ilt_rva - rdata_rva) as usize;
            let ilt_slice = rdata_buf[ilt_start..ilt_start + ilt_len].to_vec();
            rdata_buf.extend_from_slice(&ilt_slice);

            // Populate descriptor
            let desc_off = idx * 20;
            rdata_buf[desc_off..desc_off + 4].copy_from_slice(&ilt_rva.to_le_bytes());
            rdata_buf[desc_off + 12..desc_off + 16].copy_from_slice(&name_rva.to_le_bytes());
            rdata_buf[desc_off + 16..desc_off + 20].copy_from_slice(&iat_rva.to_le_bytes());
        }

        rdata_buf.len() as u32
    } else {
        rdata_buf.resize(16, 0);
        0
    };

    // Prepare .edata section (Exports) at RVA 0x3000
    let edata_rva = 0x3000u32;
    let mut edata_buf = Vec::new();

    let edata_dir_size = if let Some((dll_name, exp_specs)) = exports {
        edata_buf.resize(40, 0); // Reserve 40 bytes for IMAGE_EXPORT_DIRECTORY

        // Write DLL Name
        let name_rva = edata_rva + edata_buf.len() as u32;
        edata_buf.extend_from_slice(dll_name.as_bytes());
        edata_buf.push(0x00);

        let mut func_rvas = Vec::new();
        let mut name_rvas = Vec::new();
        let mut ord_indices = Vec::new();

        for (idx, spec) in exp_specs.iter().enumerate() {
            match spec {
                ExportSpec::ByName(fname, code_rva) => {
                    func_rvas.push(*code_rva);
                    let fn_rva = edata_rva + edata_buf.len() as u32;
                    edata_buf.extend_from_slice(fname.as_bytes());
                    edata_buf.push(0x00);
                    name_rvas.push(fn_rva);
                    ord_indices.push(idx as u16);
                }
                ExportSpec::ByOrdinal(code_rva) => {
                    func_rvas.push(*code_rva);
                }
                ExportSpec::Forwarded(fname, forward_target) => {
                    let fwd_rva = edata_rva + edata_buf.len() as u32;
                    edata_buf.extend_from_slice(forward_target.as_bytes());
                    edata_buf.push(0x00);
                    func_rvas.push(fwd_rva);

                    let fn_rva = edata_rva + edata_buf.len() as u32;
                    edata_buf.extend_from_slice(fname.as_bytes());
                    edata_buf.push(0x00);
                    name_rvas.push(fn_rva);
                    ord_indices.push(idx as u16);
                }
            }
        }

        while (edata_buf.len() % 4) != 0 {
            edata_buf.push(0x00);
        }

        // Write AddressOfFunctions
        let addr_funcs_rva = edata_rva + edata_buf.len() as u32;
        for rva in &func_rvas {
            edata_buf.extend_from_slice(&rva.to_le_bytes());
        }

        // Write AddressOfNames
        let addr_names_rva = edata_rva + edata_buf.len() as u32;
        for nrva in &name_rvas {
            edata_buf.extend_from_slice(&nrva.to_le_bytes());
        }

        // Write AddressOfNameOrdinals
        let addr_ords_rva = edata_rva + edata_buf.len() as u32;
        for ord in &ord_indices {
            edata_buf.extend_from_slice(&ord.to_le_bytes());
        }

        // Populate Export Directory Header
        edata_buf[4..8].copy_from_slice(&0x6700_0000u32.to_le_bytes()); // Timestamp
        edata_buf[8..10].copy_from_slice(&1u16.to_le_bytes()); // Major
        edata_buf[10..12].copy_from_slice(&0u16.to_le_bytes()); // Minor
        edata_buf[12..16].copy_from_slice(&name_rva.to_le_bytes());
        edata_buf[16..20].copy_from_slice(&1u32.to_le_bytes()); // Base ordinal = 1
        edata_buf[20..24].copy_from_slice(&(func_rvas.len() as u32).to_le_bytes());
        edata_buf[24..28].copy_from_slice(&(name_rvas.len() as u32).to_le_bytes());
        edata_buf[28..32].copy_from_slice(&addr_funcs_rva.to_le_bytes());
        edata_buf[32..36].copy_from_slice(&addr_names_rva.to_le_bytes());
        edata_buf[36..40].copy_from_slice(&addr_ords_rva.to_le_bytes());

        edata_buf.len() as u32
    } else {
        0
    };

    // Set Data Directories in Optional Header
    let data_dirs_off = if is_64bit { opt + 112 } else { opt + 96 };
    if edata_dir_size > 0 {
        let export_dir_entry = data_dirs_off + (IMAGE_DIRECTORY_ENTRY_EXPORT * 8);
        buf[export_dir_entry..export_dir_entry + 4].copy_from_slice(&edata_rva.to_le_bytes());
        buf[export_dir_entry + 4..export_dir_entry + 8]
            .copy_from_slice(&edata_dir_size.to_le_bytes());
    }
    if rdata_dir_size > 0 {
        let import_dir_entry = data_dirs_off + (IMAGE_DIRECTORY_ENTRY_IMPORT * 8);
        buf[import_dir_entry..import_dir_entry + 4].copy_from_slice(&rdata_rva.to_le_bytes());
        buf[import_dir_entry + 4..import_dir_entry + 8]
            .copy_from_slice(&rdata_dir_size.to_le_bytes());
    }

    // Write Section Headers & Section Raw Data
    let mut sections = vec![
        (
            ".text",
            text_code,
            0x1000u32,
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
        ),
        (
            ".rdata",
            rdata_buf,
            rdata_rva,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        ),
    ];

    if exports.is_some() {
        sections.push((
            ".edata",
            edata_buf,
            edata_rva,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        ));
    }

    for (idx, (sec_name, raw_data, rva, chars)) in sections.iter().enumerate() {
        let sec_off = sec_table_off + idx * 40;
        let mut name_buf = [0u8; 8];
        let copy_len = sec_name.len().min(8);
        name_buf[..copy_len].copy_from_slice(&sec_name.as_bytes()[..copy_len]);
        buf[sec_off..sec_off + 8].copy_from_slice(&name_buf);

        let raw_offset = buf.len() as u32;
        let aligned_raw_size = ((raw_data.len() + 0x1FF) & !0x1FF).max(0x200);
        let virtual_size = raw_data.len() as u32;

        buf[sec_off + 8..sec_off + 12].copy_from_slice(&virtual_size.to_le_bytes());
        buf[sec_off + 12..sec_off + 16].copy_from_slice(&rva.to_le_bytes());
        buf[sec_off + 16..sec_off + 20].copy_from_slice(&(aligned_raw_size as u32).to_le_bytes());
        buf[sec_off + 20..sec_off + 24].copy_from_slice(&raw_offset.to_le_bytes());
        buf[sec_off + 36..sec_off + 40].copy_from_slice(&chars.to_le_bytes());

        let mut aligned_slice = vec![0u8; aligned_raw_size];
        aligned_slice[..raw_data.len()].copy_from_slice(raw_data);
        buf.extend_from_slice(&aligned_slice);
    }

    buf
}
