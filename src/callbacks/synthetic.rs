// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::pe::{
    DOS_MAGIC, IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_TLS,
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT, IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, NT_SIGNATURE, PE32_PLUS_MAGIC,
};

/// Specification for a single x64 runtime function unwind table entry.
#[derive(Debug, Clone)]
pub struct SyntheticPdataSpec {
    pub begin_rva: u32,
    pub end_rva: u32,
    pub flags: u8,
    pub has_handler: bool,
    pub handler_rva: u32,
}

/// Configuration options for building a deterministic synthetic PE with TLS and pdata structures.
#[derive(Debug, Clone)]
pub struct SyntheticCallbacksSpec {
    pub include_tls: bool,
    pub tls_callbacks: Vec<u64>,
    pub tls_is_rwx: bool,
    pub include_pdata: bool,
    pub pdata_functions: Vec<SyntheticPdataSpec>,
}

impl Default for SyntheticCallbacksSpec {
    fn default() -> Self {
        Self {
            include_tls: true,
            tls_callbacks: vec![0x0000_0001_4000_1020],
            tls_is_rwx: false,
            include_pdata: true,
            pdata_functions: vec![SyntheticPdataSpec {
                begin_rva: 0x1000,
                end_rva: 0x1050,
                flags: 0x01, // UNW_FLAG_EHANDLER
                has_handler: true,
                handler_rva: 0x1030,
            }],
        }
    }
}

/// Builds a deterministic synthetic PE64 image with TLS directory and exception tables.
pub fn build_synthetic_callbacks_pe(spec: &SyntheticCallbacksSpec) -> Vec<u8> {
    let sec_align: usize = 0x1000;
    let file_align: usize = 0x0200;

    // --- 1. Prepare .text section ---
    let mut text_raw = vec![0u8; 0x200];
    text_raw[0] = 0xC3; // Entry point: ret
    text_raw[0x20..0x24].copy_from_slice(&[0x48, 0x31, 0xC0, 0xC3]); // TLS Callback stub
    text_raw[0x30..0x34].copy_from_slice(&[0x48, 0x31, 0xC0, 0xC3]); // Exception handler stub

    // --- 2. Prepare .pdata section ---
    let mut pdata_raw = vec![0u8; 0x200];
    let num_funcs = spec.pdata_functions.len();
    if spec.include_pdata && num_funcs > 0 {
        let unwind_base_off = num_funcs * 12;

        for (idx, func) in spec.pdata_functions.iter().enumerate() {
            let func_entry_off = idx * 12;
            let unwind_struct_off = unwind_base_off + (idx * 16);
            let unwind_rva = 0x2000 + (unwind_struct_off as u32);

            // RUNTIME_FUNCTION
            pdata_raw[func_entry_off..func_entry_off + 4]
                .copy_from_slice(&func.begin_rva.to_le_bytes());
            pdata_raw[func_entry_off + 4..func_entry_off + 8]
                .copy_from_slice(&func.end_rva.to_le_bytes());
            pdata_raw[func_entry_off + 8..func_entry_off + 12]
                .copy_from_slice(&unwind_rva.to_le_bytes());

            // UNWIND_INFO at unwind_struct_off
            let ver_flags = (func.flags << 3) | 1u8; // version 1
            pdata_raw[unwind_struct_off] = ver_flags;
            pdata_raw[unwind_struct_off + 1] = 0; // prolog size
            pdata_raw[unwind_struct_off + 2] = 0; // code count
            pdata_raw[unwind_struct_off + 3] = 0; // frame reg

            if func.has_handler {
                pdata_raw[unwind_struct_off + 4..unwind_struct_off + 8]
                    .copy_from_slice(&func.handler_rva.to_le_bytes());
            }
        }
    }

    // --- 3. Prepare .data / .tls section ---
    let mut data_raw = vec![0u8; 0x200];
    if spec.include_tls {
        let cb_array_off: usize = 40;
        let cb_array_va: u64 = 0x0000_0001_4000_3000 + (cb_array_off as u64);

        // IMAGE_TLS_DIRECTORY64
        data_raw[0..8].copy_from_slice(&0x0000_0001_4000_3000u64.to_le_bytes()); // StartAddressOfRawData
        data_raw[8..16].copy_from_slice(&0x0000_0001_4000_3020u64.to_le_bytes()); // EndAddressOfRawData
        data_raw[16..24].copy_from_slice(&0x0000_0001_4000_3020u64.to_le_bytes()); // AddressOfIndex
        data_raw[24..32].copy_from_slice(&cb_array_va.to_le_bytes()); // AddressOfCallBacks
        data_raw[32..36].copy_from_slice(&0u32.to_le_bytes()); // SizeOfZeroFill
        data_raw[36..40].copy_from_slice(&0u32.to_le_bytes()); // Characteristics

        // Callbacks array
        let mut curr_cb_off = cb_array_off;
        for &cb_va in &spec.tls_callbacks {
            if curr_cb_off + 8 <= data_raw.len() {
                data_raw[curr_cb_off..curr_cb_off + 8].copy_from_slice(&cb_va.to_le_bytes());
                curr_cb_off += 8;
            }
        }
        // Null terminator
        if curr_cb_off + 8 <= data_raw.len() {
            data_raw[curr_cb_off..curr_cb_off + 8].copy_from_slice(&0u64.to_le_bytes());
        }
    }

    // --- Headers & Section Layout ---
    let e_lfanew = 0x80usize;
    let coff_offset = e_lfanew + 4;
    let opt_offset = coff_offset + 20;
    let opt_size = 240usize;
    let section_table_offset = opt_offset + opt_size;
    let num_sections = 3u16;
    let headers_end = section_table_offset + (num_sections as usize * 40);
    let headers_raw_size = headers_end.div_ceil(file_align) * file_align;

    let text_raw_off = headers_raw_size;
    let text_raw_size = text_raw.len().div_ceil(file_align) * file_align;
    let pdata_raw_off = text_raw_off + text_raw_size;
    let pdata_raw_size = pdata_raw.len().div_ceil(file_align) * file_align;
    let data_raw_off = pdata_raw_off + pdata_raw_size;
    let data_raw_size = data_raw.len().div_ceil(file_align) * file_align;

    let total_file_size = data_raw_off + data_raw_size;
    let mut image = vec![0u8; total_file_size];

    // DOS Header
    image[0..2].copy_from_slice(&DOS_MAGIC.to_le_bytes());
    image[0x3C..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());

    // NT Signature
    image[e_lfanew..e_lfanew + 4].copy_from_slice(&NT_SIGNATURE.to_le_bytes());

    // COFF Header
    image[coff_offset..coff_offset + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
    image[coff_offset + 2..coff_offset + 4].copy_from_slice(&num_sections.to_le_bytes());
    image[coff_offset + 4..coff_offset + 8].copy_from_slice(&0x6700_0000u32.to_le_bytes());
    image[coff_offset + 16..coff_offset + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
    image[coff_offset + 18..coff_offset + 20].copy_from_slice(&0x0022u16.to_le_bytes());

    // Optional Header
    image[opt_offset..opt_offset + 2].copy_from_slice(&PE32_PLUS_MAGIC.to_le_bytes());
    image[opt_offset + 16..opt_offset + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
    image[opt_offset + 24..opt_offset + 32]
        .copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes()); // ImageBase
    image[opt_offset + 32..opt_offset + 36].copy_from_slice(&(sec_align as u32).to_le_bytes());
    image[opt_offset + 36..opt_offset + 40].copy_from_slice(&(file_align as u32).to_le_bytes());
    image[opt_offset + 68..opt_offset + 70].copy_from_slice(&3u16.to_le_bytes()); // Console

    let dll_chars = IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
        | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        | IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
    image[opt_offset + 70..opt_offset + 72].copy_from_slice(&dll_chars.to_le_bytes());
    image[opt_offset + 108..opt_offset + 112].copy_from_slice(&16u32.to_le_bytes()); // 16 Data Directories

    // Data Directory 3: EXCEPTION
    if spec.include_pdata && num_funcs > 0 {
        let pdata_dir_off = opt_offset + 112 + (IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8);
        image[pdata_dir_off..pdata_dir_off + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        image[pdata_dir_off + 4..pdata_dir_off + 8]
            .copy_from_slice(&((num_funcs * 12) as u32).to_le_bytes());
    }

    // Data Directory 9: TLS
    if spec.include_tls {
        let tls_dir_off = opt_offset + 112 + (IMAGE_DIRECTORY_ENTRY_TLS * 8);
        image[tls_dir_off..tls_dir_off + 4].copy_from_slice(&0x3000u32.to_le_bytes());
        image[tls_dir_off + 4..tls_dir_off + 8].copy_from_slice(&40u32.to_le_bytes());
    }

    // --- Section Headers ---
    // Sec 1: .text
    let sec1 = section_table_offset;
    image[sec1..sec1 + 8].copy_from_slice(b".text\0\0\0");
    image[sec1 + 8..sec1 + 12].copy_from_slice(&(sec_align as u32).to_le_bytes());
    image[sec1 + 12..sec1 + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    image[sec1 + 16..sec1 + 20].copy_from_slice(&(text_raw_size as u32).to_le_bytes());
    image[sec1 + 20..sec1 + 24].copy_from_slice(&(text_raw_off as u32).to_le_bytes());
    image[sec1 + 36..sec1 + 40].copy_from_slice(
        &(IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ).to_le_bytes(),
    );

    // Sec 2: .pdata
    let sec2 = sec1 + 40;
    image[sec2..sec2 + 8].copy_from_slice(b".pdata\0\0");
    image[sec2 + 8..sec2 + 12].copy_from_slice(&(sec_align as u32).to_le_bytes());
    image[sec2 + 12..sec2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    image[sec2 + 16..sec2 + 20].copy_from_slice(&(pdata_raw_size as u32).to_le_bytes());
    image[sec2 + 20..sec2 + 24].copy_from_slice(&(pdata_raw_off as u32).to_le_bytes());
    image[sec2 + 36..sec2 + 40]
        .copy_from_slice(&(IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ).to_le_bytes());

    // Sec 3: .data
    let sec3 = sec2 + 40;
    image[sec3..sec3 + 8].copy_from_slice(b".data\0\0\0");
    image[sec3 + 8..sec3 + 12].copy_from_slice(&(sec_align as u32).to_le_bytes());
    image[sec3 + 12..sec3 + 16].copy_from_slice(&0x3000u32.to_le_bytes());
    image[sec3 + 16..sec3 + 20].copy_from_slice(&(data_raw_size as u32).to_le_bytes());
    image[sec3 + 20..sec3 + 24].copy_from_slice(&(data_raw_off as u32).to_le_bytes());

    let data_chars = if spec.tls_is_rwx {
        IMAGE_SCN_CNT_INITIALIZED_DATA
            | IMAGE_SCN_MEM_READ
            | IMAGE_SCN_MEM_WRITE
            | IMAGE_SCN_MEM_EXECUTE
    } else {
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
    };
    image[sec3 + 36..sec3 + 40].copy_from_slice(&data_chars.to_le_bytes());

    // Copy Raw Data
    image[text_raw_off..text_raw_off + text_raw.len()].copy_from_slice(&text_raw);
    image[pdata_raw_off..pdata_raw_off + pdata_raw.len()].copy_from_slice(&pdata_raw);
    image[data_raw_off..data_raw_off + data_raw.len()].copy_from_slice(&data_raw);

    image
}
