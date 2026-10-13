// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::parser::calculate_rich_checksum;

const DANS_MARKER: u32 = 0x536E_6144; // "DanS" in LE
const RICH_MARKER: u32 = 0x6863_6952; // "Rich" in LE

/// Specification for an individual `@comp.id` record in a synthetic Rich header.
#[derive(Debug, Clone, Copy)]
pub struct SyntheticRichEntry {
    pub product_id: u16,
    pub build_number: u16,
    pub count: u32,
}

impl SyntheticRichEntry {
    pub fn new(product_id: u16, build_number: u16, count: u32) -> Self {
        Self {
            product_id,
            build_number,
            count,
        }
    }

    pub fn comp_id(&self) -> u32 {
        ((self.product_id as u32) << 16) | (self.build_number as u32)
    }
}

/// Builds a deterministic synthetic PE64 binary with an authentic or intentionally tampered Rich header.
pub fn build_synthetic_rich_pe(entries: &[SyntheticRichEntry], tamper_checksum: bool) -> Vec<u8> {
    // 1. DOS Header (exactly 64 bytes / 0x40)
    let mut data = vec![0u8; 0x40];
    data[0..2].copy_from_slice(&[0x4D, 0x5A]); // 'MZ'
    data[2..4].copy_from_slice(&[0x90, 0x00]);
    data[0x3C..0x40].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // e_lfanew placeholder

    // 2. DOS Stub message
    let dos_stub = b"\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00";
    data.extend_from_slice(dos_stub);

    // Align to 4-byte boundary for DanS
    while (data.len() % 4) != 0 {
        data.push(0x00);
    }

    let dans_offset = data.len();

    // Prepare raw comp_ids
    let raw_entries: Vec<(u32, u32)> = entries.iter().map(|e| (e.comp_id(), e.count)).collect();

    // 3. Compute authentic checksum / XOR key
    let mut xor_key = calculate_rich_checksum(&data, dans_offset, &raw_entries);
    if xor_key == 0 {
        xor_key = 0x5A5A_5A5A;
    }

    let stored_key = if tamper_checksum {
        xor_key ^ 0xDEAD_BEEF
    } else {
        xor_key
    };

    // 4. Append encrypted Rich Header
    // DanS marker XOR key
    data.extend_from_slice(&(DANS_MARKER ^ stored_key).to_le_bytes());
    // 3 zero padding words XOR key (0 ^ stored_key == stored_key)
    data.extend_from_slice(&stored_key.to_le_bytes());
    data.extend_from_slice(&stored_key.to_le_bytes());
    data.extend_from_slice(&stored_key.to_le_bytes());

    // Records XOR key
    for &(comp_id, count) in &raw_entries {
        data.extend_from_slice(&(comp_id ^ stored_key).to_le_bytes());
        data.extend_from_slice(&(count ^ stored_key).to_le_bytes());
    }

    // Rich marker (literal 0x68636952) and XOR key
    data.extend_from_slice(&RICH_MARKER.to_le_bytes());
    data.extend_from_slice(&stored_key.to_le_bytes());

    // Align to 16 bytes before PE NT Header
    while (data.len() % 16) != 0 {
        data.push(0x00);
    }

    let pe_offset = data.len() as u32;
    data[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());

    // 5. PE NT Headers
    data.extend_from_slice(b"PE\0\0"); // Signature
    data.extend_from_slice(&0x8664u16.to_le_bytes()); // Machine: x86_64
    data.extend_from_slice(&1u16.to_le_bytes()); // NumberOfSections: 1
    data.extend_from_slice(&0x6600_0000u32.to_le_bytes()); // Timestamp
    data.extend_from_slice(&0u32.to_le_bytes()); // PointerToSymbolTable
    data.extend_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
    data.extend_from_slice(&0xF0u16.to_le_bytes()); // SizeOfOptionalHeader (240 bytes)
    data.extend_from_slice(&0x0022u16.to_le_bytes()); // Characteristics (EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE)

    // Optional Header (PE32+ 240 bytes)
    data.extend_from_slice(&0x020Bu16.to_le_bytes()); // Magic: PE32+
    data.extend_from_slice(&[14, 20]); // Major/Minor Linker Version
    data.extend_from_slice(&0x1000u32.to_le_bytes()); // SizeOfCode
    data.extend_from_slice(&0u32.to_le_bytes()); // SizeOfInitializedData
    data.extend_from_slice(&0u32.to_le_bytes()); // SizeOfUninitializedData
    data.extend_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
    data.extend_from_slice(&0x1000u32.to_le_bytes()); // BaseOfCode
    data.extend_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes()); // ImageBase
    data.extend_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    data.extend_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
    data.extend_from_slice(&6u16.to_le_bytes()); // MajorOS
    data.extend_from_slice(&0u16.to_le_bytes()); // MinorOS
    data.extend_from_slice(&0u16.to_le_bytes()); // MajorImage
    data.extend_from_slice(&0u16.to_le_bytes()); // MinorImage
    data.extend_from_slice(&6u16.to_le_bytes()); // MajorSubsystem
    data.extend_from_slice(&0u16.to_le_bytes()); // MinorSubsystem
    data.extend_from_slice(&0u32.to_le_bytes()); // Win32VersionValue
    data.extend_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
    data.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
    data.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
    data.extend_from_slice(&3u16.to_le_bytes()); // Subsystem: CUI
    data.extend_from_slice(&0x8160u16.to_le_bytes()); // DllCharacteristics: DYNAMIC_BASE | NX | HIGH_ENTROPY
    data.extend_from_slice(&0x10_0000u64.to_le_bytes()); // StackReserve
    data.extend_from_slice(&0x1000u64.to_le_bytes()); // StackCommit
    data.extend_from_slice(&0x10_0000u64.to_le_bytes()); // HeapReserve
    data.extend_from_slice(&0x1000u64.to_le_bytes()); // HeapCommit
    data.extend_from_slice(&0u32.to_le_bytes()); // LoaderFlags
    data.extend_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

    // 16 Data Directories (128 bytes of zeros)
    data.extend_from_slice(&[0u8; 128]);

    // Section Header (.text, 40 bytes)
    data.extend_from_slice(b".text\0\0\0");
    data.extend_from_slice(&0x200u32.to_le_bytes()); // VirtualSize
    data.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    data.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
    data.extend_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
    data.extend_from_slice(&0u32.to_le_bytes()); // Relocs
    data.extend_from_slice(&0u32.to_le_bytes()); // LineNumbers
    data.extend_from_slice(&0u16.to_le_bytes()); // NumRelocs
    data.extend_from_slice(&0u16.to_le_bytes()); // NumLines
    data.extend_from_slice(&0x6000_0020u32.to_le_bytes()); // Characteristics: CODE | EXECUTE | READ

    // Pad headers to FileAlignment (0x200)
    while data.len() < 0x200 {
        data.push(0x00);
    }

    // Section raw data (RET instruction + padding)
    data.push(0xC3);
    while data.len() < 0x400 {
        data.push(0xCC);
    }

    data
}
