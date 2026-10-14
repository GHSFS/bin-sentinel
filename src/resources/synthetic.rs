// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::pe::{
    IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
    IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
};

/// Configuration options for building a synthetic PE with embedded resources.
#[derive(Debug, Clone)]
pub struct SyntheticResourceSpec {
    /// Requested execution level for application manifest (`requireAdministrator`, `asInvoker`, etc.).
    pub uac_level: String,
    /// Whether to enable autoElevate in the manifest.
    pub auto_elevate: bool,
    /// Product name for Version info.
    pub product_name: String,
    /// File version string.
    pub file_version: String,
    /// Whether to include a high-entropy pseudo-random RCDATA payload.
    pub include_high_entropy_rcdata: bool,
}

impl Default for SyntheticResourceSpec {
    fn default() -> Self {
        Self {
            uac_level: "requireAdministrator".to_string(),
            auto_elevate: true,
            product_name: "BinSentinel Security Tool".to_string(),
            file_version: "1.2.3.4".to_string(),
            include_high_entropy_rcdata: true,
        }
    }
}

/// Builds a deterministic synthetic PE64 binary with an embedded `.rsrc` section.
pub fn build_synthetic_resource_pe(spec: &SyntheticResourceSpec) -> Vec<u8> {
    // 1. Prepare raw payload contents
    let manifest_xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
        <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\n  \
          <assemblyIdentity version=\"{}\" processorArchitecture=\"amd64\" name=\"{}\" type=\"win32\"/>\n  \
          <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">\n    \
            <security>\n      \
              <requestedPrivileges>\n        \
                <requestedExecutionLevel level=\"{}\" uiAccess=\"false\"/>\n      \
              </requestedPrivileges>\n    \
            </security>\n  \
          </trustInfo>\n  \
          {}\n\
        </assembly>",
        spec.file_version,
        spec.product_name,
        spec.uac_level,
        if spec.auto_elevate {
            "<autoElevate>true</autoElevate>"
        } else {
            "<autoElevate>false</autoElevate>"
        }
    );
    let manifest_bytes = manifest_xml.into_bytes();

    let version_bytes = build_synthetic_version_payload(&spec.file_version, &spec.product_name);

    let rcdata_bytes = if spec.include_high_entropy_rcdata {
        build_high_entropy_payload(1024)
    } else {
        vec![0xAA; 256]
    };

    // 2. Assemble .rsrc section directory tree
    // We have 3 types: RT_MANIFEST (24), RT_VERSION (16), RT_RCDATA (10)
    let rsrc_section_rva = 0x2000u32;
    let rsrc_bytes = assemble_rsrc_section(
        rsrc_section_rva,
        &manifest_bytes,
        &version_bytes,
        &rcdata_bytes,
    );

    // 3. Assemble full PE32+ image
    assemble_pe_image(rsrc_section_rva, &rsrc_bytes)
}

fn build_synthetic_version_payload(file_ver: &str, prod_name: &str) -> Vec<u8> {
    let mut buf = Vec::new();

    let parts: Vec<u32> = file_ver
        .split('.')
        .filter_map(|s| s.parse::<u32>().ok())
        .collect();
    let (v1, v2, v3, v4) = match parts.as_slice() {
        [a, b, c, d] => (*a, *b, *c, *d),
        [a, b, c] => (*a, *b, *c, 0),
        [a, b] => (*a, *b, 0, 0),
        [a] => (*a, 0, 0, 0),
        _ => (1, 0, 0, 0),
    };
    let file_ver_ms = (v1 << 16) | (v2 & 0xFFFF);
    let file_ver_ls = (v3 << 16) | (v4 & 0xFFFF);

    // VS_VERSIONINFO placeholder (header 6 bytes + UTF-16 "VS_VERSION_INFO\0" 32 bytes)
    buf.extend_from_slice(&[0u8; 40]);

    // VS_FIXEDFILEINFO (52 bytes)
    let ffi_start = buf.len();
    buf.extend_from_slice(&0xFEEF_04BDu32.to_le_bytes()); // dwSignature
    buf.extend_from_slice(&0x0001_0000u32.to_le_bytes()); // dwStrucVersion
    buf.extend_from_slice(&file_ver_ms.to_le_bytes()); // dwFileVersionMS
    buf.extend_from_slice(&file_ver_ls.to_le_bytes()); // dwFileVersionLS
    buf.extend_from_slice(&file_ver_ms.to_le_bytes()); // dwProductVersionMS
    buf.extend_from_slice(&file_ver_ls.to_le_bytes()); // dwProductVersionLS
    buf.extend_from_slice(&[0u8; 28]); // remaining fields

    // Append StringFileInfo strings
    append_utf16_pair(&mut buf, "FileVersion", file_ver);
    append_utf16_pair(&mut buf, "ProductName", prod_name);
    append_utf16_pair(&mut buf, "CompanyName", "GHSFS Engineering");
    append_utf16_pair(&mut buf, "FileDescription", "BinSentinel Synthetic Probe");

    // Fixup VS_VERSIONINFO length
    let total_len = buf.len() as u16;
    buf[0..2].copy_from_slice(&total_len.to_le_bytes());
    buf[2..4].copy_from_slice(&(52u16).to_le_bytes()); // wValueLength (fixed file info)
    buf[4..6].copy_from_slice(&0u16.to_le_bytes()); // binary type

    // Key "VS_VERSION_INFO"
    let key_utf16: Vec<u8> = "VS_VERSION_INFO\0"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    buf[6..6 + key_utf16.len()].copy_from_slice(&key_utf16);

    let _ = ffi_start;
    buf
}

fn append_utf16_pair(buf: &mut Vec<u8>, key: &str, value: &str) {
    while (buf.len() % 4) != 0 {
        buf.push(0);
    }
    let key_bytes: Vec<u8> = format!("{key}\0")
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    buf.extend_from_slice(&key_bytes);

    while (buf.len() % 4) != 0 {
        buf.push(0);
    }
    let val_bytes: Vec<u8> = format!("{value}\0")
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    buf.extend_from_slice(&val_bytes);
}

fn build_high_entropy_payload(len: usize) -> Vec<u8> {
    // Deterministic linear congruential generator for high Shannon entropy
    let mut bytes = Vec::with_capacity(len);
    let mut state: u64 = 0x1234_5678_9ABC_DEF0;
    for _ in 0..len {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        bytes.push((state >> 56) as u8);
    }
    bytes
}

fn assemble_rsrc_section(rsrc_rva: u32, manifest: &[u8], version: &[u8], rcdata: &[u8]) -> Vec<u8> {
    // 3 Types: 10 (RCDATA), 16 (VERSION), 24 (MANIFEST) - sorted in ascending ID order
    // Level 1: 1 Directory (16 bytes) + 3 Entries (3 * 8 = 24 bytes) = 40 bytes.
    // Level 2: 3 Directories (3 * 16 = 48 bytes) + 3 Entries (3 * 8 = 24 bytes) = 72 bytes.
    // Level 3: 3 Directories (3 * 16 = 48 bytes) + 3 Entries (3 * 8 = 24 bytes) = 72 bytes.
    // Leaves: 3 Data Entries (3 * 16 = 48 bytes).
    // Total metadata = 40 + 72 + 72 + 48 = 232 bytes.
    // Payloads start at offset 256 (aligned).

    let mut buf = Vec::new();

    let l1_dir_off = 0;
    let l2_rcdata_off = 40;
    let l2_version_off = 40 + 24;
    let l2_manifest_off = 40 + 48;

    let l3_rcdata_off = 40 + 72;
    let l3_version_off = 40 + 72 + 24;
    let l3_manifest_off = 40 + 72 + 48;

    let data_entry_rcdata_off = 40 + 72 + 72;
    let data_entry_version_off = 40 + 72 + 72 + 16;
    let data_entry_manifest_off = 40 + 72 + 72 + 32;

    let payload_start = 256;

    // --- Level 1 Root ---
    buf.extend_from_slice(&[0u8; 12]); // characteristics, timestamp, major, minor
    buf.extend_from_slice(&0u16.to_le_bytes()); // 0 named entries
    buf.extend_from_slice(&3u16.to_le_bytes()); // 3 ID entries

    // L1 Entry 0: ID 10 (RT_RCDATA)
    buf.extend_from_slice(&10u32.to_le_bytes());
    buf.extend_from_slice(&(0x8000_0000 | (l2_rcdata_off as u32)).to_le_bytes());

    // L1 Entry 1: ID 16 (RT_VERSION)
    buf.extend_from_slice(&16u32.to_le_bytes());
    buf.extend_from_slice(&(0x8000_0000 | (l2_version_off as u32)).to_le_bytes());

    // L1 Entry 2: ID 24 (RT_MANIFEST)
    buf.extend_from_slice(&24u32.to_le_bytes());
    buf.extend_from_slice(&(0x8000_0000 | (l2_manifest_off as u32)).to_le_bytes());

    // --- Level 2 Directories ---
    // L2 RCDATA: ID 1 -> L3
    buf.extend_from_slice(&[0u8; 12]);
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&(0x8000_0000 | (l3_rcdata_off as u32)).to_le_bytes());

    // L2 VERSION: ID 1 -> L3
    buf.extend_from_slice(&[0u8; 12]);
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&(0x8000_0000 | (l3_version_off as u32)).to_le_bytes());

    // L2 MANIFEST: ID 1 -> L3
    buf.extend_from_slice(&[0u8; 12]);
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&(0x8000_0000 | (l3_manifest_off as u32)).to_le_bytes());

    // --- Level 3 Directories ---
    // L3 RCDATA: Lang 0x0409 -> DataEntry
    buf.extend_from_slice(&[0u8; 12]);
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0x0409u32.to_le_bytes());
    buf.extend_from_slice(&(data_entry_rcdata_off as u32).to_le_bytes());

    // L3 VERSION: Lang 0x0409 -> DataEntry
    buf.extend_from_slice(&[0u8; 12]);
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0x0409u32.to_le_bytes());
    buf.extend_from_slice(&(data_entry_version_off as u32).to_le_bytes());

    // L3 MANIFEST: Lang 0x0409 -> DataEntry
    buf.extend_from_slice(&[0u8; 12]);
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0x0409u32.to_le_bytes());
    buf.extend_from_slice(&(data_entry_manifest_off as u32).to_le_bytes());

    // --- Data Entries ---
    let rcdata_payload_off = payload_start;
    let version_payload_off = rcdata_payload_off + rcdata.len();
    let manifest_payload_off = version_payload_off + version.len();

    // RCDATA leaf
    buf.extend_from_slice(&(rsrc_rva + rcdata_payload_off as u32).to_le_bytes());
    buf.extend_from_slice(&(rcdata.len() as u32).to_le_bytes());
    buf.extend_from_slice(&[0u8; 8]); // CodePage, Reserved

    // VERSION leaf
    buf.extend_from_slice(&(rsrc_rva + version_payload_off as u32).to_le_bytes());
    buf.extend_from_slice(&(version.len() as u32).to_le_bytes());
    buf.extend_from_slice(&[0u8; 8]);

    // MANIFEST leaf
    buf.extend_from_slice(&(rsrc_rva + manifest_payload_off as u32).to_le_bytes());
    buf.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
    buf.extend_from_slice(&[0u8; 8]);

    // Pad to payload_start
    while buf.len() < payload_start {
        buf.push(0);
    }

    // Append payloads
    buf.extend_from_slice(rcdata);
    buf.extend_from_slice(version);
    buf.extend_from_slice(manifest);

    let _ = l1_dir_off;
    buf
}

fn assemble_pe_image(rsrc_rva: u32, rsrc_bytes: &[u8]) -> Vec<u8> {
    let file_align = 0x200usize;
    let sec_align = 0x1000usize;

    let headers_raw_size = file_align; // 512 bytes
    let text_raw_off = 0x200usize;
    let text_raw_size = file_align; // 512 bytes

    let rsrc_raw_off = 0x400usize;
    let rsrc_raw_size = (rsrc_bytes.len() + file_align - 1) & !(file_align - 1);

    let total_file_size = rsrc_raw_off + rsrc_raw_size;
    let mut image = vec![0u8; total_file_size];

    // DOS Header
    image[0..2].copy_from_slice(b"MZ");
    image[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew = 0x80

    // NT Signature
    let nt_off = 0x80usize;
    image[nt_off..nt_off + 4].copy_from_slice(b"PE\0\0");

    // COFF Header (20 bytes)
    let coff = nt_off + 4;
    image[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // x86_64
    image[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes()); // 2 sections (.text, .rsrc)
    image[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes()); // Optional header size
    image[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes()); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // Optional Header (PE32+ 64-bit, 240 bytes)
    let opt = coff + 20;
    image[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
    image[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
    image[opt + 24..opt + 32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes()); // ImageBase
    image[opt + 32..opt + 36].copy_from_slice(&(sec_align as u32).to_le_bytes()); // SectionAlignment
    image[opt + 36..opt + 40].copy_from_slice(&(file_align as u32).to_le_bytes()); // FileAlignment
    image[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // Subsystem = CUI (Console)

    let dll_chars = IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
        | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        | IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
    image[opt + 70..opt + 72].copy_from_slice(&dll_chars.to_le_bytes());
    image[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

    // Data Directories: Index 2 is RESOURCE
    let rsrc_dir_entry_off = opt + 112 + (IMAGE_DIRECTORY_ENTRY_RESOURCE * 8);
    image[rsrc_dir_entry_off..rsrc_dir_entry_off + 4].copy_from_slice(&rsrc_rva.to_le_bytes());
    image[rsrc_dir_entry_off + 4..rsrc_dir_entry_off + 8]
        .copy_from_slice(&(rsrc_bytes.len() as u32).to_le_bytes());

    // Section Headers (start at opt + 240 = coff + 20 + 240)
    let sec1 = opt + 240;
    // .text
    image[sec1..sec1 + 8].copy_from_slice(b".text\0\0\0");
    image[sec1 + 8..sec1 + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
    image[sec1 + 12..sec1 + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    image[sec1 + 16..sec1 + 20].copy_from_slice(&(text_raw_size as u32).to_le_bytes()); // RawSize
    image[sec1 + 20..sec1 + 24].copy_from_slice(&(text_raw_off as u32).to_le_bytes()); // RawOffset
    image[sec1 + 36..sec1 + 40].copy_from_slice(
        &(IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ).to_le_bytes(),
    );

    let sec2 = sec1 + 40;
    // .rsrc
    image[sec2..sec2 + 8].copy_from_slice(b".rsrc\0\0\0");
    image[sec2 + 8..sec2 + 12].copy_from_slice(&(sec_align as u32).to_le_bytes()); // VirtualSize
    image[sec2 + 12..sec2 + 16].copy_from_slice(&rsrc_rva.to_le_bytes()); // VirtualAddress
    image[sec2 + 16..sec2 + 20].copy_from_slice(&(rsrc_raw_size as u32).to_le_bytes()); // RawSize
    image[sec2 + 20..sec2 + 24].copy_from_slice(&(rsrc_raw_off as u32).to_le_bytes()); // RawOffset
    image[sec2 + 36..sec2 + 40]
        .copy_from_slice(&(IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ).to_le_bytes());

    // Write .text payload (a single x86_64 RET instruction 0xC3)
    image[text_raw_off] = 0xC3;

    // Write .rsrc payload
    image[rsrc_raw_off..rsrc_raw_off + rsrc_bytes.len()].copy_from_slice(rsrc_bytes);

    let _ = headers_raw_size;
    image
}
