// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::headers::*;

/// Helper to generate a deterministic synthetic Mach-O 64-bit binary image.
pub fn build_synthetic_macho64(
    cputype: u32,
    cpusubtype: u32,
    custom_sections: &[(&str, &[u8], u32)],
) -> Vec<u8> {
    let mut out = Vec::new();

    // 1. Header placeholder (32 bytes)
    out.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
    out.extend_from_slice(&cputype.to_le_bytes());
    out.extend_from_slice(&cpusubtype.to_le_bytes());
    out.extend_from_slice(&MH_EXECUTE.to_le_bytes());

    // Placeholders for ncmds, sizeofcmds, flags, reserved
    let ncmds_pos = out.len();
    out.extend_from_slice(&0u32.to_le_bytes()); // ncmds
    let sizeofcmds_pos = out.len();
    out.extend_from_slice(&0u32.to_le_bytes()); // sizeofcmds
    let flags = MH_PIE | MH_DYLDLINK | MH_TWOLEVEL;
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved

    let cmds_start = out.len();
    let mut ncmds = 0u32;

    // 2. Command 1: LC_SEGMENT_64 for __PAGEZERO (72 bytes)
    ncmds += 1;
    out.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
    out.extend_from_slice(&72u32.to_le_bytes());
    let mut pagezero_name = [0u8; 16];
    pagezero_name[..10].copy_from_slice(b"__PAGEZERO");
    out.extend_from_slice(&pagezero_name);
    out.extend_from_slice(&0u64.to_le_bytes()); // vmaddr
    out.extend_from_slice(&0x100000000u64.to_le_bytes()); // vmsize (4GB)
    out.extend_from_slice(&0u64.to_le_bytes()); // fileoff
    out.extend_from_slice(&0u64.to_le_bytes()); // filesize
    out.extend_from_slice(&0u32.to_le_bytes()); // maxprot
    out.extend_from_slice(&0u32.to_le_bytes()); // initprot
    out.extend_from_slice(&0u32.to_le_bytes()); // nsects
    out.extend_from_slice(&0u32.to_le_bytes()); // flags

    // 3. Command 2: LC_SEGMENT_64 for __TEXT (72 + nsects * 80 bytes)
    ncmds += 1;
    let nsects = custom_sections.len() as u32;
    let text_cmd_size = 72u32 + nsects * 80u32;
    out.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
    out.extend_from_slice(&text_cmd_size.to_le_bytes());
    let mut text_name = [0u8; 16];
    text_name[..6].copy_from_slice(b"__TEXT");
    out.extend_from_slice(&text_name);
    out.extend_from_slice(&0x100000000u64.to_le_bytes()); // vmaddr
    out.extend_from_slice(&0x1000u64.to_le_bytes()); // vmsize
    out.extend_from_slice(&0u64.to_le_bytes()); // fileoff
    out.extend_from_slice(&0x1000u64.to_le_bytes()); // filesize
    out.extend_from_slice(&(VM_PROT_READ | VM_PROT_EXECUTE).to_le_bytes()); // maxprot
    out.extend_from_slice(&(VM_PROT_READ | VM_PROT_EXECUTE).to_le_bytes()); // initprot
    out.extend_from_slice(&nsects.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // flags

    // Placeholders for section headers; compute file offsets after load commands
    let sect_headers_pos = out.len();
    for _ in 0..nsects {
        out.extend_from_slice(&[0u8; 80]);
    }

    // 4. Command 3: LC_MAIN (24 bytes)
    ncmds += 1;
    out.extend_from_slice(&LC_MAIN.to_le_bytes());
    out.extend_from_slice(&24u32.to_le_bytes());
    let entryoff = 0x500u64; // arbitrary entry offset within __TEXT
    out.extend_from_slice(&entryoff.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // stacksize

    // 5. Command 4: LC_LOAD_DYLIB (/usr/lib/libSystem.B.dylib)
    ncmds += 1;
    let dylib_path = b"/usr/lib/libSystem.B.dylib\0";
    let dylib_str_len = dylib_path.len();
    let dylib_padded_len = (dylib_str_len + 7) & !7;
    let dylib_cmd_size = (24 + dylib_padded_len) as u32;

    out.extend_from_slice(&LC_LOAD_DYLIB.to_le_bytes());
    out.extend_from_slice(&dylib_cmd_size.to_le_bytes());
    out.extend_from_slice(&24u32.to_le_bytes()); // name_offset
    out.extend_from_slice(&0u32.to_le_bytes()); // timestamp
    out.extend_from_slice(&0x00010000u32.to_le_bytes()); // current_version
    out.extend_from_slice(&0x00010000u32.to_le_bytes()); // compatibility_version
    out.extend_from_slice(dylib_path);
    out.resize(out.len() + (dylib_padded_len - dylib_str_len), 0);

    // 6. Command 5: LC_CODE_SIGNATURE (16 bytes)
    ncmds += 1;
    let sig_dataoff = 0x800u32;
    let sig_datasize = 64u32;
    out.extend_from_slice(&LC_CODE_SIGNATURE.to_le_bytes());
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&sig_dataoff.to_le_bytes());
    out.extend_from_slice(&sig_datasize.to_le_bytes());

    // Update ncmds and sizeofcmds in header
    let sizeofcmds = (out.len() - cmds_start) as u32;
    out[ncmds_pos..ncmds_pos + 4].copy_from_slice(&ncmds.to_le_bytes());
    out[sizeofcmds_pos..sizeofcmds_pos + 4].copy_from_slice(&sizeofcmds.to_le_bytes());

    // Now layout section data starting at offset 0x500
    if out.len() < 0x500 {
        out.resize(0x500, 0);
    }

    let mut current_offset = 0x500u32;
    let mut current_addr = 0x100000500u64;

    for (i, (sname, sbytes, sflags)) in custom_sections.iter().enumerate() {
        let cur_sect_hdr = sect_headers_pos + i * 80;
        let mut sname_buf = [0u8; 16];
        let bytes_to_copy = sname.len().min(16);
        sname_buf[..bytes_to_copy].copy_from_slice(&sname.as_bytes()[..bytes_to_copy]);

        let size = sbytes.len() as u64;
        let offset = current_offset;

        // Write section_64 header
        let mut hdr = Vec::with_capacity(80);
        hdr.extend_from_slice(&sname_buf);
        hdr.extend_from_slice(&text_name); // segname: "__TEXT"
        hdr.extend_from_slice(&current_addr.to_le_bytes());
        hdr.extend_from_slice(&size.to_le_bytes());
        hdr.extend_from_slice(&offset.to_le_bytes());
        hdr.extend_from_slice(&4u32.to_le_bytes()); // align (2^4 = 16)
        hdr.extend_from_slice(&0u32.to_le_bytes()); // reloff
        hdr.extend_from_slice(&0u32.to_le_bytes()); // nreloc
        hdr.extend_from_slice(&sflags.to_le_bytes());
        hdr.extend_from_slice(&0u32.to_le_bytes()); // reserved1
        hdr.extend_from_slice(&0u32.to_le_bytes()); // reserved2
        hdr.extend_from_slice(&0u32.to_le_bytes()); // reserved3

        out[cur_sect_hdr..cur_sect_hdr + 80].copy_from_slice(&hdr);

        // Write section payload
        out.extend_from_slice(sbytes);
        current_offset += sbytes.len() as u32;
        current_addr += sbytes.len() as u64;
    }

    // Write dummy code signature at offset 0x800
    if out.len() < (sig_dataoff + sig_datasize) as usize {
        out.resize((sig_dataoff + sig_datasize) as usize, 0xCC);
    }

    // Pad file to 4096 bytes
    if out.len() < 0x1000 {
        out.resize(0x1000, 0);
    }

    out
}

/// Helper to generate a deterministic Universal (Fat) Mach-O binary containing multiple architecture slices.
pub fn build_synthetic_macho_universal(slices: &[(u32, u32, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let nfat_arch = slices.len() as u32;

    // 1. Fat Header (8 bytes, Big-Endian)
    out.extend_from_slice(&FAT_MAGIC.to_be_bytes());
    out.extend_from_slice(&nfat_arch.to_be_bytes());

    // 2. Fat Arch Headers (20 bytes each, Big-Endian)
    // Align slices to 4096 (2^12) boundaries
    let header_size = 8 + (nfat_arch as usize) * 20;
    let align_p2 = 12u32;
    let align_bytes = 1usize << align_p2; // 4096

    let mut current_offset = (header_size + align_bytes - 1) & !(align_bytes - 1);

    for (cputype, cpusubtype, data) in slices {
        out.extend_from_slice(&cputype.to_be_bytes());
        out.extend_from_slice(&cpusubtype.to_be_bytes());
        out.extend_from_slice(&(current_offset as u32).to_be_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&align_p2.to_be_bytes());

        current_offset = (current_offset + data.len() + align_bytes - 1) & !(align_bytes - 1);
    }

    // 3. Write slice contents at aligned offsets
    for (_, _, data) in slices {
        let target_len = (out.len() + align_bytes - 1) & !(align_bytes - 1);
        if out.len() < target_len {
            out.resize(target_len, 0);
        }
        out.extend_from_slice(data);
    }

    out
}
