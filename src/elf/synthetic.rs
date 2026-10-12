// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::headers::{
    ELFCLASS64, ELFDATA2LSB, ELF_MAGIC, EM_X86_64, ET_DYN, PF_R, PF_W, PF_X, PT_GNU_RELRO,
    PT_GNU_STACK, PT_LOAD, SHF_ALLOC, SHT_DYNSYM, SHT_STRTAB,
};

/// Helper function to build a deterministic, synthetically valid ELF64 binary image.
pub fn build_synthetic_elf64(custom_sections: &[(&str, &[u8], u64, u32)]) -> Vec<u8> {
    let mut out = Vec::new();

    // 1. ELF Header (64 bytes)
    out.extend_from_slice(&ELF_MAGIC);
    out.push(ELFCLASS64); // 64-bit
    out.push(ELFDATA2LSB); // Little endian
    out.push(1); // EV_CURRENT
    out.push(3); // Linux OS/ABI
    out.extend_from_slice(&[0u8; 8]); // Padding

    let e_type = ET_DYN; // Shared object / PIE
    let e_machine = EM_X86_64;
    let e_version = 1u32;
    let e_entry = 0x0000_1000u64;

    out.extend_from_slice(&e_type.to_le_bytes());
    out.extend_from_slice(&e_machine.to_le_bytes());
    out.extend_from_slice(&e_version.to_le_bytes());
    out.extend_from_slice(&e_entry.to_le_bytes());

    let phoff = 64u64;
    let phnum = 3u16; // PT_LOAD, PT_GNU_STACK, PT_GNU_RELRO
    let phentsize = 56u16;
    let shentsize = 64u16;

    out.extend_from_slice(&phoff.to_le_bytes());
    // Placeholder for e_shoff at offset 40
    let shoff_pos = out.len();
    out.extend_from_slice(&0u64.to_le_bytes());

    let e_flags = 0u32;
    let e_ehsize = 64u16;
    out.extend_from_slice(&e_flags.to_le_bytes());
    out.extend_from_slice(&e_ehsize.to_le_bytes());
    out.extend_from_slice(&phentsize.to_le_bytes());
    out.extend_from_slice(&phnum.to_le_bytes());
    out.extend_from_slice(&shentsize.to_le_bytes());

    // Section count: null + custom sections + .dynsym + .dynstr + .shstrtab
    let shnum = (1 + custom_sections.len() + 3) as u16;
    let shstrndx = shnum - 1;

    out.extend_from_slice(&shnum.to_le_bytes());
    out.extend_from_slice(&shstrndx.to_le_bytes());

    // 2. Program Headers (3 * 56 = 168 bytes)
    // PT_LOAD (code & headers)
    out.extend_from_slice(&PT_LOAD.to_le_bytes());
    out.extend_from_slice(&(PF_R | PF_X).to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // offset
    out.extend_from_slice(&0x1000u64.to_le_bytes()); // vaddr
    out.extend_from_slice(&0x1000u64.to_le_bytes()); // paddr
    out.extend_from_slice(&0x1000u64.to_le_bytes()); // filesz
    out.extend_from_slice(&0x1000u64.to_le_bytes()); // memsz
    out.extend_from_slice(&0x1000u64.to_le_bytes()); // align

    // PT_GNU_STACK (read + write, non-executable stack)
    out.extend_from_slice(&PT_GNU_STACK.to_le_bytes());
    out.extend_from_slice(&(PF_R | PF_W).to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0x10u64.to_le_bytes());

    // PT_GNU_RELRO
    out.extend_from_slice(&PT_GNU_RELRO.to_le_bytes());
    out.extend_from_slice(&(PF_R).to_le_bytes());
    out.extend_from_slice(&0x200u64.to_le_bytes());
    out.extend_from_slice(&0x2000u64.to_le_bytes());
    out.extend_from_slice(&0x2000u64.to_le_bytes());
    out.extend_from_slice(&0x100u64.to_le_bytes());
    out.extend_from_slice(&0x100u64.to_le_bytes());
    out.extend_from_slice(&0x10u64.to_le_bytes());

    // 3. Section Data construction
    // Pad up to 0x200 for section body
    if out.len() < 0x200 {
        out.resize(0x200, 0);
    }

    struct SecRecord {
        name: String,
        sh_type: u32,
        sh_flags: u64,
        sh_addr: u64,
        offset: usize,
        size: usize,
        link: u32,
        info: u32,
        entsize: u64,
    }

    let mut records = Vec::new();
    let mut addr_counter = 0x2000u64;

    for (sec_name, sec_bytes, flags, s_type) in custom_sections {
        let off = out.len();
        out.extend_from_slice(sec_bytes);
        // Align to 8 bytes
        while out.len() % 8 != 0 {
            out.push(0);
        }
        records.push(SecRecord {
            name: (*sec_name).to_string(),
            sh_type: *s_type,
            sh_flags: *flags,
            sh_addr: addr_counter,
            offset: off,
            size: sec_bytes.len(),
            link: 0,
            info: 0,
            entsize: 0,
        });
        addr_counter += 0x1000;
    }

    // Dynamic Strings (.dynstr)
    let dynstr_off = out.len();
    let mut dynstr_buf = vec![0u8]; // Leading null byte
    let canary_str_off = dynstr_buf.len();
    dynstr_buf.extend_from_slice(b"__stack_chk_fail\0");
    let main_str_off = dynstr_buf.len();
    dynstr_buf.extend_from_slice(b"main\0");
    out.extend_from_slice(&dynstr_buf);
    while out.len() % 8 != 0 {
        out.push(0);
    }
    let dynstr_size = dynstr_buf.len();

    // Dynamic Symbols (.dynsym)
    let dynsym_off = out.len();
    // Symbol 0 (Null)
    out.extend_from_slice(&[0u8; 24]);
    // Symbol 1 (__stack_chk_fail)
    out.extend_from_slice(&(canary_str_off as u32).to_le_bytes());
    out.push(0x12); // STB_GLOBAL (1) << 4 | STT_FUNC (2)
    out.push(0); // STV_DEFAULT
    out.extend_from_slice(&0u16.to_le_bytes()); // SHN_UNDEF
    out.extend_from_slice(&0u64.to_le_bytes()); // value
    out.extend_from_slice(&0u64.to_le_bytes()); // size
                                                // Symbol 2 (main)
    out.extend_from_slice(&(main_str_off as u32).to_le_bytes());
    out.push(0x12);
    out.push(0);
    out.extend_from_slice(&1u16.to_le_bytes()); // in section 1
    out.extend_from_slice(&0x1000u64.to_le_bytes());
    out.extend_from_slice(&0x20u64.to_le_bytes());

    let dynsym_size = out.len() - dynsym_off;
    while out.len() % 8 != 0 {
        out.push(0);
    }

    let dynsym_sec_idx = 1 + custom_sections.len() as u32;
    let dynstr_sec_idx = dynsym_sec_idx + 1;

    records.push(SecRecord {
        name: ".dynsym".into(),
        sh_type: SHT_DYNSYM,
        sh_flags: SHF_ALLOC,
        sh_addr: addr_counter,
        offset: dynsym_off,
        size: dynsym_size,
        link: dynstr_sec_idx,
        info: 1,
        entsize: 24,
    });
    addr_counter += 0x1000;

    records.push(SecRecord {
        name: ".dynstr".into(),
        sh_type: SHT_STRTAB,
        sh_flags: SHF_ALLOC,
        sh_addr: addr_counter,
        offset: dynstr_off,
        size: dynstr_size,
        link: 0,
        info: 0,
        entsize: 0,
    });

    // Build .shstrtab
    let mut shstrtab = vec![0u8];
    let mut name_offsets = Vec::new();
    for rec in &records {
        let pos = shstrtab.len();
        shstrtab.extend_from_slice(rec.name.as_bytes());
        shstrtab.push(0);
        name_offsets.push(pos as u32);
    }
    let shstr_name_off = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab\0");

    let shstrtab_off = out.len();
    out.extend_from_slice(&shstrtab);
    while out.len() % 8 != 0 {
        out.push(0);
    }
    let shstrtab_size = shstrtab.len();

    records.push(SecRecord {
        name: ".shstrtab".into(),
        sh_type: SHT_STRTAB,
        sh_flags: 0,
        sh_addr: 0,
        offset: shstrtab_off,
        size: shstrtab_size,
        link: 0,
        info: 0,
        entsize: 0,
    });
    name_offsets.push(shstr_name_off);

    // 4. Section Header Table
    let shoff = out.len();
    // Section 0 (Null)
    out.extend_from_slice(&[0u8; 64]);

    for (rec, name_off) in records.iter().zip(name_offsets.iter()) {
        out.extend_from_slice(&name_off.to_le_bytes());
        out.extend_from_slice(&rec.sh_type.to_le_bytes());
        out.extend_from_slice(&rec.sh_flags.to_le_bytes());
        out.extend_from_slice(&rec.sh_addr.to_le_bytes());
        out.extend_from_slice(&(rec.offset as u64).to_le_bytes());
        out.extend_from_slice(&(rec.size as u64).to_le_bytes());
        out.extend_from_slice(&rec.link.to_le_bytes());
        out.extend_from_slice(&rec.info.to_le_bytes());
        out.extend_from_slice(&8u64.to_le_bytes()); // align
        out.extend_from_slice(&rec.entsize.to_le_bytes());
    }

    // Patch e_shoff in ELF Header
    let shoff_bytes = (shoff as u64).to_le_bytes();
    out[shoff_pos..shoff_pos + 8].copy_from_slice(&shoff_bytes);

    out
}
