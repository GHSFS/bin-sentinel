// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use sha2::{Digest, Sha256};

use super::sha1::Sha1;
use crate::error::{Result, SentinelError};
use crate::pe::{DOS_MAGIC, NT_SIGNATURE, PE32_MAGIC, PE32_PLUS_MAGIC};

/// Calculated Authenticode digests for an image.
#[derive(Debug, Clone)]
pub struct AuthenticodeDigests {
    pub sha256: [u8; 32],
    pub sha256_hex: String,
    pub sha1: [u8; 20],
    pub sha1_hex: String,
}

#[derive(Debug, Clone, Copy)]
struct SectionSpan {
    raw_offset: usize,
    raw_size: usize,
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

/// Computes the genuine Windows Authenticode image digest for SHA-256 and SHA-1.
///
/// Follows the official Microsoft Authenticode Portable Executable specification:
/// 1. Hash from file start (0) up to Optional Header `CheckSum` (opt_offset + 64).
/// 2. Skip the 4-byte `CheckSum` field.
/// 3. Hash up to the Security Directory entry in Data Directory (index 4).
/// 4. Skip the 8-byte Security Directory entry.
/// 5. Hash remainder of headers up to `SizeOfHeaders`.
/// 6. Sort sections by `PointerToRawData` in ascending order and hash their raw byte contents.
/// 7. Hash any padding up to the Certificate Table file offset.
pub fn compute_authenticode_digests(data: &[u8]) -> Result<AuthenticodeDigests> {
    if data.len() < 0x40 {
        return Err(SentinelError::InvalidFormat(
            "File smaller than minimum DOS header".into(),
        ));
    }

    let dos_magic = read_u16_le(data, 0)?;
    if dos_magic != DOS_MAGIC {
        return Err(SentinelError::InvalidFormat(format!(
            "Invalid DOS magic 0x{dos_magic:04X}"
        )));
    }

    let e_lfanew = read_u32_le(data, 0x3C)? as usize;
    let coff_offset = e_lfanew
        .checked_add(4)
        .ok_or_else(|| SentinelError::BoundsError("e_lfanew overflow".into()))?;

    let coff_end = coff_offset
        .checked_add(20)
        .ok_or_else(|| SentinelError::BoundsError("COFF header offset overflow".into()))?;

    if coff_end > data.len() {
        return Err(SentinelError::BoundsError(
            "COFF header outside file bounds".into(),
        ));
    }

    let nt_sig = read_u32_le(data, e_lfanew)?;
    if nt_sig != NT_SIGNATURE {
        return Err(SentinelError::InvalidFormat(format!(
            "Invalid PE NT signature 0x{nt_sig:08X}"
        )));
    }

    let number_of_sections = read_u16_le(data, coff_offset + 2)? as usize;
    let size_of_opt_header = read_u16_le(data, coff_offset + 16)? as usize;
    let opt_offset = coff_offset.saturating_add(20);

    let opt_end = opt_offset
        .checked_add(size_of_opt_header)
        .ok_or_else(|| SentinelError::BoundsError("Optional header offset overflow".into()))?;

    if opt_end > data.len() {
        return Err(SentinelError::BoundsError(
            "Optional header extends beyond file".into(),
        ));
    }

    let opt_magic = read_u16_le(data, opt_offset)?;
    let (sec_dir_offset, min_opt_size) = match opt_magic {
        PE32_MAGIC => (opt_offset.saturating_add(128), 128 + 8),
        PE32_PLUS_MAGIC => (opt_offset.saturating_add(144), 144 + 8),
        other => {
            return Err(SentinelError::InvalidFormat(format!(
                "Unsupported Optional Header magic: 0x{other:04X}"
            )));
        }
    };

    let checksum_offset = opt_offset.saturating_add(64);
    let size_of_headers = read_u32_le(data, opt_offset.saturating_add(60))? as usize;

    let (sec_dir_va, sec_dir_size) = if size_of_opt_header >= min_opt_size {
        (
            read_u32_le(data, sec_dir_offset)? as usize,
            read_u32_le(data, sec_dir_offset + 4)? as usize,
        )
    } else {
        (0, 0)
    };

    let section_table_offset = opt_offset.saturating_add(size_of_opt_header);
    let max_sections = number_of_sections.min(1024);
    let mut sections = Vec::with_capacity(max_sections);
    for idx in 0..number_of_sections {
        let sec_off = match idx
            .checked_mul(40)
            .and_then(|v| section_table_offset.checked_add(v))
        {
            Some(o) => o,
            None => break,
        };
        if sec_off.checked_add(40).is_some_and(|end| end <= data.len()) {
            let raw_size = read_u32_le(data, sec_off + 16)? as usize;
            let raw_offset = read_u32_le(data, sec_off + 20)? as usize;
            if raw_size > 0 && raw_offset > 0 {
                sections.push(SectionSpan {
                    raw_offset,
                    raw_size,
                });
            }
        }
    }

    sections.sort_by_key(|s| s.raw_offset);

    let mut sha256_hasher = Sha256::new();
    let mut sha1_hasher = Sha1::new();

    let mut hash_chunk = |slice: &[u8]| {
        sha256_hasher.update(slice);
        sha1_hasher.update(slice);
    };

    // Step 1: Byte 0 up to CheckSum
    if checksum_offset > data.len() {
        return Err(SentinelError::BoundsError(
            "CheckSum offset outside file".into(),
        ));
    }
    hash_chunk(&data[..checksum_offset]);

    // Step 2: Skip 4 bytes CheckSum, hash up to Security Directory entry
    let after_checksum = checksum_offset.saturating_add(4);
    if sec_dir_offset > data.len() {
        return Err(SentinelError::BoundsError(
            "Security directory offset outside file".into(),
        ));
    }
    if sec_dir_offset >= after_checksum {
        hash_chunk(&data[after_checksum..sec_dir_offset]);
    }

    // Step 3: Skip 8 bytes Security Directory entry, hash up to SizeOfHeaders
    let after_sec_dir = sec_dir_offset.saturating_add(8);
    let headers_limit = size_of_headers.min(data.len());
    if headers_limit > after_sec_dir {
        hash_chunk(&data[after_sec_dir..headers_limit]);
    }

    // Step 4: Hash sections sorted ascending by PointerToRawData
    let mut bytes_hashed_so_far = headers_limit;
    for sec in &sections {
        let start = sec.raw_offset;
        let end = sec.raw_offset.saturating_add(sec.raw_size).min(data.len());
        if start < data.len() && end >= start {
            hash_chunk(&data[start..end]);
            bytes_hashed_so_far = bytes_hashed_so_far.max(end);
        }
    }

    // Step 5: Hash any padding up to Certificate Table offset (or file end if unsigned)
    let file_boundary_to_hash = if sec_dir_va > 0 && sec_dir_size > 0 && sec_dir_va <= data.len() {
        sec_dir_va
    } else {
        data.len()
    };

    if file_boundary_to_hash > bytes_hashed_so_far && bytes_hashed_so_far < data.len() {
        let end = file_boundary_to_hash.min(data.len());
        hash_chunk(&data[bytes_hashed_so_far..end]);
    }

    let sha256_bytes: [u8; 32] = sha256_hasher.finalize().into();
    let sha256_hex = hex::encode(sha256_bytes);

    let sha1_bytes = sha1_hasher.finalize();
    let sha1_hex = hex::encode(sha1_bytes);

    Ok(AuthenticodeDigests {
        sha256: sha256_bytes,
        sha256_hex,
        sha1: sha1_bytes,
        sha1_hex,
    })
}
