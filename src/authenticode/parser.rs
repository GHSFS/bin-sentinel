// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::{
    CertificateEntry, WinCertRevision, WinCertType, WIN_CERT_TYPE_PKCS_SIGNED_DATA,
};
use crate::pe::DataDirectory;

const OID_SPC_INDIRECT_DATA_CONTEXT: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA1: &[u8] = &[0x2B, 0x0E, 0x03, 0x02, 0x1A];
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
const OID_MD5: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05];

const OID_COUNTERSIGNATURE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x06];
const OID_RFC3161_TIMESTAMP: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x03, 0x01];
const OID_SPC_OPUS_INFO: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0C];

#[derive(Debug, Clone, Copy)]
pub struct DerTlv<'a> {
    pub tag: u8,
    pub header_len: usize,
    pub length: usize,
    pub data: &'a [u8],
}

pub fn parse_der_tlv(slice: &[u8]) -> Option<DerTlv<'_>> {
    if slice.len() < 2 {
        return None;
    }
    let tag = slice[0];
    let (length, header_len) = if slice[1] < 0x80 {
        (slice[1] as usize, 2)
    } else {
        let num_len_bytes = (slice[1] & 0x7F) as usize;
        if num_len_bytes == 0 || num_len_bytes > 4 || slice.len() < 2 + num_len_bytes {
            return None;
        }
        let mut len: usize = 0;
        for &b in &slice[2..2 + num_len_bytes] {
            len = (len << 8) | (b as usize);
        }
        (len, 2 + num_len_bytes)
    };

    let total_len = header_len.checked_add(length)?;

    if slice.len() < total_len {
        return None;
    }
    Some(DerTlv {
        tag,
        header_len,
        length,
        data: &slice[header_len..total_len],
    })
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    let slice = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let slice = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Parses the PE Security Directory attribute certificate table.
///
/// In PE images, the Security Directory's VirtualAddress is a direct file offset.
/// Entries are 8-byte aligned `WIN_CERTIFICATE` structures.
pub fn parse_certificate_table(
    data: &[u8],
    sec_dir: &DataDirectory,
    alerts: &mut Vec<String>,
) -> Vec<CertificateEntry> {
    let offset = sec_dir.virtual_address as usize;
    let size = sec_dir.size as usize;

    if offset == 0 || size == 0 {
        return Vec::new();
    }

    if offset >= data.len() {
        alerts.push(format!(
            "Certificate table offset 0x{offset:X} points outside file bounds ({} bytes)",
            data.len()
        ));
        return Vec::new();
    }

    let end_offset = (offset + size).min(data.len());
    if offset + size > data.len() {
        alerts.push(format!(
            "Certificate table size ({size} bytes) extends beyond file boundary ({} bytes)",
            data.len()
        ));
    }

    let mut entries = Vec::new();
    let mut current_offset = offset;
    let mut count = 0;
    const MAX_CERTIFICATES: usize = 64;

    while current_offset + 8 <= end_offset && count < MAX_CERTIFICATES {
        let dw_length = match read_u32_le(data, current_offset) {
            Some(v) => v,
            None => break,
        };
        let w_revision = read_u16_le(data, current_offset + 4).unwrap_or(0);
        let w_cert_type = read_u16_le(data, current_offset + 6).unwrap_or(0);

        if dw_length < 8 {
            alerts.push(format!(
                "Invalid WIN_CERTIFICATE entry #{count} with dwLength {dw_length} < 8 at 0x{current_offset:X}"
            ));
            break;
        }

        let entry_len = dw_length as usize;
        let entry_end = current_offset.saturating_add(entry_len);
        if entry_end > data.len() {
            alerts.push(format!(
                "WIN_CERTIFICATE entry #{count} truncated at 0x{current_offset:X} (needs {entry_len} bytes)"
            ));
            let data_size = data.len().saturating_sub(current_offset + 8);
            entries.push(CertificateEntry {
                index: count,
                file_offset: current_offset,
                length: dw_length,
                revision: w_revision,
                revision_name: WinCertRevision::from(w_revision).display_name(),
                certificate_type: w_cert_type,
                certificate_type_name: WinCertType::from(w_cert_type).display_name(),
                data_size,
                digest_algorithm: None,
                digest_hex: None,
                has_timestamp: false,
                program_name: None,
                signer_info_count: 0,
                is_valid_format: false,
                parse_error: Some("Truncated certificate payload".to_string()),
            });
            break;
        }

        let cert_payload = &data[current_offset + 8..entry_end];
        let mut parsed_algo = None;
        let mut parsed_digest = None;
        let mut has_timestamp = false;
        let mut program_name = None;
        let mut signer_info_count = 0;
        let mut is_valid_format = false;
        let mut parse_error = None;

        if w_cert_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA {
            match parse_pkcs7_signed_data(cert_payload) {
                Ok(info) => {
                    parsed_algo = info.digest_algorithm;
                    parsed_digest = info.digest_hex;
                    has_timestamp = info.has_timestamp;
                    program_name = info.program_name;
                    signer_info_count = info.signer_info_count;
                    is_valid_format = true;
                }
                Err(err) => {
                    parse_error = Some(err);
                }
            }
        } else {
            is_valid_format = true;
        }

        entries.push(CertificateEntry {
            index: count,
            file_offset: current_offset,
            length: dw_length,
            revision: w_revision,
            revision_name: WinCertRevision::from(w_revision).display_name(),
            certificate_type: w_cert_type,
            certificate_type_name: WinCertType::from(w_cert_type).display_name(),
            data_size: cert_payload.len(),
            digest_algorithm: parsed_algo,
            digest_hex: parsed_digest,
            has_timestamp,
            program_name,
            signer_info_count,
            is_valid_format,
            parse_error,
        });

        // Advance to next entry with 8-byte alignment
        let aligned_len = match entry_len.checked_add(7) {
            Some(l) => l & !7,
            None => break,
        };
        current_offset = match current_offset.checked_add(aligned_len) {
            Some(o) => o,
            None => break,
        };
        count += 1;
    }

    entries
}

struct Pkcs7Info {
    digest_algorithm: Option<String>,
    digest_hex: Option<String>,
    has_timestamp: bool,
    program_name: Option<String>,
    signer_info_count: usize,
}

fn parse_pkcs7_signed_data(payload: &[u8]) -> std::result::Result<Pkcs7Info, String> {
    if payload.len() < 8 {
        return Err("Payload too short for PKCS#7 ContentInfo".to_string());
    }

    let top = parse_der_tlv(payload).ok_or("Failed to parse outer DER TLV")?;
    if top.tag != 0x30 {
        return Err(format!(
            "Expected outer SEQUENCE (0x30), found 0x{:02X}",
            top.tag
        ));
    }

    let has_timestamp = contains_subslice(payload, OID_COUNTERSIGNATURE)
        || contains_subslice(payload, OID_RFC3161_TIMESTAMP);

    let (digest_algo, digest_hex) = extract_spc_indirect_digest(payload)
        .or_else(|| extract_fallback_digest(payload))
        .map(|(a, h)| (Some(a), Some(h)))
        .unwrap_or((None, None));

    let program_name = extract_opus_info(payload);
    let signer_info_count = if digest_hex.is_some() { 1 } else { 0 };

    Ok(Pkcs7Info {
        digest_algorithm: digest_algo,
        digest_hex,
        has_timestamp,
        program_name,
        signer_info_count,
    })
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn extract_spc_indirect_digest(payload: &[u8]) -> Option<(String, String)> {
    let pos = find_subslice(payload, OID_SPC_INDIRECT_DATA_CONTEXT)?;
    let after_oid = &payload[pos + OID_SPC_INDIRECT_DATA_CONTEXT.len()..];

    // Search within next 512 bytes for DigestInfo
    let window_len = after_oid.len().min(512);
    let window = &after_oid[..window_len];

    match_algo_and_digest(window)
}

fn extract_fallback_digest(payload: &[u8]) -> Option<(String, String)> {
    match_algo_and_digest(payload)
}

fn match_algo_and_digest(slice: &[u8]) -> Option<(String, String)> {
    let algos = [
        (OID_SHA256, "SHA-256", 32),
        (OID_SHA1, "SHA-1", 20),
        (OID_SHA384, "SHA-384", 48),
        (OID_SHA512, "SHA-512", 64),
        (OID_MD5, "MD5", 16),
    ];

    for (oid, name, digest_len) in algos {
        if let Some(pos) = find_subslice(slice, oid) {
            let after = &slice[pos + oid.len()..];
            // Look for OCTET STRING tag (0x04) of digest_len within 64 bytes
            let limit = after.len().min(64);
            for i in 0..limit {
                if after[i] == 0x04 && i + 1 < after.len() {
                    let len = after[i + 1] as usize;
                    if len == digest_len && i + 2 + len <= after.len() {
                        let digest_bytes = &after[i + 2..i + 2 + len];
                        return Some((name.to_string(), hex::encode(digest_bytes)));
                    }
                }
            }
        }
    }

    None
}

fn extract_opus_info(payload: &[u8]) -> Option<String> {
    let pos = find_subslice(payload, OID_SPC_OPUS_INFO)?;
    let after = &payload[pos + OID_SPC_OPUS_INFO.len()..];
    let limit = after.len().min(256);
    let window = &after[..limit];

    for i in 0..window.len() {
        let tag = window[i];
        // 0x0C = UTF8String, 0x13 = PrintableString, 0x16 = IA5String
        if (tag == 0x0C || tag == 0x13 || tag == 0x16) && i + 1 < window.len() {
            let len = window[i + 1] as usize;
            if len > 0 && i + 2 + len <= window.len() {
                if let Ok(s) = std::str::from_utf8(&window[i + 2..i + 2 + len]) {
                    return Some(s.to_string());
                }
            }
        }
    }

    None
}
