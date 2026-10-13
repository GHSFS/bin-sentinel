// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::digest::compute_authenticode_digests;
use crate::pe::build_synthetic_pe64;

const OID_SIGNED_DATA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
];
const OID_SPC_INDIRECT_DATA_CONTEXT: &[u8] = &[
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04,
];
const OID_SPC_PE_IMAGE_DATA: &[u8] = &[
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0F,
];
const OID_SHA256: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag);
    if content.len() < 128 {
        out.push(content.len() as u8);
    } else if content.len() <= 0xFF {
        out.push(0x81);
        out.push(content.len() as u8);
    } else if content.len() <= 0xFFFF {
        out.push(0x82);
        out.push((content.len() >> 8) as u8);
        out.push((content.len() & 0xFF) as u8);
    } else {
        out.push(0x83);
        out.push((content.len() >> 16) as u8);
        out.push(((content.len() >> 8) & 0xFF) as u8);
        out.push((content.len() & 0xFF) as u8);
    }
    out.extend_from_slice(content);
    out
}

fn build_pkcs7_authenticode_der(sha256_digest: &[u8; 32]) -> Vec<u8> {
    // 1. DigestInfo = SEQUENCE { AlgorithmIdentifier, digest OCTET STRING }
    let algo_id = der_tlv(0x30, &[OID_SHA256, &[0x05, 0x00]].concat());
    let digest_octets = der_tlv(0x04, sha256_digest);
    let digest_info = der_tlv(
        0x30,
        &[algo_id.as_slice(), digest_octets.as_slice()].concat(),
    );

    // 2. SpcIndirectDataContent = SEQUENCE { SpcAttributeTypeAndOptionalValue, DigestInfo }
    let spc_pe_data = der_tlv(0x30, &[OID_SPC_PE_IMAGE_DATA, &[0x30, 0x00]].concat());
    let spc_indirect = der_tlv(
        0x30,
        &[spc_pe_data.as_slice(), digest_info.as_slice()].concat(),
    );

    // 3. EncapsulatedContentInfo = SEQUENCE { contentType OID, [0] EXPLICIT OCTET STRING (SpcIndirectDataContent) }
    let spc_indirect_octets = der_tlv(0x04, &spc_indirect);
    let explicit_content = der_tlv(0xA0, &spc_indirect_octets);
    let encap_content = der_tlv(
        0x30,
        &[OID_SPC_INDIRECT_DATA_CONTEXT, explicit_content.as_slice()].concat(),
    );

    // 4. SignedData = SEQUENCE { version INTEGER (1), digestAlgorithms SET, encapContentInfo, signerInfos SET }
    let version = der_tlv(0x02, &[1]);
    let digest_algos = der_tlv(0x31, &algo_id);
    let signer_infos = der_tlv(0x31, &[]);
    let signed_data_inner = der_tlv(
        0x30,
        &[
            version.as_slice(),
            digest_algos.as_slice(),
            encap_content.as_slice(),
            signer_infos.as_slice(),
        ]
        .concat(),
    );

    // 5. ContentInfo = SEQUENCE { contentType OID (signedData), [0] EXPLICIT SignedData }
    let signed_data_explicit = der_tlv(0xA0, &signed_data_inner);
    der_tlv(
        0x30,
        &[OID_SIGNED_DATA, signed_data_explicit.as_slice()].concat(),
    )
}

/// Builds a deterministic synthetic PE32+ (64-bit) binary with a genuine Authenticode signature.
///
/// Embeds a valid `WIN_CERTIFICATE` entry in Data Directory 4 (`IMAGE_DIRECTORY_ENTRY_SECURITY`)
/// containing a PKCS#7 SignedData structure matching the true calculated Authenticode SHA-256 digest.
/// Optionally appends an EOF overlay at the end of the binary.
pub fn build_synthetic_signed_pe64(
    sections: &[(&str, &[u8], u32)],
    overlay: Option<&[u8]>,
) -> Vec<u8> {
    let mut pe_buf = build_synthetic_pe64(sections);

    let cert_offset = pe_buf.len();
    let dummy_hash = [0u8; 32];
    let dummy_der = build_pkcs7_authenticode_der(&dummy_hash);
    let dw_length = (8 + dummy_der.len()) as u32;
    let cert_table_size = ((dw_length as usize + 7) & !7) as u32;

    // Optional Header Data Directory 4 is at opt_offset + 144
    // In build_synthetic_pe64: e_lfanew = 0x80, coff = 0x84, opt = 0x98.
    // opt_offset + 144 = 0x98 + 144 = 0x128.
    let sec_dir_offset = 0x80 + 4 + 20 + 144;
    pe_buf[sec_dir_offset..sec_dir_offset + 4].copy_from_slice(&(cert_offset as u32).to_le_bytes());
    pe_buf[sec_dir_offset + 4..sec_dir_offset + 8].copy_from_slice(&cert_table_size.to_le_bytes());

    // Compute genuine Authenticode digest
    let digests = compute_authenticode_digests(&pe_buf)
        .expect("Authenticode digest calculation must succeed on synthetic PE");
    let real_der = build_pkcs7_authenticode_der(&digests.sha256);
    debug_assert_eq!(real_der.len(), dummy_der.len());

    // Construct 8-byte aligned WIN_CERTIFICATE entry
    let mut cert_entry = vec![0u8; cert_table_size as usize];
    cert_entry[0..4].copy_from_slice(&dw_length.to_le_bytes());
    cert_entry[4..6].copy_from_slice(&0x0200u16.to_le_bytes()); // WIN_CERT_REVISION_2_0
    cert_entry[6..8].copy_from_slice(&0x0002u16.to_le_bytes()); // WIN_CERT_TYPE_PKCS_SIGNED_DATA
    cert_entry[8..8 + real_der.len()].copy_from_slice(&real_der);

    pe_buf.extend_from_slice(&cert_entry);

    if let Some(extra_overlay) = overlay {
        pe_buf.extend_from_slice(extra_overlay);
    }

    pe_buf
}
