// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod digest;
pub mod overlay;
pub mod parser;
pub mod sha1;
pub mod synthetic;
pub mod types;

use std::fs;
use std::path::Path;

pub use digest::{compute_authenticode_digests, AuthenticodeDigests};
pub use overlay::detect_overlay;
pub use parser::parse_certificate_table;
pub use sha1::Sha1;
pub use synthetic::build_synthetic_signed_pe64;
pub use types::{
    AuthenticodeDigestInfo, AuthenticodeReport, CertificateEntry, OverlayInfo, WinCertRevision,
    WinCertType, WIN_CERT_REVISION_1_0, WIN_CERT_REVISION_2_0, WIN_CERT_TYPE_PKCS_SIGNED_DATA,
    WIN_CERT_TYPE_RESERVED_1, WIN_CERT_TYPE_TS_STACK_SIGNED, WIN_CERT_TYPE_X509,
};

use crate::error::Result;
use crate::pe::{parse_pe, IMAGE_DIRECTORY_ENTRY_SECURITY};

/// Branchless constant-time case-insensitive hex string equality check.
/// Eliminates timing side-channel leakage during cryptographic digest comparison.
pub fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= x.to_ascii_lowercase() ^ y.to_ascii_lowercase();
    }
    diff == 0
}

/// Inspects PE Authenticode digital signatures, certificate tables, and EOF overlays in memory.
pub fn inspect_authenticode_bytes(
    data: &[u8],
    path_display: Option<&str>,
) -> Result<AuthenticodeReport> {
    let pe_info = parse_pe(data)?;
    let sec_dir = pe_info
        .data_directory(IMAGE_DIRECTORY_ENTRY_SECURITY)
        .copied();

    let mut alerts = Vec::new();
    let certificates = if let Some(ref dir) = sec_dir {
        parse_certificate_table(data, dir, &mut alerts)
    } else {
        Vec::new()
    };

    let (overlay, expected_image_size) = detect_overlay(data, &pe_info.sections, sec_dir.as_ref());

    let digests_result = compute_authenticode_digests(data);
    let mut digests = Vec::new();
    let mut signature_verified = false;

    if let Ok(calc_digests) = digests_result {
        // SHA-256
        let embedded_sha256 = certificates
            .iter()
            .find(|c| c.digest_algorithm.as_deref() == Some("SHA-256"))
            .and_then(|c| c.digest_hex.clone());
        let sha256_verified = embedded_sha256
            .as_ref()
            .map(|emb| constant_time_eq_hex(emb, &calc_digests.sha256_hex));

        digests.push(AuthenticodeDigestInfo {
            algorithm: "SHA-256".to_string(),
            calculated_hex: calc_digests.sha256_hex.clone(),
            embedded_hex: embedded_sha256,
            verified: sha256_verified,
        });

        // SHA-1
        let embedded_sha1 = certificates
            .iter()
            .find(|c| c.digest_algorithm.as_deref() == Some("SHA-1"))
            .and_then(|c| c.digest_hex.clone());
        let sha1_verified = embedded_sha1
            .as_ref()
            .map(|emb| constant_time_eq_hex(emb, &calc_digests.sha1_hex));

        digests.push(AuthenticodeDigestInfo {
            algorithm: "SHA-1".to_string(),
            calculated_hex: calc_digests.sha1_hex.clone(),
            embedded_hex: embedded_sha1,
            verified: sha1_verified,
        });

        if !certificates.is_empty() {
            let any_matched = digests.iter().any(|d| d.verified == Some(true));
            let any_mismatch = digests.iter().any(|d| d.verified == Some(false));

            if any_mismatch {
                signature_verified = false;
                alerts.push(
                    "CRITICAL: Authenticode image digest mismatch — executable contents or headers have been modified!"
                        .to_string(),
                );
            } else if any_matched {
                signature_verified = true;
            }
        }
    } else if let Err(e) = digests_result {
        alerts.push(format!("Digest calculation error: {e}"));
    }

    if overlay.detected {
        alerts.push(format!(
            "OVERLAY: Detected {} bytes appended after legitimate PE image boundary (offset 0x{:X}, {:.1}% of file, classification: {})",
            overlay.size, overlay.offset, overlay.ratio_percent, overlay.classification
        ));
        if overlay.entropy >= 7.2 {
            alerts.push(
                "OVERLAY: High-entropy overlay payload detected — potential encrypted, compressed, or steganographic container"
                    .to_string(),
            );
        }
    }

    Ok(AuthenticodeReport {
        file_path: path_display.unwrap_or("<in-memory>").to_string(),
        file_size: data.len(),
        is_pe: true,
        pe_format: Some(pe_info.format),
        security_directory: sec_dir,
        certificates,
        is_signed: sec_dir
            .map(|d| d.virtual_address > 0 && d.size > 0)
            .unwrap_or(false),
        signature_verified,
        digests,
        overlay,
        expected_image_size,
        alerts,
    })
}

/// Inspects a PE binary file on disk for Authenticode signatures and overlays.
pub fn inspect_authenticode_file(path: &Path) -> Result<AuthenticodeReport> {
    let data = fs::read(path)?;
    let display_str = path.display().to_string();
    inspect_authenticode_bytes(&data, Some(&display_str))
}
