// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::path::Path;

use crate::authenticode::inspect_authenticode_file;
use crate::error::Result;

/// CLI command handler for `bsentinel sig-check <file> [--json]`.
pub fn handle_sig_check(file: &Path, json: bool) -> Result<()> {
    let report = inspect_authenticode_file(file)?;

    if json {
        let json_str = serde_json::to_string_pretty(&report)
            .map_err(|e| crate::error::SentinelError::InvalidFormat(e.to_string()))?;
        println!("{json_str}");
        return Ok(());
    }

    println!("================================================================================");
    println!(
        "  AUTHENTICODE & DIGITAL SIGNATURE REPORT: {}",
        report.file_path
    );
    println!("================================================================================");
    println!("  File Size:              {} bytes", report.file_size);
    println!(
        "  Format:                 {}",
        report.pe_format.as_deref().unwrap_or("Unknown PE")
    );

    let sig_status = if report.is_signed {
        if report.signature_verified {
            "Signed (Verified Valid)"
        } else {
            "Signed (TAMPER ALERT / DIGEST MISMATCH)"
        }
    } else {
        "Unsigned (No Security Directory Certificate Table)"
    };
    println!("  Signature Status:       {sig_status}");
    println!("  Certificates Count:     {}", report.certificates.len());
    println!(
        "  Expected Image Size:    {} bytes",
        report.expected_image_size
    );

    if let Some(ref dir) = report.security_directory {
        println!(
            "  Security Directory:     Offset 0x{:X}, Size {} bytes",
            dir.virtual_address, dir.size
        );
    }

    if !report.certificates.is_empty() {
        println!();
        println!("── Certificate Table Entries ──────────────────────────────────────────────────");
        for cert in &report.certificates {
            println!(
                "  #{} Offset: 0x{:X}  Length: {} bytes  Revision: {}  Type: {}",
                cert.index,
                cert.file_offset,
                cert.length,
                cert.revision_name,
                cert.certificate_type_name
            );
            if let Some(ref algo) = cert.digest_algorithm {
                println!("     Digest Algorithm:    {algo}");
            }
            if let Some(ref dig) = cert.digest_hex {
                println!("     Embedded Digest:     {dig}");
            }
            if cert.has_timestamp {
                println!("     Timestamp Token:     Present (RFC 3161 / Countersignature)");
            }
            if let Some(ref prog) = cert.program_name {
                println!("     Program Description: {prog}");
            }
            if let Some(ref err) = cert.parse_error {
                println!("     Parsing Note:        {err}");
            }
        }
    }

    if !report.digests.is_empty() {
        println!();
        println!("── Authenticode PE Image Digests ──────────────────────────────────────────────");
        println!(
            "  {:<10} {:<36} {:<10}",
            "Algorithm", "Calculated Digest", "Status"
        );
        println!("  {}", "─".repeat(76));
        for dig in &report.digests {
            let status = match dig.verified {
                Some(true) => "MATCH",
                Some(false) => "MISMATCH",
                None => "N/A",
            };
            println!(
                "  {:<10} {:<64} {:<10}",
                dig.algorithm, dig.calculated_hex, status
            );
            if let Some(ref emb) = dig.embedded_hex {
                println!("             Embedded:   {emb}");
            }
        }
    }

    println!();
    println!("── EOF Overlay Analysis ───────────────────────────────────────────────────────");
    if report.overlay.detected {
        println!("  Overlay Detected:       YES (Appended EOF data present)");
        println!("  Overlay Offset:         0x{:X}", report.overlay.offset);
        println!("  Overlay Size:           {} bytes", report.overlay.size);
        println!(
            "  Overlay Ratio:          {:.2}% of file",
            report.overlay.ratio_percent
        );
        println!(
            "  Overlay Entropy:        {:.4} bits/byte",
            report.overlay.entropy
        );
        println!(
            "  Classification:         {}",
            report.overlay.classification
        );
    } else {
        println!("  Overlay Detected:       No (File terminates at legitimate image boundary)");
    }

    if !report.alerts.is_empty() {
        println!();
        println!("── Forensic Alerts ────────────────────────────────────────────────────────────");
        for alert in &report.alerts {
            println!("  [!] {alert}");
        }
    }

    Ok(())
}
