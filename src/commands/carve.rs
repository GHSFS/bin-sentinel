// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::carve::{carve_payloads_file, CarveOptions};
use crate::error::Result;
use std::path::Path;

/// CLI handler for `bsentinel carve <file> [--min-len <n>] [--extract-dir <dir>] [--json]`.
pub fn handle_carve(
    file: &Path,
    min_len: usize,
    extract_dir: Option<&Path>,
    json: bool,
) -> Result<()> {
    let options = CarveOptions {
        min_length: min_len,
        extract_dir: extract_dir.map(|p| p.to_path_buf()),
        ..Default::default()
    };

    let report = carve_payloads_file(file, &options)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| {
                crate::error::SentinelError::InvalidFormat(format!(
                    "Failed to serialize JSON report: {e}"
                ))
            })?
        );
        return Ok(());
    }

    println!(
        "=== Base64 & Hex Encoded Payload Carving: {} ===",
        file.display()
    );
    println!("File Size        : {} bytes", report.file_size);
    println!("Total Carved     : {}", report.total_carved);
    println!("Nested Binaries  : {}", report.nested_executables_count);
    println!("Embedded Scripts : {}", report.scripts_count);
    println!("Network IoCs     : {}", report.iocs_count);
    println!("RWX Anomalies    : {}", report.rwx_anomalies_count);

    if let Some(dir) = extract_dir {
        println!("Extraction Dir   : {}", dir.display());
    }

    if report.payloads.is_empty() {
        println!("\nNo encoded payloads meeting the minimum length criteria were found.");
        return Ok(());
    }

    println!("\n[Carved Payloads & Forensics]");
    println!(
        "{:<4} {:<18} {:<12} {:<10} {:<10} {:<8} {:<8} {:<24} Summary",
        "ID", "Encoding", "Offset", "EncLen", "DecLen", "Section", "Entropy", "Kind"
    );
    println!(
        "{:-<4} {:-<18} {:-<12} {:-<10} {:-<10} {:-<8} {:-<8} {:-<24} {:-<30}",
        "", "", "", "", "", "", "", "", ""
    );

    for p in &report.payloads {
        let sec_str = p.section_name.as_deref().unwrap_or("-");
        let kind_str = format!("{}", p.payload_kind);
        let truncated_kind = if kind_str.len() > 24 {
            format!("{}...", &kind_str[..21])
        } else {
            kind_str
        };

        println!(
            "{:<4} {:<18} 0x{:<10X} {:<10} {:<10} {:<8} {:<8.2} {:<24} {}",
            p.id,
            p.encoding.to_string(),
            p.file_offset,
            p.encoded_length,
            p.decoded_length,
            sec_str,
            p.entropy,
            truncated_kind,
            p.summary
        );

        if !p.preview_text.is_empty() {
            println!(
                "     Preview: [{}]  Hex: [{}]",
                p.preview_text, p.preview_hex
            );
        }
        if p.is_rwx_section {
            println!(
                "     [!] ALERT: Embedded payload resides in Read-Write-Execute (RWX) section!"
            );
        }
    }

    Ok(())
}
