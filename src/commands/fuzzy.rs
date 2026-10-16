// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::path::Path;

use crate::error::Result;
use crate::fuzzy_hash::{compare_binary_files, hash_binary_file};

/// Handles the `fuzzy-hash` CLI subcommand.
pub fn handle_fuzzy_hash(file: &Path, json: bool) -> Result<()> {
    let report = hash_binary_file(file)?;

    if json {
        let output = serde_json::to_string_pretty(&report).map_err(|e| {
            crate::error::SentinelError::InvalidFormat(format!(
                "Failed to serialize fuzzy hash report: {}",
                e
            ))
        })?;
        println!("{}", output);
        return Ok(());
    }

    println!("=== BinSentinel Fuzzy Hash (CTPH / SSDEEP) ===");
    println!(
        "Target File : {} ({} bytes)",
        report.file_path, report.file_size
    );
    println!("Format      : {}", report.format);
    println!("Fuzzy Hash  : {}", report.fuzzy_hash);
    println!("Block Size  : {} bytes", report.fuzzy_hash.block_size);
    println!();

    if !report.sections.is_empty() {
        println!("[Section Fuzzy Fingerprints]");
        println!(
            "{:<16} {:<12} {:<12} {:<8} Fuzzy Hash",
            "Name", "VA", "Raw Size", "Entropy"
        );
        println!("{}", "-".repeat(78));
        for sec in &report.sections {
            println!(
                "{:<16} 0x{:08X}   {:<12} {:<8.2} {}",
                sec.name,
                sec.virtual_address,
                format!("{} B", sec.raw_size),
                sec.entropy,
                sec.fuzzy_hash
            );
        }
    } else {
        println!("No executable sections identified (raw binary or unmapped container).");
    }

    Ok(())
}

/// Handles the `fuzzy-compare` CLI subcommand.
pub fn handle_fuzzy_compare(file1: &Path, file2: &Path, json: bool) -> Result<()> {
    let report = compare_binary_files(file1, file2)?;

    if json {
        let output = serde_json::to_string_pretty(&report).map_err(|e| {
            crate::error::SentinelError::InvalidFormat(format!(
                "Failed to serialize fuzzy compare report: {}",
                e
            ))
        })?;
        println!("{}", output);
        return Ok(());
    }

    println!("=== BinSentinel Fuzzy Similarity Comparison ===");
    println!(
        "File 1      : {} ({} B, {})",
        report.file1_path, report.file1_size, report.file1_format
    );
    println!("  Fuzzy Hash: {}", report.file1_hash);
    println!(
        "File 2      : {} ({} B, {})",
        report.file2_path, report.file2_size, report.file2_format
    );
    println!("  Fuzzy Hash: {}", report.file2_hash);
    println!();
    println!("Overall Similarity : {}", report.overall_status);
    println!();

    if !report.section_comparisons.is_empty() {
        println!("[Section-by-Section Comparison]");
        println!(
            "{:<16} {:<8} {:<24} {:<24} File 2 Hash",
            "Section", "Score", "Status", "File 1 Hash"
        );
        println!("{}", "-".repeat(90));
        for sec in &report.section_comparisons {
            println!(
                "{:<16} {:>3}%   {:<24} {:<24} {}",
                sec.name, sec.score, sec.status, sec.hash1, sec.hash2
            );
        }
    }

    Ok(())
}
